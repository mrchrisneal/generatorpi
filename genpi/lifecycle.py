# genpi/lifecycle.py -- WSGI server + process-restart machinery for GeneratorPi (roadmap #59, Stage 8).
# LAYER: depends on genpi.logg (log), the Flask `app` (still defined in genpi/__init__ until Stage 9),
# and the stdlib. Imported by genpi/__init__ once the app + routes exist, and one-way by genpi.updater
# (which schedules a process restart after a successful self-update).
#
# Owns the real WSGI serving path: _serve (cheroot keep-alive server -- one TLS session per keep-alive
# HTTPS poll instead of a fresh ECDSA handshake per request, the dominant CPU cost on the Pi Zero 2 W),
# _serve_werkzeug (the proven pre-cheroot fallback so an install without cheroot STILL serves), _do_execv
# (the argv-preserving in-place re-exec), and _schedule_process_restart (the non-systemd restart fix that
# releases the listening socket before os.execv so the re-exec can rebind the port). The live server
# handle (_WSGI_SERVER) and the restart flag (_RESTART_REQUESTED) are module globals here; they are
# REBOUND at runtime, so readers OUTSIDE this module must reference them module-qualified
# (lifecycle._WSGI_SERVER / lifecycle._RESTART_REQUESTED) -- a re-exported copy would go stale.
#
# Copyright (C) 2026 Chris Neal <https://neal.media> and Alex Neal <https://neal.tools>
# SPDX-License-Identifier: AGPL-3.0-or-later
import os              # os.execv re-exec + os._exit fallback
import sys             # sys.executable / sys.argv preserved across the re-exec
import time            # restart delay + bind-retry backoff
import errno           # EADDRINUSE / EADDRNOTAVAIL classification on the bind-retry probe
import socket          # raw-socket bind probe (a real errno) before handing the port to cheroot
import ssl             # explicit TLS 1.2 floor on the cheroot SSL adapter
import threading       # the delayed restart timer thread
from .logg import log  # server lifecycle + bind-retry logging
from . import app      # the Flask WSGI application (still defined in __init__ until Stage 9)


# The live Werkzeug WSGI server, stored so the restart path can close its LISTENING SOCKET
# before os.execv. A re-exec inherits open file descriptors, so an unclosed listening socket
# leaves the port bound against the NEW image -- it then dies with "Address already in use"
# and the app never comes back on a non-systemd host (no supervisor to retry). Closing the
# socket here releases the port for the re-exec'd process to rebind.
# ---- WSGI server config (cheroot keep-alive server) ----
# Thread-pool MINIMUM. The GIL means threads aren't CPU parallelism; this is I/O concurrency so one
# slow TLS client can't block the rest. 8 is ample for a single user + a few pollers on the Pi Zero 2 W.
SERVE_THREADS = int(os.environ.get('SERVE_THREADS', '8'))
# HARD cap on the pool. cheroot's default max=-1 is UNBOUNDED -> a connection flood would grow the pool
# until the ~512 MB Pi OOM-kills the app (~8 MB stack/thread). A cap turns "OOM" into "excess conns wait".
SERVE_MAX_THREADS = int(os.environ.get('SERVE_MAX_THREADS', '24'))
# Per-connection socket timeout (s): a peer sending/receiving nothing for this long is dropped (bounds
# slow-trickle requests). cheroot's default is 10; set explicitly so it's a reviewed value.
SERVE_TIMEOUT = int(os.environ.get('SERVE_TIMEOUT', '10'))
# cheroot stop() waits up to this many seconds for in-flight requests to drain before we re-exec on a
# restart. Small = snappy self-update; idle keep-alive conns are closed promptly regardless.
SERVE_SHUTDOWN_TIMEOUT = int(os.environ.get('SERVE_SHUTDOWN_TIMEOUT', '2'))

_WSGI_SERVER = None          # handle to the live server (cheroot Server, or the werkzeug fallback)
_RESTART_REQUESTED = False   # set by _schedule_process_restart; the MAIN thread execs when serve() returns


def _do_execv():
    """Re-exec THIS process in place, preserving argv. os.execv shouldn't return; if it does, exit so a
    supervisor (systemd) can respawn. Shared by the cheroot (main-thread) and werkzeug (in-thread) paths."""
    try:
        os.execv(sys.executable, [sys.executable] + sys.argv)
    except Exception as e:                              # execv shouldn't return; if it does...
        log.error(f"Restart re-exec failed ({e}); exiting for a supervisor to respawn.")
        os._exit(1)


def _serve(host, port, ssl_context=None, threaded=False):
    """Serve the Flask app via cheroot -- a real WSGI server with HTTP keep-alive (an HTTPS poll reuses
    ONE TLS session instead of paying a fresh ECDSA handshake every request, the dominant CPU cost on
    the Pi Zero 2 W) and a built-in stdlib-ssl adapter for our self-signed ECDSA P-256 cert. We keep a
    handle in `_WSGI_SERVER` so _schedule_process_restart can release the listening socket before the
    os.execv re-exec (the non-systemd restart fix). Belt-and-suspenders: if cheroot can't be imported
    (e.g. an install that self-updated to this version before `pip install cheroot` ran), fall back to
    the werkzeug server so the app STILL serves (minus keep-alive) instead of bricking -- keep-alive
    engages automatically once cheroot is present. `threaded` is retained for call-site compatibility
    (cheroot always uses a thread pool)."""
    global _WSGI_SERVER
    try:
        from cheroot import wsgi                         # pure-Python; no compiler on the Pi
        from cheroot.ssl.builtin import BuiltinSSLAdapter
    except Exception as e:                               # cheroot missing/broken -> stay alive
        log.warning(f"cheroot unavailable ({e}); falling back to the werkzeug server (NO HTTP "
                    f"keep-alive). Run `pip install cheroot` to enable keep-alive.")
        return _serve_werkzeug(host, port, ssl_context=ssl_context, threaded=threaded)

    # Bind-retry via a RAW-SOCKET PROBE that yields a REAL errno. cheroot's prepare() masks bind errors
    # as an errno-less socket.error, so we can't tell EADDRINUSE (retry a draining old port) from a
    # cert/permission error (surface now) by its .errno. A raw bind probe gives a real errno, preserving
    # the #41 / audit-#6 semantics. The tiny probe->cheroot TOCTOU is covered by SO_REUSEADDR (both set
    # it) and nothing else contends for the port on this single-user box.
    last_err = None
    for attempt in range(10):                           # ~5s: ride out a draining old port
        fam = socket.AF_INET6 if ':' in host else socket.AF_INET   # match an IPv6 host override
        probe = socket.socket(fam, socket.SOCK_STREAM)
        try:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind((host, int(port)))               # raises OSError WITH a real .errno
            break
        except OSError as ex:
            if ex.errno not in (errno.EADDRINUSE, errno.EADDRNOTAVAIL):
                raise                                   # cert/permission/other -> surface NOW
            last_err = ex
            log.warning(f"Bind {host}:{port} busy (attempt {attempt + 1}/10): {ex} -- retrying")
            time.sleep(0.5)
        finally:
            probe.close()                               # free it so cheroot can bind the port
    else:                                               # retries exhausted -> surface it clearly
        log.critical(f"Could not bind {host}:{port} after retries: {last_err}")
        raise last_err

    # Port is free -> build + prepare cheroot ONCE. The cert loads EAGERLY at BuiltinSSLAdapter
    # construction, so a bad/unreadable cert raises HERE (outside the retry loop) -- audit-#6 semantics.
    srv = wsgi.Server((host, int(port)), app,
                      numthreads=SERVE_THREADS, max=SERVE_MAX_THREADS,     # bounded pool (no OOM growth)
                      request_queue_size=16, timeout=SERVE_TIMEOUT,
                      accepted_queue_size=64, shutdown_timeout=SERVE_SHUTDOWN_TIMEOUT)
    if ssl_context:                                     # (certfile, keyfile) -> terminate TLS in-process
        cert, key = ssl_context
        srv.ssl_adapter = BuiltinSSLAdapter(certificate=str(cert), private_key=str(key))
        # ciphers=None -> stdlib create_default_context() secure defaults (include ECDHE-ECDSA for our
        # P-256 cert). Pin an explicit TLS 1.2 floor; create_default_context only pins it on Python 3.10+.
        srv.ssl_adapter.context.minimum_version = ssl.TLSVersion.TLSv1_2
    srv.prepare()                                       # binds the listen socket (sets SO_REUSEADDR)
    try:
        srv.socket.set_inheritable(False)               # belt-and-suspenders (cheroot already CLOEXECs)
    except Exception:
        pass
    _WSGI_SERVER = srv
    # Route cheroot's error hook through our logger so the appliance stays quiet + single-streamed
    # (cheroot logs no request bodies / auth headers).
    srv.error_log = lambda msg='', level=40, traceback=False: (
        log.error(f"cheroot: {msg}") if level >= 40 else log.info(f"cheroot: {msg}"))
    log.info(f"Serving on {host}:{port} via cheroot "
             f"(threads={SERVE_THREADS}-{SERVE_MAX_THREADS}, keep-alive=on, "
             f"ssl={'on' if ssl_context else 'off'})")
    try:
        srv.serve()                                     # blocks until srv.stop() (restart path)
    finally:
        _WSGI_SERVER = None
    # A restart request makes cheroot's stop() return serve() on THIS main thread; re-exec HERE
    # (deterministic). A daemon restart thread could be killed at interpreter shutdown before reaching
    # execv, leaving the app down on a non-systemd host. execv replaces the image, so main()'s cleanup
    # finally never runs on restart -- matching the pre-cheroot behavior (no relay close on restart).
    if _RESTART_REQUESTED:
        _do_execv()


def _serve_werkzeug(host, port, ssl_context=None, threaded=False):
    """Fallback server (NO HTTP keep-alive) -- the proven pre-cheroot werkzeug path, kept verbatim so an
    install without cheroot still serves. Its serve_forever() never returns on its own, so its restart
    re-execs IN the restart thread (see _schedule_process_restart's fallback branch), not here."""
    global _WSGI_SERVER
    from werkzeug.serving import make_server            # local import: only needed here to serve
    last_err = None
    for attempt in range(10):                           # ~5s total: ride out a draining old port
        try:
            srv = make_server(host, port, app, threaded=threaded, ssl_context=ssl_context)
            break
        except OSError as e:                            # EADDRINUSE while an old socket drains
            # A cert or permission error (ssl.SSLError / FileNotFoundError -- both OSError subclasses)
            # must surface IMMEDIATELY, not after 10 pointless retries (audit review #6).
            if e.errno not in (errno.EADDRINUSE, errno.EADDRNOTAVAIL):
                raise
            last_err = e
            log.warning(f"Bind {host}:{port} busy (attempt {attempt + 1}/10): {e} -- retrying")
            time.sleep(0.5)
    else:                                               # retries exhausted -> surface it clearly
        log.critical(f"Could not bind {host}:{port} after retries: {last_err}")
        raise last_err
    try:
        srv.socket.set_inheritable(False)               # a future exec drops this FD -> no leak
    except Exception:                                   # non-fatal: closing before exec is the
        pass                                            # primary guarantee regardless
    _WSGI_SERVER = srv
    log.info(f"Serving on {host}:{port} via werkzeug fallback "
             f"(threaded={threaded}, NO keep-alive, ssl={'on' if ssl_context else 'off'})")
    try:
        srv.serve_forever()
    finally:
        _WSGI_SERVER = None


def _schedule_process_restart(delay=1.0):
    """Re-exec THIS process after `delay`s so the HTTP response flushes first. It self-respawns with OR
    without a supervisor (systemd), which is why we don't depend on Restart=always. Isolated so tests can
    patch it out. The two server types have OPPOSITE shutdown models:
      * cheroot: set _RESTART_REQUESTED + call stop() -- stop() makes the MAIN thread's serve() return,
        and the re-exec then runs on the MAIN thread in _serve. We do NOT exec here: a daemon thread can
        be killed at interpreter shutdown before reaching execv, which would leave the app down on a
        non-systemd host (the #41 failure).
      * werkzeug fallback: its serve_forever() won't return on its own, so we close the socket and
        re-exec IN this thread (the proven pre-cheroot path)."""
    def _do():
        time.sleep(delay)
        global _RESTART_REQUESTED
        srv = _WSGI_SERVER
        if srv is not None and hasattr(srv, 'stop'):     # cheroot: the MAIN thread owns the exec
            _RESTART_REQUESTED = True                    # set BEFORE stop() (serve() returns after it,
            try:                                         #   so the main thread always observes True)
                srv.stop()                               # sets ready=False -> main serve() returns; also
            except Exception as e:                       #   releases the socket (redundant w/ CLOEXEC)
                log.warning(f"cheroot stop() before restart failed: {e}")
            return                                       # DO NOT exec here -- _serve's main thread does
        # werkzeug fallback (or no server): release the socket + re-exec in THIS thread. os.execv fires
        # on the next line so serve_forever()'s poll loop just drops the closed fd before the image is
        # replaced (audit review #2). Reading the module global is atomic under the GIL.
        _RESTART_REQUESTED = True
        if srv is not None:
            try:
                srv.socket.close()
            except Exception as e:                       # best-effort: exec's CLOEXEC drop is the backstop
                log.warning(f"Could not close listening socket before re-exec: {e}")
        _do_execv()
    threading.Thread(target=_do, daemon=True, name="restart").start()
