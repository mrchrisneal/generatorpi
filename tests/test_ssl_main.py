# test_ssl_main.py -- SSL cert helpers (_cert_expires_within, ensure_ssl_cert) and
# the main() entry point. subprocess.run is always mocked, so openssl is never
# invoked and no real certs are generated. _serve is mocked so no server binds.
import errno
import subprocess
import threading
import time as _t
from unittest import mock

import pytest


class TestCertExpiresWithin:
    def test_returns_false_when_valid(self, module, monkeypatch):
        # openssl -checkend exit 0 => still valid beyond the window => not expiring.
        fake = mock.Mock(returncode=0, stdout="", stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **k: fake)
        assert module._cert_expires_within(30) is False

    def test_returns_true_when_expiring(self, module, monkeypatch):
        # exit 1 => expires within the window.
        fake = mock.Mock(returncode=1, stdout="", stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **k: fake)
        assert module._cert_expires_within(30) is True

    def test_assumes_expired_on_exception(self, module, monkeypatch):
        # Any error checking the cert => fail safe (treat as expired -> regenerate).
        def boom(*a, **k):
            raise subprocess.TimeoutExpired(cmd="openssl", timeout=5)

        monkeypatch.setattr(subprocess, "run", boom)
        assert module._cert_expires_within(30) is True


class TestEnsureSslCert:
    def test_skips_when_cert_valid(self, module, monkeypatch, tmp_path):
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        cert.write_text("x")
        key.write_text("y")
        monkeypatch.setattr(module, "SSL_CERT_PATH", cert)
        monkeypatch.setattr(module, "SSL_KEY_PATH", key)
        # Cert not expiring -> early return, no openssl invocation.
        monkeypatch.setattr(module, "_cert_expires_within", lambda d: False)
        run = mock.Mock()
        monkeypatch.setattr(subprocess, "run", run)
        module.ensure_ssl_cert()
        run.assert_not_called()

    def test_generates_when_missing(self, module, monkeypatch, tmp_path):
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"  # neither exists
        monkeypatch.setattr(module, "SSL_CERT_PATH", cert)
        monkeypatch.setattr(module, "SSL_KEY_PATH", key)
        run = mock.Mock(return_value=mock.Mock(returncode=0, stderr=""))
        monkeypatch.setattr(subprocess, "run", run)
        # Key file isn't really created (openssl mocked), so chmod is a no-op mock.
        monkeypatch.setattr(module.os, "chmod", mock.Mock())
        module.ensure_ssl_cert()
        run.assert_called_once()
        # The generation command is an openssl req -x509 invocation.
        argv = run.call_args[0][0]
        assert argv[0] == "openssl" and "req" in argv and "-x509" in argv

    def test_regenerates_when_expiring(self, module, monkeypatch, tmp_path):
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        cert.write_text("x")
        key.write_text("y")
        monkeypatch.setattr(module, "SSL_CERT_PATH", cert)
        monkeypatch.setattr(module, "SSL_KEY_PATH", key)
        monkeypatch.setattr(module, "_cert_expires_within", lambda d: True)
        run = mock.Mock(return_value=mock.Mock(returncode=0, stderr=""))
        monkeypatch.setattr(subprocess, "run", run)
        monkeypatch.setattr(module.os, "chmod", mock.Mock())
        module.ensure_ssl_cert()
        run.assert_called_once()

    def test_raises_on_generation_failure(self, module, monkeypatch, tmp_path):
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        monkeypatch.setattr(module, "SSL_CERT_PATH", cert)
        monkeypatch.setattr(module, "SSL_KEY_PATH", key)
        run = mock.Mock(return_value=mock.Mock(returncode=1, stderr="boom"))
        monkeypatch.setattr(subprocess, "run", run)
        with pytest.raises(RuntimeError, match="SSL certificate generation failed"):
            module.ensure_ssl_cert()


class TestMain:
    def test_main_ssl_enabled_runs_server(self, module, monkeypatch):
        module.CONFIG["SSL_ENABLED"] = 1
        monkeypatch.setattr(module, "ensure_ssl_cert", mock.Mock())
        monkeypatch.setattr(module.os, "access", lambda p, m: True)  # cert readable
        run = mock.Mock()
        monkeypatch.setattr(module, "_serve", run)
        module.main()
        run.assert_called_once()
        # ssl_context tuple (cert, key) must be passed when SSL is enabled.
        assert run.call_args.kwargs["ssl_context"] is not None
        # Relay closed on shutdown (finally block).
        assert module.relay_start_stop.close.called

    def test_main_ssl_disabled_skips_cert(self, module, monkeypatch):
        module.CONFIG["SSL_ENABLED"] = 0
        ensure = mock.Mock()
        monkeypatch.setattr(module, "ensure_ssl_cert", ensure)
        run = mock.Mock()
        monkeypatch.setattr(module, "_serve", run)
        module.main()
        ensure.assert_not_called()
        assert run.call_args.kwargs["ssl_context"] is None

    def test_main_exits_when_ssl_file_unreadable(self, module, monkeypatch):
        module.CONFIG["SSL_ENABLED"] = 1
        monkeypatch.setattr(module, "ensure_ssl_cert", mock.Mock())
        # cert/key not readable -> critical exit before app.run.
        monkeypatch.setattr(module.os, "access", lambda p, m: False)
        run = mock.Mock()
        monkeypatch.setattr(module, "_serve", run)
        with pytest.raises(SystemExit) as exc:
            module.main()
        assert exc.value.code == 1
        run.assert_not_called()

    def test_main_handles_keyboard_interrupt(self, module, monkeypatch):
        module.CONFIG["SSL_ENABLED"] = 0
        monkeypatch.setattr(module, "_serve", mock.Mock(side_effect=KeyboardInterrupt))
        # Must be caught cleanly; relay still closed in finally.
        module.main()
        assert module.relay_start_stop.close.called


class TestServeAndRestart:
    """The keep-alive server (cheroot) + the non-systemd restart fix. _serve keeps a handle on the
    server so a restart releases the listening socket before re-exec; on the cheroot path the MAIN
    thread re-execs after serve() returns (a daemon thread could be killed at interpreter shutdown
    before reaching execv, leaving the app down -- the #41 failure). The werkzeug fallback keeps its
    proven in-thread close()+execv."""

    @staticmethod
    def _patch_probe_ok(module, monkeypatch):
        """Make the raw-socket bind probe succeed without touching a real port."""
        monkeypatch.setattr(module.socket, "socket", mock.Mock(return_value=mock.Mock()))

    def test_serve_builds_cheroot_and_serves(self, module, monkeypatch):
        import cheroot.wsgi
        self._patch_probe_ok(module, monkeypatch)
        fake_sock = mock.Mock()
        fake_srv = mock.Mock(socket=fake_sock)
        fake_srv.serve.side_effect = KeyboardInterrupt   # serve() blocks IRL; raise to hit the finally
        monkeypatch.setattr(cheroot.wsgi, "Server", mock.Mock(return_value=fake_srv))
        with pytest.raises(KeyboardInterrupt):
            module._serve("127.0.0.1", 5999, threaded=True)
        fake_srv.prepare.assert_called_once()
        fake_sock.set_inheritable.assert_called_once_with(False)
        fake_srv.serve.assert_called_once()

    def test_serve_bounds_thread_pool(self, module, monkeypatch):
        # M1: cheroot MUST get an explicit max= cap (not the unbounded default -1).
        import cheroot.wsgi
        self._patch_probe_ok(module, monkeypatch)
        fake_srv = mock.Mock(socket=mock.Mock())
        fake_srv.serve.side_effect = KeyboardInterrupt
        made = mock.Mock(return_value=fake_srv)
        monkeypatch.setattr(cheroot.wsgi, "Server", made)
        with pytest.raises(KeyboardInterrupt):
            module._serve("127.0.0.1", 5999)
        assert made.call_args.kwargs["max"] == module.SERVE_MAX_THREADS

    def test_serve_builds_ssl_adapter_with_tls_floor(self, module, monkeypatch):
        # ssl_context -> a BuiltinSSLAdapter is built with the cert/key and pinned to TLS 1.2.
        import ssl as _ssl
        import cheroot.wsgi
        import cheroot.ssl.builtin
        self._patch_probe_ok(module, monkeypatch)
        fake_srv = mock.Mock(socket=mock.Mock())
        fake_srv.serve.side_effect = KeyboardInterrupt
        monkeypatch.setattr(cheroot.wsgi, "Server", mock.Mock(return_value=fake_srv))
        fake_adapter = mock.Mock(context=mock.Mock())
        made = mock.Mock(return_value=fake_adapter)
        monkeypatch.setattr(cheroot.ssl.builtin, "BuiltinSSLAdapter", made)
        with pytest.raises(KeyboardInterrupt):
            module._serve("127.0.0.1", 5999, ssl_context=("/c.pem", "/k.pem"))
        assert made.call_args.kwargs == {"certificate": "/c.pem", "private_key": "/k.pem"}
        assert fake_srv.ssl_adapter is fake_adapter
        assert fake_adapter.context.minimum_version == _ssl.TLSVersion.TLSv1_2

    def test_serve_retries_only_address_in_use(self, module, monkeypatch):
        # The raw-socket PROBE yields a REAL errno (cheroot's prepare() masks it): EADDRINUSE retries,
        # but a non-address error (EACCES) surfaces immediately -- not buried under 10 retries (audit #6).
        import errno as _errno
        monkeypatch.setattr(module.time, "sleep", lambda s: None)
        fake_probe = mock.Mock()
        fake_probe.bind.side_effect = OSError(_errno.EACCES, "permission denied")
        monkeypatch.setattr(module.socket, "socket", mock.Mock(return_value=fake_probe))
        with pytest.raises(OSError) as exc:
            module._serve("127.0.0.1", 5999)
        assert exc.value.errno == _errno.EACCES

    def test_serve_retries_eaddrinuse_then_succeeds(self, module, monkeypatch):
        # First probe bind hits EADDRINUSE (draining old port), second succeeds -> cheroot serves.
        import errno as _errno
        import cheroot.wsgi
        monkeypatch.setattr(module.time, "sleep", lambda s: None)
        seen = []

        def make_probe(*a, **k):
            p = mock.Mock()
            if not seen:
                p.bind.side_effect = OSError(_errno.EADDRINUSE, "in use")
            seen.append(p)
            return p

        monkeypatch.setattr(module.socket, "socket", make_probe)
        fake_srv = mock.Mock(socket=mock.Mock())
        fake_srv.serve.side_effect = KeyboardInterrupt
        monkeypatch.setattr(cheroot.wsgi, "Server", mock.Mock(return_value=fake_srv))
        with pytest.raises(KeyboardInterrupt):
            module._serve("127.0.0.1", 5999)
        assert len(seen) == 2                      # retried once, then bound
        fake_srv.serve.assert_called_once()

    def test_serve_falls_back_to_werkzeug_when_cheroot_missing(self, module, monkeypatch):
        # cheroot import failing -> _serve_werkzeug is used so the app STILL serves (belt-and-suspenders).
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *a, **k):
            if name.startswith("cheroot"):
                raise ImportError("no cheroot")
            return real_import(name, *a, **k)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        fallback = mock.Mock()
        monkeypatch.setattr(module.lifecycle, "_serve_werkzeug", fallback)
        module._serve("127.0.0.1", 5999, threaded=True)
        fallback.assert_called_once()

    def test_restart_cheroot_stops_and_defers_execv_to_main_thread(self, module, monkeypatch):
        # cheroot branch: stop() is called, the flag is set, execv is NOT called in this thread, and
        # the socket is NOT closed (cheroot's stop() owns that).
        monkeypatch.setattr(module.lifecycle, "_RESTART_REQUESTED", False)
        fake_srv = mock.Mock(spec=["stop", "socket"])   # has .stop -> cheroot branch
        monkeypatch.setattr(module.lifecycle, "_WSGI_SERVER", fake_srv)
        monkeypatch.setattr(module.time, "sleep", lambda s: None)
        execv = mock.Mock()
        monkeypatch.setattr(module.os, "execv", execv)
        module._schedule_process_restart(delay=0)
        import time as _t
        for _ in range(400):                            # wait for the restart thread to run stop()
            if fake_srv.stop.called:
                break
            _t.sleep(0.005)
        assert fake_srv.stop.called
        assert module.lifecycle._RESTART_REQUESTED is True
        execv.assert_not_called()                       # the MAIN thread owns the exec, not this one
        fake_srv.socket.close.assert_not_called()
        monkeypatch.setattr(module.lifecycle, "_RESTART_REQUESTED", False)   # isolation

    def test_serve_execs_on_main_thread_when_restart_requested(self, module, monkeypatch):
        # After serve() returns with the flag set, _serve re-execs on the (main) thread.
        import cheroot.wsgi
        self._patch_probe_ok(module, monkeypatch)
        fake_srv = mock.Mock(socket=mock.Mock())
        fake_srv.serve.return_value = None              # returns cleanly, as after stop()
        monkeypatch.setattr(cheroot.wsgi, "Server", mock.Mock(return_value=fake_srv))
        monkeypatch.setattr(module.lifecycle, "_RESTART_REQUESTED", True)
        execv = mock.Mock()
        monkeypatch.setattr(module.lifecycle, "_do_execv", execv)
        module._serve("127.0.0.1", 5999)
        execv.assert_called_once()
        monkeypatch.setattr(module.lifecycle, "_RESTART_REQUESTED", False)   # isolation

    def test_restart_werkzeug_fallback_closes_socket_before_reexec(self, module, monkeypatch):
        # Fallback server has .socket but NO .stop -> close the socket, then execv, IN this thread.
        monkeypatch.setattr(module.lifecycle, "_RESTART_REQUESTED", False)
        calls = []
        fake_sock = mock.Mock()
        fake_sock.close.side_effect = lambda: calls.append("close")
        fake_srv = mock.Mock(spec=["socket"])           # no .stop -> werkzeug fallback branch
        fake_srv.socket = fake_sock
        monkeypatch.setattr(module.lifecycle, "_WSGI_SERVER", fake_srv)
        monkeypatch.setattr(module.time, "sleep", lambda s: None)
        done = threading.Event()

        def fake_execv(*a, **k):
            calls.append("execv")
            done.set()

        monkeypatch.setattr(module.os, "execv", fake_execv)
        module._schedule_process_restart(delay=0)
        assert done.wait(2), "restart thread never ran"
        assert calls == ["close", "execv"], f"socket must close BEFORE execv, got {calls}"
        monkeypatch.setattr(module.lifecycle, "_RESTART_REQUESTED", False)   # isolation

    def test_restart_cheroot_stop_exception_is_logged_and_defers(self, module, monkeypatch):
        # If cheroot's stop() raises, the restart thread must SWALLOW it (logged as a warning) and
        # still NOT exec in this thread -- the main thread owns the exec after serve() returns.
        monkeypatch.setattr(module.lifecycle, "_RESTART_REQUESTED", False)
        fake_srv = mock.Mock(spec=["stop", "socket"])   # has .stop -> cheroot branch
        fake_srv.stop.side_effect = RuntimeError("stop boom")
        monkeypatch.setattr(module.lifecycle, "_WSGI_SERVER", fake_srv)
        monkeypatch.setattr(module.time, "sleep", lambda s: None)
        execv = mock.Mock()
        monkeypatch.setattr(module.os, "execv", execv)
        warnings = []
        monkeypatch.setattr(module.log, "warning", lambda m, *a, **k: warnings.append(m))
        module._schedule_process_restart(delay=0)
        for _ in range(400):                            # wait for the restart thread's warning
            if warnings:
                break
            _t.sleep(0.005)
        assert any("cheroot stop()" in w for w in warnings), warnings
        assert module.lifecycle._RESTART_REQUESTED is True        # flag still set before the failed stop()
        execv.assert_not_called()                       # never exec in this thread on the cheroot path
        monkeypatch.setattr(module.lifecycle, "_RESTART_REQUESTED", False)   # isolation


class TestServeWerkzeugFallback:
    """The proven pre-cheroot werkzeug server (`_serve_werkzeug`) used when cheroot is absent.
    make_server is always mocked so nothing binds a real port; serve_forever returns immediately
    so the call doesn't block. Covers the bind-retry loop, the fail-fast on non-address errors,
    and the retries-exhausted surface."""

    def _fake_server(self):
        srv = mock.Mock(socket=mock.Mock())
        srv.serve_forever.return_value = None           # returns at once instead of blocking
        return srv

    def test_binds_serves_then_clears_handle(self, module, monkeypatch):
        import werkzeug.serving
        srv = self._fake_server()
        monkeypatch.setattr(werkzeug.serving, "make_server", mock.Mock(return_value=srv))
        module._serve_werkzeug("127.0.0.1", 5999)
        srv.serve_forever.assert_called_once()
        srv.socket.set_inheritable.assert_called_once_with(False)   # drop FD across a future exec
        assert module.lifecycle._WSGI_SERVER is None              # handle cleared in the finally

    def test_retries_eaddrinuse_then_binds(self, module, monkeypatch):
        import werkzeug.serving
        monkeypatch.setattr(module.time, "sleep", lambda s: None)
        srv = self._fake_server()
        attempts = []

        def make(*a, **k):
            attempts.append(1)
            if len(attempts) < 3:                       # first two binds fail on a draining port
                raise OSError(errno.EADDRINUSE, "address in use")
            return srv
        monkeypatch.setattr(werkzeug.serving, "make_server", make)
        module._serve_werkzeug("127.0.0.1", 5999)
        assert len(attempts) == 3                        # rode out two EADDRINUSE, then bound
        srv.serve_forever.assert_called_once()

    def test_non_address_oserror_surfaces_immediately(self, module, monkeypatch):
        # A permission/cert error (not EADDRINUSE/EADDRNOTAVAIL) must NOT be buried under 10 retries.
        import werkzeug.serving
        monkeypatch.setattr(module.time, "sleep", lambda s: None)
        attempts = []

        def make(*a, **k):
            attempts.append(1)
            raise OSError(errno.EACCES, "permission denied")
        monkeypatch.setattr(werkzeug.serving, "make_server", make)
        with pytest.raises(OSError) as exc:
            module._serve_werkzeug("127.0.0.1", 5999)
        assert exc.value.errno == errno.EACCES
        assert len(attempts) == 1                        # surfaced on the first try, no retries

    def test_retries_exhausted_raises_last_error(self, module, monkeypatch):
        import werkzeug.serving
        monkeypatch.setattr(module.time, "sleep", lambda s: None)

        def make(*a, **k):
            raise OSError(errno.EADDRINUSE, "still in use")
        monkeypatch.setattr(werkzeug.serving, "make_server", make)
        with pytest.raises(OSError) as exc:
            module._serve_werkzeug("127.0.0.1", 5999)
        assert exc.value.errno == errno.EADDRINUSE       # the for/else surfaces the last bind error

    def test_set_inheritable_failure_is_swallowed(self, module, monkeypatch):
        # set_inheritable is best-effort (CLOEXEC-on-exec is the real guarantee); a failure here
        # must not stop the server from coming up.
        import werkzeug.serving
        srv = self._fake_server()
        srv.socket.set_inheritable.side_effect = OSError("cannot set")
        monkeypatch.setattr(werkzeug.serving, "make_server", mock.Mock(return_value=srv))
        module._serve_werkzeug("127.0.0.1", 5999)        # must not raise
        srv.serve_forever.assert_called_once()
