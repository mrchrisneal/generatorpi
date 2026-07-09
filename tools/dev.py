#!/usr/bin/env python3
# =============================================================================
# tools/dev.py -- LOCAL development harness for GeneratorPi.
#
#   ****  DEVELOPMENT ONLY  ****
#   * MOCK GPIO -- gpiozero is mocked in sys.modules BEFORE the app imports, so NO
#     real pin is ever driven and the relay is NEVER actuated. Never touches hardware.
#   * DEV CREDENTIALS ARE LOCAL-ONLY -- the default dev/dev Basic-auth user (and the
#     "dev" API key) exist ONLY in this process's memory; they are never written to the
#     env file and never leave this box.
#   * NEVER SHIPPED -- tools/ is gitignored-by-default and this file is NOT in the
#     updater manifest (SHIPPED_FILES). It can never reach the Pi via an update.
#   * DO NOT EXPOSE TO THE PUBLIC INTERNET -- it binds 0.0.0.0 so it is reachable over
#     the LAN / Tailscale for on-device testing; that reach is for a trusted network
#     only. It is a convenience runner, not a hardened deployment.
#
# What it does (a clean, argparse-driven local dev runner):
#   generator_control.py builds an OutputDevice from gpiozero AT IMPORT, so gpiozero is
#   mocked first. The app is then configured for local dev (known key, plain HTTP by
#   default, a dev Basic-auth user, a relaxed brute-force limiter, a fast sampler
#   cadence) and served via the app's REAL _serve() -- the production cheroot path that
#   can release the listening socket for an os.execv restart -- NOT app.run().
#
# The SYSTEM drawer's metrics are 100% REAL: CPU / MEM / LOAD / TEMP / WiFi are read
# from /proc + sysfs on THIS host. VOLTAGE / THROTTLE come from vcgencmd (Pi-only), so
# off-Pi they read null -- exactly what a non-Pi host honestly shows, nothing faked.
# =============================================================================
import argparse
import os
import sys
import threading
import time
import unittest.mock as _mock

# The repo root (parent of tools/) holds generator_control.py. Add it to sys.path so
# the import resolves regardless of the current working directory the launcher used.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)

# --- Mock gpiozero BEFORE importing the app: it constructs an OutputDevice (the relay)
# at import time. Mocking here guarantees no real pin factory is ever loaded, so no GPIO
# line is touched and the physical relay can never be actuated from this harness.
sys.modules["gpiozero"] = _mock.MagicMock()

import generator_control as gc  # noqa: E402  (must follow the gpiozero mock above)


def _configure_dev(args):
    """Apply the dev-only CONFIG overrides + seed a dev auth user. Everything here is
    in-memory for THIS process only -- nothing is persisted to the env file."""
    # Known local key + plain HTTP (unless --ssl) + a fast sampler cadence for liveliness.
    gc.CONFIG["API_KEY"] = "dev"
    gc.CONFIG["API_KEY_ENABLED"] = 1
    gc.CONFIG["SSL_ENABLED"] = 1 if args.ssl else 0
    gc.CONFIG["SYSTEM_HISTORY_SECONDS"] = 4      # dev cadence: sample every 4s
    gc.CONFIG["SYSTEM_HISTORY_POINTS"] = 900     # 900 x 4s = 1h, so the 60m toggle has data
    # The ring buffer was sized from CONFIG at import; re-create it at the dev size so the
    # seed loop + the 60-minute view both have the expected capacity.
    gc._sys_history = gc.collections.deque(maxlen=900)

    # A dev Basic-auth user so a BROWSER can authenticate: the page's fetch() calls don't
    # append ?key=, so -- exactly like production -- they rely on the browser resending the
    # cached Basic credentials on every poll. Navigate to http://user:pass@host:port/ once
    # so the browser caches them. Without this, every poll 401s and trips the limiter.
    gc.AUTH_USERS[args.user] = gc.generate_password_hash(args.password)

    # Relax the brute-force limiter for local dev so a few stray 401s (e.g. the first
    # navigation before creds are cached) don't lock us out of our own dev box.
    gc.CONFIG["RATE_LIMIT_MAX_FAILURES"] = 100000
    gc._fail_tracker.clear()

    # --no-auth: fully disable auth for a purely local UI test. The auth_required decorator
    # looks up check_api_key by GLOBAL name at call time, so replacing it here makes EVERY
    # request pass via the key path -- no credentials needed. DEV-ONLY; never do this in prod.
    if args.no_auth:
        gc.check_api_key = lambda: True


def _real_snapshot():
    """One point read entirely from the app's REAL readers (no fakery). volt/thr come back
    None off-Pi (no vcgencmd), which is the honest, correct off-Pi behavior."""
    load1, load5 = gc._read_loadavg()
    rssi, qual = gc._read_wifi()
    return {
        "cpu": gc._cpu_pct(),
        "mem": gc._read_mem_pct(),
        "load1": load1, "load5": load5,
        "temp": gc._read_temp_c(),
        "volt": gc._read_volt(),      # None on a non-Pi host (no vcgencmd) -- honest
        "thr": gc._read_throttled(),  # None on a non-Pi host -- honest
        "rssi": rssi, "qual": qual,
    }


def _live_sampler():
    """Seed the ring buffer from a REAL current snapshot so the charts aren't empty on
    open, then run the app's REAL sampler forever on the dev cadence. Every value is real;
    the Pi-only metrics simply read null off-Pi."""
    interval = max(1, int(gc.CONFIG["SYSTEM_HISTORY_SECONDS"]))
    gc._cpu_pct()                 # prime the CPU delta baseline so the first snapshot has a value
    time.sleep(0.15)
    snap = _real_snapshot()
    now = time.time()
    n = gc._sys_history.maxlen
    for i in range(n):            # flat seed at the real current values (volt/thr null off-Pi)
        p = dict(snap)
        p["t"] = int(now - (n - i) * interval)
        gc._sys_history.append(p)
    while True:
        gc._sample_system()       # 100% real readers, on the dev cadence
        time.sleep(interval)


def _build_ssl_context(host, port):
    """When --ssl is requested, drive the app's OWN self-signed cert path (ensure_ssl_cert)
    and return the (certfile, keyfile) tuple _serve expects -- exactly what main() does."""
    gc.ensure_ssl_cert()          # auto-provision/renew the self-signed cert (app's own logic)
    for path in (gc.SSL_CERT_PATH, gc.SSL_KEY_PATH):
        if not os.access(path, os.R_OK):
            sys.exit(f"SSL file not readable: {path} -- fix its permissions/ownership.")
    return (str(gc.SSL_CERT_PATH), str(gc.SSL_KEY_PATH))


def _parse_args(argv=None):
    """Argparse front end. Defaults bind 0.0.0.0 so the dev UI is reachable over the LAN /
    Tailscale (e.g. from a phone), on port 5000, with dev/dev Basic auth over plain HTTP."""
    p = argparse.ArgumentParser(
        prog="tools/dev.py",
        description="GeneratorPi LOCAL dev server (mock GPIO -- never touches hardware). "
                    "DEV ONLY; dev creds are local-only; never shipped; do not expose publicly.",
    )
    p.add_argument("--host", default="0.0.0.0",
                   help="bind address (default 0.0.0.0 -- reachable over Tailscale/LAN)")
    p.add_argument("--port", type=int, default=5000, help="listen port (default 5000)")
    p.add_argument("--user", default="dev", help="dev Basic-auth username (default 'dev')")
    p.add_argument("--pass", dest="password", default="dev",
                   help="dev Basic-auth password (default 'dev')")
    p.add_argument("--no-auth", action="store_true",
                   help="disable auth entirely for a purely local UI test (DEV ONLY)")
    p.add_argument("--ssl", action="store_true",
                   help="serve HTTPS via the app's self-signed cert path (default: plain HTTP)")
    return p.parse_args(argv)


def main(argv=None):
    args = _parse_args(argv)
    _configure_dev(args)

    # Build the SSL context (or None for plain HTTP) the same way main() does.
    ssl_context = _build_ssl_context(args.host, args.port) if args.ssl else None
    scheme = "https" if args.ssl else "http"

    # The open-me URL. With --no-auth there are no creds to embed; otherwise embed the dev
    # creds so the browser caches Basic auth on first navigation (the polling fetch()es need it).
    if args.no_auth:
        url = f"{scheme}://{args.host}:{args.port}/"
    else:
        url = f"{scheme}://{args.user}:{args.password}@{args.host}:{args.port}/"

    # Loud, unmissable dev banner. The mandated warning leads on its own boxed, blank-line
    # separated line so it can never be missed or reworded, then the detail follows.
    print()
    print("#" * 72)
    print("WARNING: FOR DEVELOPMENT USE ONLY. DO NOT RUN ON A LIVE DEVICE.")
    print("#" * 72)
    print()
    print("=" * 72)
    print("GeneratorPi DEV server -- DEVELOPMENT ONLY")
    print("  * MOCK GPIO: no hardware touched, relay NEVER actuated")
    print("  * dev credentials are LOCAL-ONLY; never shipped / not in the manifest")
    print("  * do NOT expose to the public internet")
    print(f"  Open me -> {url}")
    if args.no_auth:
        print("  AUTH DISABLED (--no-auth): every request passes without credentials")
    print("  SYSTEM drawer metrics are REAL; VOLTAGE/THROTTLE read null off-Pi (no vcgencmd)")
    print("=" * 72)
    # FLUSH the banner NOW: stdout is block-buffered when the launcher redirects it to a
    # logfile (not a tty), so without this the warning would sit unflushed and be lost if the
    # process is later killed. Flushing guarantees the mandated warning is visible immediately,
    # whether run in a terminal or captured by dev.sh.
    sys.stdout.flush()

    # Start the REAL /proc-based system sampler (seeds the ring buffer, then loops the app's
    # own _sample_system on the dev cadence). Daemon so it dies with the process.
    threading.Thread(target=_live_sampler, daemon=True).start()

    # Serve via the app's _serve() (NOT app.run) -- the production cheroot path that can
    # release the listening socket before an os.execv restart. threaded=True is vestigial
    # (cheroot always pools) but matches the app's own call site.
    gc._serve(host=args.host, port=args.port, ssl_context=ssl_context, threaded=True)


if __name__ == "__main__":
    main()
