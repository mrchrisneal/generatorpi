# genpi/__init__.py -- GeneratorPi application package. Remote start/stop controller for a
# Powermate PM9400E generator via a Raspberry Pi GPIO relay, exposing a self-contained Flask
# web UI + REST API that deploys and runs light on a Pi. Historically a single file; being
# decomposed into an EAGERLY-imported package (roadmap #59) -- this module still holds the bulk
# of the app and is peeled section-by-section into sibling submodules, each imported at startup
# so all application code stays resident in RAM. Handles auth (API key + Basic Auth), a durable
# event log + fuel/runtime state (SQLite), the relay start/stop sequence, and the inline
# HTML/CSS/JS control panel. Entrypoint: `python3 -m genpi` (see genpi/__main__.py).
#
# Copyright (C) 2026 Chris Neal <https://neal.media> and Alex Neal <https://neal.tools>
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify it under the
# terms of the GNU Affero General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later version.
# Distributed WITHOUT ANY WARRANTY. See the GNU AGPL v3 (the LICENSE file, or
# https://www.gnu.org/licenses/agpl-3.0.html) for full terms.
#
# [update-swap verification marker | 2026-07-07] This comment is present in the released copy on
# GitHub. If it appears on disk after an in-app update, the updater successfully downloaded and
# swapped this file from GitHub. Harmless; may be kept or dropped in a later release.
import logging
import logging.handlers
import errno
import os
import sys
import time
import threading
import collections
import subprocess
import hmac
import base64
import json
import math
import ipaddress
import secrets
import socket
import ssl               # TLS version floor on the cheroot server's SSL adapter (keep-alive server swap)
import sqlite3
import re              # manifest version charset validation (self-updater)
import hashlib         # SHA-256 verification of downloaded release files (self-updater)
import importlib.util  # find_spec: check a manifest-declared dep is importable (no side-effect import)
import shutil          # staging dir management for the self-updater
import stat            # preserve file permission bits (exec bit) across an update swap
import shlex           # safe quoting when generating the swap/restart shell script
import zipfile         # ZIP backup of the project root before a self-update (rollback)
import tempfile        # the self-update swap script runs from /tmp (can replace every file)
from functools import wraps
from urllib.parse import urlparse
import urllib.request  # server-side fetch of the repo's raw VERSION for update checks
from flask import Flask, render_template_string, jsonify, request, Response, g
from datetime import datetime
from pathlib import Path

# ============================================================================
# CONFIGURATION + CREDENTIALS  (peeled into genpi/config.py -- roadmap #59, Stage 2)
# ============================================================================
# The CONFIG defaults, env-file parsing + credentials, runtime paths, app version, and the
# OPTIONAL Web-Push library guard now live in genpi/config.py -- LAYER 0, imported first and
# depending on nothing else in the package. Importing it here runs its import-time side effects
# (settings-file security check, then env parse/rewrite + credential load) EXACTLY as before; we
# then re-export its public surface so the not-yet-peeled code below -- and the test suite's
# gc.<symbol> access -- keeps working unchanged.
from . import config
from .config import (               # noqa: F401  (re-exported for the rest of this module + tests)
    CONFIG, AUTH_USERS, SCRIPT_DIR, ENV_FILE, APP_VERSION, _STARTED_AT, HASH_PREFIXES,
    _read_app_version, parse_env_file, check_settings_file_security,
)
# Web Push is OPTIONAL: on a Pi without python3-py-vapid/http-ece/requests the guard in config.py
# sets _PUSH_AVAILABLE=False and NEVER binds the library symbols, so we mirror that here -- re-
# export the library names ONLY when they exist -- to preserve graceful degradation (an
# unconditional import of a missing name would crash startup). The push code further below is
# itself guarded by _PUSH_AVAILABLE, so these names are only ever touched when present.
_PUSH_AVAILABLE = config._PUSH_AVAILABLE
_PUSH_LIB_HINT = config._PUSH_LIB_HINT
if _PUSH_AVAILABLE:                 # libs present in dev/CI; the False path is device-only
    Vapid = config.Vapid
    _vapid_b64 = config._vapid_b64
    _crypto_serialization = config._crypto_serialization
    _crypto_ec = config._crypto_ec
    http_ece = config.http_ece
    requests = config.requests


# ============================================================================
# LOGGING  (peeled into genpi/logg.py -- roadmap #59, Stage 2)
# ============================================================================
# The application logger + its rotating file/console handlers now live in genpi/logg.py (LAYER 1:
# depends only on genpi.config). Importing it here emits the startup log lines and silences
# Werkzeug's access log EXACTLY as before; we then re-export `log` (used throughout) and
# `log_path` (read by the log-viewer + factory-reset routes) for the not-yet-peeled code below
# and the test suite's gc.<symbol> access.
from . import logg
from .logg import log, log_path      # noqa: F401  (re-exported for the rest of this module + tests)

# ============================================================================
# EVENT STORE + WEB PUSH  (peeled into genpi/store.py -- roadmap #59, Stage 3)
# ============================================================================
# The durable SQLite event log + kv store + push-subscription table AND the Web-Push send path
# (encrypt + VAPID-sign + POST) now live in genpi/store.py (LAYER 2: depends on config + logg).
# Importing it here opens the event DB + records the startup event EXACTLY as before (init runs at
# store import). NOTE the split ORDER vs the original plan sketch: store is peeled BEFORE state,
# because state's load_persisted_state / _apply_running_transition / set_total_run_hours call
# kv_get/kv_set -- state depends on store, and store depends on neither (verified). We re-export the
# store surface for the routes/control/fuel/state code below and the test suite. _event_lock is a
# shared object (safe to re-export by reference); _event_conn/_event_db_path are REBOUND by
# init_event_store(), so every reader (the factory-reset route below + tests) references
# store._event_conn directly to avoid a stale re-exported copy.
from . import store
from .store import (               # noqa: F401  (re-exported for the rest of this module + tests)
    init_event_store, record_event, get_events, get_latest_seq, kv_get, kv_set,
    add_subscription, remove_subscription, get_subscriptions, subscription_count,
    push_status, push_available, send_push, send_push_async, _deliver_push,
    _vapid_key_valid, _b64url_decode, PUSH_TTL_SECONDS, _event_lock,
)

# ============================================================================
# SSL CERTIFICATE MANAGEMENT  (peeled into genpi/ssl_cert.py -- roadmap #59, Stage 10)
# ============================================================================
# The self-signed-cert auto-provision/renew (auto mode) + operator-provided-cert (manual mode) logic
# now lives in genpi/ssl_cert.py (LAYER 2: depends only on config + logg). It is used ONLY by main()
# below -- no route or other submodule touches it. We re-export ensure_ssl_cert + the resolved
# SSL_CERT_PATH/SSL_KEY_PATH for main(), and the helpers for the tests. SSL_CERT_PATH/SSL_KEY_PATH are
# MODULE SCALARS read by ssl_cert's own code, so the tests that REBIND them (then call ensure_ssl_cert
# / _generate_self_signed) patch module.ssl_cert.SSL_CERT_PATH; likewise _cert_expires_within /
# _generate_self_signed, which ensure_ssl_cert calls INTRA-module, are patched as module.ssl_cert.* (a
# bare re-exported copy would be a silent no-op). socket.gethostname / os.chmod are patched on the
# shared stdlib singletons (module.socket / module.os), which ssl_cert reads by reference.
from . import ssl_cert
from .ssl_cert import (             # noqa: F401  (re-exported for main() + the tests)
    _resolve_ssl_path, SSL_CERT_PATH, SSL_KEY_PATH, _cert_expires_within,
    _build_san, _generate_self_signed, ensure_ssl_cert,
)

# ============================================================================
# RATE LIMITING  (peeled into genpi/ratelimit.py -- roadmap #59, Stage 5)
# ============================================================================
# The per-IP failed-auth tracker + lockout logic now lives in genpi/ratelimit.py (LAYER 2: depends
# on config + logg). We re-export it for auth_required below and the test suite. The tracker map +
# its lock are shared by REFERENCE (conftest clears their CONTENTS between tests); _last_cleanup is a
# SCALAR rebound by _cleanup_tracker (and the ratelimit tests), so its readers/rebinds reference
# ratelimit._last_cleanup directly -- the conftest reset + test_ratelimit patch it as
# module.ratelimit._last_cleanup.
from . import ratelimit
from .ratelimit import (          # noqa: F401  (re-exported for auth_required below + tests)
    is_rate_limited, record_failure, record_success, _cleanup_tracker,
    _fail_tracker, _fail_tracker_lock,
)

# ============================================================================
# AUTHENTICATION  (peeled into genpi/auth.py -- roadmap #59, Stage 5)
# ============================================================================
# The API-key + HTTP-Basic auth path, the scrypt verification cache, the anti-enumeration dummy
# hash, and caller_identity now live in genpi/auth.py (LAYER 3: config + logg + ratelimit).
# auth_required decorates every protected route below, so it is re-exported here (a bare name the
# routes reference). The _auth_cache dict + its lock are shared by REFERENCE (conftest + test_auth
# mutate their CONTENTS); _AUTH_CACHE_TTL is a scalar READ by check_auth, so test_auth patches it as
# module.auth._AUTH_CACHE_TTL (a re-exported copy would be a silent no-op).
from . import auth
from .auth import (                # noqa: F401  (re-exported for the routes below + tests)
    auth_required, check_auth, check_api_key, caller_identity,
    _auth_cache, _auth_cache_lock, _auth_cache_key, _DUMMY_HASH, _AUTH_CACHE_MAX,
)
# ============================================================================
# GLOBAL STATE  (peeled into genpi/state.py -- roadmap #59, Stage 4)
# ============================================================================
# generator_state, the fuel model (fuel_state) + alerts (alerts_state), their coarse state_lock,
# the run-hours accounting helpers, and set_total_run_hours now live in genpi/state.py (LAYER 2:
# depends on store + logg). Importing it restores durable state from the kv store EXACTLY as before.
# The state dicts, state_lock, and the _monitor_stop Event are re-exported by REFERENCE -- the test
# suite and the not-yet-peeled route code mutate their CONTENTS, which is shared. _low_fuel_alerted
# lives in state and is read/written by the fuel monitor in genpi/fuel.py (Stage 7) as
# state._low_fuel_alerted, so it is NOT re-exported here (a bare copy would go stale on every rebind).
from . import state
from .state import (               # noqa: F401  (re-exported for the rest of this module + tests)
    generator_state, state_lock, fuel_state, alerts_state, FUEL_DEFAULT_RATE,
    _monitor_stop, MAX_TOTAL_RUN_HOURS, load_persisted_state,
    _live_total_run_hours_locked, _apply_running_transition_locked, set_total_run_hours,
)

# ============================================================================
# GPIO RELAY  (peeled into genpi/relay.py -- roadmap #59, Stage 6)
# ============================================================================
# The relay lock, the OutputDevice handle, and press_button now live in genpi/relay.py (LAYER 3:
# config + logg + gpiozero). SAFETY is unchanged: the relay is created DE-ENERGIZED at import
# (initial_value=False) and press_button de-energizes it in a finally on EVERY exit path. relay_lock
# + relay_start_stop are shared objects (re-exported by REFERENCE so the control sequences below, the
# shutdown close(), and the tests all act on the same lock/device); press_button is re-exported for
# the control sequences (Stage 6b moves those out too).
from . import relay
from .relay import relay_lock, relay_start_stop, press_button   # noqa: F401  (re-exported for control + tests)

# ============================================================================
# GENERATOR CONTROL LOGIC  (peeled into genpi/control.py -- roadmap #59, Stage 6)
# ============================================================================
# The generator start/stop sequences now live in genpi/control.py (LAYER 4: relay + state + store +
# config + logg). They drive the relay ONLY through press_button and are reachable ONLY from the
# authenticated /api/start | /api/stop routes below. Re-exported for those routes + the tests.
from . import control
from .control import start_generator, stop_generator   # noqa: F401  (re-exported for the routes below + tests)

# ============================================================================
# ============================================================================
# FUEL PROJECTION + LOW-FUEL ALERTS  (peeled into genpi/fuel.py -- roadmap #59, Stage 7)
# ============================================================================
# The fuel projection model, the edge-triggered low-fuel evaluator, the fuel_monitor_loop daemon,
# and the operator mutators now live in genpi/fuel.py (LAYER 3: state + store + config + logg). None
# touch the relay. Re-exported for the /api/fuel|alerts routes below, the main() thread start, and
# the tests. evaluate_low_fuel is patched by the low-fuel tests to intercept fuel_monitor_loop's
# intra-module call, so those patches target module.fuel.evaluate_low_fuel; _low_fuel_alerted stays
# in state (fuel reads/writes it as state._low_fuel_alerted), so its rebinds target module.state.
from . import fuel
from .fuel import (               # noqa: F401  (re-exported for the routes below + tests)
    _round1, fuel_snapshot_locked, projected_fuel_level_locked, FUEL_ALERT_REARM_MARGIN,
    evaluate_low_fuel, fuel_monitor_loop, FUEL_MIN_RUN_SINCE_FILL, record_fuel_reading,
    set_fuel_rate, reset_fuel_rate, set_fuel_fill, set_alerts,
)
# ============================================================================
# SYSTEM PERF MONITOR  (peeled into genpi/sysmon.py -- roadmap #59, Stage 7)
# ============================================================================
# The host-metrics readers, the sampler, and the system_monitor_loop daemon now live in
# genpi/sysmon.py (LAYER 3: config + logg + state). Re-exported for the /api/system/* routes below,
# the main() thread start, and the tests. _sys_history + _sys_hist_lock are shared by REFERENCE
# (tests mutate the deque's CONTENTS); the _read_* helpers + _sample_system are re-exported so the
# tests that patch them to intercept _sample_system / the loop can target module.sysmon.<name>.
from . import sysmon
from .sysmon import (             # noqa: F401  (re-exported for the routes below + tests)
    SYS_FIELDS, _sys_history, _sys_hist_lock, _prev_cpu,
    _read_cpu_times, _read_loadavg, _read_mem_pct, _read_temp_c,
    _read_wifi, _read_volt, _read_throttled, _sample_system, system_monitor_loop,
)


# ============================================================================
# INLINE UI TEMPLATE  (peeled into genpi/ui.py + genpi/frontend/* -- roadmap #59, Stage 2)
# ============================================================================
# The self-contained control-panel page -- its CSS, vanilla JS, body shell, and the push service
# worker -- now lives as EDITABLE source files under genpi/frontend/ and is assembled at import by
# genpi/ui.py into the EXACT same template strings as before. The page is still served 100% INLINE
# (inline <style> + inline <script>, zero external assets), so the strict CSP (default-src 'none')
# is UNCHANGED: ui.py wraps the CSS/JS in the same {% raw %}<style>/<script> markers and the index
# route still calls render_template_string(HTML_TEMPLATE, ...). The frontend/*.css/.js/.html files
# ship as code (gen-manifest globs them) and are read at import, so a missing asset fails fast on
# startup. We re-export the assembled templates for the index + /sw.js routes below (and tests).
from . import ui
from .ui import (                   # noqa: F401  (re-exported for the routes below + tests)
    HTML_TEMPLATE, HTML_TEMPLATE_HEAD, HTML_TEMPLATE_SCRIPT, HTML_TEMPLATE_BODY,
    SERVICE_WORKER_JS,
)

# ============================================================================
# ROUTE-LAYER NUMERIC HELPER  (peeled into genpi/routes/_helpers.py -- roadmap #59, Stage 9)
# ============================================================================
# _json_number (the shared numeric JSON-body parser used by the runtime-hours + fuel/alerts routes)
# now lives in genpi/routes/_helpers.py. Re-exported here as gc._json_number for the test suite.
from .routes._helpers import _json_number   # noqa: F401  (re-exported for the tests)

# ============================================================================
# WSGI SERVER + PROCESS RESTART  (peeled into genpi/lifecycle.py -- roadmap #59, Stage 8)
# ============================================================================
# The cheroot keep-alive serve loop (_serve), the werkzeug fallback (_serve_werkzeug), the in-place
# re-exec (_do_execv), and the non-systemd restart scheduler (_schedule_process_restart) now live in
# genpi/lifecycle.py. The SERVE_* pool tuning + the functions are re-exported for main(), the
# /api/restart route, the updater, and the tests. The live-server handle _WSGI_SERVER and the restart
# flag _RESTART_REQUESTED are REBOUND at runtime and so are intentionally NOT re-exported -- readers
# reference them as lifecycle._WSGI_SERVER / lifecycle._RESTART_REQUESTED (a stale copy would lie).
from . import lifecycle
from .lifecycle import (          # noqa: F401  (re-exported for main() / the restart route / tests)
    SERVE_THREADS, SERVE_MAX_THREADS, SERVE_TIMEOUT, SERVE_SHUTDOWN_TIMEOUT,
    _do_execv, _serve, _serve_werkzeug, _schedule_process_restart,
)


# ============================================================================
# UPDATE CHECK + SELF-UPDATER  (peeled into genpi/updater.py -- roadmap #59, Stage 8)
# ============================================================================
# The upstream version check (_fetch_latest_version / _run_update_check) and the full
# belt-and-suspenders self-updater -- download -> verify EVERY file's SHA-256 -> pre-swap compile ->
# backup -> atomic swap -> re-verify -> health-probe -> auto-rollback -> bootstrap, plus the #72
# CLI-only gate and the hourly update_check_loop -- now live in genpi/updater.py (LAYER: config +
# logg + store + lifecycle + state). The Flask routes that DRIVE it (/api/check-update, /api/update/*)
# stay here and call the re-exported functions + share the re-exported progress state BY REFERENCE
# (_update_state / _update_lock / the decision Event + holder). Functions the updater calls INTERNALLY
# (e.g. _run_update -> _await_decision / _http_get_bytes / _swap / ...) are patched by the tests as
# module.updater.<fn> so the interception is not a silent no-op.
from . import updater
from .updater import (   # noqa: F401  (re-exported for the /api/update routes, main(), and the tests)
    _RAW_BASE, _LATEST_VERSION_URL, _MANIFEST_URL, _version_tuple, _fetch_latest_version,
    _update_check_cache, _run_update_check,
    _UPDATE_STAGING, _BACKUP_DIR, _UPDATE_RESULT, _UPDATE_LOG, _SERVICE_UNIT,
    _update_state, _update_lock, _update_decision_event, _update_decision_choice,
    _SEV_MARK, _APT_PKG_RE, _MANIFEST_DENY_SUFFIXES, _VERSION_RE,
    _update_log, _update_log_append, _update_sev, _update_warn, _update_err, _stage_summary,
    _await_decision, _deployment_has_systemd, _service_skip_reason, _http_get_bytes, _update_phase,
    check_manifest_dependencies, dependency_install_command, _download_and_verify,
    _validate_manifest_paths, _validate_version, _ensure_backup_dir, _preflight_check,
    _write_update_result, _make_backup, _prune_backups, _swap, _rollback, _write_bootstrap_script,
    _run_update, update_check_loop,
)


# ============================================================================
# FLASK APPLICATION + ROUTES  (peeled into genpi/app.py + genpi/routes/* -- roadmap #59, Stage 9)
# ============================================================================
# The Flask `app`, its 64 KiB body cap, the CSRF same-origin guard + the security-header/strict-CSP +
# access-audit middleware, and all 28 routes now live in genpi/app.py (the app + middleware) and the
# four blueprints under genpi/routes/ (core/update/fuel/push). Importing genpi.app builds the app and
# registers the blueprints; `from .app import app` REBINDS the package attribute genpi.app to the
# Flask INSTANCE (so tests keep using module.app.test_client()). The blueprints import services + auth
# from the owning submodules and never this package's app -- the one-way app->routes edge that breaks
# the app<->routes cycle. main() below serves that app via lifecycle._serve (which fetches it lazily).
from .app import app   # noqa: F401  (the Flask application + registered blueprints)
# Re-export the route-layer view helpers the test suite reaches for as gc.<name> (the routes moved to
# blueprints, but these helpers are still exercised directly by unit tests).
from .routes.core import (   # noqa: F401  (re-exported for the tests)
    factory_reset, _read_tail_block, _tail_lines, _tail_with_cursor, _read_log_range,
)
from .routes.push import _push_endpoint_error   # noqa: F401  (re-exported for the tests)


# ============================================================================
# MAIN
# ============================================================================
def main():
    """Main entry point"""
    log.info("=" * 60)
    log.info("Powermate PM9400E Remote Start Controller")
    log.info("=" * 60)
    log.info(f"Relay control: GPIO{CONFIG['RELAY_PIN']}")
    log.info(f"Max start retries: {CONFIG['MAX_START_RETRIES']}")
    log.info(f"Prime delay: {CONFIG['PRIME_DELAY']}s")

    # SSL setup -- generate or renew cert automatically
    ssl_context = None
    if CONFIG["SSL_ENABLED"]:
        ensure_ssl_cert()
        # Fail fast if the cert/key exist but aren't readable by us (e.g. wrong
        # owner from a prior run); app.run() would otherwise die with an opaque
        # SSL error instead of a clear "fix the permissions" message.
        for path in (SSL_CERT_PATH, SSL_KEY_PATH):
            if not os.access(path, os.R_OK):
                log.critical(f"SSL file not readable: {path} -- refusing to start. "
                             f"Fix its permissions/ownership.")
                sys.exit(1)
        ssl_context = (str(SSL_CERT_PATH), str(SSL_KEY_PATH))
        protocol = "https"
    else:
        protocol = "http"

    log.info(f"Web server: {protocol}://{CONFIG['HOST']}:{CONFIG['PORT']}")
    log.info(f"Web Push: {'available' if push_available() else 'unavailable'}")
    log.info("=" * 60)

    # Background fuel monitor: fires a low-fuel push even with no browser open. Daemon
    # so it dies with the process; _monitor_stop lets a clean shutdown end it promptly.
    threading.Thread(target=fuel_monitor_loop, daemon=True).start()

    # Background system monitor: samples host perf metrics into the in-memory ring
    # buffer for the SYSTEM drawer. Daemon so it dies with the process; RAM only.
    threading.Thread(target=system_monitor_loop, daemon=True).start()

    # Background update check (hourly): pushes a notification when a newer release appears
    # upstream, even with no browser open. Daemon; _monitor_stop ends it on shutdown.
    threading.Thread(target=update_check_loop, daemon=True).start()

    try:
        # Serve via _serve (not app.run) so the restart path can release the listening socket before
        # re-exec (see _serve / _schedule_process_restart). _serve uses cheroot, which keeps HTTP
        # connections ALIVE -- so an HTTPS poll reuses one TLS session instead of paying a fresh ECDSA
        # handshake every request (the dominant CPU cost on the Pi Zero 2 W, where the handshake storm
        # pinned the single core). The app is built for concurrency (relay worker + request threads
        # sharing lock-guarded state: _event_lock/state_lock/relay_lock/_sys_hist_lock), and the relay
        # path rejects overlapping fires, so cheroot's thread pool is safe. SSL is passed through
        # unchanged. `threaded=True` is vestigial now (cheroot always pools) but kept for the signature.
        # (On a cheroot restart the MAIN thread re-execs after serve() returns; execv nukes all threads.)
        _serve(
            host=CONFIG["HOST"],
            port=CONFIG["PORT"],
            ssl_context=ssl_context,
            threaded=True,
        )
    except KeyboardInterrupt:
        log.info("Shutting down...")
    finally:
        _monitor_stop.set()
        relay_start_stop.close()
        log.info("Shutdown complete")

if __name__ == '__main__':  # pragma: no cover - CLI entrypoint guard; main() itself is covered by TestMain
    main()
