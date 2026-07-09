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
# SSL CERTIFICATE MANAGEMENT
# ============================================================================
# Self-signed cert is auto-generated on startup if missing or expiring soon.
# Uses openssl (pre-installed on Raspberry Pi OS).

def _resolve_ssl_path(value):
    """Resolve an SSL path from config: an absolute path is used as-is, a relative
    path is taken relative to the script directory."""
    p = Path(value)
    return p if p.is_absolute() else (SCRIPT_DIR / p)


# Cert/key locations come from config so an operator can point at their own files
# (e.g. a real cert) instead of the default self-signed ones next to the script.
SSL_CERT_PATH = _resolve_ssl_path(CONFIG["SSL_CERT_FILE"])
SSL_KEY_PATH = _resolve_ssl_path(CONFIG["SSL_KEY_FILE"])


def _cert_expires_within(days):
    """Check if the SSL cert expires within the given number of days.

    Uses 'openssl x509 -checkend' which returns exit code 0 if the cert is
    still valid after the specified seconds, or 1 if it will expire. This
    avoids fragile date string parsing and locale issues.
    """
    import subprocess
    seconds = days * 86400
    try:
        result = subprocess.run(
            ["openssl", "x509", "-checkend", str(seconds), "-noout",
             "-in", str(SSL_CERT_PATH)],
            capture_output=True, text=True, timeout=5,
        )
        # exit 0 = cert valid beyond the window, exit 1 = expires within window
        return result.returncode != 0
    except Exception as e:
        log.warning(f"Could not check cert expiry: {e}")
        return True  # Assume expired if we can't check


def _build_san():
    """Build the SubjectAltName string for the self-signed cert: the Pi's hostname
    (+ its .local mDNS name), localhost, 127.0.0.1, and any operator-configured extras
    (SSL_SAN). Modern browsers validate against SANs, not the CN, so this makes the
    self-signed cert actually match how the Pi is reached on the LAN (and lets a
    trusted self-signed cert satisfy the secure-context requirement for Web Push)."""
    entries = []
    try:
        hn = socket.gethostname()
        if hn:
            entries.append(f"DNS:{hn}")
            if not hn.endswith(".local"):
                entries.append(f"DNS:{hn}.local")
    except Exception:
        pass
    entries += ["DNS:localhost", "IP:127.0.0.1"]
    # Operator extras, e.g. the Pi's static LAN IP or a friendly hostname.
    extra = str(CONFIG.get("SSL_SAN", "") or "").strip()
    if extra:
        for e in extra.split(","):
            e = e.strip()
            if e:
                entries.append(e)
    # De-duplicate, preserving order.
    seen, out = set(), []
    for e in entries:
        if e not in seen:
            seen.add(e)
            out.append(e)
    return ",".join(out)


def _generate_self_signed():
    """Generate a self-signed cert+key at the configured paths, with SANs. Falls back
    to a no-SAN cert if the local openssl predates -addext support (<1.1.1)."""
    import subprocess

    cert_days = CONFIG["SSL_CERT_DAYS"]
    # ECDSA P-256 (prime256v1) key, NOT RSA-2048: on a weak ARM core (Pi Zero 2 W) the server's
    # per-handshake private-key operation and the overall TLS handshake are dramatically cheaper
    # with an EC key, which matters because every un-kept-alive HTTPS poll pays a handshake. P-256
    # is universally supported by browsers and gives ~128-bit security. -nodes = unencrypted key.
    base = [
        "openssl", "req", "-x509",
        "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-keyout", str(SSL_KEY_PATH),
        "-out", str(SSL_CERT_PATH),
        "-days", str(cert_days),
        "-nodes",                           # No passphrase on the key
        "-subj", "/CN=generatorpi",         # CN kept for legacy display; SANs do the work
    ]
    san = _build_san()
    cmd = base + (["-addext", f"subjectAltName={san}"] if san else [])
    # Tighten the umask to 0o077 around the openssl run so the freshly-written private
    # key is owner-only from the instant of creation. Without this, openssl creates the
    # key under the process's ambient umask (commonly 0o022 -> world-readable 0644), so
    # the secret key would be briefly readable by other users in the window before the
    # os.chmod(0o600) below. Restore the prior umask in the finally so this side effect
    # never leaks out to the rest of the process.
    old_umask = os.umask(0o077)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0 and san:
            # Older openssl doesn't understand -addext; retry without a SAN rather than fail.
            log.warning(
                f"openssl -addext unsupported; generating cert without SAN "
                f"({result.stderr.strip()})"
            )
            result = subprocess.run(base, capture_output=True, text=True, timeout=30)
    finally:
        os.umask(old_umask)
    if result.returncode != 0:
        log.error(f"Failed to generate SSL cert: {result.stderr.strip()}")
        raise RuntimeError("SSL certificate generation failed")
    # Restrict key file permissions (owner read-only) -- we created it. (The tightened
    # umask above already makes it owner-only; this stays as belt-and-suspenders.)
    try:
        os.chmod(SSL_KEY_PATH, 0o600)
    except OSError:
        pass
    log.info(
        f"Generated self-signed SSL cert (valid {cert_days} days"
        + (f", SAN={san}" if san else "") + ")"
    )


def ensure_ssl_cert():
    """Ensure a usable cert + key exist at the configured paths.

    SSL_CERT_MODE controls how:
      * "auto"  (default) -- a SELF-SIGNED cert is auto-generated if missing or within
                 SSL_RENEW_DAYS of expiry, and auto-renewed on startup. Includes SANs.
      * "manual"         -- use the OPERATOR-PROVIDED cert/key as-is. Never generate or
                 overwrite them. Fail fast if they're missing; warn (don't touch) if
                 they're expiring. Point at them with SSL_CERT_FILE / SSL_KEY_FILE.
    """
    mode = str(CONFIG.get("SSL_CERT_MODE", "auto") or "auto").strip().lower()

    if mode == "manual":
        # Operator opted out of self-signing -- respect their files, never clobber them.
        missing = [str(p) for p in (SSL_CERT_PATH, SSL_KEY_PATH) if not p.exists()]
        if missing:
            log.critical(
                "SSL_CERT_MODE=manual but the cert/key file(s) are missing: "
                + ", ".join(missing)
                + ". Provide them via SSL_CERT_FILE/SSL_KEY_FILE, or set SSL_CERT_MODE=auto."
            )
            sys.exit(1)
        if _cert_expires_within(CONFIG["SSL_RENEW_DAYS"]):
            log.warning(
                f"Manual SSL cert {SSL_CERT_PATH} expires within "
                f"{CONFIG['SSL_RENEW_DAYS']} days -- renew it yourself "
                f"(auto-renew is disabled in manual mode)."
            )
        else:
            log.info(f"Using operator-provided SSL cert: {SSL_CERT_PATH}")
        return

    if mode != "auto":
        log.warning(f"Unknown SSL_CERT_MODE={mode!r}; falling back to 'auto'.")

    # auto mode: generate if missing, renew if expiring soon.
    if SSL_CERT_PATH.exists() and SSL_KEY_PATH.exists():
        if not _cert_expires_within(CONFIG["SSL_RENEW_DAYS"]):
            log.info(
                f"SSL cert still valid (renew threshold: {CONFIG['SSL_RENEW_DAYS']} days)"
            )
            return
        log.info(f"SSL cert expires within {CONFIG['SSL_RENEW_DAYS']} days, regenerating")
    else:
        log.info("No SSL cert found, generating self-signed certificate")
    _generate_self_signed()


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




def _json_number(data, field):
    """Pull a numeric `field` from a JSON dict body. Returns (value, error_message);
    error_message is None on success. Accepts numeric strings; rejects bools (a bool
    is an int subclass but is never a valid level/rate/threshold); rejects non-finite
    values (Infinity/-Infinity/NaN, incl. their string forms 'inf'/'nan'/'1e999')."""
    if not isinstance(data, dict) or field not in data:
        return None, f"missing '{field}'"
    v = data[field]
    if isinstance(v, bool):
        return None, f"'{field}' is not a number"
    if isinstance(v, (int, float)):
        parsed = float(v)
    elif isinstance(v, str):
        try:
            parsed = float(v.strip())
        except ValueError:
            return None, f"'{field}' is not a number"
    else:
        return None, f"'{field}' is not a number"
    # Reject non-finite values. float("inf"/"nan"/"1e999") all parse successfully but
    # a non-finite level/rate/threshold is meaningless and dangerous: it would persist
    # Infinity/NaN into the kv store (corrupting /api/state's JSON), and int(float("inf"))
    # raises OverflowError -> a 500 on the alerts threshold path. Fail closed with 400.
    if not math.isfinite(parsed):
        return None, f"'{field}' is not a finite number"
    return parsed, None


# ============================================================================
# FLASK WEB SERVER
# ============================================================================
# static_folder=None disables Flask's built-in /static/<path> route entirely.
# We serve zero static files (the UI is one inline template), so this removes an
# unused file-serving surface -- nothing under the app dir (incl. the settings
# file) can be reached over HTTP.
app = Flask(__name__, static_folder=None)

# Cap the request body at 64 KiB (defense in depth). Every body this app accepts is
# tiny JSON -- a state toggle, a fuel number, or a push subscription (endpoint + two
# short keys) -- so 64 KiB is orders of magnitude of headroom. Werkzeug rejects a
# larger body with 413 before it's buffered, so a malicious/oversized upload can't
# exhaust memory on the Pi.
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024

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


# Methods that mutate server state -- the only ones the CSRF origin check guards.
# GET/HEAD/OPTIONS are safe/idempotent and are exempt (they change nothing).
_CSRF_PROTECTED_METHODS = ("POST", "PUT", "PATCH", "DELETE")


@app.before_request
def csrf_origin_guard():
    """Reject cross-origin state-changing browser requests (CSRF defense).

    The control routes use HTTP Basic Auth, which the browser AUTO-SENDS on every
    same-origin request once the user has logged in. Combined with a body-less action
    like POST /api/start (it reads NO request body), that means a malicious page on
    another site could auto-submit a form to this app and crank the engine using the
    victim's cached Basic-Auth credentials -- a classic CSRF. We block it by checking
    the browser-set Origin/Referer against our own origin on every mutating method:

      expected = "{scheme}://{host}"  (the origin this request was actually served on)

      * Origin present and != expected  -> reject 403 (a real cross-site request).
      * Origin absent but Referer present and not under expected -> reject 403
        (older browsers omit Origin on some requests but still send Referer).
      * NEITHER header present -> ALLOW. Browsers always attach at least one of them
        to a cross-site state-changing request, so "neither" means a NON-browser
        caller: our HomeAssistant rest_command, curl, the test client, etc. Those
        authenticate with the API key (not an ambient cookie/Basic session) and are
        not a CSRF vector, so blocking them would break legitimate automation for no
        security gain. GET/HEAD/OPTIONS are exempt entirely (safe methods).
    """
    if request.method not in _CSRF_PROTECTED_METHODS:
        return None  # safe method -- nothing to guard

    # The origin this request was actually served on (scheme + host[:port]). request.host
    # includes the port when non-default, matching how a browser builds the Origin value.
    expected = f"{request.scheme}://{request.host}"

    origin = request.headers.get("Origin")
    if origin is not None:
        # Origin is the authoritative signal: a browser sets it on cross-site (and most
        # same-site) state-changing requests and it CANNOT be forged by page JS.
        if origin != expected:
            return jsonify(
                {"success": False, "message": "cross-origin request rejected"}
            ), 403
        return None  # same-origin -- allow

    referer = request.headers.get("Referer")
    if referer is not None:
        # Fallback when Origin is absent: the Referer must point at our own origin.
        # Require it to be exactly `expected` or start with `expected + "/"` so a host
        # like "https://evilexpected.com" can't prefix-match our "https://expected".
        if referer != expected and not referer.startswith(expected + "/"):
            return jsonify(
                {"success": False, "message": "cross-origin request rejected"}
            ), 403
        return None  # same-origin Referer -- allow

    # Neither header present -> a non-browser (API-key/curl/HomeAssistant) caller. Allow.
    return None


@app.after_request
def set_security_headers(response):
    """Add security headers to every response."""
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Neutralize the server banner's version disclosure (cheroot sends "Cheroot/X.Y.Z", werkzeug sends
    # "Werkzeug/x Python/y") -- aids targeted CVE matching. Uniform for both server paths; quiet by default.
    response.headers["Server"] = "generatorpi"
    # Strict CSP for a fully self-contained page: no external requests at all.
    # default-src 'none' denies everything by default; we then re-allow ONLY inline
    # styles/scripts (the whole UI is inline), same-origin XHR/fetch (connect-src),
    # and data: images (inline SVG needs none, but data: is harmless + future-proof).
    # base-uri/form-action 'none' remove two injection footguns. Matches the design.
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "worker-src 'self'; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        "base-uri 'none'; "
        "form-action 'none'; "
        # frame-ancestors has NO default-src fallback, so it must be set explicitly.
        # 'none' forbids the page being framed anywhere -- the CSP-level equivalent of
        # X-Frame-Options: DENY (which older browsers still honor), closing clickjacking.
        "frame-ancestors 'none'"
    )
    if CONFIG["SSL_ENABLED"]:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


@app.after_request
def _access_audit_log(response):
    """Access-audit log line, written AFTER the handler so it carries the response
    STATUS code: "<caller>@<ip> -> <METHOD> <path> <status>".

    Emitted for every AUTHENTICATED request (g.auth_method is set by auth_required on
    both the API-key and basic-auth success paths). Unauthenticated failures (401 login
    prompt, 429 lockout) are already logged as warnings inside auth_required, so we skip
    them here to avoid a duplicate line. Method + path ONLY -- never request.full_path /
    query_string, which can contain the API key.

    The status lets the APP LOG view's "hide routine HTTP traffic" filter distinguish a
    routine 2xx/3xx poll from a 4xx/5xx error (errors are always surfaced). We ALWAYS
    write this line regardless of that toggle -- the toggle is a client-side DISPLAY
    filter only; the server records all traffic per usual. Severity tracks the status so
    a failed request stands out (and is colourised) in the log: 5xx error, 4xx warning,
    else info. caller_identity() reads g.auth_method (not the spoofable Authorization
    header), so a keyed caller can't forge the audit identity."""
    if getattr(g, "auth_method", None):
        status = response.status_code
        line = (
            f"{caller_identity()}@{request.remote_addr} -> "
            f"{request.method} {request.path} {status}"
        )
        if status >= 500:
            log.error(line)
        elif status >= 400:
            log.warning(line)
        else:
            log.info(line)
    return response


@app.route('/')
@auth_required
def index():
    """Web UI homepage"""
    with state_lock:
        status = generator_state.copy()
    return render_template_string(HTML_TEMPLATE, status=status, version=APP_VERSION)

@app.route('/api/start', methods=['POST'])
@auth_required
def api_start():
    """REST endpoint to start generator"""
    # Check lock before spawning a thread to avoid creating throwaway threads
    if relay_lock.locked():
        log.warning(f"Start rejected (relay busy) for {caller_identity()}@{request.remote_addr}")
        record_event("start_rejected", "relay busy")
        return jsonify({"success": False, "message": "A relay sequence is already in progress"}), 409
    threading.Thread(target=start_generator, daemon=True).start()
    return jsonify({"success": True, "message": "Start sequence initiated in background"})

@app.route('/api/stop', methods=['POST'])
@auth_required
def api_stop():
    """REST endpoint to stop generator"""
    result = stop_generator()
    return jsonify(result)

@app.route('/api/status', methods=['GET'])
@auth_required
def api_status():
    """REST endpoint for integrations"""
    with state_lock:
        status = generator_state.copy()
    return jsonify(status)

@app.route('/api/set_running', methods=['POST'])
@auth_required
def api_set_running():
    """Manual override to set running state (for manual verification)"""
    # silent=True avoids a 415 on a bodyless/wrong-content-type POST; the isinstance
    # guard then tolerates a NON-dict JSON body (a list/number/string would otherwise
    # 500 on .get). Both cases default to STOPPED.
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    # Coerce 'running' to a real bool. Interpret common string forms so that
    # {"running": "false"} / "0" / "no" map to STOPPED rather than a truthy string.
    raw = data.get('running', False)
    if isinstance(raw, str):
        running = raw.strip().lower() in ("true", "1", "yes", "on")
    else:
        running = bool(raw)

    with state_lock:
        # Manual override: correct the TRACKED state only (no relay). The transition
        # helper still does run-hours accounting so a hand-operated run is counted.
        _apply_running_transition_locked(running)
        generator_state["last_command"] = "mark_run" if running else "mark_stop"
        # Keep the Last Start/Last Stop registers meaningful for manual actions too.
        if running:
            generator_state["last_start_time"] = datetime.now().isoformat()
        else:
            generator_state["last_stop_time"] = datetime.now().isoformat()
        generator_state["message"] = f"Manually set to {'RUNNING' if running else 'STOPPED'}"

    # Durable record of the manual state override.
    record_event("set_running", f"State manually set to {'RUNNING' if running else 'STOPPED'}")
    # Notify subscribed devices of the manual state change (distinct copy from a real
    # start/stop so it's clear no engine action occurred).
    store.send_push_async(
        "Marked as running" if running else "Marked as stopped",
        "Tracked state was set manually (no relay action).",
        tag="state",
    )
    log.info(f"State manually set to {'RUNNING' if running else 'STOPPED'} by {caller_identity()}")
    return jsonify({"success": True, "running": running})

@app.route('/api/runtime/hours', methods=['POST'])
@auth_required
def api_runtime_hours():
    """Manually set the lifetime run-hours odometer. Body: {"hours": float >= 0}.

    A TRACKED-STATE correction only (like MARK RUNNING) -- it NEVER cranks or stops the
    engine and never touches the relay. The value is clamped/quantized + persisted by
    set_total_run_hours(); the fuel projection is preserved across the change. A bad or
    absent body is a 400 (never a 500), consistent with the other numeric endpoints."""
    value, err = _json_number(request.get_json(silent=True), "hours")
    if err:
        return jsonify({"success": False, "message": err}), 400
    old_live, new_total = set_total_run_hours(value)
    # Durable audit trail of the manual odometer correction (old -> new). Uses the
    # MANUAL-tagged "set_running" event type so it reads alongside the other manual
    # overrides in the event log. %g keeps whole numbers clean (250 not 250.000000).
    record_event("set_running", f"Total run-hours set to {new_total:g} h (was {old_live:g} h)")
    log.info(f"Total run-hours set to {new_total:g} h (was {old_live:g} h) by {caller_identity()}")
    return jsonify({"success": True, "total_run_hours": new_total})

@app.route('/api/events', methods=['GET'])
@auth_required
def api_events():
    """Return recent events from the persistent store, newest-first.

    Query params:
      limit  -- number of events to return (default 100, clamped to 1..1000).
      before -- optional int cursor: only events with seq < before (page older).
      after  -- optional int cursor: only events with seq > after (new since).

    Response JSON:
      {"events": [{"seq","ts","type","message"}, ...], "latest_seq": <int>}
    latest_seq lets the client cheaply tell whether new events exist without
    re-fetching the whole list.
    """
    # limit: default 100, clamped to a sane 1..1000 window. request.args.get with a
    # default + type=int returns the default (100) for a missing OR unparseable
    # value, so `limit` is always an int here.
    limit = request.args.get("limit", default=100, type=int)
    limit = max(1, min(limit, 1000))

    # Optional cursors. type=int yields None when absent or non-numeric, which the
    # store treats as "no cursor" -- so a garbage value degrades to the default view.
    before = request.args.get("before", default=None, type=int)
    after = request.args.get("after", default=None, type=int)

    return jsonify({
        "events": get_events(limit, before, after),
        "latest_seq": get_latest_seq(),
    })


@app.route('/api/state', methods=['GET'])
@auth_required
def api_state():
    """Rich state snapshot for the web UI's initial render + polling.

    Returns everything the panel needs: tracked run-state + registers, the lifetime
    run-hours base + current-run start (so the client ticks the uptime/odometer
    live), the fuel model, and the alert config. `server_now` is the server's unix
    clock so the client can align its live timers to the server rather than to a
    possibly-skewed local clock.
    """
    with state_lock:
        snap = {
            "running": generator_state["running"],
            "last_command": generator_state["last_command"],
            "last_start_time": generator_state["last_start_time"],
            "last_stop_time": generator_state["last_stop_time"],
            "start_attempts": generator_state["start_attempts"],
            "message": generator_state["message"],
            "current_run_started_at": generator_state["current_run_started_at"],
            "total_run_hours": generator_state["total_run_hours"],
            "fuel": fuel_snapshot_locked(),
            "alerts": dict(alerts_state),
            "fuel_enabled": alerts_state.get("fuel_enabled", True),
        }
    snap["server_now"] = time.time()
    # Running version + this process's start timestamp (unix). started_at CHANGES on every full
    # restart, so the client can robustly detect a completed self-update (new process = new
    # started_at) and show when the app was last fully restarted.
    snap["app_version"] = APP_VERSION
    snap["started_at"] = _STARTED_AT
    # SYSTEM drawer FACE stat -- a single glanceable value shown even when the drawer is
    # collapsed. CPU% is the most universally understood "how busy" metric and is always
    # available. Pulled from the last ring-buffer sample, NOT computed here: _cpu_pct() is a
    # stateful delta against the sampler-owned _prev_cpu, so calling it from the request path
    # would corrupt the sampler's baseline. At most one sample-interval stale (fine for a
    # collapsed-drawer glance); None until the first sample lands -> the UI hides it.
    with _sys_hist_lock:
        _last_sys = _sys_history[-1] if _sys_history else None
    snap["sys"] = {"cpu": _last_sys["cpu"] if _last_sys else None}
    # Web Push info for the client: whether the server can send (library + VAPID key),
    # the public key the browser needs to subscribe, and how many devices are subscribed.
    # push_status() gives both the boolean AND a machine reason ("library_missing" /
    # "no_keys" / "invalid_keys" / "ok") so the UI can explain EXACTLY why push is off.
    _push_ok, _push_reason = push_status()
    snap["push"] = {
        "supported": _push_ok,
        "reason": _push_reason,
        "vapid_public_key": CONFIG.get("VAPID_PUBLIC_KEY", ""),
        "subscriptions": subscription_count(),
    }
    return jsonify(snap)


@app.route('/api/system/history', methods=['GET'])
@auth_required
def api_system_history():
    """Return the in-memory SYSTEM perf-history ring buffer as JSON for the UI.
    With ?since=<unix_ts>, returns ONLY points newer than that (a delta poll -- tiny
    payload for the flaky link); without it, the full buffer (initial load). Snapshot
    under the lock so we never serialize a deque mid-append."""
    with _sys_hist_lock:
        points = list(_sys_history)
    since = request.args.get("since")
    if since is not None:
        try:
            since_t = float(since)
            points = [p for p in points if p["t"] > since_t]
        except (ValueError, TypeError):
            pass  # malformed 'since' -> fall back to the full buffer
    # COLUMNAR payload: emit one array per field instead of an array-of-objects. A
    # row-wise body repeats all 10 key names on EVERY point (240 on the Pi, 900 in dev)
    # -- thousands of redundant bytes. Columnar names each key ONCE, roughly halving the
    # wire size, so history is small enough to share the SINGLE serial poll lane with
    # state/events without stalling the flaky link. The client rebuilds row objects.
    # SYS_FIELDS order is the contract the frontend's colsToRows() relies on.
    cols = {k: [p[k] for p in points] for k in SYS_FIELDS}
    return jsonify({
        "cols": cols,
        "count": len(points),
        "sample_seconds": max(5, int(CONFIG.get("SYSTEM_HISTORY_SECONDS", 15))),
        "capacity": _sys_history.maxlen,
        "server_now": time.time(),
    })


def _read_tail_block(path, n):
    """Read fixed-size blocks BACKWARD from EOF until we have more than `n` newlines
    (so the first kept line is whole) OR reach BOF. Returns (data, start_pos, size)
    where data == file bytes [start_pos:size]. Cost is bounded by the bytes of those
    last `n` lines, NOT the whole (10MB-capped) log. Missing/empty -> (b"", 0, 0).
    Never raises on a torn read -- callers decode UTF-8 with errors replaced."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            if size == 0:
                return b"", 0, 0
            block = 4096
            data = b""
            pos = size
            while pos > 0 and data.count(b"\n") <= n:
                step = min(block, pos)
                pos -= step
                f.seek(pos)
                data = f.read(step) + data
            return data, pos, size
    except (FileNotFoundError, OSError):
        return b"", 0, 0


def _tail_lines(path, n):
    """Up to the last `n` COMPLETE lines of a text file (a trailing partial line -- a
    log write in flight -- is dropped). Missing/empty -> []. Errors replaced on decode."""
    data, _, size = _read_tail_block(path, n)
    if size == 0:
        return []
    # splitlines() drops the trailing newline; [-n:] trims any overshoot from the block.
    return data.decode("utf-8", "replace").splitlines()[-n:]


def _tail_with_cursor(path, n):
    """(last `n` complete lines, byte cursor just past the file's final newline).

    The cursor is the delta anchor: a subsequent read from it yields only newly-appended
    bytes. It stops at the last NEWLINE (not EOF), so an in-flight final line is re-read
    and completed on the next poll rather than shown half-written. Missing/empty -> ([], 0)."""
    data, pos, size = _read_tail_block(path, n)
    if size == 0:
        return [], 0
    last_nl = data.rfind(b"\n")                 # data ends at EOF, so this is the file's last NL
    cursor = (pos + last_nl + 1) if last_nl >= 0 else 0
    text = data.decode("utf-8", "replace")
    if not text.endswith("\n"):                 # drop a trailing partial (matches the cursor)
        idx = text.rfind("\n")
        text = text[:idx + 1] if idx >= 0 else ""
    return text.splitlines()[-n:], cursor


def _read_log_range(path, start, end, n):
    """Read the NEW bytes [start, end) and return (complete_lines, new_cursor).

    Only whole lines (up to the last newline in the range) are returned; the cursor
    advances to just past that newline, leaving any in-flight final line for next poll.
    No new complete line yet -> ([], start). The delta is capped to the last `n` lines
    so a huge burst can't blow the payload. Errors on decode are replaced (never raises)."""
    try:
        with open(path, "rb") as f:
            f.seek(start)
            chunk = f.read(end - start)
    except (FileNotFoundError, OSError):
        return [], start
    last_nl = chunk.rfind(b"\n")
    if last_nl < 0:
        return [], start                        # nothing complete appended yet
    complete = chunk[:last_nl]                   # bytes strictly before the last newline
    cursor = start + last_nl + 1
    lines = complete.decode("utf-8", "replace").split("\n")
    if len(lines) > n:
        lines = lines[-n:]
    return lines, cursor


@app.route('/api/logs', methods=['GET'])
@auth_required
def api_logs():
    """Application-log feed for the EVENT LOG panel's 'APP LOG' view -- an INCREMENTAL
    (delta) tail so we don't resend the whole file every poll.

    The path is FIXED server-side (log_path = SCRIPT_DIR / LOG_FILE) and never derived
    from request input, so there is zero path-traversal surface.

    Query params:
      lines -- max lines to return (default/cap 1000, clamped 1..1000).
      since -- byte cursor from a prior response's `offset`. Omitted/invalid -> a full
               tail (the last `lines` lines). A cursor PAST current EOF means the file
               rotated/truncated -> we transparently fall back to a full tail + reset.

    Response JSON:
      {"lines": [<oldest..newest>], "offset": <int byte cursor>, "reset": <bool>,
       "path": "<log file name>"}
    `reset` true tells the client to REPLACE its view (initial load or post-rotation);
    false means `lines` are strictly-new rows to append. Each line still carries its own
    "YYYY-MM-DD HH:MM:SS [LEVEL] ..." timestamp, which the client parses for display.
    """
    # type=int -> the default for a missing OR unparseable value; clamp bounds the payload.
    n = request.args.get("lines", default=1000, type=int)
    n = max(1, min(n, 1000))
    since = request.args.get("since", default=None, type=int)

    # Current EOF up front so we can classify the request (stat is cheap, never raises here).
    try:
        size = os.path.getsize(log_path)
    except OSError:
        size = 0

    # FULL TAIL (reset): no cursor (initial load) OR a cursor that's negative / past EOF
    # (the file was rotated or truncated out from under the client -> its cursor is stale).
    if since is None or since < 0 or since > size:
        tail, cursor = _tail_with_cursor(log_path, n)
        return jsonify({"lines": tail, "offset": cursor, "reset": True, "path": log_path.name})

    # Up to date already -> empty delta, cursor unchanged (the common idle poll: ~tiny).
    if since >= size:
        return jsonify({"lines": [], "offset": since, "reset": False, "path": log_path.name})

    # DELTA: return only the bytes appended since the client's cursor.
    new_lines, cursor = _read_log_range(log_path, since, size, n)
    return jsonify({"lines": new_lines, "offset": cursor, "reset": False, "path": log_path.name})


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


@app.route('/api/restart', methods=['POST'])
@auth_required
def api_restart():
    """Restart the server process (self re-exec). Returns 200 FIRST, then re-execs after a
    short delay so the response reaches the client. Authed + CSRF-guarded like every POST."""
    log.warning(f"Application restart requested by {caller_identity()}@{request.remote_addr}")
    record_event("restart", "Application restart requested")
    _schedule_process_restart()
    return jsonify({"success": True, "message": "Restarting - reconnecting shortly..."})


def factory_reset():
    """Wipe the application's runtime MEMORY back to factory defaults: empty the event
    store (events/kv/subscriptions rows), truncate the app log file, and reset the durable
    in-memory globals (lifetime run-hours, fuel model, alert config) to code defaults.

    Deliberately does NOT touch generator_control.env or ANY credential/config file -- the
    reset contract is 'logs + DB/state only, leave the env alone'. Schema is preserved
    (rows cleared, tables kept) so the app keeps working live without a restart."""
    # 1. Empty the DB tables (one shared connection, serialized by _event_lock). _event_conn is
    #    REBOUND by init_event_store(), so read it module-qualified from store (the re-exported
    #    copy would go stale after a reopen -- e.g. a test pointing the store at a tmp DB).
    with _event_lock:
        if store._event_conn is not None:
            store._event_conn.execute("DELETE FROM events")
            store._event_conn.execute("DELETE FROM kv")
            store._event_conn.execute("DELETE FROM subscriptions")
            store._event_conn.commit()
    # 2. Reset the durable in-memory globals to their code defaults.
    with state_lock:
        generator_state["running"] = False
        generator_state["current_run_started_at"] = None
        generator_state["total_run_hours"] = 0.0
        fuel_state["fill_level"] = 100.0
        fuel_state["fill_run_hours"] = 0.0
        fuel_state["drain_rate"] = FUEL_DEFAULT_RATE
        fuel_state["default_rate"] = FUEL_DEFAULT_RATE
        alerts_state["alerts_on"] = True
        alerts_state["alert_threshold"] = 20
        alerts_state["fuel_enabled"] = True
    # 3. Truncate the application log file (open 'w' empties it). Best-effort, never fatal.
    try:
        with open(log_path, "w"):
            pass
    except OSError:
        pass


@app.route('/api/factory-reset', methods=['POST'])
@auth_required
def api_factory_reset():
    """Factory reset: wipe the event store + logs + durable state (NEVER the env file) back
    to defaults. No process restart -- factory_reset() resets the live in-memory globals, so
    the running app continues with a clean slate. Authed + CSRF-guarded. The client refreshes
    to reflect the reset state."""
    log.warning(f"FACTORY RESET requested by {caller_identity()}@{request.remote_addr}")
    factory_reset()
    # First event written into the freshly-emptied store, so there's an audit trail of it.
    record_event("factory_reset", "Factory reset performed (event store + logs cleared)")
    return jsonify({"success": True, "message": "Factory reset complete."})


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


@app.route('/api/check-update', methods=['GET'])
@auth_required
def api_check_update():
    """Report installed vs. published version. `?fresh=1` does a LIVE repo check (manual
    "Check again" + the on-load check); the default returns the CACHED last-known result so the
    footer's 5-minute refresh never touches GitHub. `latest` is null when a live check couldn't
    reach the repo (offline / not yet public)."""
    if request.args.get("fresh"):
        return jsonify(_run_update_check())
    with _update_lock:
        cached = dict(_update_check_cache)
    if cached.get("checked_at") is None:          # nothing cached yet -> one live check
        return jsonify(_run_update_check())
    return jsonify({"installed": APP_VERSION, "latest": cached["latest"],
                    "update_available": bool(cached["update_available"])})


# ----------------------------------------------------------------------------
# The self-updater machinery (download / verify / backup / swap / rollback / bootstrap + the #72
# CLI-only gate) moved to genpi/updater.py in Stage 8 -- see the re-export block above. The
# /api/update/* routes below still drive it via the re-exported functions + shared progress state.
# ----------------------------------------------------------------------------

@app.route('/api/update/changelog', methods=['GET'])
@auth_required
def api_update_changelog():
    """Fetch the release CHANGELOG for the update modal. Never errors hard -- returns
    {changelog: null} if the repo is unreachable so the modal can still open."""
    try:
        # CHANGELOG-RECENT.md holds only the latest few releases (generated from the full CHANGELOG.md
        # by tools/changelog.py). We fetch the SHORT file so a version check isn't a full-changelog
        # download every time. See the "Changelog" section in the repo CLAUDE.md.
        text = _http_get_bytes(_RAW_BASE + "/CHANGELOG-RECENT.md", max_bytes=64_000).decode("utf-8", "replace")
        return jsonify({"changelog": text, "backup_dir": str(_BACKUP_DIR)})
    except Exception as e:                              # noqa: BLE001 -- non-fatal
        return jsonify({"changelog": None, "error": str(e), "backup_dir": str(_BACKUP_DIR)})


@app.route('/api/update/status', methods=['GET'])
@auth_required
def api_update_status():
    """Current updater progress (polled by the UI during an update)."""
    with _update_lock:
        return jsonify(dict(_update_state))


@app.route('/api/update/start', methods=['POST'])
@auth_required
def api_update_start():
    """Kick off the self-update in a background thread. Admin surface: authed +
    CSRF-guarded (every POST is). 409 if an update is already running."""
    with _update_lock:
        if _update_state["phase"] not in ("idle", "done", "failed"):
            return jsonify({"success": False, "message": "An update is already in progress."}), 409
        _update_state.update(phase="checking", message="Starting…", progress=0.0,
                             error=None, systemd=_deployment_has_systemd(), log=[], decide=None,
                             missing_deps=[], deps_install_cmd="", installable=True,
                             important_notes=[], stage=1,
                             counts={"stage1": {"warn": 0, "err": 0}, "stage2": {"warn": 0, "err": 0}})
    log.warning(f"Self-update requested by {caller_identity()}@{request.remote_addr}")
    threading.Thread(target=_run_update, daemon=True, name="self-update").start()
    return jsonify({"success": True})


@app.route('/api/update/decide', methods=['POST'])
@auth_required
def api_update_decide():
    """Answer a REVERT/PROCEED prompt the running update parked on (phase 'awaiting'). Body
    {choice: 'proceed'|'revert'}; 'proceed' is only honored when the parked step allowed it
    (a hard safety error offers REVERT only). 409 if nothing is awaiting a decision."""
    data = request.get_json(silent=True) or {}
    choice = data.get("choice")
    if choice not in ("proceed", "revert"):
        return jsonify({"success": False, "message": "choice must be 'proceed' or 'revert'"}), 400
    with _update_lock:
        decide = _update_state.get("decide")
        if _update_state["phase"] != "awaiting" or not decide:
            return jsonify({"success": False, "message": "no decision is pending"}), 409
        # Refuse PROCEED on a step that forbids it (safety errors) -- fall back to REVERT.
        if choice == "proceed" and not decide.get("allow_proceed"):
            choice = "revert"
        _update_decision_choice["choice"] = choice
    _update_decision_event.set()                          # unblock the worker's _await_decision
    return jsonify({"success": True, "choice": choice})


@app.route('/api/update/result', methods=['GET'])
@auth_required
def api_update_result():
    """After a restart triggered by an update, report how it went (+ the captured log) so the
    UI can show a one-time success/failure modal. {pending:false} once acknowledged/cleared."""
    if not _UPDATE_RESULT.exists():
        return jsonify({"pending": False})
    try:
        res = json.loads(_UPDATE_RESULT.read_text())
    except Exception:                                    # corrupt marker -> still surface it
        res = {"status": "unknown", "version": None, "note": ""}
    log_text = ""
    try:
        if _UPDATE_LOG.exists():
            log_text = _UPDATE_LOG.read_text(errors="replace")[-20000:]   # tail, bounded
    except Exception:
        pass
    res.update({"pending": True, "log": log_text})
    return jsonify(res)


@app.route('/api/update/result/ack', methods=['POST'])
@auth_required
def api_update_result_ack():
    """Clear the update-result marker SERVER-SIDE, so once ANY client dismisses the modal it
    never reappears (for anyone) until the next update writes a new marker."""
    for p in (_UPDATE_RESULT, _UPDATE_LOG):
        try:
            p.unlink()
        except OSError:
            pass
    return jsonify({"success": True})


# update_check_loop (the hourly background update check) moved to genpi/updater.py in Stage 8;
# main() starts it as a daemon thread via the re-export above.

@app.route('/api/fuel/reading', methods=['POST'])
@auth_required
def api_fuel_reading():
    """Record an observed tank level (%), refining the drain-rate estimate."""
    value, err = _json_number(request.get_json(silent=True), "level")
    if err:
        return jsonify({"success": False, "message": err}), 400
    rate = record_fuel_reading(value)
    # Log the CLAMPED level actually used (0..100), not the raw request value, so the
    # event log doesn't claim e.g. "150%" when 100% was fitted.
    shown = max(0.0, min(100.0, value))
    record_event("fuel", f"Observed level {shown:g}% - drain rate now {rate:g} %/hr")
    log.info(f"Fuel reading {shown:g}% by {caller_identity()} -> rate {rate:g} %/hr")
    return jsonify({"success": True, "drain_rate": rate})


@app.route('/api/fuel/rate', methods=['POST'])
@auth_required
def api_fuel_rate():
    """Set the drain rate (%/hr) directly."""
    value, err = _json_number(request.get_json(silent=True), "rate")
    if err:
        return jsonify({"success": False, "message": err}), 400
    rate = set_fuel_rate(value)
    record_event("fuel", f"Drain rate set to {rate:g} %/hr")
    log.info(f"Drain rate set to {rate:g} %/hr by {caller_identity()}")
    return jsonify({"success": True, "drain_rate": rate})


@app.route('/api/fuel/rate/reset', methods=['POST'])
@auth_required
def api_fuel_rate_reset():
    """Restore the drain rate to its configured default."""
    rate = reset_fuel_rate()
    record_event("fuel", f"Drain rate reset to default {rate:g} %/hr")
    log.info(f"Drain rate reset to {rate:g} %/hr by {caller_identity()}")
    return jsonify({"success": True, "drain_rate": rate})


@app.route('/api/fuel/fill', methods=['POST'])
@auth_required
def api_fuel_fill():
    """'Add gas': reset the baseline fill level (%). Drain rate is retained."""
    value, err = _json_number(request.get_json(silent=True), "level")
    if err:
        return jsonify({"success": False, "message": err}), 400
    snap = set_fuel_fill(value)
    record_event("fuel", f"Tank filled to {snap['fill_level']:g}%")
    log.info(f"Tank filled to {snap['fill_level']:g}% by {caller_identity()}")
    return jsonify({"success": True, "fuel": snap})


@app.route('/api/alerts', methods=['POST'])
@auth_required
def api_alerts():
    """Update low-fuel alert config: {enabled: bool?, threshold: int?}. Both
    optional; threshold is clamped to 5..40."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}

    def _bool_field(name):
        # Accept a real bool or the common string/int forms; None if absent.
        if name not in data:
            return None
        raw = data[name]
        if isinstance(raw, str):
            return raw.strip().lower() in ("true", "1", "yes", "on")
        return bool(raw)

    enabled = _bool_field("enabled")
    fuel_enabled = _bool_field("fuel_enabled")
    # threshold: optional numeric; reject a present-but-garbage value.
    threshold = None
    if "threshold" in data:
        tval, terr = _json_number(data, "threshold")
        if terr:
            return jsonify({"success": False, "message": terr}), 400
        threshold = tval
    snap = set_alerts(enabled=enabled, threshold=threshold, fuel_enabled=fuel_enabled)
    log.info(
        f"Alerts set on={snap['alerts_on']} threshold={snap['alert_threshold']}% "
        f"fuel_enabled={snap['fuel_enabled']} by {caller_identity()}"
    )
    return jsonify({"success": True, "alerts": snap})


# The push service worker (SERVICE_WORKER_JS) now lives in genpi/frontend/sw.js, loaded + re-
# exported by genpi/ui.py (above). It is served below at /sw.js as its own same-origin resource
# -- no auth, no secrets -- exactly as before.


@app.route('/sw.js')
def service_worker():
    """Serve the push service worker (no auth; no secrets)."""
    return Response(
        SERVICE_WORKER_JS,
        mimetype="application/javascript",
        headers={"Cache-Control": "no-cache"},
    )


def _push_endpoint_error(endpoint):
    """Validate a push-subscription endpoint URL, returning an error string if it is
    unacceptable, or None if it is safe to store + later POST to.

    send_push() makes an outbound HTTP request to whatever endpoint we store, so an
    attacker who can subscribe an arbitrary URL turns this into a Server-Side Request
    Forgery primitive against the Pi's own network (localhost admin panels, LAN
    devices, cloud metadata IPs, etc.). We therefore require:

      * an https:// URL (a real push service is always https; http:// is rejected), and
      * a host that is NOT an IP literal in a private/loopback/link-local/reserved
        range. A normal push-service DNS hostname (fcm.googleapis.com, *.notify.
        windows.com, ...) is NOT an IP literal, so ipaddress.ip_address() raises and it
        passes. Only a bare private/internal IP is blocked.
    """
    if not isinstance(endpoint, str) or not endpoint:
        return "missing endpoint or keys"
    parsed = urlparse(endpoint)
    if parsed.scheme != "https":
        return "endpoint must be an https:// URL"
    host = parsed.hostname
    if not host:
        return "endpoint has no host"
    try:
        # If the host parses as an IP literal, block internal/non-routable ranges.
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Not an IP literal -> an ordinary DNS hostname (the normal case) -> allow.
        return None
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        return "endpoint host is not a routable public address"
    return None


@app.route('/api/push/subscribe', methods=['POST'])
@auth_required
def api_push_subscribe():
    """Store a browser's Web Push subscription (endpoint + p256dh + auth keys)."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "message": "invalid subscription"}), 400
    endpoint = data.get("endpoint")
    keys = data.get("keys") or {}
    p256dh = keys.get("p256dh")
    auth = keys.get("auth")
    if not endpoint or not p256dh or not auth:
        return jsonify({"success": False, "message": "missing endpoint or keys"}), 400
    # SSRF hardening: only accept an https:// endpoint whose host is not an internal
    # IP literal (see _push_endpoint_error). send_push() will POST to this URL, so an
    # unvalidated endpoint would let a caller aim the daemon at the loopback/LAN.
    ep_err = _push_endpoint_error(endpoint)
    if ep_err:
        return jsonify({"success": False, "message": ep_err}), 400
    add_subscription(endpoint, p256dh, auth)
    log.info(f"Push subscription added by {caller_identity()}")
    return jsonify({"success": True, "subscriptions": subscription_count()})


@app.route('/api/push/unsubscribe', methods=['POST'])
@auth_required
def api_push_unsubscribe():
    """Remove a push subscription by its endpoint."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    endpoint = data.get("endpoint")
    if not endpoint:
        return jsonify({"success": False, "message": "missing endpoint"}), 400
    remove_subscription(endpoint)
    return jsonify({"success": True, "subscriptions": subscription_count()})


@app.route('/api/push/test', methods=['POST'])
@auth_required
def api_push_test():
    """Send a test push to all subscribed devices (the Advanced-drawer button)."""
    if not push_available():
        return jsonify({"success": False, "message": "push not available on server"}), 503
    if subscription_count() == 0:
        return jsonify({"success": False, "message": "no subscriptions"}), 409
    store.send_push_async("Test notification", "Push notifications are working.", tag="test")
    record_event("push", "Test notification sent")
    log.info(f"Test push sent by {caller_identity()}")
    return jsonify({"success": True})

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
