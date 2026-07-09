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
from gpiozero import OutputDevice
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
from werkzeug.security import generate_password_hash, check_password_hash

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
# AUTHENTICATION
# ============================================================================
# Dummy hash used when a username doesn't exist, so the response time is the
# same whether the username is valid or not (prevents enumeration via timing).
_DUMMY_HASH = generate_password_hash("timing-safe-dummy-value")

# ----------------------------------------------------------------------------
# Basic-auth verification cache. check_password_hash() is scrypt -- deliberately
# CPU/memory-hard, ~1.7s PER verify on a Pi Zero 2 W core (measured). A browser
# polls several endpoints every few seconds over HTTP Basic auth, so WITHOUT
# this cache every request re-runs scrypt and pins the single core near 100%.
# We cache ONLY successful verifications, briefly, keyed by an HMAC over
# (username, CURRENT stored hash, password) under a per-process random secret:
#   * the plaintext password is never stored (only an HMAC that dies with the
#     process -- not reversible without the secret);
#   * the key binds to the current stored hash, so a password change INSTANTLY
#     invalidates cached entries (the old password now hashes against the new
#     stored hash -> cache miss -> scrypt -> fail);
#   * FAILURES are never cached, so the brute-force limiter (run BEFORE auth)
#     still sees and slows every wrong guess -- no auth bypass.
# Set AUTH_CACHE_TTL=0 to disable (every request re-runs scrypt).
# ----------------------------------------------------------------------------
_AUTH_CACHE_SECRET = secrets.token_bytes(32)      # per-process; gone on restart
_AUTH_CACHE_TTL = float(os.environ.get("AUTH_CACHE_TTL", "60"))   # seconds a success stays cached
_AUTH_CACHE_MAX = 256                             # hard cap on entries (bound memory)
_auth_cache = {}                                  # hmac_key(bytes) -> expiry_epoch(float)
_auth_cache_lock = threading.Lock()


def _auth_cache_key(username, stored_hash, password):
    """Fast keyed hash of (username, current stored hash, password). Binds to stored_hash so a
    password change misses the cache; the '\\x00' separators stop a||b == a'||b' key collisions."""
    mac = hmac.new(_AUTH_CACHE_SECRET, digestmod=hashlib.sha256)
    for part in (username, stored_hash, password):
        mac.update(part.encode("utf-8"))
        mac.update(b"\x00")
    return mac.digest()


def check_auth(username, password):
    """Verify a username + password. Constant-time against a dummy hash when the username
    doesn't exist (anti-enumeration). Successful verifications are cached for AUTH_CACHE_TTL
    seconds so a polling browser doesn't re-run scrypt on every request (see the cache notes)."""
    stored_hash = AUTH_USERS.get(username, _DUMMY_HASH)
    key = _auth_cache_key(username, stored_hash, password)
    now = time.time()
    with _auth_cache_lock:
        exp = _auth_cache.get(key)
        if exp is not None and exp > now:
            # Cached SUCCESS. Re-check membership so a user deleted since caching is rejected
            # immediately (a CHANGED password already misses via the stored-hash-bound key).
            return username in AUTH_USERS
    # Cache miss/expired -> pay the scrypt cost exactly once per TTL per credential. A nonexistent
    # user still hashes against _DUMMY_HASH here (constant time) and is never cached (ok stays False).
    ok = check_password_hash(stored_hash, password) and username in AUTH_USERS
    if ok and _AUTH_CACHE_TTL > 0:                            # TTL<=0 disables the cache entirely
        with _auth_cache_lock:
            if len(_auth_cache) >= _AUTH_CACHE_MAX:          # evict expired; hard-reset if still full
                for k in [k for k, e in _auth_cache.items() if e <= now]:
                    _auth_cache.pop(k, None)
                if len(_auth_cache) >= _AUTH_CACHE_MAX:
                    _auth_cache.clear()
            _auth_cache[key] = now + _AUTH_CACHE_TTL
    return ok


def check_api_key():
    """Verify a machine-caller API key (e.g. from HomeAssistant).

    The key may arrive either as a URL query parameter (?key=...) -- the primary
    path used by our HomeAssistant rest_command -- or as an "X-API-Key" header.
    Returns True only if key auth is ENABLED (API_KEY_ENABLED) and CONFIGURED
    (non-empty API_KEY) and the presented key matches, compared in constant time
    via hmac.compare_digest to avoid leaking the key through timing. Returns False
    when key auth is disabled or no/incorrect key is presented, so the caller falls
    through to basic auth.
    """
    if not CONFIG["API_KEY_ENABLED"]:
        return False  # Key auth turned off via the settings file
    configured = CONFIG["API_KEY"]
    if not configured:
        return False  # No key configured -- basic auth only
    # Query param takes precedence, then header
    presented = request.args.get("key") or request.headers.get("X-API-Key")
    if not presented:
        return False
    # Compare on BYTES, not str: hmac.compare_digest raises TypeError on a str with
    # any non-ASCII char, which would otherwise 500 (bypassing the failure counter
    # and flooding the log with tracebacks). Bytes are defined for all inputs and
    # stay constant-time.
    return hmac.compare_digest(presented.encode("utf-8"), configured.encode("utf-8"))


def auth_required(f):
    """Decorator that enforces authentication (API key OR HTTP Basic Auth)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = request.remote_addr

        # Check rate limit before doing anything else (avoids wasting CPU on scrypt)
        remaining = is_rate_limited(ip)
        if remaining > 0:
            log.warning(f"Rate limited request from {ip} ({int(remaining)}s remaining)")
            return Response(
                f"<html><body><h1>Too Many Attempts</h1>"
                f"<p>Your IP has been temporarily locked out after too many failed login attempts.</p>"
                f"<p>Try again in {int(remaining)} seconds.</p></body></html>",
                429,
                {"Content-Type": "text/html", "Retry-After": str(int(remaining))},
            )

        # Path 1 -- API key (query ?key=... or X-API-Key header), for machine
        # callers like HomeAssistant. Checked before basic auth so keyed callers
        # never get a browser auth challenge. A valid key clears prior failures.
        if check_api_key():
            record_success(ip)
            # Record HOW we authed so downstream audit logs don't trust a spoofable
            # Authorization header a keyed caller might also send (see caller_identity).
            g.auth_method = "apikey"
            # The access-audit line is emitted POST-handler by the _access_audit_log
            # after_request hook, so it can carry the response status code (which the
            # APP LOG's "hide routine HTTP traffic" filter keys off). Method + path only
            # there -- never the query string, which would contain the key.
            return f(*args, **kwargs)

        # Path 2 -- HTTP Basic Auth (browser login / manual fallback). A present
        # but WRONG key falls through to here and is recorded as a failed attempt.
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            attempted = auth.username if auth else "(none)"
            locked, fail_count = record_failure(ip)
            max_failures = CONFIG["RATE_LIMIT_MAX_FAILURES"]
            # Log the attempted username via !r (repr), NOT raw: it comes from the
            # base64-decoded Authorization header and can carry CR/LF/other control
            # chars. repr escapes them (e.g. '\r\nInjected') so a crafted username
            # can't forge extra log lines (log injection). repr also supplies its own
            # quoting, so the surrounding literal quotes are dropped.
            log.warning(
                f"Auth failed for {attempted!r}@{ip} "
                f"({fail_count}/{max_failures} attempts)"
                + (" [LOCKED OUT]" if locked else "")
            )
            return Response(
                "Authentication required.\n",
                401,
                {"WWW-Authenticate": 'Basic realm="Generator Control"'},
            )

        # Successful basic auth -- clear any prior failures for this IP
        record_success(ip)
        g.auth_method = "basic"
        # Access-audit line emitted post-handler (see _access_audit_log) so it can
        # include the response status the APP LOG's traffic filter keys off.
        return f(*args, **kwargs)
    return decorated


def caller_identity():
    """Human-readable identity of the authenticated caller, for log lines.

    Trusts g.auth_method (set by auth_required) rather than inferring from
    request.authorization -- a key-authenticated caller can ALSO send an arbitrary
    Authorization header, and inferring from it would let them forge the audit-log
    identity. Returns "apikey" for keyed callers, else the validated basic-auth
    username. Safe from any authenticated route.
    """
    if getattr(g, "auth_method", None) == "apikey":
        return "apikey"
    auth = request.authorization
    return auth.username if auth else "apikey"

# ============================================================================
# GLOBAL STATE  (peeled into genpi/state.py -- roadmap #59, Stage 4)
# ============================================================================
# generator_state, the fuel model (fuel_state) + alerts (alerts_state), their coarse state_lock,
# the run-hours accounting helpers, and set_total_run_hours now live in genpi/state.py (LAYER 2:
# depends on store + logg). Importing it restores durable state from the kv store EXACTLY as before.
# The state dicts, state_lock, and the _monitor_stop Event are re-exported by REFERENCE -- the test
# suite and the not-yet-peeled relay/control/fuel/route code mutate their CONTENTS, which is shared.
# _low_fuel_alerted is defined in state but read/written by the fuel monitor still in THIS module,
# so its gc-level rebinds (conftest + the low-fuel tests) keep working until fuel peels out (Stage 7).
from . import state
from .state import (               # noqa: F401  (re-exported for the rest of this module + tests)
    generator_state, state_lock, fuel_state, alerts_state, FUEL_DEFAULT_RATE,
    _low_fuel_alerted, _monitor_stop, MAX_TOTAL_RUN_HOURS, load_persisted_state,
    _live_total_run_hours_locked, _apply_running_transition_locked, set_total_run_hours,
)

# Prevents overlapping relay sequences (e.g. two simultaneous start requests)
relay_lock = threading.Lock()

# ============================================================================
# GPIO SETUP
# ============================================================================
# SunFounder relays are LOW-triggered (active_high=False means on() sends LOW signal)
relay_start_stop = OutputDevice(CONFIG["RELAY_PIN"], active_high=False, initial_value=False)
log.info(f"GPIO initialized - pin {CONFIG['RELAY_PIN']} (relay control)")

# ============================================================================
# RELAY CONTROL FUNCTIONS
# ============================================================================
def press_button():
    """Simulate a momentary button press on the generator."""
    duration = CONFIG["BUTTON_PRESS_DURATION"]
    log.debug(f"Pressing relay ({duration}s)")
    relay_start_stop.on()   # Energize relay (closes contacts)
    # HARDWARE SAFETY: the off() MUST run even if something raises between on() and
    # off() (e.g. a KeyboardInterrupt/SystemExit during shutdown while we're asleep,
    # or a signal-driven exception). Without the finally, an exception here would
    # leave the relay energized -- i.e. the physical start/stop button held DOWN
    # indefinitely -- which is exactly the failure mode we must never allow. The
    # try/finally guarantees the relay is de-energized on every exit path; the
    # exception still propagates to the caller afterwards.
    try:
        time.sleep(duration)
    finally:
        relay_start_stop.off()  # De-energize relay (opens contacts) -- ALWAYS runs
    time.sleep(0.1)         # Small debounce delay (only reached on the normal path)

# ============================================================================
# GENERATOR CONTROL LOGIC
# ============================================================================
def start_generator():
    """Start the generator with PM9400E one-touch sequence:
    1. Press once to prime
    2. Wait for prime delay
    3. Press again to start
    4. Repeat if retries configured

    The relay_lock prevents overlapping sequences if multiple requests arrive.
    """
    # Acquire relay lock (non-blocking) -- reject if a sequence is already running
    if not relay_lock.acquire(blocking=False):
        log.warning("Start rejected: relay sequence already in progress")
        # Record the rejection so the event log shows the attempt was refused.
        record_event("start_rejected", "relay sequence already in progress")
        return {"success": False, "message": "A relay sequence is already in progress"}

    try:
        with state_lock:
            if generator_state["running"]:
                # Reject a start when we already believe the generator is running.
                record_event("start_rejected", "generator already marked as running")
                return {"success": False, "message": "Generator already marked as running"}
            generator_state["last_command"] = "start"
            generator_state["start_attempts"] = 0

        max_retries = CONFIG["MAX_START_RETRIES"]
        prime_delay = CONFIG["PRIME_DELAY"]
        retry_delay = CONFIG["RETRY_DELAY"]

        log.info("Initiating generator start sequence")
        # Durable record that a start sequence began (paired with start_complete).
        record_event("start", "Start sequence initiated")

        for attempt in range(1, max_retries + 1):
            with state_lock:
                generator_state["start_attempts"] = attempt
                generator_state["message"] = f"Start attempt {attempt}/{max_retries}"

            log.info(f"Start attempt {attempt}/{max_retries}")

            # PM9400E sequence: prime press
            log.info("Pressing button to prime")
            press_button()

            # Wait for prime/auto-choke
            log.info(f"Waiting {prime_delay}s for prime...")
            time.sleep(prime_delay)

            # PM9400E sequence: start press
            log.info("Pressing button to start")
            press_button()

            with state_lock:
                generator_state["last_start_time"] = datetime.now().isoformat()

            log.info(f"Start sequence {attempt} completed")

            if attempt < max_retries:
                log.info(f"Waiting {retry_delay}s before next attempt...")
                time.sleep(retry_delay)

        # Mark as running (assume success -- no auto-detect available). The
        # transition helper stamps current_run_started_at so the uptime/odometer
        # start ticking from now.
        with state_lock:
            _apply_running_transition_locked(True)
            generator_state["message"] = (
                f"Start sequence completed ({max_retries} attempt(s)). "
                "Verify generator manually."
            )

        log.info("Start sequence finished")
        # Durable record that the start sequence completed (paired with the
        # "start" initiate event above).
        record_event("start_complete", f"Start sequence completed ({max_retries} attempt(s))")
        # Notify subscribed devices (off-thread; no-op if push unavailable).
        send_push_async("Generator started", "Start sequence completed. Verify the unit is running.", tag="state")
        return {
            "success": True,
            "message": (
                f"Start sequence completed ({max_retries} attempt(s)). "
                "Please verify generator is running."
            ),
        }
    finally:
        relay_lock.release()


def stop_generator():
    """Stop the generator by simulating stop button press.

    The relay_lock prevents overlapping with a start sequence.
    """
    # Acquire relay lock (non-blocking) -- reject if a sequence is already running
    if not relay_lock.acquire(blocking=False):
        log.warning("Stop rejected: relay sequence already in progress")
        return {"success": False, "message": "A relay sequence is already in progress"}

    try:
        log.info("Stopping generator")

        # Press the button first, then update state (so state reflects reality)
        press_button()

        with state_lock:
            generator_state["last_command"] = "stop"
            # Transition banks this run's elapsed time into total_run_hours + persists.
            _apply_running_transition_locked(False)
            generator_state["last_stop_time"] = datetime.now().isoformat()
            generator_state["message"] = "Stop command sent"

        # Durable record of the stop command.
        record_event("stop", "Stop command sent")
        send_push_async("Generator stopped", "Stop command sent.", tag="state")
        log.info("Stop button pressed")
        return {"success": True, "message": "Stop button pressed. Generator should be stopping."}
    finally:
        relay_lock.release()

# ============================================================================
# FUEL PROJECTION MODEL (linear drain: level = fill_level - drain_rate * run-hours)
# ============================================================================
# The server holds the raw model (fill baseline + estimated %/hr) and ships it in
# the state snapshot; the FRONT-END derives the projected level + "reaches / empty"
# durations so they tick live without polling. Mutations here just update + persist
# the model. All the arithmetic below is O(1).

def _round1(x):
    """Round to one decimal place (matches the design's %/hr precision)."""
    return round(float(x), 1)


def fuel_snapshot_locked():
    """Return a plain copy of the fuel model for the state snapshot. Caller holds
    state_lock."""
    return dict(fuel_state)


def projected_fuel_level_locked():
    """Current projected tank level (%), server-side, using the same linear model the
    client renders (level = fill_level - drain_rate * run-hours-since-fill). Caller
    holds state_lock. Shared by the low-fuel monitor so client + server agree."""
    run = max(0.0, _live_total_run_hours_locked() - fuel_state["fill_run_hours"])
    return max(0.0, min(100.0, fuel_state["fill_level"] - fuel_state["drain_rate"] * run))


# Hysteresis (%) the level must climb back above the threshold before a new low-fuel
# push can fire again -- prevents flapping around the threshold from re-alerting.
FUEL_ALERT_REARM_MARGIN = 5


def evaluate_low_fuel():
    """Edge-triggered low-fuel check. Fires at most ONE push per below-threshold
    crossing (re-arms after climbing back above threshold + margin, on refuel, or when
    stopped). Safe to call repeatedly (the monitor thread + tests do). Returns the
    action taken: 'push' | 'rearm' | 'skip' (for logging/tests). Never raises."""
    global _low_fuel_alerted
    do_push = False
    msg_level = 0
    with state_lock:
        # Feature or alerting off -> do nothing (but don't touch the arm flag).
        if not alerts_state.get("fuel_enabled", True) or not alerts_state.get("alerts_on", True):
            return "skip"
        # Not running -> nothing is draining; re-arm for the next real crossing.
        if not generator_state["running"]:
            _low_fuel_alerted = False
            return "skip"
        level = projected_fuel_level_locked()
        thr = alerts_state.get("alert_threshold", 20)
        if level <= thr and not _low_fuel_alerted:
            _low_fuel_alerted = True
            do_push = True
            msg_level = int(round(level))
        elif level > thr + FUEL_ALERT_REARM_MARGIN and _low_fuel_alerted:
            _low_fuel_alerted = False
            return "rearm"
        else:
            return "skip"
    # Send OUTSIDE the lock (send_push_async only spawns a thread, but keep the pattern).
    if do_push:
        record_event("fuel", f"Low fuel alert: projected level ~{msg_level}%")
        send_push_async(
            "Low fuel", f"Projected level ~{msg_level}% - refuel soon.", tag="lowfuel"
        )
        return "push"
    return "skip"  # pragma: no cover - unreachable: the only branch that exits the `with` block without returning sets do_push=True, so `if do_push` is always True here


# ---------------------------------------------------------------------------
# SYSTEM perf history -- an in-memory ring buffer of cheap host metrics sampled
# on ONE background daemon thread. RAM only: nothing here ever touches the SD
# card. Every reader below fails SOFT (returns None) so a missing source (no
# thermal zone / no vcgencmd / no wlan0 on a dev box) degrades to a null series
# instead of crashing the sampler.
# ---------------------------------------------------------------------------

# The metric fields in a single history point, in a FIXED order. This tuple is the
# single source of truth shared by _sample_system() (which builds each point) and the
# columnar /api/system/history serializer (which emits one array per field). The
# frontend's colsToRows() rebuilds row objects assuming this exact set of keys.
SYS_FIELDS = ("t", "cpu", "mem", "load1", "load5", "temp", "volt", "thr", "rssi", "qual")

# Fixed-size history. maxlen evicts the oldest point automatically, so memory is
# bounded regardless of uptime. Guarded by _sys_hist_lock for snapshot-vs-append.
_sys_history = collections.deque(maxlen=int(CONFIG.get("SYSTEM_HISTORY_POINTS", 240)))
_sys_hist_lock = threading.Lock()

# Previous (total, idle) jiffies from /proc/stat, held between samples so CPU% is a
# DELTA computed by the sampler -- never a per-request cost.
_prev_cpu = None


def _read_cpu_times():
    """Return (total_jiffies, idle_jiffies) from the aggregate 'cpu' line of
    /proc/stat, or None if it can't be read/parsed. idle counts idle+iowait."""
    try:
        with open("/proc/stat") as f:
            line = f.readline()
        parts = line.split()
        if not parts or parts[0] != "cpu":
            return None
        vals = [int(x) for x in parts[1:]]
        # Fields: user nice system idle iowait irq softirq steal guest guest_nice
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)  # idle + iowait
        return (sum(vals), idle)
    except (OSError, ValueError, IndexError):
        return None


def _cpu_delta_pct(prev, cur):
    """Utilization % between two (total, idle) samples, or None when it can't be
    computed (no previous sample yet, or no elapsed time)."""
    if prev is None or cur is None:
        return None
    total_d = cur[0] - prev[0]
    idle_d = cur[1] - prev[1]
    if total_d <= 0:
        return None
    return round(100.0 * (total_d - idle_d) / total_d, 1)


def _cpu_pct():
    """Stateful CPU% for the sampler: reads /proc/stat, diffs against the previous
    read, stores the new read. Returns None on the first call (seeds the baseline)
    and on any read failure."""
    global _prev_cpu
    cur = _read_cpu_times()
    prev, _prev_cpu = _prev_cpu, cur
    return _cpu_delta_pct(prev, cur)


def _read_loadavg():
    """(1-min, 5-min) load averages from /proc/loadavg, or (None, None)."""
    try:
        with open("/proc/loadavg") as f:
            parts = f.read().split()
        return (round(float(parts[0]), 2), round(float(parts[1]), 2))
    except (OSError, ValueError, IndexError):
        return (None, None)


def _read_mem_pct():
    """Used-memory percentage from /proc/meminfo: 100*(1 - MemAvailable/MemTotal),
    or None. MemAvailable (not MemFree) is the kernel's honest 'free-ish' figure."""
    try:
        total = avail = None
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    total = float(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    avail = float(line.split()[1])
                if total is not None and avail is not None:
                    break
        if not total or avail is None:
            return None
        return round(100.0 * (1.0 - avail / total), 1)
    except (OSError, ValueError, IndexError):
        return None


# Cached auto-detected thermal-zone path (resolved once; scanning every sample is waste).
_temp_path_cache = None


def _auto_temp_path():
    """Pick the best thermal-zone temp file in Python: honor SYSTEM_TEMP_PATH if set,
    else scan /sys/class/thermal for a zone whose `type` looks like the CPU/SoC sensor
    (cpu/soc/x86_pkg/arm), falling back to the first zone, then thermal_zone0. Cached so
    the scan runs once."""
    global _temp_path_cache
    override = CONFIG.get("SYSTEM_TEMP_PATH", "")
    if override:
        return override
    if _temp_path_cache is not None:
        return _temp_path_cache
    default = "/sys/class/thermal/thermal_zone0/temp"
    chosen = default
    try:
        import glob
        first = None
        for zt in sorted(glob.glob("/sys/class/thermal/thermal_zone*/type")):
            base = zt.rsplit("/", 1)[0] + "/temp"
            if first is None:
                first = base
            try:
                kind = open(zt).read().strip().lower()
            except OSError:
                continue
            if any(k in kind for k in ("cpu", "soc", "x86_pkg", "arm")):
                chosen = base
                break
        else:
            chosen = first or default
    except Exception:
        chosen = default
    _temp_path_cache = chosen
    return chosen


def _read_temp_c():
    """SoC/CPU temperature in degrees C (millidegrees / 1000), or None. Reads the
    auto-selected (or SYSTEM_TEMP_PATH-overridden) thermal zone."""
    try:
        with open(_auto_temp_path()) as f:
            return round(int(f.read().strip()) / 1000.0, 1)
    except (OSError, ValueError):
        return None


def _read_wifi():
    """(rssi_dbm, link_quality) from /proc/net/wireless, or (None, None). The first
    two lines are headers; an interface data line has the form:
        wlan0: 0000   48.  -62.  -256   ...
    where col 2 = link quality and col 3 = signal level (dBm). Uses SYSTEM_WIFI_IFACE
    if set, else the first interface found. Trailing dots are stripped before int()."""
    want = CONFIG.get("SYSTEM_WIFI_IFACE", "")
    try:
        with open("/proc/net/wireless") as f:
            lines = f.readlines()
        for line in lines[2:]:
            if ":" in line:
                name = line.split(":", 1)[0].strip()
                if want and name != want:
                    continue
                fields = line.split()
                qual = int(float(fields[2].rstrip(".")))
                rssi = int(float(fields[3].rstrip(".")))
                return (rssi, qual)
        return (None, None)
    except (OSError, ValueError, IndexError):
        return (None, None)


def _vcgencmd(*args):
    """Run `vcgencmd <args>` and return stripped stdout, or None if the binary is
    absent (dev laptop) or the call errors/times out. Pi-only; cheap (~ms)."""
    try:
        res = subprocess.run(["vcgencmd", *args],
                             capture_output=True, text=True, timeout=2)
        if res.returncode != 0:
            return None
        return res.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def _parse_volts(s):
    """'volt=1.3500V' -> 1.35 (V), or None (incl. a None input from _vcgencmd)."""
    try:
        return round(float(s.strip().split("=")[1].rstrip("V")), 3)
    except (ValueError, IndexError, AttributeError):
        return None


def _read_volt():
    """Core voltage in volts via vcgencmd, or None off-Pi."""
    return _parse_volts(_vcgencmd("measure_volts", "core"))


def _parse_throttled(s):
    """'throttled=0x50005' -> 0x50005 (int bitmask), or None (incl. a None input).
    Bits of interest: 0 = under-voltage NOW, 2 = throttled NOW,
    16 = under-voltage since boot, 18 = throttled since boot."""
    try:
        return int(s.strip().split("=")[1], 16)
    except (ValueError, IndexError, AttributeError):
        return None


def _read_throttled():
    """get_throttled bitmask via vcgencmd, or None off-Pi."""
    return _parse_throttled(_vcgencmd("get_throttled"))


def _sample_system():
    """Read every metric once and append a single compact point to the in-memory
    ring buffer. Each reader already fails soft to None, so a missing source just
    yields a null field. Never raises for a normal missing-source condition."""
    load1, load5 = _read_loadavg()
    rssi, qual = _read_wifi()
    point = {
        "t": int(time.time()),
        "cpu": _cpu_pct(),        # stateful delta; None on the very first sample
        "mem": _read_mem_pct(),
        "load1": load1,
        "load5": load5,
        "temp": _read_temp_c(),
        "volt": _read_volt(),
        "thr": _read_throttled(),
        "rssi": rssi,
        "qual": qual,
    }
    with _sys_hist_lock:
        _sys_history.append(point)


def system_monitor_loop():
    """Background daemon: sample host metrics into the ring buffer every
    SYSTEM_HISTORY_SECONDS. Stops cleanly when _monitor_stop is set. RAM only --
    never writes to disk."""
    interval = max(5, int(CONFIG.get("SYSTEM_HISTORY_SECONDS", 15)))
    log.info(f"System monitor started (every {interval}s)")
    while not _monitor_stop.wait(interval):
        try:
            _sample_system()
        except Exception as e:
            log.warning(f"System monitor iteration error: {e}")


def fuel_monitor_loop():
    """Background daemon: periodically evaluate the fuel projection so a low-fuel push
    fires even with NO browser open. Cadence from FUEL_MONITOR_SECONDS. Stops when
    _monitor_stop is set (clean shutdown)."""
    interval = max(5, int(CONFIG.get("FUEL_MONITOR_SECONDS", 60)))
    log.info(f"Fuel monitor started (every {interval}s)")
    while not _monitor_stop.wait(interval):
        try:
            evaluate_low_fuel()
        except Exception as e:
            log.warning(f"Fuel monitor iteration error: {e}")


# Minimum run-hours since the last fill before a reading is trusted to fit a rate.
# With a near-zero denominator the linear fit explodes (a 50% drop over 1 minute of
# runtime would imply ~3000 %/hr), so a too-soon reading is IGNORED rather than
# folded in and corrupting the estimate. ~0.05 h = 3 minutes of engine run-time.
FUEL_MIN_RUN_SINCE_FILL = 0.05


def record_fuel_reading(level):
    """Blend a freshly-observed tank level (%) into the drain-rate estimate and
    persist. Returns the (possibly unchanged) drain_rate.

    newRate = (fill_level - observed) / run-hours-since-fill, floored at 0.1; the
    stored rate is a 50/50 blend of the old and new estimate so a single noisy
    reading can't swing it wildly. More readings on one tank -> better estimate.

    A reading taken before FUEL_MIN_RUN_SINCE_FILL of run-time has elapsed since the
    fill is a no-op (returns the current rate): there isn't enough signal to fit a
    line, and forcing one would wildly corrupt the estimate.
    """
    level = max(0.0, min(100.0, float(level)))
    with state_lock:
        run_since_fill = max(
            0.0, _live_total_run_hours_locked() - fuel_state["fill_run_hours"]
        )
        if run_since_fill < FUEL_MIN_RUN_SINCE_FILL:
            # Too little run-time since the fill to fit a meaningful rate -- leave the
            # estimate untouched rather than blow it up on a tiny denominator.
            return fuel_state["drain_rate"]
        new_rate = max(0.1, (fuel_state["fill_level"] - level) / run_since_fill)
        fuel_state["drain_rate"] = _round1(0.5 * fuel_state["drain_rate"] + 0.5 * new_rate)
        snapshot = dict(fuel_state)
        # ATOMICITY: snapshot AND persist under the SAME state_lock. If kv_set ran
        # after releasing the lock, two overlapping mutators could interleave so the
        # LAST writer to reach kv_set persists a STALE snapshot -- kv would diverge
        # from memory and a field would silently revert on the next restart.
        # Persisting in-lock makes the (memory-mutate, kv-write) pair atomic.
        # LOCK ORDER (verified across the whole file): the only ordering that ever
        # occurs is state_lock -> _event_lock (kv_set/kv_get/record_event each take
        # _event_lock internally; already relied on at _apply_running_transition_locked
        # and load_persisted_state). NO code path takes _event_lock and THEN state_lock
        # -- every _event_lock holder (record_event/kv_get/kv_set/get_events/
        # subscription helpers) is a self-contained DB op that never touches state_lock.
        # So there is no lock-order inversion and no deadlock from calling kv_set here.
        kv_set("fuel_state", snapshot)
    return snapshot["drain_rate"]


def set_fuel_rate(rate):
    """Set the drain rate directly (%/hr, floored at 0.1) and persist. Returns it."""
    rate = max(0.1, _round1(rate))
    with state_lock:
        fuel_state["drain_rate"] = rate
        snapshot = dict(fuel_state)
        # Persist in-lock so the snapshot can't go stale between two overlapping
        # writers (see record_fuel_reading for the atomicity + lock-order rationale;
        # state_lock -> _event_lock is the only ordering, so no deadlock).
        kv_set("fuel_state", snapshot)
    return rate


def reset_fuel_rate():
    """Restore the drain rate to its configured default and persist. Returns it."""
    with state_lock:
        fuel_state["drain_rate"] = _round1(fuel_state["default_rate"])
        rate = fuel_state["drain_rate"]
        snapshot = dict(fuel_state)
        # Persist in-lock so the snapshot can't go stale between two overlapping
        # writers (see record_fuel_reading for the atomicity + lock-order rationale).
        kv_set("fuel_state", snapshot)
    return rate


def set_fuel_fill(level):
    """'Add gas': reset the baseline fill to `level` (%) at the current run-hour
    mark; the drain rate is retained. Persist + return the new fuel model."""
    global _low_fuel_alerted
    level = max(0.0, min(100.0, float(level)))
    with state_lock:
        fuel_state["fill_level"] = level
        fuel_state["fill_run_hours"] = _live_total_run_hours_locked()
        # Refuelling re-arms the low-fuel alert so the next real low crossing pushes.
        _low_fuel_alerted = False
        snapshot = dict(fuel_state)
        # Persist in-lock so the snapshot can't go stale between two overlapping
        # writers (see record_fuel_reading for the atomicity + lock-order rationale).
        kv_set("fuel_state", snapshot)
    return snapshot


def set_alerts(enabled=None, threshold=None, fuel_enabled=None):
    """Update the fuel/alert config (all fields optional) and persist. threshold is
    clamped to the design's 5..40 slider range. fuel_enabled gates the whole fuel
    feature. Returns the config."""
    with state_lock:
        if enabled is not None:
            alerts_state["alerts_on"] = bool(enabled)
        if threshold is not None:
            alerts_state["alert_threshold"] = int(max(5, min(40, int(threshold))))
        if fuel_enabled is not None:
            alerts_state["fuel_enabled"] = bool(fuel_enabled)
        snapshot = dict(alerts_state)
        # Persist in-lock so the snapshot can't go stale between two overlapping
        # writers (see record_fuel_reading for the atomicity + lock-order rationale).
        kv_set("alerts_state", snapshot)
    return snapshot


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
    send_push_async(
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


# Base for all release fetches -- the repo's default branch over HTTPS. Every updater URL
# is built from this FIXED base + a fixed suffix (never request-derived), so there is no
# SSRF surface. TLS gives MITM protection; the manifest's per-file SHA-256 gives integrity.
_RAW_BASE = "https://raw.githubusercontent.com/mrchrisneal/generatorpi/main"
_LATEST_VERSION_URL = _RAW_BASE + "/VERSION"
_MANIFEST_URL = _RAW_BASE + "/manifest.json"


def _version_tuple(v):
    """Parse a dotted version like '1.2.3' into a comparable int tuple (1,2,3). Non-numeric
    parts degrade to 0 so a malformed value can't raise into the caller."""
    out = []
    for part in str(v).split("."):
        try:
            out.append(int(part))
        except ValueError:
            out.append(0)
    return tuple(out)


def _fetch_latest_version():
    """Fetch the latest published version string from the repo's raw VERSION file.
    Returns the trimmed string, or None on ANY failure (offline Pi, private/renamed repo,
    timeout) -- the caller treats None as 'could not check', never as an error."""
    try:
        req = urllib.request.Request(_LATEST_VERSION_URL,
                                     headers={"User-Agent": "GeneratorPi-update-check"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            # Read a small, bounded amount -- a VERSION file is a few bytes; cap defensively.
            return resp.read(64).decode("utf-8", "replace").strip() or None
    except Exception as e:                       # noqa: BLE001 -- network/parse errors are non-fatal
        log.info(f"Update check failed: {e}")
        return None


# Cached result of the most recent GitHub update check. The footer refreshes on a 5-minute
# timer by READING THIS CACHE (no network) -- only the server loop, the on-load check, and a
# manual "Check again" actually reach out to the repo, so an open browser never hammers GitHub.
_update_check_cache = {"latest": None, "update_available": False, "checked_at": None}


def _run_update_check():
    """Hit the repo, compute availability, UPDATE THE CACHE, and return the result. The ONLY
    path that performs the network call for an update check (loop / on-load / manual)."""
    latest = _fetch_latest_version()
    available = latest is not None and _version_tuple(latest) > _version_tuple(APP_VERSION)
    with _update_lock:
        _update_check_cache.update(latest=latest, update_available=bool(available),
                                   checked_at=time.time())
    return {"installed": APP_VERSION, "latest": latest, "update_available": bool(available)}


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


# ============================================================================
# SELF-UPDATER (#8) -- download a release, verify EVERY file's SHA-256 against the
# published manifest, full-backup, swap, then restart. TLS + hash (no signing); files
# come from the repo raw base per the manifest. Verify-before-swap is mandatory; any
# failure aborts and restores the backup (we keep running the old version).
# ============================================================================
_UPDATE_STAGING = SCRIPT_DIR / ".update_staging"   # downloaded (then verified) release files
_BACKUP_DIR = SCRIPT_DIR / "backups"               # ZIP snapshots taken before each update
# Result marker + log written by the swap step and READ on the next startup, so we can show
# the user "the update just succeeded/failed" + the log in a modal even though the process
# restarted in between. Cleared once the client acknowledges it.
_UPDATE_RESULT = _BACKUP_DIR / "last_update.json"
_UPDATE_LOG = _BACKUP_DIR / "last_update.log"
# systemd unit written by setup.sh on a real install; absent in dev. Presence tells a
# managed-service deploy (restart via systemctl) from a run-it-yourself one (re-exec).
_SERVICE_UNIT = Path("/etc/systemd/system/generator_control.service")

# Live progress the UI polls. phase: idle/checking/downloading/verifying/backing_up/
# swapping/restarting/done/failed. Its own lock (touched from the worker thread).
_update_state = {"phase": "idle", "message": "", "progress": 0.0, "error": None,
                 "version": None, "systemd": None, "log": [], "decide": None,
                 # Stage-1 dependency check results (populated during [CHECKING DEPENDENCIES]).
                 # missing_deps: [{apt, feature, required}, ...]; deps_install_cmd: the apt one-liner.
                 "missing_deps": [], "deps_install_cmd": "",
                 # Manifest-declared update constraints (populated during [VALIDATING RELEASE]).
                 # installable: False => the release refuses in-app apply (greyed button); important_notes:
                 # operator guidance shown as "IMPORTANT: <note>" lines. Default installable True so an
                 # older manifest (no key) stays applicable (forward-compatible).
                 "installable": True, "important_notes": [],
                 # Which stage the worker is in (1 = pre-apply checks, 2 = apply/swap/restart) + a
                 # per-stage tally of warning/error lines -> the end-of-stage colored summary lines.
                 "stage": 1, "counts": {"stage1": {"warn": 0, "err": 0}, "stage2": {"warn": 0, "err": 0}}}
_update_lock = threading.Lock()
# Decision gate: when the run hits an error/warning it parks on phase "awaiting" and BLOCKS on
# this event until the user clicks REVERT or PROCEED (default REVERT on timeout). One update runs
# at a time, so a single event + holder is sufficient.
_update_decision_event = threading.Event()
_update_decision_choice = {"choice": None}


def _update_log(line):
    """Append one line to the live terminal log the progress view + result modal render."""
    with _update_lock:
        _update_state["log"].append(line)


def _update_log_append(text):
    """Append `text` to the CURRENT last log line (e.g. tack ' ok' onto a '[SECTION]' header
    once its step finishes, so it renders as '[SECTION] ok' on one line)."""
    with _update_lock:
        if _update_state["log"]:
            _update_state["log"][-1] += text
        else:
            _update_state["log"].append(text)


# Severity markers prefixed onto a log line so the terminal colours the WHOLE line (amber for a
# warning, red for an error) even when it carries no visible "WARNING:"/"ERROR:" label or "[TAG]".
# _fmtLogLine in the UI strips the marker before rendering, so it never displays or gets copied.
_SEV_MARK = {"warn": "", "err": ""}


def _update_sev(line, sev):
    """Log a line flagged with a severity marker so the terminal colours the whole line. Does NOT
    tally -- for label-less detail lines (e.g. the copy-clean install command)."""
    _update_log(_SEV_MARK.get(sev, "") + line)


def _update_warn(line):
    """Log a WARNING line AND tally it against the CURRENT stage for the end-of-stage summary. The
    caller includes the visible 'WARNING:' label (which the terminal colours amber); this logs +
    counts."""
    _update_log(line)
    with _update_lock:
        _update_state["counts"]["stage2" if _update_state.get("stage") == 2 else "stage1"]["warn"] += 1


def _update_err(line):
    """Log an ERROR line AND tally it against the CURRENT stage (see _update_warn; the caller
    includes the visible 'ERROR:' label, coloured red)."""
    _update_log(line)
    with _update_lock:
        _update_state["counts"]["stage2" if _update_state.get("stage") == 2 else "stage1"]["err"] += 1


def _stage_summary(stage):
    """Emit up to TWO colored summary lines as the LAST lines of a stage: a yellow [WARNING] count
    (only if any warnings were tallied) and a red [ERROR] count (only if any errors). Zero of a kind
    -> no line for it, so a clean stage adds nothing. Purely additive to the existing warning banner
    + log; the UI also one-time-scrolls to the bottom when a stage ends so these can't be missed."""
    with _update_lock:
        c = _update_state["counts"].get(f"stage{stage}", {"warn": 0, "err": 0})
        w, e = c["warn"], c["err"]
    if w:
        _update_log(f"[WARNING] Stage {stage}: {w} warning{'' if w == 1 else 's'} encountered")
    if e:
        _update_log(f"[ERROR] Stage {stage}: {e} error{'' if e == 1 else 's'} encountered")


def _await_decision(message, allow_proceed, proceed_label="PROCEED", proceed_disabled=False):
    """Park the run: show `message`, offer REVERT (+ a proceed button labelled `proceed_label`
    iff allow_proceed), and BLOCK until the user decides. Returns 'proceed' or 'revert' (defaults
    to the SAFE 'revert' on timeout so an unattended browser can never leave the updater hung
    mid-run). Requests to the Pi stay sequential -- the worker just waits; only the status poll
    continues. The caller already logs a terminal line for the situation, so we do NOT re-log
    `message` here (that would duplicate the line); it's kept only as the phase message.

    `proceed_disabled` (used for a release the manifest declares NOT web-installable) makes the UI
    SHOW the apply button but GREYED/disabled -- distinct from a plain error park, which hides it --
    so the operator sees the action exists yet is refused. allow_proceed stays False in that case,
    so the backend also rejects a proceed even if the disabled button were somehow clicked."""
    with _update_lock:
        _update_state.update(phase="awaiting", message=message,
                             decide={"allow_proceed": bool(allow_proceed),
                                     "proceed_label": proceed_label,
                                     "proceed_disabled": bool(proceed_disabled)})
        _update_decision_choice["choice"] = None
    _update_decision_event.clear()
    got = _update_decision_event.wait(600)               # up to 10 min for a human decision
    with _update_lock:
        choice = _update_decision_choice["choice"] if got else "revert"
        if choice not in ("proceed", "revert"):
            choice = "revert"
        _update_state["decide"] = None
    _update_log(f"→ {choice.upper()}")
    return choice


def _deployment_has_systemd():
    """True on a systemd-managed install (unit file present AND systemctl available). False
    in dev, where we still swap the files but re-exec this process instead of a service."""
    return _SERVICE_UNIT.exists() and shutil.which("systemctl") is not None


def _service_skip_reason():
    """Decide whether the update restarts via the systemd SERVICE or swaps in-process, and say
    WHY. Returns None to use the service; otherwise a human-readable reason for skipping ALL
    service/systemd steps (swap in-process + re-exec instead). Honors the operator's env/config
    (a disabled service or autostart) BEFORE falling back to host detection, so the updater obeys
    the same preferences the rest of the app does."""
    def _off(v):
        return str(v).strip().lower() in ("false", "0", "no", "off", "disabled")
    # 1) Explicit operator opt-out in the env/config wins (obey preferences).
    if "SERVICE_ENABLED" in CONFIG and _off(CONFIG.get("SERVICE_ENABLED")):
        return "service disabled in config (SERVICE_ENABLED is off)"
    if "AUTOSTART" in CONFIG and _off(CONFIG.get("AUTOSTART")):
        return "autostart disabled in config (AUTOSTART is off)"
    # 2) Otherwise detect a non-systemd host / uninstalled unit.
    if not _SERVICE_UNIT.exists():
        return "no systemd service unit installed (not a service-managed install)"
    if shutil.which("systemctl") is None:
        return "systemctl not available (not a systemd / Raspberry Pi OS host)"
    return None


def _http_get_bytes(url, timeout=30, max_bytes=12_000_000):
    """GET a URL, return the (bounded) body. Raises on any HTTP/size error -- the updater
    treats every failure as 'abort + keep the old version'."""
    req = urllib.request.Request(url, headers={"User-Agent": "GeneratorPi-updater"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"response exceeds {max_bytes} bytes")
    return data


def _update_phase(name, msg, prog, error=None):
    with _update_lock:
        _update_state.update(phase=name, message=msg, progress=round(prog, 3), error=error)


def check_manifest_dependencies(manifest):
    """Return the manifest-DECLARED runtime dependencies that are NOT importable on THIS device.

    The manifest carries a `dependencies` list (module import-name, apt package, feature,
    required-ness). During update Stage 1 the updater checks each so it can warn the operator --
    with a copy-able install command -- about anything missing BEFORE the apply, WITHOUT ever
    installing it (auto-apt on a headless box would need broad privileged access + can hang the
    update). Importability is checked with importlib.util.find_spec, which resolves the module
    WITHOUT importing/executing it (no side effects, safe to run mid-update). An older manifest
    with no `dependencies` key -> [] (nothing to check). A find_spec that raises (a broken/partial
    install, e.g. a namespace-package shadow) is treated as MISSING, fail-safe."""
    missing = []
    for dep in manifest.get("dependencies") or []:
        mod = dep.get("module")
        # Only plain TOP-LEVEL module names are ever passed to find_spec. A dotted name ("a.b")
        # would make find_spec IMPORT the parent package ("a"), executing its __init__ -- so
        # restricting to a single identifier keeps this fully side-effect-free even against a
        # hostile/garbled manifest. Every real declared dep is top-level, so this never skips one.
        if not isinstance(mod, str) or not mod.isidentifier():
            continue
        try:
            present = importlib.util.find_spec(mod) is not None
        except Exception:
            present = False   # ImportError/ValueError from a broken install -> treat as missing
        if not present:
            missing.append(dep)
    return missing


# Valid Debian/apt package-name charset. dependency_install_command only ever emits names matching
# this, so a hostile/garbled manifest cannot smuggle shell metacharacters into the copy-able install
# one-liner. The app never RUNS the command, but a user might paste it -- defense in depth.
_APT_PKG_RE = re.compile(r"^[a-z0-9][a-z0-9+.\-]*$")


def dependency_install_command(missing):
    """Build the copy-able apt one-liner that installs the given missing dependencies. Packages are
    deduped + sorted for a stable, tidy command, and ONLY well-formed apt package names (see
    _APT_PKG_RE) are included so a garbled/hostile manifest can't inject shell metacharacters into a
    string a user might paste. Returns "" when nothing installable is missing."""
    pkgs = sorted({d.get("apt") for d in missing
                   if isinstance(d.get("apt"), str) and _APT_PKG_RE.match(d.get("apt"))})
    if not pkgs:
        return ""
    return "sudo apt install -y " + " ".join(pkgs)


def _download_and_verify(manifest, base=None, staging=None):
    """Download every manifest file to a FRESH staging dir and verify its SHA-256. Raises
    on the FIRST mismatch/failure (nothing live is touched). Also compile-checks EVERY staged
    .py -- a file that hashes fine but won't compile would brick the swap.
    `base`/`staging` are injectable for tests."""
    base = base or _RAW_BASE
    staging = staging or _UPDATE_STAGING
    files = manifest.get("files") or []
    if not files:
        raise ValueError("manifest lists no files")
    _validate_manifest_paths(manifest)                 # never write outside the project root
    if staging.exists():
        shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True, exist_ok=True)
    n = len(files)
    # STAGE 'DOWNLOADING': fetch every file into staging (nothing live is touched). The caller
    # logs the [DOWNLOADING] header; we log one child line per file as it lands.
    for i, f in enumerate(files):
        rel, size = f["path"], int(f.get("bytes", 0))
        _update_phase("downloading", f"Downloading {rel}…", 0.10 + 0.40 * (i / n))
        data = _http_get_bytes(base + "/" + rel, max_bytes=max(size + 4096, 8192))
        dest = staging / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        _update_log(f"  {rel} … {len(data)} bytes")
    # STAGE 'VERIFYING': re-hash each staged file against the manifest, then compile-check every
    # staged .py. All verification is on the staged copies -- nothing live is touched until it passes.
    _update_log(f"[VERIFYING] SHA-256 of {n} files")
    _update_phase("verifying", "Verifying SHA-256…", 0.66)
    for f in files:
        rel, want = f["path"], f["sha256"]
        got = hashlib.sha256((staging / rel).read_bytes()).hexdigest()
        if got != want:
            raise ValueError(f"hash mismatch for {rel}: expected {want[:12]}…, got {got[:12]}…")
        _update_log(f"  {rel} … ok")
    # Compile-check EVERY staged .py before the swap is allowed to proceed. The app is now a
    # PACKAGE (genpi/…), so a single-file check is no longer enough: a submodule that hashes
    # fine but won't compile (a bad merge, a truncated download that still matched a stale hash)
    # would break the eager-import at startup and force a post-swap rollback. Catching it HERE --
    # on the staged copies, before anything live is touched -- keeps the apply safe.
    import py_compile
    py_files = [f["path"] for f in files if f["path"].endswith(".py")]
    for rel in py_files:
        try:
            py_compile.compile(str(staging / rel), doraise=True)
        except py_compile.PyCompileError as e:
            raise ValueError(f"staged {rel} failed to compile: {e}")
    if py_files:
        _update_log(f"  {len(py_files)} .py file(s) compile … ok")
    return staging


# Files a manifest must NEVER be allowed to overwrite even with an otherwise-valid in-root path
# -- operator secrets/config/certs. Clobbering these wouldn't leave the app unreachable, but it
# would destroy credentials / lock users out, so we deny them as defense-in-depth (audit NEW-7).
# No shipped file legitimately ends in any of these, so the denylist can never block a real release.
_MANIFEST_DENY_SUFFIXES = (".env", ".pem", ".key")


def _validate_manifest_paths(manifest):
    """Reject a manifest whose file paths could escape the project root (absolute or
    containing '..'), or that target operator secrets/certs. These paths drive downloads,
    staging, backup, swap AND zip extraction, so this single gate is what stops a hostile/garbled
    manifest writing outside SCRIPT_DIR or clobbering .env / TLS material."""
    for f in manifest.get("files") or []:
        p = f.get("path", "")
        if (not p) or p.startswith("/") or p.startswith("\\") or ".." in Path(p).parts:
            raise ValueError(f"unsafe manifest path: {p!r}")
        low = p.lower()
        if low.endswith(_MANIFEST_DENY_SUFFIXES) or low.endswith("generator_control.env"):
            raise ValueError(f"manifest may not overwrite a secret/cert file: {p!r}")


# Version strings are interpolated into the bootstrap shell script + JSON marker, so restrict
# them to an obviously-safe charset (defends against shell/JSON injection from a hostile or
# garbled manifest -- audit H1).
_VERSION_RE = re.compile(r"^[A-Za-z0-9.+_-]{1,64}$")


def _validate_version(version):
    if not (version and _VERSION_RE.match(str(version))):
        raise ValueError(f"unsafe manifest version: {version!r}")


def _ensure_backup_dir():
    """Create backups/ and PROVE it's writable (write+delete a probe). Called at startup so a
    permission problem is an immediate, loud failure -- we must never discover mid-update that
    we can't take a backup. Raises on any failure (the caller fails the process fast)."""
    _BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    probe = _BACKUP_DIR / ".write_probe"
    probe.write_text("ok")
    probe.unlink()


def _preflight_check(manifest, dest_root=None, log=None):
    """FINAL sanity check BEFORE any download/swap: prove we can actually write everywhere the
    update will touch -- the backups dir, the staging area, the project root, and EVERY target
    file's directory (and the file itself if it already exists) -- plus enough free disk. Raises
    with a clear message on the first problem so we abort before changing anything, never
    half-applying an update we can't finish. `dest_root` is injectable for tests; `log`, if given,
    receives one '  <check> … ok' terminal line per passed sub-check."""
    dest_root = dest_root or SCRIPT_DIR

    def writable(p):
        return os.access(str(p), os.W_OK)

    def _ok(msg):
        if log:
            log(f"  {msg} … ok")

    _ensure_backup_dir()                                  # backups/ creatable + writable (rollback)
    _ok("backups directory writable (rollback path)")
    if not writable(dest_root):
        raise PermissionError(f"project root is not writable: {dest_root}")
    _ok("project root writable")
    if not writable(_UPDATE_STAGING.parent):
        raise PermissionError(f"cannot write the staging area under: {_UPDATE_STAGING.parent}")
    _ok("staging area writable")
    files = manifest.get("files") or []
    for f in files:
        target = dest_root / f["path"]
        d = target.parent
        if d.exists() and not writable(d):
            raise PermissionError(f"target directory is not writable: {d}")
        if target.exists() and not writable(target):
            raise PermissionError(f"target file is not writable: {target}")
    _ok(f"all {len(files)} target files writable")
    # Free space: we need room for the download staging + the backup zip + the swap. Require the
    # summed file sizes with generous headroom so we never run out mid-swap (audit H2).
    need = sum(int(f.get("bytes", 0)) for f in files) * 3 + 5_000_000
    try:
        free = shutil.disk_usage(str(dest_root)).free
    except OSError:
        free = None
    if free is not None and free < need:
        raise OSError(f"insufficient free disk space for update: need ~{need}, have {free}")
    if free is not None:
        _ok(f"free disk space ({free // 1_000_000} MB free, need ~{need // 1_000_000} MB)")


def _write_update_result(status, version, note="", log_text=None, started_ts=None):
    """Persist an update outcome ({status, version, note, ts}) + optional log to backups/ so
    the NEXT startup can show the user how the update went (a restart happens in between).
    `started_ts` is the apply-start unix time; it's stored so the post-restart startup can compute
    how long the update took (the restart happens in between, so it can't measure it directly).
    Best-effort -- never raises into the update flow."""
    try:
        _BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        _UPDATE_RESULT.write_text(json.dumps({
            "status": status, "version": version, "note": note,
            "ts": datetime.now().isoformat(timespec="seconds"),
            "started_ts": started_ts,
        }))
        if log_text is not None:
            _UPDATE_LOG.write_text(log_text)
    except Exception as e:                               # noqa: BLE001 -- marker is best-effort
        log.error(f"could not write update result marker: {e}")


def _make_backup(manifest, dest_root=None, backup_dir=None):
    """Snapshot the CURRENT state of every manifest file into a timestamped ZIP in backups/
    (which is never itself in the manifest, so never backed up or swapped). Also record --
    inside the zip -- the manifest files that DON'T yet exist ('added'), so a rollback can
    DELETE them and land on the exact pre-update file set (presence/names/count, not just
    contents). Returns (zip_path, added)."""
    dest_root = dest_root or SCRIPT_DIR
    backup_dir = backup_dir or _BACKUP_DIR
    backup_dir.mkdir(parents=True, exist_ok=True)
    paths = [f["path"] for f in (manifest.get("files") or [])]
    present = [p for p in paths if (dest_root / p).is_file()]
    added = [p for p in paths if not (dest_root / p).exists()]
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    zpath = backup_dir / f"backup-{ts}-v{APP_VERSION}.zip"
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for p in present:
            z.write(dest_root / p, p)                    # arcname = relative path
        z.writestr("__added__.json", json.dumps(added))
    # VERIFY the backup before anyone relies on it for rollback (audit H3): a corrupt/truncated
    # zip must be caught NOW, while the old files are still live, not discovered mid-rollback.
    with zipfile.ZipFile(zpath) as z:
        if z.testzip() is not None:
            raise OSError(f"backup archive failed integrity check: {zpath}")
        names = set(z.namelist())
        for p in present:                                # every backed-up file must read back
            if p not in names or hashlib.sha256(z.read(p)).hexdigest() != \
                    hashlib.sha256((dest_root / p).read_bytes()).hexdigest():
                raise OSError(f"backup archive is missing/corrupt for {p}")
    _prune_backups(backup_dir=backup_dir)                # cap retained backups (newest 20)
    return zpath, added


def _prune_backups(keep=20, backup_dir=None):
    """Keep at most `keep` most-recent backup zips and delete the rest, so backups/ can never
    grow without bound across many updates. Best-effort -- never raises into the update flow."""
    backup_dir = backup_dir or _BACKUP_DIR
    try:
        zips = sorted(backup_dir.glob("backup-*.zip"),
                      key=lambda p: p.stat().st_mtime, reverse=True)
        for old in zips[keep:]:
            try:
                old.unlink()
            except OSError:
                pass
    except Exception as e:                                # noqa: BLE001 -- pruning is best-effort
        log.warning(f"backup prune failed: {e}")


def _swap(manifest, staging=None, dest_root=None, log_fn=None):
    """Copy verified staged files over the live ones (the DEV path; the systemd path swaps
    from the /tmp bootstrap while the service is stopped). Each file is replaced ATOMICALLY --
    copy to a sibling temp, then os.replace (rename) over the live file -- so an interruption
    can never leave a half-written live file (mirrors the bootstrap's cp→mv, audit NEW-1).
    If `log_fn` is given, each swapped file is reported (old→new bytes) so Stage 2's terminal
    shows exactly what was replaced, at Stage-1-level detail."""
    staging = staging or _UPDATE_STAGING
    dest_root = dest_root or SCRIPT_DIR
    for f in manifest.get("files") or []:
        live = dest_root / f["path"]
        live.parent.mkdir(parents=True, exist_ok=True)
        existed = live.exists()
        old_bytes = live.stat().st_size if existed else 0   # for the "old→new" report
        # Preserve the LIVE file's permission bits (e.g. the +x on setup.sh/update.sh): the staged
        # copy was written via write_bytes() with the default umask mode, so without this the swap
        # would silently drop the executable bit on shell scripts (audit: exec-bit preservation).
        orig_mode = stat.S_IMODE(live.stat().st_mode) if existed else None
        tmp = live.with_name(live.name + ".gpnew")       # sibling temp on the same filesystem
        shutil.copy2(staging / f["path"], tmp)
        if orig_mode is not None:
            os.chmod(tmp, orig_mode)                     # re-apply the original permissions
        os.replace(tmp, live)                            # atomic rename over the live file
        if log_fn:                                       # per-file line: "<path> … 332385 → 333025 bytes … ok"
            new_bytes = live.stat().st_size
            verb = "new" if old_bytes == 0 else f"{old_bytes} →"
            log_fn(f"  {f['path']} … {verb} {new_bytes} bytes … ok")


def _rollback(zip_path, dest_root=None):
    """Restore the EXACT pre-update state from a backup zip: delete update-added files, then
    extract the backed-up files over the live ones. Best-effort, never raises."""
    dest_root = dest_root or SCRIPT_DIR
    try:
        with zipfile.ZipFile(zip_path) as z:
            try:
                added = json.loads(z.read("__added__.json").decode("utf-8"))
            except Exception:
                added = []
            for p in added:
                try:
                    (dest_root / p).unlink()
                except OSError:
                    pass
            for name in z.namelist():
                if name != "__added__.json":
                    z.extract(name, dest_root)
    except Exception as e:                               # noqa: BLE001 -- rollback is best-effort
        log.error(f"Rollback from {zip_path} failed: {e}")


def _write_bootstrap_script(manifest, version, zip_path, staging, health_url, t_apply=None):
    """Write a STANDALONE swap+restart+rollback script to /tmp; return its path.

    Runs from /tmp -- OUTSIDE the project root -- so it can replace EVERY project file,
    including the genpi/ package that houses this updater code itself. Robustness (post-audit):
      * The unit is installed with KillMode=process (setup.sh), so a `systemctl restart`
        kills only the OLD main process, NOT this detached child -- fixing the cgroup
        self-kill that previously bricked every update (audit C1).
      * HEALTH = an actual HTTP request to the listener (any response, even a 401 auth
        challenge, proves it bound + is serving), required 3 times consecutively -- NOT
        `systemctl is-active`, which reports active the instant a Type=simple process forks
        and would pass a broken build (audit C2).
      * An EXIT trap rolls back on ANY non-success exit -- swap error, failed restart, failed
        health check, or an unexpected death mid-run (audit M2). Rollback restores the backup
        zip (delete-added + extract), restarts the OLD version, and re-verifies it is healthy,
        recording whether recovery itself succeeded (audit H5).
      * `version` is validated (charset) upstream and referenced only via the quoted $VER
        shell var, never interpolated raw (audit H1)."""
    q = shlex.quote
    paths = [f["path"] for f in (manifest.get("files") or [])]
    # ATOMIC per-file swap (audit NEW-1): copy the staged file to a sibling temp on the SAME
    # filesystem, then `mv` (rename(2)) it over the live file. The live file is therefore only
    # ever replaced all-at-once -- a power loss mid-copy leaves a harmless *.gpnew temp, never a
    # truncated genpi module that would crash-loop the service on reboot.
    # Also preserve the live file's mode (e.g. +x on setup.sh/update.sh) onto the replacement,
    # best-effort via `chmod --reference` -- otherwise the swap would drop the exec bit like the
    # dev _swap did before its fix. The ( …; true ) subshell can't fail the &&-chain, so mv always
    # proceeds even if the reference/chmod is unavailable.
    copies = "\n".join(
        f'mkdir -p "$ROOT/$(dirname {q(p)})" && '
        f'cp -f {q(str(staging))}/{q(p)} "$ROOT"/{q(p)}.gpnew && '
        f'( [ -e "$ROOT"/{q(p)} ] && chmod --reference="$ROOT"/{q(p)} "$ROOT"/{q(p)}.gpnew 2>/dev/null; true ) && '
        f'mv -f "$ROOT"/{q(p)}.gpnew "$ROOT"/{q(p)}'
        for p in paths
    )
    # Rollback via system python3 (independent of the project files being swapped).
    py_rollback = (
        "python3 - " + q(str(zip_path)) + " \"$ROOT\" <<'PY'\n"
        "import sys, zipfile, json, os\n"
        "zp, root = sys.argv[1], sys.argv[2]\n"
        "z = zipfile.ZipFile(zp)\n"
        "try: added = json.loads(z.read('__added__.json'))\n"
        "except Exception: added = []\n"
        "for p in added:\n"
        "    try: os.remove(os.path.join(root, p))\n"
        "    except OSError: pass\n"
        "for n in z.namelist():\n"
        "    if n != '__added__.json': z.extract(n, root)\n"
        "PY"
    )
    body = (
        "#!/bin/bash\n"
        "# GeneratorPi self-update bootstrap (generated). Detached + KillMode=process, so a\n"
        "# service restart can't kill it; replaces every file incl. the updater; HTTP health-\n"
        "# checks the new version; EXIT-trap rolls back to the backup on ANY failure.\n"
        f"ROOT={q(str(SCRIPT_DIR))}\n"
        f"VER={q(version)}\n"
        f"HEALTH_URL={q(health_url)}\n"
        "SVC=generator_control.service\n"
        "mkdir -p \"$ROOT/backups\"\n"
        "RESULT=\"$ROOT/backups/last_update.json\"\n"
        "exec >> \"$ROOT/backups/last_update.log\" 2>&1\n"          # APPEND to the seeded pre-restart log
        # Emit lines verbatim so they match the Stage-1 terminal style: a bracketed [TAG] renders as
        # a bright header, a leading-space '  … ok' as a dim child. No prefix, no timestamp.
        "log() { echo \"$*\"; }\n"
        "write_result() { printf '{\"status\":\"%s\",\"version\":\"%s\",\"ts\":\"%s\",\"note\":\"%s\"}\\n'"
        " \"$1\" \"$VER\" \"$(date -Iseconds)\" \"$2\" > \"$RESULT\"; }\n"
        # Any HTTP response (incl. a 401 challenge) proves the listener bound + is serving.
        # Probe via python3 -- the app's OWN runtime, so it's guaranteed present (curl is not
        # on every base image; a missing curl would fail every health check and needlessly roll
        # back good updates -- audit NEW-2). TLS verification is intentionally DISABLED here and
        # ONLY here: this is a 127.0.0.1 liveness probe against the app's OWN self-signed cert,
        # where we care whether it ANSWERS, not its identity (same reason the old curl used -k).
        # It is NOT a data fetch -- the actual manifest/file downloads use full TLS verification.
        "health() { python3 - \"$HEALTH_URL\" <<'PY'\n"
        "import sys, urllib.request, urllib.error, ssl\n"
        "try:\n"
        "    urllib.request.urlopen(sys.argv[1], timeout=3, context=ssl._create_unverified_context())\n"
        "except urllib.error.HTTPError:\n"
        "    pass          # any HTTP status (401 etc.) means the server is up + serving\n"
        "except Exception:\n"
        "    sys.exit(1)   # connection refused / timeout -> not serving yet\n"
        "PY\n"
        "}\n"
        "wait_healthy() { local c=0 i; for i in $(seq 1 30); do if health; then c=$((c+1)); "
        "[ $c -ge 3 ] && return 0; else c=0; fi; sleep 2; done; return 1; }\n"
        "rollback() {\n"
        "  log '[ROLLBACK] restoring backup + restarting the previous version'\n"
        f"  {py_rollback}\n"
        "  sudo systemctl restart \"$SVC\" 2>/dev/null || true\n"
        "  [ \"$T_APPLY\" != 0 ] && log \"Update failed after $(( $(date +%s) - T_APPLY )) seconds\"\n"
        "  if wait_healthy; then write_result failed 'Update failed - rolled back to the previous version.';\n"
        "  else write_result failed 'Update failed AND rollback did not become healthy - manual check needed.'; fi\n"
        "}\n"
        # Apply-start unix time (stamped in Python at [APPLYING]) so the bootstrap can report how
        # long the update took; 0 means unknown -> the timing line is skipped.
        f"T_APPLY={int(t_apply) if t_apply else 0}\n"
        # Roll back on ANY exit that didn't reach SUCCEEDED=1 (covers unexpected deaths too).
        "SUCCEEDED=0\n"
        "DONE_FLAG=\"$ROOT/backups/.gp_update_done\"; rm -f \"$DONE_FLAG\"\n"
        "on_exit() { [ \"$SUCCEEDED\" = 1 ] && return; log '[ROLLBACK] update did not complete — rolling back'; rollback; }\n"
        "trap on_exit EXIT\n"
        # WATCHDOG (audit M-3): guarantee a BOUNDED recovery. An update should never run long --
        # owner cap is 10 minutes TOPS. If the whole apply isn't done within 10 min (a wedged
        # systemctl restart / stuck mount leaving the app down), force a rollback and tear down this
        # run's process group so we never hang indefinitely. $$ is the session leader's PID (setsid),
        # so -$$ targets the bootstrap's group -- NOT the restarted service.
        "( sleep 600; [ -f \"$DONE_FLAG\" ] && exit 0; log '[WATCHDOG] 10m elapsed — forcing rollback'; rollback; kill -9 -$$ 2>/dev/null ) &\n"
        "WATCHDOG=$!\n"
        # Bound a stuck restart with `timeout` when it's available (dependency-free: fall back to a
        # plain restart if `timeout` isn't installed, so a missing coreutils never fails the update).
        "do_restart() { if command -v timeout >/dev/null 2>&1; then timeout 150 sudo systemctl restart \"$SVC\"; else sudo systemctl restart \"$SVC\"; fi; }\n"
        "sleep 1\n"
        # Swap while the OLD process is still running its in-memory code (safe for a python app),
        # then restart -- KillMode=process spares this detached bootstrap.
        f"( set -e\n{copies}\n) || exit 1\n"
        "log '  files swapped … ok'\n"
        "do_restart 2>/dev/null || exit 1\n"
        "log '  service restarted … ok'\n"
        "wait_healthy || exit 1\n"
        "log '  new version is serving … ok'\n"
        "[ \"$T_APPLY\" != 0 ] && log \"Update finished in $(( $(date +%s) - T_APPLY )) seconds\"\n"
        "log \"[DONE] Application successfully updated to v$VER!\"\n"
        "SUCCEEDED=1\n"
        "touch \"$DONE_FLAG\"\n"                                    # tell the watchdog we finished
        "kill \"$WATCHDOG\" 2>/dev/null\n"                          # cancel the watchdog
        "write_result success \"Updated to v$VER.\"\n"
        f"rm -f \"$DONE_FLAG\"; rm -rf {q(str(staging))}; rm -f \"$0\"\n"
    )
    fd, tmp = tempfile.mkstemp(prefix="gp-update-", suffix=".sh")
    os.close(fd)
    Path(tmp).write_text(body)
    os.chmod(tmp, 0o755)
    return tmp


def _run_update():
    """Background worker. DEV (no systemd): download+verify+backup, swap in-process, then
    re-exec -- safe because the running process holds the OLD code in memory until re-exec.
    SYSTEMD: download+verify+backup, then hand swap+restart to a /tmp bootstrap that can
    replace even the genpi/ package itself and self-heals (rollback + restart) on failure. Errors
    before any swap abort cleanly; a failed same-process swap rolls back from the backup zip."""
    manifest = None
    zpath = None
    swapped = False
    t_apply = None                                        # set when Stage 2 (apply/swap) actually begins
    with _update_lock:                                    # fresh per-run stage + warn/err tally + dep
        _update_state["stage"] = 1                        # results (belt-and-suspenders: self-contained
        _update_state["counts"] = {"stage1": {"warn": 0, "err": 0},  # even if a caller skipped the
                                   "stage2": {"warn": 0, "err": 0}}   # api_update_start reset)
        _update_state["missing_deps"] = []
        _update_state["deps_install_cmd"] = ""
        _update_state["installable"] = True               # optimistic default; the manifest may lower it
        _update_state["important_notes"] = []
    try:
        # Terminal log format: bracketed [SECTION] headers (bright, left-aligned) get ' ok' or an
        # error tacked on when their step finishes; detail lines are indented two spaces.
        _update_log(f"[UPDATE] GeneratorPi — installed v{APP_VERSION}")
        _update_log("[CONTACTING GITHUB]")
        _update_phase("checking", "Reaching GitHub…", 0.03)
        manifest = json.loads(_http_get_bytes(_MANIFEST_URL, max_bytes=1_000_000).decode("utf-8"))
        version = manifest.get("version") or "?"
        nfiles = len(manifest.get("files") or [])
        _update_log_append(" ok")
        _update_log(f"  manifest v{version} · {nfiles} files")
        # Validate the manifest BEFORE trusting any of it (each check aborts the run on failure).
        _update_log("[VALIDATING RELEASE]")
        _validate_manifest_paths(manifest)               # traversal + secret/cert denylist
        _update_log("  file paths safe (no traversal, no secret/cert targets) … ok")
        _validate_version(version)                       # charset-safe before it hits shell/JSON
        _update_log("  version string well-formed … ok")
        with _update_lock:
            _update_state["version"] = version
        # CLI-ONLY GATE: the manifest may list versions installable ONLY via the CLI (a release that
        # changes the systemd entrypoint / package layout, which the in-app updater can't do). If ANY
        # listed gate G falls STRICTLY ABOVE the installed version and AT-OR-BELOW the latest
        # (installed < G <= latest), a manual gate sits between where we are and where we'd land -- so we
        # REFUSE the web apply HERE, before downloading or touching anything. This stops a very old install
        # from web-JUMPING across a gate and failing hard; the operator installs manually instead (which
        # jumps straight to latest, crossing every gate at once). Missing/empty list -> nothing gates ->
        # applicable (forward-compatible with older manifests). A single string is accepted as one gate.
        _gates = manifest.get("cli_only_versions") or []
        if isinstance(_gates, str):
            _gates = [_gates]
        # Normalize a gate for comparison: trim + tolerate a 'v'-tagged form ("v1.4.0" -> "1.4.0"). Releases
        # are TAGGED vX.Y.Z, so that typo is the natural mistake -- and left as-is it would parse to (0,4,0)
        # and silently NEVER block (fail-OPEN), letting exactly the old install this protects web-jump a gate
        # and brick. (gen-manifest.py ALSO rejects a malformed gate at generation time -- defense in depth.)
        def _gate_ver(g):
            g = str(g).strip()
            return g[1:] if g[:1] in ("v", "V") else g
        _cur_t, _latest_t = _version_tuple(APP_VERSION), _version_tuple(version)
        _blocking = sorted({_gate_ver(g) for g in _gates
                            if _gate_ver(g) and _cur_t < _version_tuple(_gate_ver(g)) <= _latest_t},
                           key=_version_tuple)
        _notes = manifest.get("important_notes") or []
        if isinstance(_notes, str):                      # accept a single string OR a list of strings
            _notes = [_notes]
        _notes = [str(n).strip() for n in _notes if str(n).strip()]
        with _update_lock:
            _update_state["installable"] = not _blocking
            # Rendered in the UI's dedicated IMPORTANT box: with notes -> the intro + note(s) + a divider
            # + the release/repo links (Case A); empty -> the single-sentence fallback with the links
            # (Case B). Either way the box carries the message, so the log only points to it.
            _update_state["important_notes"] = _notes
        if _blocking:
            # The terminal log only POINTS to the box; the note TEXT itself is shown in the dedicated
            # bordered "IMPORTANT" box below the log (the UI reads it from _update_state.important_notes).
            _update_log(f"[ERROR] v{version} cannot be installed by the web updater")
            _update_sev(f"  A manual-install-only version ({', '.join('v' + g for g in _blocking)}) is "
                        f"between your v{APP_VERSION} and v{version}.", "err")
            _update_sev("  Nothing has changed. See the IMPORTANT note below, then install it "
                        "manually (e.g. ./setup.sh reinstall).", "err")
            _update_phase("staged", f"v{version} is not installable via the web updater.", 0.85)
            # Park: apply button SHOWN but greyed/disabled + REVERT/CLOSE; allow_proceed False so the
            # backend refuses proceed even if the disabled button were clicked (belt-and-suspenders).
            _await_decision(f"v{version} cannot be installed by the web updater.",
                            allow_proceed=False, proceed_label="UPDATE", proceed_disabled=True)
            _update_log(f"[ERROR] not applied. Still on v{APP_VERSION}.")
            _update_phase("failed", "This release must be installed manually.", 0.0)
            return
        # Restart path + WHY up front (obeys env/config; honest about non-systemd hosts).
        _svc_skip = _service_skip_reason()
        _update_log("[DEPLOYMENT PLAN] " + (
            "systemd service — will restart the service to apply"
            if not _svc_skip else "in-process swap + re-exec"))
        if _svc_skip:
            _update_log(f"  reason: {_svc_skip}")
        _update_log(f"  installed v{APP_VERSION} → target v{version}")
        _update_log(f"  backups dir: {_BACKUP_DIR}")
        # Detailed system-readiness checks (writability of every target + free disk space).
        _update_log("[CHECKING SYSTEM]")
        _update_phase("checking", "Validating permissions + free space…", 0.06)
        _preflight_check(manifest, log=_update_log)      # logs each sub-check; aborts on first failure
        # Stage-1 DEPENDENCY CHECK: the manifest DECLARES the runtime deps this release needs. Report
        # any not importable on THIS device + a copy-able apt one-liner so the operator can install
        # them. The updater NEVER installs them itself (auto-apt on a headless box needs broad
        # privileged access + can hang the update). This is a WARNING, not a gate -- a missing
        # OPTIONAL dep just means that feature (e.g. Web Push) stays off until it's installed.
        _update_log("[CHECKING DEPENDENCIES]")
        _update_phase("checking", "Checking declared dependencies…", 0.07)
        _missing_deps = check_manifest_dependencies(manifest)
        _deps_cmd = dependency_install_command(_missing_deps)
        with _update_lock:
            _update_state["missing_deps"] = [
                {"apt": d.get("apt", ""), "feature": d.get("feature", ""),
                 "required": bool(d.get("required"))}
                for d in _missing_deps
            ]
            _update_state["deps_install_cmd"] = _deps_cmd
        if not _missing_deps:
            _update_log("  all declared dependencies present … ok")
        else:
            _any_required = any(d.get("required") for d in _missing_deps)
            for d in _missing_deps:
                _req = bool(d.get("required"))
                # A missing REQUIRED dep is an ERROR (red); a missing OPTIONAL one (e.g. a Web Push
                # library) is a WARNING (amber) -- that feature just stays off. The visible
                # WARNING:/ERROR: label drives the terminal colour; both feed the stage tally.
                _line = (f"  {'ERROR' if _req else 'WARNING'}: Missing "
                         f"({'required' if _req else 'optional'}) dependency: "
                         f"{d.get('apt', '?')} ({d.get('feature', '')})")
                (_update_err if _req else _update_warn)(_line)
            # Colour the remedy note + copy-clean command with the block's overall severity (a
            # missing REQUIRED dep makes the whole block red) WITHOUT tallying them as extra items;
            # the command carries no visible label so it stays clean to select/copy.
            _sev = "err" if _any_required else "warn"
            _update_sev("  The updater will NOT install these — run the following command over SSH, then restart the application to resolve:", _sev)
            _update_sev(f"    {_deps_cmd}", _sev)
        # Two logged stages: download to staging, then verify SHA-256 + compile-check.
        _update_log(f"[DOWNLOADING] {nfiles} files")
        _update_phase("downloading", "Downloading files…", 0.1)
        staging = _download_and_verify(manifest)         # logs per-file download, then [VERIFYING]
        _update_log("[BACKING UP]")
        _update_phase("backing_up", "Backing up current files…", 0.8)
        zpath, _added = _make_backup(manifest)
        _update_log_append(" ok")
        _update_log(f"  {zpath.name} (integrity-verified)")
        # ── END OF STAGE 1 ── everything is downloaded, hash-verified, and backed up, but NOTHING
        # live has changed yet. Park for the user's go/no-go before STAGE 2 (the swap + restart):
        # UPDATE applies it, REVERT cancels cleanly (this is the last point a cancel is free).
        _update_log("[STAGED]")
        _update_log_append(" ok")
        _update_log(f"  v{version} ready to apply — nothing has changed yet")
        _stage_summary(1)          # colored warning/error count lines (if any) as the last Stage-1 lines
        _update_phase("staged", f"Ready to apply v{version}.", 0.85)
        choice = _await_decision(
            f"Ready to apply v{version}.", allow_proceed=True, proceed_label="UPDATE")
        if choice == "revert":
            try:
                if _UPDATE_STAGING.exists():
                    shutil.rmtree(_UPDATE_STAGING, ignore_errors=True)
            except Exception:                            # noqa: BLE001 -- cleanup is best-effort
                pass
            _update_log(f"[REVERTED] canceled before applying — still on v{APP_VERSION}")
            _update_phase("failed", "Update canceled before applying.", 0.0)
            return
        _update_log(f"[APPLYING] stage 2 — installing v{version}")
        with _update_lock:                               # subsequent warn/err lines tally to Stage 2
            _update_state["stage"] = 2
        t_apply = time.time()                            # start timing the apply (past the go/no-go gate)
        if not _svc_skip:
            with _update_lock:
                _update_state["systemd"] = True
            _update_log("[RESTARTING] swapping files + restarting the service…")
            _update_phase("restarting", f"Applying v{version} + restarting service…", 0.92)
            # Seed the shared log with everything so far, so the post-restart result terminal
            # shows the FULL run (these pre-restart lines + the bootstrap's swap/restart/health
            # lines, which the bootstrap APPENDS to this same file).
            with _update_lock:
                _seed = "\n".join(_update_state["log"])
            try:
                _BACKUP_DIR.mkdir(parents=True, exist_ok=True)
                _UPDATE_LOG.write_text(_seed + "\n")
            except OSError:
                pass
            # Health URL the bootstrap probes to confirm the NEW version actually serves.
            scheme = "https" if CONFIG.get("SSL_ENABLED") else "http"
            health_url = f"{scheme}://127.0.0.1:{CONFIG['PORT']}/"
            script = _write_bootstrap_script(manifest, version, zpath, staging, health_url, t_apply=t_apply)
            # Run the bootstrap at a gentle (mild) CPU niceness so it never starves the generator
            # controller / other work while it swaps + restarts. os.nice() in preexec_fn keeps it
            # dependency-free (no `nice` binary needed); +5 is polite but still prompt for the swap.
            def _be_nice():
                try:
                    os.nice(5)
                except OSError:
                    pass
            # Detach the bootstrap into its own session so it outlives this process. Use ONLY
            # start_new_session=True (it calls setsid(2) directly) -- no "setsid" argv, which
            # would add a needless binary dependency whose absence fails the launch (audit NEW-6).
            # KillMode=process spares the child regardless of session anyway.
            subprocess.Popen(["bash", script],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True, preexec_fn=_be_nice)
        else:
            with _update_lock:
                _update_state["systemd"] = False
            _update_phase("swapping", "Applying update…", 0.86)
            # ---- STAGE 2 (non-systemd): in-process atomic swap + re-exec, logged in DETAIL so the
            # terminal shows exactly what changed -- parity with Stage 1's download/verify sections.
            # Arm rollback BEFORE the swap: if _swap raises partway (file k of n), the except path
            # MUST restore from the backup, else the disk is left with a mixed old/new file set that
            # would brick the next restart (audit H-1). The running process still holds the OLD code
            # in RAM, so restoring the backup + not re-exec'ing keeps us reachable.
            swapped = True
            _update_log(f"  rollback point armed: {zpath.name}")
            _update_log(f"[SWAPPING] {nfiles} files (atomic replace)")
            _swap(manifest, log_fn=_update_log)          # per-file: "<path> … old → new bytes … ok"
            # Confirm the swap actually landed: re-hash each LIVE file against the manifest. A bad
            # on-disk file raises -> the except path rolls back from the backup zip.
            _update_log("[VERIFYING SWAP] on-disk SHA-256")
            for f in manifest.get("files") or []:
                rel, want = f["path"], f["sha256"]
                got = hashlib.sha256((SCRIPT_DIR / rel).read_bytes()).hexdigest()
                if got != want:
                    raise ValueError(f"post-swap hash mismatch for {rel}")
                _update_log(f"  {rel} … ok")
            # In-process Stage 2 only. The systemd path's Stage 2 runs in the detached bootstrap
            # (its own colored [DONE]/[ROLLBACK]/[WATCHDOG] lines), so it has no in-app summary here.
            _stage_summary(2)          # colored Stage-2 warning/error counts (if any) before re-exec
            _update_log("[RESTARTING] in-process re-exec")
            _update_log("  releasing the listening socket, then re-exec'ing this process")
            with _update_lock:
                _full_log = "\n".join(_update_state["log"])
            # Mark 'restarting' (NOT success) BEFORE re-exec; the freshly-started process flips
            # it to success at startup, so an import failure in the new code can't masquerade as
            # a successful update (audit M1). The captured log is the whole terminal, so the
            # result modal shows the same lines the user just watched.
            _write_update_result(
                "restarting", version,
                note="Files were swapped directly (non-systemd); the app is restarting.",
                log_text=_full_log, started_ts=t_apply)
            _update_phase("restarting",
                          f"Updated to v{version}. Restarting the app process…", 0.95)
            _schedule_process_restart(1.5)
    except Exception as e:
        # Any failure BEFORE the restart lands here. Show it in the terminal and PARK for the
        # user's decision (hard errors can't be safely proceeded past, so REVERT only). REVERT
        # rolls back any partial swap, discards staging, and leaves the OLD version running.
        log.error(f"Self-update failed: {e}")
        _update_log(f"[ERROR] {e}")
        _await_decision(f"Update failed: {e}", allow_proceed=False)
        if swapped and zpath is not None:                # same-process swap failed -> restore
            _update_log("[ROLLBACK] restoring the previous version…")
            _rollback(zpath)
        try:                                             # discard the staged download
            if _UPDATE_STAGING.exists():
                shutil.rmtree(_UPDATE_STAGING, ignore_errors=True)
        except Exception:                                # noqa: BLE001 -- cleanup is best-effort
            pass
        if t_apply is not None:                          # only if we'd started applying (past the gate)
            _update_log(f"Update failed after {max(0.0, time.time() - t_apply):.1f} seconds")
        _update_log(f"[REVERTED] no changes applied — still on v{APP_VERSION}")
        _update_phase("failed", f"Update reverted: {e}", 0.0, error=str(e))


# FAIL FAST at startup: the updater must always be able to write a rollback backup, so a
# missing/unwritable backups/ dir is a hard stop here rather than a nasty surprise mid-update.
try:
    _ensure_backup_dir()
except OSError as _e:  # pragma: no cover - import-time fail-fast; the backups dir is writable in dev/CI, so this hard-stop branch isn't reachable without a module reload against a broken filesystem
    log.critical(
        f"Cannot create or write the backups directory ({_BACKUP_DIR}): {_e}. Fix the "
        f"permissions and restart -- refusing to run without a working rollback path."
    )
    raise SystemExit(1)


# If the DEV (re-exec) update path left a 'restarting' marker, reaching HERE proves the new
# code imported + started cleanly, so promote it to 'success'. If the new code had failed to
# import we'd never get here and the marker would stay 'restarting' (honest -- not a false
# success). The systemd path writes its own result from the bootstrap, so leave those alone.
try:  # pragma: no cover - import-time-only marker promotion (runs in the fresh process after a dev self-update re-exec); no 'restarting' marker exists during tests and it can't be re-triggered without a full module reload
    if _UPDATE_RESULT.exists():
        _r = json.loads(_UPDATE_RESULT.read_text())
        if _r.get("status") == "restarting":
            _r["status"] = "success"
            _ver = _r.get("version", APP_VERSION)
            _r["note"] = f"Application successfully updated to v{_ver}."
            _UPDATE_RESULT.write_text(json.dumps(_r))
            # How long the apply took, measured ACROSS the re-exec: started_ts was stamped at
            # [APPLYING] before the restart, so elapsed = now - started_ts.
            _st = _r.get("started_ts")
            _took = (f"\nUpdate finished in {max(0.0, time.time() - _st):.1f} seconds"
                     if isinstance(_st, (int, float)) else "")
            # Append the FINAL confirmation to the captured terminal log so the result modal ends
            # with a clear, green "[DONE]" line (the log was captured just before re-exec; reaching
            # here proves the new version imported + is serving) -- Stage 2 finishes with a result.
            try:
                _prev = _UPDATE_LOG.read_text() if _UPDATE_LOG.exists() else ""
                _UPDATE_LOG.write_text(
                    _prev.rstrip("\n")
                    + "\n[HEALTH] checking if the application is back up … ok"
                    + _took
                    + f"\n[DONE] Application successfully updated to v{_ver}!"
                )
            except Exception:                             # noqa: BLE001 -- log tail is best-effort
                pass
except Exception as _e:                                    # pragma: no cover - import-time-only guard around the marker-promotion block above; unreachable in tests (no marker) and not re-triggerable without a module reload
    log.warning(f"could not promote update result marker: {_e}")


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


def update_check_loop():
    """Hourly background update check (production). On finding a NEWER published version --
    higher than installed and not one already announced this run -- record an event and,
    if push is configured, send a push so operators learn of it with no browser open.
    Daemon thread; _monitor_stop ends it promptly on shutdown. The FRONTEND does its own
    on-load check via /api/check-update; this loop is the no-browser-open path.

    ONE-SHOT per run: we push (and log an event) AT MOST ONCE per application start, even
    if further releases appear later -- the operator hears about it once, not hourly. The
    flag resets naturally when the app restarts."""
    pushed = False
    if _monitor_stop.wait(30):                        # first check 30s after startup
        return
    while True:
        # Refresh the footer cache every cycle (so cached footer reads stay reasonably current)
        # and push exactly once per run when a newer version first appears.
        result = _run_update_check()
        latest = result["latest"]
        if not pushed and result["update_available"]:
            pushed = True                             # exactly one update push per restart
            log.info(f"Update available: v{latest} (installed v{APP_VERSION})")
            record_event("update", f"Update available: v{latest} (installed v{APP_VERSION})")
            send_push_async(
                "Update available",
                f"GeneratorPi v{latest} is available (you have v{APP_VERSION}).",
                tag="update",
            )
        if _monitor_stop.wait(3600):                  # ~hourly repo check; True == stop requested
            return


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
    send_push_async("Test notification", "Push notifications are working.", tag="test")
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
