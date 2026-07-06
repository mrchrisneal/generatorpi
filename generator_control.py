# generator_control.py -- Remote start/stop controller for a Powermate PM9400E
# generator via a Raspberry Pi GPIO relay, exposing a self-contained Flask web UI +
# REST API. Single-file by design so it deploys and runs light on a Pi. Handles auth
# (API key + Basic Auth), a durable event log + fuel/runtime state (SQLite), the
# relay start/stop sequence, and the inline HTML/CSS/JS control panel.
#
# Copyright (C) 2026 Alex Neal <https://neal.tools> and Chris Neal <https://neal.media>
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify it under the
# terms of the GNU Affero General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later version.
# Distributed WITHOUT ANY WARRANTY. See the GNU AGPL v3 (the LICENSE file, or
# https://www.gnu.org/licenses/agpl-3.0.html) for full terms.
from gpiozero import OutputDevice
import logging
import logging.handlers
import os
import sys
import time
import threading
import hmac
import json
import secrets
import sqlite3
from functools import wraps
from flask import Flask, render_template_string, jsonify, request, Response, g
from datetime import datetime
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash

# ============================================================================
# CONFIGURATION
# ============================================================================
# All configuration lives in generator_control.env (same directory as this script).
# See generator_control.env.example for format and defaults.
SCRIPT_DIR = Path(__file__).parent
ENV_FILE = SCRIPT_DIR / "generator_control.env"

# Defaults -- overridden by values in the env file
CONFIG = {
    # GPIO
    "RELAY_PIN": 27,                    # GPIO pin number for relay control
    # Generator start sequence
    "MAX_START_RETRIES": 1,             # Number of start attempts before giving up
    "BUTTON_PRESS_DURATION": 0.25,      # Seconds to hold relay closed per press
    "PRIME_DELAY": 0.75,                # Seconds to wait between prime and start press
    "RETRY_DELAY": 5.0,                  # Seconds between retry attempts
    # Web server
    "HOST": "0.0.0.0",                  # Bind address
    "PORT": 9400,                       # Bind port
    # SSL / HTTPS
    "SSL_ENABLED": 1,                   # 1 = HTTPS, 0 = plain HTTP
    "SSL_CERT_DAYS": 365,              # Validity period for generated certs
    "SSL_RENEW_DAYS": 30,              # Regenerate cert when fewer than this many days remain
    # API authentication (for machine callers, e.g. HomeAssistant)
    "API_KEY_ENABLED": 1,               # 1 = accept API-key auth, 0 = disable it (basic auth only)
    "API_KEY": "",                      # Static bearer key; auto-generated into the env file on startup when enabled+empty
    # Rate limiting (brute force protection)
    "RATE_LIMIT_MAX_FAILURES": 5,       # Failed attempts before an IP is locked out
    "RATE_LIMIT_LOCKOUT_SECONDS": 300,  # Lockout duration in seconds (5 minutes)
    "RATE_LIMIT_CLEANUP_SECONDS": 600,  # How often to purge stale entries (10 minutes)
    "RATE_LIMIT_MAX_TRACKED_IPS": 1000, # Hard cap on tracked IPs (prevents memory exhaustion)
    # Logging
    "LOG_FILE": "generator_control.log",  # Log file name (relative to script dir)
    "LOG_MAX_BYTES": 10_485_760,        # 10 MB per log file
    "LOG_BACKUP_COUNT": 3,              # Number of rotated log files to keep
    "LOG_LEVEL": "INFO",                # DEBUG, INFO, WARNING, ERROR, CRITICAL
    # Event store (persistent, capped log of generator events)
    "EVENT_LOG_DB": "events.db",        # SQLite DB file name (relative to script dir)
    "EVENT_LOG_MAX": 10000,             # Cap on stored events; oldest are evicted past this
}

# Werkzeug password hashes always start with one of these method prefixes
HASH_PREFIXES = ("scrypt:", "pbkdf2:")


def parse_env_file():
    """Parse the env file into config values and user credentials.

    Lines starting with USER_ are credentials: USER_chris=mypassword
    All other non-comment key=value lines are config overrides.
    Plaintext passwords are auto-hashed and the file is rewritten.
    """
    users = {}

    if not ENV_FILE.exists():
        print(f"WARNING: {ENV_FILE} not found - using defaults, no users loaded")
        return users

    lines = ENV_FILE.read_text().splitlines()
    needs_rewrite = False
    new_lines = []

    for line in lines:
        stripped = line.strip()

        # Preserve comments and blank lines
        if not stripped or stripped.startswith("#"):
            new_lines.append(line)
            continue

        # Split on first = sign
        eq_index = stripped.find("=")
        if eq_index == -1:
            new_lines.append(line)
            continue

        key = stripped[:eq_index].strip()
        value = stripped[eq_index + 1:].strip()

        if key.startswith("USER_"):
            # Credential line: USER_username=password_or_hash
            username = key[5:]  # Strip "USER_" prefix
            if not username:
                new_lines.append(line)
                continue

            if value.startswith(HASH_PREFIXES):
                # Already hashed
                users[username] = value
                new_lines.append(line)
            else:
                # Plaintext -- hash it and rewrite
                hashed = generate_password_hash(value)
                users[username] = hashed
                new_lines.append(f"USER_{username}={hashed}")
                needs_rewrite = True
                print(f"Hashed plaintext password for user '{username}'")
        elif key == "API_KEY":
            # Special-cased so duplicate API_KEY lines can't shadow the real key.
            # The FIRST API_KEY line wins; any later one is dropped on rewrite, so a
            # stray/empty duplicate can't blank the key and force regeneration
            # (which would silently break HomeAssistant on every restart).
            if CONFIG["API_KEY"]:
                needs_rewrite = True
                print("Dropping duplicate API_KEY line from settings file")
                continue  # skip append -> the duplicate line is removed on rewrite
            CONFIG["API_KEY"] = value
            new_lines.append(line)
        elif key in CONFIG:
            # Config override -- cast to the same type as the default
            default = CONFIG[key]
            try:
                if isinstance(default, int):
                    # Accept boolean words for on/off toggles so that e.g.
                    # API_KEY_ENABLED=false actually disables key auth -- int('false')
                    # would raise and silently keep the (enabled) default.
                    low = value.strip().lower()
                    if low in ("true", "yes", "on"):
                        CONFIG[key] = 1
                    elif low in ("false", "no", "off"):
                        CONFIG[key] = 0
                    else:
                        CONFIG[key] = int(value)
                elif isinstance(default, float):
                    CONFIG[key] = float(value)
                else:
                    CONFIG[key] = value
            except ValueError:
                print(f"Invalid value for {key}: {value!r}, keeping default {default!r}")
            new_lines.append(line)
        else:
            # Unknown key, preserve it
            new_lines.append(line)

    # Auto-provision the API key: when key auth is enabled but no key is set yet
    # (first startup, or the value was cleared/deleted to rotate it), generate a
    # strong random key and persist it into THIS settings file (no separate file).
    if CONFIG["API_KEY_ENABLED"] and not CONFIG["API_KEY"]:
        generated = secrets.token_urlsafe(32)  # 256-bit, URL-safe (no query escaping)
        CONFIG["API_KEY"] = generated
        # Fill an existing "API_KEY=" line in place; otherwise append a documented
        # block. Rotation stays clean: clear the value or delete the line, restart,
        # and a fresh key lands right back here.
        for i, existing in enumerate(new_lines):
            if existing.split("=", 1)[0].strip() == "API_KEY":
                new_lines[i] = f"API_KEY={generated}"
                break
        else:
            new_lines.append("")
            new_lines.append("# API key for machine callers (e.g. HomeAssistant).")
            new_lines.append("# Auto-generated on startup. To rotate: clear the value")
            new_lines.append("# (leave 'API_KEY=') or delete the line, then restart:")
            new_lines.append("#   sudo systemctl restart generator_control")
            new_lines.append("# A fresh key is generated + written here on startup;")
            new_lines.append("# update HomeAssistant's key to match or its calls 401.")
            new_lines.append("# Set API_KEY_ENABLED=0 to disable key auth entirely.")
            new_lines.append(f"API_KEY={generated}")
        needs_rewrite = True
        print("Generated a new API key and wrote it to the settings file")

    # Persist changes (hashed passwords and/or a generated API key). Write to a
    # temp file first, then atomic rename (POSIX guarantees atomicity). mkstemp
    # creates the temp file 0600, so after the rename the settings file is
    # owner-only -- correct for a file holding secrets.
    if needs_rewrite:
        import tempfile
        tmp_fd, tmp_path = tempfile.mkstemp(dir=SCRIPT_DIR, prefix=".env_tmp_")
        try:
            with os.fdopen(tmp_fd, "w") as tmp_f:
                tmp_f.write("\n".join(new_lines) + "\n")
            os.rename(tmp_path, ENV_FILE)
        except OSError as e:
            # Couldn't persist -- clean up and fail fast rather than silently
            # dropping a generated key / password hashes.
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            print(f"CRITICAL: could not write settings file {ENV_FILE} ({e}). "
                  f"Refusing to start -- check its permissions/ownership.",
                  file=sys.stderr)
            sys.exit(1)
        # Belt-and-suspenders: ensure owner-only perms even if the rename inherited
        # something looser from an unusual umask/filesystem.
        try:
            os.chmod(ENV_FILE, 0o600)
        except OSError:
            pass
        print(f"Rewrote {ENV_FILE.name} (secrets persisted, owner-only)")

    return users


def check_settings_file_security():
    """Startup guard: refuse to run if the settings file's ownership or permissions
    would break functionality or expose its secrets (the API key + password hashes).

    Runs BEFORE the file is read or rewritten. Logging isn't configured yet at this
    point, so failures are printed to stderr and the process exits non-zero -- a
    clean 'critical error and stop' rather than a mid-run traceback. A missing file
    is not fatal here (parse_env_file handles that; setup.sh creates it).
    """
    if not ENV_FILE.exists():
        return

    problems = []

    # Refuse a symlinked settings file: a swapped symlink could redirect our
    # chmod/rewrite at another file. exists() above already followed the link, so a
    # symlink here points at a real file (the stat below is safe).
    if ENV_FILE.is_symlink():
        problems.append("is a symlink (refusing to follow it)")

    st = ENV_FILE.stat()

    # Ownership: we must be able to secure (chmod) and rewrite the file. root can
    # always do both, so only REQUIRE ownership when NOT running as root -- otherwise
    # a root-run service (common for GPIO access) would false-positive on a file
    # owned by the 'pi' user and refuse to start.
    euid = os.geteuid() if hasattr(os, "geteuid") else None
    if euid is not None and euid != 0 and st.st_uid != euid:
        problems.append(
            f"is owned by uid {st.st_uid}, but this non-root process runs as uid "
            f"{euid} -- it cannot secure or update the settings file")

    # Readability: required to load config + credentials at all. (os.access uses the
    # real uid and always returns True for root; under root an unreadable file
    # surfaces later as a clean read error instead.)
    if not os.access(ENV_FILE, os.R_OK):
        problems.append("is not readable by the service user")

    # Permissions: the file holds secrets, so group/other must have NO access.
    # Try to tighten to 0600 in place; only fail if we cannot.
    mode = st.st_mode & 0o777
    if mode & 0o077:
        try:
            os.chmod(ENV_FILE, 0o600)
            print(f"NOTICE: tightened {ENV_FILE.name} permissions {oct(mode)} -> 0o600",
                  file=sys.stderr)
        except OSError as e:
            problems.append(
                f"has permissions {oct(mode)} (group/other can read its secrets) "
                f"and they could not be tightened: {e}")

    if problems:
        print("CRITICAL: settings-file startup check FAILED -- refusing to start:",
              file=sys.stderr)
        for p in problems:
            print(f"  - {ENV_FILE} {p}", file=sys.stderr)
        print("Fix ownership/permissions (owner-only, owned by the service user), "
              "then restart the service.", file=sys.stderr)
        sys.exit(1)


# Enforce settings-file security BEFORE touching it, then load config + credentials.
check_settings_file_security()
AUTH_USERS = parse_env_file()

# ============================================================================
# LOGGING
# ============================================================================
log_path = SCRIPT_DIR / CONFIG["LOG_FILE"]
log_formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Rotating file handler
file_handler = logging.handlers.RotatingFileHandler(
    log_path,
    maxBytes=CONFIG["LOG_MAX_BYTES"],
    backupCount=CONFIG["LOG_BACKUP_COUNT"],
)
file_handler.setFormatter(log_formatter)

# Console handler (so journald still captures output)
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)

log = logging.getLogger("generator_control")
log.setLevel(getattr(logging, CONFIG["LOG_LEVEL"].upper(), logging.INFO))
log.addHandler(file_handler)
log.addHandler(console_handler)

log.info(f"Loaded {len(AUTH_USERS)} user(s): {', '.join(AUTH_USERS.keys()) or 'none'}")
log.info(f"Log file: {log_path} (max {CONFIG['LOG_MAX_BYTES'] // 1_048_576}MB x {CONFIG['LOG_BACKUP_COUNT']} backups)")

# Suppress Werkzeug's built-in per-request access log. That log prints the full
# request line -- INCLUDING the "?key=..." query string -- to stdout/journald,
# which would leak the API key into logs. Our own audit line (in auth_required)
# records only method + path (never the query string), so we lose nothing useful
# by silencing Werkzeug's access log while closing the key-leak vector.
logging.getLogger("werkzeug").setLevel(logging.ERROR)

# ============================================================================
# EVENT STORE (persistent, capped log of generator events)
# ============================================================================
# A durable, on-disk log of notable generator events (start/stop/manual
# overrides/rejections), stored in a small SQLite database next to this script.
# The front-end reads it back over /api/events to show recent activity and page
# backwards through history (~100 rows at a time).
#
# Design notes:
#   * SQLite (stdlib sqlite3) gives us durability + a monotonic primary key for
#     free -- no external service, one file, survives restarts.
#   * seq is INTEGER PRIMARY KEY AUTOINCREMENT: it never repeats or gets reused,
#     even after old rows are evicted, so a client cursor (before=/after=) stays
#     unambiguous forever.
#   * ts is a unix timestamp (time.time(), float seconds) so the UI can render an
#     absolute wall-clock time without depending on server-local formatting.
#   * The table is capped at CONFIG["EVENT_LOG_MAX"] rows; the oldest rows are
#     evicted on every insert so the file can't grow without bound.
#   * The app is multithreaded (a relay worker thread + Flask request threads), so
#     a single shared connection (opened check_same_thread=False) is guarded by a
#     module-level lock. Events are human-frequency, so this coarse lock is fine.

# Guards the shared connection below -- every read/write takes this lock.
_event_lock = threading.Lock()
# The single shared sqlite3 connection. Opened by init_event_store(); None until then.
_event_conn = None
# The resolved on-disk path of the current event DB (set by init_event_store()).
_event_db_path = None


def init_event_store(db_path=None):
    """Open (or reopen) the event-store database and ensure its schema exists.

    Called once at startup, after logging is configured. Opens a single shared
    connection (check_same_thread=False -- see the section header), enables WAL
    mode for better concurrent read/write behavior, creates the events table if
    it doesn't already exist, and records a one-off "startup" event.

    db_path lets tests point the store at a throwaway database; production passes
    nothing and the DB lives at SCRIPT_DIR / CONFIG["EVENT_LOG_DB"].
    """
    global _event_conn, _event_db_path

    # Resolve the target path (default: alongside this script).
    if db_path is None:
        db_path = SCRIPT_DIR / CONFIG["EVENT_LOG_DB"]

    with _event_lock:
        # Close any previously-open connection first so a reopen (e.g. in tests)
        # doesn't leak file handles or leave two connections fighting the same file.
        if _event_conn is not None:
            try:
                _event_conn.close()
            except Exception:
                pass
            _event_conn = None

        _event_db_path = Path(db_path)
        # check_same_thread=False: the relay worker thread and Flask request
        # threads all share this one connection; _event_lock serializes access.
        _event_conn = sqlite3.connect(str(_event_db_path), check_same_thread=False)
        # WAL mode: readers don't block the writer (and vice versa) and it's more
        # crash-resilient than the default rollback journal.
        _event_conn.execute("PRAGMA journal_mode=WAL")
        # Schema. AUTOINCREMENT guarantees seq is monotonic and never reused, even
        # after the DELETEs done during eviction -- so client cursors stay valid.
        _event_conn.execute(
            "CREATE TABLE IF NOT EXISTS events ("
            "seq INTEGER PRIMARY KEY AUTOINCREMENT, "
            "ts REAL NOT NULL, "
            "type TEXT NOT NULL, "
            "message TEXT NOT NULL)"
        )
        # Durable key/value state that must survive a process restart: lifetime
        # total run-hours and the fuel-projection model. Values are stored as JSON
        # text so the same tiny table can hold floats, ints, and small dicts without
        # a per-field schema. Reuses this one connection + _event_lock -- no extra
        # file, no extra lock (the Pi is the constraint; keep it minimal).
        _event_conn.execute(
            "CREATE TABLE IF NOT EXISTS kv ("
            "key TEXT PRIMARY KEY, "
            "value TEXT NOT NULL)"
        )
        _event_conn.commit()

    log.info(f"Event store ready: {_event_db_path}")
    # Record process start in the durable log. Done outside the lock above --
    # record_event acquires _event_lock itself.
    record_event("startup", "Controller started")


def record_event(event_type, message):
    """Append an event to the durable store, then evict the oldest rows past cap.

    Inserts (ts=time.time(), type, message) and deletes any rows beyond
    CONFIG["EVENT_LOG_MAX"] so the table stays bounded.

    This MUST NOT raise into its caller: recording an event is only a side effect
    of starting/stopping the generator and must never be able to break the relay
    control path. Any failure is swallowed and logged as a warning.
    """
    try:
        max_rows = CONFIG["EVENT_LOG_MAX"]
        with _event_lock:
            if _event_conn is None:
                # Store not initialized (shouldn't happen in normal operation);
                # drop the event rather than crash the caller.
                log.warning("record_event called before init_event_store; dropping event")
                return
            _event_conn.execute(
                "INSERT INTO events (ts, type, message) VALUES (?, ?, ?)",
                (time.time(), event_type, message),
            )
            # Evict everything older than the newest max_rows rows. seq is
            # monotonic, so "keep the highest max_rows seq values" is exactly
            # "delete where seq <= MAX(seq) - max_rows".
            _event_conn.execute(
                "DELETE FROM events WHERE seq <= (SELECT MAX(seq) FROM events) - ?",
                (max_rows,),
            )
            _event_conn.commit()
    except Exception as e:
        # Never propagate -- a broken event log must not stop the generator.
        log.warning(f"Failed to record event ({event_type!r}): {e}")


def get_events(limit=100, before=None, after=None):
    """Return events newest-first as a list of dicts {seq, ts, type, message}.

    limit  -- max rows to return.
    before -- if given, only rows with seq < before (page backwards / older).
    after  -- if given (and before is not), only rows with seq > after (fetch
              what's new since a cursor the client already holds).
    before takes precedence over after: a client pages in one direction at a time.
    """
    try:
        with _event_lock:
            if _event_conn is None:
                return []
            # Build the cursor WHERE clause. Parameterized -- never string-formatted
            # with user input -- so there's no SQL-injection surface.
            where = ""
            params = []
            if before is not None:
                where = "WHERE seq < ?"
                params.append(before)
            elif after is not None:
                where = "WHERE seq > ?"
                params.append(after)
            params.append(limit)
            rows = _event_conn.execute(
                f"SELECT seq, ts, type, message FROM events {where} "
                "ORDER BY seq DESC LIMIT ?",
                params,
            ).fetchall()
        # Map row tuples -> dicts outside the lock (pure CPU, no DB access).
        return [
            {"seq": r[0], "ts": r[1], "type": r[2], "message": r[3]}
            for r in rows
        ]
    except Exception as e:
        log.warning(f"Failed to read events: {e}")
        return []


def get_latest_seq():
    """Return the highest seq currently in the store, or 0 if it's empty."""
    try:
        with _event_lock:
            if _event_conn is None:
                return 0
            row = _event_conn.execute("SELECT MAX(seq) FROM events").fetchone()
        # MAX() over an empty table returns (None,); treat that as 0.
        return row[0] if row and row[0] is not None else 0
    except Exception as e:
        log.warning(f"Failed to read latest event seq: {e}")
        return 0


def kv_get(key, default=None):
    """Read a durable value from the kv table, JSON-decoded. Returns default if the
    key is absent or the store isn't ready. Never raises into its caller."""
    try:
        with _event_lock:
            if _event_conn is None:
                return default
            row = _event_conn.execute(
                "SELECT value FROM kv WHERE key = ?", (key,)
            ).fetchone()
        if row is None:
            return default
        return json.loads(row[0])
    except Exception as e:
        log.warning(f"Failed to read kv {key!r}: {e}")
        return default


def kv_set(key, value):
    """Persist a JSON-serializable value into the kv table (UPSERT). Never raises
    into its caller -- a failed persist logs a warning; the in-memory value stands."""
    try:
        payload = json.dumps(value)
        with _event_lock:
            if _event_conn is None:
                log.warning("kv_set called before init_event_store; dropping write")
                return
            _event_conn.execute(
                "INSERT INTO kv (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, payload),
            )
            _event_conn.commit()
    except Exception as e:
        log.warning(f"Failed to write kv {key!r}: {e}")


# Bring the store up now that logging is live. This also records the startup event.
init_event_store()

# ============================================================================
# SSL CERTIFICATE MANAGEMENT
# ============================================================================
# Self-signed cert is auto-generated on startup if missing or expiring soon.
# Uses openssl (pre-installed on Raspberry Pi OS).

SSL_CERT_PATH = SCRIPT_DIR / "ssl_cert.pem"
SSL_KEY_PATH = SCRIPT_DIR / "ssl_key.pem"


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


def ensure_ssl_cert():
    """Generate a self-signed SSL cert if missing or expiring soon.

    Checks on every startup so the cert is always valid. Regenerates when
    fewer than SSL_RENEW_DAYS days remain.
    """
    import subprocess

    cert_days = CONFIG["SSL_CERT_DAYS"]
    renew_days = CONFIG["SSL_RENEW_DAYS"]

    # Check if cert/key exist and are still valid
    if SSL_CERT_PATH.exists() and SSL_KEY_PATH.exists():
        if not _cert_expires_within(renew_days):
            log.info(f"SSL cert still valid (renew threshold: {renew_days} days)")
            return
        log.info(f"SSL cert expires within {renew_days} days, regenerating")
    else:
        log.info("No SSL cert found, generating self-signed certificate")

    # Generate new self-signed cert + key in one openssl command
    result = subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(SSL_KEY_PATH),
            "-out", str(SSL_CERT_PATH),
            "-days", str(cert_days),
            "-nodes",                           # No passphrase on the key
            "-subj", "/CN=generatorpi",         # Minimal subject
        ],
        capture_output=True, text=True, timeout=30,
    )

    if result.returncode != 0:
        log.error(f"Failed to generate SSL cert: {result.stderr.strip()}")
        raise RuntimeError("SSL certificate generation failed")

    # Restrict key file permissions (owner read-only)
    os.chmod(SSL_KEY_PATH, 0o600)

    log.info(f"Generated self-signed SSL cert (valid {cert_days} days)")


# ============================================================================
# RATE LIMITING (brute force / enumeration protection)
# ============================================================================
# Tracks failed auth attempts per IP. After RATE_LIMIT_MAX_FAILURES consecutive
# failures, the IP is locked out for RATE_LIMIT_LOCKOUT_SECONDS. A successful
# login resets the counter for that IP. Stale entries are purged periodically.

# _fail_tracker[ip] = {"count": int, "locked_until": float or None, "last_attempt": float}
_fail_tracker = {}
_fail_tracker_lock = threading.Lock()
_last_cleanup = time.monotonic()


def _cleanup_tracker():
    """Remove expired lockouts and stale entries from the failure tracker."""
    global _last_cleanup
    now = time.monotonic()
    cleanup_interval = CONFIG["RATE_LIMIT_CLEANUP_SECONDS"]
    if now - _last_cleanup < cleanup_interval:
        return
    _last_cleanup = now
    expired = [
        ip for ip, entry in _fail_tracker.items()
        if (entry["locked_until"] is not None and entry["locked_until"] <= now)
        or (now - entry["last_attempt"] > cleanup_interval)
    ]
    for ip in expired:
        del _fail_tracker[ip]
    if expired:
        log.debug(f"Rate limiter cleanup: purged {len(expired)} stale entries")


def is_rate_limited(ip):
    """Check if an IP is currently locked out. Returns seconds remaining or 0."""
    with _fail_tracker_lock:
        _cleanup_tracker()
        entry = _fail_tracker.get(ip)
        if not entry or entry["locked_until"] is None:
            return 0
        remaining = entry["locked_until"] - time.monotonic()
        if remaining <= 0:
            # Lockout expired, reset
            del _fail_tracker[ip]
            return 0
        return remaining


def record_failure(ip):
    """Record a failed auth attempt. Returns (locked_out, fail_count)."""
    with _fail_tracker_lock:
        # Enforce hard cap -- if at limit and this is a new IP, evict the oldest entry
        max_ips = CONFIG["RATE_LIMIT_MAX_TRACKED_IPS"]
        if ip not in _fail_tracker and len(_fail_tracker) >= max_ips:
            oldest_ip = min(_fail_tracker, key=lambda k: _fail_tracker[k]["last_attempt"])
            del _fail_tracker[oldest_ip]
            log.debug(f"Rate limiter at capacity ({max_ips}), evicted oldest entry")

        entry = _fail_tracker.get(ip, {"count": 0, "locked_until": None, "last_attempt": 0})
        entry["count"] += 1
        entry["last_attempt"] = time.monotonic()
        max_failures = CONFIG["RATE_LIMIT_MAX_FAILURES"]

        if entry["count"] >= max_failures:
            lockout = CONFIG["RATE_LIMIT_LOCKOUT_SECONDS"]
            entry["locked_until"] = time.monotonic() + lockout
            _fail_tracker[ip] = entry
            return True, entry["count"]

        _fail_tracker[ip] = entry
        return False, entry["count"]


def record_success(ip):
    """Reset the failure counter for an IP after a successful login."""
    with _fail_tracker_lock:
        if ip in _fail_tracker:
            del _fail_tracker[ip]


# ============================================================================
# AUTHENTICATION
# ============================================================================
# Dummy hash used when a username doesn't exist, so the response time is the
# same whether the username is valid or not (prevents enumeration via timing).
_DUMMY_HASH = generate_password_hash("timing-safe-dummy-value")


def check_auth(username, password):
    """Verify that the provided username and password are valid.

    Uses a constant-time comparison path regardless of whether the username
    exists, to prevent timing-based username enumeration.
    """
    stored_hash = AUTH_USERS.get(username, _DUMMY_HASH)
    valid = check_password_hash(stored_hash, password)
    return valid and username in AUTH_USERS


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
            # Log method + path ONLY -- never request.full_path / query_string,
            # which would contain the key.
            log.info(f"apikey@{ip} -> {request.method} {request.path}")
            return f(*args, **kwargs)

        # Path 2 -- HTTP Basic Auth (browser login / manual fallback). A present
        # but WRONG key falls through to here and is recorded as a failed attempt.
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            attempted = auth.username if auth else "(none)"
            locked, fail_count = record_failure(ip)
            max_failures = CONFIG["RATE_LIMIT_MAX_FAILURES"]
            log.warning(
                f"Auth failed for '{attempted}'@{ip} "
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
        log.info(f"{auth.username}@{ip} -> {request.method} {request.path}")
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
# GLOBAL STATE
# ============================================================================
# state_lock guards generator_state, fuel_state, and alerts_state below. All are
# mutated at human frequency, so one coarse lock is plenty and keeps the invariant
# (run-hours accounting + the fuel baseline both key off total_run_hours) atomic.
generator_state = {
    "running": False,           # Manually tracked (no auto-detect)
    "last_command": None,
    "last_start_time": None,    # ISO string of the last start (display)
    "last_stop_time": None,     # ISO string of the last stop (display)
    "start_attempts": 0,
    "message": "System ready",
    # current_run_started_at: unix ts the CURRENT run began, or None when stopped.
    # In-memory only (not persisted) -- it is tied to `running`, which resets to
    # False on a server restart, exactly like the pre-existing behavior. The live
    # uptime + odometer tick are derived from this client-side.
    "current_run_started_at": None,
    # total_run_hours: lifetime cumulative run-time (float hours). PERSISTED -- the
    # accumulated base; the live value = this + (running ? elapsed-this-run : 0).
    "total_run_hours": 0.0,
}
state_lock = threading.Lock()

# Fuel-projection model (linear drain: level = fill_level - drain_rate * run-hours
# since the fill). All PERSISTED. See the /api/fuel/* endpoints + FUEL_DEFAULT_RATE.
FUEL_DEFAULT_RATE = 6.4          # %/hr -- the reset target (matches the design ref)
fuel_state = {
    "fill_level": 100.0,         # % the tank was last filled to ("add gas" baseline)
    "fill_run_hours": 0.0,       # total_run_hours at the moment of that fill
    "drain_rate": FUEL_DEFAULT_RATE,   # estimated %/hr consumption while running
    "default_rate": FUEL_DEFAULT_RATE, # what "reset rate" restores to
}

# Low-fuel alert config. PERSISTED. threshold is a % (slider range 5..40).
alerts_state = {
    "alerts_on": True,
    "alert_threshold": 20,
}


def load_persisted_state():
    """Restore durable state (total run-hours, fuel model, alerts) from the kv store
    at startup. Missing keys keep the in-memory defaults above (first boot)."""
    with state_lock:
        generator_state["total_run_hours"] = float(
            kv_get("total_run_hours", generator_state["total_run_hours"])
        )
        saved_fuel = kv_get("fuel_state")
        if isinstance(saved_fuel, dict):
            # Only copy known keys so a stale/foreign field can't leak in.
            for k in fuel_state:
                if k in saved_fuel:
                    fuel_state[k] = saved_fuel[k]
        saved_alerts = kv_get("alerts_state")
        if isinstance(saved_alerts, dict):
            for k in alerts_state:
                if k in saved_alerts:
                    alerts_state[k] = saved_alerts[k]
    log.info(
        f"Restored state: total_run_hours={generator_state['total_run_hours']:.3f}, "
        f"drain_rate={fuel_state['drain_rate']}%/hr, "
        f"fill_level={fuel_state['fill_level']}%"
    )


def _live_total_run_hours_locked():
    """Lifetime run-hours INCLUDING the current in-progress run. Caller holds
    state_lock. Used by the fuel math + the state snapshot so projections track the
    engine in real time, not just completed runs."""
    base = generator_state["total_run_hours"]
    started = generator_state["current_run_started_at"]
    if generator_state["running"] and started is not None:
        base += max(0.0, (time.time() - started) / 3600.0)
    return base


def _apply_running_transition_locked(new_running):
    """Move tracked run-state to new_running, doing run-hours accounting. Caller
    holds state_lock. On stop, folds the just-finished run's elapsed time into the
    persisted total; on start, stamps the run's start. Idempotent: re-asserting the
    same state does not double-count or reset the current run's start."""
    was_running = generator_state["running"]
    now = time.time()

    if new_running and not was_running:
        # Stopped -> running: begin timing a new run.
        generator_state["current_run_started_at"] = now
    elif not new_running and was_running:
        # Running -> stopped: bank the elapsed run-time, then clear the run clock.
        started = generator_state["current_run_started_at"]
        if started is not None:
            generator_state["total_run_hours"] += max(0.0, (now - started) / 3600.0)
        generator_state["current_run_started_at"] = None
        # Persist the newly-accumulated lifetime total (outside? no -- kv_set takes
        # its own lock, distinct from state_lock, so calling it here is safe).
        kv_set("total_run_hours", generator_state["total_run_hours"])

    generator_state["running"] = new_running


# Restore durable state now that the kv store + these globals exist.
load_persisted_state()

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
    time.sleep(duration)
    relay_start_stop.off()  # De-energize relay (opens contacts)
    time.sleep(0.1)         # Small debounce delay

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
    kv_set("fuel_state", snapshot)
    return snapshot["drain_rate"]


def set_fuel_rate(rate):
    """Set the drain rate directly (%/hr, floored at 0.1) and persist. Returns it."""
    rate = max(0.1, _round1(rate))
    with state_lock:
        fuel_state["drain_rate"] = rate
        snapshot = dict(fuel_state)
    kv_set("fuel_state", snapshot)
    return rate


def reset_fuel_rate():
    """Restore the drain rate to its configured default and persist. Returns it."""
    with state_lock:
        fuel_state["drain_rate"] = _round1(fuel_state["default_rate"])
        rate = fuel_state["drain_rate"]
        snapshot = dict(fuel_state)
    kv_set("fuel_state", snapshot)
    return rate


def set_fuel_fill(level):
    """'Add gas': reset the baseline fill to `level` (%) at the current run-hour
    mark; the drain rate is retained. Persist + return the new fuel model."""
    level = max(0.0, min(100.0, float(level)))
    with state_lock:
        fuel_state["fill_level"] = level
        fuel_state["fill_run_hours"] = _live_total_run_hours_locked()
        snapshot = dict(fuel_state)
    kv_set("fuel_state", snapshot)
    return snapshot


def set_alerts(enabled=None, threshold=None):
    """Update the low-fuel alert config (either field optional) and persist. The
    threshold is clamped to the design's 5..40 slider range. Returns the config."""
    with state_lock:
        if enabled is not None:
            alerts_state["alerts_on"] = bool(enabled)
        if threshold is not None:
            alerts_state["alert_threshold"] = int(max(5, min(40, int(threshold))))
        snapshot = dict(alerts_state)
    kv_set("alerts_state", snapshot)
    return snapshot


def _json_number(data, field):
    """Pull a numeric `field` from a JSON dict body. Returns (value, error_message);
    error_message is None on success. Accepts numeric strings; rejects bools (a bool
    is an int subclass but is never a valid level/rate/threshold)."""
    if not isinstance(data, dict) or field not in data:
        return None, f"missing '{field}'"
    v = data[field]
    if isinstance(v, bool):
        return None, f"'{field}' is not a number"
    if isinstance(v, (int, float)):
        return float(v), None
    if isinstance(v, str):
        try:
            return float(v.strip()), None
        except ValueError:
            return None, f"'{field}' is not a number"
    return None, f"'{field}' is not a number"


# ============================================================================
# FLASK WEB SERVER
# ============================================================================
# static_folder=None disables Flask's built-in /static/<path> route entirely.
# We serve zero static files (the UI is one inline template), so this removes an
# unused file-serving surface -- nothing under the app dir (incl. the settings
# file) can be reached over HTTP.
app = Flask(__name__, static_folder=None)

# The UI is ONE self-contained page: inline <style> + inline vanilla JS, no external
# assets, no framework, no build step (see the design handoff). Split into HEAD/BODY
# only for readability. Jinja `{% raw %}` wraps the CSS/JS so their braces + JS
# template literals are never mistaken for Jinja tags; the initial RUNNING/STOPPED
# state is server-rendered in the BODY (outside raw) so the page shows correct state
# even before JS runs and so no-JS/tests still see it.
HTML_TEMPLATE_HEAD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>GENERATOR CONTROL</title>
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="dark">
{% raw %}<style>
/* ---- reset + page frame ---- */
*{box-sizing:border-box;margin:0;padding:0}
html,body{background:#0a0a0b;color:#d7d3cc;-webkit-text-size-adjust:100%}
body{font-family:ui-sans-serif,system-ui,-apple-system,'Segoe UI',sans-serif;
  min-height:100vh;display:flex;justify-content:center;
  padding:16px;padding:max(16px,env(safe-area-inset-top)) max(16px,env(safe-area-inset-right)) max(16px,env(safe-area-inset-bottom)) max(16px,env(safe-area-inset-left))}
:root{--mono:ui-monospace,'SF Mono',Menlo,monospace}
button{font-family:inherit}

/* ---- root metal panel ---- */
.panel{position:relative;overflow:hidden;width:100%;max-width:960px;
  display:flex;flex-direction:column;gap:20px;padding:24px;border-radius:16px;
  background:linear-gradient(150deg,#26262b 0%,#191a1d 42%,#141416 100%);
  border:1px solid #000;
  box-shadow:0 1px 0 rgba(255,255,255,.05) inset,0 24px 60px rgba(0,0,0,.6),0 0 0 1px rgba(0,0,0,.6)}
.rivet{position:absolute;width:9px;height:9px;border-radius:50%;
  background:radial-gradient(circle at 35% 30%,#5a5a60,#0c0c0d);
  box-shadow:0 1px 1px #000,inset 0 1px 1px rgba(255,255,255,.4);z-index:5}
.rivet.tl{top:11px;left:11px}.rivet.tr{top:11px;right:11px}
.rivet.bl{bottom:11px;left:11px}.rivet.br{bottom:11px;right:11px}

/* ---- header placard ---- */
.placard{padding:16px 18px;border-radius:11px;
  background:linear-gradient(180deg,#2f2f34,#1c1c1f);border:1px solid #0a0a0b;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.06),inset 0 -2px 4px rgba(0,0,0,.5),0 1px 2px rgba(0,0,0,.6)}
.placard h1{font:700 19px sans-serif;letter-spacing:.16em;color:#e8e4dc;text-shadow:0 1px 0 #000}

/* ---- body columns ---- */
.body{display:flex;flex-wrap:wrap;gap:20px}
.col{display:flex;flex-direction:column;gap:20px;min-width:0}
.col-left{flex:1 1 262px}
.col-right{flex:1.6 1 344px}
.section-label{font:600 11px var(--mono);letter-spacing:.2em;color:#7d786f;margin-bottom:8px}

/* ---- status annunciator ---- */
.annunciator{display:flex;align-items:center;gap:16px;padding:16px 18px;border-radius:11px;
  background:linear-gradient(180deg,#1a1a1d,#101012);
  box-shadow:inset 0 2px 6px rgba(0,0,0,.7),inset 0 1px 0 rgba(255,255,255,.03)}
.lamp{position:relative;flex:0 0 auto;width:26px;height:26px;border-radius:50%;
  animation:pulse 2.4s ease-in-out infinite;
  background:radial-gradient(circle at 40% 35%,#5a564f,#2a2824);box-shadow:inset 0 2px 3px rgba(0,0,0,.5)}
.lamp::after{content:"";position:absolute;inset:0;border-radius:50%;
  background:repeating-linear-gradient(0deg,rgba(0,0,0,.26) 0 1px,transparent 1px 3px);mix-blend-mode:multiply}
.panel[data-running="true"] .lamp{
  background:radial-gradient(circle at 40% 35%,#ffb0a0,#ff2a12 55%,#7a0e04);
  box-shadow:0 0 16px 3px rgba(255,50,25,.75),inset 0 2px 3px rgba(0,0,0,.5)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.82}}
.ann-label{font:600 12px var(--mono);letter-spacing:.24em;color:#807b71}
.ann-value{font:800 28px var(--mono);letter-spacing:.08em;color:#8f8a80;text-shadow:0 0 12px currentColor}
.panel[data-running="true"] .ann-value{color:#ff5a4a}

/* ---- detail strip ---- */
.detail{position:relative;overflow:hidden;display:flex;align-items:center;gap:12px;
  padding:14px 16px;min-height:66px;border-radius:11px;
  background:linear-gradient(180deg,#0e0e10,#060607);box-shadow:inset 0 2px 8px rgba(0,0,0,.8)}
.detail::after{content:"";position:absolute;inset:0;pointer-events:none;
  background:repeating-linear-gradient(0deg,rgba(0,0,0,.26) 0 1px,transparent 1px 3px);mix-blend-mode:multiply}
.detail-dot{flex:0 0 auto;width:8px;height:8px;border-radius:50%;background:#ffb347;box-shadow:0 0 8px 2px rgba(255,180,71,.6)}
.detail span:last-child{font:600 14px var(--mono);color:#ffcf8a;text-shadow:0 0 6px rgba(255,180,71,.45)}

/* ---- hero rocker switch (Uiverse/Nawsome, keyboard-accessible variant) ---- */
.switch-wrap{display:flex;justify-content:center;padding:6px 0}
.switch{display:block;background:#000;width:150px;height:195px;
  box-shadow:0 0 10px 2px rgba(0,0,0,.4),0 0 1px 2px #000,inset 0 2px 2px -2px #fff,inset 0 0 2px 15px #47434c,inset 0 0 2px 22px #000;
  border-radius:6px;padding:20px;perspective:700px;position:relative}
.switch input{position:absolute;inset:0;width:100%;height:100%;margin:0;opacity:0;cursor:pointer;z-index:3}
.switch input:checked ~ .btn{transform:translateZ(20px) rotateX(25deg);box-shadow:0 -10px 20px #ff1818}
.switch input:checked ~ .btn .light{animation:flicker .2s infinite .3s}
.switch input:checked ~ .btn .shine{opacity:1}
.switch input:checked ~ .btn .shadow{opacity:0}
.switch input:focus-visible ~ .btn{outline:3px solid #ffca7a;outline-offset:8px;border-radius:3px}
.btn{display:block;transition:all .3s cubic-bezier(1,0,1,1);transform-origin:center center -20px;
  transform:translateZ(20px) rotateX(-25deg);transform-style:preserve-3d;height:100%;position:relative;cursor:pointer;
  background:linear-gradient(#980000 0%,#6f0000 30%,#6f0000 70%,#980000 100%);background-repeat:no-repeat;pointer-events:none}
.btn::before{content:"";background:linear-gradient(rgba(255,255,255,.8) 10%,rgba(255,255,255,.3) 30%,#650000 75%,#320000) 50% 50%/97% 97%,#b10000;
  background-repeat:no-repeat;width:100%;height:50px;transform-origin:top;transform:rotateX(-90deg);position:absolute;top:0}
.btn::after{content:"";background-image:linear-gradient(#650000,#320000);width:100%;height:50px;transform-origin:top;
  transform:translateY(50px) rotateX(-90deg);position:absolute;bottom:0;box-shadow:0 50px 8px 0 #000,0 80px 20px 0 rgba(0,0,0,.5)}
.light{opacity:0;animation:light-off 1s;position:absolute;width:100%;height:100%;background-image:radial-gradient(#ffc97e,#ff1818 40%,transparent 70%)}
.dots{position:absolute;width:100%;height:100%;background-image:radial-gradient(transparent 30%,rgba(101,0,0,.7) 70%);background-size:10px 10px}
.chars{position:absolute;width:100%;height:100%;background:linear-gradient(#fff,#fff) 50% 20%/5% 20%,radial-gradient(circle,transparent 50%,#fff 52%,#fff 70%,transparent 72%) 50% 80%/33% 25%;background-repeat:no-repeat}
.shine{transition:all .3s cubic-bezier(1,0,1,1);opacity:.3;position:absolute;width:100%;height:100%;background:linear-gradient(#fff,transparent 3%) 50% 50%/97% 97%,linear-gradient(rgba(255,255,255,.5),transparent 50%,transparent 80%,rgba(255,255,255,.5)) 50% 50%/97% 97%;background-repeat:no-repeat}
.shadow{transition:all .3s cubic-bezier(1,0,1,1);opacity:1;position:absolute;width:100%;height:100%;background:linear-gradient(transparent 70%,rgba(0,0,0,.8));background-repeat:no-repeat}
@keyframes flicker{0%{opacity:1}80%{opacity:.8}100%{opacity:1}}
@keyframes light-off{0%{opacity:1}80%{opacity:0}}

/* ---- current-run nixie readout ---- */
.nixie{padding:16px;border-radius:8px;text-align:center;
  background:radial-gradient(120% 120% at 50% 0%,#241300,#0a0600 70%);
  box-shadow:inset 0 2px 10px rgba(0,0,0,.8);
  font:800 40px var(--mono);color:#5a4420;letter-spacing:.04em}
.panel[data-running="true"] .nixie{color:#ffb347;text-shadow:0 0 12px rgba(255,150,40,.75),0 0 2px rgba(255,200,120,.9)}

/* ---- total-runtime odometer ---- */
.odometer{display:flex;align-items:flex-end;gap:1px;padding:10px 12px;border-radius:8px;
  background:linear-gradient(180deg,#101012,#050506);box-shadow:inset 0 2px 10px rgba(0,0,0,.85);justify-content:center}
.wheel{position:relative;width:30px;height:46px;overflow:hidden;border-radius:3px;
  background:linear-gradient(180deg,#4a463f 0%,#d8d2c6 24%,#fffef9 50%,#d8d2c6 76%,#4a463f 100%)}
.wheel::after{content:"";position:absolute;inset:0;pointer-events:none;
  box-shadow:inset 0 5px 7px -4px rgba(0,0,0,.65),inset 0 -5px 7px -4px rgba(0,0,0,.65)}
.reel{position:absolute;left:0;right:0;top:0;will-change:transform}
.reel .cell{height:46px;display:flex;align-items:center;justify-content:center;
  font:800 30px var(--mono);color:#141210}
.wheel-int .reel{transition:transform .7s cubic-bezier(.33,0,.15,1)}
.wheel-tenths .reel{transition:transform 1s linear}
.odo-dot{font:800 34px var(--mono);color:#ff7a3a;align-self:flex-end;margin:0 -2px 2px}

/* ---- system registers ---- */
.registers{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.reg{position:relative;overflow:hidden;padding:12px 14px;border-radius:8px;
  background:radial-gradient(120% 130% at 50% -10%,#0d1210,#050806 75%);box-shadow:inset 0 2px 8px rgba(0,0,0,.75)}
.reg::after{content:"";position:absolute;inset:0;pointer-events:none;
  background:repeating-linear-gradient(0deg,rgba(0,0,0,.22) 0 1px,transparent 1px 3px);mix-blend-mode:multiply}
.reg-label{font:600 10px var(--mono);letter-spacing:.2em;color:#4f7d64;margin-bottom:6px}
.reg-value{font:700 17px var(--mono);color:#6fe6a0;text-shadow:0 0 7px rgba(80,224,140,.4);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

/* ---- event log (VFD) ---- */
.log-head{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:8px}
.log-count{font:600 11px var(--mono);letter-spacing:.14em;color:#5a564f}
.log{container-type:inline-size;position:relative;height:190px;overflow-y:auto;padding:8px 10px;border-radius:8px;
  background:radial-gradient(120% 100% at 50% 0%,#04120a,#010704 75%);box-shadow:inset 0 2px 10px rgba(0,0,0,.85)}
.log::-webkit-scrollbar{width:8px}.log::-webkit-scrollbar-track{background:#020604}
.log::-webkit-scrollbar-thumb{background:#1c4a30;border-radius:4px}
.log{scrollbar-color:#1c4a30 #020604;scrollbar-width:thin}
.evt{display:flex;gap:8px;padding:5px 0;border-bottom:1px solid rgba(87,224,138,.08);
  font:600 13px var(--mono);color:#57e08a;text-shadow:0 0 5px rgba(87,224,138,.45)}
.evt .t{flex:0 0 152px;color:#3f8f5e}
.evt .g{flex:0 0 74px;color:#8fe0a8}
.evt .m{flex:1 1 auto;word-break:break-word}
@container (max-width:560px){
  .evt{display:block}.evt .t,.evt .g,.evt .m{flex:none;display:inline}
  .evt .t::after,.evt .g::after{content:" "}
}
.log-foot{margin-top:6px;text-align:center;font:600 10px var(--mono);letter-spacing:.16em;color:#2f5a40}

/* ---- drawers (shared) ---- */
.drawer{border-radius:11px;overflow:hidden;background:linear-gradient(180deg,#141416,#0b0b0d);border:1px solid #000}
.drawer.fuel{--tint:#0e1416}.drawer.adv{--tint:#160f0e}
.drawer-face{display:flex;align-items:center;justify-content:space-between;gap:12px;
  min-height:54px;padding:0 16px;cursor:pointer;border:0;width:100%;text-align:left;color:#d7d3cc;
  background:linear-gradient(180deg,#34343b 0%,#26262c 52%,#1e1e23 100%);
  box-shadow:inset 0 1px 0 rgba(255,255,255,.13),inset 0 -2px 5px rgba(0,0,0,.5),0 3px 6px rgba(0,0,0,.45)}
.drawer-face:hover{filter:brightness(1.12)}.drawer-face:active{filter:brightness(.94)}
.drawer-face:focus-visible{outline:3px solid #ffca7a;outline-offset:-3px}
.face-left{display:flex;align-items:center;gap:10px;font:700 12px sans-serif;letter-spacing:.14em}
.face-right{display:flex;align-items:center;gap:10px;font:700 13px var(--mono)}
.caret{transition:transform .35s;font-size:14px;color:#9b9689}
.drawer.open .caret{transform:rotate(180deg)}
.drawer-clip{overflow:hidden;max-height:0;transition:max-height .45s cubic-bezier(.4,0,.2,1)}
.drawer-cavity{padding:16px;display:flex;flex-direction:column;gap:14px;
  background:linear-gradient(180deg,#0a0a0c,#0d0d10);
  box-shadow:inset 0 13px 16px -11px rgba(0,0,0,.95),inset 7px 0 10px -8px rgba(0,0,0,.9),inset -7px 0 10px -8px rgba(0,0,0,.9),inset 0 -9px 12px -8px rgba(0,0,0,.9)}
.drawer-base{height:10px;background:linear-gradient(180deg,#2c2c32,#161619);
  box-shadow:inset 0 1px 0 rgba(255,255,255,.12),0 2px 4px rgba(0,0,0,.5)}
.engrave{display:inline-flex;filter:drop-shadow(0 1px 0 rgba(255,255,255,.14)) drop-shadow(0 -1px 1px rgba(0,0,0,.5))}
.engrave svg{width:18px;height:18px;display:block}
.warn-copy{font:600 12px var(--mono);color:#e0b090;line-height:1.5}

/* ---- fuel drawer internals ---- */
.fuel-top{display:flex;gap:14px;flex-wrap:wrap;align-items:stretch}
.tank-col{flex:0 0 60px;display:flex;flex-direction:column;align-items:center;gap:6px}
.tank{position:relative;width:52px;flex:1 1 auto;min-height:70px;border-radius:6px;overflow:hidden;
  background:linear-gradient(180deg,#0c0c0e,#050506);box-shadow:inset 0 0 0 2px #000,inset 0 2px 8px rgba(0,0,0,.9)}
.tank-fill{position:absolute;left:0;right:0;bottom:0;height:0%;transition:height .5s ease,background .3s;
  background:linear-gradient(180deg,#ffb347,#7a3a08);box-shadow:0 0 12px rgba(255,150,40,.55)}
.tank.low .tank-fill{background:linear-gradient(180deg,#ff5a4a,#a01810);box-shadow:0 0 12px rgba(255,70,50,.6)}
.tank-line{position:absolute;left:0;right:0;height:3px;background:#ff2a1a;
  box-shadow:0 0 0 1px rgba(0,0,0,.85),0 1px 3px rgba(0,0,0,.9),0 0 7px rgba(255,50,25,.65)}
.tank-label{font:600 10px var(--mono);letter-spacing:.2em;color:#807b71}
.fuel-grid{flex:1 1 200px;display:grid;grid-template-columns:repeat(3,1fr);gap:9px}
@container (max-width:520px){.fuel-grid{grid-template-columns:1fr 1fr}}
@container (max-width:340px){.fuel-grid{grid-template-columns:1fr}}
.fcard{padding:10px 12px;border-radius:8px;background:linear-gradient(160deg,#0b1214,#04080a);
  border:1px solid #08161a;box-shadow:inset 0 2px 7px rgba(0,0,0,.7)}
.fcard-label{font:600 10px var(--mono);letter-spacing:.18em;color:#4f7d8a;margin-bottom:5px}
.fcard-value{font:700 16px var(--mono);color:#8fd6e8;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.fuel-io{display:flex;gap:9px;align-items:stretch}
.crt-input{flex:1 1 auto;min-width:0;padding:0 12px;height:48px;border-radius:8px;border:1px solid #000;
  background:radial-gradient(120% 130% at 50% -10%,#0d1210,#050806 75%);
  color:#7ce0b0;font:700 16px var(--mono);text-shadow:0 0 6px rgba(80,224,140,.4);
  box-shadow:inset 0 2px 7px rgba(0,0,0,.75)}
.crt-input::placeholder{color:#3f7d64}
.crt-input:focus{outline:3px solid #ffca7a;outline-offset:2px}
.helper{font:500 11px var(--mono);color:#6f6a62;line-height:1.5}
.alert-banner{display:none;align-items:center;gap:10px;padding:11px 14px;border-radius:8px;
  background:linear-gradient(180deg,#2a0f0c,#1a0906);border:1px solid #6a2018;
  font:600 12px var(--mono);color:#ffb0a0}
.alert-banner.show{display:flex}
.alert-dot{width:9px;height:9px;border-radius:50%;background:#ff3a22;box-shadow:0 0 8px 2px rgba(255,60,30,.7);animation:pulse 1s ease-in-out infinite}
.alert-cfg{padding:12px 14px;border-radius:8px;background:linear-gradient(160deg,#0b1214,#04080a);border:1px solid #08161a;display:flex;flex-direction:column;gap:12px}
.alert-cfg-row{display:flex;align-items:center;justify-content:space-between;gap:12px}
.alert-cfg-row .lbl{display:flex;align-items:center;gap:9px;font:700 12px sans-serif;letter-spacing:.1em;color:#9fdcec}
.thresh-row{display:flex;align-items:center;gap:12px}
.thresh-row .tval{font:700 15px var(--mono);color:#ffb347;min-width:44px;text-align:right}
input[type=range].thresh{-webkit-appearance:none;appearance:none;flex:1 1 auto;height:6px;border-radius:3px;
  background:linear-gradient(90deg,#ff7a3a,#7a3a08);outline-offset:4px}
input[type=range].thresh::-webkit-slider-thumb{-webkit-appearance:none;width:20px;height:20px;border-radius:50%;
  background:radial-gradient(circle at 35% 30%,#dcd8d0,#5a5a60);box-shadow:0 1px 3px rgba(0,0,0,.8),inset 0 1px 1px rgba(255,255,255,.5);cursor:pointer}
input[type=range].thresh::-moz-range-thumb{width:20px;height:20px;border:0;border-radius:50%;
  background:radial-gradient(circle at 35% 30%,#dcd8d0,#5a5a60);box-shadow:0 1px 3px rgba(0,0,0,.8);cursor:pointer}

/* ---- flat I/O toggle ---- */
.iotoggle{display:inline-flex;width:80px;height:34px;padding:2px;border-radius:6px;
  background:#08080a;border:1px solid #000;box-shadow:inset 0 2px 5px rgba(0,0,0,.8);cursor:pointer}
.iotoggle .half{flex:1 1 50%;display:flex;align-items:center;justify-content:center;
  font:800 15px ui-sans-serif,system-ui,sans-serif}
.iotoggle .half.i{border-radius:4px 0 0 4px;border-right:1px solid #000;background:#1a1a1e;color:#5a5650}
.iotoggle .half.o{border-radius:0 4px 4px 0;background:#1a1a1e;color:#5a5650}
.iotoggle[aria-checked="true"] .half.i{background:linear-gradient(180deg,#1a6040,#123f2a);color:#7effb0;box-shadow:0 0 5px rgba(87,224,138,.3);text-shadow:0 0 4px rgba(87,224,138,.5)}
.iotoggle[aria-checked="false"] .half.o{background:linear-gradient(180deg,#6a2a1e,#4a1610);color:#ffb0a0;box-shadow:0 0 5px rgba(255,90,60,.28)}
.iotoggle:focus-visible{outline:3px solid #ffca7a;outline-offset:3px}

/* ---- tactile 3D buttons ---- */
.btn3d{--b:#0b0b0d;min-height:48px;padding:0 16px;border-radius:9px;border:1px solid #000;cursor:pointer;
  display:inline-flex;align-items:center;justify-content:center;gap:8px;
  background:linear-gradient(180deg,#4c4c54 0%,#34343b 46%,#282830 100%);color:#e4e0d8;
  font:700 12px sans-serif;letter-spacing:.1em;
  box-shadow:0 4px 0 var(--b),0 0 0 2px rgba(0,0,0,.75),0 8px 15px rgba(0,0,0,.6),inset 0 1px 0 rgba(255,255,255,.24);
  transition:transform .09s,box-shadow .09s,filter .15s}
.btn3d:hover{filter:brightness(1.16);transform:translateY(-1px);box-shadow:0 5px 0 var(--b),0 0 0 2px rgba(0,0,0,.75),0 10px 16px rgba(0,0,0,.6),inset 0 1px 0 rgba(255,255,255,.24)}
.btn3d:active{transform:translateY(4px);box-shadow:0 0 0 var(--b),0 0 0 2px rgba(0,0,0,.75),inset 0 2px 4px rgba(0,0,0,.5)}
.btn3d:focus-visible{outline:3px solid #ffca7a;outline-offset:3px}
.btn3d.amber{color:#ffd89a}.btn3d.steel{color:#c7c3bc}.btn3d.cyan{color:#9fdcec}.btn3d.green{color:#b6e89a}
.btn3d.red{background:linear-gradient(180deg,#ff8a54,#d23a10);--b:#7a1e06;color:#fff}
.btn3dsm{min-height:40px;padding:0 12px}
.led{width:9px;height:9px;border-radius:50%}
.led.amber{background:#ffb347;box-shadow:0 0 7px rgba(255,180,71,.7)}
.led.grey{background:#5a564f}
.adv-btns{display:flex;gap:12px;flex-wrap:wrap}
.adv-btns .btn3d{flex:1 1 140px}

/* ---- cannot-auto-detect note + footer ---- */
.note{display:flex;align-items:center;gap:12px;padding:12px 16px;border-radius:10px;
  background:linear-gradient(160deg,#1c1509,#120d05);border:1px solid #3a2a10;
  font:600 12px var(--mono);color:#d8ac60;line-height:1.5}
footer{border-top:1px solid rgba(255,255,255,.06);padding-top:16px;
  display:flex;flex-direction:column;align-items:center;gap:10px;text-align:center}
footer .frow{font:500 11.5px var(--mono);color:#6f6a62}
footer a{color:#9b9689;text-decoration:underline}

/* ---- start confirm dialog ---- */
.confirm-overlay{position:absolute;inset:0;z-index:20;display:none;align-items:center;justify-content:center;padding:20px;
  background:rgba(6,6,7,.82);backdrop-filter:blur(2px)}
.confirm-overlay.show{display:flex}
.confirm-card{max-width:340px;width:100%;padding:22px;border-radius:12px;text-align:center;
  background:linear-gradient(160deg,#2a1a14,#1a1210);border:1px solid #6a3a1a;box-shadow:0 20px 50px rgba(0,0,0,.7)}
.confirm-badge{display:inline-flex;margin-bottom:12px;color:#ffb347}
.confirm-card h2{font:800 18px sans-serif;letter-spacing:.08em;color:#ffcf8a;margin-bottom:10px}
.confirm-card p{font:600 13px var(--mono);color:#e0b090;line-height:1.6;margin-bottom:18px}
.confirm-btns{display:flex;gap:12px}.confirm-btns .btn3d{flex:1 1 0}

.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);border:0}
</style>{% endraw %}
</head>"""

# Inline vanilla JS. Wrapped in {% raw %} so its braces / string literals are never
# parsed as Jinja. Hydrates the server-rendered shell from /api/state + /api/events
# and drives every interaction. No framework, no external requests, no build step.
HTML_TEMPLATE_SCRIPT = """{% raw %}<script>
(function(){
"use strict";
var $=function(id){return document.getElementById(id);};
var panel=$('panel');
var state=null, clockOffset=0, busy=false, confirmOpen=false;
var newestSeq=0, oldestSeq=null, loadingOlder=false, totalEvents=0;

/* ---------- fetch helpers ---------- */
function api(path,opts){return fetch(path,opts||{}).then(function(r){return r.json().catch(function(){return {};});});}
function post(path,body){return api(path,{method:'POST',headers:{'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});}
function fetchState(cb){api('/api/state').then(cb).catch(function(){cb(null);});}

/* ---------- clocks / formatting ---------- */
function nowSec(){return (Date.now()+clockOffset)/1000;}
var MON=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
function clock12(d){var h=d.getHours(),m=d.getMinutes(),ap=h<12?'am':'pm';h=h%12;if(h===0)h=12;return h+':'+(m<10?'0':'')+m+ap;}
function fmtStamp(d,withYear){var s=MON[d.getMonth()]+' '+d.getDate();if(withYear){s+=' '+String(d.getFullYear()).slice(-2);}return s+' '+clock12(d);}
function parseISO(s){if(!s)return null;var d=new Date(s);return isNaN(d.getTime())?null:d;}
function pad2(n){return (n<10?'0':'')+n;}
function fmtClock(secs){secs=Math.max(0,Math.floor(secs));var d=Math.floor(secs/86400);secs-=d*86400;var h=Math.floor(secs/3600);secs-=h*3600;var m=Math.floor(secs/60);var s=secs-m*60;var base=pad2(h)+':'+pad2(m)+':'+pad2(s);return d>0?d+'d '+base:base;}
var DASH='\\u2014';
function fmtDur(hours){if(hours==null||!isFinite(hours))return DASH;var m=Math.round(hours*60);var d=Math.floor(m/1440);m-=d*1440;var h=Math.floor(m/60);m-=h*60;if(d>0)return d+'d '+h+'h';if(h>0)return h+'h '+m+'m';return m+'m';}

/* ---------- live derived values ---------- */
function liveTotalHours(){if(!state)return 0;var t=state.total_run_hours||0;if(state.running&&state.current_run_started_at){t+=Math.max(0,(nowSec()-state.current_run_started_at)/3600);}return t;}
function uptimeSecs(){if(state&&state.running&&state.current_run_started_at){return Math.max(0,nowSec()-state.current_run_started_at);}return 0;}
function fuel(){return state?state.fuel:null;}
function alertCfg(){return state&&state.alerts?state.alerts:{alerts_on:true,alert_threshold:20};}
function projectedLevel(){var f=fuel();if(!f)return null;var run=Math.max(0,liveTotalHours()-f.fill_run_hours);return Math.max(0,Math.min(100,f.fill_level-f.drain_rate*run));}
function hoursTo(target){var f=fuel();if(!f||!state.running)return null;var lvl=projectedLevel();if(f.drain_rate>0&&lvl>target)return (lvl-target)/f.drain_rate;return null;}

/* ---------- odometer wheels ---------- */
var odoReels=[];
function buildOdometer(){var odo=$('odometer');odo.innerHTML='';
  function wheel(cls){var w=document.createElement('div');w.className='wheel '+cls;var reel=document.createElement('div');reel.className='reel';for(var i=0;i<=10;i++){var c=document.createElement('div');c.className='cell';c.textContent=i%10;reel.appendChild(c);}w.appendChild(reel);odo.appendChild(w);return reel;}
  odoReels=[];for(var i=0;i<4;i++)odoReels.push(wheel('wheel-int'));
  var dot=document.createElement('span');dot.className='odo-dot';dot.textContent='.';odo.appendChild(dot);
  odoReels.push(wheel('wheel-tenths'));}
function updateOdometer(hours){var intPart=Math.min(9999,Math.floor(hours));var ds=('0000'+intPart).slice(-4);for(var i=0;i<4;i++){odoReels[i].style.transform='translateY(-'+(parseInt(ds.charAt(i),10)*46)+'px)';}var frac=hours-Math.floor(hours);odoReels[4].style.transform='translateY(-'+((frac*10)*46)+'px)';}

/* ---------- state render ---------- */
function cmdLabel(c){return {start:'START',stop:'STOP',mark_run:'MARK RUN',mark_stop:'MARK STOP'}[c]||DASH;}
function applyState(s){
  if(!s)return; state=s; clockOffset=s.server_now*1000-Date.now();
  panel.setAttribute('data-running',s.running?'true':'false');
  $('statusWord').textContent=s.running?'RUNNING':'STOPPED';
  $('detailMsg').textContent=s.running?('Start sequence completed '+DASH+' verify the unit is running.'):('System idle '+DASH+' generator stopped. Flip switch up to start.');
  $('regLastCmd').textContent=cmdLabel(s.last_command);
  $('regAttempts').textContent=s.start_attempts;
  var ls=parseISO(s.last_start_time),lp=parseISO(s.last_stop_time);
  $('regLastStart').textContent=ls?fmtStamp(ls,false):DASH;
  $('regLastStop').textContent=lp?fmtStamp(lp,false):DASH;
  if(!busy&&!confirmOpen){$('powerSwitch').checked=s.running;}
  if(s.fuel){$('rateInput').placeholder=s.fuel.drain_rate+' %/hr';}
  var a=s.alerts||{}; setToggle(a.alerts_on!==false);
  if(document.activeElement!==$('threshSlider')){$('threshSlider').value=a.alert_threshold||20;$('threshVal').textContent=(a.alert_threshold||20)+'%';}
  tick();
}
function tick(){if(!state)return;$('uptime').textContent=fmtClock(uptimeSecs());updateOdometer(liveTotalHours());renderFuel();}
function renderFuel(){
  var f=fuel();if(!f)return;var lvl=projectedLevel();var thr=alertCfg().alert_threshold;var running=state.running;
  var levelEl=$('fLevel');levelEl.textContent=Math.round(lvl)+'%';
  levelEl.style.color=lvl<=thr?'#ff5a4a':(lvl<=thr+15?'#ffb347':'#7ce0b0');
  var faceLvl=$('fuelFaceLevel');faceLvl.textContent=Math.round(lvl)+'%';faceLvl.style.color=levelEl.style.color;
  $('fRate').textContent=f.drain_rate.toFixed(1)+' %/hr';
  $('fReachesLabel').textContent='REACHES '+thr+'%';
  var toThr=hoursTo(thr),toEmpty=hoursTo(0);
  $('fReaches').textContent=running?(toThr!=null?fmtDur(toThr):DASH):'PAUSED';
  $('fEmptyIn').textContent=running?(toEmpty!=null?fmtDur(toEmpty):DASH):'PAUSED';
  $('fLowAt').textContent=(running&&toThr!=null)?clock12(new Date(Date.now()+toThr*3600000)):(running?DASH:'STOPPED');
  $('fEmptyAt').textContent=(running&&toEmpty!=null)?clock12(new Date(Date.now()+toEmpty*3600000)):(running?DASH:'STOPPED');
  var tank=$('tank');$('tankFill').style.height=lvl+'%';tank.className='tank'+(lvl<=thr?' low':'');$('tankLine').style.bottom=thr+'%';
  $('alertBanner').className='alert-banner'+((alertCfg().alerts_on!==false&&lvl<=thr)?' show':'');
}

/* ---------- event log ---------- */
function tagLabel(t){return '['+({startup:'BOOT',start:'START',start_complete:'START',start_rejected:'ERR',stop:'STOP',set_running:'MANUAL',fuel:'FUEL'}[t]||'LOG')+']';}
function evtEl(e){var row=document.createElement('div');row.className='evt';
  var t=document.createElement('span');t.className='t';t.textContent=fmtStamp(new Date(e.ts*1000),true);
  var g=document.createElement('span');g.className='g';g.textContent=tagLabel(e.type);
  var m=document.createElement('span');m.className='m';m.textContent=e.message;
  row.appendChild(t);row.appendChild(g);row.appendChild(m);return row;}
function setCount(n){totalEvents=n;$('logCount').textContent=n+' EVENT'+(n===1?'':'S');}
function loadInitialEvents(){api('/api/events?limit=100').then(function(d){var log=$('log');log.innerHTML='';var evs=d.events||[];evs.forEach(function(e){log.appendChild(evtEl(e));});if(evs.length){newestSeq=evs[0].seq;oldestSeq=evs[evs.length-1].seq;}setCount(d.latest_seq||evs.length);});}
function loadNewEvents(){if(!newestSeq){loadInitialEvents();return;}api('/api/events?after='+newestSeq+'&limit=100').then(function(d){var evs=d.events||[];var log=$('log');for(var i=evs.length-1;i>=0;i--){log.insertBefore(evtEl(evs[i]),log.firstChild);}if(evs.length){newestSeq=evs[0].seq;}if(d.latest_seq)setCount(d.latest_seq);});}
function loadOlderEvents(){if(loadingOlder||oldestSeq==null)return;loadingOlder=true;api('/api/events?before='+oldestSeq+'&limit=100').then(function(d){var evs=d.events||[];var log=$('log');evs.forEach(function(e){log.appendChild(evtEl(e));});if(evs.length){oldestSeq=evs[evs.length-1].seq;}loadingOlder=false;}).catch(function(){loadingOlder=false;});}

/* ---------- actions ---------- */
function refresh(){fetchState(function(s){if(s)applyState(s);});loadNewEvents();}
function settle(target){var n=0;(function step(){setTimeout(function(){fetchState(function(s){if(s)applyState(s);if((s&&s.running===target)||++n>20){busy=false;if(s)applyState(s);loadNewEvents();}else step();});},600);})();}
var sw=$('powerSwitch');
sw.addEventListener('change',function(){if(sw.checked){confirmOpen=true;$('confirmOverlay').className='confirm-overlay show';}else{doStop();}});
function closeConfirm(revert){confirmOpen=false;$('confirmOverlay').className='confirm-overlay';if(revert){sw.checked=false;}}
$('confirmCancel').addEventListener('click',function(){closeConfirm(true);});
$('confirmStart').addEventListener('click',function(){closeConfirm(false);doStart();});
function doStart(){busy=true;post('/api/start').then(function(d){if(d&&d.success===false){busy=false;sw.checked=false;refresh();}else{settle(true);}}).catch(function(){busy=false;sw.checked=false;refresh();});}
function doStop(){busy=true;sw.checked=false;post('/api/stop').then(function(){settle(false);}).catch(function(){busy=false;refresh();});}
$('markRunBtn').addEventListener('click',function(){post('/api/set_running',{running:true}).then(refresh);});
$('markStopBtn').addEventListener('click',function(){post('/api/set_running',{running:false}).then(refresh);});

/* ---------- fuel controls ---------- */
function numVal(id){var v=parseFloat($(id).value);return isFinite(v)?v:null;}
$('setRateBtn').addEventListener('click',function(){var v=numVal('rateInput');if(v==null)return;post('/api/fuel/rate',{rate:v}).then(function(){$('rateInput').value='';refresh();});});
$('resetRateBtn').addEventListener('click',function(){post('/api/fuel/rate/reset').then(function(){$('rateInput').value='';refresh();});});
$('recordBtn').addEventListener('click',function(){var v=numVal('readingInput');if(v==null)return;post('/api/fuel/reading',{level:v}).then(function(){$('readingInput').value='';refresh();});});
$('fillBtn').addEventListener('click',function(){var v=numVal('fillInput');if(v==null)return;post('/api/fuel/fill',{level:v}).then(function(){$('fillInput').value='';refresh();});});

/* ---------- alert toggle + threshold ---------- */
function setToggle(on){$('alertToggle').setAttribute('aria-checked',on?'true':'false');}
function toggleAlerts(){var on=$('alertToggle').getAttribute('aria-checked')==='true';post('/api/alerts',{enabled:!on}).then(refresh);}
$('alertToggle').addEventListener('click',toggleAlerts);
$('alertToggle').addEventListener('keydown',function(e){if(e.key===' '||e.key==='Enter'){e.preventDefault();toggleAlerts();}});
$('threshSlider').addEventListener('input',function(){$('threshVal').textContent=this.value+'%';if(state){state.alerts=state.alerts||{};state.alerts.alert_threshold=parseInt(this.value,10);renderFuel();}});
$('threshSlider').addEventListener('change',function(){post('/api/alerts',{threshold:parseInt(this.value,10)}).then(refresh);});

/* ---------- drawers ---------- */
function initDrawer(id,cls){var d=$(id);var face=d.querySelector('.drawer-face');var clip=d.querySelector('.drawer-clip');
  face.addEventListener('click',function(){var open=d.className.indexOf('open')<0;d.className='drawer '+cls+(open?' open':'');face.setAttribute('aria-expanded',open?'true':'false');clip.style.maxHeight=open?'1600px':'0';});}

/* ---------- event-log infinite scroll ---------- */
$('log').addEventListener('scroll',function(){if(this.scrollTop+this.clientHeight>=this.scrollHeight-24){loadOlderEvents();}});

/* ---------- boot ---------- */
buildOdometer();initDrawer('fuelDrawer','fuel');initDrawer('advDrawer','adv');
refresh();
setInterval(function(){if(!busy)refresh();},4000);
setInterval(function(){tick();},1000);
})();
</script>{% endraw %}"""

# Body shell. Server-renders the initial RUNNING/STOPPED state (Jinja, outside the
# raw script) so the page is correct before JS runs / with JS off. All icons are
# inline SVG (currentColor) so the strict CSP holds with zero external requests.
HTML_TEMPLATE_BODY = """
<main class="panel" id="panel" data-running="{{ 'true' if status.running else 'false' }}">
  <span class="rivet tl"></span><span class="rivet tr"></span>
  <span class="rivet bl"></span><span class="rivet br"></span>

  <!-- Header placard -->
  <div class="placard"><h1>GENERATOR CONTROL</h1></div>

  <div class="body">
    <!-- ===== LEFT COLUMN ===== -->
    <div class="col col-left">
      <!-- Status annunciator (read-only) -->
      <div class="annunciator">
        <div class="lamp"></div>
        <div>
          <div class="ann-label">STATUS</div>
          <div class="ann-value" id="statusWord">{{ 'RUNNING' if status.running else 'STOPPED' }}</div>
        </div>
      </div>

      <!-- Detail strip (read-only) -->
      <div>
        <div class="section-label">DETAIL</div>
        <div class="detail">
          <span class="detail-dot"></span>
          <span id="detailMsg">{{ 'Start sequence completed — verify the unit is running.' if status.running else 'System idle — generator stopped. Flip switch up to start.' }}</span>
        </div>
      </div>

      <!-- Hero power switch -->
      <div class="switch-wrap">
        <label class="switch">
          <input type="checkbox" id="powerSwitch"
                 aria-label="Generator power — flip up to start the engine, down to stop"
                 {{ 'checked' if status.running else '' }}>
          <div class="btn"><div class="light"></div><div class="dots"></div>
               <div class="chars"></div><div class="shine"></div><div class="shadow"></div></div>
        </label>
      </div>

      <!-- Current-run nixie readout -->
      <div>
        <div class="section-label">CURRENT RUN · HR:MIN:SEC</div>
        <div class="nixie" id="uptime">00:00:00</div>
      </div>

      <!-- Total-runtime odometer -->
      <div>
        <div class="section-label">TOTAL RUNTIME (HOURS)</div>
        <div class="odometer" id="odometer"></div>
      </div>
    </div>

    <!-- ===== RIGHT COLUMN ===== -->
    <div class="col col-right">
      <!-- System registers -->
      <div>
        <div class="section-label">SYSTEM REGISTERS</div>
        <div class="registers">
          <div class="reg"><div class="reg-label">LAST COMMAND</div><div class="reg-value" id="regLastCmd">—</div></div>
          <div class="reg"><div class="reg-label">START ATTEMPTS</div><div class="reg-value" id="regAttempts">0</div></div>
          <div class="reg"><div class="reg-label">LAST START</div><div class="reg-value" id="regLastStart">—</div></div>
          <div class="reg"><div class="reg-label">LAST STOP</div><div class="reg-value" id="regLastStop">—</div></div>
        </div>
      </div>

      <!-- Event log -->
      <div>
        <div class="log-head">
          <span class="section-label" style="margin:0">EVENT LOG</span>
          <span class="log-count" id="logCount">0 EVENTS</span>
        </div>
        <div class="log" id="log"></div>
        <div class="log-foot">SCROLL FOR OLDER · AUTO-LOADS</div>
      </div>

      <!-- Fuel Projection drawer -->
      <div class="drawer fuel" id="fuelDrawer">
        <button type="button" class="drawer-face" aria-expanded="false" aria-controls="fuelClip">
          <span class="face-left"><span class="engrave"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="4" y="3" width="9" height="18" rx="1"/><line x1="4" y1="9" x2="13" y2="9"/><path d="M13 8h3l2 2v7a2 2 0 0 0 2 2 2 2 0 0 0 2-2V9l-3-3"/></svg></span>FUEL PROJECTION</span>
          <span class="face-right"><span id="fuelFaceLevel" style="color:#7ce0b0">—</span><span class="caret">▾</span></span>
        </button>
        <div class="drawer-clip" id="fuelClip">
          <div class="drawer-cavity">
            <div class="fuel-top">
              <div class="tank-col">
                <div class="tank" id="tank">
                  <div class="tank-fill" id="tankFill"></div>
                  <div class="tank-line" id="tankLine" style="bottom:20%"></div>
                </div>
                <div class="tank-label">TANK</div>
              </div>
              <div class="fuel-grid">
                <div class="fcard"><div class="fcard-label">LEVEL</div><div class="fcard-value" id="fLevel">—</div></div>
                <div class="fcard"><div class="fcard-label">DRAIN RATE</div><div class="fcard-value" id="fRate">—</div></div>
                <div class="fcard"><div class="fcard-label" id="fReachesLabel">REACHES 20%</div><div class="fcard-value" id="fReaches" style="color:#ffb347">—</div></div>
                <div class="fcard"><div class="fcard-label">LOW AT</div><div class="fcard-value" id="fLowAt" style="color:#d8ac60">—</div></div>
                <div class="fcard"><div class="fcard-label">EMPTY IN</div><div class="fcard-value" id="fEmptyIn" style="color:#ff8a6a">—</div></div>
                <div class="fcard"><div class="fcard-label">EMPTY AT</div><div class="fcard-value" id="fEmptyAt" style="color:#e08a70">—</div></div>
              </div>
            </div>

            <div>
              <div class="fuel-io">
                <input class="crt-input" id="rateInput" type="number" step="0.1" min="0" inputmode="decimal" placeholder="drain %/hr" aria-label="Set drain rate percent per hour">
                <button type="button" class="btn3d cyan" id="setRateBtn">SET</button>
                <button type="button" class="btn3d steel btn3dsm" id="resetRateBtn" aria-label="Reset drain rate to default"><span class="engrave"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 12a9 9 0 1 0 3-6.7"/><path d="M3 4v4h4"/></svg></span>RESET</button>
              </div>
              <div class="helper">Estimated automatically from readings, or set it here directly.</div>
            </div>

            <div class="alert-banner" id="alertBanner">
              <span class="alert-dot"></span>LOW FUEL — projected level at or below alert threshold. Refuel soon.
            </div>

            <div>
              <div class="fuel-io">
                <input class="crt-input" id="readingInput" type="number" step="1" min="0" max="100" inputmode="numeric" placeholder="e.g. 48" aria-label="Record observed level percent">
                <button type="button" class="btn3d cyan" id="recordBtn"><span class="engrave"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="9"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/></svg></span>RECORD</button>
              </div>
              <div class="helper">Each reading refines the linear drain estimate (level = start − rate × run-hours). More readings on one tank → better projection.</div>
            </div>

            <div>
              <div class="fuel-io">
                <input class="crt-input" id="fillInput" type="number" step="1" min="0" max="100" inputmode="numeric" placeholder="e.g. 100" aria-label="Set gas tank level percent">
                <button type="button" class="btn3d green" id="fillBtn"><span class="engrave"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="4" y="3" width="9" height="18" rx="1"/><line x1="4" y1="9" x2="13" y2="9"/><path d="M13 8h3l2 2v7a2 2 0 0 0 2 2 2 2 0 0 0 2-2V9l-3-3"/></svg></span>SET</button>
              </div>
              <div class="helper">Resets the baseline level to the new fill; drain rate is retained.</div>
            </div>

            <div class="alert-cfg">
              <div class="alert-cfg-row">
                <span class="lbl"><span class="engrave"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M18 8a6 6 0 1 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.7 21a2 2 0 0 1-3.4 0"/></svg></span>LOW-FUEL ALERTS</span>
                <div class="iotoggle" id="alertToggle" role="switch" aria-checked="true" tabindex="0" aria-label="Low-fuel alerts on or off">
                  <span class="half i">I</span><span class="half o">O</span>
                </div>
              </div>
              <div class="thresh-row">
                <span class="section-label" style="margin:0">THRESHOLD</span>
                <input type="range" class="thresh" id="threshSlider" min="5" max="40" step="1" value="20" aria-label="Low-fuel threshold percent">
                <span class="tval" id="threshVal">20%</span>
              </div>
            </div>
          </div>
        </div>
        <div class="drawer-base"></div>
      </div>

      <!-- Advanced drawer (manual state override) -->
      <div class="drawer adv" id="advDrawer">
        <button type="button" class="drawer-face" aria-expanded="false" aria-controls="advClip">
          <span class="face-left"><span class="engrave"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><line x1="4" y1="7" x2="20" y2="7"/><line x1="4" y1="12" x2="20" y2="12"/><line x1="4" y1="17" x2="20" y2="17"/><circle cx="9" cy="7" r="2.2" fill="currentColor" stroke="none"/><circle cx="15" cy="12" r="2.2" fill="currentColor" stroke="none"/><circle cx="8" cy="17" r="2.2" fill="currentColor" stroke="none"/></svg></span>ADVANCED</span>
          <span class="face-right"><span class="caret">▾</span></span>
        </button>
        <div class="drawer-clip" id="advClip">
          <div class="drawer-cavity">
            <div class="warn-copy">These correct the <strong>tracked</strong> state only — they do <strong>not</strong> crank or stop the engine or touch the relay. Use to re-sync after operating the unit by hand.</div>
            <div class="adv-btns">
              <button type="button" class="btn3d amber" id="markRunBtn"><span class="led amber"></span>MARK AS RUNNING</button>
              <button type="button" class="btn3d steel" id="markStopBtn"><span class="led grey"></span>MARK AS STOPPED</button>
            </div>
          </div>
        </div>
        <div class="drawer-base"></div>
      </div>
    </div>
  </div>

  <!-- Cannot auto-detect note -->
  <div class="note">
    <span class="engrave"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z"/><circle cx="12" cy="12" r="3"/></svg></span>
    <span>This system <strong>cannot auto-detect</strong> the real generator state. Always verify the unit visually and audibly before relying on this readout.</span>
  </div>

  <!-- Footer -->
  <footer>
    <div class="frow">&copy; 2026 <a href="https://neal.tools" target="_blank" rel="noopener">Alex Neal</a> &amp; <a href="https://neal.media" target="_blank" rel="noopener">Chris Neal</a></div>
    <div class="frow">Running <a href="https://github.com/mrchrisneal/generatorpi" target="_blank" rel="noopener">v1.0.0</a> · <a href="https://www.gnu.org/licenses/agpl-3.0.html" target="_blank" rel="noopener">AGPL v3</a></div>
    <a class="btn3d steel" href="https://github.com/mrchrisneal/generatorpi" target="_blank" rel="noopener"><span class="engrave"><svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.6 7.6 0 0 1 2-.27c.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg></span>GITHUB</a>
  </footer>

  <!-- Start confirmation dialog -->
  <div class="confirm-overlay" id="confirmOverlay" role="dialog" aria-modal="true" aria-labelledby="confirmTitle">
    <div class="confirm-card">
      <div class="confirm-badge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="34" height="34"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg></div>
      <h2 id="confirmTitle">START GENERATOR?</h2>
      <p>This <strong>cranks the real engine</strong>. Confirm the area around the unit is clear and it is safe to start.</p>
      <div class="confirm-btns">
        <button type="button" class="btn3d steel" id="confirmCancel">CANCEL</button>
        <button type="button" class="btn3d red" id="confirmStart">CONFIRM START</button>
      </div>
    </div>
  </div>
</main>
""" + HTML_TEMPLATE_SCRIPT

# Final page = head (CSS) + <body> + shell + inline script.
HTML_TEMPLATE = HTML_TEMPLATE_HEAD + """
<body>
""" + HTML_TEMPLATE_BODY + """
</body>
</html>
"""


@app.after_request
def set_security_headers(response):
    """Add security headers to every response."""
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Strict CSP for a fully self-contained page: no external requests at all.
    # default-src 'none' denies everything by default; we then re-allow ONLY inline
    # styles/scripts (the whole UI is inline), same-origin XHR/fetch (connect-src),
    # and data: images (inline SVG needs none, but data: is harmless + future-proof).
    # base-uri/form-action 'none' remove two injection footguns. Matches the design.
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        "base-uri 'none'; "
        "form-action 'none'"
    )
    if CONFIG["SSL_ENABLED"]:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


@app.route('/')
@auth_required
def index():
    """Web UI homepage"""
    with state_lock:
        status = generator_state.copy()
    return render_template_string(HTML_TEMPLATE, status=status)

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
    log.info(f"State manually set to {'RUNNING' if running else 'STOPPED'} by {caller_identity()}")
    return jsonify({"success": True, "running": running})

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
        }
    snap["server_now"] = time.time()
    return jsonify(snap)


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
    # enabled: accept a real bool or the common string/int forms; None if absent.
    enabled = None
    if "enabled" in data:
        raw = data["enabled"]
        if isinstance(raw, str):
            enabled = raw.strip().lower() in ("true", "1", "yes", "on")
        else:
            enabled = bool(raw)
    # threshold: optional numeric; reject a present-but-garbage value.
    threshold = None
    if "threshold" in data:
        tval, terr = _json_number(data, "threshold")
        if terr:
            return jsonify({"success": False, "message": terr}), 400
        threshold = tval
    snap = set_alerts(enabled=enabled, threshold=threshold)
    log.info(
        f"Alerts set on={snap['alerts_on']} threshold={snap['alert_threshold']}% "
        f"by {caller_identity()}"
    )
    return jsonify({"success": True, "alerts": snap})

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
    log.info("=" * 60)

    try:
        app.run(
            host=CONFIG["HOST"],
            port=CONFIG["PORT"],
            ssl_context=ssl_context,
            debug=False,
        )
    except KeyboardInterrupt:
        log.info("Shutting down...")
    finally:
        relay_start_stop.close()
        log.info("Shutdown complete")

if __name__ == '__main__':
    main()
