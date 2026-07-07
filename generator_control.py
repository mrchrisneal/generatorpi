# generator_control.py -- Remote start/stop controller for a Powermate PM9400E
# generator via a Raspberry Pi GPIO relay, exposing a self-contained Flask web UI +
# REST API. Single-file by design so it deploys and runs light on a Pi. Handles auth
# (API key + Basic Auth), a durable event log + fuel/runtime state (SQLite), the
# relay start/stop sequence, and the inline HTML/CSS/JS control panel.
#
# Copyright (C) 2026 Chris Neal <https://neal.media> and Alex Neal <https://neal.tools>
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
import collections
import subprocess
import hmac
import json
import math
import ipaddress
import secrets
import socket
import sqlite3
from functools import wraps
from urllib.parse import urlparse
from flask import Flask, render_template_string, jsonify, request, Response, g
from datetime import datetime
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash

# Web Push is OPTIONAL: the controller must still run on a Pi that doesn't have
# pywebpush installed (push simply becomes unavailable server-side). Import is guarded
# so a missing dependency degrades gracefully instead of crashing at startup.
try:
    from pywebpush import webpush, WebPushException
    from py_vapid import Vapid
    from py_vapid.utils import b64urlencode as _vapid_b64
    from cryptography.hazmat.primitives import serialization as _crypto_serialization
    _PUSH_AVAILABLE = True
except Exception:  # ImportError, or a partially-installed crypto stack
    _PUSH_AVAILABLE = False

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
    "SSL_RENEW_DAYS": 30,              # Regenerate cert when fewer than this many days remain (auto mode only)
    "SSL_CERT_MODE": "auto",           # "auto" = self-signed, auto-provision + auto-renew; "manual" = use the provided cert/key, never generate or overwrite
    "SSL_CERT_FILE": "ssl_cert.pem",   # Certificate path (relative to the script dir, or absolute)
    "SSL_KEY_FILE": "ssl_key.pem",     # Private key path (relative to the script dir, or absolute)
    "SSL_SAN": "",                     # Extra SubjectAltName entries for the SELF-SIGNED cert, comma-separated, e.g. "DNS:gen.home,IP:192.168.1.50"
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
    # Web Push (VAPID). Keys are auto-generated into the settings file on first startup
    # when push is available and they're empty (like API_KEY). Private key is secret.
    "VAPID_PUBLIC_KEY": "",             # base64url uncompressed point -- the browser's applicationServerKey (non-secret)
    "VAPID_PRIVATE_KEY": "",            # base64url 32-byte EC private scalar (SECRET)
    "VAPID_SUBJECT": "mailto:admin@localhost",  # VAPID 'sub' claim sent to push services
    # Hard cap on stored push subscriptions. Unlike the event log this table had no
    # bound, so an authenticated caller (or a browser re-subscribing under churning
    # endpoints) could grow it without limit. 100 is far more than the handful of
    # devices a home controller ever serves; the oldest rows are evicted past this.
    "SUBSCRIPTION_MAX": 100,
    # How often (seconds) the background monitor re-checks the fuel projection to fire a
    # low-fuel push. Cheap; low fuel develops over many minutes of runtime.
    "FUEL_MONITOR_SECONDS": 60,
    # SYSTEM perf-history sampler (in-memory only, zero disk writes). How often to
    # sample host metrics into the ring buffer, and how many points to retain.
    "SYSTEM_HISTORY_SECONDS": 15,   # sample cadence; clamped to >= 5s at use
    "SYSTEM_HISTORY_POINTS": 240,   # ring-buffer capacity (~1 hour at 15s)
    # SYSTEM sensor selection. Empty = auto-detect the best sensor in Python; set a
    # value in the env file to force a specific one (useful when auto-detect guesses
    # wrong on unusual hardware).
    "SYSTEM_TEMP_PATH": "",         # thermal-zone temp file; "" = auto-pick the CPU zone
    "SYSTEM_WIFI_IFACE": "",        # wireless iface for RSSI (e.g. wlan0); "" = first found
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

    # Auto-provision a VAPID keypair for Web Push, same pattern as the API key: when
    # push support is installed and no private key is set yet, generate a keypair and
    # persist it here. If pywebpush/crypto isn't installed, this is skipped entirely and
    # push stays unavailable (the app still runs fine).
    if _PUSH_AVAILABLE and not CONFIG["VAPID_PRIVATE_KEY"]:
        try:
            v = Vapid()
            v.generate_keys()
            # Store the private key as the raw 32-byte scalar (base64url) and the public
            # key as the uncompressed EC point (base64url) -- the latter is exactly the
            # applicationServerKey the browser needs. Both are single-line, env-safe.
            priv_b64 = _vapid_b64(
                v.private_key.private_numbers().private_value.to_bytes(32, "big")
            )
            pub_b64 = _vapid_b64(
                v.public_key.public_bytes(
                    _crypto_serialization.Encoding.X962,
                    _crypto_serialization.PublicFormat.UncompressedPoint,
                )
            )
            CONFIG["VAPID_PRIVATE_KEY"] = priv_b64
            CONFIG["VAPID_PUBLIC_KEY"] = pub_b64

            def _upsert(lines, key, value):
                # Replace an existing "key=" line in place, else append a new one.
                for i, ex in enumerate(lines):
                    if ex.split("=", 1)[0].strip() == key:
                        lines[i] = f"{key}={value}"
                        return
                lines.append(f"{key}={value}")

            have_any = any(
                ln.split("=", 1)[0].strip() in ("VAPID_PRIVATE_KEY", "VAPID_PUBLIC_KEY")
                for ln in new_lines
            )
            if not have_any:
                # Fresh file: append a documented block so operators understand rotation.
                new_lines.append("")
                new_lines.append("# Web Push (VAPID) keys -- auto-generated on startup.")
                new_lines.append("# VAPID_PRIVATE_KEY is SECRET. To rotate: clear both")
                new_lines.append("# values (or delete both lines) and restart -- a fresh")
                new_lines.append("# keypair is generated + written here. Rotation forces")
                new_lines.append("# browsers to re-subscribe (handled automatically).")
                new_lines.append(f"VAPID_PUBLIC_KEY={pub_b64}")
                new_lines.append(f"VAPID_PRIVATE_KEY={priv_b64}")
            else:
                _upsert(new_lines, "VAPID_PUBLIC_KEY", pub_b64)
                _upsert(new_lines, "VAPID_PRIVATE_KEY", priv_b64)
            needs_rewrite = True
            print("Generated a VAPID keypair for Web Push and wrote it to the settings file")
        except Exception as e:
            print(f"WARNING: could not generate VAPID keys ({e}); Web Push disabled")

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
        # Web Push subscriptions (one row per subscribed browser+device). endpoint is
        # unique and is the pushService URL; p256dh/auth are the client keys needed to
        # encrypt payloads. Dead subscriptions are pruned on a 404/410 from send_push.
        _event_conn.execute(
            "CREATE TABLE IF NOT EXISTS subscriptions ("
            "endpoint TEXT PRIMARY KEY, "
            "p256dh TEXT NOT NULL, "
            "auth TEXT NOT NULL, "
            "created_ts REAL NOT NULL)"
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


def add_subscription(endpoint, p256dh, auth):
    """Store (or refresh) a browser push subscription. Never raises into its caller."""
    try:
        with _event_lock:
            if _event_conn is None:
                return
            _event_conn.execute(
                "INSERT INTO subscriptions (endpoint, p256dh, auth, created_ts) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(endpoint) DO UPDATE SET "
                "p256dh = excluded.p256dh, auth = excluded.auth",
                (endpoint, p256dh, auth, time.time()),
            )
            # Cap the table like the event log: keep only the newest SUBSCRIPTION_MAX
            # rows (by created_ts) and evict any older ones. Prevents an authenticated
            # caller -- or a browser re-subscribing under many churning endpoints --
            # from growing this table without bound. Done under the same _event_lock.
            max_subs = CONFIG["SUBSCRIPTION_MAX"]
            _event_conn.execute(
                "DELETE FROM subscriptions WHERE endpoint NOT IN ("
                "SELECT endpoint FROM subscriptions ORDER BY created_ts DESC LIMIT ?)",
                (max_subs,),
            )
            _event_conn.commit()
    except Exception as e:
        log.warning(f"Failed to store push subscription: {e}")


def remove_subscription(endpoint):
    """Delete a push subscription by endpoint. Never raises into its caller."""
    try:
        with _event_lock:
            if _event_conn is None:
                return
            _event_conn.execute("DELETE FROM subscriptions WHERE endpoint = ?", (endpoint,))
            _event_conn.commit()
    except Exception as e:
        log.warning(f"Failed to remove push subscription: {e}")


def get_subscriptions():
    """Return all push subscriptions as pywebpush-shaped dicts. Never raises."""
    try:
        with _event_lock:
            if _event_conn is None:
                return []
            rows = _event_conn.execute(
                "SELECT endpoint, p256dh, auth FROM subscriptions"
            ).fetchall()
        return [
            {"endpoint": r[0], "keys": {"p256dh": r[1], "auth": r[2]}}
            for r in rows
        ]
    except Exception as e:
        log.warning(f"Failed to read push subscriptions: {e}")
        return []


def subscription_count():
    """Return the number of stored push subscriptions (0 on any error)."""
    try:
        with _event_lock:
            if _event_conn is None:
                return 0
            row = _event_conn.execute("SELECT COUNT(*) FROM subscriptions").fetchone()
        return row[0] if row else 0
    except Exception:
        return 0


def push_available():
    """True when Web Push can actually be sent: the library is importable AND a VAPID
    private key is configured. Used by the UI + guards on the send path."""
    return bool(_PUSH_AVAILABLE and CONFIG.get("VAPID_PRIVATE_KEY"))


def send_push(title, body, tag=None):
    """Send a Web Push notification to every subscribed browser.

    MUST NOT raise into its caller (it is fired from state-transition paths + a
    monitor thread). No-ops when push is unavailable or there are no subscriptions.
    A 404/410 from a push service means the subscription is dead -> prune it.
    """
    if not push_available():
        return
    subs = get_subscriptions()
    if not subs:
        return
    payload = json.dumps({"title": title, "body": body, "tag": tag or "generatorpi"})
    subject = CONFIG.get("VAPID_SUBJECT") or "mailto:admin@localhost"
    try:
        # One Vapid instance signs a fresh JWT (with the correct per-endpoint audience)
        # on every webpush() call, so it's safe to build once and reuse across sends.
        vapid = Vapid.from_raw(CONFIG["VAPID_PRIVATE_KEY"].encode("utf-8"))
    except Exception as e:
        log.warning(f"Invalid VAPID key, cannot send push: {e}")
        return
    for sub in subs:
        try:
            # pywebpush MUTATES vapid_claims (adds aud/exp), so pass a FRESH dict each call.
            # timeout=(connect, read): a black-hole or slow push endpoint must not hang
            # the daemon send thread forever -- bound both the connect and read phases so
            # a stuck service fails fast and we move on to the next subscription.
            webpush(
                subscription_info=sub,
                data=payload,
                vapid_private_key=vapid,
                vapid_claims={"sub": subject},
                timeout=(5, 10),
            )
        except WebPushException as e:
            status = getattr(getattr(e, "response", None), "status_code", None)
            if status in (404, 410):
                log.info(f"Pruning dead push subscription ({status})")
                remove_subscription(sub["endpoint"])
            else:
                log.warning(f"Web push failed (status={status}): {e}")
        except Exception as e:
            log.warning(f"Web push error: {e}")


def send_push_async(title, body, tag=None):
    """Fire-and-forget send_push on a daemon thread so a slow/blocked push to N devices
    never stalls a request handler or the relay control path."""
    if not push_available():
        return
    threading.Thread(
        target=send_push, args=(title, body, tag), daemon=True
    ).start()


# Bring the store up now that logging is live. This also records the startup event.
init_event_store()

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
    base = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
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
# fuel_enabled gates the ENTIRE fuel-projection feature (drawer + monitor + banner);
# default on. alerts_on gates only the low-fuel alerting within it.
alerts_state = {
    "alerts_on": True,
    "alert_threshold": 20,
    "fuel_enabled": True,
}

# Edge-trigger flag for the low-fuel push: True once we've alerted for the current
# below-threshold crossing, cleared when we climb back above threshold+hysteresis, on
# refuel, or when stopped -- so a single crossing fires exactly one push, not a stream.
# In-memory only: a server restart resets running->False, which re-arms it naturally.
_low_fuel_alerted = False
# Lets the background fuel monitor thread be stopped cleanly on shutdown.
_monitor_stop = threading.Event()


def load_persisted_state():
    """Restore durable state (total run-hours, fuel model, alerts) from the kv store
    at startup. Missing keys keep the in-memory defaults above (first boot)."""
    with state_lock:
        # total_run_hours is the lifetime odometer -- the one piece of durable state
        # we must never lose silently. kv_get returns the JSON-decoded value, which is
        # normally a number but could be a non-numeric JSON value (e.g. a hand-edited
        # events.db holding the string "abc"). float() on that raises ValueError/
        # TypeError and would crash the whole controller at startup. Guard the
        # coercion, but do NOT silently fall back to 0: a bad odometer value must be
        # impossible to miss, so we log LOUDLY at CRITICAL and KEEP the in-memory
        # default (whatever total_run_hours already holds) rather than clobber it.
        raw_total = kv_get("total_run_hours", generator_state["total_run_hours"])
        try:
            generator_state["total_run_hours"] = float(raw_total)
        except (TypeError, ValueError):
            log.critical(
                f"Persisted total_run_hours is corrupt ({raw_total!r}); the lifetime "
                f"run-hours total could not be restored -- check events.db. Keeping the "
                f"in-memory default ({generator_state['total_run_hours']})."
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
    return "skip"


# ---------------------------------------------------------------------------
# SYSTEM perf history -- an in-memory ring buffer of cheap host metrics sampled
# on ONE background daemon thread. RAM only: nothing here ever touches the SD
# card. Every reader below fails SOFT (returns None) so a missing source (no
# thermal zone / no vcgencmd / no wlan0 on a dev box) degrades to a null series
# instead of crashing the sampler.
# ---------------------------------------------------------------------------

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
<title>GeneratorPi</title>
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="dark">
<!-- Empty inline icon: suppresses the browser's default /favicon.ico request (which
     would 404 -- static serving is disabled) without any external asset. -->
<link rel="icon" href="data:,">
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
.section-label{font:600 12px var(--mono);letter-spacing:.16em;color:#969085;margin-bottom:8px}

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
.ann-label{font:600 12px var(--mono);letter-spacing:.24em;color:#9a9488}
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

/* ---- hero rocker switch -- CSS adapted from Uiverse.io "empty-snail-69" by Nawsome
   (MIT, (c) 2026 Nawsome; see THIRD-PARTY-NOTICES.md), keyboard-accessible variant ---- */
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
/* Tenths wheel is INVERTED like a real trip odometer: a dark cylinder drum with a
   light digit, instead of the ivory drum + dark digit of the integer wheels. */
.wheel-tenths{background:linear-gradient(180deg,#050506 0%,#26262b 24%,#3a3a42 50%,#26262b 76%,#050506 100%)}
.wheel-tenths .cell{color:#fffef9}
.odo-dot{font:800 34px var(--mono);color:#9f9f9f;align-self:flex-end;margin:0 -3px -1px}

/* ---- system registers ---- */
/* Always a 2x2 grid (4 registers) at every width -- not auto-fit, which flowed 3+1. */
.registers{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.reg{position:relative;overflow:hidden;padding:12px 14px;border-radius:8px;
  background:radial-gradient(120% 130% at 50% -10%,#0d1210,#050806 75%);box-shadow:inset 0 2px 8px rgba(0,0,0,.75)}
.reg::after{content:"";position:absolute;inset:0;pointer-events:none;
  background:repeating-linear-gradient(0deg,rgba(0,0,0,.22) 0 1px,transparent 1px 3px);mix-blend-mode:multiply}
.reg-label{font:600 12px var(--mono);letter-spacing:.08em;color:#4f7d64;margin-bottom:6px}
.reg-value{font:700 17px var(--mono);color:#6fe6a0;text-shadow:0 0 7px rgba(80,224,140,.4);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

/* ---- event log (VFD) ---- */
.log-head{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:8px}
.log-count{font:600 12px var(--mono);letter-spacing:.1em;color:#6c675f}
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

/* ---- drawers (shared) ---- */
.drawer{border-radius:11px;overflow:hidden;background:linear-gradient(180deg,#141416,#0b0b0d);border:1px solid #000}
.drawer.fuel{--tint:#0e1416}.drawer.adv{--tint:#160f0e}
.drawer-face{display:flex;align-items:center;justify-content:space-between;gap:12px;
  min-height:54px;padding:0 16px;cursor:pointer;border:0;width:100%;text-align:left;color:#d7d3cc;
  background:linear-gradient(180deg,#2a2a2f 0%,#1e1e23 52%,#18181c 100%);
  box-shadow:inset 0 1px 0 rgba(255,255,255,.11),inset 0 -2px 5px rgba(0,0,0,.55),0 3px 6px rgba(0,0,0,.45)}
/* No hover effect on the drawer face -- the brightness change read as inconsistent
   with the static darkened face. A subtle press dim is kept for tactile feedback. */
.drawer-face:active{filter:brightness(.92)}
.drawer-face:focus-visible{outline:3px solid #ffca7a;outline-offset:-3px}
.face-left{display:flex;align-items:center;gap:10px;font:700 12px sans-serif;letter-spacing:.14em}
.face-right{display:flex;align-items:center;gap:10px;font:700 13px var(--mono)}
.caret{transition:transform .35s;font-size:14px;color:#9b9689}
.drawer.open .caret{transform:rotate(180deg)}
.drawer-clip{overflow:hidden;max-height:0;transition:max-height .45s cubic-bezier(.4,0,.2,1)}
.drawer-cavity{padding:16px;display:flex;flex-direction:column;gap:14px;
  background:linear-gradient(180deg,#0a0a0c,#0d0d10);
  box-shadow:inset 0 13px 16px -11px rgba(0,0,0,.95),inset 7px 0 10px -8px rgba(0,0,0,.9),inset -7px 0 10px -8px rgba(0,0,0,.9),inset 0 -9px 12px -8px rgba(0,0,0,.9)}
/* caution-tape footer: diagonal hazard stripes painted onto the curved metal -- a
   translucent vertical sheen (light top -> dark bottom) sits OVER the stripes so they
   read as part of the brushed-metal base, not a flat sticker. */
.drawer-base{height:5px;
  background:linear-gradient(rgba(0,0,0,.2),rgba(0,0,0,.2)),linear-gradient(90deg,rgba(0,0,0,.9) 0,rgba(0,0,0,0) 7%,rgba(0,0,0,0) 93%,rgba(0,0,0,.9) 100%),linear-gradient(180deg,rgba(255,255,255,.08),rgba(0,0,0,.62)),repeating-linear-gradient(45deg,#b8760c 0 8px,#0c0c0c 8px 16px);
  box-shadow:inset 0 1px 0 rgba(255,255,255,.10),0 2px 4px rgba(0,0,0,.6)}
.engrave{display:inline-flex;filter:drop-shadow(0 1px 0 rgba(255,255,255,.14)) drop-shadow(0 -1px 1px rgba(0,0,0,.5))}
.engrave svg{width:18px;height:18px;display:block}
.warn-copy{font:600 12px var(--mono);color:#e0b090;line-height:1.5}

/* ---- fuel drawer internals ---- */
/* Tank stays on the left with the indicator cards always beside it (nowrap); this row
   is a query container so the card grid can respond to ITS width (container queries
   need an ancestor with container-type -- previously absent, so the grid never
   reflowed and stayed 3-across, clobbering the cards). */
.fuel-top{display:flex;gap:14px;flex-wrap:nowrap;align-items:stretch;container-type:inline-size}
.tank-col{flex:0 0 60px;display:flex;flex-direction:column;align-items:center;gap:6px}
.tank{position:relative;width:52px;flex:1 1 auto;min-height:70px;border-radius:6px;overflow:hidden;
  background:linear-gradient(180deg,#0c0c0e,#050506);box-shadow:inset 0 0 0 2px #000,inset 0 2px 8px rgba(0,0,0,.9)}
.tank-fill{position:absolute;left:0;right:0;bottom:0;height:0%;transition:height .5s ease,background .3s;
  background:linear-gradient(180deg,#ffb347,#7a3a08);box-shadow:0 0 12px rgba(255,150,40,.55)}
.tank.low .tank-fill{background:linear-gradient(180deg,#ff5a4a,#a01810);box-shadow:0 0 12px rgba(255,70,50,.6)}
.tank-line{position:absolute;left:0;right:0;height:3px;background:#ff2a1a;
  box-shadow:0 0 0 1px rgba(0,0,0,.85),0 1px 3px rgba(0,0,0,.9),0 0 7px rgba(255,50,25,.65)}
.tank-label{font:600 12px var(--mono);letter-spacing:.08em;color:#9a9488}
/* Default 2x3 (two columns) -- the clean layout for the mid range that was clobbering.
   3-across only when the row is genuinely roomy (roomy stacked view / desktop), and a
   single column when very narrow so the cards stay legible beside the tank. min-width:0
   lets the grid actually shrink inside the flex row. */
.fuel-grid{flex:1 1 200px;min-width:0;display:grid;grid-template-columns:1fr 1fr;gap:9px}
@container (min-width:480px){.fuel-grid{grid-template-columns:repeat(3,1fr)}}
/* Single column when very narrow -- and shave ~10px off the tank (not half) so the lone
   card column gets a little more width beside it while the tank stays readable. */
@container (max-width:300px){
  .fuel-grid{grid-template-columns:1fr}
  .tank-col{flex:0 0 50px}
  .tank{width:42px}
}
.fcard{padding:10px 12px;border-radius:8px;background:linear-gradient(160deg,#0b1214,#04080a);
  border:1px solid #08161a;box-shadow:inset 0 2px 7px rgba(0,0,0,.7)}
.fcard-label{font:600 12px var(--mono);letter-spacing:.08em;color:#4f7d8a;margin-bottom:5px}
.fcard-value{font:700 16px var(--mono);color:#8fd6e8;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.fuel-io{display:flex;gap:9px;align-items:stretch}
.crt-input{flex:1 1 auto;min-width:0;padding:0 12px;height:48px;border-radius:8px;border:1px solid #000;
  background:radial-gradient(120% 130% at 50% -10%,#0d1210,#050806 75%);
  color:#7ce0b0;font:700 16px var(--mono);text-shadow:0 0 6px rgba(80,224,140,.4);
  box-shadow:inset 0 2px 7px rgba(0,0,0,.75)}
.crt-input::placeholder{color:#3f7d64}
.crt-input:focus{outline:3px solid #ffca7a;outline-offset:2px}
.helper{font:500 12px var(--mono);color:#ada79d;line-height:1.55;margin-top:9px}
/* Centered hairline divider between form rows in the drawers: ~30% width, 1px, faded
   ends, with 10px of margin above and below the line. */
.drawer-divider{width:30%;height:1px;border:0;margin:10px auto;background:linear-gradient(90deg,transparent,rgba(255,255,255,.24),transparent)}
.drawer-cavity > .drawer-divider{margin:10px auto}
.alert-cfg > .drawer-divider{margin:10px auto}
.alert-banner{display:none;align-items:center;gap:10px;padding:11px 14px;border-radius:8px;
  background:linear-gradient(180deg,#2a0f0c,#1a0906);border:1px solid #6a2018;
  font:600 12px var(--mono);color:#ffb0a0}
.alert-banner.show{display:flex}
.alert-dot{width:9px;height:9px;border-radius:50%;background:#ff3a22;box-shadow:0 0 8px 2px rgba(255,60,30,.7);animation:pulse 1s ease-in-out infinite}
.alert-cfg{padding:12px 14px;border-radius:8px;background:linear-gradient(160deg,#0b1214,#04080a);border:1px solid #08161a;display:flex;flex-direction:column;gap:12px;container-type:inline-size}
.alert-cfg-row{display:flex;align-items:center;justify-content:space-between;gap:12px}
.alert-cfg-row .lbl{display:flex;align-items:center;gap:9px;font:700 12px sans-serif;letter-spacing:.1em;color:#9fdcec}
.thresh-row{display:flex;align-items:center;gap:12px}
.thresh-row .tval{font:700 15px var(--mono);color:#ffb347;min-width:44px;text-align:right}
/* When the alert card gets narrow (~440px viewport and below) the label+slider+value
   no longer fit on one line and the slider gets squeezed. Reflow to: slider + value on
   top, the THRESHOLD label centered beneath. */
@container (max-width:280px){
  .thresh-row{flex-wrap:wrap;justify-content:center;row-gap:8px}
  .thresh-row .thresh{order:1;flex:1 1 auto}
  .thresh-row .tval{order:2}
  .thresh-row .section-label{order:3;flex:1 1 100%;text-align:center;margin:0}
}
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
  font:700 12px sans-serif;letter-spacing:.1em;white-space:nowrap;
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
footer .frow{font:500 12px var(--mono);color:#a6a094}
footer a{color:rgba(255,255,255,.9);text-decoration:none}
footer a:hover{text-decoration:underline}

/* ---- start confirm dialog ---- */
/* position:fixed (not absolute) so the overlay + card center in the VIEWPORT, not
   within the tall panel -- otherwise on a long page the modal lands mid-document
   instead of mid-screen. */
.confirm-overlay{position:fixed;inset:0;z-index:20;display:none;align-items:center;justify-content:center;padding:20px;
  background:rgba(6,6,7,.82);backdrop-filter:blur(2px)}
.confirm-overlay.show{display:flex}
.confirm-card{max-width:340px;width:100%;padding:22px;border-radius:12px;text-align:center;
  background:linear-gradient(160deg,#2a1a14,#1a1210);border:1px solid #6a3a1a;box-shadow:0 20px 50px rgba(0,0,0,.7)}
.confirm-badge{display:inline-flex;margin-bottom:12px;color:#ffb347}
.confirm-card h2{font:800 18px sans-serif;letter-spacing:.08em;color:#ffcf8a;margin-bottom:10px}
.confirm-card p{font:600 13px var(--mono);color:#e0b090;line-height:1.6;margin-bottom:18px}
.confirm-btns{display:flex;gap:12px}.confirm-btns .btn3d{flex:1 1 0}
/* In the confirm dialog, drop the raised "0 4px 0 var(--b)" ledge so CANCEL and START
   sit LEVEL with each other -- otherwise the red button's lighter base color reads as
   raised while the steel button's near-black base is invisible on the dark card. Both
   keep a soft shadow + press feedback, just no mismatched ledge. */
.confirm-btns .btn3d{box-shadow:0 3px 8px rgba(0,0,0,.55),0 0 0 2px rgba(0,0,0,.6),inset 0 1px 0 rgba(255,255,255,.2)}
.confirm-btns .btn3d:hover{transform:translateY(-1px);box-shadow:0 5px 10px rgba(0,0,0,.55),0 0 0 2px rgba(0,0,0,.6),inset 0 1px 0 rgba(255,255,255,.2)}
.confirm-btns .btn3d:active{transform:translateY(1px);box-shadow:0 1px 3px rgba(0,0,0,.6),0 0 0 2px rgba(0,0,0,.6),inset 0 2px 4px rgba(0,0,0,.4)}

.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);border:0}

/* ---- SYSTEM drawer + CRT charts (uniform 13px text, matching the event log .evt) ---- */
.drawer.sys{--tint:#0d1418}
.sys-hdr{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:6px}
.sys-temp-big{font:700 13px/1 var(--mono,monospace);letter-spacing:.5px}
.sys-temp-big.ok{color:#7ce0b0}.sys-temp-big.warn{color:#ffb347}.sys-temp-big.hot{color:#ff8a6a}
.sys-chip{font:600 13px/1 var(--mono,monospace);padding:5px 9px;border-radius:7px;border:1px solid #000;letter-spacing:.6px}
.sys-chip.clean{color:#7ce0b0;background:#0e1a14}
.sys-chip.thr{color:#ffb347;background:#1a1509}
.sys-chip.uv{color:#ff8a6a;background:#1c0f0d}
.sys-panel{border-radius:9px;overflow:hidden;background:linear-gradient(180deg,#0b1113,#070b0d);border:1px solid #000;margin-bottom:12px}
.sys-panel-face{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:9px 12px;cursor:pointer;user-select:none}
.sys-panel-title{font:700 13px/1 var(--mono,monospace);letter-spacing:1.2px;color:#9fb3ad}
.sys-legend{display:flex;gap:12px;align-items:center}
.sys-leg{display:flex;gap:5px;align-items:center;font:600 13px/1 var(--mono,monospace);letter-spacing:.5px;color:#8aa;cursor:pointer}
.sys-leg .sw{width:12px;height:3px;border-radius:2px;box-shadow:0 0 5px currentColor}
.sys-leg.off{opacity:.32;text-decoration:line-through}
.sys-eye{background:none;border:0;color:#6a8;cursor:pointer;font:600 13px/1 var(--mono,monospace);padding:2px 4px}
.sys-panel.collapsed .sys-panel-body{display:none}
.sys-panel-body{padding:0 10px 6px}
.sys-screen{position:relative;height:200px;border-radius:6px;overflow:hidden;background:radial-gradient(120% 100% at 50% 0%,#0c1a16,#060b0a);border:1px solid #10201b;box-shadow:inset 0 0 22px rgba(0,0,0,.7)}
.sys-screen::after{content:"";position:absolute;inset:0;pointer-events:none;background:repeating-linear-gradient(0deg,rgba(0,0,0,0) 0 2px,rgba(0,0,0,.16) 2px 3px)}
.sysgraph{position:absolute;inset:0;width:100%;height:100%}
.sysgraph .grid{stroke:rgba(120,220,180,.10);stroke-width:.5}
.sysgraph .refline{stroke:rgba(255,179,71,.35);stroke-width:.7;stroke-dasharray:3 3}
.sysgraph .band{fill:rgba(255,80,60,.16)}
.sysgraph polyline{fill:none;stroke-width:1.4;vector-effect:non-scaling-stroke;filter:drop-shadow(0 0 3px currentColor)}
.sysgraph .cross{stroke:rgba(255,255,255,.45);stroke-width:.6}
.sysgraph .dot{r:2.4;filter:drop-shadow(0 0 4px currentColor)}
/* y-axis corner labels as crisp HTML (SVG text would distort under non-uniform scale) */
.sys-ax{position:absolute;font:600 13px/1 var(--mono,monospace);color:#7f9;opacity:.85;pointer-events:none;text-shadow:0 0 4px rgba(0,0,0,.9)}
.sys-ax.tl{top:4px;left:5px}.sys-ax.bl{bottom:4px;left:5px}
.sys-ax.tr{top:4px;right:5px;color:#6fd3e0}.sys-ax.br{bottom:4px;right:5px;color:#6fd3e0}
.sys-strip{display:flex;justify-content:space-between;align-items:baseline;gap:10px;margin-top:7px;padding:6px 9px;border-radius:5px;background:#060d0b;border:1px solid #10201b;font:600 13px/1.3 var(--mono,monospace);letter-spacing:.4px;min-height:15px}
.sys-strip .t{color:#6f8f7e;white-space:nowrap;flex:0 0 auto}
.sys-strip .v{display:flex;gap:14px;flex:1 1 auto;justify-content:flex-end;flex-wrap:wrap}
.sys-strip .v span{text-shadow:0 0 6px currentColor}
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
/* Build request URLs from location.origin (which never includes userinfo) rather
   than a bare relative path: if the page was opened via a credentials-in-URL
   bookmark (http://user:pass@host/), a relative fetch would resolve against that
   document URL and the Fetch API rejects constructing a Request from a URL that
   embeds credentials. location.origin strips them, so fetch works either way. */
function api(path,opts){return fetch(location.origin+path,opts||{}).then(function(r){return r.json().catch(function(){return {};});});}
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
var odoReels=[];var ODO_CELL=46;
function buildOdometer(){var odo=$('odometer');odo.innerHTML='';
  // Each wheel is a .reel of 11 .cells (0..9 then a DUPLICATE 0 at index 10).
  // The 11th cell is the seamless-wrap landing pad: on a 9->0 rollover we roll
  // FORWARD onto it, then invisibly snap back to the real 0 -- never backward.
  function wheel(cls,dur){var w=document.createElement('div');w.className='wheel '+cls;var reel=document.createElement('div');reel.className='reel';for(var i=0;i<=10;i++){var c=document.createElement('div');c.className='cell';c.textContent=i%10;reel.appendChild(c);}w.appendChild(reel);odo.appendChild(w);
    // Per-reel animation state: pos = current -translateY() magnitude in px;
    // dur = this wheel's CSS transition duration (ms, must match the stylesheet);
    // wrapping = true while a rollover roll+snap is in flight (re-entrancy guard);
    // pending = latest requested target px queued while that wrap runs.
    return {el:reel,pos:0,dur:dur,wrapping:false,pending:null};}
  odoReels=[];for(var i=0;i<4;i++)odoReels.push(wheel('wheel-int',700));
  var dot=document.createElement('span');dot.className='odo-dot';dot.textContent='.';odo.appendChild(dot);
  odoReels.push(wheel('wheel-tenths',1000));}
// Move one reel toward a target px magnitude. total_run_hours only ever INCREASES
// within a session, so a target that is LOWER than the current position is always a
// wrap-past-9-to-0, never a real decrease -- handle it as a forward roll, not a
// backward spin.
function setReel(r,target){
  // A wrap animation is already running for this reel: don't disturb it -- just
  // record the newest target so the snap step lands on the latest value.
  if(r.wrapping){r.pending=target;return;}
  if(target>=r.pos){
    // Forward (or no) motion: the reel climbs up the strip; the CSS transition
    // animates it normally. Record the new resting position.
    r.pos=target;r.el.style.transform='translateY(-'+target+'px)';return;}
  // WRAP: target moved back toward 0. Roll FORWARD onto the duplicate 0 (11th cell
  // at 10*ODO_CELL) using the wheel's normal transition, so it reads 9 -> 0 upward.
  r.wrapping=true;r.pending=target;
  r.el.style.transform='translateY(-'+(10*ODO_CELL)+'px)';
  // After that roll finishes, snap (no animation) to the equivalent low position so
  // the next real forward move continues cleanly. Timer matched to the wheel's
  // transition duration (+ small buffer to guarantee the roll has landed).
  setTimeout(function(){
    var t=(r.pending==null?target:r.pending); // apply the freshest queued value
    r.el.style.transition='none';
    r.el.style.transform='translateY(-'+t+'px)';
    void r.el.offsetHeight;                    // force reflow so the snap commits
    r.el.style.transition='';                  // restore the stylesheet transition
    r.pos=t;r.wrapping=false;r.pending=null;
  },r.dur+40);
}
function updateOdometer(hours){var intPart=Math.min(9999,Math.floor(hours));var ds=('0000'+intPart).slice(-4);for(var i=0;i<4;i++){setReel(odoReels[i],parseInt(ds.charAt(i),10)*ODO_CELL);}var frac=hours-Math.floor(hours);setReel(odoReels[4],frac*10*ODO_CELL);}

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
  // Fuel feature enable/disable: hide the whole Fuel drawer + reflect the toggle.
  var fEnabled=s.fuel_enabled!==false;
  $('fuelDrawer').style.display=fEnabled?'':'none';
  setTog('fuelToggle',fEnabled);
  // Web push server state (vapid key + whether the server can send).
  pushApplyState(s.push||{});
  tick();
}
function setTog(id,on){$(id).setAttribute('aria-checked',on?'true':'false');}
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
function settle(target){var n=0;(function step(){setTimeout(function(){fetchState(function(s){if(s)applyState(s);if((s&&s.running===target)||++n>20){busy=false;sw.disabled=false;if(s)applyState(s);loadNewEvents();}else step();});},600);})();}
var sw=$('powerSwitch');
var confirmOverlayEl=$('confirmOverlay');
/* Element focused before the dialog opened (normally #powerSwitch) so we can
   restore focus to it on close for keyboard/AT users. */
var confirmPrevFocus=null;
/* Toggle the `inert` attribute on the two regions that hold every background
   control (.body + footer). inert makes them non-interactive AND hides them from
   assistive tech while the modal is up. We deliberately do NOT inert #panel or
   #confirmOverlay: the overlay is a CHILD of #panel and must stay interactive. */
function setBackgroundInert(on){
  var body=panel.querySelector('.body'),foot=panel.querySelector('footer');
  if(body){if(on){body.setAttribute('inert','');}else{body.removeAttribute('inert');}}
  if(foot){if(on){foot.setAttribute('inert','');}else{foot.removeAttribute('inert');}}
}
function openConfirm(){
  confirmOpen=true;
  confirmPrevFocus=document.activeElement;           /* remember where focus was */
  confirmOverlayEl.className='confirm-overlay show';  /* keep existing show class */
  setBackgroundInert(true);                           /* trap: bg non-interactive */
  $('confirmStart').focus();                          /* move focus into the dialog */
}
sw.addEventListener('change',function(){if(sw.checked){openConfirm();}else{doStop();}});
function closeConfirm(revert){
  confirmOpen=false;
  confirmOverlayEl.className='confirm-overlay';
  setBackgroundInert(false);                          /* restore bg BEFORE focusing */
  if(revert){sw.checked=false;}
  /* Restore focus to the pre-open element, falling back to the power switch. */
  var restore=confirmPrevFocus||$('powerSwitch');
  confirmPrevFocus=null;
  if(restore&&typeof restore.focus==='function'){restore.focus();}
}
$('confirmCancel').addEventListener('click',function(){closeConfirm(true);});
$('confirmStart').addEventListener('click',function(){closeConfirm(false);doStart();});
/* Escape cancels the dialog (reverting the switch) while it is open. */
document.addEventListener('keydown',function(e){if(confirmOpen&&(e.key==='Escape'||e.key==='Esc')){e.preventDefault();closeConfirm(true);}});
/* Backdrop click cancels — only when the click lands on the overlay itself,
   not on anything inside the confirm card. */
confirmOverlayEl.addEventListener('click',function(e){if(e.target===confirmOverlayEl){closeConfirm(true);}});
/* Disable the switch for the whole in-flight start/stop so a mid-settle flip
   can't kick off a second concurrent settle() loop. Re-enabled wherever busy is
   cleared (settle completion + every failure/reject path). */
function doStart(){busy=true;sw.disabled=true;post('/api/start').then(function(d){if(d&&d.success===false){busy=false;sw.disabled=false;sw.checked=false;refresh();}else{settle(true);}}).catch(function(){busy=false;sw.disabled=false;sw.checked=false;refresh();});}
/* /api/stop returns {success:false} when the relay is busy with an in-progress
   start; honor it (like doStart) instead of settling to OFF and flipping back. */
function doStop(){busy=true;sw.disabled=true;sw.checked=false;post('/api/stop').then(function(d){if(d&&d.success===false){busy=false;sw.disabled=false;refresh();return;}settle(false);}).catch(function(){busy=false;sw.disabled=false;refresh();});}
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

/* ---------- fuel feature toggle ---------- */
function toggleFuel(){var on=$('fuelToggle').getAttribute('aria-checked')==='true';post('/api/alerts',{fuel_enabled:!on}).then(refresh);}
$('fuelToggle').addEventListener('click',toggleFuel);
$('fuelToggle').addEventListener('keydown',function(e){if(e.key===' '||e.key==='Enter'){e.preventDefault();toggleFuel();}});

/* ---------- web push ---------- */
/* Requires a service worker + PushManager + a SECURE CONTEXT. On a self-signed cert the
   origin may not be secure until the client trusts it, so this degrades gracefully:
   the toggle shows an "unavailable" helper and the in-page banner still covers alerts. */
var swReg=null;
var pushSupported=('serviceWorker' in navigator)&&('PushManager' in window)&&('Notification' in window)&&(window.isSecureContext===true);
var serverPush={supported:false,vapidKey:''};
function setPushHelp(t){$('pushHelp').textContent=t;}
function urlB64ToUint8(base64){
  var pad='='.repeat((4-base64.length%4)%4);
  var b64=(base64+pad).replace(/-/g,'+').replace(/_/g,'/');
  var raw=atob(b64),out=new Uint8Array(raw.length);
  for(var i=0;i<raw.length;i++)out[i]=raw.charCodeAt(i);
  return out;
}
function pushApplyState(p){serverPush.supported=!!p.supported;serverPush.vapidKey=p.vapid_public_key||'';refreshPushUI();}
function refreshPushUI(){
  var testBtn=$('testPushBtn');
  if(!pushSupported){setTog('pushToggle',false);setPushHelp('Push unavailable on this browser/origin \\u2014 using in-page alerts.');testBtn.disabled=true;return;}
  if(!serverPush.supported){setTog('pushToggle',false);setPushHelp('Push not configured on the server \\u2014 using in-page alerts.');testBtn.disabled=true;return;}
  if(Notification.permission==='denied'){setTog('pushToggle',false);setPushHelp('Notifications are blocked in browser settings. Allow them to enable push.');testBtn.disabled=true;return;}
  if(swReg){
    swReg.pushManager.getSubscription().then(function(sub){
      var on=!!sub;setTog('pushToggle',on);
      setPushHelp(on?'Push enabled on this device.':'Push available \\u2014 flip to enable on this device.');
      testBtn.disabled=!on;
    }).catch(function(){setTog('pushToggle',false);setPushHelp('Push state unavailable \\u2014 using in-page alerts.');testBtn.disabled=true;});
  }else{setTog('pushToggle',false);setPushHelp('Push available \\u2014 flip to enable on this device.');testBtn.disabled=true;}
}
function registerSW(){
  if(!pushSupported){refreshPushUI();return;}
  navigator.serviceWorker.register('/sw.js').then(function(reg){
    swReg=reg;
    /* If this browser already has a subscription from a prior visit, make sure the
       SERVER has it too -- the browser's local subscription and the server's stored
       record can drift (server db reset, subscription pruned, different instance).
       This idempotent upsert re-syncs it so the test button + pushes actually work. */
    reg.pushManager.getSubscription().then(function(sub){if(sub){post('/api/push/subscribe',sub.toJSON());}}).catch(function(){setTog('pushToggle',false);setPushHelp('Push state unavailable \\u2014 using in-page alerts.');});
    refreshPushUI();
  }).catch(function(){pushSupported=false;refreshPushUI();});
}
function enablePush(){
  if(!pushSupported||!serverPush.supported||!serverPush.vapidKey||!swReg)return;
  /* Promise.resolve() tolerates BOTH a returned promise (modern) and undefined
     (legacy callback-only requestPermission that would otherwise throw on .then). */
  Promise.resolve(Notification.requestPermission()).then(function(perm){
    if(perm!=='granted'){refreshPushUI();return;}
    swReg.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:urlB64ToUint8(serverPush.vapidKey)})
      .then(function(sub){post('/api/push/subscribe',sub.toJSON()).then(function(){refreshPushUI();refresh();});})
      .catch(function(){setPushHelp('Could not subscribe (is the cert trusted?). In-page alerts still work.');});
  });
}
function disablePush(){
  if(!swReg){refreshPushUI();return;}
  swReg.pushManager.getSubscription().then(function(sub){
    if(!sub){refreshPushUI();return;}
    var ep=sub.endpoint;
    /* Catch an out-of-band unsubscribe rejection so it doesn't become an
       unhandled rejection or leave the toggle stale. */
    sub.unsubscribe().then(function(){post('/api/push/unsubscribe',{endpoint:ep}).then(function(){refreshPushUI();refresh();});}).catch(function(){setTog('pushToggle',false);setPushHelp('Push state unavailable \\u2014 using in-page alerts.');});
  }).catch(function(){setTog('pushToggle',false);setPushHelp('Push state unavailable \\u2014 using in-page alerts.');});
}
function togglePush(){var on=$('pushToggle').getAttribute('aria-checked')==='true';if(on)disablePush();else enablePush();}
$('pushToggle').addEventListener('click',togglePush);
$('pushToggle').addEventListener('keydown',function(e){if(e.key===' '||e.key==='Enter'){e.preventDefault();togglePush();}});
$('testPushBtn').addEventListener('click',function(){post('/api/push/test').then(function(d){setPushHelp((d&&d.success)?'Test sent \\u2014 check your notifications.':((d&&d.message)||'Test failed.'));});});

/* ---------- SYSTEM charts (hand-rolled inline SVG, no libs) ---------- */
var SYS=(function(){
  var SVGNS="http://www.w3.org/2000/svg";
  var W=300,H=100;                 // viewBox units (preserveAspectRatio=none stretches)
  var points=[];                   // last fetched samples
  // Per-chart definitions: which series, colors, axis behavior.
  var CHARTS={
    compute:{series:[{k:"cpu",c:"#ffb347"},{k:"mem",c:"#6fd3e0"}],min:0,max:100},
    load:{series:[{k:"load1",c:"#9fb5ff"},{k:"load5",c:"#eb9fd0"}],min:0,max:"auto"},
    vitals:{series:[{k:"temp",c:"#ff8a6a",axis:"l"},{k:"volt",c:"#6fd3e0",axis:"r"}],
            dual:true,bands:true},
    link:{series:[{k:"rssi",c:"#7ce0b0",axis:"l"},{k:"qual",c:"#ffb347",axis:"r"}],dual:true}
  };
  var hidden={};                   // series key -> true when legend-toggled off

  function el(name,attrs){var e=document.createElementNS(SVGNS,name);
    for(var a in attrs)e.setAttribute(a,attrs[a]);return e;}
  function svgOf(chart){return document.querySelector('#sysChart-'+chart+' .sysgraph');}

  // Value range for a set of series keys across all points (nulls skipped).
  function rangeOf(keys){var lo=Infinity,hi=-Infinity;
    for(var i=0;i<points.length;i++){for(var j=0;j<keys.length;j++){
      var v=points[i][keys[j]];if(v==null)continue;if(v<lo)lo=v;if(v>hi)hi=v;}}
    if(lo===Infinity)return null;return [lo,hi];}

  // Build "x,y x,y" polyline segments for one series, splitting on nulls so gaps
  // aren't drawn as straight lines through missing data.
  function segs(key,ymin,ymspan){
    var n=points.length,out=[],cur=[];
    for(var i=0;i<n;i++){
      var v=points[i][key];
      if(v==null){if(cur.length){out.push(cur);cur=[];}continue;}
      var x=n<2?0:(i/(n-1))*W;
      var y=H-((v-ymin)/(ymspan||1))*H;
      cur.push(x.toFixed(1)+","+y.toFixed(1));
    }
    if(cur.length)out.push(cur);return out;}

  // Scale helper for a chart+series: returns [ymin, yspan] honoring fixed/auto/dual.
  function scaleFor(def,key){
    if(def.dual){var r=rangeOf([key]);if(!r)return [0,1];
      var pad=(r[1]-r[0])*0.15||1;return [r[0]-pad,(r[1]-r[0])+2*pad];}
    if(def.max==="auto"){var rr=rangeOf(def.series.map(function(s){return s.k;}));
      var top=rr?Math.max(1.0,rr[1]*1.2):1.0;return [def.min,top-def.min];}
    return [def.min,def.max-def.min];}

  function draw(chart){
    var def=CHARTS[chart],svg=svgOf(chart);if(!svg)return;
    while(svg.firstChild)svg.removeChild(svg.firstChild);
    // faint horizontal grid
    for(var g=1;g<4;g++)svg.appendChild(el("line",
      {x1:0,y1:g*H/4,x2:W,y2:g*H/4,"class":"grid"}));
    if(!points.length)return;
    // throttle/undervolt alert bands behind VITALS
    if(def.bands){var n=points.length,run=null;
      for(var i=0;i<=n;i++){
        var bad=i<n&&points[i].thr!=null&&((points[i].thr&0x1)||(points[i].thr&0x4));
        if(bad&&run===null)run=i;
        else if(!bad&&run!==null){
          var x0=(run/(n-1))*W,x1=((i-1)/(n-1))*W;
          svg.appendChild(el("rect",{x:x0,y:0,width:Math.max(1,x1-x0),height:H,"class":"band"}));
          run=null;}}}
    // reference line (LOAD @ 1.0)
    if(def.ref!=null){var sc=scaleFor(def,def.series[0].k);
      var yr=H-((def.ref-sc[0])/(sc[1]||1))*H;
      svg.appendChild(el("line",{x1:0,y1:yr,x2:W,y2:yr,"class":"refline"}));}
    // series polylines
    def.series.forEach(function(s){
      if(hidden[s.k])return;
      var sc=scaleFor(def,s.k);
      segs(s.k,sc[0],sc[1]).forEach(function(seg){
        var pl=el("polyline",{points:seg.join(" ")});
        pl.style.stroke=s.c;pl.style.color=s.c;svg.appendChild(pl);});});
    // y-axis corner labels for EVERY chart (crisp HTML overlay; SVG text would distort
    // under the non-uniform viewBox scale). A series with NO data (all null -- e.g.
    // voltage off-Pi) gets a BLANK axis rather than a phantom 0..1 scale.
    var lk=def.series[0].k,tl="",bl="",tr="",br="";
    if(rangeOf([lk])){var l=scaleFor(def,lk);tl=axfmt(l[0]+l[1]);bl=axfmt(l[0]);}
    if(def.dual){var rk=def.series[1].k;
      if(rangeOf([rk])){var r=scaleFor(def,rk);tr=axfmt(r[0]+r[1]);br=axfmt(r[0]);}}
    // Colour each axis to match its line: left = series[0], right = series[1] (dual).
    setAx(chart,tl,bl,tr,br,def.series[0].c,def.dual?def.series[1].c:null);
  }
  function axfmt(v){return v===0?"0":(Math.abs(v)<10?v.toFixed(2):v.toFixed(0));}
  function setAx(chart,tl,bl,tr,br,lc,rc){
    var s=document.querySelectorAll('#sysChart-'+chart+' .sys-ax');
    if(s.length<4)return;
    s[0].textContent=tl;s[1].textContent=bl;s[2].textContent=tr;s[3].textContent=br;
    if(lc){s[0].style.color=lc;s[1].style.color=lc;}
    if(rc){s[2].style.color=rc;s[3].style.color=rc;}}

  function render(){for(var c in CHARTS){
    if(!document.getElementById('sysChart-'+c).classList.contains('collapsed'))draw(c);}
    if(window.SYS_afterRender)window.SYS_afterRender();}

  function load(){return api('/api/system/history').then(function(d){
    points=(d&&d.points)||[];render();});}

  return {load:load,render:render,draw:draw,CHARTS:CHARTS,hidden:hidden,
          get points(){return points;},set points(v){points=v;}};
})();

/* ---------- boot ---------- */
buildOdometer();initDrawer('fuelDrawer','fuel');initDrawer('advDrawer','adv');initDrawer('sysDrawer','sys');
// Poll system history only while the SYSTEM drawer is open (zero cost when closed).
(function(){
  var d=$('sysDrawer'),face=d.querySelector('.drawer-face'),timer=null;
  face.addEventListener('click',function(){
    var open=d.className.indexOf('open')>=0;   // class already toggled by initDrawer
    if(open){SYS.load();timer=setInterval(function(){SYS.load();},15000);}
    else if(timer){clearInterval(timer);timer=null;}
  });
})();

/* ---------- SYSTEM interaction: hover, strips, collapse, legend, status ---------- */
(function(){
  var LS_C="gp.sys.collapsed",LS_H="gp.sys.hidden";
  function relTime(t){var s=Math.max(0,Math.round(Date.now()/1000)-t);
    if(s<60)return "-"+s+"s";if(s<3600)return "-"+Math.round(s/60)+"m";
    return "-"+(s/3600).toFixed(1)+"h";}
  function num(v,suf,dp){return v==null?"--":((dp!=null?v.toFixed(dp):v)+(suf||""));}

  function esc(s){return String(s).replace(/[<>&]/g,function(c){
    return c==="<"?"&lt;":c===">"?"&gt;":"&amp;";});}
  function seg(text,color){return '<span style="color:'+color+'">'+esc(text)+'</span>';}
  function thrWord(thr){if(thr==null)return "";
    if(thr&0x1)return "\\u26d4undervolt";if(thr&0x4)return "\\u26a0throttle";
    if((thr&0x10000)||(thr&0x40000))return "\\u26a0since-boot";return "\\u2713nominal";}
  function thrColor(thr){if(thr&0x1)return "#ff8a6a";
    if((thr&0x4)||(thr&0x10000)||(thr&0x40000))return "#ffb347";return "#7ce0b0";}
  // Build the hover strip: time LEFT, colour-matched values RIGHT. Each value's colour
  // matches its chart line.
  function stripHTML(chart,p){
    if(!p)return '<span class="t">\\u2014</span>';
    var v="";
    if(chart==="compute")v=seg("CPU "+num(p.cpu,"%"),"#ffb347")+seg("MEM "+num(p.mem,"%"),"#6fd3e0");
    else if(chart==="load")v=seg("1m "+num(p.load1,"",2),"#7ce0b0")+seg("5m "+num(p.load5,"",2),"#eb9fd0");
    else if(chart==="vitals"){v=seg(num(p.temp,"\\u00b0C",1),"#ff8a6a")+seg(num(p.volt,"V",2),"#6fd3e0");
      var w=thrWord(p.thr);if(w)v+=seg(w,thrColor(p.thr));}
    else if(chart==="link")v=seg(num(p.rssi,"dBm"),"#7ce0b0")+seg("Qual "+num(p.qual,""),"#ffb347");
    return '<span class="t">'+esc(relTime(p.t))+'</span><span class="v">'+v+'</span>';}

  var hoverIdx=-1;                 // -1 => show latest
  function updateStatus(){
    var pts=SYS.points,p=null;
    if(pts.length)p=hoverIdx>=0&&hoverIdx<pts.length?pts[hoverIdx]:pts[pts.length-1];
    for(var c in SYS.CHARTS){
      var strip=document.querySelector('#sysChart-'+c+' .sys-strip');
      if(strip)strip.innerHTML=stripHTML(c,p);}
    // header + face live status always reflect the LATEST sample
    var last=pts.length?pts[pts.length-1]:null;
    var big=$('sysHdrTemp'),face=$('sysFaceTemp'),chip=$('sysThrChip');
    if(last&&last.temp!=null){
      var cls=last.temp>=75?"hot":last.temp>=60?"warn":"ok";
      big.className="sys-temp-big "+cls;big.textContent=last.temp.toFixed(1)+"\\u00b0C";
      face.style.color=cls==="hot"?"#ff8a6a":cls==="warn"?"#ffb347":"#7ce0b0";
      face.textContent=last.temp.toFixed(0)+"\\u00b0C";
    }else{big.textContent="\\u2014";face.textContent="\\u2014";}
    if(chip){var t=last?last.thr:null;
      if(t!=null&&(t&0x1)){chip.className="sys-chip uv";chip.textContent="UNDERVOLTING";}
      else if(t!=null&&((t&0x10000)||(t&0x40000))){chip.className="sys-chip thr";chip.textContent="THROTTLED";}
      else if(t!=null){chip.className="sys-chip clean";chip.textContent="NOMINAL";}
      else{chip.className="sys-chip clean";chip.textContent="\\u2014";}}
  }

  // Synced crosshair: pointer x over any screen -> nearest index -> all strips.
  function showAt(idx){hoverIdx=idx;
    document.querySelectorAll('#sysDrawer .sysgraph .cross,#sysDrawer .sysgraph .dot')
      .forEach(function(n){n.remove();});
    var pts=SYS.points;
    if(idx>=0&&pts.length>1){var x=(idx/(pts.length-1))*300;
      for(var c in SYS.CHARTS){var svg=document.querySelector('#sysChart-'+c+' .sysgraph');
        if(!svg||document.getElementById('sysChart-'+c).classList.contains('collapsed'))continue;
        var ln=document.createElementNS("http://www.w3.org/2000/svg","line");
        ln.setAttribute("x1",x);ln.setAttribute("y1",0);ln.setAttribute("x2",x);
        ln.setAttribute("y2",100);ln.setAttribute("class","cross");svg.appendChild(ln);}}
    updateStatus();}

  function bindHover(){
    document.querySelectorAll('#sysDrawer .sys-screen').forEach(function(scr){
      scr.addEventListener('mousemove',function(e){move(e.clientX,scr);});
      scr.addEventListener('touchmove',function(e){
        if(e.touches[0])move(e.touches[0].clientX,scr);},{passive:true});
      scr.addEventListener('mouseleave',function(){showAt(-1);});});}
  function move(clientX,scr){var r=scr.getBoundingClientRect();
    var pts=SYS.points;if(!pts.length)return;
    var frac=Math.min(1,Math.max(0,(clientX-r.left)/r.width));
    showAt(Math.round(frac*(pts.length-1)));}

  // Per-chart collapse (eye) with localStorage persistence.
  function loadSet(k){try{return JSON.parse(localStorage.getItem(k))||[];}catch(e){return [];}}
  function saveSet(k,arr){try{localStorage.setItem(k,JSON.stringify(arr));}catch(e){}}
  function applyCollapsed(){var cs=loadSet(LS_C);
    for(var c in SYS.CHARTS){$('sysChart-'+c).classList.toggle('collapsed',cs.indexOf(c)>=0);}}
  function bindEyes(){
    document.querySelectorAll('#sysDrawer .sys-eye').forEach(function(btn){
      btn.addEventListener('click',function(e){e.stopPropagation();
        var panel=btn.closest('.sys-panel'),c=panel.getAttribute('data-chart');
        panel.classList.toggle('collapsed');
        var cs=loadSet(LS_C),i=cs.indexOf(c);
        if(panel.classList.contains('collapsed')){if(i<0)cs.push(c);}else if(i>=0)cs.splice(i,1);
        saveSet(LS_C,cs);SYS.render();});});}

  // Legend series toggles (persisted).
  function applyHidden(){var hs=loadSet(LS_H);hs.forEach(function(k){SYS.hidden[k]=true;});
    document.querySelectorAll('#sysDrawer .sys-leg').forEach(function(l){
      l.classList.toggle('off',!!SYS.hidden[l.getAttribute('data-series')]);});}
  function bindLegend(){
    document.querySelectorAll('#sysDrawer .sys-leg').forEach(function(l){
      l.addEventListener('click',function(){var k=l.getAttribute('data-series');
        SYS.hidden[k]=!SYS.hidden[k];l.classList.toggle('off',!!SYS.hidden[k]);
        var hs=loadSet(LS_H),i=hs.indexOf(k);
        if(SYS.hidden[k]){if(i<0)hs.push(k);}else if(i>=0)hs.splice(i,1);
        saveSet(LS_H,hs);SYS.render();});});}

  // Re-apply strips after every data render.
  window.SYS_afterRender=function(){updateStatus();};

  applyCollapsed();applyHidden();bindEyes();bindLegend();bindHover();updateStatus();
})();
registerSW();
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
  <div class="placard"><h1>GeneratorPi</h1></div>

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

            <div class="drawer-divider"></div>

            <div>
              <div class="fuel-io">
                <input class="crt-input" id="rateInput" type="number" step="0.1" min="0" inputmode="decimal" placeholder="drain %/hr" aria-label="Set drain rate percent per hour">
                <button type="button" class="btn3d cyan" id="setRateBtn">SET</button>
                <button type="button" class="btn3d steel btn3dsm" id="resetRateBtn" aria-label="Reset drain rate to default">RESET</button>
              </div>
              <div class="helper">Estimated automatically from readings, or set it here directly.</div>
            </div>

            <div class="alert-banner" id="alertBanner" role="alert">
              <span class="alert-dot"></span>LOW FUEL — projected level at or below alert threshold. Refuel soon.
            </div>

            <div class="drawer-divider"></div>

            <div>
              <div class="fuel-io">
                <input class="crt-input" id="readingInput" type="number" step="1" min="0" max="100" inputmode="numeric" placeholder="e.g. 48" aria-label="Record observed level percent">
                <button type="button" class="btn3d cyan" id="recordBtn">RECORD</button>
              </div>
              <div class="helper">Each reading refines the linear drain estimate (level = start − rate × run-hours). More readings on one tank → better projection.</div>
            </div>

            <div class="drawer-divider"></div>

            <div>
              <div class="fuel-io">
                <input class="crt-input" id="fillInput" type="number" step="1" min="0" max="100" inputmode="numeric" placeholder="e.g. 100" aria-label="Set gas tank level percent">
                <button type="button" class="btn3d green" id="fillBtn">SET</button>
              </div>
              <div class="helper">Resets the baseline level to the new fill; drain rate is retained.</div>
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
            <div class="section-label" style="margin:0">SYSTEM</div>
            <div class="alert-cfg">
              <div class="alert-cfg-row">
                <span class="lbl"><span class="engrave"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M18 8a6 6 0 1 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.7 21a2 2 0 0 1-3.4 0"/></svg></span>PUSH NOTIFICATIONS</span>
                <div class="iotoggle" id="pushToggle" role="switch" aria-checked="false" tabindex="0" aria-label="Push notifications on or off">
                  <span class="half i">I</span><span class="half o">O</span>
                </div>
              </div>
              <div class="helper" id="pushHelp">Checking push support…</div>
              <button type="button" class="btn3d cyan" id="testPushBtn" style="width:100%" disabled><span class="engrave"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"><path d="M22 2 11 13"/><path d="M22 2 15 22l-4-9-9-4z"/></svg></span>SEND TEST NOTIFICATION</button>
              <div class="drawer-divider"></div>
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
              <div class="drawer-divider"></div>
              <div class="alert-cfg-row">
                <span class="lbl"><span class="engrave"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><line x1="4" y1="7" x2="20" y2="7"/><line x1="4" y1="12" x2="20" y2="12"/><line x1="4" y1="17" x2="20" y2="17"/><circle cx="9" cy="7" r="2.2" fill="currentColor" stroke="none"/><circle cx="15" cy="12" r="2.2" fill="currentColor" stroke="none"/><circle cx="8" cy="17" r="2.2" fill="currentColor" stroke="none"/></svg></span>FUEL PROJECTION</span>
                <div class="iotoggle" id="fuelToggle" role="switch" aria-checked="true" tabindex="0" aria-label="Fuel projection feature on or off">
                  <span class="half i">I</span><span class="half o">O</span>
                </div>
              </div>
              <div class="helper">Turn the fuel-projection panel and low-fuel alerts on or off for everyone.</div>
            </div>
            <div class="section-label" style="margin:0">MANUAL OVERRIDE</div>
            <div class="alert-cfg">
              <div class="warn-copy">These correct the <strong>tracked</strong> state only — they do <strong>not</strong> crank or stop the engine or touch the relay. Use to re-sync after operating the unit by hand.</div>
              <div class="adv-btns">
                <button type="button" class="btn3d amber" id="markRunBtn"><span class="led amber"></span>MARK AS RUNNING</button>
                <button type="button" class="btn3d steel" id="markStopBtn"><span class="led grey"></span>MARK AS STOPPED</button>
              </div>
            </div>
          </div>
        </div>
        <div class="drawer-base"></div>
      </div>

      <!-- SYSTEM drawer: in-memory host perf history, client-rendered CRT charts -->
      <div class="drawer sys" id="sysDrawer">
        <button type="button" class="drawer-face" aria-expanded="false" aria-controls="sysClip">
          <span class="face-left"><span class="engrave"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="4" width="18" height="13" rx="1"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/><polyline points="6 12 9 9 12 12 15 8 18 11"/></svg></span>SYSTEM</span>
          <span class="face-right"><span id="sysFaceTemp" style="color:#7ce0b0">—</span><span class="caret">▾</span></span>
        </button>
        <div class="drawer-clip" id="sysClip">
          <div class="drawer-cavity">
            <div class="sys-hdr">
              <div><span class="sys-temp-big ok" id="sysHdrTemp">—</span></div>
              <span class="sys-chip clean" id="sysThrChip">—</span>
            </div>

            <!-- COMPUTE: CPU% + MEM% (fixed 0-100) -->
            <div class="sys-panel" data-chart="compute" id="sysChart-compute">
              <div class="sys-panel-face">
                <span class="sys-panel-title">COMPUTE</span>
                <span class="sys-legend">
                  <span class="sys-leg" data-series="cpu"><span class="sw" style="background:#ffb347;color:#ffb347"></span>CPU</span>
                  <span class="sys-leg" data-series="mem"><span class="sw" style="background:#6fd3e0;color:#6fd3e0"></span>MEM</span>
                  <button type="button" class="sys-eye" aria-label="Collapse chart">◉</button>
                </span>
              </div>
              <div class="sys-panel-body">
                <div class="sys-screen"><svg class="sysgraph" preserveAspectRatio="none" viewBox="0 0 300 100"></svg><span class="sys-ax tl"></span><span class="sys-ax bl"></span><span class="sys-ax tr"></span><span class="sys-ax br"></span></div>
                <div class="sys-strip">—</div>
              </div>
            </div>

            <!-- LOAD: 1m + 5m (auto max, ref line @1.0) -->
            <div class="sys-panel" data-chart="load" id="sysChart-load">
              <div class="sys-panel-face">
                <span class="sys-panel-title">LOAD</span>
                <span class="sys-legend">
                  <span class="sys-leg" data-series="load1"><span class="sw" style="background:#7ce0b0;color:#7ce0b0"></span>1m</span>
                  <span class="sys-leg" data-series="load5"><span class="sw" style="background:#eb9fd0;color:#eb9fd0"></span>5m</span>
                  <button type="button" class="sys-eye" aria-label="Collapse chart">◉</button>
                </span>
              </div>
              <div class="sys-panel-body">
                <div class="sys-screen"><svg class="sysgraph" preserveAspectRatio="none" viewBox="0 0 300 100"></svg><span class="sys-ax tl"></span><span class="sys-ax bl"></span><span class="sys-ax tr"></span><span class="sys-ax br"></span></div>
                <div class="sys-strip">—</div>
              </div>
            </div>

            <!-- SENSORS: temp (left °C) + voltage (right V), throttle bands -->
            <div class="sys-panel" data-chart="vitals" id="sysChart-vitals">
              <div class="sys-panel-face">
                <span class="sys-panel-title">SENSORS</span>
                <span class="sys-legend">
                  <span class="sys-leg" data-series="temp"><span class="sw" style="background:#ff8a6a;color:#ff8a6a"></span>°C</span>
                  <span class="sys-leg" data-series="volt"><span class="sw" style="background:#6fd3e0;color:#6fd3e0"></span>V</span>
                  <button type="button" class="sys-eye" aria-label="Collapse chart">◉</button>
                </span>
              </div>
              <div class="sys-panel-body">
                <div class="sys-screen"><svg class="sysgraph" preserveAspectRatio="none" viewBox="0 0 300 100"></svg><span class="sys-ax tl"></span><span class="sys-ax bl"></span><span class="sys-ax tr"></span><span class="sys-ax br"></span></div>
                <div class="sys-strip">—</div>
              </div>
            </div>

            <!-- WLINK: wireless-link RSSI (dBm) + link quality -->
            <div class="sys-panel" data-chart="link" id="sysChart-link">
              <div class="sys-panel-face">
                <span class="sys-panel-title">WLINK</span>
                <span class="sys-legend">
                  <span class="sys-leg" data-series="rssi"><span class="sw" style="background:#7ce0b0;color:#7ce0b0"></span>dBm</span>
                  <span class="sys-leg" data-series="qual"><span class="sw" style="background:#ffb347;color:#ffb347"></span>Qual</span>
                  <button type="button" class="sys-eye" aria-label="Collapse chart">◉</button>
                </span>
              </div>
              <div class="sys-panel-body">
                <div class="sys-screen"><svg class="sysgraph" preserveAspectRatio="none" viewBox="0 0 300 100"></svg><span class="sys-ax tl"></span><span class="sys-ax bl"></span><span class="sys-ax tr"></span><span class="sys-ax br"></span></div>
                <div class="sys-strip">—</div>
              </div>
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
    <div class="frow">&copy; 2026 <a href="https://neal.media" target="_blank" rel="noopener">Chris Neal</a> &amp; <a href="https://neal.tools" target="_blank" rel="noopener">Alex Neal</a></div>
    <div class="frow"><a href="https://github.com/mrchrisneal/generatorpi" target="_blank" rel="noopener">v1.0.0</a> · <a href="https://github.com/mrchrisneal/generatorpi" target="_blank" rel="noopener">GitHub</a> · <a href="https://www.gnu.org/licenses/agpl-3.0.html" target="_blank" rel="noopener">AGPL v3</a></div>
  </footer>

  <!-- Start confirmation dialog -->
  <div class="confirm-overlay" id="confirmOverlay" role="dialog" aria-modal="true" aria-labelledby="confirmTitle">
    <div class="confirm-card">
      <div class="confirm-badge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="34" height="34"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9.5" x2="12" y2="13.5"/><circle cx="12" cy="16.9" r="0.9" fill="currentColor" stroke="none"/></svg></div>
      <h2 id="confirmTitle">START GENERATOR?</h2>
      <p>This <strong>cranks the real engine</strong>. Confirm the area around the unit is clear and it is safe to start.</p>
      <div class="confirm-btns">
        <button type="button" class="btn3d steel" id="confirmCancel">CANCEL</button>
        <button type="button" class="btn3d red" id="confirmStart">START</button>
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
    # Notify subscribed devices of the manual state change (distinct copy from a real
    # start/stop so it's clear no engine action occurred).
    send_push_async(
        "Marked as running" if running else "Marked as stopped",
        "Tracked state was set manually (no relay action).",
        tag="state",
    )
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
            "fuel_enabled": alerts_state.get("fuel_enabled", True),
        }
    snap["server_now"] = time.time()
    # Web Push info for the client: whether the server can send (library + VAPID key),
    # the public key the browser needs to subscribe, and how many devices are subscribed.
    snap["push"] = {
        "supported": push_available(),
        "vapid_public_key": CONFIG.get("VAPID_PUBLIC_KEY", ""),
        "subscriptions": subscription_count(),
    }
    return jsonify(snap)


@app.route('/api/system/history', methods=['GET'])
@auth_required
def api_system_history():
    """Return the in-memory SYSTEM perf-history ring buffer as JSON for the UI.
    Snapshot under the lock so we never serialize a deque mid-append. Small (<=240
    tiny dicts); computed only when the UI polls (and only while the drawer is open)."""
    with _sys_hist_lock:
        points = list(_sys_history)
    return jsonify({
        "points": points,
        "sample_seconds": max(5, int(CONFIG.get("SYSTEM_HISTORY_SECONDS", 15))),
        "capacity": _sys_history.maxlen,
        "server_now": time.time(),
    })


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


# The service worker: a plain same-origin script (served as its own resource, NOT via
# the Jinja template) that shows a notification on 'push' and focuses/opens the app on
# click. It holds no secrets, so it is intentionally NOT behind @auth_required -- the
# browser's SW runtime fetches it directly. Scope '/' comes from serving it at /sw.js.
SERVICE_WORKER_JS = """
self.addEventListener('push', function(event){
  var data = {};
  try { data = event.data ? event.data.json() : {}; } catch (e) {}
  var title = data.title || 'Generator';
  var opts = { body: data.body || '', tag: data.tag || 'generatorpi', renotify: true };
  event.waitUntil(self.registration.showNotification(title, opts));
});
self.addEventListener('notificationclick', function(event){
  event.notification.close();
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function(list){
      for (var i = 0; i < list.length; i++){ if ('focus' in list[i]) return list[i].focus(); }
      if (clients.openWindow) return clients.openWindow('/');
    })
  );
});
"""


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
        _monitor_stop.set()
        relay_start_stop.close()
        log.info("Shutdown complete")

if __name__ == '__main__':
    main()
