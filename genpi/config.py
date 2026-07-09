# genpi/config.py -- Configuration, credentials, and runtime paths for GeneratorPi (roadmap #59,
# Stage 2). This is LAYER 0 of the package: it depends on nothing else in genpi and is imported
# FIRST by genpi/__init__.py, so every other submodule can read CONFIG / paths / credentials here.
#
# Owns: the CONFIG defaults dict; env-file parsing + credential loading (parse_env_file, which
# auto-hashes plaintext passwords and auto-provisions the API key + VAPID keypair); the settings-
# file security gate (check_settings_file_security); the runtime paths (SCRIPT_DIR, ENV_FILE) and
# app version (APP_VERSION); the process start timestamp (_STARTED_AT); and the OPTIONAL Web-Push
# library import guard (_PUSH_AVAILABLE + the py-vapid / http-ece / requests symbols). The guard
# lives HERE -- not in the later push/store layer -- because parse_env_file's VAPID key auto-
# generation needs Vapid at import time (layer 0), so the guard must sit at or below this module.
#
# Importing this module runs its import-time side effects EXACTLY as the old single file did:
# check_settings_file_security() then AUTH_USERS = parse_env_file() (at the very bottom).
#
# Copyright (C) 2026 Chris Neal <https://neal.media> and Alex Neal <https://neal.tools>
# SPDX-License-Identifier: AGPL-3.0-or-later
import os                                              # perms/ownership checks, atomic rename, env
import sys                                             # stderr diagnostics + hard-exit on bad settings file
import time                                            # process start timestamp (_STARTED_AT)
import secrets                                         # strong random API-key generation
from pathlib import Path                               # SCRIPT_DIR / ENV_FILE / VERSION resolution
from werkzeug.security import generate_password_hash   # hash plaintext USER_ passwords on load

# Web Push is OPTIONAL: the controller must still run on a Pi without the push libraries
# (push simply becomes unavailable server-side). We send pushes OURSELVES using three small
# libraries -- py-vapid (signs the VAPID JWT auth header), http-ece (RFC 8188 "aes128gcm"
# payload encryption), and requests (the HTTPS POST to the push service). All three are
# packaged for Raspberry Pi OS as python3-py-vapid / python3-http-ece / python3-requests, so
# the device stays 100% apt-only (no pip, no source builds). This deliberately AVOIDS the
# `pywebpush` wrapper, which is NOT available as an apt package on Raspberry Pi OS. The import
# is guarded so a missing dependency degrades gracefully instead of crashing at startup, and
# push_status() reports EXACTLY which piece is missing so the UI can say why push is off.
try:
    from py_vapid import Vapid
    from py_vapid.utils import b64urlencode as _vapid_b64
    from cryptography.hazmat.primitives import serialization as _crypto_serialization
    from cryptography.hazmat.primitives.asymmetric import ec as _crypto_ec
    import http_ece
    import requests
    _PUSH_AVAILABLE = True
    _PUSH_LIB_HINT = ""
except Exception:  # pragma: no cover - import-time only; push libs are present in dev/CI, so this fallback fires only on a device missing python3-py-vapid/http-ece/requests and can't be re-triggered without a module reload
    _PUSH_AVAILABLE = False
    # Operator-facing hint (surfaced in the UI) naming exactly what to install.
    _PUSH_LIB_HINT = "python3-py-vapid, python3-http-ece and python3-requests"

# ============================================================================
# CONFIGURATION
# ============================================================================
# All operator/runtime files -- generator_control.env (credentials), the VERSION file, the TLS
# cert/key, events.db, and the logs -- live in the PROJECT ROOT: the directory that CONTAINS the
# genpi/ package, NOT the package dir itself. __file__ is genpi/__init__.py (or a genpi/ submodule),
# so the root is two levels up. Keeping runtime data at the root (unchanged from the old single-file
# layout, where this file WAS the root) means the deploy tar, setup.sh, and the self-updater all keep
# finding the env file + certs exactly where they have always been -- the package split moved code,
# not operator data. See generator_control.env.example for the env format and defaults.
SCRIPT_DIR = Path(__file__).resolve().parent.parent
ENV_FILE = SCRIPT_DIR / "generator_control.env"

# Application version -- the SINGLE SOURCE OF TRUTH is the VERSION file next to this
# script (one line, e.g. "1.0.0"). The UI footer, the startup event, the /api/state
# payload, and (later) the update-manifest check all read this one value, so bumping a
# release is a single-file edit. Falls back to a sentinel if the file is missing/unreadable
# so the app still boots and reports *something* rather than crashing on a packaging slip.
def _read_app_version():
    try:
        v = (SCRIPT_DIR / "VERSION").read_text(encoding="utf-8").strip()
        return v or "0.0.0"
    except OSError:
        return "0.0.0"


APP_VERSION = _read_app_version()

# Unix timestamp of THIS process's start, captured at import. A full restart (systemd restart or
# the updater's os.execv re-exec) re-imports the module, so this value CHANGES on every restart --
# the client uses it as a robust "did the app actually restart?" signal (and to show when the app
# was last fully restarted). Bundled into /api/state alongside app_version.
_STARTED_AT = time.time()

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
    # Service / auto-update behaviour (obeyed by the in-app self-updater). These must be real
    # CONFIG defaults so the env-file loader (which only accepts keys already in CONFIG) can set
    # them -- otherwise the updater's service opt-out is unreachable (audit M-2).
    "SERVICE_ENABLED": 1,               # 0 = NOT run as a systemd service -> updater swaps in-process + re-execs instead of restarting a unit
    "AUTOSTART": 1,                     # 0 = don't treat the service as auto-starting -> updater skips the systemd restart path
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
    # persist it here. If the push libraries aren't installed, this is skipped entirely and
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
