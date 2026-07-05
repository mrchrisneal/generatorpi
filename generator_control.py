from gpiozero import OutputDevice
import logging
import logging.handlers
import os
import sys
import time
import threading
import hmac
import secrets
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
generator_state = {
    "running": False,       # Manually tracked (no auto-detect)
    "last_command": None,
    "last_start_time": None,
    "last_stop_time": None,
    "start_attempts": 0,
    "message": "System ready"
}
state_lock = threading.Lock()

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
        return {"success": False, "message": "A relay sequence is already in progress"}

    try:
        with state_lock:
            if generator_state["running"]:
                return {"success": False, "message": "Generator already marked as running"}
            generator_state["last_command"] = "start"
            generator_state["start_attempts"] = 0

        max_retries = CONFIG["MAX_START_RETRIES"]
        prime_delay = CONFIG["PRIME_DELAY"]
        retry_delay = CONFIG["RETRY_DELAY"]

        log.info("Initiating generator start sequence")

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

        # Mark as running (assume success -- no auto-detect available)
        with state_lock:
            generator_state["running"] = True
            generator_state["message"] = (
                f"Start sequence completed ({max_retries} attempt(s)). "
                "Verify generator manually."
            )

        log.info("Start sequence finished")
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
            generator_state["running"] = False
            generator_state["last_stop_time"] = datetime.now().isoformat()
            generator_state["message"] = "Stop command sent"

        log.info("Stop button pressed")
        return {"success": True, "message": "Stop button pressed. Generator should be stopping."}
    finally:
        relay_lock.release()

# ============================================================================
# FLASK WEB SERVER
# ============================================================================
# static_folder=None disables Flask's built-in /static/<path> route entirely.
# We serve zero static files (the UI is one inline template), so this removes an
# unused file-serving surface -- nothing under the app dir (incl. the settings
# file) can be reached over HTTP.
app = Flask(__name__, static_folder=None)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Generator Control</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
            background: #f5f5f5;
        }
        h1 { color: #333; text-align: center; }
        .status {
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
            text-align: center;
            font-size: 20px;
            font-weight: bold;
        }
        .running { background: #d4edda; color: #155724; border: 2px solid #28a745; }
        .stopped { background: #f8d7da; color: #721c24; border: 2px solid #dc3545; }
        .controls {
            display: flex;
            gap: 10px;
            justify-content: center;
            margin: 20px 0;
        }
        .button {
            padding: 15px 30px;
            font-size: 18px;
            cursor: pointer;
            border: none;
            border-radius: 8px;
            color: white;
            font-weight: bold;
            transition: opacity 0.2s;
        }
        .start-btn { background: #28a745; }
        .stop-btn { background: #dc3545; }
        .button:hover { opacity: 0.9; }
        .button:disabled { opacity: 0.5; cursor: not-allowed; }
        .info {
            margin: 20px 0;
            padding: 15px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .info-row {
            padding: 8px 0;
            border-bottom: 1px solid #eee;
        }
        .info-row:last-child { border-bottom: none; }
        .label { font-weight: bold; color: #666; }
        .message-box {
            margin: 15px 0;
            padding: 12px;
            background: #e7f3ff;
            border-left: 4px solid #2196F3;
            border-radius: 4px;
        }
        .warning {
            background: #fff3cd;
            border-left-color: #ffc107;
            color: #856404;
        }
    </style>
</head>
<body>
    <h1>Powermate PM9400E Control</h1>

    <div class="status {{ 'running' if status.running else 'stopped' }}">
        {{ "RUNNING" if status.running else "STOPPED" }}
    </div>

    <div class="message-box {{ 'warning' if not status.running and status.last_command == 'start' else '' }}">
        {{ status.message }}
    </div>

    <div class="controls">
        <button class="button start-btn" onclick="startGen()" id="startBtn"
                {{ 'disabled' if status.running else '' }}>
            START
        </button>
        <button class="button stop-btn" onclick="stopGen()" id="stopBtn"
                {{ 'disabled' if not status.running else '' }}>
            STOP
        </button>
    </div>

    <div class="info">
        <div class="info-row">
            <span class="label">Last Command:</span>
            {{ status.last_command or "None" }}
        </div>
        <div class="info-row">
            <span class="label">Start Attempts:</span>
            {{ status.start_attempts }}
        </div>
        <div class="info-row">
            <span class="label">Last Start:</span>
            {{ status.last_start_time or "Never" }}
        </div>
        <div class="info-row">
            <span class="label">Last Stop:</span>
            {{ status.last_stop_time or "Never" }}
        </div>
    </div>

    <div class="info" style="background: #fff9e6; font-size: 14px;">
        <strong>Note:</strong> This system cannot auto-detect if the generator is running.
        Please verify generator status visually/audibly after commands.
    </div>

    <script>
        let isProcessing = false;

        function startGen() {
            if (isProcessing) return;
            isProcessing = true;

            const btn = document.getElementById('startBtn');
            btn.disabled = true;
            btn.textContent = 'Starting...';

            fetch('/api/start', {method: 'POST'})
                .then(r => r.json())
                .then(data => {
                    location.reload();
                })
                .catch(err => {
                    console.error('Start error:', err);
                    isProcessing = false;
                    btn.disabled = false;
                    btn.textContent = 'START';
                });
        }

        function stopGen() {
            if (isProcessing) return;
            isProcessing = true;

            const btn = document.getElementById('stopBtn');
            btn.disabled = true;
            btn.textContent = 'Stopping...';

            fetch('/api/stop', {method: 'POST'})
                .then(r => r.json())
                .then(data => {
                    location.reload();
                })
                .catch(err => {
                    console.error('Stop error:', err);
                    isProcessing = false;
                    btn.disabled = false;
                    btn.textContent = 'STOP';
                });
        }

        // Auto-refresh every 10 seconds
        setTimeout(() => location.reload(), 10000);
    </script>
</body>
</html>
"""

@app.after_request
def set_security_headers(response):
    """Add security headers to every response."""
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'"
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
        generator_state["running"] = running
        generator_state["message"] = f"Manually set to {'RUNNING' if running else 'STOPPED'}"

    log.info(f"State manually set to {'RUNNING' if running else 'STOPPED'} by {caller_identity()}")
    return jsonify({"success": True, "running": running})

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
