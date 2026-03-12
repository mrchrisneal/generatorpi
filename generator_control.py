from gpiozero import OutputDevice
import logging
import logging.handlers
import os
import time
import threading
from functools import wraps
from flask import Flask, render_template_string, jsonify, request, Response
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
        elif key in CONFIG:
            # Config override -- cast to the same type as the default
            default = CONFIG[key]
            try:
                if isinstance(default, int):
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

    # Rewrite file to replace plaintext passwords with hashes.
    # Write to a temp file first, then atomic rename (POSIX guarantees this).
    if needs_rewrite:
        import tempfile
        tmp_fd, tmp_path = tempfile.mkstemp(dir=SCRIPT_DIR, prefix=".env_tmp_")
        try:
            with os.fdopen(tmp_fd, "w") as tmp_f:
                tmp_f.write("\n".join(new_lines) + "\n")
            os.rename(tmp_path, ENV_FILE)
        except Exception:
            # Clean up temp file if rename fails
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise
        print(f"Rewrote {ENV_FILE.name} with hashed passwords")

    return users


# Load config and credentials before anything else
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
    """Record a failed auth attempt. Returns True if the IP is now locked out."""
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
            log.warning(
                f"Rate limit: IP {ip} locked out for {lockout}s "
                f"after {entry['count']} failed attempts"
            )
            return True

        _fail_tracker[ip] = entry
        return False


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


def auth_required(f):
    """Decorator that enforces HTTP Basic Auth on a route."""
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

        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            attempted = auth.username if auth else "(none)"
            locked = record_failure(ip)
            log.warning(
                f"Auth failed for user '{attempted}' from {ip}"
                + (" [NOW LOCKED OUT]" if locked else "")
            )
            return Response(
                "Authentication required.\n",
                401,
                {"WWW-Authenticate": 'Basic realm="Generator Control"'},
            )

        # Successful auth -- clear any prior failures for this IP
        record_success(ip)
        return f(*args, **kwargs)
    return decorated

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
app = Flask(__name__)

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
        return jsonify({"success": False, "message": "A relay sequence is already in progress"}), 409
    log.info(f"Start requested by {request.authorization.username} from {request.remote_addr}")
    threading.Thread(target=start_generator, daemon=True).start()
    return jsonify({"success": True, "message": "Start sequence initiated in background"})

@app.route('/api/stop', methods=['POST'])
@auth_required
def api_stop():
    """REST endpoint to stop generator"""
    log.info(f"Stop requested by {request.authorization.username} from {request.remote_addr}")
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
    data = request.get_json() or {}
    running = data.get('running', False)

    with state_lock:
        generator_state["running"] = running
        generator_state["message"] = f"Manually set to {'RUNNING' if running else 'STOPPED'}"

    log.info(f"State manually set to {'RUNNING' if running else 'STOPPED'} by {request.authorization.username}")
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
