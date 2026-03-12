from gpiozero import OutputDevice
import logging
import logging.handlers
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

    # Rewrite file to replace plaintext passwords with hashes
    if needs_rewrite:
        ENV_FILE.write_text("\n".join(new_lines) + "\n")
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
# AUTHENTICATION
# ============================================================================
def check_auth(username, password):
    """Verify that the provided username and password are valid."""
    if username not in AUTH_USERS:
        return False
    return check_password_hash(AUTH_USERS[username], password)


def auth_required(f):
    """Decorator that enforces HTTP Basic Auth on a route."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            # Log failed attempts with the username tried (not the password)
            attempted = auth.username if auth else "(none)"
            log.warning(f"Auth failed for user '{attempted}' from {request.remote_addr}")
            return Response(
                "Authentication required.\n",
                401,
                {"WWW-Authenticate": 'Basic realm="Generator Control"'},
            )
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
    """
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


def stop_generator():
    """Stop the generator by simulating stop button press."""
    log.info("Stopping generator")

    with state_lock:
        generator_state["last_command"] = "stop"
        generator_state["running"] = False
        generator_state["last_stop_time"] = datetime.now().isoformat()
        generator_state["message"] = "Stop command sent"

    press_button()

    log.info("Stop button pressed")
    return {"success": True, "message": "Stop button pressed. Generator should be stopping."}

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
    log.info(f"Web server: http://{CONFIG['HOST']}:{CONFIG['PORT']}")
    log.info("=" * 60)

    try:
        app.run(host=CONFIG["HOST"], port=CONFIG["PORT"], debug=False)
    except KeyboardInterrupt:
        log.info("Shutting down...")
    finally:
        relay_start_stop.close()
        log.info("Shutdown complete")

if __name__ == '__main__':
    main()
