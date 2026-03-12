from gpiozero import OutputDevice
import time
import threading
from flask import Flask, render_template_string, jsonify, request
from datetime import datetime

# ============================================================================
# GPIO PIN CONFIGURATION
# ============================================================================
RELAY_START_STOP_PIN = 27  # GPIO27 -> Relay CH1 (simulates start/stop button)

# ============================================================================
# STATE MACHINE CONFIGURATION
# ============================================================================
MAX_START_RETRIES = 1      # Maximum number of start attempts
BUTTON_PRESS_DURATION = 0.25  # Seconds to hold relay closed (simulating button press)
PRIME_DELAY = .75            # Seconds to wait after first press before second press
RETRY_DELAY = 5            # Seconds between retry attempts

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
relay_start_stop = OutputDevice(RELAY_START_STOP_PIN, active_high=False, initial_value=False)
print(f"[GPIO] Initialized - GPIO{RELAY_START_STOP_PIN} (relay control)")

# ============================================================================
# RELAY CONTROL FUNCTIONS
# ============================================================================
def press_button():
    """Simulate a momentary button press on the generator"""
    print(f"[RELAY] Pressing start/stop button ({BUTTON_PRESS_DURATION}s)")
    relay_start_stop.on()   # Energize relay (closes contacts)
    time.sleep(BUTTON_PRESS_DURATION)
    relay_start_stop.off()  # De-energize relay (opens contacts)
    time.sleep(0.1)  # Small debounce delay

# ============================================================================
# GENERATOR CONTROL LOGIC
# ============================================================================
def start_generator():
    """
    Start the generator with PM9400E one-touch sequence:
    1. Press once to prime
    2. Wait for prime delay
    3. Press again to start
    4. Repeat if specified retries
    """
    with state_lock:
        if generator_state["running"]:
            return {"success": False, "message": "Generator already marked as running"}

        generator_state["last_command"] = "start"
        generator_state["start_attempts"] = 0

    print("[START] Initiating generator start sequence")

    for attempt in range(1, MAX_START_RETRIES + 1):
        with state_lock:
            generator_state["start_attempts"] = attempt
            generator_state["message"] = f"Start attempt {attempt}/{MAX_START_RETRIES}"

        print(f"[START] Attempt {attempt}/{MAX_START_RETRIES}")

        # PM9400E sequence: prime press
        print("[START] Pressing button to prime")
        press_button()

        # Wait for prime/auto-choke
        print(f"[START] Waiting {PRIME_DELAY}s for prime...")
        time.sleep(PRIME_DELAY)

        # PM9400E sequence: start press
        print("[START] Pressing button to start")
        press_button()

        # Set timestamp
        with state_lock:
            generator_state["last_start_time"] = datetime.now().isoformat()

        print(f"[START] Start sequence {attempt} completed")

        if attempt < MAX_START_RETRIES:
            print(f"[START] Waiting {RETRY_DELAY}s before next attempt...")
            time.sleep(RETRY_DELAY)

    # Mark as running after all attempts (assume success)
    with state_lock:
        generator_state["running"] = True
        generator_state["message"] = (
            f"Start sequence completed ({MAX_START_RETRIES} attempts). "
            "Verify generator manually."
        )

    print("[START] Start sequence finished. Check generator status manually.")
    return {
        "success": True,
        "message": (
            f"Start sequence completed ({MAX_START_RETRIES} attempts). "
            "Please verify generator is running."
        ),
    }

def stop_generator():
    """Stop the generator by simulating stop button press"""
    print("[STOP] Stopping generator")

    with state_lock:
        generator_state["last_command"] = "stop"
        generator_state["running"] = False
        generator_state["last_stop_time"] = datetime.now().isoformat()
        generator_state["message"] = "Stop command sent"

    # Single press stops the generator
    press_button()

    print("[STOP] Stop button pressed")
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
def index():
    """Web UI homepage"""
    with state_lock:
        status = generator_state.copy()
    return render_template_string(HTML_TEMPLATE, status=status)

@app.route('/api/start', methods=['POST'])
def api_start():
    """REST endpoint to start generator"""
    threading.Thread(target=start_generator, daemon=True).start()
    return jsonify({"success": True, "message": "Start sequence initiated in background"})

@app.route('/api/stop', methods=['POST'])
def api_stop():
    """REST endpoint to stop generator"""
    result = stop_generator()
    return jsonify(result)

@app.route('/api/status', methods=['GET'])
def api_status():
    """REST endpoint for integrations"""
    with state_lock:
        status = generator_state.copy()
    return jsonify(status)

@app.route('/api/set_running', methods=['POST'])
def api_set_running():
    """Manual override to set running state (for manual verification)"""
    data = request.get_json() or {}
    running = data.get('running', False)

    with state_lock:
        generator_state["running"] = running
        generator_state["message"] = f"Manually set to {'RUNNING' if running else 'STOPPED'}"

    return jsonify({"success": True, "running": running})

# ============================================================================
# MAIN
# ============================================================================
def main():
    """Main entry point"""
    print("=" * 60)
    print("Powermate PM9400E Remote Start Controller")
    print("Using gpiozero library")
    print("=" * 60)

    print(f"[CONFIG] Relay control: GPIO{RELAY_START_STOP_PIN}")
    print(f"[CONFIG] Max start retries: {MAX_START_RETRIES}")
    print(f"[CONFIG] Prime delay: {PRIME_DELAY}s")
    print(f"[CONFIG] Starting web server on http://0.0.0.0:9400")
    print("[CONFIG] Manual status tracking (no auto-detect)")
    print("=" * 60)

    try:
        app.run(host='0.0.0.0', port=9400, debug=False)
    except KeyboardInterrupt:
        print("\n[SHUTDOWN] Cleaning up...")
    finally:
        relay_start_stop.close()
        print("[SHUTDOWN] Done")

if __name__ == '__main__':
    main()
