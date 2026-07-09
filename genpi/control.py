# genpi/control.py -- Generator start/stop control sequences for GeneratorPi (roadmap #59, Stage 6).
# LAYER 4: depends on genpi.relay (relay_lock + press_button -- the ONLY way this drives hardware),
# genpi.state (the run-hours transition + state_lock/generator_state), genpi.store (durable event
# log + push notify), genpi.config, and genpi.logg. Imported by genpi/__init__.py after relay.
#
# start_generator runs the PM9400E one-touch sequence (prime press -> wait -> start press, with
# optional retries); stop_generator sends a single stop press. Both take relay_lock NON-blocking so
# overlapping requests are rejected rather than racing on the relay, both bank/stamp run-hours via
# state's transition helper under state_lock, and both are reachable ONLY from the authenticated
# POST /api/start | /api/stop routes -- never from any boot/import/monitor path (engine safety).
#
# Copyright (C) 2026 Chris Neal <https://neal.media> and Alex Neal <https://neal.tools>
# SPDX-License-Identifier: AGPL-3.0-or-later
import time                              # inter-press waits in the start sequence
from datetime import datetime            # last_start_time / last_stop_time ISO stamps
from .config import CONFIG               # start-sequence timings + retry count
from .logg import log                    # sequence progress logging
from .relay import relay_lock, press_button                 # the relay lock + the ONLY hardware entry point
from .state import state_lock, generator_state, _apply_running_transition_locked  # tracked run-state
from . import store                                          # push notify is called module-qualified (store.send_push_async)
from .store import record_event                              # durable events

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
        store.send_push_async("Generator started", "Start sequence completed. Verify the unit is running.", tag="state")
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
        store.send_push_async("Generator stopped", "Stop command sent.", tag="state")
        log.info("Stop button pressed")
        return {"success": True, "message": "Stop button pressed. Generator should be stopping."}
    finally:
        relay_lock.release()
