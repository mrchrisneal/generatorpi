# genpi/relay.py -- GPIO relay control for GeneratorPi (roadmap #59, Stage 6). LAYER 3: depends on
# genpi.config (RELAY_PIN + BUTTON_PRESS_DURATION), genpi.logg (log), and gpiozero. Imported by
# genpi/__init__.py before control; the generator start/stop sequences (genpi.control) drive the
# relay exclusively through press_button() here.
#
# 🚨 HARDWARE SAFETY (unchanged from the single-file original -- this is a pure relocation):
#   * The relay is created DE-ENERGIZED: OutputDevice(..., active_high=False, initial_value=False).
#     It is NEVER energized at import / boot -- only press_button() ever calls .on().
#   * press_button() de-energizes the relay in a `finally` on EVERY exit path (even a
#     KeyboardInterrupt/SystemExit mid-sleep), so the physical button is never left held DOWN.
#   * relay_lock serializes relay sequences so two requests can't overlap on the hardware.
# In the test suite gpiozero is a MagicMock (registered in sys.modules by tests/conftest.py before
# import), so no pin is ever driven; on the Pi this is the one real GPIO handle.
#
# Copyright (C) 2026 Chris Neal <https://neal.media> and Alex Neal <https://neal.tools>
# SPDX-License-Identifier: AGPL-3.0-or-later
import time                         # button-press duration + debounce sleeps
import threading                    # relay_lock serializes overlapping sequences
from gpiozero import OutputDevice   # the physical relay handle (MagicMock under test)
from .config import CONFIG          # RELAY_PIN + BUTTON_PRESS_DURATION
from .logg import log               # GPIO-init + press-button debug lines

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
