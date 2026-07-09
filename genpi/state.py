# genpi/state.py -- In-memory application state for GeneratorPi (roadmap #59, Stage 4). LAYER 2:
# depends on genpi.store (kv_get/kv_set for durable persistence) + genpi.logg (log) + the stdlib,
# and on nothing else in the package. Imported by genpi/__init__.py AFTER store, because state's
# load_persisted_state / run-hours accounting read+write the kv store. Nothing in store reads
# state, so the dependency is one-way (acyclic).
#
# Owns: generator_state (manual running flag + the lifetime run-hours odometer), the fuel-
# projection model (fuel_state) + its default drain rate, the low-fuel alert config (alerts_state)
# + the low-fuel edge-trigger flag (_low_fuel_alerted), the fuel-monitor stop Event (_monitor_stop),
# the single coarse state_lock guarding them, the run-hours accounting helpers
# (_live_total_run_hours_locked / _apply_running_transition_locked), and set_total_run_hours (the
# manual odometer correction that NEVER touches the relay). Importing this module restores durable
# state from the kv store (load_persisted_state() at the bottom), exactly as the old single file did
# at this point in startup.
#
# Copyright (C) 2026 Chris Neal <https://neal.media> and Alex Neal <https://neal.tools>
# SPDX-License-Identifier: AGPL-3.0-or-later
import time                        # run-hours accounting + current-run clock
import threading                   # state_lock + the fuel-monitor stop Event
from .logg import log              # startup "Restored state" line + corrupt-odometer CRITICAL log
from .store import kv_get, kv_set  # durable persistence of the odometer + fuel model + alerts

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


# Sanity ceiling for a MANUALLY-set lifetime odometer. The analog odometer display
# saturates at 9999.9 h and storage above that is harmless, but an absurd value (a
# fat-fingered paste, or abuse) is rejected outright. A real generator's lifetime is
# orders of magnitude below this, so the cap only ever trips on garbage.
MAX_TOTAL_RUN_HOURS = 1_000_000.0


def set_total_run_hours(hours):
    """Manually override the lifetime run-hours odometer and persist it. This is a
    TRACKED-STATE correction only (like MARK RUNNING) -- it NEVER touches the relay or
    the generator. Clamps to [0, MAX_TOTAL_RUN_HOURS], rounds to 3 decimals, and returns
    (old_live_total, new_total) for the audit log.

    Two invariants are held under a single state_lock:

      * The LIVE odometer (base + current-run elapsed) reads EXACTLY `hours` the instant
        this returns. If a run is in progress we re-stamp current_run_started_at to now,
        so the persisted base is ALWAYS the non-negative value the operator entered --
        never a transient negative that a mid-run restart could persist. The consequence
        is that the current run's uptime clock restarts from 0; that is intentional (the
        baseline is being redefined), and the helper copy advises setting it while stopped.

      * The FUEL gauge does NOT lurch. fuel_state['fill_run_hours'] is an absolute point
        on this same odometer, so the projection's run-since-fill = live - fill_run_hours
        would jump if we moved the odometer alone. We shift fill_run_hours by the same
        delta (clamped >= 0) so the PHYSICAL run-hours-since-fill -- and thus the projected
        tank level -- is preserved across the correction.
    """
    # Clamp + quantize BEFORE taking the lock (pure arithmetic; keep the lock section tiny).
    hours = round(max(0.0, min(MAX_TOTAL_RUN_HOURS, float(hours))), 3)
    with state_lock:
        # Snapshot the physical run-hours-since-fill the fuel model depends on, using the
        # live total (base + any in-progress run) so a running engine is accounted for.
        old_live = _live_total_run_hours_locked()
        run_since_fill = max(0.0, old_live - fuel_state["fill_run_hours"])
        # Set the lifetime base to exactly the requested value.
        generator_state["total_run_hours"] = hours
        if generator_state["running"]:
            # Re-baseline the in-progress run to NOW: live == hours immediately, and the
            # banked base stays == hours (non-negative, restart-safe). Uptime resets to 0.
            generator_state["current_run_started_at"] = time.time()
        # Re-anchor the fuel fill so run-since-fill (hence the projected level) is unchanged.
        # Clamp >= 0 so a very small `hours` (below run_since_fill) can't store a negative
        # fill mark; in that corner the gauge shifts rather than going nonsensical.
        fuel_state["fill_run_hours"] = max(0.0, hours - run_since_fill)
        fuel_snapshot = dict(fuel_state)
        # Persist BOTH mutated stores IN-LOCK so an overlapping writer can't race a stale
        # snapshot to the kv store (same atomicity + lock-order rationale as the fuel
        # helpers: the only ordering that ever occurs is state_lock -> _event_lock, so
        # there is no inversion and no deadlock).
        kv_set("total_run_hours", generator_state["total_run_hours"])
        kv_set("fuel_state", fuel_snapshot)
    return old_live, hours


# Restore durable state now that the kv store + these globals exist.
load_persisted_state()
