# genpi/fuel.py -- Fuel-projection model + low-fuel alerting for GeneratorPi (roadmap #59, Stage 7).
# LAYER 3: depends on genpi.state (the fuel_state/alerts_state model + run-hours helpers + the
# shared _monitor_stop Event + the state._low_fuel_alerted edge flag), genpi.store (durable kv + event
# log + push notify), genpi.config, and genpi.logg. Imported by genpi/__init__.py after state/store.
#
# Linear-drain projection: level = fill_level - drain_rate * (run-hours since the fill). Owns the
# projection helpers (fuel_snapshot_locked / projected_fuel_level_locked), the low-fuel evaluator
# (evaluate_low_fuel -- edge-triggered so ONE push per crossing), the background fuel_monitor_loop
# daemon, and the operator mutators (record_fuel_reading / set_fuel_rate / reset_fuel_rate /
# set_fuel_fill / set_alerts). NONE of these touch the relay -- they only adjust tracked state.
#
# The _low_fuel_alerted edge flag lives in genpi.state (it is reset on stop / server restart alongside
# the running flag); this module reads + writes it as state._low_fuel_alerted (module-qualified) so a
# single binding is shared with the test suite's reset -- a bare global here would rebind a private copy.
#
# Copyright (C) 2026 Chris Neal <https://neal.media> and Alex Neal <https://neal.tools>
# SPDX-License-Identifier: AGPL-3.0-or-later
import time                                  # run-hours-since-fill timing
from .config import CONFIG                   # FUEL_MONITOR_SECONDS cadence
from .logg import log                        # monitor start + low-fuel warnings
from . import state                          # state._low_fuel_alerted is read/written module-qualified
from .state import (                         # the fuel model + run-hours helpers + monitor stop Event
    fuel_state, alerts_state, generator_state, state_lock,
    _live_total_run_hours_locked, _monitor_stop,
)
from . import store                          # push notify is module-qualified (store.send_push_async)
from .store import kv_set, record_event      # durable persistence + event log

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
    do_push = False
    msg_level = 0
    with state_lock:
        # Feature or alerting off -> do nothing (but don't touch the arm flag).
        if not alerts_state.get("fuel_enabled", True) or not alerts_state.get("alerts_on", True):
            return "skip"
        # Not running -> nothing is draining; re-arm for the next real crossing.
        if not generator_state["running"]:
            state._low_fuel_alerted = False
            return "skip"
        level = projected_fuel_level_locked()
        thr = alerts_state.get("alert_threshold", 20)
        if level <= thr and not state._low_fuel_alerted:
            state._low_fuel_alerted = True
            do_push = True
            msg_level = int(round(level))
        elif level > thr + FUEL_ALERT_REARM_MARGIN and state._low_fuel_alerted:
            state._low_fuel_alerted = False
            return "rearm"
        else:
            return "skip"
    # Send OUTSIDE the lock (send_push_async only spawns a thread, but keep the pattern).
    if do_push:
        record_event("fuel", f"Low fuel alert: projected level ~{msg_level}%")
        store.send_push_async(
            "Low fuel", f"Projected level ~{msg_level}% - refuel soon.", tag="lowfuel"
        )
        return "push"
    return "skip"  # pragma: no cover - unreachable: the only branch that exits the `with` block without returning sets do_push=True, so `if do_push` is always True here


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
    level = max(0.0, min(100.0, float(level)))
    with state_lock:
        fuel_state["fill_level"] = level
        fuel_state["fill_run_hours"] = _live_total_run_hours_locked()
        # Refuelling re-arms the low-fuel alert so the next real low crossing pushes.
        state._low_fuel_alerted = False
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
