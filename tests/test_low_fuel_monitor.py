# test_low_fuel_monitor.py -- the edge-triggered low-fuel push logic
# (evaluate_low_fuel) and the fuel_enabled master toggle that gates the whole fuel
# feature.
#
# evaluate_low_fuel() is what actually decides whether a "Low fuel" push fires. It is
# EDGE-triggered via the module global _low_fuel_alerted: exactly one push per
# below-threshold crossing, re-arming only after the level climbs back above
# threshold + FUEL_ALERT_REARM_MARGIN, on refuel, or when the engine stops. It returns
# a string action ('push' | 'rearm' | 'skip') purely for logging/tests.
#
# We drive it DIRECTLY (never via the real 60s monitor loop) and make the projected
# level fully deterministic:
#   projected = clamp0..100(fill_level - drain_rate * (live_run_hours - fill_run_hours))
# By setting running=True but current_run_started_at=None, live_run_hours collapses to
# total_run_hours (no wall-clock term), so with total_run_hours == fill_run_hours the
# projected level is exactly fill_level -- we then steer the projection just by setting
# fill_level. send_push_async is patched everywhere so no real push is ever dispatched.
import pytest


API_KEY = "lowfuel-test-key"


@pytest.fixture(autouse=True)
def _configure_api_key(module):
    """/api/alerts + /api/state are @auth_required; give them a working key."""
    module.CONFIG["API_KEY"] = API_KEY


def _q(path):
    """Append the API key as a query param to authorize the request."""
    sep = "&" if "?" in path else "?"
    return f"{path}{sep}key={API_KEY}"


@pytest.fixture
def tmp_store(module, tmp_path):
    """Redirect the event/kv store to a throwaway DB (evaluate_low_fuel records a "fuel"
    event + persistence is exercised), then restore the default store afterwards."""
    module.init_event_store(db_path=tmp_path / "t.db")
    yield
    module.init_event_store()


@pytest.fixture
def record_async(module, monkeypatch):
    """Patch send_push_async to record calls instead of dispatching a real push."""
    calls = []
    monkeypatch.setattr(module, "send_push_async",
                        lambda *a, **k: calls.append((a, k)))
    return calls


def _set_projection(module, fill_level, running=True, drain_rate=0.1):
    """Pin the fuel projection to `fill_level` deterministically.

    Setting current_run_started_at=None removes the wall-clock term from live run-hours,
    and total_run_hours == fill_run_hours makes run-hours-since-fill zero, so
    projected == fill_level regardless of drain_rate. Lets a test choose "above" or
    "below" the alert threshold precisely, with no clock dependence.
    """
    with module.state_lock:
        module.generator_state["running"] = running
        module.generator_state["current_run_started_at"] = None
        module.generator_state["total_run_hours"] = 0.0
        module.fuel_state["fill_level"] = float(fill_level)
        module.fuel_state["fill_run_hours"] = 0.0
        module.fuel_state["drain_rate"] = float(drain_rate)


# ---------------------------------------------------------------------------
# evaluate_low_fuel -- the edge-trigger core
# ---------------------------------------------------------------------------
class TestEvaluateLowFuelEdge:
    def test_first_crossing_pushes_then_second_call_skips(
        self, module, tmp_store, record_async
    ):
        # Default threshold is 20. Projected 10 (<=20) with the arm flag clear -> "push".
        _set_projection(module, fill_level=10)
        assert module.evaluate_low_fuel() == "push"
        assert len(record_async) == 1
        assert module._low_fuel_alerted is True

        # Still below threshold, but already alerted for THIS crossing -> "skip", no
        # second push (edge-trigger, not level-trigger).
        assert module.evaluate_low_fuel() == "skip"
        assert len(record_async) == 1

    def test_rearm_then_next_low_crossing_pushes_again(
        self, module, tmp_store, record_async
    ):
        # Cross low -> push + arm.
        _set_projection(module, fill_level=10)
        assert module.evaluate_low_fuel() == "push"
        assert len(record_async) == 1

        # Climb back ABOVE threshold + margin (20 + 5 = 25); 30 clears the arm -> "rearm".
        _set_projection(module, fill_level=30)
        assert module.evaluate_low_fuel() == "rearm"
        assert module._low_fuel_alerted is False
        assert len(record_async) == 1  # rearm does not push

        # A fresh low crossing after re-arming pushes again.
        _set_projection(module, fill_level=8)
        assert module.evaluate_low_fuel() == "push"
        assert len(record_async) == 2

    def test_within_hysteresis_band_does_not_rearm(
        self, module, tmp_store, record_async
    ):
        # After alerting, a level between threshold and threshold+margin (e.g. 23, in the
        # 20..25 band) is NOT enough to re-arm -> "skip", arm flag stays set, no push.
        _set_projection(module, fill_level=10)
        assert module.evaluate_low_fuel() == "push"
        _set_projection(module, fill_level=23)
        assert module.evaluate_low_fuel() == "skip"
        assert module._low_fuel_alerted is True
        assert len(record_async) == 1

    def test_at_threshold_boundary_pushes(self, module, tmp_store, record_async):
        # The comparison is `level <= thr`, so a projection sitting exactly on the
        # threshold (20) still counts as low and pushes.
        _set_projection(module, fill_level=20)
        assert module.evaluate_low_fuel() == "push"
        assert len(record_async) == 1


# ---------------------------------------------------------------------------
# evaluate_low_fuel -- the gates (feature off / alerts off / not running)
# ---------------------------------------------------------------------------
class TestEvaluateLowFuelGates:
    def test_skip_when_fuel_feature_disabled(self, module, tmp_store, record_async):
        # fuel_enabled=False gates the ENTIRE feature -> skip even when projected is low.
        _set_projection(module, fill_level=5)
        with module.state_lock:
            module.alerts_state["fuel_enabled"] = False
        assert module.evaluate_low_fuel() == "skip"
        assert len(record_async) == 0

    def test_skip_when_alerts_off(self, module, tmp_store, record_async):
        # alerts_on=False disables just the low-fuel alerting within the feature.
        _set_projection(module, fill_level=5)
        with module.state_lock:
            module.alerts_state["alerts_on"] = False
        assert module.evaluate_low_fuel() == "skip"
        assert len(record_async) == 0

    def test_not_running_skips_and_clears_arm_flag(
        self, module, tmp_store, record_async
    ):
        # When the engine isn't running, nothing is draining: skip AND re-arm (clear the
        # flag) so the next real run's first low crossing fires cleanly.
        module._low_fuel_alerted = True  # pretend a prior crossing armed it
        _set_projection(module, fill_level=5, running=False)
        assert module.evaluate_low_fuel() == "skip"
        assert module._low_fuel_alerted is False
        assert len(record_async) == 0

    def test_disabled_gate_does_not_touch_arm_flag(
        self, module, tmp_store, record_async
    ):
        # The feature/alerts-off gate returns BEFORE the running/arm logic, so it must
        # leave a previously-set arm flag untouched (only the not-running path clears it).
        module._low_fuel_alerted = True
        _set_projection(module, fill_level=5)
        with module.state_lock:
            module.alerts_state["fuel_enabled"] = False
        assert module.evaluate_low_fuel() == "skip"
        assert module._low_fuel_alerted is True


# ---------------------------------------------------------------------------
# Refuel re-arms the low-fuel alert
# ---------------------------------------------------------------------------
class TestRefuelRearm:
    def test_set_fuel_fill_clears_arm_flag(self, module, tmp_store):
        # "Add gas" must re-arm the alert so the next low crossing on the fresh tank pushes.
        module._low_fuel_alerted = True
        module.set_fuel_fill(100.0)
        assert module._low_fuel_alerted is False

    def test_refuel_then_low_pushes_again(self, module, tmp_store, record_async):
        # End-to-end: low -> push -> refuel (re-arms) -> drop low again -> pushes again.
        _set_projection(module, fill_level=10)
        assert module.evaluate_low_fuel() == "push"
        assert len(record_async) == 1

        module.set_fuel_fill(100.0)          # re-arms
        assert module._low_fuel_alerted is False

        _set_projection(module, fill_level=9)
        assert module.evaluate_low_fuel() == "push"
        assert len(record_async) == 2


# ---------------------------------------------------------------------------
# fuel_monitor_loop -- the background daemon that drives evaluate_low_fuel
# ---------------------------------------------------------------------------
class _FakeStop:
    """Stand-in for the module's threading.Event stop flag. .wait(interval) returns the
    scripted sequence of booleans (False = keep looping, True = stop), so we can run the
    monitor loop for an exact, finite number of iterations without any real sleeping."""

    def __init__(self, sequence):
        self._seq = list(sequence)

    def wait(self, interval):
        # Pop the next scripted result; once exhausted, always stop (defensive).
        return self._seq.pop(0) if self._seq else True


class TestFuelMonitorLoop:
    def test_loop_evaluates_each_tick_then_stops(self, module, monkeypatch):
        # wait() yields False, False, True -> the loop body runs evaluate_low_fuel twice
        # then the stop flag ends it. No real interval elapses.
        calls = []
        monkeypatch.setattr(module, "evaluate_low_fuel", lambda: calls.append(1))
        monkeypatch.setattr(module, "_monitor_stop",
                            _FakeStop([False, False, True]))
        module.fuel_monitor_loop()
        assert len(calls) == 2

    def test_loop_swallows_evaluate_exceptions(self, module, monkeypatch):
        # An exception inside a tick is caught + logged, and the loop keeps running to
        # the next wait() -- one bad evaluation must never kill the monitor thread.
        def boom():
            raise RuntimeError("boom")

        monkeypatch.setattr(module, "evaluate_low_fuel", boom)
        monkeypatch.setattr(module, "_monitor_stop", _FakeStop([False, True]))
        # Must complete without propagating the RuntimeError.
        module.fuel_monitor_loop()


# ---------------------------------------------------------------------------
# fuel_enabled toggle -- set_alerts + /api/alerts + state exposure
# ---------------------------------------------------------------------------
class TestFuelEnabledToggle:
    def test_set_alerts_fuel_enabled_only(self, module, tmp_store):
        # fuel_enabled is settable on its own; the other fields stay put.
        with module.state_lock:
            module.alerts_state["alerts_on"] = True
            module.alerts_state["alert_threshold"] = 25
        snap = module.set_alerts(fuel_enabled=False)
        assert snap["fuel_enabled"] is False
        assert snap["alerts_on"] is True         # untouched
        assert snap["alert_threshold"] == 25     # untouched

    def test_endpoint_persists_fuel_enabled_false(self, client, module, tmp_store):
        # POST /api/alerts {fuel_enabled:false} persists to the kv store.
        resp = client.post(_q("/api/alerts"), json={"fuel_enabled": False})
        assert resp.status_code == 200
        assert resp.get_json()["alerts"]["fuel_enabled"] is False
        assert module.kv_get("alerts_state")["fuel_enabled"] is False

    @pytest.mark.parametrize("raw,expected", [
        (True, True), (False, False),
        ("true", True), ("false", False),
        ("1", True), ("0", False),
        ("yes", True), ("no", False),
        ("on", True), ("off", False),
        ("garbage", False),
    ])
    def test_endpoint_coerces_fuel_enabled(
        self, client, module, tmp_store, raw, expected
    ):
        # Same bool/string coercion the `enabled` field gets -- only the recognized
        # truthy forms map to True; anything else is False.
        resp = client.post(_q("/api/alerts"), json={"fuel_enabled": raw})
        assert resp.status_code == 200
        assert resp.get_json()["alerts"]["fuel_enabled"] is expected

    def test_state_exposes_fuel_enabled_top_level_and_nested(
        self, client, module, tmp_store
    ):
        # /api/state exposes fuel_enabled BOTH at the top level and inside "alerts".
        module.set_alerts(fuel_enabled=False)
        resp = client.get(_q("/api/state"))
        assert resp.status_code == 200
        state = resp.get_json()
        assert state["fuel_enabled"] is False
        assert state["alerts"]["fuel_enabled"] is False

    def test_state_fuel_enabled_defaults_true(self, client, module, tmp_store):
        # Default (baseline) is fuel_enabled True in both places.
        resp = client.get(_q("/api/state"))
        state = resp.get_json()
        assert state["fuel_enabled"] is True
        assert state["alerts"]["fuel_enabled"] is True
