# test_runtime_accounting.py -- lifetime run-hours accounting.
#
# The odometer/uptime feature tracks cumulative engine run-time. Two helpers do
# the arithmetic (both require the caller to hold state_lock):
#   _apply_running_transition_locked(new_running) -- on start stamps the run's
#       start time; on stop folds the just-finished run's elapsed hours into the
#       persisted total_run_hours and clears the run clock. Idempotent.
#   _live_total_run_hours_locked() -- the persisted base PLUS the in-progress
#       run's elapsed time (while running), so projections tick in real time.
#
# time.time() is monkeypatched to a controllable value so elapsed intervals are
# exact and deterministic. The three real callers (POST /api/set_running true/
# false and stop_generator via POST /api/stop) are exercised end-to-end to prove
# they wire into the accounting helper. Persistence-touching cases use tmp_store.
import pytest


API_KEY = "runtime-accounting-test-key"


@pytest.fixture(autouse=True)
def _configure_api_key(module):
    """Working API key for the @auth_required endpoints exercised here."""
    module.CONFIG["API_KEY"] = API_KEY


def _q(path):
    """Append the API key as a query param to authorize the request."""
    sep = "&" if "?" in path else "?"
    return f"{path}{sep}key={API_KEY}"


@pytest.fixture
def tmp_store(module, tmp_path):
    """Redirect the shared event/kv store to a throwaway DB for the duration of a
    test, then restore the default on-disk store afterwards. Required for any test
    that asserts a kv_set persist (run-hours banking persists total_run_hours)."""
    module.init_event_store(db_path=tmp_path / "t.db")
    yield
    module.init_event_store()


@pytest.fixture
def fixed_time(module, monkeypatch):
    """Pin module.time.time() to a mutable clock the test can advance. Returns the
    dict; set clock['now'] to move time forward. _apply_running_transition_locked
    and _live_total_run_hours_locked both read time.time(), so this makes elapsed
    intervals exact."""
    clock = {"now": 1_000_000.0}
    monkeypatch.setattr(module.time, "time", lambda: clock["now"])
    return clock


# ---------------------------------------------------------------------------
# _apply_running_transition_locked
# ---------------------------------------------------------------------------
class TestApplyRunningTransition:
    def test_start_stamps_started_and_does_not_change_total(self, module, fixed_time):
        # Stopped -> running: current_run_started_at is stamped with "now"; the
        # persisted total is untouched (nothing has elapsed yet).
        assert module.generator_state["running"] is False
        with module.state_lock:
            module._apply_running_transition_locked(True)
        assert module.generator_state["running"] is True
        assert module.generator_state["current_run_started_at"] == 1_000_000.0
        assert module.generator_state["total_run_hours"] == 0.0

    def test_stop_banks_elapsed_and_clears_and_persists(
        self, module, fixed_time, tmp_store
    ):
        # Running for exactly one hour, then stopped: +1.0 h banked, run clock
        # cleared, and the new lifetime total PERSISTED to the kv store.
        with module.state_lock:
            module._apply_running_transition_locked(True)     # start at T
        fixed_time["now"] += 3600.0                            # advance one hour
        with module.state_lock:
            module._apply_running_transition_locked(False)     # stop at T+3600
        assert module.generator_state["total_run_hours"] == pytest.approx(1.0)
        assert module.generator_state["current_run_started_at"] is None
        assert module.generator_state["running"] is False
        # Banking calls kv_set("total_run_hours", ...); confirm it was persisted.
        assert module.kv_get("total_run_hours") == pytest.approx(1.0)

    def test_stop_adds_to_existing_base(self, module, fixed_time, tmp_store):
        # A pre-existing base accumulates rather than being overwritten.
        with module.state_lock:
            module.generator_state["total_run_hours"] = 2.5
            module._apply_running_transition_locked(True)
        fixed_time["now"] += 1800.0                            # half an hour
        with module.state_lock:
            module._apply_running_transition_locked(False)
        assert module.generator_state["total_run_hours"] == pytest.approx(3.0)

    def test_reasserting_running_is_idempotent(self, module, fixed_time):
        # Re-asserting RUNNING while already running must NOT move the start time
        # or double-count -- the start stamp is preserved and total stays put.
        with module.state_lock:
            module._apply_running_transition_locked(True)
        started = module.generator_state["current_run_started_at"]
        fixed_time["now"] += 5000.0
        with module.state_lock:
            module._apply_running_transition_locked(True)      # still running
        assert module.generator_state["current_run_started_at"] == started
        assert module.generator_state["total_run_hours"] == 0.0

    def test_reasserting_stopped_is_idempotent(self, module, fixed_time):
        # Re-asserting STOPPED while already stopped is a no-op: no negative time,
        # no spurious banking (current_run_started_at is None so nothing is added).
        with module.state_lock:
            module._apply_running_transition_locked(False)
        assert module.generator_state["running"] is False
        assert module.generator_state["total_run_hours"] == 0.0
        assert module.generator_state["current_run_started_at"] is None


# ---------------------------------------------------------------------------
# _live_total_run_hours_locked
# ---------------------------------------------------------------------------
class TestLiveTotalRunHours:
    def test_while_running_returns_base_plus_elapsed(self, module, fixed_time):
        # Running: live total = base + (now - started)/3600.
        with module.state_lock:
            module.generator_state["total_run_hours"] = 2.0
            module.generator_state["running"] = True
            module.generator_state["current_run_started_at"] = fixed_time["now"]
            fixed_time["now"] += 3600.0                        # +1 h in progress
            live = module._live_total_run_hours_locked()
        assert live == pytest.approx(3.0)

    def test_while_stopped_returns_base(self, module, fixed_time):
        # Stopped: no in-progress run, so live total equals the stored base.
        with module.state_lock:
            module.generator_state["total_run_hours"] = 4.25
            module.generator_state["running"] = False
            module.generator_state["current_run_started_at"] = None
            live = module._live_total_run_hours_locked()
        assert live == pytest.approx(4.25)

    def test_running_but_no_start_stamp_returns_base(self, module, fixed_time):
        # Defensive: flagged running with a None start stamp must not crash and
        # simply returns the base (no elapsed can be computed).
        with module.state_lock:
            module.generator_state["total_run_hours"] = 1.0
            module.generator_state["running"] = True
            module.generator_state["current_run_started_at"] = None
            live = module._live_total_run_hours_locked()
        assert live == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# Real callers wire into the accounting helper
# ---------------------------------------------------------------------------
class TestCallersWireIntoAccounting:
    def test_set_running_true_stamps_and_marks_run(self, client, module, fixed_time):
        # POST /api/set_running {running:true} must stamp a start time (via the
        # transition helper) and set last_command to "mark_run".
        resp = client.post(_q("/api/set_running"), json={"running": True})
        assert resp.status_code == 200
        assert module.generator_state["current_run_started_at"] == 1_000_000.0
        assert module.generator_state["last_command"] == "mark_run"

    def test_set_running_false_marks_stop(self, client, module, fixed_time, tmp_store):
        # POST /api/set_running {running:false} must set last_command "mark_stop".
        # Start from RUNNING so the transition actually banks + clears the clock.
        with module.state_lock:
            module.generator_state["running"] = True
            module.generator_state["current_run_started_at"] = fixed_time["now"]
        resp = client.post(_q("/api/set_running"), json={"running": False})
        assert resp.status_code == 200
        assert module.generator_state["last_command"] == "mark_stop"
        assert module.generator_state["current_run_started_at"] is None

    def test_set_running_true_then_false_banks_hours(
        self, client, module, fixed_time, tmp_store
    ):
        # Full manual run through the endpoint: mark run, advance an hour, mark
        # stop -> +1.0 h banked into the lifetime total.
        client.post(_q("/api/set_running"), json={"running": True})
        fixed_time["now"] += 3600.0
        client.post(_q("/api/set_running"), json={"running": False})
        assert module.generator_state["total_run_hours"] == pytest.approx(1.0)

    def test_stop_generator_banks_hours(
        self, client, module, fixed_time, tmp_store, no_sleep
    ):
        # stop_generator() (via POST /api/stop) banks the in-progress run. Set up a
        # run that started one hour ago, then stop. no_sleep keeps press_button
        # instant; the relay is a MagicMock so nothing physical happens.
        with module.state_lock:
            module.generator_state["running"] = True
            module.generator_state["current_run_started_at"] = fixed_time["now"]
        fixed_time["now"] += 3600.0
        resp = client.post(_q("/api/stop"))
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True
        assert module.generator_state["running"] is False
        assert module.generator_state["total_run_hours"] == pytest.approx(1.0)
        assert module.generator_state["current_run_started_at"] is None
        assert module.kv_get("total_run_hours") == pytest.approx(1.0)
