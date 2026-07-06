# test_backend_robustness.py -- backend robustness / safety guarantees that don't
# fit neatly into the feature-oriented suites:
#
#   1. press_button relay safety -- the physical start/stop relay MUST be
#      de-energized even if an exception fires mid-press (the try/finally guard),
#      so a crash while the button is "held" can never leave it held.
#   2. load_persisted_state corruption guard -- a non-numeric persisted
#      total_run_hours (e.g. a hand-corrupted "abc") must NOT crash startup, must
#      keep the in-memory default, and must log LOUDLY (never silently zero the
#      lifetime odometer).
#   3. fuel-mutator persistence atomicity -- after moving each kv_set INSIDE
#      state_lock, the kv snapshot must still equal the in-memory state (persistence
#      keeps working; the in-lock write is the atomicity fix, not a behavior change).
#
# Reuses the shared conftest fixtures (module, no_sleep) plus the tmp_store helper
# copied from test_fuel.py so persistence assertions hit a throwaway DB.
import logging

import pytest


# ---------------------------------------------------------------------------
# Local fixtures (mirrors of test_fuel.py's -- kept local so this file stands alone)
# ---------------------------------------------------------------------------
@pytest.fixture
def tmp_store(module, tmp_path):
    """Redirect the shared event/kv store to a throwaway DB so persistence + event
    assertions are hermetic, then restore the default store afterwards."""
    module.init_event_store(db_path=tmp_path / "t.db")
    yield
    module.init_event_store()


# ---------------------------------------------------------------------------
# Fix 1 -- press_button ALWAYS de-energizes the relay (hardware safety)
# ---------------------------------------------------------------------------
class TestPressButtonRelaySafety:
    def test_off_called_after_on_normal_path(self, module, no_sleep):
        # Happy path: on() then off() both run, in order, on a clean press.
        relay = module.relay_start_stop
        relay.reset_mock()
        module.press_button()
        # Both energize and de-energize happened...
        assert relay.on.called
        assert relay.off.called
        # ...and on() preceded off() (energize before de-energize).
        order = [c[0] for c in relay.method_calls]
        assert order.index("on") < order.index("off")

    def test_off_called_even_when_sleep_raises(self, module, monkeypatch):
        # HARDWARE SAFETY: if time.sleep raises mid-press (simulating a crash/signal
        # between on() and off()), the try/finally must STILL de-energize the relay,
        # and the exception must propagate to the caller (it isn't swallowed).
        relay = module.relay_start_stop
        relay.reset_mock()

        # Make the FIRST sleep call (the button-hold) raise. Using a one-shot flag so
        # only the in-press sleep blows up, not any later debounce sleep.
        state = {"raised": False}

        def boom(*a, **k):
            if not state["raised"]:
                state["raised"] = True
                raise RuntimeError("simulated crash during button hold")
            return None

        monkeypatch.setattr(module.time, "sleep", boom)

        with pytest.raises(RuntimeError, match="simulated crash during button hold"):
            module.press_button()

        # The relay was energized...
        assert relay.on.called
        # ...and CRITICALLY was de-energized despite the exception (finally ran).
        assert relay.off.called, "relay.off() MUST run even when the press raises"


# ---------------------------------------------------------------------------
# Fix 3 -- load_persisted_state must NOT silently lose the odometer total
# ---------------------------------------------------------------------------
class TestLoadPersistedStateGuard:
    def test_corrupt_total_run_hours_keeps_default_and_logs_loud(
        self, module, tmp_store, caplog
    ):
        # A persisted total_run_hours that is valid JSON but non-numeric (a
        # hand-corrupted "abc") must NOT crash load_persisted_state.
        module.kv_set("total_run_hours", "not-a-number")
        # Establish a known in-memory default we can assert is preserved.
        with module.state_lock:
            module.generator_state["total_run_hours"] = 0.0

        with caplog.at_level(logging.CRITICAL):
            # Must not raise.
            module.load_persisted_state()

        # The in-memory default is KEPT (never silently zeroed to a bogus value).
        with module.state_lock:
            assert module.generator_state["total_run_hours"] == pytest.approx(0.0)

        # And the failure was logged LOUDLY (ERROR/CRITICAL) so it's impossible to
        # miss -- with the corrupt repr and a pointer to events.db.
        loud = [
            r for r in caplog.records
            if r.levelno >= logging.ERROR
            and "total_run_hours" in r.getMessage()
        ]
        assert loud, "a corrupt total_run_hours must log at ERROR/CRITICAL"
        assert "'not-a-number'" in loud[0].getMessage()
        assert "events.db" in loud[0].getMessage()

    def test_valid_total_run_hours_is_restored(self, module, tmp_store, caplog):
        # Happy path: a valid persisted float is restored into memory, no loud log.
        module.kv_set("total_run_hours", 12.5)
        with module.state_lock:
            module.generator_state["total_run_hours"] = 0.0

        with caplog.at_level(logging.ERROR):
            module.load_persisted_state()

        with module.state_lock:
            assert module.generator_state["total_run_hours"] == pytest.approx(12.5)
        # No ERROR/CRITICAL about the odometer on the happy path.
        assert not [
            r for r in caplog.records
            if r.levelno >= logging.ERROR and "total_run_hours" in r.getMessage()
        ]

    def test_numeric_string_total_run_hours_is_restored(
        self, module, tmp_store, caplog
    ):
        # float() accepts a numeric STRING -- this is a valid (not corrupt) value and
        # must be restored, not flagged. Guards against an over-eager guard that would
        # reject legitimate numeric-string persistence.
        module.kv_set("total_run_hours", "7.25")
        with module.state_lock:
            module.generator_state["total_run_hours"] = 0.0

        with caplog.at_level(logging.ERROR):
            module.load_persisted_state()

        with module.state_lock:
            assert module.generator_state["total_run_hours"] == pytest.approx(7.25)
        assert not [
            r for r in caplog.records
            if r.levelno >= logging.ERROR and "total_run_hours" in r.getMessage()
        ]


# ---------------------------------------------------------------------------
# Fix 2 -- fuel mutators still persist after moving kv_set inside state_lock
# ---------------------------------------------------------------------------
# A true race can't be reproduced deterministically, so we assert the observable
# invariant the atomicity change must preserve: after each mutator returns, the kv
# snapshot equals the in-memory state (the persist happened and matches memory).
class TestFuelMutatorPersistenceAtomicity:
    def test_set_fuel_rate_persists_matches_memory(self, module, tmp_store):
        module.set_fuel_rate(4.2)
        persisted = module.kv_get("fuel_state")
        with module.state_lock:
            in_memory = dict(module.fuel_state)
        assert persisted == in_memory
        assert persisted["drain_rate"] == pytest.approx(4.2)

    def test_reset_fuel_rate_persists_matches_memory(self, module, tmp_store):
        # Move it off-default first so the reset is observable.
        module.set_fuel_rate(9.9)
        module.reset_fuel_rate()
        persisted = module.kv_get("fuel_state")
        with module.state_lock:
            in_memory = dict(module.fuel_state)
        assert persisted == in_memory
        assert persisted["drain_rate"] == pytest.approx(module.FUEL_DEFAULT_RATE)

    def test_set_fuel_fill_persists_matches_memory(self, module, tmp_store):
        module.set_fuel_fill(73.0)
        persisted = module.kv_get("fuel_state")
        with module.state_lock:
            in_memory = dict(module.fuel_state)
        assert persisted == in_memory
        assert persisted["fill_level"] == pytest.approx(73.0)

    def test_record_fuel_reading_persists_matches_memory(self, module, tmp_store):
        # Arrange enough run-hours since the fill that the reading is trusted (past
        # FUEL_MIN_RUN_SINCE_FILL), so a rate blend actually happens + persists.
        with module.state_lock:
            module.generator_state["running"] = False
            module.generator_state["total_run_hours"] = 5.0
            module.fuel_state["fill_level"] = 100.0
            module.fuel_state["fill_run_hours"] = 0.0
        module.record_fuel_reading(60.0)
        persisted = module.kv_get("fuel_state")
        with module.state_lock:
            in_memory = dict(module.fuel_state)
        assert persisted == in_memory

    def test_record_fuel_reading_too_soon_does_not_persist(self, module, tmp_store):
        # Below FUEL_MIN_RUN_SINCE_FILL the reading is a no-op (no rate change) and,
        # by design, does NOT persist -- confirm the early return path is unaffected
        # by moving kv_set inside the lock (the kv_set is AFTER that return).
        with module.state_lock:
            module.generator_state["running"] = False
            module.generator_state["total_run_hours"] = 0.0
            module.fuel_state["fill_run_hours"] = 0.0
        # No fuel_state persisted yet -> kv_get returns None (default).
        rate = module.record_fuel_reading(50.0)
        assert rate == pytest.approx(module.fuel_state["drain_rate"])
        assert module.kv_get("fuel_state") is None

    def test_set_alerts_persists_matches_memory(self, module, tmp_store):
        module.set_alerts(enabled=False, threshold=33, fuel_enabled=False)
        persisted = module.kv_get("alerts_state")
        with module.state_lock:
            in_memory = dict(module.alerts_state)
        assert persisted == in_memory
        assert persisted["alerts_on"] is False
        assert persisted["alert_threshold"] == 33
        assert persisted["fuel_enabled"] is False
