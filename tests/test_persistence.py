# test_persistence.py -- the durable kv layer (kv_set / kv_get) and
# load_persisted_state(), which restore lifetime run-hours + the fuel model +
# the alert config across a process restart.
#
# The kv table lives in the SAME shared sqlite connection as the event store, so
# init_event_store(db_path=...) reopens the connection on a throwaway DB and
# builds both tables. Values are stored as JSON text, so floats, ints, strings,
# lists and small dicts all round-trip. Both kv helpers are defensive: they must
# NEVER raise into their caller -- a store that's uninitialized or erroring logs
# a warning and returns the default (kv_get) / no-ops (kv_set).
import pytest


@pytest.fixture
def tmp_store(module, tmp_path):
    """Redirect the shared event/kv store to a throwaway DB (rebuilding the events
    + kv tables) for a test, then restore the default on-disk store afterwards so
    later tests keep a live connection."""
    module.init_event_store(db_path=tmp_path / "t.db")
    yield
    module.init_event_store()


# ---------------------------------------------------------------------------
# kv_set / kv_get round-trip
# ---------------------------------------------------------------------------
class TestKvRoundTrip:
    @pytest.mark.parametrize("value", [
        1.5,                       # float
        42,                        # int
        "hello",                   # string
        [1, 2, 3],                 # list
        {"a": 1, "b": 2.5},        # dict (the fuel/alerts shape)
        True,                      # bool (JSON-serializable)
    ])
    def test_round_trip(self, module, tmp_store, value):
        # Whatever went in comes back JSON-equal after a set/get cycle.
        module.kv_set("probe", value)
        assert module.kv_get("probe") == value

    def test_upsert_overwrites(self, module, tmp_store):
        # A second kv_set for the same key UPSERTs (replaces) rather than erroring
        # on the PRIMARY KEY conflict.
        module.kv_set("k", 1)
        module.kv_set("k", 2)
        assert module.kv_get("k") == 2

    def test_missing_key_returns_default(self, module, tmp_store):
        # An absent key returns the caller-supplied default (None if unspecified).
        assert module.kv_get("never-written") is None
        assert module.kv_get("never-written", 99) == 99

    def test_dict_value_is_independent_copy(self, module, tmp_store):
        # A round-tripped dict is a fresh object (JSON decode), not a shared ref, so
        # mutating the original after persisting doesn't change the stored value.
        original = {"fill_level": 80.0}
        module.kv_set("fuel_state", original)
        original["fill_level"] = 0.0
        assert module.kv_get("fuel_state")["fill_level"] == 80.0


# ---------------------------------------------------------------------------
# load_persisted_state -- restore run-hours + fuel + alerts from kv
# ---------------------------------------------------------------------------
class TestLoadPersistedState:
    def test_restores_all_three(self, module, tmp_store):
        # Persist known values, corrupt the in-memory state, then restore.
        module.kv_set("total_run_hours", 7.5)
        module.kv_set("fuel_state", {
            "fill_level": 60.0, "fill_run_hours": 3.0,
            "drain_rate": 5.1, "default_rate": 6.4,
        })
        module.kv_set("alerts_state", {"alerts_on": False, "alert_threshold": 33})
        # Scramble in-memory state so a no-op load would be visibly wrong.
        with module.state_lock:
            module.generator_state["total_run_hours"] = 0.0
            module.fuel_state["fill_level"] = 100.0
            module.fuel_state["drain_rate"] = 99.0
            module.alerts_state["alerts_on"] = True
            module.alerts_state["alert_threshold"] = 20

        module.load_persisted_state()

        assert module.generator_state["total_run_hours"] == pytest.approx(7.5)
        assert module.fuel_state["fill_level"] == pytest.approx(60.0)
        assert module.fuel_state["fill_run_hours"] == pytest.approx(3.0)
        assert module.fuel_state["drain_rate"] == pytest.approx(5.1)
        assert module.alerts_state["alerts_on"] is False
        assert module.alerts_state["alert_threshold"] == 33

    def test_total_run_hours_coerced_to_float(self, module, tmp_store):
        # An int stored value is coerced to float on restore (the model is float).
        module.kv_set("total_run_hours", 4)
        with module.state_lock:
            module.generator_state["total_run_hours"] = 0.0
        module.load_persisted_state()
        assert isinstance(module.generator_state["total_run_hours"], float)
        assert module.generator_state["total_run_hours"] == pytest.approx(4.0)

    def test_missing_keys_keep_defaults(self, module, tmp_store):
        # First boot: nothing persisted yet. load_persisted_state leaves the
        # in-memory defaults untouched (no key -> keep current value).
        with module.state_lock:
            module.generator_state["total_run_hours"] = 1.25
            module.fuel_state["fill_level"] = 88.0
            module.alerts_state["alert_threshold"] = 15
        module.load_persisted_state()
        assert module.generator_state["total_run_hours"] == pytest.approx(1.25)
        assert module.fuel_state["fill_level"] == pytest.approx(88.0)
        assert module.alerts_state["alert_threshold"] == 15

    def test_only_known_fuel_keys_are_copied(self, module, tmp_store):
        # A persisted fuel dict carrying a stale/foreign field must not leak that
        # field into fuel_state -- only the four known keys are copied.
        module.kv_set("fuel_state", {"fill_level": 55.0, "bogus_key": 123})
        module.load_persisted_state()
        assert module.fuel_state["fill_level"] == pytest.approx(55.0)
        assert "bogus_key" not in module.fuel_state

    def test_non_dict_persisted_fuel_is_ignored(self, module, tmp_store):
        # A corrupt (non-dict) fuel_state value is ignored, defaults preserved.
        module.kv_set("fuel_state", "corrupt-not-a-dict")
        with module.state_lock:
            module.fuel_state["fill_level"] = 77.0
        module.load_persisted_state()
        assert module.fuel_state["fill_level"] == pytest.approx(77.0)


# ---------------------------------------------------------------------------
# Defensive behavior -- kv helpers never raise into their caller
# ---------------------------------------------------------------------------
class TestKvNeverRaises:
    def test_kv_get_returns_default_when_store_uninitialized(self, module, monkeypatch):
        # With no connection, kv_get logs + returns the default instead of raising.
        # monkeypatch.setattr auto-restores the real connection after the test.
        monkeypatch.setattr(module.store, "_event_conn", None)
        assert module.kv_get("total_run_hours", 42.0) == 42.0

    def test_kv_set_is_noop_when_store_uninitialized(self, module, monkeypatch):
        # With no connection, kv_set logs a warning and returns without raising.
        monkeypatch.setattr(module.store, "_event_conn", None)
        module.kv_set("anything", 1)   # must not raise

    def test_kv_get_swallows_db_errors(self, module, monkeypatch):
        # A connection whose execute() raises must be swallowed -> default returned.
        class BoomConn:
            def execute(self, *a, **k):
                raise RuntimeError("boom")
        monkeypatch.setattr(module.store, "_event_conn", BoomConn())
        assert module.kv_get("k", "fallback") == "fallback"

    def test_kv_set_swallows_db_errors(self, module, monkeypatch):
        # Likewise a failing execute() on write is swallowed (in-memory value stands).
        class BoomConn:
            def execute(self, *a, **k):
                raise RuntimeError("boom")
        monkeypatch.setattr(module.store, "_event_conn", BoomConn())
        module.kv_set("k", 1)          # must not raise
