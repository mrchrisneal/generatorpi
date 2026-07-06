# test_fuel.py -- the fuel-projection model + its /api/fuel/* and /api/alerts
# endpoints, plus the _json_number body parser they all share.
#
# The server holds a raw linear-drain model (a fill baseline % + an estimated
# %/hr drain rate) and ships it in the state snapshot; the client derives the
# live projected level. These endpoints just mutate + persist that model:
#   /api/fuel/reading  -- blend an observed level into the drain-rate estimate
#   /api/fuel/rate     -- set the drain rate directly (floored 0.1, 1dp)
#   /api/fuel/rate/reset -- restore the default rate (FUEL_DEFAULT_RATE)
#   /api/fuel/fill     -- "add gas": reset the fill baseline at the current run-hr
#   /api/alerts        -- low-fuel alert on/off + threshold (clamped 5..40)
#
# Every successful mutation (a) appends a "fuel" event and (b) persists the model
# to the kv store, so persistence-touching tests use the tmp_store fixture.
# time.time() is pinned via fixed_time where live run-hours feed the math.
import pytest


API_KEY = "fuel-test-key"


@pytest.fixture(autouse=True)
def _configure_api_key(module):
    """Working API key for the @auth_required fuel/alert endpoints."""
    module.CONFIG["API_KEY"] = API_KEY


def _q(path):
    """Append the API key as a query param to authorize the request."""
    sep = "&" if "?" in path else "?"
    return f"{path}{sep}key={API_KEY}"


@pytest.fixture
def tmp_store(module, tmp_path):
    """Redirect the shared event/kv store to a throwaway DB so persistence + event
    assertions are hermetic, then restore the default store afterwards."""
    module.init_event_store(db_path=tmp_path / "t.db")
    yield
    module.init_event_store()


@pytest.fixture
def fixed_time(module, monkeypatch):
    """Pin module.time.time() to a mutable clock. The fuel math keys off live
    run-hours (_live_total_run_hours_locked), so a controllable clock makes the
    run-since-fill interval exact."""
    clock = {"now": 2_000_000.0}
    monkeypatch.setattr(module.time, "time", lambda: clock["now"])
    return clock


# ---------------------------------------------------------------------------
# _json_number -- shared numeric body parser
# ---------------------------------------------------------------------------
class TestJsonNumber:
    def test_missing_field(self, module):
        # A missing field yields a "missing '<f>'" error, value None.
        val, err = module._json_number({}, "level")
        assert val is None
        assert "missing 'level'" in err

    def test_non_dict_body(self, module):
        # A non-dict body (e.g. get_json returned None or a list) is reported as a
        # missing field rather than raising.
        assert module._json_number(None, "level")[0] is None
        assert module._json_number([1, 2], "level")[0] is None

    def test_accepts_int_and_float(self, module):
        # Real numbers pass through as floats.
        assert module._json_number({"x": 5}, "x") == (5.0, None)
        assert module._json_number({"x": 5.5}, "x") == (5.5, None)

    def test_accepts_numeric_string(self, module):
        # Numeric strings (with surrounding whitespace) are coerced.
        assert module._json_number({"x": " 6.5 "}, "x") == (6.5, None)

    def test_rejects_bool(self, module):
        # A bool is an int subclass but is never a valid level/rate/threshold; it
        # must be rejected, not silently treated as 0/1.
        val, err = module._json_number({"x": True}, "x")
        assert val is None
        assert "not a number" in err

    def test_rejects_non_numeric_string(self, module):
        val, err = module._json_number({"x": "abc"}, "x")
        assert val is None
        assert "not a number" in err

    def test_rejects_other_types(self, module):
        # A list/dict value is not a number.
        assert module._json_number({"x": [1]}, "x")[0] is None


# ---------------------------------------------------------------------------
# record_fuel_reading -- drain-rate estimate blend
# ---------------------------------------------------------------------------
class TestRecordFuelReading:
    def test_blend_matches_documented_formula(self, module, tmp_store, fixed_time):
        # Setup: full tank baseline at run-hour 0, 10 run-hours elapsed, old rate
        # 4.0. Observing 40% => new = (100-40)/10 = 6.0 => blend = 0.5*4 + 0.5*6 = 5.0.
        with module.state_lock:
            module.generator_state["running"] = False
            module.generator_state["total_run_hours"] = 10.0
            module.fuel_state["fill_level"] = 100.0
            module.fuel_state["fill_run_hours"] = 0.0
            module.fuel_state["drain_rate"] = 4.0
        rate = module.record_fuel_reading(40.0)
        assert rate == pytest.approx(5.0)
        assert module.fuel_state["drain_rate"] == pytest.approx(5.0)

    def test_premature_reading_is_noop(self, module, tmp_store, fixed_time):
        # A reading taken before FUEL_MIN_RUN_SINCE_FILL of run-time has elapsed since
        # the fill is IGNORED (returns the unchanged rate) rather than exploding the
        # estimate on a near-zero denominator. Here run_since_fill == 0.
        with module.state_lock:
            module.generator_state["total_run_hours"] = 5.0
            module.fuel_state["fill_level"] = 100.0
            module.fuel_state["fill_run_hours"] = 5.0   # run_since_fill == 0
            module.fuel_state["drain_rate"] = 4.0
        rate = module.record_fuel_reading(50.0)
        # No-op: rate unchanged, no raise.
        assert rate == pytest.approx(4.0)
        assert module.fuel_state["drain_rate"] == pytest.approx(4.0)

    def test_reading_just_below_threshold_is_noop(self, module, tmp_store, fixed_time):
        # Just under the run-time threshold -> still ignored (rate unchanged).
        with module.state_lock:
            module.generator_state["total_run_hours"] = 5.0 + module.FUEL_MIN_RUN_SINCE_FILL / 2
            module.fuel_state["fill_level"] = 100.0
            module.fuel_state["fill_run_hours"] = 5.0
            module.fuel_state["drain_rate"] = 4.0
        rate = module.record_fuel_reading(20.0)
        assert rate == pytest.approx(4.0)
        assert module.fuel_state["drain_rate"] == pytest.approx(4.0)

    def test_level_clamped_low(self, module, tmp_store, fixed_time):
        # A negative observed level is clamped to 0 BEFORE the math. With rate 10.0
        # and 10 run-hours: clamped(0) => new=(100-0)/10=10 => blend=10.0. If the
        # clamp were missing, level=-50 => new=15 => blend=12.5, so 10.0 proves it.
        with module.state_lock:
            module.generator_state["total_run_hours"] = 10.0
            module.fuel_state["fill_level"] = 100.0
            module.fuel_state["fill_run_hours"] = 0.0
            module.fuel_state["drain_rate"] = 10.0
        rate = module.record_fuel_reading(-50.0)
        assert rate == pytest.approx(10.0)

    def test_rate_floored_at_min(self, module, tmp_store, fixed_time):
        # Observing a level ABOVE the fill baseline yields a negative raw estimate;
        # the max(0.1, ...) floor keeps the rate positive. old 0.1 => blend 0.1.
        with module.state_lock:
            module.generator_state["total_run_hours"] = 10.0
            module.fuel_state["fill_level"] = 50.0
            module.fuel_state["fill_run_hours"] = 0.0
            module.fuel_state["drain_rate"] = 0.1
        rate = module.record_fuel_reading(100.0)
        assert rate == pytest.approx(0.1)

    def test_endpoint_records_event_and_persists(self, client, module, tmp_store):
        # A successful reading returns the new drain_rate, appends a "fuel" event,
        # and persists the fuel model to kv. Establish enough run-time since the fill
        # (10 run-hours) so the reading is actually fitted, not a premature no-op.
        with module.state_lock:
            module.generator_state["total_run_hours"] = 10.0
            module.fuel_state["fill_level"] = 100.0
            module.fuel_state["fill_run_hours"] = 0.0
        resp = client.post(_q("/api/fuel/reading"), json={"level": 50})
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["success"] is True
        assert isinstance(body["drain_rate"], float)
        types = [e["type"] for e in module.get_events()]
        assert "fuel" in types
        assert module.kv_get("fuel_state")["drain_rate"] == body["drain_rate"]


# ---------------------------------------------------------------------------
# set_fuel_rate / reset_fuel_rate
# ---------------------------------------------------------------------------
class TestSetFuelRate:
    def test_sets_and_rounds_to_1dp(self, client, module, tmp_store):
        # 7.28 rounds to 7.3.
        resp = client.post(_q("/api/fuel/rate"), json={"rate": 7.28})
        assert resp.status_code == 200
        assert resp.get_json()["drain_rate"] == pytest.approx(7.3)
        assert module.fuel_state["drain_rate"] == pytest.approx(7.3)

    def test_floors_at_min(self, module, tmp_store):
        # A tiny/zero/negative rate is floored at 0.1.
        assert module.set_fuel_rate(0.02) == pytest.approx(0.1)
        assert module.set_fuel_rate(-5) == pytest.approx(0.1)

    def test_accepts_numeric_string_via_endpoint(self, client, module, tmp_store):
        # _json_number coerces the string "6.5" to 6.5 before set_fuel_rate.
        resp = client.post(_q("/api/fuel/rate"), json={"rate": "6.5"})
        assert resp.status_code == 200
        assert resp.get_json()["drain_rate"] == pytest.approx(6.5)

    def test_persists_and_records_event(self, client, module, tmp_store):
        client.post(_q("/api/fuel/rate"), json={"rate": 8.1})
        assert module.kv_get("fuel_state")["drain_rate"] == pytest.approx(8.1)
        assert "fuel" in [e["type"] for e in module.get_events()]


class TestResetFuelRate:
    def test_restores_default(self, client, module, tmp_store):
        # Change the rate, then reset -> back to FUEL_DEFAULT_RATE (default_rate).
        with module.state_lock:
            module.fuel_state["drain_rate"] = 99.9
        resp = client.post(_q("/api/fuel/rate/reset"))
        assert resp.status_code == 200
        assert resp.get_json()["drain_rate"] == pytest.approx(module.FUEL_DEFAULT_RATE)
        assert module.fuel_state["drain_rate"] == pytest.approx(module.FUEL_DEFAULT_RATE)

    def test_reset_persists(self, client, module, tmp_store):
        with module.state_lock:
            module.fuel_state["drain_rate"] = 42.0
        client.post(_q("/api/fuel/rate/reset"))
        assert module.kv_get("fuel_state")["drain_rate"] == pytest.approx(
            module.FUEL_DEFAULT_RATE
        )


# ---------------------------------------------------------------------------
# set_fuel_fill -- "add gas" resets the baseline at the current run-hour
# ---------------------------------------------------------------------------
class TestSetFuelFill:
    def test_sets_level_and_stamps_run_hours_retains_rate(
        self, module, tmp_store, fixed_time
    ):
        # Filling records the level and stamps fill_run_hours = current live total;
        # the drain rate is intentionally retained across a fill.
        with module.state_lock:
            module.generator_state["running"] = False
            module.generator_state["total_run_hours"] = 5.0
            module.fuel_state["drain_rate"] = 3.3
        snap = module.set_fuel_fill(80.0)
        assert snap["fill_level"] == pytest.approx(80.0)
        assert snap["fill_run_hours"] == pytest.approx(5.0)
        assert snap["drain_rate"] == pytest.approx(3.3)   # retained

    def test_fill_run_hours_tracks_live_total_while_running(
        self, module, tmp_store, fixed_time
    ):
        # If the engine is running, the fill baseline stamps the LIVE total
        # (base + in-progress elapsed), not just the completed base.
        with module.state_lock:
            module.generator_state["total_run_hours"] = 2.0
            module.generator_state["running"] = True
            module.generator_state["current_run_started_at"] = fixed_time["now"]
        fixed_time["now"] += 3600.0                        # +1 h in progress
        snap = module.set_fuel_fill(100.0)
        assert snap["fill_run_hours"] == pytest.approx(3.0)

    def test_level_clamped(self, module, tmp_store, fixed_time):
        # Fill level is clamped to 0..100.
        assert module.set_fuel_fill(150.0)["fill_level"] == pytest.approx(100.0)
        assert module.set_fuel_fill(-10.0)["fill_level"] == pytest.approx(0.0)

    def test_endpoint_persists_and_records_event(self, client, module, tmp_store):
        resp = client.post(_q("/api/fuel/fill"), json={"level": 75})
        assert resp.status_code == 200
        assert resp.get_json()["fuel"]["fill_level"] == pytest.approx(75.0)
        assert module.kv_get("fuel_state")["fill_level"] == pytest.approx(75.0)
        assert "fuel" in [e["type"] for e in module.get_events()]


# ---------------------------------------------------------------------------
# set_alerts / /api/alerts
# ---------------------------------------------------------------------------
class TestSetAlerts:
    def test_direct_both_fields(self, module, tmp_store):
        snap = module.set_alerts(enabled=False, threshold=30)
        assert snap["alerts_on"] is False
        assert snap["alert_threshold"] == 30

    def test_threshold_clamped_low_and_high(self, module, tmp_store):
        # Slider range is 5..40.
        assert module.set_alerts(threshold=3)["alert_threshold"] == 5
        assert module.set_alerts(threshold=100)["alert_threshold"] == 40

    def test_both_fields_optional_no_change(self, module, tmp_store):
        # Passing neither leaves the existing config untouched.
        with module.state_lock:
            module.alerts_state["alerts_on"] = True
            module.alerts_state["alert_threshold"] = 22
        snap = module.set_alerts()
        assert snap["alerts_on"] is True
        assert snap["alert_threshold"] == 22

    @pytest.mark.parametrize("raw,expected", [
        (True, True), (False, False),
        ("true", True), ("false", False),
        ("1", True), ("0", False),
        ("yes", True), ("no", False),
        ("on", True), ("off", False),
        ("garbage", False),
    ])
    def test_endpoint_coerces_enabled(self, client, module, tmp_store, raw, expected):
        # /api/alerts coerces bool / common string forms into a real bool.
        resp = client.post(_q("/api/alerts"), json={"enabled": raw})
        assert resp.status_code == 200
        assert resp.get_json()["alerts"]["alerts_on"] is expected

    def test_endpoint_threshold_only(self, client, module, tmp_store):
        # threshold may be supplied without enabled; clamped and applied.
        resp = client.post(_q("/api/alerts"), json={"threshold": 35})
        assert resp.status_code == 200
        assert resp.get_json()["alerts"]["alert_threshold"] == 35

    def test_endpoint_non_dict_body_no_change_no_500(self, client, module, tmp_store):
        # A non-dict JSON body degrades to {} -> no change, and must not 500.
        with module.state_lock:
            module.alerts_state["alert_threshold"] = 18
        resp = client.post(_q("/api/alerts"), json=[1, 2, 3])
        assert resp.status_code == 200
        assert resp.get_json()["alerts"]["alert_threshold"] == 18

    def test_endpoint_persists(self, client, module, tmp_store):
        client.post(_q("/api/alerts"), json={"enabled": False, "threshold": 12})
        saved = module.kv_get("alerts_state")
        assert saved["alerts_on"] is False
        assert saved["alert_threshold"] == 12


# ---------------------------------------------------------------------------
# Error paths -- bad/absent bodies return HTTP 400 with success:false, never 500
# ---------------------------------------------------------------------------
class TestFuelErrorPaths:
    @pytest.mark.parametrize("path,field", [
        ("/api/fuel/reading", "level"),
        ("/api/fuel/rate", "rate"),
    ])
    def test_missing_field_is_400(self, client, module, tmp_store, path, field):
        resp = client.post(_q(path), json={})
        assert resp.status_code == 400
        assert resp.get_json()["success"] is False

    @pytest.mark.parametrize("path", ["/api/fuel/reading", "/api/fuel/rate"])
    def test_non_numeric_is_400(self, client, module, tmp_store, path):
        key = "level" if path.endswith("reading") else "rate"
        resp = client.post(_q(path), json={key: "not-a-number"})
        assert resp.status_code == 400
        assert resp.get_json()["success"] is False

    @pytest.mark.parametrize("path", ["/api/fuel/reading", "/api/fuel/rate"])
    def test_bool_as_number_is_400(self, client, module, tmp_store, path):
        # A JSON bool passed where a number is expected must be rejected (400).
        key = "level" if path.endswith("reading") else "rate"
        resp = client.post(_q(path), json={key: True})
        assert resp.status_code == 400
        assert resp.get_json()["success"] is False

    @pytest.mark.parametrize("path", [
        "/api/fuel/reading", "/api/fuel/rate", "/api/fuel/fill",
    ])
    def test_bodyless_post_is_400_not_500(self, client, module, tmp_store, path):
        # A bodyless POST (get_json(silent=True) -> None) is a missing-field 400,
        # never a 500.
        resp = client.post(_q(path))
        assert resp.status_code == 400
        assert resp.status_code != 500

    def test_alerts_garbage_threshold_is_400(self, client, module, tmp_store):
        # A present-but-garbage threshold is rejected by _json_number (400).
        resp = client.post(_q("/api/alerts"), json={"threshold": "abc"})
        assert resp.status_code == 400
        assert resp.get_json()["success"] is False

    def test_fuel_fill_non_numeric_is_400(self, client, module, tmp_store):
        resp = client.post(_q("/api/fuel/fill"), json={"level": "xyz"})
        assert resp.status_code == 400
        assert resp.get_json()["success"] is False


# ---------------------------------------------------------------------------
# Auth -- all fuel/alert routes are @auth_required
# ---------------------------------------------------------------------------
class TestFuelAuth:
    @pytest.mark.parametrize("path", [
        "/api/fuel/reading", "/api/fuel/rate", "/api/fuel/rate/reset",
        "/api/fuel/fill", "/api/alerts",
    ])
    def test_unauthenticated_is_401(self, client, module, path):
        # With a key configured but none supplied, every mutation is rejected 401.
        module.CONFIG["API_KEY"] = "some-key"
        resp = client.post(path, json={"level": 50})  # no ?key=
        assert resp.status_code == 401
