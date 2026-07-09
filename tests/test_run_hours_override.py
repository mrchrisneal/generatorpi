# test_run_hours_override.py -- the manual lifetime run-hours override.
#
# v1.3.2 adds a Settings-drawer field that lets the operator set the lifetime
# run-hours odometer directly (e.g. to match the engine's own hour meter). The
# server side is:
#   set_total_run_hours(hours) -- clamp [0, MAX_TOTAL_RUN_HOURS], round 3dp, set the
#       persisted base, and (a) if a run is in progress re-stamp current_run_started_at
#       to now so the LIVE total reads exactly `hours` and the base stays non-negative,
#       and (b) shift fuel_state['fill_run_hours'] by the same delta so the fuel
#       projection's run-since-fill (hence the tank level) is UNCHANGED. Persists both
#       total_run_hours and fuel_state to the kv store. Returns (old_live, new_total).
#   POST /api/runtime/hours {"hours": float>=0} -- @auth_required wrapper; parses via
#       _json_number (400 on missing/garbage/non-finite), records a MANUAL event, logs.
#
# It is a TRACKED-STATE correction only -- it never actuates the relay. time.time()
# is pinned via fixed_time where an in-progress run's elapsed time feeds the math;
# persistence/event assertions use tmp_store to keep the kv/event store hermetic.
import pytest


API_KEY = "run-hours-test-key"

# The Flask test client's default origin -- what the CSRF guard computes as `expected`.
SAME_ORIGIN = "http://localhost"


@pytest.fixture(autouse=True)
def _configure_api_key(module):
    """Working API key for the @auth_required /api/runtime/hours endpoint."""
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
    """Pin module.time.time() to a mutable clock the test can advance. set_total_run_hours
    re-stamps current_run_started_at with time.time() while running, and
    _live_total_run_hours_locked reads it, so this makes the live math exact."""
    clock = {"now": 1_000_000.0}
    monkeypatch.setattr(module.time, "time", lambda: clock["now"])
    return clock


@pytest.fixture(autouse=True)
def _reset_state(module):
    """Each test starts from a known STOPPED baseline so a prior test's run clock or
    banked hours can't leak in. Restores nothing special -- the module-level defaults."""
    with module.state_lock:
        module.generator_state["running"] = False
        module.generator_state["current_run_started_at"] = None
        module.generator_state["total_run_hours"] = 0.0
        module.fuel_state["fill_level"] = 100.0
        module.fuel_state["fill_run_hours"] = 0.0
        module.fuel_state["drain_rate"] = module.FUEL_DEFAULT_RATE
    yield


# ---------------------------------------------------------------------------
# set_total_run_hours -- stopped (the common correction case)
# ---------------------------------------------------------------------------
class TestSetTotalRunHoursStopped:
    def test_sets_base_directly_and_returns_old_and_new(self, module, tmp_store):
        # Stopped: the entered value becomes the persisted base verbatim; the return
        # carries the pre-change live total (for the audit log) and the new total.
        with module.state_lock:
            module.generator_state["total_run_hours"] = 5.0
        old_live, new_total = module.set_total_run_hours(20.0)
        assert old_live == pytest.approx(5.0)
        assert new_total == pytest.approx(20.0)
        assert module.generator_state["total_run_hours"] == pytest.approx(20.0)
        # Stopped: no run clock is stamped.
        assert module.generator_state["current_run_started_at"] is None

    def test_persists_total_and_fuel_to_kv(self, module, tmp_store):
        # Both mutated stores are written to kv IN-LOCK so a restart restores them.
        module.set_total_run_hours(42.0)
        assert module.kv_get("total_run_hours") == pytest.approx(42.0)
        # fuel_state is re-anchored + persisted even on a stopped set.
        assert isinstance(module.kv_get("fuel_state"), dict)

    def test_survives_a_simulated_restart(self, module, tmp_store):
        # Round-trip: set, wipe the in-memory base, reload from kv (what a restart does).
        module.set_total_run_hours(137.25)
        with module.state_lock:
            module.generator_state["total_run_hours"] = 0.0  # simulate fresh process
        module.load_persisted_state()
        assert module.generator_state["total_run_hours"] == pytest.approx(137.25)

    def test_clamps_negative_to_zero(self, module, tmp_store):
        old_live, new_total = module.set_total_run_hours(-5.0)
        assert new_total == 0.0
        assert module.generator_state["total_run_hours"] == 0.0

    def test_clamps_above_max(self, module, tmp_store):
        # An absurd value is capped at MAX_TOTAL_RUN_HOURS rather than stored raw.
        _, new_total = module.set_total_run_hours(2 * module.MAX_TOTAL_RUN_HOURS)
        assert new_total == module.MAX_TOTAL_RUN_HOURS
        assert module.generator_state["total_run_hours"] == module.MAX_TOTAL_RUN_HOURS

    def test_rounds_to_three_decimals(self, module, tmp_store):
        _, new_total = module.set_total_run_hours(1.23456)
        assert new_total == pytest.approx(1.235)

    def test_accepts_int(self, module, tmp_store):
        # A plain int coerces cleanly to the float base.
        _, new_total = module.set_total_run_hours(300)
        assert new_total == pytest.approx(300.0)


# ---------------------------------------------------------------------------
# set_total_run_hours -- running (re-baseline the in-progress run)
# ---------------------------------------------------------------------------
class TestSetTotalRunHoursRunning:
    def test_live_equals_entered_and_base_stays_nonnegative(
        self, module, tmp_store, fixed_time
    ):
        # Running for one hour on a base of 2 -> live total 3. Override to 100: the LIVE
        # total must read exactly 100 immediately, the persisted base must be 100 (not a
        # transient negative), and the run clock is re-stamped to now.
        with module.state_lock:
            module.generator_state["total_run_hours"] = 2.0
            module.generator_state["running"] = True
            module.generator_state["current_run_started_at"] = fixed_time["now"]
        fixed_time["now"] += 3600.0                         # one hour into the run
        old_live, new_total = module.set_total_run_hours(100.0)
        assert old_live == pytest.approx(3.0)               # base + elapsed pre-change
        assert new_total == pytest.approx(100.0)
        assert module.generator_state["total_run_hours"] == pytest.approx(100.0)
        # Run clock re-stamped to now -> uptime restarts, and live == base + 0.
        assert module.generator_state["current_run_started_at"] == fixed_time["now"]
        with module.state_lock:
            assert module._live_total_run_hours_locked() == pytest.approx(100.0)

    def test_uptime_clock_resets_to_now(self, module, tmp_store, fixed_time):
        # The current-run uptime is derived from current_run_started_at; overriding
        # mid-run re-stamps it to now, so uptime restarts from zero (documented behavior).
        with module.state_lock:
            module.generator_state["total_run_hours"] = 0.0
            module.generator_state["running"] = True
            module.generator_state["current_run_started_at"] = fixed_time["now"] - 7200.0
        module.set_total_run_hours(50.0)
        assert module.generator_state["current_run_started_at"] == fixed_time["now"]


# ---------------------------------------------------------------------------
# Fuel projection is preserved across the odometer change
# ---------------------------------------------------------------------------
class TestFuelPreservedAcrossOverride:
    def test_run_since_fill_is_preserved(self, module, tmp_store):
        # Stopped, base 10 with a fill 6 run-hours ago (run_since_fill = 6). After setting
        # the odometer to 100, run_since_fill must still be 6 -- the tank doesn't lurch.
        with module.state_lock:
            module.generator_state["total_run_hours"] = 10.0
            module.fuel_state["fill_run_hours"] = 4.0        # 10 - 4 = 6 run-hrs since fill
        module.set_total_run_hours(100.0)
        assert module.fuel_state["fill_run_hours"] == pytest.approx(94.0)  # 100 - 6
        run_since_fill = (
            module.generator_state["total_run_hours"] - module.fuel_state["fill_run_hours"]
        )
        assert run_since_fill == pytest.approx(6.0)

    def test_fill_mark_clamped_nonnegative_when_hours_below_run_since_fill(
        self, module, tmp_store
    ):
        # run_since_fill = 6, but the operator sets the odometer to 2 (< 6). fill_run_hours
        # can't go negative, so it clamps to 0 (the gauge shifts rather than storing a
        # nonsensical negative fill mark).
        with module.state_lock:
            module.generator_state["total_run_hours"] = 10.0
            module.fuel_state["fill_run_hours"] = 4.0        # run_since_fill = 6
        module.set_total_run_hours(2.0)
        assert module.fuel_state["fill_run_hours"] == 0.0

    def test_fuel_snapshot_persisted_with_new_fill_mark(self, module, tmp_store):
        with module.state_lock:
            module.generator_state["total_run_hours"] = 10.0
            module.fuel_state["fill_run_hours"] = 4.0
        module.set_total_run_hours(100.0)
        assert module.kv_get("fuel_state")["fill_run_hours"] == pytest.approx(94.0)


# ---------------------------------------------------------------------------
# POST /api/runtime/hours -- endpoint behavior
# ---------------------------------------------------------------------------
class TestRuntimeHoursEndpoint:
    def test_sets_and_returns_new_total(self, client, module, tmp_store):
        resp = client.post(_q("/api/runtime/hours"), json={"hours": 250.5})
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["success"] is True
        assert body["total_run_hours"] == pytest.approx(250.5)
        assert module.generator_state["total_run_hours"] == pytest.approx(250.5)

    def test_accepts_numeric_string(self, client, module, tmp_store):
        # _json_number coerces "250.5" before set_total_run_hours.
        resp = client.post(_q("/api/runtime/hours"), json={"hours": "250.5"})
        assert resp.status_code == 200
        assert resp.get_json()["total_run_hours"] == pytest.approx(250.5)

    def test_records_manual_event(self, client, module, tmp_store):
        # A successful override appends a MANUAL-tagged ("set_running") audit event whose
        # message names the new total, so the correction is visible in the event log.
        client.post(_q("/api/runtime/hours"), json={"hours": 250})
        evts = module.get_events()
        assert any(
            e["type"] == "set_running" and "Total run-hours set to 250 h" in e["message"]
            for e in evts
        )

    def test_reflected_in_state_snapshot(self, client, module, tmp_store):
        # /api/state (what the UI polls) must carry the new total so the odometer updates.
        client.post(_q("/api/runtime/hours"), json={"hours": 321.0})
        resp = client.get(_q("/api/state"))
        assert resp.status_code == 200
        assert resp.get_json()["total_run_hours"] == pytest.approx(321.0)

    def test_running_override_via_endpoint_reads_entered_value(
        self, client, module, tmp_store, fixed_time
    ):
        # End-to-end running case: mark running, advance an hour, override to 500 -> the
        # state snapshot's base is 500 and the run clock is re-stamped to now.
        client.post(_q("/api/set_running"), json={"running": True})
        fixed_time["now"] += 3600.0
        resp = client.post(_q("/api/runtime/hours"), json={"hours": 500.0})
        assert resp.status_code == 200
        assert module.generator_state["total_run_hours"] == pytest.approx(500.0)
        assert module.generator_state["current_run_started_at"] == fixed_time["now"]


# ---------------------------------------------------------------------------
# Error paths -- bad/absent bodies are 400 (success:false), never 500
# ---------------------------------------------------------------------------
class TestRuntimeHoursErrorPaths:
    def test_missing_field_is_400(self, client, module, tmp_store):
        resp = client.post(_q("/api/runtime/hours"), json={})
        assert resp.status_code == 400
        assert resp.get_json()["success"] is False

    def test_non_numeric_is_400(self, client, module, tmp_store):
        resp = client.post(_q("/api/runtime/hours"), json={"hours": "not-a-number"})
        assert resp.status_code == 400
        assert resp.get_json()["success"] is False

    def test_bool_as_number_is_400(self, client, module, tmp_store):
        # A JSON bool where a number is expected must be rejected (bool is an int
        # subclass but is never a valid hours value).
        resp = client.post(_q("/api/runtime/hours"), json={"hours": True})
        assert resp.status_code == 400
        assert resp.get_json()["success"] is False

    @pytest.mark.parametrize("bad", ["inf", "-inf", "nan", "1e999"])
    def test_non_finite_is_400(self, client, module, tmp_store, bad):
        # Infinity/NaN (and the 1e999 overflow-to-inf string) all parse as floats but are
        # rejected by _json_number, so they can never corrupt the persisted odometer.
        resp = client.post(_q("/api/runtime/hours"), json={"hours": bad})
        assert resp.status_code == 400
        assert resp.get_json()["success"] is False

    def test_json_null_is_400(self, client, module, tmp_store):
        # An explicit JSON null for the field is neither number nor numeric string -> 400.
        resp = client.post(_q("/api/runtime/hours"), json={"hours": None})
        assert resp.status_code == 400
        assert resp.get_json()["success"] is False

    def test_bodyless_post_is_400_not_500(self, client, module, tmp_store):
        # get_json(silent=True) -> None -> missing-field 400, never a 500.
        resp = client.post(_q("/api/runtime/hours"))
        assert resp.status_code == 400
        assert resp.status_code != 500


# ---------------------------------------------------------------------------
# Security -- the new mutating route is @auth_required AND covered by the CSRF guard
# ---------------------------------------------------------------------------
class TestRuntimeHoursSecurity:
    def test_unauthenticated_is_401(self, client, module):
        # Key configured but none supplied -> the mutation is rejected before any change.
        module.CONFIG["API_KEY"] = "some-key"
        resp = client.post("/api/runtime/hours", json={"hours": 100})  # no ?key=
        assert resp.status_code == 401

    def test_cross_origin_post_is_rejected_403(self, client, module):
        # A foreign Origin (cross-site auto-submit) is rejected by the before_request CSRF
        # guard before it can reach the handler -- proving the new route participates.
        resp = client.post(
            _q("/api/runtime/hours"),
            json={"hours": 100},
            headers={"Origin": "https://evil.example"},
        )
        assert resp.status_code == 403
        assert resp.get_json()["message"] == "cross-origin request rejected"

    def test_does_not_touch_the_relay(self, client, module, tmp_store):
        # Belt-and-suspenders safety assertion: an odometer override must NEVER actuate
        # the relay (it is a tracked-state correction). The relay is a MagicMock in tests;
        # confirm no on()/off() energize call was made by the override path.
        module.relay_start_stop.reset_mock()
        resp = client.post(_q("/api/runtime/hours"), json={"hours": 100})
        assert resp.status_code == 200
        # Neither energize (on) nor de-energize (off) is touched -- the override path is
        # pure state/persistence, entirely off the relay path.
        assert not module.relay_start_stop.on.called
        assert not module.relay_start_stop.off.called
