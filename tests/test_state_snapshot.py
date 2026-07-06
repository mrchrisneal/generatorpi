# test_state_snapshot.py -- the GET /api/state rich snapshot endpoint.
#
# /api/state is the single JSON payload the redesigned web UI reads on first
# render and while polling. It must expose the tracked run-state + display
# registers, the lifetime run-hours base + current-run start (so the client can
# tick the odometer/uptime live), the fuel model, the alert config, and the
# server's own clock (server_now) so client timers align to the server.
#
# Every route is @auth_required, so an API key is configured and appended to
# each request via _q(). Relay/hardware side effects are never triggered here --
# these are pure read-of-state assertions -- so no no_sleep/tmp_store is needed.
import pytest


# A fixed key used for all requests in this module.
API_KEY = "state-snapshot-test-key"


@pytest.fixture(autouse=True)
def _configure_api_key(module):
    """Give every test in this file a working API key so @auth_required passes."""
    module.CONFIG["API_KEY"] = API_KEY


def _q(path):
    """Append the API key as a query param to authorize the request (matches the
    established pattern in test_endpoints.py)."""
    sep = "&" if "?" in path else "?"
    return f"{path}{sep}key={API_KEY}"


class TestStateSnapshotShape:
    def test_returns_all_expected_keys(self, client):
        # The snapshot contract: exactly these top-level keys must be present so
        # the front-end can rely on them without defensive existence checks.
        resp = client.get(_q("/api/state"))
        assert resp.status_code == 200
        data = resp.get_json()
        expected = {
            "running", "last_command", "last_start_time", "last_stop_time",
            "start_attempts", "message", "current_run_started_at",
            "total_run_hours", "fuel", "alerts", "server_now",
        }
        assert expected.issubset(data.keys())

    def test_fuel_and_alerts_are_nested_dicts_with_model_fields(self, client):
        # fuel + alerts ship as nested objects; assert their inner field names so a
        # rename in the model is caught by a failing test (the UI keys off these).
        data = client.get(_q("/api/state")).get_json()
        assert set(data["fuel"].keys()) == {
            "fill_level", "fill_run_hours", "drain_rate", "default_rate"
        }
        assert set(data["alerts"].keys()) == {"alerts_on", "alert_threshold"}

    def test_server_now_is_a_float(self, client, module, monkeypatch):
        # server_now must be the server's unix clock as a float. Pin time.time so
        # the assertion is exact rather than "roughly now".
        monkeypatch.setattr(module.time, "time", lambda: 1234567.5)
        data = client.get(_q("/api/state")).get_json()
        assert isinstance(data["server_now"], float)
        assert data["server_now"] == 1234567.5


class TestStateSnapshotReflectsGlobals:
    def test_reflects_generator_state(self, client, module):
        # Values in the snapshot must mirror generator_state, not be hardcoded.
        with module.state_lock:
            module.generator_state["running"] = True
            module.generator_state["last_command"] = "start"
            module.generator_state["message"] = "snapshot-probe"
            module.generator_state["start_attempts"] = 3
            module.generator_state["total_run_hours"] = 12.75
            module.generator_state["current_run_started_at"] = 5000.0
        data = client.get(_q("/api/state")).get_json()
        assert data["running"] is True
        assert data["last_command"] == "start"
        assert data["message"] == "snapshot-probe"
        assert data["start_attempts"] == 3
        # total_run_hours is the STORED base here (running but we didn't advance the
        # clock in this test, so the endpoint's base value is returned verbatim).
        assert data["total_run_hours"] == 12.75
        assert data["current_run_started_at"] == 5000.0

    def test_reflects_fuel_state(self, client, module):
        # Mutating fuel_state must surface through the snapshot's nested fuel dict.
        with module.state_lock:
            module.fuel_state["fill_level"] = 73.0
            module.fuel_state["fill_run_hours"] = 4.0
            module.fuel_state["drain_rate"] = 5.5
            module.fuel_state["default_rate"] = 6.4
        fuel = client.get(_q("/api/state")).get_json()["fuel"]
        assert fuel["fill_level"] == 73.0
        assert fuel["fill_run_hours"] == 4.0
        assert fuel["drain_rate"] == 5.5
        assert fuel["default_rate"] == 6.4

    def test_reflects_alerts_state(self, client, module):
        # Alert config likewise flows through unchanged.
        with module.state_lock:
            module.alerts_state["alerts_on"] = False
            module.alerts_state["alert_threshold"] = 30
        alerts = client.get(_q("/api/state")).get_json()["alerts"]
        assert alerts["alerts_on"] is False
        assert alerts["alert_threshold"] == 30

    def test_default_snapshot_matches_code_defaults(self, client, module):
        # With pristine globals (reset_globals runs autouse), the snapshot should
        # show the documented defaults: stopped, zero run-hours, full tank at the
        # default rate, alerts on at threshold 20.
        data = client.get(_q("/api/state")).get_json()
        assert data["running"] is False
        assert data["total_run_hours"] == 0.0
        assert data["current_run_started_at"] is None
        assert data["fuel"]["fill_level"] == 100.0
        assert data["fuel"]["drain_rate"] == module.FUEL_DEFAULT_RATE
        assert data["alerts"]["alerts_on"] is True
        assert data["alerts"]["alert_threshold"] == 20


class TestStateSnapshotAuth:
    def test_unauthenticated_request_is_401(self, client, module):
        # /api/state is @auth_required: with a key configured but none supplied,
        # the request must be rejected with 401 (never leak state unauthenticated).
        module.CONFIG["API_KEY"] = "some-key"
        resp = client.get("/api/state")  # no ?key=
        assert resp.status_code == 401
