# test_endpoints.py -- Flask routes (/, /api/start, /api/stop, /api/status,
# /api/set_running), the security headers applied to every response, and the
# assertion that Flask's built-in /static route is fully disabled.
#
# All routes are @auth_required, so an API key is configured and passed on each
# request. Relay side effects are patched out so nothing sleeps or touches "hardware".
import base64
import logging

import pytest


API_KEY = "endpoint-test-key"


@pytest.fixture(autouse=True)
def _configure_api_key(module):
    """Give every endpoint test a working API key for auth."""
    module.CONFIG["API_KEY"] = API_KEY


def _q(path):
    """Append the API key as a query param to authorize the request."""
    sep = "&" if "?" in path else "?"
    return f"{path}{sep}key={API_KEY}"


class TestIndex:
    def test_renders_html(self, client):
        resp = client.get(_q("/"))
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        assert "GeneratorPi" in body
        # Default state is server-rendered STOPPED (annunciator word).
        assert "STOPPED" in body

    def test_reflects_running_state(self, client, module):
        with module.state_lock:
            module.generator_state["running"] = True
        resp = client.get(_q("/"))
        assert "RUNNING" in resp.get_data(as_text=True)


class TestApiStart:
    def test_start_spawns_background_thread(self, client, module, monkeypatch):
        # Patch threading.Thread so no real thread/relay work happens; assert the
        # endpoint wires start_generator as the daemon target.
        created = {}

        class FakeThread:
            def __init__(self, target=None, daemon=None):
                created["target"] = target
                created["daemon"] = daemon

            def start(self):
                created["started"] = True

        monkeypatch.setattr(module.threading, "Thread", FakeThread)
        resp = client.post(_q("/api/start"))
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert created["target"] is module.start_generator
        assert created["daemon"] is True
        assert created["started"] is True

    def test_start_returns_409_when_relay_busy(self, client, module):
        # Hold the relay lock to simulate an in-progress sequence.
        acquired = module.relay_lock.acquire(blocking=False)
        assert acquired
        try:
            resp = client.post(_q("/api/start"))
            assert resp.status_code == 409
            assert resp.get_json()["success"] is False
        finally:
            module.relay_lock.release()


class TestApiStop:
    def test_stop_presses_button_and_updates_state(self, client, module, no_sleep):
        # Real stop_generator runs, but time.sleep is a no-op (no_sleep) and the
        # relay is a MagicMock, so it's instant and hardware-free.
        resp = client.post(_q("/api/stop"))
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True
        assert module.generator_state["running"] is False
        assert module.generator_state["last_command"] == "stop"
        # The relay was toggled on then off at least once.
        assert module.relay_start_stop.on.called
        assert module.relay_start_stop.off.called


class TestApiStatus:
    def test_status_returns_state_json(self, client, module):
        with module.state_lock:
            module.generator_state["message"] = "hello-world"
        resp = client.get(_q("/api/status"))
        assert resp.status_code == 200
        assert resp.get_json()["message"] == "hello-world"


class TestNonAsciiApiKeyRequest:
    def test_non_ascii_key_does_not_500_and_records_failure(self, client, module):
        # FIX #1 (end-to-end): a non-ASCII ?key= must NOT 500. It compares unequal,
        # falls through to basic-auth (none present) -> 401, and is counted as a
        # failed attempt so it still contributes to lockout.
        module.CONFIG["API_KEY"] = "correct-key"
        resp = client.get("/api/status?key=café")
        assert resp.status_code == 401
        assert resp.status_code != 500
        assert module._fail_tracker["127.0.0.1"]["count"] == 1


class TestApiKeyIdentityNotForgeable:
    def test_keyed_request_with_stray_basic_header_logs_apikey(
        self, client, module, caplog
    ):
        # FIX #5 (end-to-end): hit an endpoint that logs caller_identity() with a
        # VALID ?key= plus a bogus Authorization: Basic header. The audit log must
        # attribute the action to "apikey", never the smuggled header username.
        bogus = base64.b64encode(b"attacker:whatever").decode()
        with caplog.at_level(logging.INFO, logger="generator_control"):
            resp = client.post(
                _q("/api/set_running"),
                json={"running": True},
                headers={"Authorization": "Basic " + bogus},
            )
        assert resp.status_code == 200
        # The "State manually set ... by <identity>" line must credit apikey.
        set_lines = [r.message for r in caplog.records
                     if "State manually set" in r.message]
        assert set_lines, "expected a 'State manually set' audit log line"
        assert "by apikey" in set_lines[-1]
        assert "attacker" not in set_lines[-1]


class TestApiSetRunning:
    def test_set_running_true(self, client, module):
        resp = client.post(_q("/api/set_running"), json={"running": True})
        assert resp.status_code == 200
        assert resp.get_json()["running"] is True
        assert module.generator_state["running"] is True
        assert "RUNNING" in module.generator_state["message"]

    def test_set_running_false(self, client, module):
        with module.state_lock:
            module.generator_state["running"] = True
        resp = client.post(_q("/api/set_running"), json={"running": False})
        assert resp.status_code == 200
        assert resp.get_json()["running"] is False
        assert module.generator_state["running"] is False

    def test_set_running_json_null_defaults_false(self, client, module):
        # A JSON `null` body -> request.get_json() returns None -> `or {}` kicks in
        # -> data.get('running', False) defaults to False. This is the only path
        # that actually reaches the `or {}` fallback.
        resp = client.post(
            _q("/api/set_running"), data="null", content_type="application/json"
        )
        assert resp.status_code == 200
        assert resp.get_json()["running"] is False

    def test_set_running_bodyless_post_defaults_stopped(self, client, module):
        # FIXED behavior: with request.get_json(silent=True), a bodyless POST no
        # longer 415s -- get_json returns None, the isinstance guard yields {}, and
        # data.get('running', False) defaults to False (STOPPED).
        with module.state_lock:
            module.generator_state["running"] = True  # start from RUNNING
        resp = client.post(_q("/api/set_running"))
        assert resp.status_code == 200
        assert resp.get_json()["running"] is False
        assert module.generator_state["running"] is False

    @pytest.mark.parametrize("body", [[1, 2], "hi", 5])
    def test_set_running_non_dict_body_defaults_stopped(self, client, module, body):
        # FIX #4: a NON-dict JSON body (list / string / number) must not 500. The
        # isinstance(data, dict) guard replaces it with {} -> defaults to STOPPED.
        with module.state_lock:
            module.generator_state["running"] = True
        resp = client.post(_q("/api/set_running"), json=body)
        assert resp.status_code == 200
        assert resp.get_json()["running"] is False
        assert module.generator_state["running"] is False

    @pytest.mark.parametrize("val", ["true", "1", "yes", "on"])
    def test_set_running_truthy_string_coerces_true(self, client, module, val):
        # FIX #4: recognized truthy string forms coerce to RUNNING (real bool True).
        resp = client.post(_q("/api/set_running"), json={"running": val})
        assert resp.status_code == 200
        assert resp.get_json()["running"] is True
        assert module.generator_state["running"] is True

    @pytest.mark.parametrize("val", ["false", "0", "no", "off", "", "garbage"])
    def test_set_running_falsy_string_coerces_false(self, client, module, val):
        # FIX #4: "false"/"0"/"no" -- and any UNrecognized string -- map to STOPPED,
        # never a truthy non-empty string. Start from RUNNING to prove it flips.
        with module.state_lock:
            module.generator_state["running"] = True
        resp = client.post(_q("/api/set_running"), json={"running": val})
        assert resp.status_code == 200
        assert resp.get_json()["running"] is False
        assert module.generator_state["running"] is False

    def test_set_running_native_bool_true(self, client, module):
        # A native JSON boolean true still works via bool(raw).
        resp = client.post(_q("/api/set_running"), json={"running": True})
        assert resp.status_code == 200
        assert resp.get_json()["running"] is True


class TestSecurityHeaders:
    def test_headers_present_on_authed_response(self, client):
        resp = client.get(_q("/api/status"))
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        # Redesign tightened the CSP: default-deny, inline-only, same-origin fetch.
        csp = resp.headers["Content-Security-Policy"]
        assert "default-src 'none'" in csp
        assert "connect-src 'self'" in csp
        assert "script-src 'self' 'unsafe-inline'" in csp

    def test_headers_present_on_401_response(self, client, module):
        # Security headers are applied via after_request to EVERY response,
        # including auth failures.
        module.CONFIG["API_KEY"] = "different"
        resp = client.get("/api/status")  # no key -> 401
        assert resp.status_code == 401
        assert resp.headers["X-Frame-Options"] == "DENY"

    def test_hsts_present_when_ssl_enabled(self, client, module):
        module.CONFIG["SSL_ENABLED"] = 1
        resp = client.get(_q("/api/status"))
        assert resp.headers.get("Strict-Transport-Security") == "max-age=31536000"

    def test_hsts_absent_when_ssl_disabled(self, client, module):
        module.CONFIG["SSL_ENABLED"] = 0
        resp = client.get(_q("/api/status"))
        assert "Strict-Transport-Security" not in resp.headers


class TestStaticRouteDisabled:
    def test_static_folder_is_none(self, module):
        assert module.app.static_folder is None

    def test_static_path_returns_404(self, client):
        # With static_folder=None there is no /static/<path> route registered.
        resp = client.get("/static/anything.txt")
        assert resp.status_code == 404


class TestSystemDrawerMarkup:
    def test_system_drawer_present(self, client):
        body = client.get(_q("/")).get_data(as_text=True)
        assert 'id="sysDrawer"' in body
        for cid in ("sysChart-compute", "sysChart-load",
                    "sysChart-vitals", "sysChart-link"):
            assert f'id="{cid}"' in body
        assert "SYSTEM" in body and "VITALS" in body
