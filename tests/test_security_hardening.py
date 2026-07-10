# test_security_hardening.py -- the batch of security fixes layered onto
# generator_control.py:
#   * CSRF origin/referer guard on state-changing methods (@app.before_request)
#   * SSRF hardening of /api/push/subscribe (https-only, no internal-IP endpoints)
#   * non-finite number rejection in _json_number (Infinity/NaN can't persist)
#   * the push-subscription table cap (SUBSCRIPTION_MAX eviction)
#
# All mutating routes are @auth_required, so an API key is configured and passed on
# each request via the same _q() helper the other suites use. The Flask test client's
# default origin is http://localhost (request.scheme=http, request.host=localhost), so
# "http://localhost" is the same-origin value the CSRF guard compares against.
import socket
import time

import pytest


API_KEY = "hardening-test-key"

# The origin the Flask test client serves requests on by default -- what the CSRF
# guard computes as `expected` = f"{request.scheme}://{request.host}".
SAME_ORIGIN = "http://localhost"


@pytest.fixture(autouse=True)
def _configure_api_key(module):
    """Every mutating route is @auth_required; give them a working key."""
    module.CONFIG["API_KEY"] = API_KEY


def _q(path):
    """Append the API key as a query param to authorize the request."""
    sep = "&" if "?" in path else "?"
    return f"{path}{sep}key={API_KEY}"


@pytest.fixture
def tmp_store(module, tmp_path):
    """Redirect the shared event/kv/subscription store to a throwaway sqlite DB so
    subscription + persistence assertions are hermetic, then restore the default store
    on teardown (same pattern the push/fuel suites use)."""
    module.init_event_store(db_path=tmp_path / "t.db")
    yield
    module.init_event_store()


# ---------------------------------------------------------------------------
# 1. CSRF origin/referer guard (@app.before_request)
# ---------------------------------------------------------------------------
class TestCsrfOriginGuard:
    def test_cross_origin_post_is_rejected_403(self, client):
        # A mutating POST carrying a foreign Origin (a real cross-site auto-submit) is
        # rejected 403 before it can reach the handler -- the CSRF defense.
        resp = client.post(
            _q("/api/set_running"),
            json={"running": True},
            headers={"Origin": "https://evil.example"},
        )
        assert resp.status_code == 403
        data = resp.get_json()
        assert data["success"] is False
        assert data["message"] == "cross-origin request rejected"

    def test_same_origin_post_is_allowed(self, client):
        # The browser UI's own same-origin fetch sets Origin == expected -> allowed.
        resp = client.post(
            _q("/api/set_running"),
            json={"running": True},
            headers={"Origin": SAME_ORIGIN},
        )
        assert resp.status_code == 200
        assert resp.get_json()["running"] is True

    def test_no_origin_post_is_allowed(self, client):
        # No Origin AND no Referer -> a non-browser (API-key/curl/HomeAssistant) caller.
        # This is the default for the whole existing suite; it must stay allowed.
        resp = client.post(_q("/api/set_running"), json={"running": False})
        assert resp.status_code == 200
        assert resp.get_json()["running"] is False

    def test_get_with_bad_origin_is_not_blocked(self, client):
        # GET is a safe method: even a foreign Origin must NOT be blocked (the guard only
        # covers POST/PUT/PATCH/DELETE).
        resp = client.get(
            _q("/api/status"), headers={"Origin": "https://evil.example"}
        )
        assert resp.status_code == 200

    def test_cross_origin_referer_is_rejected_403(self, client):
        # Origin absent but a foreign Referer present -> reject (the Referer fallback).
        resp = client.post(
            _q("/api/set_running"),
            json={"running": True},
            headers={"Referer": "https://evil.example/attack"},
        )
        assert resp.status_code == 403
        assert resp.get_json()["message"] == "cross-origin request rejected"

    def test_same_origin_referer_is_allowed(self, client):
        # A Referer under our own origin (the usual same-origin navigation case) passes.
        resp = client.post(
            _q("/api/set_running"),
            json={"running": True},
            headers={"Referer": SAME_ORIGIN + "/"},
        )
        assert resp.status_code == 200

    def test_prefix_lookalike_referer_is_rejected(self, client):
        # A host that merely PREFIXES our origin ("http://localhost.evil.com") must not
        # slip through the startswith() check -- expected + "/" anchors it.
        resp = client.post(
            _q("/api/set_running"),
            json={"running": True},
            headers={"Referer": SAME_ORIGIN + ".evil.com/x"},
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 2. SSRF hardening of /api/push/subscribe
# ---------------------------------------------------------------------------
class TestPushSubscribeSsrf:
    def _body(self, endpoint):
        # A structurally complete subscription so only the endpoint URL is under test.
        return {"endpoint": endpoint, "keys": {"p256dh": "PPP", "auth": "AAA"}}

    def test_http_endpoint_is_rejected_400(self, client, module, tmp_store):
        # Non-https endpoint -> 400 and nothing stored.
        resp = client.post(
            _q("/api/push/subscribe"), json=self._body("http://push.example/abc")
        )
        assert resp.status_code == 400
        assert resp.get_json()["success"] is False
        assert module.subscription_count() == 0

    @pytest.mark.parametrize("endpoint", [
        "https://127.0.0.1/abc",        # loopback
        "https://192.168.1.50/abc",     # private (RFC1918)
        "https://10.0.0.5/abc",         # private
        "https://169.254.169.254/abc",  # link-local (cloud metadata)
    ])
    def test_internal_ip_endpoint_is_rejected_400(
        self, client, module, tmp_store, endpoint
    ):
        # An IP-literal endpoint in a private/loopback/link-local range is an SSRF
        # vector (send_push() would POST to it) -> 400, nothing stored.
        resp = client.post(_q("/api/push/subscribe"), json=self._body(endpoint))
        assert resp.status_code == 400
        assert resp.get_json()["success"] is False
        assert module.subscription_count() == 0

    def test_public_hostname_endpoint_is_accepted_200(self, client, module, tmp_store, monkeypatch):
        # A normal push-service DNS hostname that RESOLVES to a public address passes and is stored.
        # DNS is mocked so the test never depends on real name resolution (#33 added the resolve step).
        monkeypatch.setattr(module.routes.push.socket, "getaddrinfo",
                            lambda host, port, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("142.250.1.1", port))])
        endpoint = "https://fcm.googleapis.com/fcm/send/abc123"
        resp = client.post(_q("/api/push/subscribe"), json=self._body(endpoint))
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True
        assert module.get_subscriptions()[0]["endpoint"] == endpoint

    def test_endpoint_validator_unit(self, module, monkeypatch):
        # Direct unit coverage of the validator helper: https host resolving public -> None (ok);
        # http, and internal-IP hosts -> an error string. DNS mocked to a public address (no network).
        monkeypatch.setattr(module.routes.push.socket, "getaddrinfo",
                            lambda host, port, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("142.250.1.1", port))])
        assert module._push_endpoint_error("https://fcm.googleapis.com/x") is None
        assert module._push_endpoint_error("http://fcm.googleapis.com/x") is not None
        assert module._push_endpoint_error("https://127.0.0.1/x") is not None
        assert module._push_endpoint_error("https://10.1.2.3/x") is not None


# ---------------------------------------------------------------------------
# 3. Non-finite number rejection in _json_number
# ---------------------------------------------------------------------------
class TestNonFiniteNumbers:
    def test_fuel_rate_1e999_is_400(self, client, module, tmp_store):
        # "1e999" parses to float('inf'); persisting Infinity would corrupt /api/state.
        resp = client.post(_q("/api/fuel/rate"), json={"rate": "1e999"})
        assert resp.status_code == 400
        assert resp.get_json()["success"] is False

    def test_fuel_reading_nan_is_400(self, client, module, tmp_store):
        # "nan" parses to a NaN float; reject it as non-finite.
        resp = client.post(_q("/api/fuel/reading"), json={"level": "nan"})
        assert resp.status_code == 400
        assert resp.get_json()["success"] is False

    def test_alerts_threshold_inf_is_400_not_500(self, client, module, tmp_store):
        # "inf" would hit int(float('inf')) -> OverflowError -> 500 without the guard.
        # It must be a clean 400 client error instead.
        resp = client.post(_q("/api/alerts"), json={"threshold": "inf"})
        assert resp.status_code == 400
        assert resp.status_code != 500
        assert resp.get_json()["success"] is False

    def test_finite_value_still_works(self, client, module, tmp_store):
        # Regression guard: an ordinary finite number is unaffected by the new check.
        resp = client.post(_q("/api/fuel/rate"), json={"rate": "5.5"})
        assert resp.status_code == 200
        assert resp.get_json()["drain_rate"] == 5.5

    def test_json_number_helper_rejects_non_finite(self, module):
        # Direct unit coverage: inf/-inf/nan (native + string) all -> finite error.
        for bad in (float("inf"), float("-inf"), float("nan"), "inf", "-inf", "nan", "1e999"):
            val, err = module._json_number({"x": bad}, "x")
            assert val is None
            assert err == "'x' is not a finite number"
        # A finite value still round-trips cleanly.
        val, err = module._json_number({"x": "3.25"}, "x")
        assert err is None
        assert val == 3.25


# ---------------------------------------------------------------------------
# 4. Push-subscription table cap (SUBSCRIPTION_MAX eviction)
# ---------------------------------------------------------------------------
class TestSubscriptionCap:
    def test_oldest_evicted_beyond_cap(self, module, tmp_store, monkeypatch):
        # Cap the table at 3, then add 5 distinct subscriptions. Only the newest 3
        # (by created_ts) survive; the two oldest are evicted.
        monkeypatch.setitem(module.CONFIG, "SUBSCRIPTION_MAX", 3)
        for i in range(5):
            module.add_subscription(f"ep-{i}", f"p{i}", f"a{i}")
            # A tiny sleep guarantees strictly-increasing created_ts so the eviction
            # order (ORDER BY created_ts DESC) is deterministic regardless of clock
            # resolution.
            time.sleep(0.002)

        assert module.subscription_count() == 3
        remaining = {s["endpoint"] for s in module.get_subscriptions()}
        # The 3 newest kept; the 2 oldest gone.
        assert remaining == {"ep-2", "ep-3", "ep-4"}
        assert "ep-0" not in remaining
        assert "ep-1" not in remaining
