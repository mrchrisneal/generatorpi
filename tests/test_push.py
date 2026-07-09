# test_push.py -- the Web Push feature added to generator_control.py:
#   * VAPID keypair auto-generation in parse_env_file() (mirrors the API_KEY pattern)
#   * the subscription store (add/get/remove/count, UPSERT, browser PushSubscription shape)
#   * the HTTP surface: /api/push/subscribe, /api/push/unsubscribe, /api/push/test,
#     and the no-auth /sw.js service worker
#   * push_available() / push_status() / send_push() / send_push_async() -- the send path
#     and its granular "why is push off" reason (library_missing / no_keys / invalid_keys / ok)
#   * the state-transition + endpoint TRIGGERS that fire a push
#   * the /api/state "push" object (supported + reason + vapid_public_key + subscriptions)
#
# The app sends pushes ITSELF (NO pywebpush wrapper -- it has no Raspberry Pi OS apt package):
# py-vapid signs the VAPID JWT, http-ece does the aes128gcm payload encryption, and requests
# makes the HTTPS POST. So the ONLY thing mocked here is the network boundary --
# module.requests.post -- while the REAL VAPID signing + encryption run. No test ever contacts
# a real push service. Tests that need a working server key mint a REAL VAPID keypair locally
# (fast, offline); the send tests also mint a REAL browser keypair so http_ece.encrypt has a
# valid receiver key -- and one test DECRYPTS the captured body end-to-end to prove the
# encryption is correct.
import base64
import json
import os

import pytest

# py-vapid + http-ece are the push building blocks; we reuse the app's exact VAPID key recipe
# to mint real, self-consistent server keypairs, a raw EC key for a real browser subscription,
# and http_ece to prove the encrypted body round-trips back to the plaintext payload.
import http_ece
from cryptography.hazmat.primitives.asymmetric import ec
from py_vapid import Vapid
from py_vapid.utils import b64urlencode
from cryptography.hazmat.primitives import serialization


API_KEY = "push-test-key"


@pytest.fixture(autouse=True)
def _configure_api_key(module):
    """All push endpoints except /sw.js are @auth_required; give them a working key."""
    module.CONFIG["API_KEY"] = API_KEY


def _q(path):
    """Append the API key as a query param to authorize the request."""
    sep = "&" if "?" in path else "?"
    return f"{path}{sep}key={API_KEY}"


@pytest.fixture
def tmp_store(module, tmp_path):
    """Redirect the shared event/kv/subscription store to a throwaway sqlite DB so
    subscription + persistence + event assertions are hermetic, then restore the
    default store on teardown (same pattern the fuel/persistence suites use)."""
    module.init_event_store(db_path=tmp_path / "t.db")
    yield
    module.init_event_store()


def _gen_vapid_pair():
    """Generate a real VAPID keypair the way parse_env_file() does: private key as the
    raw 32-byte EC scalar (base64url), public key as the uncompressed EC point
    (base64url). Returns (priv_b64, pub_b64). Offline + fast -- no network."""
    v = Vapid()
    v.generate_keys()
    priv = b64urlencode(
        v.private_key.private_numbers().private_value.to_bytes(32, "big")
    )
    pub = b64urlencode(
        v.public_key.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
    )
    return priv, pub


def _gen_browser_keys():
    """Mint a VALID browser PushSubscription keypair the way a real browser would: p256dh is a
    fresh P-256 public key as the uncompressed point (base64url, unpadded); auth is 16 random
    bytes (base64url). Returns (p256dh_b64, auth_b64, browser_private_key, auth_raw) so a test
    can SUBSCRIBE with the public parts AND decrypt the pushed body with the private ones. Real
    keys are required now that send_push runs http_ece.encrypt for real (invalid keys raise)."""
    priv = ec.generate_private_key(ec.SECP256R1())
    p256dh = base64.urlsafe_b64encode(
        priv.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
    ).rstrip(b"=").decode()
    auth_raw = os.urandom(16)
    auth = base64.urlsafe_b64encode(auth_raw).rstrip(b"=").decode()
    return p256dh, auth, priv, auth_raw


@pytest.fixture
def vapid_key(module):
    """Configure a REAL server VAPID keypair so push_available() is True and send_push()
    can build a Vapid from it. The conftest baseline blanks these between tests, so this
    only lasts for the test that opts in."""
    priv, pub = _gen_vapid_pair()
    module.CONFIG["VAPID_PRIVATE_KEY"] = priv
    module.CONFIG["VAPID_PUBLIC_KEY"] = pub
    return priv, pub


class _Resp:
    """Minimal stand-in for a push-service HTTP response, exposing just the one field the send
    path (_deliver_push) reads: .status_code. Lets us drive the prune/fail branches."""

    def __init__(self, status_code):
        self.status_code = status_code


# ---------------------------------------------------------------------------
# 1. VAPID auto-generation in parse_env_file()
# ---------------------------------------------------------------------------
class TestVapidAutoGeneration:
    def test_generates_and_persists_keypair_on_fresh_env(self, module, env_paths):
        # parse_env_file() only runs its generation block when the env file EXISTS but
        # carries no private key (a missing file short-circuits to "no users"), so seed
        # an empty file. _PUSH_AVAILABLE is True in the test venv, so generation fires.
        env_paths.write_text("")
        module.parse_env_file()

        priv = module.CONFIG["VAPID_PRIVATE_KEY"]
        pub = module.CONFIG["VAPID_PUBLIC_KEY"]
        # Both keys are now set, non-empty, single-line and env-safe (no spaces): they
        # get written verbatim into a KEY=VALUE settings line, so a space/newline would
        # corrupt the file or the key.
        assert priv and pub
        for k in (priv, pub):
            assert "\n" not in k and " " not in k

        # They were actually persisted to the env file (survives a restart), not just
        # left in the in-memory CONFIG.
        text = env_paths.read_text()
        assert f"VAPID_PRIVATE_KEY={priv}" in text
        assert f"VAPID_PUBLIC_KEY={pub}" in text

        # The stored private scalar round-trips through Vapid.from_raw to the SAME public
        # key -- proving the pair is internally consistent (the send path relies on this).
        v = Vapid.from_raw(priv.encode())
        recovered_pub = b64urlencode(
            v.public_key.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
        )
        assert recovered_pub == pub

    def test_rotation_upserts_keys_in_place(self, module, env_paths):
        # Documented rotation: clear both VAPID VALUES (leaving the lines) and restart.
        # The private value is empty -> generation fires; because VAPID lines already
        # exist, the fresh keys are UPSERTed in place (not appended as a new block).
        env_paths.write_text("VAPID_PUBLIC_KEY=\nVAPID_PRIVATE_KEY=\n")
        module.parse_env_file()

        priv = module.CONFIG["VAPID_PRIVATE_KEY"]
        pub = module.CONFIG["VAPID_PUBLIC_KEY"]
        assert priv and pub
        lines = env_paths.read_text().splitlines()
        # Exactly one line per key (replaced in place, not duplicated) with the new value.
        priv_lines = [ln for ln in lines if ln.startswith("VAPID_PRIVATE_KEY=")]
        pub_lines = [ln for ln in lines if ln.startswith("VAPID_PUBLIC_KEY=")]
        assert priv_lines == [f"VAPID_PRIVATE_KEY={priv}"]
        assert pub_lines == [f"VAPID_PUBLIC_KEY={pub}"]

    def test_upsert_appends_missing_key_line(self, module, env_paths):
        # Only the PUBLIC line pre-exists (private value absent) -> generation fires and
        # UPSERT replaces the public line in place BUT appends a fresh PRIVATE line (the
        # append branch of the in-place _upsert helper).
        env_paths.write_text("VAPID_PUBLIC_KEY=stalepub\n")
        module.parse_env_file()
        lines = env_paths.read_text().splitlines()
        priv = module.CONFIG["VAPID_PRIVATE_KEY"]
        pub = module.CONFIG["VAPID_PUBLIC_KEY"]
        assert priv and pub
        # Public replaced in place (single line, new value); private appended (now present).
        assert [ln for ln in lines if ln.startswith("VAPID_PUBLIC_KEY=")] == \
            [f"VAPID_PUBLIC_KEY={pub}"]
        assert f"VAPID_PRIVATE_KEY={priv}" in lines

    def test_generation_failure_is_swallowed(self, module, env_paths, monkeypatch):
        # If the VAPID keypair generation raises, parse_env_file must NOT crash startup --
        # it logs a warning and leaves push unavailable (keys stay empty).
        def boom(*a, **k):
            raise RuntimeError("crypto backend unavailable")
        # VAPID keygen runs inside parse_env_file, which lives in genpi.config now (#59 Stage 2);
        # patch Vapid THERE (config's binding is the one that function calls).
        monkeypatch.setattr(module.config, "Vapid", boom)
        env_paths.write_text("")
        module.parse_env_file()                            # must not raise
        assert module.CONFIG["VAPID_PRIVATE_KEY"] == ""    # generation aborted cleanly

    def test_existing_keys_are_not_regenerated(self, module, env_paths):
        # Idempotency: when both VAPID keys are already present, the generation guard
        # (`not CONFIG["VAPID_PRIVATE_KEY"]`) is False, so the existing values must be
        # preserved exactly -- rotating the key on every restart would silently force
        # every browser to re-subscribe.
        priv, pub = _gen_vapid_pair()
        env_paths.write_text(
            f"VAPID_PRIVATE_KEY={priv}\nVAPID_PUBLIC_KEY={pub}\n"
        )
        module.parse_env_file()
        assert module.CONFIG["VAPID_PRIVATE_KEY"] == priv
        assert module.CONFIG["VAPID_PUBLIC_KEY"] == pub


# ---------------------------------------------------------------------------
# 2. Subscription store (add / get / remove / count, UPSERT, shape)
# ---------------------------------------------------------------------------
class TestSubscriptionStore:
    def test_add_get_remove_roundtrip(self, module, tmp_store):
        assert module.subscription_count() == 0
        module.add_subscription("ep-1", "p256-1", "auth-1")
        assert module.subscription_count() == 1

        subs = module.get_subscriptions()
        assert len(subs) == 1
        # get_subscriptions returns the browser PushSubscription shape (endpoint + keys).
        assert subs[0] == {
            "endpoint": "ep-1",
            "keys": {"p256dh": "p256-1", "auth": "auth-1"},
        }

        module.remove_subscription("ep-1")
        assert module.subscription_count() == 0
        assert module.get_subscriptions() == []

    def test_add_is_upsert_on_endpoint(self, module, tmp_store):
        # endpoint is the PRIMARY KEY: adding the same endpoint twice must update the
        # keys in place (a browser re-subscribing rotates its p256dh/auth), never
        # duplicate the row.
        module.add_subscription("ep-1", "old-p", "old-a")
        module.add_subscription("ep-1", "new-p", "new-a")
        assert module.subscription_count() == 1
        assert module.get_subscriptions()[0]["keys"] == {
            "p256dh": "new-p",
            "auth": "new-a",
        }

    def test_remove_unknown_endpoint_is_noop(self, module, tmp_store):
        # Removing an endpoint that was never stored is harmless (no raise, count stays).
        module.add_subscription("ep-1", "p", "a")
        module.remove_subscription("does-not-exist")
        assert module.subscription_count() == 1


# ---------------------------------------------------------------------------
# 3. HTTP endpoints: subscribe / unsubscribe / test / sw.js
# ---------------------------------------------------------------------------
class TestSubscribeEndpoint:
    def test_valid_subscription_is_stored(self, client, module, tmp_store):
        body = {"endpoint": "https://push.example/abc",
                "keys": {"p256dh": "PPP", "auth": "AAA"}}
        resp = client.post(_q("/api/push/subscribe"), json=body)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["subscriptions"] == 1
        # It really landed in the store in the browser PushSubscription shape.
        assert module.get_subscriptions()[0]["endpoint"] == "https://push.example/abc"

    @pytest.mark.parametrize("body", [
        {"keys": {"p256dh": "P", "auth": "A"}},          # missing endpoint
        {"endpoint": "ep"},                               # missing keys entirely
        {"endpoint": "ep", "keys": {"p256dh": "P"}},      # missing auth
        {"endpoint": "ep", "keys": {"auth": "A"}},        # missing p256dh
        {"endpoint": "", "keys": {"p256dh": "P", "auth": "A"}},  # empty endpoint
    ])
    def test_missing_fields_are_400_not_500(self, client, module, tmp_store, body):
        # Incomplete subscriptions are a client error (400), never a 500, and store nothing.
        resp = client.post(_q("/api/push/subscribe"), json=body)
        assert resp.status_code == 400
        assert resp.get_json()["success"] is False
        assert module.subscription_count() == 0

    @pytest.mark.parametrize("body", [[1, 2, 3], "hello", 5])
    def test_non_dict_body_is_400(self, client, module, tmp_store, body):
        # A non-dict JSON body ("invalid subscription") -> 400, not a 500 on .get().
        resp = client.post(_q("/api/push/subscribe"), json=body)
        assert resp.status_code == 400
        assert resp.get_json()["success"] is False

    def test_bodyless_post_is_400(self, client, module, tmp_store):
        # No body at all (get_json(silent=True) -> None) degrades to the non-dict 400.
        resp = client.post(_q("/api/push/subscribe"))
        assert resp.status_code == 400


class TestUnsubscribeEndpoint:
    def test_removes_subscription(self, client, module, tmp_store):
        module.add_subscription("ep-1", "p", "a")
        resp = client.post(_q("/api/push/unsubscribe"), json={"endpoint": "ep-1"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["subscriptions"] == 0
        assert module.subscription_count() == 0

    def test_missing_endpoint_is_400(self, client, module, tmp_store):
        resp = client.post(_q("/api/push/unsubscribe"), json={})
        assert resp.status_code == 400
        assert resp.get_json()["success"] is False

    def test_non_dict_body_missing_endpoint_is_400(self, client, module, tmp_store):
        # A non-dict body degrades to {} -> missing endpoint -> 400 (never a 500).
        resp = client.post(_q("/api/push/unsubscribe"), json=[1, 2])
        assert resp.status_code == 400


class TestPushTestEndpoint:
    def test_503_when_push_unavailable(self, client, module, tmp_store):
        # No VAPID key configured (conftest baseline) -> push_available() False -> 503.
        resp = client.post(_q("/api/push/test"))
        assert resp.status_code == 503
        assert resp.get_json()["success"] is False

    def test_409_when_no_subscriptions(self, client, module, tmp_store, vapid_key):
        # Key configured (push available) but nobody is subscribed -> 409 conflict.
        resp = client.post(_q("/api/push/test"))
        assert resp.status_code == 409
        assert resp.get_json()["success"] is False

    def test_200_and_triggers_send_when_ready(
        self, client, module, tmp_store, vapid_key, monkeypatch
    ):
        # Available + >=1 subscription -> 200, and it fires send_push_async. Patch the
        # async sender so NOTHING real is dispatched; just record that it was invoked.
        calls = []
        monkeypatch.setattr(module.store, "send_push_async",
                            lambda *a, **k: calls.append((a, k)))
        module.add_subscription("ep-1", "p", "a")
        resp = client.post(_q("/api/push/test"))
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True
        # Exactly one push dispatch, tagged "test" (the Advanced-drawer test button).
        assert len(calls) == 1
        assert calls[0][1].get("tag") == "test" or "test" in calls[0][0]


class TestPushEndpointsAuth:
    @pytest.mark.parametrize("path", [
        "/api/push/subscribe", "/api/push/unsubscribe", "/api/push/test",
    ])
    def test_unauthenticated_is_401(self, client, module, path):
        # With a key configured but none supplied, every push mutation is rejected 401.
        module.CONFIG["API_KEY"] = "some-key"
        resp = client.post(path, json={"endpoint": "ep"})  # no ?key=
        assert resp.status_code == 401


class TestServiceWorker:
    def test_sw_js_served_without_auth(self, client, module):
        # /sw.js holds no secrets and the browser's SW runtime fetches it directly, so
        # it must be reachable even with a key configured and NONE supplied.
        module.CONFIG["API_KEY"] = "some-key"
        resp = client.get("/sw.js")  # deliberately no ?key=
        assert resp.status_code == 200

    def test_sw_js_content_type_and_body(self, client):
        resp = client.get("/sw.js")
        assert resp.status_code == 200
        # Served as JavaScript (charset suffix allowed -> startswith, not ==).
        assert resp.headers["Content-Type"].startswith("application/javascript")
        body = resp.get_data(as_text=True)
        # The worker must handle the 'push' event and raise a notification.
        assert "push" in body
        assert "showNotification" in body


# ---------------------------------------------------------------------------
# 4. push_available() / push_status() / send_push() / send_push_async()
# ---------------------------------------------------------------------------
class TestPushAvailable:
    def test_false_without_vapid_key(self, module):
        # Baseline: no private key -> not available even though the libraries are installed.
        assert module.CONFIG["VAPID_PRIVATE_KEY"] == ""
        assert module.push_available() is False

    def test_true_with_key_and_lib(self, module, vapid_key):
        # Libraries present (_PUSH_AVAILABLE True in the venv) + a key -> available. Note
        # push_available() is a PRESENCE check (not full validity); push_status() validates.
        assert module._PUSH_AVAILABLE is True
        assert module.push_available() is True


class TestPushStatus:
    """push_status() -> (supported, reason). The reason is what lets the UI say WHY push is
    off instead of the old misleading blanket 'no VAPID keys' message."""

    def test_ok_when_libs_and_valid_key(self, module, vapid_key):
        assert module.push_status() == (True, "ok")

    def test_no_keys_when_libs_present_but_key_absent(self, module):
        # Libraries importable (venv) but no VAPID keypair configured -> "no_keys".
        assert module.CONFIG["VAPID_PRIVATE_KEY"] == ""
        assert module.push_status() == (False, "no_keys")

    def test_invalid_keys_when_key_will_not_parse(self, module):
        # A present but structurally invalid private scalar -> "invalid_keys" (NOT "no_keys").
        # This is the case an operator hits after hand-editing the settings file.
        module.CONFIG["VAPID_PRIVATE_KEY"] = "AAAA"
        module.CONFIG["VAPID_PUBLIC_KEY"] = "whatever"
        assert module.push_status() == (False, "invalid_keys")

    def test_library_missing_dominates_even_with_a_valid_key(
        self, module, monkeypatch, vapid_key
    ):
        # Simulate a Pi WITHOUT python3-py-vapid/http-ece/requests: even with a valid key the
        # missing library must be the reported reason -- that exact misdiagnosis (blaming keys
        # when the library was absent) is what this whole change fixes.
        monkeypatch.setattr(module.store, "_PUSH_AVAILABLE", False)
        assert module.push_status() == (False, "library_missing")

    def test_key_validity_is_cached_by_value(self, module, vapid_key):
        # _vapid_key_valid caches by key VALUE: validate on first sight, reuse for the same
        # value, re-validate when the value changes (so a poll never re-parses a steady key).
        assert module._vapid_key_valid() is True       # miss -> validate + cache
        assert module._vapid_key_valid() is True       # same value -> cache hit (no re-parse)
        module.CONFIG["VAPID_PRIVATE_KEY"] = "not-a-key"
        assert module._vapid_key_valid() is False       # value changed -> re-validated invalid

    def test_key_validity_false_for_empty_key(self, module):
        # Defensive: called directly with no key, the helper returns False (no crypto attempt).
        module.CONFIG["VAPID_PRIVATE_KEY"] = ""
        assert module._vapid_key_valid() is False


class TestSendPush:
    def _mock_post(self, module, monkeypatch, handler):
        """Replace ONLY the network boundary: module.requests.post ->
        handler(endpoint, data, headers) which returns a _Resp (or raises). The REAL
        vapid.sign + http_ece.encrypt still run before this, so the crypto path is exercised."""
        def fake_post(endpoint, data=None, headers=None, timeout=None, allow_redirects=None):
            return handler(endpoint, data, headers)
        monkeypatch.setattr(module.requests, "post", fake_post)

    def test_encrypts_a_payload_the_browser_can_decrypt(
        self, module, tmp_store, vapid_key, monkeypatch
    ):
        # End-to-end crypto proof: with a REAL browser keypair, capture the POSTed body and
        # decrypt it with the browser's OWN private key -> it must be the exact JSON payload.
        # Also asserts the VAPID Authorization header + aes128gcm content-encoding + ttl.
        p256dh, auth, browser_priv, auth_raw = _gen_browser_keys()
        captured = {}

        def handler(endpoint, data, headers):
            captured.update(endpoint=endpoint, data=data, headers=headers)
            return _Resp(201)

        self._mock_post(module, monkeypatch, handler)
        module.add_subscription("https://push.example/ep1", p256dh, auth)
        module.send_push("Hello", "World", tag="state")

        assert captured["headers"]["content-encoding"] == "aes128gcm"
        assert captured["headers"]["Authorization"].startswith("vapid ")
        assert captured["headers"]["ttl"] == str(module.PUSH_TTL_SECONDS)
        # The browser decrypts the aes128gcm body (salt + sender public key are embedded in it)
        # with its own private key + auth secret -> proves the whole encryption path is correct.
        plain = http_ece.decrypt(
            captured["data"], private_key=browser_priv, auth_secret=auth_raw, version="aes128gcm"
        )
        assert json.loads(plain) == {"title": "Hello", "body": "World", "tag": "state"}

    def test_sends_once_per_subscription_to_each_endpoint(
        self, module, tmp_store, vapid_key, monkeypatch
    ):
        # With 2 subscriptions, requests.post fires exactly twice -- once per endpoint -- each
        # with a VAPID auth header. (Payload correctness is proven by the decrypt test above.)
        posts = []
        p1, a1, _, _ = _gen_browser_keys()
        p2, a2, _, _ = _gen_browser_keys()

        def handler(endpoint, data, headers):
            posts.append((endpoint, headers))
            return _Resp(201)

        self._mock_post(module, monkeypatch, handler)
        module.add_subscription("https://push.example/ep-1", p1, a1)
        module.add_subscription("https://push.example/ep-2", p2, a2)
        module.send_push("Hello", "World", tag="state")

        assert len(posts) == 2
        assert {ep for ep, _ in posts} == {
            "https://push.example/ep-1", "https://push.example/ep-2"
        }
        for _, headers in posts:
            assert headers["Authorization"].startswith("vapid ")

    def test_post_refuses_redirects(self, module, tmp_store, vapid_key, monkeypatch):
        # SSRF defense in depth: the POST MUST pass allow_redirects=False so a subscribed
        # redirector endpoint can't 3xx-bounce the request to an internal address (a real push
        # service answers 201 directly and never redirects).
        seen = {}

        def fake_post(endpoint, data=None, headers=None, timeout=None, allow_redirects=None):
            seen["allow_redirects"] = allow_redirects
            return _Resp(201)

        monkeypatch.setattr(module.requests, "post", fake_post)
        p, a, _, _ = _gen_browser_keys()
        module.add_subscription("https://push.example/ep", p, a)
        module.send_push("t", "b")
        assert seen["allow_redirects"] is False

    @pytest.mark.parametrize("dead_status", [410, 404])
    def test_dead_subscription_is_pruned(
        self, module, tmp_store, vapid_key, monkeypatch, dead_status
    ):
        # A 404/410 from the push service means the browser is gone -> prune THAT subscription
        # while leaving the live one intact.
        pd, ad, _, _ = _gen_browser_keys()
        pl, al, _, _ = _gen_browser_keys()
        self._mock_post(
            module, monkeypatch,
            lambda e, d, h: _Resp(dead_status if e.endswith("dead") else 201),
        )
        module.add_subscription("https://push.example/dead", pd, ad)
        module.add_subscription("https://push.example/live", pl, al)

        module.send_push("t", "b")

        remaining = {s["endpoint"] for s in module.get_subscriptions()}
        assert remaining == {"https://push.example/live"}

    def test_other_error_status_is_not_pruned(
        self, module, tmp_store, vapid_key, monkeypatch
    ):
        # A non-404/410 failure (e.g. a transient 500) is logged but must NOT prune the
        # subscription -- the browser is still valid, the push just failed this time.
        p, a, _, _ = _gen_browser_keys()
        self._mock_post(module, monkeypatch, lambda e, d, h: _Resp(500))
        module.add_subscription("https://push.example/ep", p, a)
        module.send_push("t", "b")   # must not raise
        assert module.subscription_count() == 1

    def test_transport_error_is_swallowed_and_not_pruned(
        self, module, tmp_store, vapid_key, monkeypatch
    ):
        # A requests transport failure (timeout / DNS / TLS / connreset) is caught PER
        # subscription so send_push never raises into its state-transition / monitor callers,
        # and the sub is kept (a transport blip doesn't mean the browser unsubscribed).
        p, a, _, _ = _gen_browser_keys()

        def boom(e, d, h):
            raise module.requests.RequestException("connection reset")

        self._mock_post(module, monkeypatch, boom)
        module.add_subscription("https://push.example/ep", p, a)
        module.send_push("t", "b")   # must not raise
        assert module.subscription_count() == 1

    def test_generic_send_error_is_swallowed_and_not_pruned(
        self, module, tmp_store, vapid_key, monkeypatch
    ):
        # A non-requests error (e.g. a bug during encode) must ALSO be swallowed per
        # subscription and must NOT prune -- only a 404/410 means the browser is gone.
        p, a, _, _ = _gen_browser_keys()

        def boom(e, d, h):
            raise ValueError("unexpected failure")

        self._mock_post(module, monkeypatch, boom)
        module.add_subscription("https://push.example/ep", p, a)
        module.send_push("t", "b")   # must not raise
        assert module.subscription_count() == 1

    def test_noop_when_push_unavailable(self, module, tmp_store, monkeypatch):
        # No VAPID key -> send_push short-circuits before touching the network at all.
        posts = []
        self._mock_post(module, monkeypatch, lambda e, d, h: posts.append(e) or _Resp(201))
        module.add_subscription("https://push.example/ep", "p", "a")  # sub exists, no key
        module.send_push("t", "b")
        assert posts == []

    def test_noop_when_no_subscriptions(
        self, module, tmp_store, vapid_key, monkeypatch
    ):
        # Key set but zero subscriptions -> nothing to send, requests.post never called.
        posts = []
        self._mock_post(module, monkeypatch, lambda e, d, h: posts.append(e) or _Resp(201))
        module.send_push("t", "b")
        assert posts == []

    def test_invalid_vapid_key_aborts_without_sending(
        self, module, tmp_store, monkeypatch
    ):
        # push_available() is a PRESENCE check, so a present-but-malformed private key passes
        # it -> send_push reaches Vapid.from_raw("AAAA"), which raises -> it logs + returns,
        # never posting. Exercises the send-path from_raw guard (defense in depth).
        module.CONFIG["VAPID_PRIVATE_KEY"] = "AAAA"
        module.CONFIG["VAPID_PUBLIC_KEY"] = "whatever"
        assert module.push_available() is True
        posts = []
        self._mock_post(module, monkeypatch, lambda e, d, h: posts.append(e) or _Resp(201))
        p, a, _, _ = _gen_browser_keys()
        module.add_subscription("https://push.example/ep", p, a)
        module.send_push("t", "b")   # must not raise
        assert posts == []


class TestSendPushAsync:
    def test_spawns_thread_that_runs_send_push(self, module, vapid_key, monkeypatch):
        # send_push_async offloads send_push onto a daemon thread. Patch threading.Thread
        # with a synchronous fake so the dispatch is deterministic, and patch send_push
        # to a recorder so nothing real fires.
        ran = []

        class FakeThread:
            def __init__(self, target=None, args=(), daemon=None):
                self._target = target
                self._args = args

            def start(self):
                # Run synchronously so the assertion below is deterministic.
                self._target(*self._args)

        monkeypatch.setattr(module.threading, "Thread", FakeThread)
        monkeypatch.setattr(module.store, "send_push",
                            lambda *a, **k: ran.append((a, k)))

        module.send_push_async("Title", "Body", tag="state")
        assert ran == [(("Title", "Body", "state"), {})]

    def test_noop_when_unavailable(self, module, monkeypatch):
        # With push unavailable, send_push_async returns BEFORE creating any thread.
        created = []

        class FakeThread:
            def __init__(self, *a, **k):
                created.append((a, k))

            def start(self):  # pragma: no cover - never reached in this test
                pass

        monkeypatch.setattr(module.threading, "Thread", FakeThread)
        module.send_push_async("t", "b")  # no VAPID key -> guard returns early
        assert created == []


# ---------------------------------------------------------------------------
# 5. Triggers -- state transitions + endpoints that fire a push
# ---------------------------------------------------------------------------
class TestPushTriggers:
    @pytest.fixture
    def record_async(self, module, monkeypatch):
        """Patch send_push_async to record its calls without dispatching anything."""
        calls = []
        monkeypatch.setattr(module.store, "send_push_async",
                            lambda *a, **k: calls.append((a, k)))
        return calls

    def test_stop_generator_pushes(self, client, module, tmp_store, no_sleep, record_async):
        # A real stop (relay is a MagicMock, sleep is a no-op) notifies subscribers.
        resp = client.post(_q("/api/stop"))
        assert resp.status_code == 200
        assert len(record_async) == 1

    def test_start_generator_pushes(self, module, tmp_store, no_sleep, record_async):
        # Drive start_generator() directly (no_sleep keeps it instant); completion pushes.
        result = module.start_generator()
        assert result["success"] is True
        assert len(record_async) == 1

    def test_set_running_true_pushes(self, client, module, tmp_store, record_async):
        resp = client.post(_q("/api/set_running"), json={"running": True})
        assert resp.status_code == 200
        assert len(record_async) == 1

    def test_set_running_false_pushes(self, client, module, tmp_store, record_async):
        resp = client.post(_q("/api/set_running"), json={"running": False})
        assert resp.status_code == 200
        assert len(record_async) == 1

    def test_push_test_endpoint_triggers_send(
        self, client, module, tmp_store, vapid_key, record_async
    ):
        # /api/push/test dispatches when available + subscribed.
        module.add_subscription("ep-1", "p", "a")
        resp = client.post(_q("/api/push/test"))
        assert resp.status_code == 200
        assert len(record_async) == 1


# ---------------------------------------------------------------------------
# 6. /api/state "push" object
# ---------------------------------------------------------------------------
class TestStatePushObject:
    def test_push_object_shape_when_unavailable(self, client, module, tmp_store):
        # No key, no subs: supported False, and reason "no_keys" (libraries ARE present in the
        # venv, so the cause is the missing keypair) -- this is what the UI renders a message
        # from. Also: empty public key string, 0 subscriptions.
        resp = client.get(_q("/api/state"))
        assert resp.status_code == 200
        push = resp.get_json()["push"]
        assert push["supported"] is False
        assert push["reason"] == "no_keys"
        assert push["vapid_public_key"] == ""
        assert isinstance(push["vapid_public_key"], str)
        assert push["subscriptions"] == 0
        assert isinstance(push["subscriptions"], int)

    def test_push_object_reflects_key_and_subscriptions(
        self, client, module, tmp_store, vapid_key
    ):
        priv, pub = vapid_key
        module.add_subscription("ep-1", "p", "a")
        resp = client.get(_q("/api/state"))
        push = resp.get_json()["push"]
        # supported mirrors push_available(); reason "ok"; vapid_public_key is the configured pubkey.
        assert push["supported"] is True
        assert push["reason"] == "ok"
        assert push["vapid_public_key"] == pub
        assert push["subscriptions"] == 1
