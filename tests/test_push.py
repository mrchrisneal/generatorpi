# test_push.py -- the Web Push feature added to generator_control.py:
#   * VAPID keypair auto-generation in parse_env_file() (mirrors the API_KEY pattern)
#   * the subscription store (add/get/remove/count, UPSERT, pywebpush shape)
#   * the HTTP surface: /api/push/subscribe, /api/push/unsubscribe, /api/push/test,
#     and the no-auth /sw.js service worker
#   * push_available() / send_push() / send_push_async() (the network send path)
#   * the state-transition + endpoint TRIGGERS that fire a push
#   * the /api/state "push" object
#
# HARD RULE for this file: the real network send (module.webpush) is ALWAYS mocked --
# no test may ever contact a real push service. Tests that need a working server key
# generate a REAL VAPID keypair locally (fast, offline) and set it on CONFIG so
# push_available() flips True and send_push() reaches the (mocked) webpush() call.
import json

import pytest

# py_vapid is a hard dep of the push feature (pywebpush pulls it in); the send path
# round-trips the stored private scalar through Vapid.from_raw, so we reuse the exact
# generation recipe the app uses to mint a real, self-consistent test keypair.
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
    """Minimal stand-in for a pushService HTTP response, exposing just the one field
    send_push() inspects: .status_code. Lets us drive the prune branch deterministically."""

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
        monkeypatch.setattr(module, "Vapid", boom)
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
        # get_subscriptions returns the exact pywebpush "subscription_info" shape.
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
        # It really landed in the store in pywebpush shape.
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
        monkeypatch.setattr(module, "send_push_async",
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
# 4. push_available() / send_push() / send_push_async()
# ---------------------------------------------------------------------------
class TestPushAvailable:
    def test_false_without_vapid_key(self, module):
        # Baseline: no private key -> not available even though the lib is installed.
        assert module.CONFIG["VAPID_PRIVATE_KEY"] == ""
        assert module.push_available() is False

    def test_true_with_key_and_lib(self, module, vapid_key):
        # Library present (_PUSH_AVAILABLE True in the venv) + a key -> available.
        assert module._PUSH_AVAILABLE is True
        assert module.push_available() is True


class TestSendPush:
    def test_sends_once_per_subscription_with_payload_and_claims(
        self, module, tmp_store, vapid_key, monkeypatch
    ):
        # With 2 subscriptions, webpush() must be called exactly twice (once each), and
        # each call must carry the JSON payload + a fresh vapid_claims {"sub": ...}.
        calls = []
        monkeypatch.setattr(module, "webpush", lambda **kw: calls.append(kw))
        module.add_subscription("ep-1", "p1", "a1")
        module.add_subscription("ep-2", "p2", "a2")

        module.send_push("Hello", "World", tag="state")

        assert len(calls) == 2
        for kw in calls:
            # Payload is the JSON-encoded notification content.
            payload = json.loads(kw["data"])
            assert payload["title"] == "Hello"
            assert payload["body"] == "World"
            assert payload["tag"] == "state"
            # The VAPID 'sub' claim comes from CONFIG["VAPID_SUBJECT"] (default mailto).
            assert kw["vapid_claims"] == {"sub": "mailto:admin@localhost"}
        # Both distinct endpoints were targeted.
        endpoints = {kw["subscription_info"]["endpoint"] for kw in calls}
        assert endpoints == {"ep-1", "ep-2"}

    @pytest.mark.parametrize("dead_status", [410, 404])
    def test_dead_subscription_is_pruned(
        self, module, tmp_store, vapid_key, monkeypatch, dead_status
    ):
        # A 404/410 from a pushService means the browser is gone -> that subscription is
        # pruned. The live one is left intact.
        def fake_webpush(**kw):
            if kw["subscription_info"]["endpoint"] == "ep-dead":
                raise module.WebPushException("gone", response=_Resp(dead_status))
            # ep-live succeeds silently.

        monkeypatch.setattr(module, "webpush", fake_webpush)
        module.add_subscription("ep-dead", "p", "a")
        module.add_subscription("ep-live", "p", "a")

        module.send_push("t", "b")

        remaining = {s["endpoint"] for s in module.get_subscriptions()}
        assert remaining == {"ep-live"}

    def test_other_error_status_is_not_pruned(
        self, module, tmp_store, vapid_key, monkeypatch
    ):
        # A non-404/410 failure (e.g. a transient 500) is swallowed but must NOT prune
        # the subscription -- the browser is still valid, the push just failed this time.
        def fake_webpush(**kw):
            raise module.WebPushException("boom", response=_Resp(500))

        monkeypatch.setattr(module, "webpush", fake_webpush)
        module.add_subscription("ep-1", "p", "a")
        # Must not raise into the caller.
        module.send_push("t", "b")
        assert module.subscription_count() == 1

    def test_generic_send_error_is_swallowed_and_not_pruned(
        self, module, tmp_store, vapid_key, monkeypatch
    ):
        # A non-WebPushException failure (e.g. a bug or a transport error surfacing as a plain
        # Exception) must be swallowed per-subscription -- send_push is fired from state-transition
        # paths + a monitor thread and MUST NOT raise. The subscription is NOT pruned (only a
        # 404/410 from the push service means the browser is gone).
        def fake_webpush(**kw):
            raise ValueError("unexpected transport failure")

        monkeypatch.setattr(module, "webpush", fake_webpush)
        module.add_subscription("ep-1", "p", "a")
        module.send_push("t", "b")   # must not raise
        assert module.subscription_count() == 1

    def test_noop_when_push_unavailable(self, module, tmp_store, monkeypatch):
        # No VAPID key -> send_push short-circuits before touching webpush at all.
        calls = []
        monkeypatch.setattr(module, "webpush", lambda **kw: calls.append(kw))
        module.add_subscription("ep-1", "p", "a")  # a sub exists, but no key
        module.send_push("t", "b")
        assert calls == []

    def test_noop_when_no_subscriptions(
        self, module, tmp_store, vapid_key, monkeypatch
    ):
        # Key set but zero subscriptions -> nothing to send, webpush never called.
        calls = []
        monkeypatch.setattr(module, "webpush", lambda **kw: calls.append(kw))
        module.send_push("t", "b")
        assert calls == []

    def test_invalid_vapid_key_aborts_without_sending(
        self, module, tmp_store, monkeypatch
    ):
        # A malformed (but non-empty) private key makes push_available() True yet
        # Vapid.from_raw() raises -> send_push logs + returns, never reaching webpush.
        # "AAAA" is a non-empty (so push_available() True) but structurally invalid
        # private scalar -> Vapid.from_raw() raises ValueError inside send_push.
        module.CONFIG["VAPID_PRIVATE_KEY"] = "AAAA"
        module.CONFIG["VAPID_PUBLIC_KEY"] = "whatever"
        assert module.push_available() is True
        calls = []
        monkeypatch.setattr(module, "webpush", lambda **kw: calls.append(kw))
        module.add_subscription("ep-1", "p", "a")
        module.send_push("t", "b")   # must not raise
        assert calls == []


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
        monkeypatch.setattr(module, "send_push",
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
        monkeypatch.setattr(module, "send_push_async",
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
        # No key, no subs: supported False, empty public key string, 0 subscriptions.
        resp = client.get(_q("/api/state"))
        assert resp.status_code == 200
        push = resp.get_json()["push"]
        assert push["supported"] is False
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
        # supported mirrors push_available(); vapid_public_key is the configured pubkey.
        assert push["supported"] is True
        assert push["vapid_public_key"] == pub
        assert push["subscriptions"] == 1
