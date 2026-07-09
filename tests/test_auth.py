# test_auth.py -- authentication core: check_auth, check_api_key, the auth_required
# decorator (API-key path, basic-auth fallback, wrong-key-falls-through, rate-limit
# gate) and caller_identity. This is the security-sensitive heart of the app.
import base64

import pytest
from werkzeug.security import generate_password_hash


def _basic_header(username, password):
    """Build an HTTP Basic Authorization header value."""
    raw = f"{username}:{password}".encode()
    return {"Authorization": "Basic " + base64.b64encode(raw).decode()}


# ---------------------------------------------------------------------------
# check_auth
# ---------------------------------------------------------------------------
class TestCheckAuth:
    def test_valid_credentials(self, module):
        module.AUTH_USERS["chris"] = generate_password_hash("s3cret")
        assert module.check_auth("chris", "s3cret") is True

    def test_wrong_password(self, module):
        module.AUTH_USERS["chris"] = generate_password_hash("s3cret")
        assert module.check_auth("chris", "wrong") is False

    def test_unknown_user_returns_false(self, module):
        # No users loaded -> falls back to the dummy hash (timing-safe) but must
        # still report failure because the username isn't in AUTH_USERS.
        assert module.check_auth("ghost", "anything") is False

    def test_unknown_user_even_with_dummy_value(self, module):
        # Even presenting the literal dummy plaintext must not authenticate an
        # unknown user: the `username in AUTH_USERS` guard is what makes it safe.
        assert module.check_auth("ghost", "timing-safe-dummy-value") is False


# ---------------------------------------------------------------------------
# check_auth verification cache -- scrypt is ~1.7s/verify on a Pi, so successful
# Basic-auth verifications are cached briefly to stop a polling browser from
# re-running scrypt every request. Security-sensitive: only successes are cached,
# a password change invalidates instantly, and failures always re-run scrypt.
# ---------------------------------------------------------------------------
class TestAuthCache:
    @staticmethod
    def _spy_scrypt(module, monkeypatch):
        """Wrap check_password_hash with a call counter that still verifies for real."""
        from werkzeug.security import check_password_hash as real
        calls = {"n": 0}

        def spy(stored, pw):
            calls["n"] += 1
            return real(stored, pw)

        monkeypatch.setattr(module.auth, "check_password_hash", spy)
        return calls

    def test_cache_hit_skips_scrypt(self, module, monkeypatch):
        module._auth_cache.clear()
        module.AUTH_USERS["chris"] = generate_password_hash("s3cret")
        calls = self._spy_scrypt(module, monkeypatch)
        assert module.check_auth("chris", "s3cret") is True      # miss -> scrypt
        assert module.check_auth("chris", "s3cret") is True      # hit -> no scrypt
        assert module.check_auth("chris", "s3cret") is True      # hit -> no scrypt
        assert calls["n"] == 1, "scrypt must run once, then serve from cache"

    def test_failure_is_never_cached(self, module, monkeypatch):
        module._auth_cache.clear()
        module.AUTH_USERS["chris"] = generate_password_hash("s3cret")
        calls = self._spy_scrypt(module, monkeypatch)
        assert module.check_auth("chris", "wrong") is False
        assert module.check_auth("chris", "wrong") is False
        assert calls["n"] == 2, "a wrong password must re-run scrypt every time (rate limiter intact)"

    def test_password_change_invalidates_immediately(self, module, monkeypatch):
        module._auth_cache.clear()
        module.AUTH_USERS["chris"] = generate_password_hash("oldpw")
        assert module.check_auth("chris", "oldpw") is True       # cached success
        module.AUTH_USERS["chris"] = generate_password_hash("newpw")   # owner changes password
        calls = self._spy_scrypt(module, monkeypatch)
        assert module.check_auth("chris", "oldpw") is False      # old pw rejected NOW (no stale window)
        assert module.check_auth("chris", "newpw") is True       # new pw works (re-runs scrypt)
        assert calls["n"] == 2

    def test_user_deletion_invalidates(self, module):
        module._auth_cache.clear()
        module.AUTH_USERS["chris"] = generate_password_hash("s3cret")
        assert module.check_auth("chris", "s3cret") is True      # cached success
        del module.AUTH_USERS["chris"]
        assert module.check_auth("chris", "s3cret") is False     # deleted user rejected even on a hit

    def test_ttl_expiry_reruns_scrypt(self, module, monkeypatch):
        module._auth_cache.clear()
        monkeypatch.setattr(module.auth, "_AUTH_CACHE_TTL", 0.05)
        module.AUTH_USERS["chris"] = generate_password_hash("s3cret")
        calls = self._spy_scrypt(module, monkeypatch)
        assert module.check_auth("chris", "s3cret") is True      # miss -> scrypt (n=1)
        import time as _t
        _t.sleep(0.08)                                           # let the entry expire
        assert module.check_auth("chris", "s3cret") is True      # expired -> scrypt again (n=2)
        assert calls["n"] == 2

    def test_ttl_zero_disables_cache(self, module, monkeypatch):
        module._auth_cache.clear()
        monkeypatch.setattr(module.auth, "_AUTH_CACHE_TTL", 0.0)
        module.AUTH_USERS["chris"] = generate_password_hash("s3cret")
        calls = self._spy_scrypt(module, monkeypatch)
        assert module.check_auth("chris", "s3cret") is True
        assert module.check_auth("chris", "s3cret") is True
        assert calls["n"] == 2, "TTL=0 disables caching (scrypt every request)"

    def test_no_plaintext_password_in_cache_keys(self, module):
        module._auth_cache.clear()
        module.AUTH_USERS["chris"] = generate_password_hash("SuperSecretPw!")
        assert module.check_auth("chris", "SuperSecretPw!") is True
        # Keys are HMAC-SHA256 digests (opaque bytes); the plaintext must appear nowhere.
        for k in module._auth_cache:
            assert isinstance(k, bytes)
            assert b"SuperSecretPw!" not in k

    def test_full_cache_purges_expired_before_insert(self, module, monkeypatch):
        # At the hard cap, a new SUCCESS first evicts EXPIRED entries (memory-bound). scrypt is
        # stubbed True so the test isolates the eviction logic, not the (slow) hashing.
        module._auth_cache.clear()
        monkeypatch.setattr(module.auth, "check_password_hash", lambda h, p: True)
        module.AUTH_USERS["chris"] = module._DUMMY_HASH
        now = module.time.time()
        # Fill exactly to the cap with entries whose expiry is already in the past.
        for i in range(module._AUTH_CACHE_MAX):
            module._auth_cache[b"stale-%d" % i] = now - 1.0
        assert len(module._auth_cache) == module._AUTH_CACHE_MAX
        assert module.check_auth("chris", "pw") is True
        # Expired entries were purged (len fell below the cap, so no hard-reset), and only the
        # single fresh success remains -- the opaque digest key, not any of the stale sentinels.
        assert len(module._auth_cache) == 1
        assert all(not k.startswith(b"stale-") for k in module._auth_cache)

    def test_full_cache_of_live_entries_is_hard_reset(self, module, monkeypatch):
        # If the cache is full of NON-expired entries, purging frees nothing, so it is hard-reset
        # (cleared) rather than growing unbounded -- the second guard that bounds memory even under
        # sustained distinct-credential load.
        module._auth_cache.clear()
        monkeypatch.setattr(module.auth, "check_password_hash", lambda h, p: True)
        module.AUTH_USERS["chris"] = module._DUMMY_HASH
        far_future = module.time.time() + 10_000.0
        for i in range(module._AUTH_CACHE_MAX):
            module._auth_cache[b"live-%d" % i] = far_future
        assert len(module._auth_cache) == module._AUTH_CACHE_MAX
        assert module.check_auth("chris", "pw") is True
        # Nothing was expired, so the whole map was cleared, then the new success added.
        assert len(module._auth_cache) == 1
        assert all(not k.startswith(b"live-") for k in module._auth_cache)


# ---------------------------------------------------------------------------
# check_api_key -- exercised through a request context
# ---------------------------------------------------------------------------
class TestCheckApiKey:
    def _ctx(self, module, query_string="", headers=None):
        """Push a request context so request.args / request.headers are populated."""
        return module.app.test_request_context(
            "/api/status" + (f"?{query_string}" if query_string else ""),
            headers=headers or {},
        )

    def test_disabled_returns_false(self, module):
        module.CONFIG["API_KEY_ENABLED"] = 0
        module.CONFIG["API_KEY"] = "abc"
        with self._ctx(module, "key=abc"):
            assert module.check_api_key() is False

    def test_no_key_configured_returns_false(self, module):
        module.CONFIG["API_KEY_ENABLED"] = 1
        module.CONFIG["API_KEY"] = ""
        with self._ctx(module, "key=whatever"):
            assert module.check_api_key() is False

    def test_no_key_presented_returns_false(self, module):
        module.CONFIG["API_KEY"] = "secret-key"
        with self._ctx(module):
            assert module.check_api_key() is False

    def test_valid_key_query_param(self, module):
        module.CONFIG["API_KEY"] = "secret-key"
        with self._ctx(module, "key=secret-key"):
            assert module.check_api_key() is True

    def test_valid_key_header(self, module):
        module.CONFIG["API_KEY"] = "secret-key"
        with self._ctx(module, headers={"X-API-Key": "secret-key"}):
            assert module.check_api_key() is True

    def test_wrong_key_returns_false(self, module):
        module.CONFIG["API_KEY"] = "secret-key"
        with self._ctx(module, "key=nope"):
            assert module.check_api_key() is False

    def test_query_param_takes_precedence_over_header(self, module):
        # Query param is read first; a valid query key wins even if header is wrong.
        module.CONFIG["API_KEY"] = "secret-key"
        with self._ctx(module, "key=secret-key", headers={"X-API-Key": "wrong"}):
            assert module.check_api_key() is True

    def test_header_used_when_query_absent(self, module):
        module.CONFIG["API_KEY"] = "secret-key"
        with self._ctx(module, headers={"X-API-Key": "secret-key"}):
            assert module.check_api_key() is True

    def test_non_ascii_key_returns_false_without_raising(self, module):
        # FIX #1: compare_digest is now fed BYTES. A non-ASCII presented key (which
        # would make a str-based compare_digest raise TypeError) must simply compare
        # unequal and return False -- never raise.
        module.CONFIG["API_KEY"] = "correct-key"
        with self._ctx(module, "key=café"):  # 'café' -- non-ASCII
            assert module.check_api_key() is False

    def test_non_ascii_multibyte_key_returns_false(self, module):
        # A multibyte emoji key must also compare False without raising.
        module.CONFIG["API_KEY"] = "correct-key"
        with self._ctx(module, headers={"X-API-Key": "\U0001f512key"}):  # 🔒key
            assert module.check_api_key() is False


# ---------------------------------------------------------------------------
# caller_identity -- exercised through a request context
# ---------------------------------------------------------------------------
class TestCallerIdentity:
    def test_returns_basic_auth_username(self, module):
        with module.app.test_request_context(
            "/", headers=_basic_header("chris", "pw")
        ):
            assert module.caller_identity() == "chris"

    def test_returns_apikey_when_no_basic_auth(self, module):
        with module.app.test_request_context("/"):
            assert module.caller_identity() == "apikey"

    def test_apikey_method_overrides_stray_basic_header(self, module):
        # FIX #5: when auth_required has flagged the request as key-authenticated
        # (g.auth_method == "apikey"), caller_identity must return "apikey" EVEN IF
        # the caller also smuggled in an Authorization: Basic header. Trusting the
        # header would let a keyed caller forge the audit-log identity.
        from flask import g
        with module.app.test_request_context(
            "/", headers=_basic_header("attacker", "pw")
        ):
            g.auth_method = "apikey"
            assert module.caller_identity() == "apikey"

    def test_basic_method_returns_username(self, module):
        # When g.auth_method is "basic", the validated username is returned.
        from flask import g
        with module.app.test_request_context(
            "/", headers=_basic_header("chris", "pw")
        ):
            g.auth_method = "basic"
            assert module.caller_identity() == "chris"


# ---------------------------------------------------------------------------
# auth_required decorator -- full behavioral matrix via the real endpoints
# ---------------------------------------------------------------------------
class TestAuthRequiredDecorator:
    def test_no_auth_challenges_with_401(self, client):
        resp = client.get("/api/status")
        assert resp.status_code == 401
        assert resp.headers.get("WWW-Authenticate", "").startswith("Basic")

    def test_valid_api_key_query_authorizes(self, client, module):
        module.CONFIG["API_KEY"] = "key123"
        resp = client.get("/api/status?key=key123")
        assert resp.status_code == 200

    def test_valid_api_key_header_authorizes(self, client, module):
        module.CONFIG["API_KEY"] = "key123"
        resp = client.get("/api/status", headers={"X-API-Key": "key123"})
        assert resp.status_code == 200

    def test_valid_api_key_clears_prior_failures(self, client, module):
        module.CONFIG["API_KEY"] = "key123"
        # Rack up some failures for this IP first.
        module.record_failure("127.0.0.1")
        module.record_failure("127.0.0.1")
        assert "127.0.0.1" in module._fail_tracker
        # A valid keyed request must reset the counter for the IP.
        resp = client.get("/api/status?key=key123")
        assert resp.status_code == 200
        assert "127.0.0.1" not in module._fail_tracker

    def test_valid_basic_auth_authorizes(self, client, module):
        module.AUTH_USERS["chris"] = generate_password_hash("pw")
        resp = client.get("/api/status", headers=_basic_header("chris", "pw"))
        assert resp.status_code == 200

    def test_valid_basic_auth_clears_prior_failures(self, client, module):
        module.AUTH_USERS["chris"] = generate_password_hash("pw")
        module.record_failure("127.0.0.1")
        assert "127.0.0.1" in module._fail_tracker
        resp = client.get("/api/status", headers=_basic_header("chris", "pw"))
        assert resp.status_code == 200
        assert "127.0.0.1" not in module._fail_tracker

    def test_wrong_basic_auth_password_records_failure(self, client, module):
        module.AUTH_USERS["chris"] = generate_password_hash("pw")
        resp = client.get("/api/status", headers=_basic_header("chris", "bad"))
        assert resp.status_code == 401
        assert module._fail_tracker["127.0.0.1"]["count"] == 1

    def test_present_but_wrong_key_falls_through_and_counts_as_failure(
        self, client, module
    ):
        # KEY SECURITY BEHAVIOR: a present-but-WRONG key does NOT short-circuit;
        # it falls through to basic auth, and with no valid basic creds it is
        # recorded as a failed attempt (counts toward lockout).
        module.CONFIG["API_KEY"] = "correct-key"
        resp = client.get("/api/status?key=wrong-key")
        assert resp.status_code == 401
        assert module._fail_tracker["127.0.0.1"]["count"] == 1

    def test_wrong_key_plus_valid_basic_auth_still_authorizes(self, client, module):
        # A wrong key falls through, but valid basic auth on the same request
        # still authorizes (and clears failures).
        module.CONFIG["API_KEY"] = "correct-key"
        module.AUTH_USERS["chris"] = generate_password_hash("pw")
        resp = client.get(
            "/api/status?key=wrong-key", headers=_basic_header("chris", "pw")
        )
        assert resp.status_code == 200

    def test_lockout_after_max_failures_returns_429(self, client, module):
        module.CONFIG["RATE_LIMIT_MAX_FAILURES"] = 3
        module.AUTH_USERS["chris"] = generate_password_hash("pw")
        # 3 wrong attempts -> the 3rd trips the lockout, but still returns 401.
        for _ in range(3):
            r = client.get("/api/status", headers=_basic_header("chris", "bad"))
            assert r.status_code == 401
        # Now locked out: the next request is short-circuited with 429 BEFORE auth.
        r = client.get("/api/status", headers=_basic_header("chris", "pw"))
        assert r.status_code == 429
        assert "Retry-After" in r.headers
        assert int(r.headers["Retry-After"]) > 0

    def test_locked_out_ip_blocks_even_valid_api_key(self, client, module):
        # The rate-limit gate runs FIRST, before the API-key path, so even a valid
        # key is refused while the IP is locked out.
        module.CONFIG["RATE_LIMIT_MAX_FAILURES"] = 2
        module.CONFIG["API_KEY"] = "key123"
        for _ in range(2):
            client.get("/api/status?key=wrong")
        r = client.get("/api/status?key=key123")
        assert r.status_code == 429

    def test_missing_auth_records_failure_with_none_username(self, client, module):
        # No Authorization header at all -> attempted username logged as "(none)"
        # and still counted as a failure.
        resp = client.get("/api/status")
        assert resp.status_code == 401
        assert module._fail_tracker["127.0.0.1"]["count"] == 1
