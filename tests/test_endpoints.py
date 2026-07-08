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
        assert "SYSTEM" in body and "SENSORS" in body


class TestAppLogEndpoint:
    """GET /api/logs -- the tail of the application log file backing the EVENT LOG
    panel's 'APP LOG' view. Path is FIXED (log_path), so `lines` only controls count."""

    def _point_log(self, module, tmp_path, text):
        """Write `text` to a temp file and repoint the module's log_path at it.
        Returns the Path. Not monkeypatch: these tests receive `module` + `tmp_path`
        directly and set the global; reset_globals doesn't touch log_path, so we
        restore it explicitly in each test via the returned original where needed."""
        p = tmp_path / "app.log"
        p.write_text(text, encoding="utf-8")
        module.log_path = p
        return p

    def test_requires_auth(self, client):
        # @auth_required with a key configured -> no key means 401.
        assert client.get("/api/logs").status_code == 401

    def test_returns_last_n_lines(self, client, module, tmp_path):
        orig = module.log_path
        try:
            self._point_log(module, tmp_path,
                            "".join(f"line {i}\n" for i in range(1, 11)))
            data = client.get(_q("/api/logs?lines=3")).get_json()
            # Oldest-first (file order); the LAST 3 of 10 lines.
            assert data["lines"] == ["line 8", "line 9", "line 10"]
            assert data["path"] == "app.log"
        finally:
            module.log_path = orig

    def test_default_lines_is_1000(self, client, module, tmp_path):
        orig = module.log_path
        try:
            # 1200 lines present; default (no ?lines) returns the last 1000.
            self._point_log(module, tmp_path,
                            "".join(f"L{i}\n" for i in range(1200)))
            lines = client.get(_q("/api/logs")).get_json()["lines"]
            assert len(lines) == 1000
            assert lines[0] == "L200" and lines[-1] == "L1199"
        finally:
            module.log_path = orig

    def test_lines_clamped_to_max_1000(self, client, module, tmp_path):
        orig = module.log_path
        try:
            # 1500 lines; ask for far more than the cap -> exactly 1000 returned.
            self._point_log(module, tmp_path,
                            "".join(f"L{i}\n" for i in range(1500)))
            lines = client.get(_q("/api/logs?lines=99999")).get_json()["lines"]
            assert len(lines) == 1000
            assert lines[-1] == "L1499"
        finally:
            module.log_path = orig

    def test_lines_clamped_to_min_1(self, client, module, tmp_path):
        orig = module.log_path
        try:
            self._point_log(module, tmp_path, "a\nb\nc\n")
            # lines=0 (and negatives) clamp UP to 1 -> just the final line.
            assert client.get(_q("/api/logs?lines=0")).get_json()["lines"] == ["c"]
        finally:
            module.log_path = orig

    def test_bad_lines_falls_back_to_default(self, client, module, tmp_path):
        orig = module.log_path
        try:
            self._point_log(module, tmp_path,
                            "".join(f"L{i}\n" for i in range(10)))
            # Non-numeric 'lines' -> type=int yields the 200 default, so all 10 return.
            assert len(client.get(_q("/api/logs?lines=xyz")).get_json()["lines"]) == 10
        finally:
            module.log_path = orig

    def test_missing_file_returns_empty(self, client, module, tmp_path):
        orig = module.log_path
        try:
            # Point at a path that does not exist -> [] and HTTP 200 (never a 500).
            module.log_path = tmp_path / "does-not-exist.log"
            resp = client.get(_q("/api/logs"))
            assert resp.status_code == 200
            assert resp.get_json()["lines"] == []
        finally:
            module.log_path = orig

    def test_empty_file_returns_empty(self, client, module, tmp_path):
        orig = module.log_path
        try:
            self._point_log(module, tmp_path, "")
            assert client.get(_q("/api/logs")).get_json()["lines"] == []
        finally:
            module.log_path = orig

    def test_tail_spans_multiple_blocks(self, client, module, tmp_path):
        # Each line is ~200 bytes; 100 lines ~= 20KB, forcing several 4096-byte
        # backward reads so the block-boundary stitching in _tail_lines is exercised.
        orig = module.log_path
        try:
            body = "".join(f"{i:04d}-" + ("x" * 200) + "\n" for i in range(100))
            self._point_log(module, tmp_path, body)
            lines = client.get(_q("/api/logs?lines=5")).get_json()["lines"]
            assert len(lines) == 5
            assert lines[0].startswith("0095-") and lines[-1].startswith("0099-")
        finally:
            module.log_path = orig

    def test_tail_lines_helper_handles_no_trailing_newline(self, module, tmp_path):
        # A file whose last line has no trailing "\n" (mid-write) still yields that line.
        p = tmp_path / "partial.log"
        p.write_text("first\nsecond\nthird", encoding="utf-8")
        assert module._tail_lines(p, 2) == ["second", "third"]


class TestAppLogDelta:
    """GET /api/logs incremental (byte-cursor) behaviour: the client passes ?since=<offset>
    and the server returns ONLY newly-appended complete lines, so idle polls are tiny."""

    API_KEY = "endpoint-test-key"  # matches the module-level fixture's configured key

    def _point(self, module, tmp_path, text):
        p = tmp_path / "app.log"
        p.write_text(text, encoding="utf-8")
        module.log_path = p
        return p

    def test_full_tail_is_reset_with_cursor(self, client, module, tmp_path):
        orig = module.log_path
        try:
            p = self._point(module, tmp_path, "a\nb\nc\n")
            d = client.get(_q("/api/logs")).get_json()
            assert d["reset"] is True
            assert d["lines"] == ["a", "b", "c"]
            # File ends in a newline, so the cursor is the full file size (past last NL).
            assert d["offset"] == p.stat().st_size
        finally:
            module.log_path = orig

    def test_delta_returns_only_new_lines(self, client, module, tmp_path):
        orig = module.log_path
        try:
            p = self._point(module, tmp_path, "a\nb\n")
            off = client.get(_q("/api/logs")).get_json()["offset"]
            # Append two more lines and poll from the cursor.
            with open(p, "a", encoding="utf-8") as f:
                f.write("c\nd\n")
            d = client.get(_q(f"/api/logs?since={off}")).get_json()
            assert d["reset"] is False
            assert d["lines"] == ["c", "d"]      # ONLY the new lines, not a/b
            assert d["offset"] == p.stat().st_size
        finally:
            module.log_path = orig

    def test_idle_poll_is_empty(self, client, module, tmp_path):
        orig = module.log_path
        try:
            self._point(module, tmp_path, "a\nb\n")
            off = client.get(_q("/api/logs")).get_json()["offset"]
            # No append -> since == size -> empty delta, cursor unchanged.
            d = client.get(_q(f"/api/logs?since={off}")).get_json()
            assert d["reset"] is False and d["lines"] == [] and d["offset"] == off
        finally:
            module.log_path = orig

    def test_cursor_past_eof_triggers_reset(self, client, module, tmp_path):
        orig = module.log_path
        try:
            self._point(module, tmp_path, "a\nb\nc\n")
            # A stale cursor past EOF (file rotated/truncated) -> full tail + reset.
            d = client.get(_q("/api/logs?since=999999")).get_json()
            assert d["reset"] is True and d["lines"] == ["a", "b", "c"]
        finally:
            module.log_path = orig

    def test_partial_line_withheld_until_complete(self, client, module, tmp_path):
        orig = module.log_path
        try:
            p = self._point(module, tmp_path, "a\nb\n")
            off = client.get(_q("/api/logs")).get_json()["offset"]
            # Append an in-flight line with NO trailing newline: not a complete line yet.
            with open(p, "a", encoding="utf-8") as f:
                f.write("partial")
            d1 = client.get(_q(f"/api/logs?since={off}")).get_json()
            assert d1["lines"] == [] and d1["offset"] == off   # withheld, cursor frozen
            # Complete the line -> now it (whole) is returned and the cursor advances.
            with open(p, "a", encoding="utf-8") as f:
                f.write(" rest\n")
            d2 = client.get(_q(f"/api/logs?since={off}")).get_json()
            assert d2["lines"] == ["partial rest"]
            assert d2["offset"] == p.stat().st_size
        finally:
            module.log_path = orig

    def test_full_tail_offset_stops_at_last_newline(self, client, module, tmp_path):
        orig = module.log_path
        try:
            # File does NOT end in a newline: the trailing partial is dropped AND the
            # cursor stops just past the last complete line's newline (not at EOF).
            p = self._point(module, tmp_path, "a\nb\nhalf")
            d = client.get(_q("/api/logs")).get_json()
            assert d["lines"] == ["a", "b"]         # "half" withheld
            assert d["offset"] == len("a\nb\n")     # past the 2nd newline, before "half"
            assert d["offset"] < p.stat().st_size
        finally:
            module.log_path = orig


class TestRestartEndpoint:
    """POST /api/restart schedules a self re-exec (the actual exec is patched out)."""

    def test_requires_auth(self, client):
        assert client.post("/api/restart").status_code == 401

    def test_restart_schedules_reexec_and_records_event(self, client, module, monkeypatch):
        called = {}
        # Patch the re-exec scheduler so the test process is NOT actually replaced.
        monkeypatch.setattr(module, "_schedule_process_restart",
                            lambda *a, **k: called.__setitem__("scheduled", True))
        events = []
        monkeypatch.setattr(module, "record_event", lambda t, m: events.append((t, m)))
        resp = client.post(_q("/api/restart"))
        assert resp.status_code == 200 and resp.get_json()["success"] is True
        assert called.get("scheduled") is True
        assert any(t == "restart" for t, _ in events)


class TestFactoryResetEndpoint:
    """POST /api/factory-reset wipes the store + logs + durable state, NEVER the env file."""

    @pytest.fixture
    def temp_store(self, module, tmp_path):
        # Point the event store at a throwaway DB; restore the real default afterwards.
        module.init_event_store(tmp_path / "events.db")
        yield
        with module._event_lock:
            c = module._event_conn
            module._event_conn = None
            if c is not None:
                try:
                    c.close()
                except Exception:
                    pass
        module.init_event_store()

    def test_requires_auth(self, client):
        assert client.post("/api/factory-reset").status_code == 401

    def test_wipes_store_and_state_but_leaves_env_alone(
        self, client, module, tmp_path, temp_store, monkeypatch
    ):
        # Seed non-default rows + globals so we can prove they get cleared/reset.
        module.record_event("start", "seed event")
        module.kv_set("total_run_hours", 12.5)
        with module._event_lock:
            module._event_conn.execute(
                "INSERT OR REPLACE INTO subscriptions(endpoint,p256dh,auth,created_ts) "
                "VALUES('ep','p','a',1)")
            module._event_conn.commit()
        module.generator_state["total_run_hours"] = 12.5
        module.fuel_state["fill_level"] = 42.0
        module.alerts_state["alert_threshold"] = 33

        # A log file with content -> must end up truncated.
        logf = tmp_path / "app.log"
        logf.write_text("noise\n" * 10, encoding="utf-8")
        monkeypatch.setattr(module, "log_path", logf)
        # An env file that must be left UNTOUCHED by the reset.
        env = tmp_path / "generator_control.env"
        env.write_text("API_KEY=keepme\n", encoding="utf-8")
        monkeypatch.setattr(module, "ENV_FILE", env)

        resp = client.post(_q("/api/factory-reset"))
        assert resp.status_code == 200 and resp.get_json()["success"] is True

        # Store emptied, then the endpoint records exactly one 'factory_reset' event.
        with module._event_lock:
            ev = [r[0] for r in module._event_conn.execute(
                "SELECT type FROM events").fetchall()]
            kv = module._event_conn.execute("SELECT COUNT(*) FROM kv").fetchone()[0]
            subs = module._event_conn.execute(
                "SELECT COUNT(*) FROM subscriptions").fetchone()[0]
        assert ev == ["factory_reset"]
        assert kv == 0 and subs == 0
        # Durable globals reset to code defaults.
        assert module.generator_state["total_run_hours"] == 0.0
        assert module.fuel_state["fill_level"] == 100.0
        assert module.alerts_state["alert_threshold"] == 20
        # Log truncated; env file byte-for-byte UNTOUCHED.
        assert logf.read_text(encoding="utf-8") == ""
        assert env.read_text(encoding="utf-8") == "API_KEY=keepme\n"


class TestCheckUpdateEndpoint:
    """GET /api/check-update compares APP_VERSION to the upstream version (network mocked)."""

    @pytest.fixture(autouse=True)
    def _reset_check_cache(self, module):
        # The update-check cache is module-level; clear it before each test so the first read
        # performs a live (mocked) check instead of returning a prior test's cached result.
        module._update_check_cache.update(latest=None, update_available=False, checked_at=None)

    def test_requires_auth(self, client):
        assert client.get("/api/check-update").status_code == 401

    def test_update_available(self, client, module, monkeypatch):
        monkeypatch.setattr(module, "APP_VERSION", "1.0.0")
        monkeypatch.setattr(module, "_fetch_latest_version", lambda: "1.2.0")
        d = client.get(_q("/api/check-update")).get_json()
        assert d == {"installed": "1.0.0", "latest": "1.2.0", "update_available": True}

    def test_up_to_date(self, client, module, monkeypatch):
        monkeypatch.setattr(module, "APP_VERSION", "1.2.0")
        monkeypatch.setattr(module, "_fetch_latest_version", lambda: "1.2.0")
        d = client.get(_q("/api/check-update")).get_json()
        assert d["update_available"] is False and d["latest"] == "1.2.0"

    def test_local_ahead_is_not_an_update(self, client, module, monkeypatch):
        # Dev build ahead of the published release -> not "available".
        monkeypatch.setattr(module, "APP_VERSION", "1.3.0")
        monkeypatch.setattr(module, "_fetch_latest_version", lambda: "1.2.0")
        assert client.get(_q("/api/check-update")).get_json()["update_available"] is False

    def test_unreachable_latest_is_null(self, client, module, monkeypatch):
        # Offline / private repo -> latest null, never an error, never "available".
        monkeypatch.setattr(module, "_fetch_latest_version", lambda: None)
        d = client.get(_q("/api/check-update")).get_json()
        assert d["latest"] is None and d["update_available"] is False

    def test_cached_read_does_not_hit_github(self, client, module, monkeypatch):
        # Passive footer refresh: a default read returns the CACHED value WITHOUT any network.
        module._update_check_cache.update(latest="9.9.9", update_available=True, checked_at=1.0)

        def boom():
            raise AssertionError("passive footer read must not hit GitHub")
        monkeypatch.setattr(module, "_fetch_latest_version", boom)
        d = client.get(_q("/api/check-update")).get_json()
        assert d["latest"] == "9.9.9" and d["update_available"] is True

    def test_fresh_forces_live_check(self, client, module, monkeypatch):
        # ?fresh=1 (manual "Check again" / on-load) hits the (mocked) network even with a cache.
        module._update_check_cache.update(latest="1.0.0", update_available=False, checked_at=1.0)
        monkeypatch.setattr(module, "APP_VERSION", "1.0.0")
        monkeypatch.setattr(module, "_fetch_latest_version", lambda: "2.0.0")
        d = client.get(_q("/api/check-update?fresh=1")).get_json()
        assert d["latest"] == "2.0.0" and d["update_available"] is True

    def test_version_tuple_orders_numerically(self, module):
        # "1.10.0" > "1.9.0" numerically (string compare would get this wrong).
        assert module._version_tuple("1.10.0") > module._version_tuple("1.9.0")
        assert module._version_tuple("2.0.0") > module._version_tuple("1.99.99")
