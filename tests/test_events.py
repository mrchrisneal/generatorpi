# test_events.py -- the persistent, capped event store and the GET /api/events
# endpoint.
#
# The store is a small on-disk SQLite database. To keep tests isolated and
# deterministic, we point the module's shared connection at a throwaway tmp DB
# (via init_event_store(<tmp>)) and restore the default on-disk store afterwards
# so unrelated tests still have a live connection. conftest.py already mocks
# gpiozero and resets the module globals between tests.
import logging
import sqlite3
import time

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def _restore_store(module):
    """Restore the default on-disk event store after a test repoints it.

    Any test that swaps _event_conn (directly or by init_event_store(<tmp>)) must
    leave the module with a valid default connection for the tests that follow.
    """
    yield
    with module._event_lock:
        conn = module.store._event_conn
        module.store._event_conn = None
        if conn is not None:
            # A test may have swapped in a fake connection (e.g. one whose methods
            # raise); tolerate a missing/failing close() so teardown never errors.
            try:
                conn.close()
            except Exception:
                pass
    # Reopen the default store (SCRIPT_DIR / CONFIG["EVENT_LOG_DB"]).
    module.init_event_store()


@pytest.fixture
def event_db(module, tmp_path, _restore_store):
    """A fresh, EMPTY event store backed by a throwaway tmp DB.

    init_event_store() records a "startup" event; we then clear the table and
    reset the AUTOINCREMENT counter so each test starts from a pristine, empty
    store with seq beginning at 1. Returns the DB Path.
    """
    db = tmp_path / "events.db"
    module.init_event_store(db)
    with module._event_lock:
        module.store._event_conn.execute("DELETE FROM events")
        # Reset AUTOINCREMENT so the first insert in the test gets seq=1.
        module.store._event_conn.execute("DELETE FROM sqlite_sequence WHERE name='events'")
        module.store._event_conn.commit()
    return db


# ---------------------------------------------------------------------------
# init_event_store / startup event
# ---------------------------------------------------------------------------
class TestInit:
    def test_init_records_startup_event(self, module, tmp_path, _restore_store):
        # A freshly-initialized store contains exactly the startup event.
        db = tmp_path / "events.db"
        module.init_event_store(db)
        events = module.get_events()
        assert len(events) == 1
        assert events[0]["type"] == "startup"
        # Versioned startup line (single-source-of-truth APP_VERSION).
        assert events[0]["message"] == f"GeneratorPi v{module.APP_VERSION} started"
        assert events[0]["seq"] == 1

    def test_init_creates_db_file(self, module, tmp_path, _restore_store):
        db = tmp_path / "events.db"
        module.init_event_store(db)
        assert db.exists()  # the SQLite file was created on disk

    def test_init_tolerates_failing_close_on_reopen(
        self, module, tmp_path, monkeypatch, _restore_store
    ):
        # If closing the previous connection fails on reopen, init must swallow the
        # error and still bring the store up (never leave it unusable).
        class BadClose:
            def close(self):
                raise RuntimeError("cannot close")

        monkeypatch.setattr(module.store, "_event_conn", BadClose())
        db = tmp_path / "events.db"
        module.init_event_store(db)  # must not raise despite the failing close()
        assert module.get_latest_seq() >= 1  # startup event was recorded


# ---------------------------------------------------------------------------
# record_event: monotonic seq, plausible ts, newest-first ordering
# ---------------------------------------------------------------------------
class TestRecordEvent:
    def test_monotonic_seq_and_newest_first(self, module, event_db):
        before = time.time()
        module.record_event("start", "a")
        module.record_event("stop", "b")
        module.record_event("set_running", "c")
        after = time.time()

        events = module.get_events()
        # Newest-first ordering.
        assert [e["message"] for e in events] == ["c", "b", "a"]
        # seq is monotonic (3, 2, 1 newest-first).
        assert [e["seq"] for e in events] == [3, 2, 1]
        # ts is a plausible unix timestamp captured during the test.
        for e in events:
            assert before <= e["ts"] <= after

    def test_dict_shape(self, module, event_db):
        module.record_event("start", "hello")
        e = module.get_events()[0]
        assert set(e.keys()) == {"seq", "ts", "type", "message"}
        assert e["type"] == "start"
        assert e["message"] == "hello"


# ---------------------------------------------------------------------------
# Eviction: cap enforced, OLDEST evicted, seq keeps climbing (never reused)
# ---------------------------------------------------------------------------
class TestEviction:
    def test_caps_count_and_evicts_oldest(self, module, event_db):
        module.CONFIG["EVENT_LOG_MAX"] = 5
        # Insert 12 events -> seq 1..12. With a cap of 5, only the newest 5 remain.
        for i in range(12):
            module.record_event("test", f"event-{i}")

        events = module.get_events(limit=1000)
        assert len(events) == 5  # capped at EVENT_LOG_MAX

        # The five kept are the LAST five inserted (event-11 .. event-7),
        # newest-first.
        assert [e["message"] for e in events] == [f"event-{i}" for i in range(11, 6, -1)]

        seqs = [e["seq"] for e in events]
        # seq kept climbing to 12 and was never reused; the oldest surviving seq
        # is 8 (seq 1..7 were evicted).
        assert seqs == [12, 11, 10, 9, 8]
        assert module.get_latest_seq() == 12

    def test_seq_never_reused_after_eviction(self, module, event_db):
        module.CONFIG["EVENT_LOG_MAX"] = 3
        for i in range(6):
            module.record_event("test", f"e{i}")  # seq 1..6, keep 4,5,6
        # Record one more: seq must be 7 (a fresh high-water mark), never a reused
        # low value even though rows 1..3 were deleted.
        module.record_event("test", "next")
        assert module.get_latest_seq() == 7
        assert module.get_events()[0]["seq"] == 7


# ---------------------------------------------------------------------------
# get_events: limit, before/after cursors, precedence, clamping helpers
# ---------------------------------------------------------------------------
class TestGetEvents:
    def test_default_and_explicit_limit(self, module, event_db):
        for i in range(10):
            module.record_event("t", f"m{i}")
        assert len(module.get_events(limit=3)) == 3
        # Default limit (100) exceeds the 10 stored rows -> all 10 returned.
        assert len(module.get_events()) == 10

    def test_before_cursor_pages_older(self, module, event_db):
        for i in range(5):
            module.record_event("t", f"m{i}")  # seq 1..5
        # before=3 -> seq < 3 -> rows 2, 1 (newest-first).
        ev = module.get_events(before=3)
        assert [e["seq"] for e in ev] == [2, 1]

    def test_after_cursor_returns_new(self, module, event_db):
        for i in range(5):
            module.record_event("t", f"m{i}")  # seq 1..5
        # after=3 -> seq > 3 -> rows 5, 4 (newest-first).
        ev = module.get_events(after=3)
        assert [e["seq"] for e in ev] == [5, 4]

    def test_before_takes_precedence_over_after(self, module, event_db):
        for i in range(5):
            module.record_event("t", f"m{i}")  # seq 1..5
        # When both cursors are supplied, before wins (client pages one way).
        ev = module.get_events(before=3, after=1)
        assert [e["seq"] for e in ev] == [2, 1]

    def test_empty_store_returns_empty_list(self, module, event_db):
        assert module.get_events() == []


class TestGetLatestSeq:
    def test_empty_returns_zero(self, module, event_db):
        assert module.get_latest_seq() == 0

    def test_tracks_highest_seq(self, module, event_db):
        module.record_event("t", "x")
        assert module.get_latest_seq() == 1
        module.record_event("t", "y")
        assert module.get_latest_seq() == 2


# ---------------------------------------------------------------------------
# Persistence: events survive closing + reopening the store (proves on-disk)
# ---------------------------------------------------------------------------
class TestPersistence:
    def test_events_survive_reopen(self, module, tmp_path, _restore_store):
        db = tmp_path / "events.db"
        module.init_event_store(db)  # startup event (seq 1)
        module.record_event("stop", "Stop command sent")  # seq 2
        latest_before = module.get_latest_seq()
        assert latest_before == 2

        # Reopen: init_event_store() closes the old connection and opens a brand
        # new one on the SAME file, then records another startup event.
        module.init_event_store(db)

        events = module.get_events(limit=1000)
        types = [e["type"] for e in events]
        # The pre-reopen "stop" event is still there -> it was persisted to disk.
        assert "stop" in types
        # Two opens -> two startup events.
        assert types.count("startup") == 2
        # seq kept climbing across the reopen (never reset / reused).
        assert module.get_latest_seq() > latest_before


# ---------------------------------------------------------------------------
# Defensive behavior: record_event / readers never raise into their callers
# ---------------------------------------------------------------------------
class TestDefensive:
    def test_record_event_swallows_db_errors(self, module, event_db, monkeypatch, caplog):
        # Replace the connection with one whose execute() always raises. A DB
        # failure must NOT propagate out of record_event (it must never break the
        # relay control path), and it should be logged as a warning.
        class BoomConn:
            def execute(self, *a, **k):
                raise sqlite3.OperationalError("boom")

            def commit(self):
                pass

        monkeypatch.setattr(module.store, "_event_conn", BoomConn())
        with caplog.at_level(logging.WARNING, logger="generator_control"):
            module.record_event("start", "should be swallowed")  # must not raise
        assert any("Failed to record event" in r.message for r in caplog.records)

    def test_readers_safe_when_store_uninitialized(self, module, monkeypatch, _restore_store):
        # If the store somehow isn't initialized (conn is None), readers degrade
        # gracefully and record_event drops the event instead of crashing.
        monkeypatch.setattr(module.store, "_event_conn", None)
        module.record_event("start", "x")  # must not raise
        assert module.get_events() == []
        assert module.get_latest_seq() == 0

    def test_readers_swallow_db_errors(self, module, monkeypatch, _restore_store):
        # A read failure returns a safe empty result rather than 500-ing a request.
        class BoomConn:
            def execute(self, *a, **k):
                raise sqlite3.OperationalError("boom")

        monkeypatch.setattr(module.store, "_event_conn", BoomConn())
        assert module.get_events() == []
        assert module.get_latest_seq() == 0


# ---------------------------------------------------------------------------
# GET /api/events endpoint
# ---------------------------------------------------------------------------
class TestApiEventsEndpoint:
    API_KEY = "events-test-key"

    @pytest.fixture(autouse=True)
    def _configure_api_key(self, module):
        """Give every endpoint test a working API key for auth."""
        module.CONFIG["API_KEY"] = self.API_KEY

    def _q(self, path):
        sep = "&" if "?" in path else "?"
        return f"{path}{sep}key={self.API_KEY}"

    def test_authed_returns_correct_shape(self, client, module, event_db):
        module.record_event("start", "Start sequence initiated")
        resp = client.get(self._q("/api/events"))
        assert resp.status_code == 200
        data = resp.get_json()
        assert set(data.keys()) == {"events", "latest_seq"}
        assert data["latest_seq"] == 1
        assert data["events"][0]["type"] == "start"
        assert set(data["events"][0].keys()) == {"seq", "ts", "type", "message"}

    def test_limit_honored(self, client, module, event_db):
        for i in range(10):
            module.record_event("t", f"m{i}")
        resp = client.get(self._q("/api/events?limit=3"))
        assert resp.status_code == 200
        assert len(resp.get_json()["events"]) == 3

    def test_limit_clamped_high_low_and_nonint(self, client, module, event_db):
        for i in range(3):
            module.record_event("t", f"m{i}")
        # Over-large limit is clamped to 1000 (no error).
        assert client.get(self._q("/api/events?limit=99999")).status_code == 200
        # Zero/negative clamps up to 1 (no error).
        assert client.get(self._q("/api/events?limit=0")).status_code == 200
        assert client.get(self._q("/api/events?limit=-5")).status_code == 200
        # Non-integer degrades to the default (no 400/500).
        assert client.get(self._q("/api/events?limit=abc")).status_code == 200

    def test_before_and_after_query_params(self, client, module, event_db):
        for i in range(5):
            module.record_event("t", f"m{i}")  # seq 1..5
        rb = client.get(self._q("/api/events?before=3")).get_json()
        assert [e["seq"] for e in rb["events"]] == [2, 1]
        ra = client.get(self._q("/api/events?after=3")).get_json()
        assert [e["seq"] for e in ra["events"]] == [5, 4]

    def test_unauthenticated_returns_401(self, client, module, event_db):
        # A request without the key (and wrong configured key) is rejected.
        module.CONFIG["API_KEY"] = "a-different-key"
        resp = client.get("/api/events")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Instrumentation: the control paths record the expected event types
# ---------------------------------------------------------------------------
class TestInstrumentation:
    def test_stop_records_stop_event(self, module, event_db, no_sleep):
        module.stop_generator()
        types = [e["type"] for e in module.get_events()]
        assert "stop" in types

    def test_start_sequence_records_start_and_complete(self, module, event_db, no_sleep):
        result = module.start_generator()
        assert result["success"] is True
        types = [e["type"] for e in module.get_events(limit=1000)]
        assert "start" in types
        assert "start_complete" in types

    def test_start_rejected_when_already_running(self, module, event_db):
        with module.state_lock:
            module.generator_state["running"] = True
        result = module.start_generator()
        assert result["success"] is False
        types = [e["type"] for e in module.get_events()]
        assert "start_rejected" in types

    def test_start_rejected_when_relay_busy(self, module, event_db):
        acquired = module.relay_lock.acquire(blocking=False)
        assert acquired
        try:
            result = module.start_generator()
            assert result["success"] is False
        finally:
            module.relay_lock.release()
        types = [e["type"] for e in module.get_events()]
        assert "start_rejected" in types

    def test_set_running_endpoint_records_event(self, client, module, event_db):
        module.CONFIG["API_KEY"] = "k"
        resp = client.post("/api/set_running?key=k", json={"running": True})
        assert resp.status_code == 200
        events = module.get_events()
        assert events[0]["type"] == "set_running"
        assert "RUNNING" in events[0]["message"]

    def test_busy_start_endpoint_records_rejected(self, client, module, event_db):
        module.CONFIG["API_KEY"] = "k"
        # Hold the relay lock so /api/start hits the busy-409 path.
        acquired = module.relay_lock.acquire(blocking=False)
        assert acquired
        try:
            resp = client.post("/api/start?key=k")
            assert resp.status_code == 409
        finally:
            module.relay_lock.release()
        types = [e["type"] for e in module.get_events()]
        assert "start_rejected" in types
