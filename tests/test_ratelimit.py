# test_ratelimit.py -- the brute-force / enumeration rate limiter:
# is_rate_limited, record_failure (lockout + capacity eviction), record_success,
# and _cleanup_tracker (periodic purge of stale/expired entries).
import time

import pytest


class TestRecordFailure:
    def test_increments_count(self, module):
        locked, count = module.record_failure("1.1.1.1")
        assert (locked, count) == (False, 1)
        locked, count = module.record_failure("1.1.1.1")
        assert (locked, count) == (False, 2)

    def test_locks_out_at_max_failures(self, module):
        module.CONFIG["RATE_LIMIT_MAX_FAILURES"] = 3
        module.record_failure("2.2.2.2")
        module.record_failure("2.2.2.2")
        locked, count = module.record_failure("2.2.2.2")
        assert locked is True
        assert count == 3
        # locked_until is set to a future monotonic time.
        entry = module._fail_tracker["2.2.2.2"]
        assert entry["locked_until"] is not None
        assert entry["locked_until"] > time.monotonic()

    def test_capacity_eviction_removes_oldest(self, module, monkeypatch):
        # Force a tiny capacity so the eviction branch is exercised. The oldest
        # entry (smallest last_attempt) is evicted when a new IP arrives at cap.
        module.CONFIG["RATE_LIMIT_MAX_TRACKED_IPS"] = 2
        # Seed two entries with controlled last_attempt ordering.
        with module._fail_tracker_lock:
            module._fail_tracker["old"] = {
                "count": 1, "locked_until": None, "last_attempt": 100.0,
            }
            module._fail_tracker["new"] = {
                "count": 1, "locked_until": None, "last_attempt": 200.0,
            }
        # A brand-new IP at capacity evicts "old" (lowest last_attempt).
        module.record_failure("fresh")
        assert "old" not in module._fail_tracker
        assert "new" in module._fail_tracker
        assert "fresh" in module._fail_tracker

    def test_existing_ip_at_capacity_does_not_evict(self, module):
        # Recording another failure for an ALREADY-tracked IP must not trigger
        # eviction even when the tracker is at capacity.
        module.CONFIG["RATE_LIMIT_MAX_TRACKED_IPS"] = 1
        module.record_failure("only")
        module.record_failure("only")  # same IP, still at cap, no eviction
        assert module._fail_tracker["only"]["count"] == 2


class TestIsRateLimited:
    def test_unknown_ip_not_limited(self, module):
        assert module.is_rate_limited("9.9.9.9") == 0

    def test_ip_with_failures_but_no_lockout_not_limited(self, module):
        module.record_failure("3.3.3.3")  # count 1, locked_until None
        assert module.is_rate_limited("3.3.3.3") == 0

    def test_locked_ip_returns_remaining_seconds(self, module):
        module.CONFIG["RATE_LIMIT_MAX_FAILURES"] = 1
        module.CONFIG["RATE_LIMIT_LOCKOUT_SECONDS"] = 300
        module.record_failure("4.4.4.4")  # trips lockout immediately
        remaining = module.is_rate_limited("4.4.4.4")
        assert 0 < remaining <= 300

    def test_expired_lockout_is_cleared(self, module):
        # A lockout whose locked_until is already in the past is deleted and
        # reported as not-limited.
        with module._fail_tracker_lock:
            module._fail_tracker["5.5.5.5"] = {
                "count": 9,
                "locked_until": time.monotonic() - 1,  # already expired
                "last_attempt": time.monotonic(),
            }
        assert module.is_rate_limited("5.5.5.5") == 0
        assert "5.5.5.5" not in module._fail_tracker


class TestRecordSuccess:
    def test_clears_tracked_ip(self, module):
        module.record_failure("6.6.6.6")
        assert "6.6.6.6" in module._fail_tracker
        module.record_success("6.6.6.6")
        assert "6.6.6.6" not in module._fail_tracker

    def test_no_error_for_untracked_ip(self, module):
        # Must be a harmless no-op for an IP that was never recorded.
        module.record_success("7.7.7.7")
        assert "7.7.7.7" not in module._fail_tracker


class TestCleanupTracker:
    def test_skips_when_interval_not_elapsed(self, module):
        # If less than the cleanup interval has passed since the last cleanup,
        # _cleanup_tracker returns immediately and touches nothing.
        module.CONFIG["RATE_LIMIT_CLEANUP_SECONDS"] = 600
        module.ratelimit._last_cleanup = time.monotonic()  # just now
        with module._fail_tracker_lock:
            module._fail_tracker["keep"] = {
                "count": 1, "locked_until": None, "last_attempt": 0.0,
            }
            module._cleanup_tracker()
        assert "keep" in module._fail_tracker

    def test_purges_expired_lockouts_and_stale_entries(self, module):
        module.CONFIG["RATE_LIMIT_CLEANUP_SECONDS"] = 600
        now = time.monotonic()
        # Force the interval to have elapsed so cleanup actually runs.
        module.ratelimit._last_cleanup = now - 601
        with module._fail_tracker_lock:
            # Expired lockout -> purged.
            module._fail_tracker["expired_lock"] = {
                "count": 5, "locked_until": now - 5, "last_attempt": now,
            }
            # Stale (last_attempt older than cleanup interval) -> purged.
            module._fail_tracker["stale"] = {
                "count": 1, "locked_until": None, "last_attempt": now - 1000,
            }
            # Fresh, no lockout -> kept.
            module._fail_tracker["fresh"] = {
                "count": 1, "locked_until": None, "last_attempt": now,
            }
            module._cleanup_tracker()
        assert "expired_lock" not in module._fail_tracker
        assert "stale" not in module._fail_tracker
        assert "fresh" in module._fail_tracker

    def test_active_lockout_not_purged(self, module):
        module.CONFIG["RATE_LIMIT_CLEANUP_SECONDS"] = 600
        now = time.monotonic()
        module.ratelimit._last_cleanup = now - 601
        with module._fail_tracker_lock:
            # Active lockout (locked_until in the future) and recent -> kept.
            module._fail_tracker["active"] = {
                "count": 5, "locked_until": now + 300, "last_attempt": now,
            }
            module._cleanup_tracker()
        assert "active" in module._fail_tracker
