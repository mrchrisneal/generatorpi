# genpi/ratelimit.py -- Per-IP brute-force / enumeration rate limiting for GeneratorPi (roadmap
# #59, Stage 5). LAYER 2: depends only on genpi.config (CONFIG thresholds) + genpi.logg (log) + the
# stdlib. Imported by genpi/__init__.py before auth (auth_required consults these on every request).
#
# Tracks failed auth attempts per client IP in a bounded in-memory map (_fail_tracker, guarded by
# _fail_tracker_lock): after RATE_LIMIT_MAX_FAILURES consecutive failures an IP is locked out for
# RATE_LIMIT_LOCKOUT_SECONDS; a success clears it; stale entries are purged periodically and the map
# is hard-capped (RATE_LIMIT_MAX_TRACKED_IPS) so it can't be grown without bound to exhaust memory.
#
# Copyright (C) 2026 Chris Neal <https://neal.media> and Alex Neal <https://neal.tools>
# SPDX-License-Identifier: AGPL-3.0-or-later
import time                  # monotonic clock for lockout windows + cleanup cadence
import threading             # the lock guarding the shared failure map
from .config import CONFIG   # RATE_LIMIT_* thresholds
from .logg import log        # debug lines for cleanup / capacity eviction

# ============================================================================
# RATE LIMITING (brute force / enumeration protection)
# ============================================================================
# Tracks failed auth attempts per IP. After RATE_LIMIT_MAX_FAILURES consecutive
# failures, the IP is locked out for RATE_LIMIT_LOCKOUT_SECONDS. A successful
# login resets the counter for that IP. Stale entries are purged periodically.

# _fail_tracker[ip] = {"count": int, "locked_until": float or None, "last_attempt": float}
_fail_tracker = {}
_fail_tracker_lock = threading.Lock()
_last_cleanup = time.monotonic()


def _cleanup_tracker():
    """Remove expired lockouts and stale entries from the failure tracker."""
    global _last_cleanup
    now = time.monotonic()
    cleanup_interval = CONFIG["RATE_LIMIT_CLEANUP_SECONDS"]
    if now - _last_cleanup < cleanup_interval:
        return
    _last_cleanup = now
    expired = [
        ip for ip, entry in _fail_tracker.items()
        if (entry["locked_until"] is not None and entry["locked_until"] <= now)
        or (now - entry["last_attempt"] > cleanup_interval)
    ]
    for ip in expired:
        del _fail_tracker[ip]
    if expired:
        log.debug(f"Rate limiter cleanup: purged {len(expired)} stale entries")


def is_rate_limited(ip):
    """Check if an IP is currently locked out. Returns seconds remaining or 0."""
    with _fail_tracker_lock:
        _cleanup_tracker()
        entry = _fail_tracker.get(ip)
        if not entry or entry["locked_until"] is None:
            return 0
        remaining = entry["locked_until"] - time.monotonic()
        if remaining <= 0:
            # Lockout expired, reset
            del _fail_tracker[ip]
            return 0
        return remaining


def record_failure(ip):
    """Record a failed auth attempt. Returns (locked_out, fail_count)."""
    with _fail_tracker_lock:
        # Enforce hard cap -- if at limit and this is a new IP, evict the oldest entry
        max_ips = CONFIG["RATE_LIMIT_MAX_TRACKED_IPS"]
        if ip not in _fail_tracker and len(_fail_tracker) >= max_ips:
            oldest_ip = min(_fail_tracker, key=lambda k: _fail_tracker[k]["last_attempt"])
            del _fail_tracker[oldest_ip]
            log.debug(f"Rate limiter at capacity ({max_ips}), evicted oldest entry")

        entry = _fail_tracker.get(ip, {"count": 0, "locked_until": None, "last_attempt": 0})
        entry["count"] += 1
        entry["last_attempt"] = time.monotonic()
        max_failures = CONFIG["RATE_LIMIT_MAX_FAILURES"]

        if entry["count"] >= max_failures:
            lockout = CONFIG["RATE_LIMIT_LOCKOUT_SECONDS"]
            entry["locked_until"] = time.monotonic() + lockout
            _fail_tracker[ip] = entry
            return True, entry["count"]

        _fail_tracker[ip] = entry
        return False, entry["count"]


def record_success(ip):
    """Reset the failure counter for an IP after a successful login."""
    with _fail_tracker_lock:
        if ip in _fail_tracker:
            del _fail_tracker[ip]
