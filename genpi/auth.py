# genpi/auth.py -- Authentication for GeneratorPi (roadmap #59, Stage 5). LAYER 3: depends on
# genpi.config (CONFIG + the loaded AUTH_USERS), genpi.logg (log), and genpi.ratelimit (the per-IP
# brute-force limiter consulted BEFORE any password work) -- plus Flask + Werkzeug. Imported by
# genpi/__init__.py after ratelimit; auth_required decorates every protected route.
#
# Two auth paths (auth_required): an API key (?key= / X-API-Key, constant-time compared) for machine
# callers, OR HTTP Basic Auth. Basic-auth verification is scrypt (check_password_hash) -- CPU/memory-
# hard, ~1.7s per verify on a Pi Zero 2 W core -- so successful verifications are briefly cached
# (keyed by an HMAC over username+stored-hash+password under a per-process secret; failures are NEVER
# cached, so the rate limiter still sees every wrong guess). A dummy hash keeps timing flat for
# unknown users (anti-enumeration). caller_identity() trusts g.auth_method (set here), never a
# spoofable Authorization header.
#
# SECURITY-CRITICAL: this is a pure relocation -- the constant-time compares, the cache invariants
# (success-only, stored-hash-bound, TTL-bounded, capacity-capped), the rate-limit-before-scrypt
# ordering, and the log-injection-safe (%r) failure logging are all preserved verbatim.
#
# Copyright (C) 2026 Chris Neal <https://neal.media> and Alex Neal <https://neal.tools>
# SPDX-License-Identifier: AGPL-3.0-or-later
import os                                    # AUTH_CACHE_TTL override from the environment
import time                                  # cache-entry expiry clock
import hmac                                  # keyed cache hash + constant-time API-key compare
import hashlib                               # sha256 for the cache-key HMAC
import secrets                               # per-process cache-key secret
import threading                             # lock guarding the verification cache
from functools import wraps                  # preserve the wrapped route's identity on the decorator
from flask import request, Response, g       # request data, auth challenges, per-request auth flag
from werkzeug.security import generate_password_hash, check_password_hash  # dummy hash + scrypt verify
from .config import CONFIG, AUTH_USERS       # key-auth toggle/value + the loaded credential map
from .logg import log                        # rate-limit + auth-failure warnings
from .ratelimit import is_rate_limited, record_failure, record_success  # brute-force limiter

# ============================================================================
# AUTHENTICATION
# ============================================================================
# Dummy hash used when a username doesn't exist, so the response time is the
# same whether the username is valid or not (prevents enumeration via timing).
_DUMMY_HASH = generate_password_hash("timing-safe-dummy-value")

# ----------------------------------------------------------------------------
# Basic-auth verification cache. check_password_hash() is scrypt -- deliberately
# CPU/memory-hard, ~1.7s PER verify on a Pi Zero 2 W core (measured). A browser
# polls several endpoints every few seconds over HTTP Basic auth, so WITHOUT
# this cache every request re-runs scrypt and pins the single core near 100%.
# We cache ONLY successful verifications, briefly, keyed by an HMAC over
# (username, CURRENT stored hash, password) under a per-process random secret:
#   * the plaintext password is never stored (only an HMAC that dies with the
#     process -- not reversible without the secret);
#   * the key binds to the current stored hash, so a password change INSTANTLY
#     invalidates cached entries (the old password now hashes against the new
#     stored hash -> cache miss -> scrypt -> fail);
#   * FAILURES are never cached, so the brute-force limiter (run BEFORE auth)
#     still sees and slows every wrong guess -- no auth bypass.
# Set AUTH_CACHE_TTL=0 to disable (every request re-runs scrypt).
# ----------------------------------------------------------------------------
_AUTH_CACHE_SECRET = secrets.token_bytes(32)      # per-process; gone on restart
_AUTH_CACHE_TTL = float(os.environ.get("AUTH_CACHE_TTL", "60"))   # seconds a success stays cached
_AUTH_CACHE_MAX = 256                             # hard cap on entries (bound memory)
_auth_cache = {}                                  # hmac_key(bytes) -> expiry_epoch(float)
_auth_cache_lock = threading.Lock()


def _auth_cache_key(username, stored_hash, password):
    """Fast keyed hash of (username, current stored hash, password). Binds to stored_hash so a
    password change misses the cache; the '\\x00' separators stop a||b == a'||b' key collisions."""
    mac = hmac.new(_AUTH_CACHE_SECRET, digestmod=hashlib.sha256)
    for part in (username, stored_hash, password):
        mac.update(part.encode("utf-8"))
        mac.update(b"\x00")
    return mac.digest()


def check_auth(username, password):
    """Verify a username + password. Constant-time against a dummy hash when the username
    doesn't exist (anti-enumeration). Successful verifications are cached for AUTH_CACHE_TTL
    seconds so a polling browser doesn't re-run scrypt on every request (see the cache notes)."""
    stored_hash = AUTH_USERS.get(username, _DUMMY_HASH)
    key = _auth_cache_key(username, stored_hash, password)
    now = time.time()
    with _auth_cache_lock:
        exp = _auth_cache.get(key)
        if exp is not None and exp > now:
            # Cached SUCCESS. Re-check membership so a user deleted since caching is rejected
            # immediately (a CHANGED password already misses via the stored-hash-bound key).
            return username in AUTH_USERS
    # Cache miss/expired -> pay the scrypt cost exactly once per TTL per credential. A nonexistent
    # user still hashes against _DUMMY_HASH here (constant time) and is never cached (ok stays False).
    ok = check_password_hash(stored_hash, password) and username in AUTH_USERS
    if ok and _AUTH_CACHE_TTL > 0:                            # TTL<=0 disables the cache entirely
        with _auth_cache_lock:
            if len(_auth_cache) >= _AUTH_CACHE_MAX:          # evict expired; hard-reset if still full
                for k in [k for k, e in _auth_cache.items() if e <= now]:
                    _auth_cache.pop(k, None)
                if len(_auth_cache) >= _AUTH_CACHE_MAX:
                    _auth_cache.clear()
            _auth_cache[key] = now + _AUTH_CACHE_TTL
    return ok


def check_api_key():
    """Verify a machine-caller API key (e.g. from HomeAssistant).

    The key may arrive either as a URL query parameter (?key=...) -- the primary
    path used by our HomeAssistant rest_command -- or as an "X-API-Key" header.
    Returns True only if key auth is ENABLED (API_KEY_ENABLED) and CONFIGURED
    (non-empty API_KEY) and the presented key matches, compared in constant time
    via hmac.compare_digest to avoid leaking the key through timing. Returns False
    when key auth is disabled or no/incorrect key is presented, so the caller falls
    through to basic auth.
    """
    if not CONFIG["API_KEY_ENABLED"]:
        return False  # Key auth turned off via the settings file
    configured = CONFIG["API_KEY"]
    if not configured:
        return False  # No key configured -- basic auth only
    # Query param takes precedence, then header
    presented = request.args.get("key") or request.headers.get("X-API-Key")
    if not presented:
        return False
    # Compare on BYTES, not str: hmac.compare_digest raises TypeError on a str with
    # any non-ASCII char, which would otherwise 500 (bypassing the failure counter
    # and flooding the log with tracebacks). Bytes are defined for all inputs and
    # stay constant-time.
    return hmac.compare_digest(presented.encode("utf-8"), configured.encode("utf-8"))


def auth_required(f):
    """Decorator that enforces authentication (API key OR HTTP Basic Auth)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = request.remote_addr

        # Check rate limit before doing anything else (avoids wasting CPU on scrypt)
        remaining = is_rate_limited(ip)
        if remaining > 0:
            log.warning(f"Rate limited request from {ip} ({int(remaining)}s remaining)")
            return Response(
                f"<html><body><h1>Too Many Attempts</h1>"
                f"<p>Your IP has been temporarily locked out after too many failed login attempts.</p>"
                f"<p>Try again in {int(remaining)} seconds.</p></body></html>",
                429,
                {"Content-Type": "text/html", "Retry-After": str(int(remaining))},
            )

        # Path 1 -- API key (query ?key=... or X-API-Key header), for machine
        # callers like HomeAssistant. Checked before basic auth so keyed callers
        # never get a browser auth challenge. A valid key clears prior failures.
        if check_api_key():
            record_success(ip)
            # Record HOW we authed so downstream audit logs don't trust a spoofable
            # Authorization header a keyed caller might also send (see caller_identity).
            g.auth_method = "apikey"
            # The access-audit line is emitted POST-handler by the _access_audit_log
            # after_request hook, so it can carry the response status code (which the
            # APP LOG's "hide routine HTTP traffic" filter keys off). Method + path only
            # there -- never the query string, which would contain the key.
            return f(*args, **kwargs)

        # Path 2 -- HTTP Basic Auth (browser login / manual fallback). A present
        # but WRONG key falls through to here and is recorded as a failed attempt.
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            attempted = auth.username if auth else "(none)"
            locked, fail_count = record_failure(ip)
            max_failures = CONFIG["RATE_LIMIT_MAX_FAILURES"]
            # Log the attempted username via !r (repr), NOT raw: it comes from the
            # base64-decoded Authorization header and can carry CR/LF/other control
            # chars. repr escapes them (e.g. '\r\nInjected') so a crafted username
            # can't forge extra log lines (log injection). repr also supplies its own
            # quoting, so the surrounding literal quotes are dropped.
            log.warning(
                f"Auth failed for {attempted!r}@{ip} "
                f"({fail_count}/{max_failures} attempts)"
                + (" [LOCKED OUT]" if locked else "")
            )
            return Response(
                "Authentication required.\n",
                401,
                {"WWW-Authenticate": 'Basic realm="Generator Control"'},
            )

        # Successful basic auth -- clear any prior failures for this IP
        record_success(ip)
        g.auth_method = "basic"
        # Access-audit line emitted post-handler (see _access_audit_log) so it can
        # include the response status the APP LOG's traffic filter keys off.
        return f(*args, **kwargs)
    return decorated


def caller_identity():
    """Human-readable identity of the authenticated caller, for log lines.

    Trusts g.auth_method (set by auth_required) rather than inferring from
    request.authorization -- a key-authenticated caller can ALSO send an arbitrary
    Authorization header, and inferring from it would let them forge the audit-log
    identity. Returns "apikey" for keyed callers, else the validated basic-auth
    username. Safe from any authenticated route.
    """
    if getattr(g, "auth_method", None) == "apikey":
        return "apikey"
    auth = request.authorization
    return auth.username if auth else "apikey"
