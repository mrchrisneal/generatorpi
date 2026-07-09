# genpi/store.py -- Durable persistence + Web-Push delivery for GeneratorPi (roadmap #59, Stage 3).
# LAYER 2: depends on genpi.config (CONFIG, paths, the optional push libraries) and genpi.logg
# (log) -- and on NOTHING else in the package. Imported by genpi/__init__.py BEFORE genpi.state,
# because state's persistence (load_persisted_state / run-hours accounting) calls kv_get/kv_set
# here; store itself reads no application state, so the dependency is one-way (acyclic).
#
# Owns: the single shared SQLite connection (_event_conn, guarded by _event_lock) behind the
# capped event log (record_event/get_events/get_latest_seq), the key/value store (kv_get/kv_set)
# used for durable state, the bounded push-subscription table (add/remove/get/count), and the
# Web-Push SEND path -- payload encryption (http-ece), VAPID signing (py-vapid), and the HTTPS POST
# (requests) in _deliver_push/send_push/send_push_async, plus push_status/push_available. Importing
# this module opens the DB + records the startup event (init_event_store() at the bottom), exactly
# as the old single file did at this point in startup.
#
# The push libraries are OPTIONAL: they are imported (from config, where the guard lives) ONLY when
# available, so importing store on a Pi without them does not fail; the send path is gated by
# _PUSH_AVAILABLE and degrades gracefully.
#
# Copyright (C) 2026 Chris Neal <https://neal.media> and Alex Neal <https://neal.tools>
# SPDX-License-Identifier: AGPL-3.0-or-later
import sqlite3                         # the on-disk event log + kv + subscriptions store
import json                            # kv values + push payloads are JSON
import time                            # event timestamps (unix seconds)
import threading                       # the shared-connection lock + fire-and-forget push thread
import base64                          # decode browser subscription keys (p256dh / auth)
from pathlib import Path               # resolve the event-DB path (_event_db_path)
from urllib.parse import urlparse      # validate/inspect a subscription endpoint URL

from .config import CONFIG, SCRIPT_DIR, APP_VERSION, _PUSH_AVAILABLE
from .logg import log
# Web-Push crypto/HTTP libraries live behind the guard in config.py; bind them here ONLY when
# present so a push-less Pi still imports store cleanly (the send path is _PUSH_AVAILABLE-gated).
if _PUSH_AVAILABLE:
    from .config import Vapid, http_ece, requests, _crypto_ec

# ============================================================================
# EVENT STORE (persistent, capped log of generator events)
# ============================================================================
# A durable, on-disk log of notable generator events (start/stop/manual
# overrides/rejections), stored in a small SQLite database next to this script.
# The front-end reads it back over /api/events to show recent activity and page
# backwards through history (~100 rows at a time).
#
# Design notes:
#   * SQLite (stdlib sqlite3) gives us durability + a monotonic primary key for
#     free -- no external service, one file, survives restarts.
#   * seq is INTEGER PRIMARY KEY AUTOINCREMENT: it never repeats or gets reused,
#     even after old rows are evicted, so a client cursor (before=/after=) stays
#     unambiguous forever.
#   * ts is a unix timestamp (time.time(), float seconds) so the UI can render an
#     absolute wall-clock time without depending on server-local formatting.
#   * The table is capped at CONFIG["EVENT_LOG_MAX"] rows; the oldest rows are
#     evicted on every insert so the file can't grow without bound.
#   * The app is multithreaded (a relay worker thread + Flask request threads), so
#     a single shared connection (opened check_same_thread=False) is guarded by a
#     module-level lock. Events are human-frequency, so this coarse lock is fine.

# Guards the shared connection below -- every read/write takes this lock.
_event_lock = threading.Lock()
# The single shared sqlite3 connection. Opened by init_event_store(); None until then.
_event_conn = None
# The resolved on-disk path of the current event DB (set by init_event_store()).
_event_db_path = None


def init_event_store(db_path=None):
    """Open (or reopen) the event-store database and ensure its schema exists.

    Called once at startup, after logging is configured. Opens a single shared
    connection (check_same_thread=False -- see the section header), enables WAL
    mode for better concurrent read/write behavior, creates the events table if
    it doesn't already exist, and records a one-off "startup" event.

    db_path lets tests point the store at a throwaway database; production passes
    nothing and the DB lives at SCRIPT_DIR / CONFIG["EVENT_LOG_DB"].
    """
    global _event_conn, _event_db_path

    # Resolve the target path (default: alongside this script).
    if db_path is None:
        db_path = SCRIPT_DIR / CONFIG["EVENT_LOG_DB"]

    with _event_lock:
        # Close any previously-open connection first so a reopen (e.g. in tests)
        # doesn't leak file handles or leave two connections fighting the same file.
        if _event_conn is not None:
            try:
                _event_conn.close()
            except Exception:
                pass
            _event_conn = None

        _event_db_path = Path(db_path)
        # check_same_thread=False: the relay worker thread and Flask request
        # threads all share this one connection; _event_lock serializes access.
        _event_conn = sqlite3.connect(str(_event_db_path), check_same_thread=False)
        # WAL mode: readers don't block the writer (and vice versa) and it's more
        # crash-resilient than the default rollback journal.
        _event_conn.execute("PRAGMA journal_mode=WAL")
        # Schema. AUTOINCREMENT guarantees seq is monotonic and never reused, even
        # after the DELETEs done during eviction -- so client cursors stay valid.
        _event_conn.execute(
            "CREATE TABLE IF NOT EXISTS events ("
            "seq INTEGER PRIMARY KEY AUTOINCREMENT, "
            "ts REAL NOT NULL, "
            "type TEXT NOT NULL, "
            "message TEXT NOT NULL)"
        )
        # Durable key/value state that must survive a process restart: lifetime
        # total run-hours and the fuel-projection model. Values are stored as JSON
        # text so the same tiny table can hold floats, ints, and small dicts without
        # a per-field schema. Reuses this one connection + _event_lock -- no extra
        # file, no extra lock (the Pi is the constraint; keep it minimal).
        _event_conn.execute(
            "CREATE TABLE IF NOT EXISTS kv ("
            "key TEXT PRIMARY KEY, "
            "value TEXT NOT NULL)"
        )
        # Web Push subscriptions (one row per subscribed browser+device). endpoint is
        # unique and is the pushService URL; p256dh/auth are the client keys needed to
        # encrypt payloads. Dead subscriptions are pruned on a 404/410 from send_push.
        _event_conn.execute(
            "CREATE TABLE IF NOT EXISTS subscriptions ("
            "endpoint TEXT PRIMARY KEY, "
            "p256dh TEXT NOT NULL, "
            "auth TEXT NOT NULL, "
            "created_ts REAL NOT NULL)"
        )
        _event_conn.commit()

    log.info(f"Event store ready: {_event_db_path}")
    # Record process start in the durable log. Done outside the lock above --
    # record_event acquires _event_lock itself.
    record_event("startup", f"GeneratorPi v{APP_VERSION} started")


def record_event(event_type, message):
    """Append an event to the durable store, then evict the oldest rows past cap.

    Inserts (ts=time.time(), type, message) and deletes any rows beyond
    CONFIG["EVENT_LOG_MAX"] so the table stays bounded.

    This MUST NOT raise into its caller: recording an event is only a side effect
    of starting/stopping the generator and must never be able to break the relay
    control path. Any failure is swallowed and logged as a warning.
    """
    try:
        max_rows = CONFIG["EVENT_LOG_MAX"]
        with _event_lock:
            if _event_conn is None:
                # Store not initialized (shouldn't happen in normal operation);
                # drop the event rather than crash the caller.
                log.warning("record_event called before init_event_store; dropping event")
                return
            _event_conn.execute(
                "INSERT INTO events (ts, type, message) VALUES (?, ?, ?)",
                (time.time(), event_type, message),
            )
            # Evict everything older than the newest max_rows rows. seq is
            # monotonic, so "keep the highest max_rows seq values" is exactly
            # "delete where seq <= MAX(seq) - max_rows".
            _event_conn.execute(
                "DELETE FROM events WHERE seq <= (SELECT MAX(seq) FROM events) - ?",
                (max_rows,),
            )
            _event_conn.commit()
    except Exception as e:
        # Never propagate -- a broken event log must not stop the generator.
        log.warning(f"Failed to record event ({event_type!r}): {e}")


def get_events(limit=100, before=None, after=None):
    """Return events newest-first as a list of dicts {seq, ts, type, message}.

    limit  -- max rows to return.
    before -- if given, only rows with seq < before (page backwards / older).
    after  -- if given (and before is not), only rows with seq > after (fetch
              what's new since a cursor the client already holds).
    before takes precedence over after: a client pages in one direction at a time.
    """
    try:
        with _event_lock:
            if _event_conn is None:
                return []
            # Build the cursor WHERE clause. Parameterized -- never string-formatted
            # with user input -- so there's no SQL-injection surface.
            where = ""
            params = []
            if before is not None:
                where = "WHERE seq < ?"
                params.append(before)
            elif after is not None:
                where = "WHERE seq > ?"
                params.append(after)
            params.append(limit)
            rows = _event_conn.execute(
                f"SELECT seq, ts, type, message FROM events {where} "
                "ORDER BY seq DESC LIMIT ?",
                params,
            ).fetchall()
        # Map row tuples -> dicts outside the lock (pure CPU, no DB access).
        return [
            {"seq": r[0], "ts": r[1], "type": r[2], "message": r[3]}
            for r in rows
        ]
    except Exception as e:
        log.warning(f"Failed to read events: {e}")
        return []


def get_latest_seq():
    """Return the highest seq currently in the store, or 0 if it's empty."""
    try:
        with _event_lock:
            if _event_conn is None:
                return 0
            row = _event_conn.execute("SELECT MAX(seq) FROM events").fetchone()
        # MAX() over an empty table returns (None,); treat that as 0.
        return row[0] if row and row[0] is not None else 0
    except Exception as e:
        log.warning(f"Failed to read latest event seq: {e}")
        return 0


def kv_get(key, default=None):
    """Read a durable value from the kv table, JSON-decoded. Returns default if the
    key is absent or the store isn't ready. Never raises into its caller."""
    try:
        with _event_lock:
            if _event_conn is None:
                return default
            row = _event_conn.execute(
                "SELECT value FROM kv WHERE key = ?", (key,)
            ).fetchone()
        if row is None:
            return default
        return json.loads(row[0])
    except Exception as e:
        log.warning(f"Failed to read kv {key!r}: {e}")
        return default


def kv_set(key, value):
    """Persist a JSON-serializable value into the kv table (UPSERT). Never raises
    into its caller -- a failed persist logs a warning; the in-memory value stands."""
    try:
        payload = json.dumps(value)
        with _event_lock:
            if _event_conn is None:
                log.warning("kv_set called before init_event_store; dropping write")
                return
            _event_conn.execute(
                "INSERT INTO kv (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, payload),
            )
            _event_conn.commit()
    except Exception as e:
        log.warning(f"Failed to write kv {key!r}: {e}")


def add_subscription(endpoint, p256dh, auth):
    """Store (or refresh) a browser push subscription. Never raises into its caller."""
    try:
        with _event_lock:
            if _event_conn is None:
                return
            _event_conn.execute(
                "INSERT INTO subscriptions (endpoint, p256dh, auth, created_ts) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(endpoint) DO UPDATE SET "
                "p256dh = excluded.p256dh, auth = excluded.auth",
                (endpoint, p256dh, auth, time.time()),
            )
            # Cap the table like the event log: keep only the newest SUBSCRIPTION_MAX
            # rows (by created_ts) and evict any older ones. Prevents an authenticated
            # caller -- or a browser re-subscribing under many churning endpoints --
            # from growing this table without bound. Done under the same _event_lock.
            max_subs = CONFIG["SUBSCRIPTION_MAX"]
            _event_conn.execute(
                "DELETE FROM subscriptions WHERE endpoint NOT IN ("
                "SELECT endpoint FROM subscriptions ORDER BY created_ts DESC LIMIT ?)",
                (max_subs,),
            )
            _event_conn.commit()
    except Exception as e:
        log.warning(f"Failed to store push subscription: {e}")


def remove_subscription(endpoint):
    """Delete a push subscription by endpoint. Never raises into its caller."""
    try:
        with _event_lock:
            if _event_conn is None:
                return
            _event_conn.execute("DELETE FROM subscriptions WHERE endpoint = ?", (endpoint,))
            _event_conn.commit()
    except Exception as e:
        log.warning(f"Failed to remove push subscription: {e}")


def get_subscriptions():
    """Return all push subscriptions as browser PushSubscription dicts (endpoint +
    keys{p256dh, auth}) -- the shape the send path encrypts + POSTs to. Never raises."""
    try:
        with _event_lock:
            if _event_conn is None:
                return []
            rows = _event_conn.execute(
                "SELECT endpoint, p256dh, auth FROM subscriptions"
            ).fetchall()
        return [
            {"endpoint": r[0], "keys": {"p256dh": r[1], "auth": r[2]}}
            for r in rows
        ]
    except Exception as e:
        log.warning(f"Failed to read push subscriptions: {e}")
        return []


def subscription_count():
    """Return the number of stored push subscriptions (0 on any error)."""
    try:
        with _event_lock:
            if _event_conn is None:
                return 0
            row = _event_conn.execute("SELECT COUNT(*) FROM subscriptions").fetchone()
        return row[0] if row else 0
    except Exception:
        return 0


# VAPID key validity is cached BY KEY VALUE so push_status() -- called on every state poll
# -- only pays the parse cost when the configured key actually changes (normally once, at
# startup). A blank key short-circuits before any crypto.
_vapid_valid_cache = {"key": None, "ok": False}


def _vapid_key_valid():
    """True iff the configured VAPID private key parses via Vapid.from_raw. Result cached by
    key value so the poll path never re-runs the parse for an unchanged key."""
    priv = CONFIG.get("VAPID_PRIVATE_KEY") or ""
    if not priv:
        return False
    if _vapid_valid_cache["key"] != priv:
        _vapid_valid_cache["key"] = priv
        try:
            Vapid.from_raw(priv.encode("utf-8"))
            _vapid_valid_cache["ok"] = True
        except Exception:
            _vapid_valid_cache["ok"] = False
    return _vapid_valid_cache["ok"]


def push_status():
    """Explain whether Web Push can be sent AND, if not, exactly why -- so the UI can show an
    accurate cause instead of a one-size-fits-all "no VAPID keys" message. Returns
    (supported: bool, reason: str) where reason is one of:
      * "ok"              -- libraries present and a valid VAPID keypair is configured.
      * "library_missing" -- the py-vapid / http-ece / requests libraries aren't installed.
      * "no_keys"         -- libraries present but no VAPID keypair (auto-gen skipped/failed,
                             e.g. the settings file wasn't writable at first start).
      * "invalid_keys"    -- a VAPID key is configured but does not parse (e.g. hand-edited)."""
    if not _PUSH_AVAILABLE:
        return False, "library_missing"
    if not CONFIG.get("VAPID_PRIVATE_KEY") or not CONFIG.get("VAPID_PUBLIC_KEY"):
        return False, "no_keys"
    if not _vapid_key_valid():
        return False, "invalid_keys"
    return True, "ok"


def push_available():
    """True when Web Push can be ATTEMPTED: the libraries are importable AND a VAPID private
    key is PRESENT. Deliberately a cheap presence check, NOT full key validity -- the send
    path (send_push) still guards Vapid.from_raw and fails gracefully on a malformed key, and
    push_status() does the full validity check to drive the UI's "invalid_keys" reason. Guards
    send_push / send_push_async and the /api/push/test endpoint."""
    return bool(_PUSH_AVAILABLE and CONFIG.get("VAPID_PRIVATE_KEY"))


def _b64url_decode(value):
    """Decode a base64url value that may be missing '=' padding -- browser subscription keys
    (p256dh / auth) are sent unpadded. Re-pads to a multiple of 4, then decodes to bytes."""
    if isinstance(value, str):
        value = value.encode("utf-8")
    return base64.urlsafe_b64decode(value + b"=" * (-len(value) % 4))


# How long a push service should hold a message for a briefly-OFFLINE device before dropping
# it. A bounded TTL (vs the old drop-immediately 0) means a low-fuel / start / stop alert still
# arrives after a short dead zone, without delivering day-stale state much later.
PUSH_TTL_SECONDS = 3600   # 1 hour


def _deliver_push(sub, payload, vapid, subject):
    """Encrypt `payload` (bytes) for ONE subscription and POST it to its push service,
    returning the HTTP status code. Reimplements what pywebpush.webpush() did, using the
    apt-available primitives directly (so the Pi needs no pip):

      * A FRESH ephemeral P-256 sender key is generated per message (never reused).
      * http_ece.encrypt(..., version="aes128gcm") performs RFC 8188 payload encryption from
        that sender key + the subscription's p256dh (receiver key) and auth secret. In
        aes128gcm the salt and the sender public key are carried INSIDE the body, so no
        Crypto-Key / Encryption headers are required -- only Content-Encoding: aes128gcm.
      * vapid.sign(claims) yields the "Authorization: vapid t=<jwt>,k=<pubkey>" header, with
        aud = the push endpoint's ORIGIN and a 12-hour expiry (well within the spec's 24h cap).

    Raises on a transport error (requests) -- the caller handles/logs it per subscription."""
    keys = sub.get("keys") or {}
    receiver_key = _b64url_decode(keys.get("p256dh", ""))   # the browser's public key (raw point)
    auth_key = _b64url_decode(keys.get("auth", ""))         # the browser's auth secret
    # One-time ECDH sender key -> forward secrecy; http_ece embeds its public half in the body.
    server_key = _crypto_ec.generate_private_key(_crypto_ec.SECP256R1())
    encrypted = http_ece.encrypt(
        payload,
        private_key=server_key,
        dh=receiver_key,
        auth_secret=auth_key,
        version="aes128gcm",
    )
    endpoint = sub["endpoint"]
    u = urlparse(endpoint)
    # A fresh signed JWT per send: aud MUST be the push service origin; exp is bounded.
    claims = {
        "sub": subject,
        "aud": f"{u.scheme}://{u.netloc}",
        "exp": int(time.time()) + 12 * 60 * 60,
    }
    headers = dict(vapid.sign(claims))
    headers["content-encoding"] = "aes128gcm"
    headers["ttl"] = str(PUSH_TTL_SECONDS)
    # timeout=(connect, read): a black-hole or slow push endpoint must never hang the daemon
    # send thread forever -- bound both phases so a stuck service fails fast and we move on.
    # allow_redirects=False (defense in depth): a real push service answers the POST DIRECTLY
    # (201) and never redirects. Following a 3xx would let an authenticated subscriber register
    # a redirector endpoint that bounces this POST to an internal address (127.0.0.1 /
    # 169.254.169.254), side-stepping the IP-literal SSRF check on /api/push/subscribe. A
    # redirect is therefore treated as a failed send (its 3xx status is logged, never pruned).
    resp = requests.post(
        endpoint, data=encrypted, headers=headers, timeout=(5, 10), allow_redirects=False
    )
    return resp.status_code


def send_push(title, body, tag=None):
    """Send a Web Push notification to every subscribed browser.

    MUST NOT raise into its caller (it is fired from state-transition paths + a monitor
    thread). No-ops when push is unavailable or there are no subscriptions. A 404/410 from a
    push service means the subscription is dead -> prune it; any other per-subscription error
    is logged and skipped so one bad endpoint can't stop the rest.
    """
    if not push_available():
        return
    subs = get_subscriptions()
    if not subs:
        return
    payload = json.dumps({"title": title, "body": body, "tag": tag or "generatorpi"}).encode("utf-8")
    subject = CONFIG.get("VAPID_SUBJECT") or "mailto:admin@localhost"
    try:
        # One Vapid instance signs a fresh JWT (fresh aud/exp) for each send below, so build
        # it once and reuse it across every subscription.
        vapid = Vapid.from_raw(CONFIG["VAPID_PRIVATE_KEY"].encode("utf-8"))
    except Exception as e:
        log.warning(f"Invalid VAPID key, cannot send push: {e}")
        return
    for sub in subs:
        try:
            status = _deliver_push(sub, payload, vapid, subject)
            if status in (404, 410):
                # 404 Not Found / 410 Gone: the browser unsubscribed -> drop the dead record.
                log.info(f"Pruning dead push subscription ({status})")
                remove_subscription(sub["endpoint"])
            elif status > 202:
                log.warning(f"Web push failed (status={status})")
        except requests.RequestException as e:
            # Network/transport failure to the push service (timeout, DNS, TLS, connreset).
            log.warning(f"Web push transport error: {e}")
        except Exception as e:
            log.warning(f"Web push error: {e}")


def send_push_async(title, body, tag=None):
    """Fire-and-forget send_push on a daemon thread so a slow/blocked push to N devices
    never stalls a request handler or the relay control path."""
    if not push_available():
        return
    threading.Thread(
        target=send_push, args=(title, body, tag), daemon=True
    ).start()


# Bring the store up now that logging is live. This also records the startup event.
init_event_store()
