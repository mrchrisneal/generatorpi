# genpi/routes/core.py -- the CORE route blueprint (roadmap #59, Stage 9): the web UI homepage,
# the relay start/stop + tracked-state endpoints, the event/state/system-history feeds, the app-log
# tail, and the restart + factory-reset admin actions. Route BODIES are byte-identical to the old
# genpi/__init__ handlers; only @app.route became @bp.route and the handful of service calls a test
# patches to intercept a route are module-qualified to their owning submodule (store.record_event,
# logg.log_path, lifecycle._schedule_process_restart, sysmon._sys_history) so those patches are not
# silent no-ops. Imports services + auth ONLY -- never the Flask app (that is app.py's job).
# Copyright (C) 2026 Chris Neal <https://neal.media> and Alex Neal <https://neal.tools>
# SPDX-License-Identifier: AGPL-3.0-or-later
from datetime import datetime
import threading
import time
import os
from flask import Blueprint, request, jsonify, render_template_string
from .. import store, logg, lifecycle, sysmon
from ..config import CONFIG, APP_VERSION, _STARTED_AT
from ..logg import log
from ..auth import auth_required, caller_identity
from ..state import (state_lock, generator_state, fuel_state, alerts_state,
                     _apply_running_transition_locked, set_total_run_hours, FUEL_DEFAULT_RATE)
from ..control import start_generator, stop_generator
from ..fuel import fuel_snapshot_locked
from ..store import get_events, get_latest_seq, subscription_count, push_status, _event_lock
from ..ui import HTML_TEMPLATE
from ..relay import relay_lock
from ._helpers import _json_number

bp = Blueprint("core", __name__)


@bp.route('/')
@auth_required
def index():
    """Web UI homepage"""
    with state_lock:
        status = generator_state.copy()
    return render_template_string(HTML_TEMPLATE, status=status, version=APP_VERSION)

@bp.route('/api/start', methods=['POST'])
@auth_required
def api_start():
    """REST endpoint to start generator"""
    # Capture the issuing user HERE, in the request context (#63) -- the worker thread
    # we spawn below has no Flask request context to read caller_identity() from.
    actor = caller_identity()
    # Check lock before spawning a thread to avoid creating throwaway threads
    if relay_lock.locked():
        log.warning(f"Start rejected (relay busy) for {actor}@{request.remote_addr}")
        store.record_event("start_rejected", "relay busy", actor=actor)
        return jsonify({"success": False, "message": "A relay sequence is already in progress"}), 409
    # Pass the captured identity into the worker so every start event is attributed.
    threading.Thread(target=start_generator, kwargs={"actor": actor}, daemon=True).start()
    return jsonify({"success": True, "message": "Start sequence initiated in background"})

@bp.route('/api/stop', methods=['POST'])
@auth_required
def api_stop():
    """REST endpoint to stop generator"""
    result = stop_generator(actor=caller_identity())
    return jsonify(result)

@bp.route('/api/status', methods=['GET'])
@auth_required
def api_status():
    """REST endpoint for integrations"""
    with state_lock:
        status = generator_state.copy()
    return jsonify(status)

@bp.route('/api/set_running', methods=['POST'])
@auth_required
def api_set_running():
    """Manual override to set running state (for manual verification)"""
    # silent=True avoids a 415 on a bodyless/wrong-content-type POST; the isinstance
    # guard then tolerates a NON-dict JSON body (a list/number/string would otherwise
    # 500 on .get). Both cases default to STOPPED.
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    # Coerce 'running' to a real bool. Interpret common string forms so that
    # {"running": "false"} / "0" / "no" map to STOPPED rather than a truthy string.
    raw = data.get('running', False)
    if isinstance(raw, str):
        running = raw.strip().lower() in ("true", "1", "yes", "on")
    else:
        running = bool(raw)

    with state_lock:
        # Manual override: correct the TRACKED state only (no relay). The transition
        # helper still does run-hours accounting so a hand-operated run is counted.
        _apply_running_transition_locked(running)
        generator_state["last_command"] = "mark_run" if running else "mark_stop"
        # Keep the Last Start/Last Stop registers meaningful for manual actions too.
        if running:
            generator_state["last_start_time"] = datetime.now().isoformat()
        else:
            generator_state["last_stop_time"] = datetime.now().isoformat()
        generator_state["message"] = f"Manually set to {'RUNNING' if running else 'STOPPED'}"

    # Durable record of the manual state override, attributed to the issuing user (#63).
    store.record_event("set_running", f"State manually set to {'RUNNING' if running else 'STOPPED'}",
                       actor=caller_identity())
    # Notify subscribed devices of the manual state change (distinct copy from a real
    # start/stop so it's clear no engine action occurred).
    store.send_push_async(
        "Marked as running" if running else "Marked as stopped",
        "Tracked state was set manually (no relay action).",
        tag="state",
    )
    log.info(f"State manually set to {'RUNNING' if running else 'STOPPED'} by {caller_identity()}")
    return jsonify({"success": True, "running": running})

@bp.route('/api/runtime/hours', methods=['POST'])
@auth_required
def api_runtime_hours():
    """Manually set the lifetime run-hours odometer. Body: {"hours": float >= 0}.

    A TRACKED-STATE correction only (like MARK RUNNING) -- it NEVER cranks or stops the
    engine and never touches the relay. The value is clamped/quantized + persisted by
    set_total_run_hours(); the fuel projection is preserved across the change. A bad or
    absent body is a 400 (never a 500), consistent with the other numeric endpoints."""
    value, err = _json_number(request.get_json(silent=True), "hours")
    if err:
        return jsonify({"success": False, "message": err}), 400
    old_live, new_total = set_total_run_hours(value)
    # Durable audit trail of the manual odometer correction (old -> new). Uses the
    # MANUAL-tagged "set_running" event type so it reads alongside the other manual
    # overrides in the event log. %g keeps whole numbers clean (250 not 250.000000).
    store.record_event("set_running", f"Total run-hours set to {new_total:g} h (was {old_live:g} h)",
                       actor=caller_identity())
    log.info(f"Total run-hours set to {new_total:g} h (was {old_live:g} h) by {caller_identity()}")
    return jsonify({"success": True, "total_run_hours": new_total})

@bp.route('/api/events', methods=['GET'])
@auth_required
def api_events():
    """Return recent events from the persistent store, newest-first.

    Query params:
      limit  -- number of events to return (default 100, clamped to 1..1000).
      before -- optional int cursor: only events with seq < before (page older).
      after  -- optional int cursor: only events with seq > after (new since).

    Response JSON:
      {"events": [{"seq","ts","type","message"}, ...], "latest_seq": <int>}
    latest_seq lets the client cheaply tell whether new events exist without
    re-fetching the whole list.
    """
    # limit: default 100, clamped to a sane 1..1000 window. request.args.get with a
    # default + type=int returns the default (100) for a missing OR unparseable
    # value, so `limit` is always an int here.
    limit = request.args.get("limit", default=100, type=int)
    limit = max(1, min(limit, 1000))

    # Optional cursors. type=int yields None when absent or non-numeric, which the
    # store treats as "no cursor" -- so a garbage value degrades to the default view.
    before = request.args.get("before", default=None, type=int)
    after = request.args.get("after", default=None, type=int)

    return jsonify({
        "events": get_events(limit, before, after),
        "latest_seq": get_latest_seq(),
    })


@bp.route('/api/state', methods=['GET'])
@auth_required
def api_state():
    """Rich state snapshot for the web UI's initial render + polling.

    Returns everything the panel needs: tracked run-state + registers, the lifetime
    run-hours base + current-run start (so the client ticks the uptime/odometer
    live), the fuel model, and the alert config. `server_now` is the server's unix
    clock so the client can align its live timers to the server rather than to a
    possibly-skewed local clock.
    """
    with state_lock:
        snap = {
            "running": generator_state["running"],
            "last_command": generator_state["last_command"],
            "last_start_time": generator_state["last_start_time"],
            "last_stop_time": generator_state["last_stop_time"],
            "start_attempts": generator_state["start_attempts"],
            "message": generator_state["message"],
            "current_run_started_at": generator_state["current_run_started_at"],
            "total_run_hours": generator_state["total_run_hours"],
            "fuel": fuel_snapshot_locked(),
            "alerts": dict(alerts_state),
            "fuel_enabled": alerts_state.get("fuel_enabled", True),
        }
    snap["server_now"] = time.time()
    # Running version + this process's start timestamp (unix). started_at CHANGES on every full
    # restart, so the client can robustly detect a completed self-update (new process = new
    # started_at) and show when the app was last fully restarted.
    snap["app_version"] = APP_VERSION
    snap["started_at"] = _STARTED_AT
    # SYSTEM drawer FACE stat -- a single glanceable value shown even when the drawer is
    # collapsed. CPU% is the most universally understood "how busy" metric and is always
    # available. Pulled from the last ring-buffer sample, NOT computed here: _cpu_pct() is a
    # stateful delta against the sampler-owned _prev_cpu, so calling it from the request path
    # would corrupt the sampler's baseline. At most one sample-interval stale (fine for a
    # collapsed-drawer glance); None until the first sample lands -> the UI hides it.
    with sysmon._sys_hist_lock:
        _last_sys = sysmon._sys_history[-1] if sysmon._sys_history else None
    snap["sys"] = {"cpu": _last_sys["cpu"] if _last_sys else None}
    # Web Push info for the client: whether the server can send (library + VAPID key),
    # the public key the browser needs to subscribe, and how many devices are subscribed.
    # push_status() gives both the boolean AND a machine reason ("library_missing" /
    # "no_keys" / "invalid_keys" / "ok") so the UI can explain EXACTLY why push is off.
    _push_ok, _push_reason = push_status()
    snap["push"] = {
        "supported": _push_ok,
        "reason": _push_reason,
        "vapid_public_key": CONFIG.get("VAPID_PUBLIC_KEY", ""),
        "subscriptions": subscription_count(),
    }
    return jsonify(snap)


@bp.route('/api/system/history', methods=['GET'])
@auth_required
def api_system_history():
    """Return the in-memory SYSTEM perf-history ring buffer as JSON for the UI.
    With ?since=<unix_ts>, returns ONLY points newer than that (a delta poll -- tiny
    payload for the flaky link); without it, the full buffer (initial load). Snapshot
    under the lock so we never serialize a deque mid-append."""
    with sysmon._sys_hist_lock:
        points = list(sysmon._sys_history)
    since = request.args.get("since")
    if since is not None:
        try:
            since_t = float(since)
            points = [p for p in points if p["t"] > since_t]
        except (ValueError, TypeError):
            pass  # malformed 'since' -> fall back to the full buffer
    # COLUMNAR payload: emit one array per field instead of an array-of-objects. A
    # row-wise body repeats all 10 key names on EVERY point (240 on the Pi, 900 in dev)
    # -- thousands of redundant bytes. Columnar names each key ONCE, roughly halving the
    # wire size, so history is small enough to share the SINGLE serial poll lane with
    # state/events without stalling the flaky link. The client rebuilds row objects.
    # sysmon.SYS_FIELDS order is the contract the frontend's colsToRows() relies on.
    cols = {k: [p[k] for p in points] for k in sysmon.SYS_FIELDS}
    return jsonify({
        "cols": cols,
        "count": len(points),
        "sample_seconds": max(5, int(CONFIG.get("SYSTEM_HISTORY_SECONDS", 15))),
        "capacity": sysmon._sys_history.maxlen,
        "server_now": time.time(),
    })


def _read_tail_block(path, n):
    """Read fixed-size blocks BACKWARD from EOF until we have more than `n` newlines
    (so the first kept line is whole) OR reach BOF. Returns (data, start_pos, size)
    where data == file bytes [start_pos:size]. Cost is bounded by the bytes of those
    last `n` lines, NOT the whole (10MB-capped) log. Missing/empty -> (b"", 0, 0).
    Never raises on a torn read -- callers decode UTF-8 with errors replaced."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            if size == 0:
                return b"", 0, 0
            block = 4096
            data = b""
            pos = size
            while pos > 0 and data.count(b"\n") <= n:
                step = min(block, pos)
                pos -= step
                f.seek(pos)
                data = f.read(step) + data
            return data, pos, size
    except (FileNotFoundError, OSError):
        return b"", 0, 0


def _tail_lines(path, n):
    """Up to the last `n` COMPLETE lines of a text file (a trailing partial line -- a
    log write in flight -- is dropped). Missing/empty -> []. Errors replaced on decode."""
    data, _, size = _read_tail_block(path, n)
    if size == 0:
        return []
    # splitlines() drops the trailing newline; [-n:] trims any overshoot from the block.
    return data.decode("utf-8", "replace").splitlines()[-n:]


def _tail_with_cursor(path, n):
    """(last `n` complete lines, byte cursor just past the file's final newline).

    The cursor is the delta anchor: a subsequent read from it yields only newly-appended
    bytes. It stops at the last NEWLINE (not EOF), so an in-flight final line is re-read
    and completed on the next poll rather than shown half-written. Missing/empty -> ([], 0)."""
    data, pos, size = _read_tail_block(path, n)
    if size == 0:
        return [], 0
    last_nl = data.rfind(b"\n")                 # data ends at EOF, so this is the file's last NL
    cursor = (pos + last_nl + 1) if last_nl >= 0 else 0
    text = data.decode("utf-8", "replace")
    if not text.endswith("\n"):                 # drop a trailing partial (matches the cursor)
        idx = text.rfind("\n")
        text = text[:idx + 1] if idx >= 0 else ""
    return text.splitlines()[-n:], cursor


def _read_log_range(path, start, end, n):
    """Read the NEW bytes [start, end) and return (complete_lines, new_cursor).

    Only whole lines (up to the last newline in the range) are returned; the cursor
    advances to just past that newline, leaving any in-flight final line for next poll.
    No new complete line yet -> ([], start). The delta is capped to the last `n` lines
    so a huge burst can't blow the payload. Errors on decode are replaced (never raises)."""
    try:
        with open(path, "rb") as f:
            f.seek(start)
            chunk = f.read(end - start)
    except (FileNotFoundError, OSError):
        return [], start
    last_nl = chunk.rfind(b"\n")
    if last_nl < 0:
        return [], start                        # nothing complete appended yet
    complete = chunk[:last_nl]                   # bytes strictly before the last newline
    cursor = start + last_nl + 1
    lines = complete.decode("utf-8", "replace").split("\n")
    if len(lines) > n:
        lines = lines[-n:]
    return lines, cursor


@bp.route('/api/logs', methods=['GET'])
@auth_required
def api_logs():
    """Application-log feed for the EVENT LOG panel's 'APP LOG' view -- an INCREMENTAL
    (delta) tail so we don't resend the whole file every poll.

    The path is FIXED server-side (logg.log_path = SCRIPT_DIR / LOG_FILE) and never derived
    from request input, so there is zero path-traversal surface.

    Query params:
      lines -- max lines to return (default/cap 1000, clamped 1..1000).
      since -- byte cursor from a prior response's `offset`. Omitted/invalid -> a full
               tail (the last `lines` lines). A cursor PAST current EOF means the file
               rotated/truncated -> we transparently fall back to a full tail + reset.

    Response JSON:
      {"lines": [<oldest..newest>], "offset": <int byte cursor>, "reset": <bool>,
       "path": "<log file name>"}
    `reset` true tells the client to REPLACE its view (initial load or post-rotation);
    false means `lines` are strictly-new rows to append. Each line still carries its own
    "YYYY-MM-DD HH:MM:SS [LEVEL] ..." timestamp, which the client parses for display.
    """
    # type=int -> the default for a missing OR unparseable value; clamp bounds the payload.
    n = request.args.get("lines", default=1000, type=int)
    n = max(1, min(n, 1000))
    since = request.args.get("since", default=None, type=int)

    # Current EOF up front so we can classify the request (stat is cheap, never raises here).
    try:
        size = os.path.getsize(logg.log_path)
    except OSError:
        size = 0

    # FULL TAIL (reset): no cursor (initial load) OR a cursor that's negative / past EOF
    # (the file was rotated or truncated out from under the client -> its cursor is stale).
    if since is None or since < 0 or since > size:
        tail, cursor = _tail_with_cursor(logg.log_path, n)
        return jsonify({"lines": tail, "offset": cursor, "reset": True, "path": logg.log_path.name})

    # Up to date already -> empty delta, cursor unchanged (the common idle poll: ~tiny).
    if since >= size:
        return jsonify({"lines": [], "offset": since, "reset": False, "path": logg.log_path.name})

    # DELTA: return only the bytes appended since the client's cursor.
    new_lines, cursor = _read_log_range(logg.log_path, since, size, n)
    return jsonify({"lines": new_lines, "offset": cursor, "reset": False, "path": logg.log_path.name})


@bp.route('/api/restart', methods=['POST'])
@auth_required
def api_restart():
    """Restart the server process (self re-exec). Returns 200 FIRST, then re-execs after a
    short delay so the response reaches the client. Authed + CSRF-guarded like every POST."""
    log.warning(f"Application restart requested by {caller_identity()}@{request.remote_addr}")
    store.record_event("restart", "Application restart requested", actor=caller_identity())
    lifecycle._schedule_process_restart()
    return jsonify({"success": True, "message": "Restarting - reconnecting shortly..."})


def factory_reset():
    """Wipe the application's runtime MEMORY back to factory defaults: empty the event
    store (events/kv/subscriptions rows), truncate the app log file, and reset the durable
    in-memory globals (lifetime run-hours, fuel model, alert config) to code defaults.

    Deliberately does NOT touch generator_control.env or ANY credential/config file -- the
    reset contract is 'logs + DB/state only, leave the env alone'. Schema is preserved
    (rows cleared, tables kept) so the app keeps working live without a restart."""
    # 1. Empty the DB tables (one shared connection, serialized by _event_lock). _event_conn is
    #    REBOUND by init_event_store(), so read it module-qualified from store (the re-exported
    #    copy would go stale after a reopen -- e.g. a test pointing the store at a tmp DB).
    with _event_lock:
        if store._event_conn is not None:
            store._event_conn.execute("DELETE FROM events")
            store._event_conn.execute("DELETE FROM kv")
            store._event_conn.execute("DELETE FROM subscriptions")
            store._event_conn.commit()
    # 2. Reset the durable in-memory globals to their code defaults.
    with state_lock:
        generator_state["running"] = False
        generator_state["current_run_started_at"] = None
        generator_state["total_run_hours"] = 0.0
        fuel_state["fill_level"] = 100.0
        fuel_state["fill_run_hours"] = 0.0
        fuel_state["drain_rate"] = FUEL_DEFAULT_RATE
        fuel_state["default_rate"] = FUEL_DEFAULT_RATE
        alerts_state["alerts_on"] = True
        alerts_state["alert_threshold"] = 20
        alerts_state["fuel_enabled"] = True
    # 3. Truncate the application log file (open 'w' empties it). Best-effort, never fatal.
    try:
        with open(logg.log_path, "w"):
            pass
    except OSError:
        pass


@bp.route('/api/factory-reset', methods=['POST'])
@auth_required
def api_factory_reset():
    """Factory reset: wipe the event store + logs + durable state (NEVER the env file) back
    to defaults. No process restart -- factory_reset() resets the live in-memory globals, so
    the running app continues with a clean slate. Authed + CSRF-guarded. The client refreshes
    to reflect the reset state."""
    who = caller_identity()
    log.warning(f"FACTORY RESET requested by {who}@{request.remote_addr}")
    factory_reset()
    # First event written into the freshly-emptied store, so there's an audit trail of it.
    store.record_event("factory_reset", "Factory reset performed (event store + logs cleared)", actor=who)
    return jsonify({"success": True, "message": "Factory reset complete."})

