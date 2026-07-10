# genpi/routes/update.py -- the UPDATE route blueprint (roadmap #59, Stage 9): the version-check +
# self-updater DRIVER endpoints (/api/check-update, /api/update/{changelog,status,start,decide,
# result,result/ack}). The heavy lifting lives in genpi/updater.py; these routes only drive it and
# share its progress state. Route BODIES are byte-identical except that every updater-owned symbol is
# module-qualified as updater.<name> -- the test suite patches those via module.updater.* (constants,
# the decision Event, _run_update, _http_get_bytes, ...), so a bare import would make them no-ops.
# Copyright (C) 2026 Chris Neal <https://neal.media> and Alex Neal <https://neal.tools>
# SPDX-License-Identifier: AGPL-3.0-or-later
import json
import threading
from flask import Blueprint, request, jsonify
from .. import updater
from ..logg import log
from ..auth import auth_required, caller_identity

bp = Blueprint("update", __name__)


@bp.route('/api/check-update', methods=['GET'])
@auth_required
def api_check_update():
    """Report installed vs. published version. `?fresh=1` does a LIVE repo check (manual
    "Check again" + the on-load check); the default returns the CACHED last-known result so the
    footer's 5-minute refresh never touches GitHub. `latest` is null when a live check couldn't
    reach the repo (offline / not yet public)."""
    if request.args.get("fresh"):
        return jsonify(updater._run_update_check())
    with updater._update_lock:
        cached = dict(updater._update_check_cache)
    if cached.get("checked_at") is None:          # nothing cached yet -> one live check
        return jsonify(updater._run_update_check())
    return jsonify({"installed": updater.APP_VERSION, "latest": cached["latest"],
                    "update_available": bool(cached["update_available"])})


# ----------------------------------------------------------------------------
# The self-updater machinery (download / verify / backup / swap / rollback / bootstrap + the #72
# CLI-only gate) moved to genpi/updater.py in Stage 8 -- see the re-export block above. The
# /api/update/* routes below still drive it via the re-exported functions + shared progress state.
# ----------------------------------------------------------------------------

@bp.route('/api/update/changelog', methods=['GET'])
@auth_required
def api_update_changelog():
    """Fetch the release CHANGELOG for the update modal. Never errors hard -- returns
    {changelog: null} if the repo is unreachable so the modal can still open."""
    try:
        # CHANGELOG-RECENT.md holds only the latest few releases (generated from the full CHANGELOG.md
        # by tools/changelog.py). We fetch the SHORT file so a version check isn't a full-changelog
        # download every time. See the "Changelog" section in the repo CLAUDE.md.
        text = updater._http_get_bytes(updater._RAW_BASE + "/CHANGELOG-RECENT.md", max_bytes=64_000).decode("utf-8", "replace")
        return jsonify({"changelog": text, "backup_dir": str(updater._BACKUP_DIR)})
    except Exception as e:                              # noqa: BLE001 -- non-fatal
        return jsonify({"changelog": None, "error": str(e), "backup_dir": str(updater._BACKUP_DIR)})


@bp.route('/api/update/status', methods=['GET'])
@auth_required
def api_update_status():
    """Current updater progress (polled by the UI during an update)."""
    with updater._update_lock:
        return jsonify(dict(updater._update_state))


@bp.route('/api/update/start', methods=['POST'])
@auth_required
def api_update_start():
    """Kick off the self-update in a background thread. Admin surface: authed +
    CSRF-guarded (every POST is). 409 if an update is already running."""
    with updater._update_lock:
        if updater._update_state["phase"] not in ("idle", "done", "failed"):
            return jsonify({"success": False, "message": "An update is already in progress."}), 409
        updater._update_state.update(phase="checking", message="Starting…", progress=0.0,
                             error=None, systemd=updater._deployment_has_systemd(), log=[], decide=None,
                             missing_deps=[], deps_install_cmd="", installable=True,
                             important_notes=[], stage=1,
                             counts={"stage1": {"warn": 0, "err": 0}, "stage2": {"warn": 0, "err": 0}})
    log.warning(f"Self-update requested by {caller_identity()}@{request.remote_addr}")
    threading.Thread(target=updater._run_update, daemon=True, name="self-update").start()
    return jsonify({"success": True})


@bp.route('/api/update/decide', methods=['POST'])
@auth_required
def api_update_decide():
    """Answer a REVERT/PROCEED prompt the running update parked on (phase 'awaiting'). Body
    {choice: 'proceed'|'revert'}; 'proceed' is only honored when the parked step allowed it
    (a hard safety error offers REVERT only). 409 if nothing is awaiting a decision."""
    data = request.get_json(silent=True) or {}
    choice = data.get("choice")
    if choice not in ("proceed", "revert"):
        return jsonify({"success": False, "message": "choice must be 'proceed' or 'revert'"}), 400
    with updater._update_lock:
        decide = updater._update_state.get("decide")
        if updater._update_state["phase"] != "awaiting" or not decide:
            return jsonify({"success": False, "message": "no decision is pending"}), 409
        # Refuse PROCEED on a step that forbids it (safety errors) -- fall back to REVERT.
        if choice == "proceed" and not decide.get("allow_proceed"):
            choice = "revert"
        updater._update_decision_choice["choice"] = choice
    updater._update_decision_event.set()                          # unblock the worker's _await_decision
    return jsonify({"success": True, "choice": choice})


@bp.route('/api/update/result', methods=['GET'])
@auth_required
def api_update_result():
    """After a restart triggered by an update, report how it went (+ the captured log) so the
    UI can show a one-time success/failure modal. {pending:false} once acknowledged/cleared."""
    if not updater._UPDATE_RESULT.exists():
        return jsonify({"pending": False})
    try:
        res = json.loads(updater._UPDATE_RESULT.read_text())
    except Exception:                                    # corrupt marker -> still surface it
        res = {"status": "unknown", "version": None, "note": ""}
    log_text = ""
    try:
        if updater._UPDATE_LOG.exists():
            log_text = updater._UPDATE_LOG.read_text(errors="replace")[-20000:]   # tail, bounded
    except Exception:
        pass
    res.update({"pending": True, "log": log_text})
    return jsonify(res)


@bp.route('/api/update/result/ack', methods=['POST'])
@auth_required
def api_update_result_ack():
    """Clear the update-result marker SERVER-SIDE, so once ANY client dismisses the modal it
    never reappears (for anyone) until the next update writes a new marker."""
    for p in (updater._UPDATE_RESULT, updater._UPDATE_LOG):
        try:
            p.unlink()
        except OSError:
            pass
    return jsonify({"success": True})

