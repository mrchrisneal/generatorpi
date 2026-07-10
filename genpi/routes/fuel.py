# genpi/routes/fuel.py -- the FUEL route blueprint (roadmap #59, Stage 9): the operator fuel-model
# mutators (/api/fuel/{reading,rate,rate/reset,fill}) + the low-fuel alert config (/api/alerts).
# The fuel math + mutators live in genpi/fuel.py; these routes validate the JSON body (_json_number)
# and call them. Bodies are byte-identical apart from @bp.route + store.record_event qualification.
# Copyright (C) 2026 Chris Neal <https://neal.media> and Alex Neal <https://neal.tools>
# SPDX-License-Identifier: AGPL-3.0-or-later
from flask import Blueprint, request, jsonify
from .. import store
from ..logg import log
from ..auth import auth_required, caller_identity
from ..fuel import (record_fuel_reading, set_fuel_rate, reset_fuel_rate,
                    set_fuel_fill, set_alerts)
from ._helpers import _json_number

bp = Blueprint("fuel", __name__)


@bp.route('/api/fuel/reading', methods=['POST'])
@auth_required
def api_fuel_reading():
    """Record an observed tank level (%), refining the drain-rate estimate."""
    value, err = _json_number(request.get_json(silent=True), "level")
    if err:
        return jsonify({"success": False, "message": err}), 400
    rate = record_fuel_reading(value)
    # Log the CLAMPED level actually used (0..100), not the raw request value, so the
    # event log doesn't claim e.g. "150%" when 100% was fitted.
    shown = max(0.0, min(100.0, value))
    store.record_event("fuel", f"Observed level {shown:g}% - drain rate now {rate:g} %/hr",
                       actor=caller_identity())
    log.info(f"Fuel reading {shown:g}% by {caller_identity()} -> rate {rate:g} %/hr")
    return jsonify({"success": True, "drain_rate": rate})


@bp.route('/api/fuel/rate', methods=['POST'])
@auth_required
def api_fuel_rate():
    """Set the drain rate (%/hr) directly."""
    value, err = _json_number(request.get_json(silent=True), "rate")
    if err:
        return jsonify({"success": False, "message": err}), 400
    rate = set_fuel_rate(value)
    store.record_event("fuel", f"Drain rate set to {rate:g} %/hr", actor=caller_identity())
    log.info(f"Drain rate set to {rate:g} %/hr by {caller_identity()}")
    return jsonify({"success": True, "drain_rate": rate})


@bp.route('/api/fuel/rate/reset', methods=['POST'])
@auth_required
def api_fuel_rate_reset():
    """Restore the drain rate to its configured default."""
    rate = reset_fuel_rate()
    store.record_event("fuel", f"Drain rate reset to default {rate:g} %/hr", actor=caller_identity())
    log.info(f"Drain rate reset to {rate:g} %/hr by {caller_identity()}")
    return jsonify({"success": True, "drain_rate": rate})


@bp.route('/api/fuel/fill', methods=['POST'])
@auth_required
def api_fuel_fill():
    """'Add gas': reset the baseline fill level (%). Drain rate is retained."""
    value, err = _json_number(request.get_json(silent=True), "level")
    if err:
        return jsonify({"success": False, "message": err}), 400
    snap = set_fuel_fill(value)
    store.record_event("fuel", f"Tank filled to {snap['fill_level']:g}%", actor=caller_identity())
    log.info(f"Tank filled to {snap['fill_level']:g}% by {caller_identity()}")
    return jsonify({"success": True, "fuel": snap})


@bp.route('/api/alerts', methods=['POST'])
@auth_required
def api_alerts():
    """Update low-fuel alert config: {enabled: bool?, threshold: int?}. Both
    optional; threshold is clamped to 5..40."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}

    def _bool_field(name):
        # Accept a real bool or the common string/int forms; None if absent.
        if name not in data:
            return None
        raw = data[name]
        if isinstance(raw, str):
            return raw.strip().lower() in ("true", "1", "yes", "on")
        return bool(raw)

    enabled = _bool_field("enabled")
    fuel_enabled = _bool_field("fuel_enabled")
    # threshold: optional numeric; reject a present-but-garbage value.
    threshold = None
    if "threshold" in data:
        tval, terr = _json_number(data, "threshold")
        if terr:
            return jsonify({"success": False, "message": terr}), 400
        threshold = tval
    snap = set_alerts(enabled=enabled, threshold=threshold, fuel_enabled=fuel_enabled)
    log.info(
        f"Alerts set on={snap['alerts_on']} threshold={snap['alert_threshold']}% "
        f"fuel_enabled={snap['fuel_enabled']} by {caller_identity()}"
    )
    return jsonify({"success": True, "alerts": snap})

