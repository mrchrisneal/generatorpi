# genpi/routes/push.py -- the PUSH route blueprint (roadmap #59, Stage 9): the push service worker
# (/sw.js, no auth, no secrets) + the Web-Push subscription endpoints (/api/push/{subscribe,
# unsubscribe,test}). _push_endpoint_error is the SSRF guard on a subscription endpoint URL (moved
# here with its sole caller). Bodies are byte-identical apart from @bp.route + store.record_event.
# Copyright (C) 2026 Chris Neal <https://neal.media> and Alex Neal <https://neal.tools>
# SPDX-License-Identifier: AGPL-3.0-or-later
import ipaddress
from urllib.parse import urlparse
from flask import Blueprint, request, jsonify, Response
from .. import store
from ..logg import log
from ..auth import auth_required, caller_identity
from ..store import add_subscription, remove_subscription, subscription_count, push_available
from ..ui import SERVICE_WORKER_JS

bp = Blueprint("push", __name__)


@bp.route('/sw.js')
def service_worker():
    """Serve the push service worker (no auth; no secrets)."""
    return Response(
        SERVICE_WORKER_JS,
        mimetype="application/javascript",
        headers={"Cache-Control": "no-cache"},
    )


def _push_endpoint_error(endpoint):
    """Validate a push-subscription endpoint URL, returning an error string if it is
    unacceptable, or None if it is safe to store + later POST to.

    send_push() makes an outbound HTTP request to whatever endpoint we store, so an
    attacker who can subscribe an arbitrary URL turns this into a Server-Side Request
    Forgery primitive against the Pi's own network (localhost admin panels, LAN
    devices, cloud metadata IPs, etc.). We therefore require:

      * an https:// URL (a real push service is always https; http:// is rejected), and
      * a host that is NOT an IP literal in a private/loopback/link-local/reserved
        range. A normal push-service DNS hostname (fcm.googleapis.com, *.notify.
        windows.com, ...) is NOT an IP literal, so ipaddress.ip_address() raises and it
        passes. Only a bare private/internal IP is blocked.
    """
    if not isinstance(endpoint, str) or not endpoint:
        return "missing endpoint or keys"
    parsed = urlparse(endpoint)
    if parsed.scheme != "https":
        return "endpoint must be an https:// URL"
    host = parsed.hostname
    if not host:
        return "endpoint has no host"
    try:
        # If the host parses as an IP literal, block internal/non-routable ranges.
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Not an IP literal -> an ordinary DNS hostname (the normal case) -> allow.
        return None
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        return "endpoint host is not a routable public address"
    return None


@bp.route('/api/push/subscribe', methods=['POST'])
@auth_required
def api_push_subscribe():
    """Store a browser's Web Push subscription (endpoint + p256dh + auth keys)."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "message": "invalid subscription"}), 400
    endpoint = data.get("endpoint")
    keys = data.get("keys") or {}
    p256dh = keys.get("p256dh")
    auth = keys.get("auth")
    if not endpoint or not p256dh or not auth:
        return jsonify({"success": False, "message": "missing endpoint or keys"}), 400
    # SSRF hardening: only accept an https:// endpoint whose host is not an internal
    # IP literal (see _push_endpoint_error). send_push() will POST to this URL, so an
    # unvalidated endpoint would let a caller aim the daemon at the loopback/LAN.
    ep_err = _push_endpoint_error(endpoint)
    if ep_err:
        return jsonify({"success": False, "message": ep_err}), 400
    add_subscription(endpoint, p256dh, auth)
    log.info(f"Push subscription added by {caller_identity()}")
    return jsonify({"success": True, "subscriptions": subscription_count()})


@bp.route('/api/push/unsubscribe', methods=['POST'])
@auth_required
def api_push_unsubscribe():
    """Remove a push subscription by its endpoint."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    endpoint = data.get("endpoint")
    if not endpoint:
        return jsonify({"success": False, "message": "missing endpoint"}), 400
    remove_subscription(endpoint)
    return jsonify({"success": True, "subscriptions": subscription_count()})


@bp.route('/api/push/test', methods=['POST'])
@auth_required
def api_push_test():
    """Send a test push to all subscribed devices (the Advanced-drawer button)."""
    if not push_available():
        return jsonify({"success": False, "message": "push not available on server"}), 503
    if subscription_count() == 0:
        return jsonify({"success": False, "message": "no subscriptions"}), 409
    store.send_push_async("Test notification", "Push notifications are working.", tag="test")
    store.record_event("push", "Test notification sent")
    log.info(f"Test push sent by {caller_identity()}")
    return jsonify({"success": True})

