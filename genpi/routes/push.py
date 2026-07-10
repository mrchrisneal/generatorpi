# genpi/routes/push.py -- the PUSH route blueprint (roadmap #59, Stage 9): the push service worker
# (/sw.js, no auth, no secrets) + the Web-Push subscription endpoints (/api/push/{subscribe,
# unsubscribe,test}). _push_endpoint_error is the SSRF guard on a subscription endpoint URL (moved
# here with its sole caller). Bodies are byte-identical apart from @bp.route + store.record_event.
# Copyright (C) 2026 Chris Neal <https://neal.media> and Alex Neal <https://neal.tools>
# SPDX-License-Identifier: AGPL-3.0-or-later
import ipaddress
import socket                                # resolve endpoint hostnames to catch hostname->internal SSRF
from urllib.parse import urlparse
from flask import Blueprint, request, jsonify, Response
from .. import store
from ..logg import log
from ..auth import auth_required, caller_identity
from ..store import add_subscription, remove_subscription, subscription_count, push_available, get_events
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

      * an https:// URL (a real push service is always https; http:// is rejected),
      * an IP-literal host that is NOT in a private/loopback/link-local/reserved range, and
      * a DNS host that RESOLVES only to routable public addresses -- previously any
        hostname was allowed unresolved, so `https://evil.example/` pointing at
        127.0.0.1 / 169.254.169.254 (cloud metadata) / a LAN IP was an SSRF hole
        (#33). We now resolve it and reject if ANY answer is internal. A host that
        does not resolve is rejected too (it is unusable anyway, and failing closed
        beats guessing). NOTE: this does not fully defeat DNS REBINDING (the address
        could change between this check and the later POST); it closes the common
        hostname->internal case at subscribe time. This endpoint is auth-gated, so
        only an authenticated caller can even reach it.
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
        # If the host is an IP literal, decide purely on its range (no DNS needed).
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return "endpoint host is not a routable public address"
        return None
    # DNS hostname: resolve it and reject if ANY resolved address is internal. Fail closed on
    # a resolution error -- an unresolvable endpoint can never receive a push anyway.
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError:
        return "endpoint host could not be resolved"
    if not infos:
        return "endpoint host could not be resolved"
    for info in infos:
        addr = info[4][0]                          # sockaddr -> the resolved IP string
        try:
            rip = ipaddress.ip_address(addr)
        except ValueError:
            return "endpoint host resolved to an invalid address"
        if rip.is_private or rip.is_loopback or rip.is_link_local or rip.is_reserved:
            return "endpoint host resolves to a non-routable address"
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
    store.record_event("push", "Test notification sent", actor=caller_identity())
    log.info(f"Test push sent by {caller_identity()}")
    return jsonify({"success": True})


# #5: fixed, server-defined messages for the small set of BROWSER-side notification states a
# client may report. The client sends only a STATUS CODE (one of these keys) -- never free text --
# so nothing user-controlled ever reaches the durable event log, eliminating log injection. An
# unknown/missing code is a 400. Only browser-side causes are here; server-side push problems
# (missing library / no keys) are already visible server-side and are NOT client-reportable.
_BROWSER_NOTIFY_MESSAGES = {
    "blocked":     "Browser reports notifications are BLOCKED in this device's site settings",
    "unsupported": "Browser reports it does not support web push notifications",
    "insecure":    "Browser cannot enable push (insecure / non-HTTPS context on this device)",
}


@bp.route('/api/client/notify-status', methods=['POST'])
@auth_required
def api_client_notify_status():
    """Record a durable BROWSER diagnostic event (#5) when a client reports that web-push
    notifications are unavailable on THAT device -- so an operator scanning the Event Log can see
    WHY pushes aren't arriving without opening the browser's dev tools.

    SECURITY: the client sends only a fixed STATUS CODE, which the server maps to its OWN fixed
    message -- no client free text ever reaches the durable log (no log injection). Authed +
    CSRF-guarded like every mutating POST. Anti-spam is belt-and-suspenders: the client reports at
    most once per browser session, AND the server skips recording when the NEWEST event is already
    this identical browser report, so a misbehaving/repeating client can't flood the log."""
    # Tolerate a bodyless / non-dict / wrong-content-type POST without a 500 (mirrors the other
    # endpoints): anything that isn't a dict yields an unknown status -> a clean 400.
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    status = data.get("status")
    # Map the client code to a SERVER-OWNED message; an unknown/non-string code is rejected 400.
    message = _BROWSER_NOTIFY_MESSAGES.get(status) if isinstance(status, str) else None
    if message is None:
        return jsonify({"success": False, "message": "unknown notification status"}), 400
    # Belt-and-suspenders dedup: don't append an identical consecutive browser event. record_event
    # appends " (by <actor>)" to the stored text, so compare with startswith() on the base message.
    newest = get_events(limit=1)
    if newest and newest[0].get("type") == "browser" \
            and str(newest[0].get("message", "")).startswith(message):
        return jsonify({"success": True, "recorded": False})
    store.record_event("browser", message, actor=caller_identity())
    log.info(f"Browser notification status '{status}' reported by {caller_identity()}")
    return jsonify({"success": True, "recorded": True})

