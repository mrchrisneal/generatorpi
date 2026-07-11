# genpi/app.py -- the Flask WSGI application + its security middleware (roadmap #59, Stage 9).
# LAYER 6: owns the `app` object (static_folder=None -> zero file-serving surface), the 64 KiB body
# cap, the CSRF same-origin guard (before_request), and the security-header/strict-CSP + access-audit
# middleware (after_request), then registers the four route blueprints. The `app` instance is created
# BEFORE the blueprints are imported so the app<->routes cycle is broken structurally: app imports
# routes, routes never import app. genpi/__init__ does `from .app import app`, which rebinds the
# package attribute genpi.app to THIS Flask instance (tests use module.app.test_client()).
# Copyright (C) 2026 Chris Neal <https://neal.media> and Alex Neal <https://neal.tools>
# SPDX-License-Identifier: AGPL-3.0-or-later
from flask import Flask, request, jsonify, g
from .config import CONFIG
from .logg import log
from .auth import caller_identity
from . import store

app = Flask(__name__, static_folder=None)

# Cap the request body at 64 KiB (defense in depth). Every body this app accepts is
# tiny JSON -- a state toggle, a fuel number, or a push subscription (endpoint + two
# short keys) -- so 64 KiB is orders of magnitude of headroom. Werkzeug rejects a
# larger body with 413 before it's buffered, so a malicious/oversized upload can't
# exhaust memory on the Pi.
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024


# Methods that mutate server state -- the only ones the CSRF origin check guards.
# GET/HEAD/OPTIONS are safe/idempotent and are exempt (they change nothing).
_CSRF_PROTECTED_METHODS = ("POST", "PUT", "PATCH", "DELETE")


@app.before_request
def csrf_origin_guard():
    """Reject cross-origin state-changing browser requests (CSRF defense).

    The control routes use HTTP Basic Auth, which the browser AUTO-SENDS on every
    same-origin request once the user has logged in. Combined with a body-less action
    like POST /api/start (it reads NO request body), that means a malicious page on
    another site could auto-submit a form to this app and crank the engine using the
    victim's cached Basic-Auth credentials -- a classic CSRF. We block it by checking
    the browser-set Origin/Referer against our own origin on every mutating method:

      expected = "{scheme}://{host}"  (the origin this request was actually served on)

      * Origin present and != expected  -> reject 403 (a real cross-site request).
      * Origin absent but Referer present and not under expected -> reject 403
        (older browsers omit Origin on some requests but still send Referer).
      * NEITHER header present -> ALLOW. Browsers always attach at least one of them
        to a cross-site state-changing request, so "neither" means a NON-browser
        caller: our HomeAssistant rest_command, curl, the test client, etc. Those
        authenticate with the API key (not an ambient cookie/Basic session) and are
        not a CSRF vector, so blocking them would break legitimate automation for no
        security gain. GET/HEAD/OPTIONS are exempt entirely (safe methods).
    """
    if request.method not in _CSRF_PROTECTED_METHODS:
        return None  # safe method -- nothing to guard

    # The origin this request was actually served on (scheme + host[:port]). request.host
    # includes the port when non-default, matching how a browser builds the Origin value.
    expected = f"{request.scheme}://{request.host}"

    origin = request.headers.get("Origin")
    if origin is not None:
        # Origin is the authoritative signal: a browser sets it on cross-site (and most
        # same-site) state-changing requests and it CANNOT be forged by page JS.
        if origin != expected:
            return jsonify(
                {"success": False, "message": "cross-origin request rejected"}
            ), 403
        return None  # same-origin -- allow

    referer = request.headers.get("Referer")
    if referer is not None:
        # Fallback when Origin is absent: the Referer must point at our own origin.
        # Require it to be exactly `expected` or start with `expected + "/"` so a host
        # like "https://evilexpected.com" can't prefix-match our "https://expected".
        if referer != expected and not referer.startswith(expected + "/"):
            return jsonify(
                {"success": False, "message": "cross-origin request rejected"}
            ), 403
        return None  # same-origin Referer -- allow

    # Neither header present -> a non-browser (API-key/curl/HomeAssistant) caller. Allow.
    return None


@app.after_request
def set_security_headers(response):
    """Add security headers to every response."""
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Neutralize the server banner's version disclosure (cheroot sends "Cheroot/X.Y.Z", werkzeug sends
    # "Werkzeug/x Python/y") -- aids targeted CVE matching. Uniform for both server paths; quiet by default.
    response.headers["Server"] = "generatorpi"
    # Strict CSP for a fully self-contained page: no external requests at all.
    # default-src 'none' denies everything by default; we then re-allow ONLY inline
    # styles/scripts (the whole UI is inline), same-origin XHR/fetch (connect-src),
    # and data: images (inline SVG needs none, but data: is harmless + future-proof).
    # base-uri/form-action 'none' remove two injection footguns. Matches the design.
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "worker-src 'self'; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        "base-uri 'none'; "
        "form-action 'none'; "
        # frame-ancestors has NO default-src fallback, so it must be set explicitly.
        # 'none' forbids the page being framed anywhere -- the CSP-level equivalent of
        # X-Frame-Options: DENY (which older browsers still honor), closing clickjacking.
        "frame-ancestors 'none'"
    )
    if CONFIG["SSL_ENABLED"]:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


@app.after_request
def _access_audit_log(response):
    """Access-audit log line, written AFTER the handler so it carries the response
    STATUS code: "<caller>@<ip> -> <METHOD> <path> <status>".

    Emitted for every AUTHENTICATED request (g.auth_method is set by auth_required on
    both the API-key and basic-auth success paths). Unauthenticated failures (401 login
    prompt, 429 lockout) are already logged as warnings inside auth_required, so we skip
    them here to avoid a duplicate line. Method + path ONLY -- never request.full_path /
    query_string, which can contain the API key.

    The status drives BOTH the severity AND whether a routine line is recorded at all:
      * 5xx  -> ERROR   (always recorded)
      * 4xx  -> WARNING (always recorded -- failed/denied requests always stand out)
      * 2xx/3xx -> INFO if the server-global "record routine HTTP" setting is ON, else DEBUG.
    That setting is OFF by default (roadmap #99): the live UI polls a few read-only endpoints
    every few seconds, so recording every routine 2xx/3xx access line floods the log -- burying
    real events and needlessly churning the Pi's SD card. Demoting them to DEBUG keeps the log
    readable and cheap while ALWAYS preserving real events (logged by their handlers), mutations'
    own audit lines, and every 4xx/5xx. Flip the LOG VIEWER toggle to record routine traffic too.
    caller_identity() reads g.auth_method (not the spoofable Authorization header), so a keyed
    caller can't forge the audit identity. store.record_routine_http() is an in-memory cached
    read, so this per-request hook never touches the DB."""
    if getattr(g, "auth_method", None):
        status = response.status_code
        line = (
            f"{caller_identity()}@{request.remote_addr} -> "
            f"{request.method} {request.path} {status}"
        )
        if status >= 500:
            log.error(line)
        elif status >= 400:
            log.warning(line)
        elif store.record_routine_http():
            log.info(line)     # routine 2xx/3xx, recording ON -> keep it in the log
        else:
            log.debug(line)    # routine 2xx/3xx, recording OFF (default) -> not written at INFO
    return response



# ============================================================================
# BLUEPRINT REGISTRATION
# ============================================================================
# Imported LAST (after `app` exists) so the one-way app -> routes edge holds. Each blueprint pulls
# its services + auth from the owning submodules; none imports this module. Registration order is
# cosmetic (URL rules are disjoint). The endpoints become <bp>.<view> (e.g. core.index) internally;
# the app uses no url_for (the UI is one inline template), so nothing depends on the bare names.
from .routes.core import bp as core_bp
from .routes.update import bp as update_bp
from .routes.fuel import bp as fuel_bp
from .routes.push import bp as push_bp

app.register_blueprint(core_bp)
app.register_blueprint(update_bp)
app.register_blueprint(fuel_bp)
app.register_blueprint(push_bp)
