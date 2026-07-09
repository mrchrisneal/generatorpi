# genpi/ui.py -- Inline UI template assembly for GeneratorPi (roadmap #59, Stage 2). LAYER 1:
# depends on nothing but the stdlib. Imported early by genpi/__init__.py so the page template is
# built once at startup.
#
# The control panel is ONE self-contained page: inline <style> + inline vanilla <script>, no
# external assets, no framework, no build step. Its CSS, JS, body shell, and the push service
# worker now live as EDITABLE source files under genpi/frontend/ (shipped as code -- gen-manifest
# globs *.css/*.js/*.html). This module reads them at import and assembles the SAME template
# strings the old single file built inline, BYTE-FOR-BYTE, so the strict CSP (default-src 'none';
# style-src/script-src 'self' 'unsafe-inline') is UNCHANGED -- everything is still served inline.
#
# read_text() has NO fallback on purpose: a missing/unreadable asset raises at import, so a
# packaging slip fails FAST on startup rather than serving a broken page. A startup sentinel
# (bottom) additionally asserts the assembled page carries its inline <style> and <script>.
#
# Copyright (C) 2026 Chris Neal <https://neal.media> and Alex Neal <https://neal.tools>
# SPDX-License-Identifier: AGPL-3.0-or-later
from pathlib import Path

# Directory of editable frontend source files (CSS / JS / body shell / service worker).
_FRONTEND = Path(__file__).resolve().parent / "frontend"


def _asset(name):
    """Read a frontend asset at import time. No fallback: a missing/unreadable file raises
    immediately so a packaging slip fails FAST rather than serving a broken page."""
    return (_FRONTEND / name).read_text(encoding="utf-8")


# The page parts + the service worker, loaded from disk (all CSP-inline sources).
_CSS = _asset("style.css")
_JS = _asset("app.js")
_BODY = _asset("body.html")
SERVICE_WORKER_JS = _asset("sw.js")  # served as its own /sw.js resource (no auth, no secrets)

# Document head: doctype/meta/title/icon, then the OPEN of the inline <style>. Jinja {% raw %}
# wraps the CSS + JS so their braces / JS template literals are never parsed as Jinja tags. This
# small glue is a literal; the CSS/JS/body CONTENT lives in genpi/frontend/*.
_HEAD_OPEN = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>GeneratorPi</title>
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="dark">
<!-- Empty inline icon: suppresses the browser's default /favicon.ico request (which
     would 404 -- static serving is disabled) without any external asset. -->
<link rel="icon" href="data:,">
{% raw %}<style>
"""

# Assemble the template strings BYTE-IDENTICALLY to the historic single-file layout:
#   HEAD   = head-open + CSS + </style>{% endraw %}</head>
#   SCRIPT = {% raw %}<script> + JS + </script>{% endraw %}
#   BODY   = body shell + SCRIPT      (the shell server-renders the initial RUNNING/STOPPED state)
#   PAGE   = HEAD + <body> + BODY + </body></html>
# style.css / app.js carry a POSIX trailing newline, absorbed here so the output is unchanged.
HTML_TEMPLATE_HEAD = _HEAD_OPEN + _CSS + "</style>{% endraw %}\n</head>"
HTML_TEMPLATE_SCRIPT = "{% raw %}<script>\n" + _JS + "</script>{% endraw %}"
HTML_TEMPLATE_BODY = _BODY + HTML_TEMPLATE_SCRIPT
HTML_TEMPLATE = HTML_TEMPLATE_HEAD + "\n<body>\n" + HTML_TEMPLATE_BODY + "\n</body>\n</html>\n"

# Startup sentinel: the assembled page must be non-empty and carry BOTH an inline <style> and an
# inline <script> -- the strict CSP relies on everything being inline. Fails fast on an asset slip.
assert HTML_TEMPLATE and "<style>" in HTML_TEMPLATE and "<script>" in HTML_TEMPLATE, \
    "ui.py: assembled HTML_TEMPLATE lost its inline <style>/<script> -- frontend asset problem"
