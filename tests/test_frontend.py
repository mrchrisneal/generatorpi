# test_frontend.py -- guards the roadmap-#59 (Stage 2) frontend extraction: the inline UI's CSS,
# vanilla JS, body shell, and push service worker now live as editable source files under
# genpi/frontend/ and are assembled at import by genpi/ui.py. The load-bearing invariant is that
# NOTHING about how the page is SERVED changed: it must still be 100% inline (no external CSS/JS/
# font/CDN assets) so the strict CSP (default-src 'none') keeps holding, and the Jinja {% raw %}
# wrappers must stay in place so the CSS/JS braces are never mangled by the template engine.
import genpi as _g
from pathlib import Path

import pytest


API_KEY = "frontend-test-key"


@pytest.fixture(autouse=True)
def _key(module):
    module.CONFIG["API_KEY"] = API_KEY


def _page(client):
    """The server-rendered homepage HTML (authorized)."""
    return client.get(f"/?key={API_KEY}").get_data(as_text=True)


class TestInlineOnly:
    def test_page_is_served_fully_inline(self, client):
        # The whole UI is inline: an inline <style> and inline <script>, and NO externally
        # loaded asset -- each of which would require relaxing the strict CSP.
        page = _page(client)
        assert "<style>" in page and "</style>" in page      # inline CSS present
        assert "<script>" in page and "</script>" in page    # inline JS present
        assert "<script src=" not in page                    # no external script
        assert '<link rel="stylesheet"' not in page          # no external stylesheet
        assert 'href="data:,"' in page                       # the only <link> is the inline data: favicon

    def test_no_unrendered_jinja_leaks(self, client):
        # If the {% raw %} wrappers were lost, Jinja would choke on the CSS/JS braces or leak
        # template tags into the page. A correctly rendered page has ZERO Jinja syntax left.
        page = _page(client)
        assert "{% raw %}" not in page and "{% endraw %}" not in page
        assert "{%" not in page          # no leftover statement tags
        assert "{{" not in page          # no unrendered interpolations

    def test_server_rendered_state_is_present(self, client, module):
        # The body shell (outside {% raw %}) server-renders the initial RUNNING/STOPPED state and
        # the version, so the page is correct before JS runs / with JS off. Confirm that survived
        # the move out to genpi/frontend/body.html.
        with module.state_lock:
            module.generator_state["running"] = False
        page = _page(client)
        assert "STOPPED" in page
        assert f"v{module.APP_VERSION}" in page


class TestFrontendAssets:
    def _frontend_dir(self):
        return Path(_g.__file__).resolve().parent / "frontend"

    def test_all_assets_present_and_nonempty(self):
        # Every frontend source file must exist + be non-empty: they ship as code (gen-manifest
        # globs them) and are read at import with NO fallback, so a missing one bricks startup.
        fe = self._frontend_dir()
        for name in ("style.css", "app.js", "body.html", "sw.js"):
            p = fe / name
            assert p.is_file(), f"missing frontend asset: {name}"
            assert p.read_text(encoding="utf-8").strip(), f"empty frontend asset: {name}"

    def test_missing_asset_raises_fast(self, module):
        # The loader deliberately has no fallback -- an absent asset raises immediately (fail fast
        # on startup) rather than silently serving a broken page.
        with pytest.raises(OSError):
            module.ui._asset("does-not-exist.css")

    def test_inline_wrappers_are_intact(self, module):
        # The {% raw %} wrappers around the inline <style>/<script> are what stop Jinja from
        # parsing CSS/JS braces as template tags. Guard that ui.py still emits them.
        assert "{% raw %}<style>" in module.HTML_TEMPLATE_HEAD
        assert "</style>{% endraw %}" in module.HTML_TEMPLATE_HEAD
        assert module.HTML_TEMPLATE_SCRIPT.startswith("{% raw %}<script>")
        assert module.HTML_TEMPLATE_SCRIPT.endswith("</script>{% endraw %}")

    def test_service_worker_sourced_from_frontend_file(self, module):
        # /sw.js content is now genpi/frontend/sw.js, re-exported via genpi/ui.py.
        assert module.SERVICE_WORKER_JS is module.ui.SERVICE_WORKER_JS
        assert "showNotification" in module.SERVICE_WORKER_JS
