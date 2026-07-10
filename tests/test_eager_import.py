# test_eager_import.py -- the Stage-10 eager-import guarantee (roadmap #59). The package promises
# that EVERY application submodule is imported at startup (no lazy imports) so all code is resident in
# RAM before the first request on the single-core Pi. genpi._assert_eager_imports() makes that promise
# verifiable; these tests prove the guard actually fires (a missing submodule / a broken UI template
# both raise) rather than being a no-op, and that _EXPECTED matches the modules the package really loads.
import sys

import pytest


class TestEagerImportGuard:
    def test_all_expected_modules_resident(self, module):
        # Happy path: after `import genpi`, every _EXPECTED submodule is in sys.modules and the guard
        # returns the resident count (== len(_EXPECTED)).
        for name in module._EXPECTED:
            assert f"genpi.{name}" in sys.modules, f"{name} not resident"
        assert module._assert_eager_imports() == len(module._EXPECTED)

    def test_expected_has_no_duplicates(self, module):
        # A typo/dupe in _EXPECTED would inflate the count and weaken the guard -- lock it down.
        assert len(module._EXPECTED) == len(set(module._EXPECTED))

    def test_expected_names_are_real_submodules(self, module):
        # Every name in _EXPECTED must resolve to an actually-imported genpi submodule (guards a stale
        # name left behind after a rename), so the guard checks real modules, not phantoms.
        for name in module._EXPECTED:
            assert f"genpi.{name}" in sys.modules

    def test_missing_submodule_raises_importerror(self, module, monkeypatch):
        # Drop a submodule from sys.modules -> the guard must FAIL FAST (this is the whole point: a
        # half-loaded package can never serve). monkeypatch restores sys.modules afterwards.
        monkeypatch.delitem(sys.modules, "genpi.config")
        with pytest.raises(ImportError, match="eager-import incomplete"):
            module._assert_eager_imports()

    def test_missing_submodule_names_the_gap(self, module, monkeypatch):
        # The raised error must name the missing module so a broken build is diagnosable.
        monkeypatch.delitem(sys.modules, "genpi.updater")
        with pytest.raises(ImportError, match="updater"):
            module._assert_eager_imports()

    def test_ui_sentinel_empty_template_raises(self, module, monkeypatch):
        # An empty assembled template (a frontend asset failed to load) must raise -- not serve a
        # broken page. All submodules are still resident, so this exercises the UI-sentinel branch.
        monkeypatch.setattr(module, "HTML_TEMPLATE", "")
        with pytest.raises(RuntimeError, match="UI template failed to assemble"):
            module._assert_eager_imports()

    def test_ui_sentinel_missing_markers_raises(self, module, monkeypatch):
        # A non-empty template that lost its inline <style>/<script> markers (e.g. external assets
        # crept in) also fails the sentinel -- guards the strict-CSP inline-only invariant at startup.
        monkeypatch.setattr(module, "HTML_TEMPLATE", "<html>no inline blocks</html>")
        with pytest.raises(RuntimeError, match="UI template failed to assemble"):
            module._assert_eager_imports()
