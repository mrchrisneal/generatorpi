# test_gen_manifest.py -- the release manifest generator (tools/gen-manifest.py) is a standalone
# release tool (NOT part of the genpi package), so it's loaded by path. These lock in the per-release
# update-constraint contract the in-app updater reads: incompatible_versions, an APPEND-ONLY map of
# { version -> reason } naming the releases that must be installed manually (the gate) and why. (The
# tool isn't under --cov=genpi; this guards its output contract regardless.)
import importlib.util
from pathlib import Path

import pytest

_GM_PATH = Path(__file__).resolve().parent.parent / "tools" / "gen-manifest.py"


@pytest.fixture
def gm():
    """Load tools/gen-manifest.py fresh per test (its name has a hyphen, so it can't be imported
    normally). Fresh each time so a test mutating its module-level release knobs can't leak."""
    spec = importlib.util.spec_from_file_location("gen_manifest_under_test", _GM_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_manifest_declares_incompatible_versions_map(gm):
    m = gm.build_manifest()
    # The key is ALWAYS emitted so every committed manifest carries the contract explicitly, as a
    # { version -> reason } MAP: keys are the gates, values the guidance shown in the IMPORTANT box.
    assert "incompatible_versions" in m
    assert isinstance(m["incompatible_versions"], dict)
    # v1.4.0 (the package/entrypoint restructure) and v1.5.0 (the full monolith->package split) are
    # both manual-install-only gates -- neither is applied by the in-app updater.
    assert "1.4.0" in m["incompatible_versions"]
    assert "1.5.0" in m["incompatible_versions"]
    # Every gate carries a non-empty reason string (the per-version IMPORTANT-box guidance).
    for ver, reason in m["incompatible_versions"].items():
        assert isinstance(reason, str) and reason.strip(), f"gate {ver} has no reason text"


def test_incompatible_versions_map_flows_into_the_manifest(gm):
    # The append-only { version -> reason } map is reflected verbatim so the in-app updater can refuse a
    # web-jump across any gate and show THAT version's specific reason.
    gm.INCOMPATIBLE_VERSIONS = {"1.4.0": "systemd entrypoint changed.", "2.0.0": "big rewrite."}
    m = gm.build_manifest()
    assert m["incompatible_versions"] == {"1.4.0": "systemd entrypoint changed.", "2.0.0": "big rewrite."}


@pytest.mark.parametrize("bad_key", ["v1.4.0", "1.4", "garbage", "1.4.0.1"])
def test_malformed_gate_key_raises_at_generation_time(gm, bad_key):
    # A 'v'-prefixed / short / garbage gate KEY would parse to a tiny tuple in the updater and silently
    # NEVER block (fail-OPEN), so the generator must reject it LOUDLY -- a broken build beats shipping an
    # inert gate that lets an old install web-jump across it and brick.
    gm.INCOMPATIBLE_VERSIONS = {"1.4.0": "ok", bad_key: "bad reason"}
    with pytest.raises(ValueError, match="malformed"):
        gm.build_manifest()


def test_manifest_covers_every_package_asset(gm):
    # Roadmap #59 Stage 10: the in-app updater downloads + hash-verifies + swaps EXACTLY the manifest's
    # file list, so any code/asset file under genpi/ that is absent from the manifest would be silently
    # left stale (or missing) on an update -- a broken package after a self-update. gen-manifest globs
    # the package for this reason; this is the belt-and-suspenders that proves the on-disk package and
    # the generated manifest never drift (catches e.g. a new submodule the glob logic somehow skipped).
    root = _GM_PATH.resolve().parent.parent
    exts = {".py", ".css", ".js", ".html"}
    on_disk = {
        str(p.relative_to(root))
        for p in (root / "genpi").rglob("*")
        if p.is_file() and p.suffix in exts and "__pycache__" not in p.parts
    }
    assert on_disk, "expected to find package assets under genpi/"
    # manifest["files"] is a list of {path, sha256, bytes} entries -- pull the paths.
    manifest_files = {e["path"] for e in gm.build_manifest()["files"]}
    missing = on_disk - manifest_files
    assert not missing, f"package assets absent from the generated manifest: {sorted(missing)}"
