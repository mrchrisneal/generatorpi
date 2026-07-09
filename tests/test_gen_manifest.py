# test_gen_manifest.py -- the release manifest generator (tools/gen-manifest.py) is a standalone
# release tool (NOT part of the genpi package), so it's loaded by path. These lock in the two
# per-release update-constraint keys the in-app updater reads: cli_only_versions (the gate list) +
# important_notes. (The tool isn't under --cov=genpi; this guards its output contract regardless.)
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


def test_manifest_declares_update_constraint_keys(gm):
    m = gm.build_manifest()
    # Both keys are ALWAYS emitted so every committed manifest carries the contract explicitly.
    assert "cli_only_versions" in m
    assert "important_notes" in m
    assert isinstance(m["cli_only_versions"], list)
    # v1.4.0 (the package/entrypoint restructure) is the known CLI-only gate.
    assert "1.4.0" in m["cli_only_versions"]
    assert m["important_notes"] == []


def test_gate_list_and_notes_flow_into_the_manifest(gm):
    # The append-only gate list + operator notes are reflected verbatim so the in-app updater can
    # refuse a web-jump across any gate and show the guidance.
    gm.CLI_ONLY_VERSIONS = ["1.4.0", "2.0.0"]
    gm.IMPORTANT_NOTES = ["Run ./setup.sh reinstall."]
    m = gm.build_manifest()
    assert m["cli_only_versions"] == ["1.4.0", "2.0.0"]
    assert m["important_notes"] == ["Run ./setup.sh reinstall."]


@pytest.mark.parametrize("bad", [["v1.4.0"], ["1.4"], ["garbage"], ["1.4.0", "nope"], ["1.4.0.1"]])
def test_malformed_gate_raises_at_generation_time(gm, bad):
    # A 'v'-prefixed / short / garbage gate would parse to a tiny tuple in the updater and silently
    # NEVER block (fail-OPEN), so the generator must reject it LOUDLY -- a broken build beats shipping
    # an inert gate that lets an old install web-jump across it and brick.
    gm.CLI_ONLY_VERSIONS = bad
    with pytest.raises(ValueError, match="malformed"):
        gm.build_manifest()
