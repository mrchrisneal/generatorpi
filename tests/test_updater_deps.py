# test_updater_deps.py -- the manifest-declared dependency check + the end-of-stage warning/error
# summary added to the self-updater (v1.3.3).
#
# The manifest now carries a `dependencies` list (module import-name, apt package, feature,
# required). During update Stage 1 the worker checks each against THIS device via
# check_manifest_dependencies() -- importlib.util.find_spec, which resolves a module WITHOUT
# importing it (no side effects) -- and, if any are missing, logs them + a copy-able apt one-liner
# (dependency_install_command) so the operator can install them BEFORE applying. The updater NEVER
# installs them itself. Warnings/errors are tallied per stage (_update_warn/_update_err) and
# summarized as colored last-lines of the stage (_stage_summary). The full worker wiring is covered
# in test_run_update_flow.py; this file unit-tests the pieces.
import pytest


class TestCheckManifestDependencies:
    def test_all_present_returns_empty(self, module):
        # Modules that clearly exist in the interpreter -> nothing missing.
        manifest = {"dependencies": [
            {"module": "json", "apt": "python3-x", "required": True, "feature": "f"},
            {"module": "os", "apt": "python3-y", "required": False, "feature": "g"},
        ]}
        assert module.check_manifest_dependencies(manifest) == []

    def test_missing_module_is_returned(self, module):
        manifest = {"dependencies": [
            {"module": "os", "apt": "python3-os", "required": True, "feature": "f"},
            {"module": "totally_absent_module_xyz", "apt": "python3-absent",
             "required": False, "feature": "Web Push"},
        ]}
        missing = module.check_manifest_dependencies(manifest)
        assert [d["module"] for d in missing] == ["totally_absent_module_xyz"]

    def test_no_dependencies_key_returns_empty(self, module):
        # An older manifest (pre-1.3.3) has no `dependencies` -> nothing to check, no crash.
        assert module.check_manifest_dependencies({"version": "1.0.0", "files": []}) == []

    def test_entry_without_module_is_skipped(self, module):
        # A malformed entry missing "module" is skipped, not treated as missing.
        assert module.check_manifest_dependencies({"dependencies": [{"apt": "python3-x"}]}) == []

    def test_dotted_module_name_is_skipped_no_parent_import(self, module):
        # Security: a DOTTED name would make find_spec import the parent package ("os" here),
        # executing its __init__. Only top-level identifiers are checked, so a dotted name (even a
        # real one like "os.path") is skipped -- never imported -- rather than probed.
        manifest = {"dependencies": [{"module": "os.path", "apt": "python3-x",
                                      "required": False, "feature": "f"}]}
        assert module.check_manifest_dependencies(manifest) == []

    def test_find_spec_exception_treated_as_missing(self, module, monkeypatch):
        # A broken/partial install can make find_spec RAISE (e.g. a shadowed namespace package);
        # that must be treated as MISSING (fail-safe) and never crash the update.
        def boom(name):
            raise ValueError("broken package metadata")
        monkeypatch.setattr(module.importlib.util, "find_spec", boom)
        manifest = {"dependencies": [{"module": "anything", "apt": "python3-x",
                                      "required": False, "feature": "f"}]}
        assert len(module.check_manifest_dependencies(manifest)) == 1


class TestDependencyInstallCommand:
    def test_builds_sorted_deduped_apt_oneliner(self, module):
        missing = [
            {"apt": "python3-requests"},
            {"apt": "python3-py-vapid"},
            {"apt": "python3-requests"},   # duplicate collapses
        ]
        assert module.dependency_install_command(missing) == \
            "sudo apt install -y python3-py-vapid python3-requests"

    def test_empty_when_nothing_missing(self, module):
        assert module.dependency_install_command([]) == ""

    def test_ignores_entries_without_apt(self, module):
        assert module.dependency_install_command([{"feature": "f"}]) == ""

    def test_rejects_shell_metacharacters_in_apt_name(self, module):
        # Defense in depth: a hostile/garbled manifest `apt` value with shell metacharacters must
        # NOT reach the shown one-liner (the app never runs it, but a user might paste it). Only
        # well-formed lowercase Debian package names survive.
        missing = [
            {"apt": "python3-requests"},
            {"apt": "python3-foo; rm -rf ~"},   # injection attempt -> dropped
            {"apt": "evil name with spaces"},   # -> dropped
            {"apt": "UPPER_case"},              # not a valid debian package name -> dropped
        ]
        assert module.dependency_install_command(missing) == "sudo apt install -y python3-requests"


class TestStageTallyAndSummary:
    @pytest.fixture(autouse=True)
    def _fresh_counts(self, module):
        # Reset the per-stage tally + log the helpers mutate (a module global not reset by conftest).
        module._update_state.update(
            stage=1, log=[],
            counts={"stage1": {"warn": 0, "err": 0}, "stage2": {"warn": 0, "err": 0}})
        yield

    def test_update_warn_and_err_tally_current_stage_and_log(self, module):
        module._update_warn("  w1")
        module._update_warn("  w2")
        module._update_err("  e1")
        c = module._update_state["counts"]["stage1"]
        assert (c["warn"], c["err"]) == (2, 1)
        # The lines are also appended to the terminal log.
        assert module._update_state["log"][-3:] == ["  w1", "  w2", "  e1"]

    def test_tally_follows_the_current_stage(self, module):
        module._update_warn("  s1")             # stage 1
        module._update_state["stage"] = 2
        module._update_err("  s2")              # stage 2
        assert module._update_state["counts"]["stage1"] == {"warn": 1, "err": 0}
        assert module._update_state["counts"]["stage2"] == {"warn": 0, "err": 1}

    def test_summary_emits_colored_lines_only_when_nonzero(self, module):
        module._update_state["counts"]["stage1"] = {"warn": 2, "err": 1}
        module._stage_summary(1)
        joined = "\n".join(module._update_state["log"])
        # [WARNING]/[ERROR] tags are what the terminal colours yellow/red. Plural vs singular.
        assert "[WARNING] Stage 1: 2 warnings encountered" in joined
        assert "[ERROR] Stage 1: 1 error encountered" in joined

    def test_summary_is_silent_when_clean(self, module):
        module._stage_summary(1)                 # all counts zero
        assert module._update_state["log"] == []  # nothing appended -> a clean stage adds no lines
