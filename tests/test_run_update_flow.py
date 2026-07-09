# test_run_update_flow.py -- end-to-end orchestration of the self-updater's background
# worker `_run_update()` plus the surrounding decision/service/log helpers that the
# lower-level test_updater.py doesn't drive as a whole flow. Every network call, file
# swap, restart, and subprocess launch is mocked, so nothing binds, downloads, execs,
# or touches the real project tree. These lock in the STAGE-1 (download/verify/backup) ->
# decision gate -> STAGE-2 (systemd bootstrap OR in-process re-exec) control flow, and the
# error path that rolls back a partially-applied same-process swap.
import errno
import json
import hashlib
import zipfile
from unittest import mock

import pytest


API_KEY = "run-update-test-key"


def _sha(b):
    return hashlib.sha256(b).hexdigest()


@pytest.fixture(autouse=True)
def _key(module):
    """The update endpoints exercised here are @auth_required."""
    module.CONFIG["API_KEY"] = API_KEY


@pytest.fixture(autouse=True)
def _reset_update_state(module):
    """`_update_state` is a module global not reset by conftest; _run_update mutates it.
    Restore it (and the decision gate) after every test so nothing leaks between tests."""
    yield
    with module._update_lock:
        module._update_state.update(phase="idle", message="", progress=0.0, error=None,
                                    version=None, systemd=None, log=[], decide=None)
    module._update_decision_event.clear()
    module._update_decision_choice["choice"] = None


def _q(path):
    sep = "&" if "?" in path else "?"
    return f"{path}{sep}key={API_KEY}"


def _prime_state(module):
    """Put the updater into the state api_update_start would leave it in before the worker runs."""
    with module._update_lock:
        module._update_state.update(phase="checking", message="", progress=0.0, error=None,
                                    version=None, systemd=None, log=[], decide=None)


def _wire_stage1(module, monkeypatch, tmp_path, manifest, live_files):
    """Stub STAGE 1 (network + preflight + download/verify + backup) so _run_update reaches the
    decision gate deterministically. `live_files` is {relpath: bytes} written under a tmp
    SCRIPT_DIR so the non-systemd post-swap re-hash can read them. Returns the backup zip path."""
    monkeypatch.setattr(module, "SCRIPT_DIR", tmp_path)
    backups = tmp_path / "backups"
    backups.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(module, "_BACKUP_DIR", backups)
    monkeypatch.setattr(module, "_UPDATE_RESULT", backups / "last_update.json")
    monkeypatch.setattr(module, "_UPDATE_LOG", backups / "last_update.log")
    monkeypatch.setattr(module, "_UPDATE_STAGING", tmp_path / ".update_staging")
    for rel, data in live_files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    # The ONLY network call the worker itself makes is the manifest fetch.
    monkeypatch.setattr(module, "_http_get_bytes",
                        lambda url, **k: json.dumps(manifest).encode("utf-8"))
    monkeypatch.setattr(module, "_preflight_check", lambda *a, **k: None)
    staging = tmp_path / "stg"
    staging.mkdir(exist_ok=True)
    monkeypatch.setattr(module, "_download_and_verify", lambda m, **k: staging)
    zpath = backups / "backup-test.zip"
    zpath.write_text("zip")
    monkeypatch.setattr(module, "_make_backup", lambda m, **k: (zpath, []))
    return zpath


class TestRunUpdateDependencies:
    def test_stage1_reports_missing_dependencies_with_install_command(
        self, module, monkeypatch, tmp_path
    ):
        # A manifest that DECLARES a dependency not importable on this device: Stage 1 lists each
        # missing one, tallies a warning (optional) / error (required), stashes a copy-able apt
        # one-liner, and the end-of-stage-1 summary emits colored count lines. REVERT at the gate so
        # nothing is applied -- the updater must NEVER install anything itself.
        manifest = {"version": "2.0.0",
                    "files": [{"path": "a.py", "sha256": _sha(b"x"), "bytes": 1}],
                    "dependencies": [
                        {"module": "os", "apt": "python3-os", "required": True, "feature": "core"},
                        {"module": "totally_absent_xyz", "apt": "python3-absent-opt",
                         "required": False, "feature": "Web Push"},
                        {"module": "also_absent_req", "apt": "python3-absent-req",
                         "required": True, "feature": "critical"},
                    ]}
        _wire_stage1(module, monkeypatch, tmp_path, manifest, {"a.py": b"x"})
        monkeypatch.setattr(module, "_await_decision", lambda *a, **k: "revert")  # stop at the gate
        _prime_state(module)

        module._run_update()

        # The two ABSENT modules are captured (present "os" is not); with a deterministic command.
        apts = {d["apt"] for d in module._update_state["missing_deps"]}
        assert apts == {"python3-absent-opt", "python3-absent-req"}
        assert module._update_state["deps_install_cmd"] == \
            "sudo apt install -y python3-absent-opt python3-absent-req"
        log = "\n".join(module._update_state["log"])
        assert "[CHECKING DEPENDENCIES]" in log
        # Missing deps read as coloured WARNING:/ERROR: lines (optional -> warning, required -> error).
        assert "WARNING: Missing (optional) dependency: python3-absent-opt" in log
        assert "ERROR: Missing (required) dependency: python3-absent-req" in log
        # End-of-stage-1 summary: 1 optional-missing warning + 1 required-missing error.
        assert "[WARNING] Stage 1: 1 warning encountered" in log
        assert "[ERROR] Stage 1: 1 error encountered" in log

    def test_stage1_all_dependencies_present_is_clean(
        self, module, monkeypatch, tmp_path
    ):
        # When every declared dependency is importable, Stage 1 logs the clean "ok" line and adds
        # NO warning/error summary lines (a clean stage stays quiet).
        manifest = {"version": "2.0.0",
                    "files": [{"path": "a.py", "sha256": _sha(b"x"), "bytes": 1}],
                    "dependencies": [
                        {"module": "os", "apt": "python3-os", "required": True, "feature": "core"},
                        {"module": "json", "apt": "python3-json", "required": False, "feature": "x"},
                    ]}
        _wire_stage1(module, monkeypatch, tmp_path, manifest, {"a.py": b"x"})
        monkeypatch.setattr(module, "_await_decision", lambda *a, **k: "revert")
        _prime_state(module)

        module._run_update()

        assert module._update_state["missing_deps"] == []
        log = "\n".join(module._update_state["log"])
        assert "all declared dependencies present" in log
        assert "[WARNING] Stage 1" not in log and "[ERROR] Stage 1" not in log


class TestManifestForwardCompat:
    def test_unknown_manifest_keys_and_fields_are_ignored(
        self, module, monkeypatch, tmp_path
    ):
        # FORWARD-COMPAT CONTRACT: a manifest may grow NEW top-level keys and NEW fields inside its
        # file / dependency entries in future releases. An EXISTING updater must read only what it
        # understands (all via .get()) and silently ignore the rest -- never fail. This locks that
        # in so a future refactor can't slip in strict schema validation that would break old
        # installs. Prove a manifest stuffed with unknown keys still runs Stage 1 to the gate and
        # computes the dependency check correctly from the fields it knows.
        manifest = {
            "version": "2.0.0",
            "min_updater_version": "99.0",                 # unknown top-level key (future)
            "signature": {"alg": "ed25519", "sig": "…"},   # unknown top-level dict (future)
            "files": [{"path": "a.py", "sha256": _sha(b"x"), "bytes": 1,
                       "mode": "0644", "note": "future per-file field"}],   # unknown file fields
            "dependencies": [
                {"module": "os", "apt": "python3-os", "required": True, "feature": "core",
                 "min_version": "1.0", "extra": {"nested": True}},          # unknown dep fields
                {"module": "totally_absent_fc", "apt": "python3-absent-fc",
                 "required": False, "feature": "x", "future": [1, 2, 3]},
            ],
        }
        _wire_stage1(module, monkeypatch, tmp_path, manifest, {"a.py": b"x"})
        monkeypatch.setattr(module, "_await_decision", lambda *a, **k: "revert")
        _prime_state(module)

        module._run_update()                               # must NOT raise on the unknown keys/fields

        # Reached the go/no-go and reverted cleanly, having computed deps from the KNOWN fields only.
        assert module._update_state["phase"] == "failed"   # canceled at the gate (nothing applied)
        assert {d["apt"] for d in module._update_state["missing_deps"]} == {"python3-absent-fc"}


class TestCliOnlyGate:
    """cli_only_versions: the manifest lists versions installable ONLY via the CLI. The web updater
    REFUSES the latest release when ANY listed gate G satisfies installed < G <= latest -- a manual gate
    sits between the device and the target -- so a very old install can't web-jump across it and fail. It
    logs an [ERROR] pointing to the IMPORTANT box, exposes the note(s) via _update_state["important_notes"],
    and parks with the apply button disabled, WITHOUT downloading or touching anything."""

    def _run(self, module, monkeypatch, tmp_path, installed, latest, gates, notes=None, seen=None):
        monkeypatch.setattr(module, "APP_VERSION", installed)   # deterministic "installed" version
        manifest = {"version": latest,
                    "files": [{"path": "a.py", "sha256": _sha(b"x"), "bytes": 1}],
                    "cli_only_versions": gates}
        if notes is not None:
            manifest["important_notes"] = notes
        _wire_stage1(module, monkeypatch, tmp_path, manifest, {"a.py": b"x"})
        def _await(msg, allow_proceed, proceed_label="PROCEED", proceed_disabled=False):
            if seen is not None:
                seen.update(allow_proceed=allow_proceed, proceed_label=proceed_label,
                            proceed_disabled=proceed_disabled)
            return "revert"
        monkeypatch.setattr(module, "_await_decision", _await)
        _prime_state(module)
        module._run_update()

    def test_gate_between_installed_and_latest_blocks(self, module, monkeypatch, tmp_path):
        seen = {}
        self._run(module, monkeypatch, tmp_path, installed="1.3.4", latest="1.6.0",
                  gates=["1.4.0"], notes=["Run ./setup.sh reinstall.", "Then restart the app."], seen=seen)
        st = module._update_state
        assert st["installable"] is False
        # Notes go to the BOX (this state field), NOT dumped into the terminal log.
        assert st["important_notes"] == ["Run ./setup.sh reinstall.", "Then restart the app."]
        log = "\n".join(st["log"])
        assert "[ERROR] v1.6.0 cannot be installed by the web updater" in log
        assert "manual-install-only version (v1.4.0)" in log     # names the blocking gate
        assert "between your v1.3.4 and v1.6.0" in log
        assert "See the IMPORTANT note below" in log             # log only POINTS to the box
        assert "Then restart the app." not in log                # note text lives in the box, not the log
        assert "[DOWNLOADING]" not in log and "[STAGED]" not in log   # refused before touching anything
        assert st["phase"] == "failed"
        assert seen["proceed_disabled"] is True and seen["allow_proceed"] is False
        assert seen["proceed_label"] == "UPDATE"

    def test_installed_at_the_gate_is_allowed(self, module, monkeypatch, tmp_path):
        # Already crossed the gate (installed == gate) -> web-update to latest is allowed (not < G).
        seen = {}
        self._run(module, monkeypatch, tmp_path, installed="1.4.0", latest="1.6.0",
                  gates=["1.4.0"], seen=seen)
        st = module._update_state
        assert st["installable"] is True
        assert "cannot be installed by the web updater" not in "\n".join(st["log"])
        assert "[STAGED]" in "\n".join(st["log"])
        assert seen["allow_proceed"] is True and seen["proceed_disabled"] is False

    def test_gate_below_installed_does_not_block(self, module, monkeypatch, tmp_path):
        # A gate the user already passed (G < installed) never blocks.
        self._run(module, monkeypatch, tmp_path, installed="1.5.0", latest="1.6.0", gates=["1.4.0"])
        assert module._update_state["installable"] is True
        assert "[STAGED]" in "\n".join(module._update_state["log"])

    def test_latest_itself_is_a_gate_blocks_everyone_below(self, module, monkeypatch, tmp_path):
        # When the LATEST release is itself CLI-only (gate == latest), everyone below it is blocked.
        self._run(module, monkeypatch, tmp_path, installed="1.4.0", latest="1.5.0", gates=["1.5.0"])
        assert module._update_state["installable"] is False
        assert "[ERROR] v1.5.0 cannot be installed by the web updater" in \
            "\n".join(module._update_state["log"])

    def test_no_cli_only_versions_key_is_forward_compatible(self, module, monkeypatch, tmp_path):
        # Older/ordinary manifest with no cli_only_versions -> nothing gates -> applicable.
        monkeypatch.setattr(module, "APP_VERSION", "1.0.0")
        manifest = {"version": "2.0.0", "files": [{"path": "a.py", "sha256": _sha(b"x"), "bytes": 1}]}
        _wire_stage1(module, monkeypatch, tmp_path, manifest, {"a.py": b"x"})
        monkeypatch.setattr(module, "_await_decision", lambda *a, **k: "revert")
        _prime_state(module)

        module._run_update()

        assert module._update_state["installable"] is True
        assert module._update_state["important_notes"] == []
        assert "[STAGED]" in "\n".join(module._update_state["log"])

    def test_blocked_without_notes_leaves_notes_empty_for_case_b(self, module, monkeypatch, tmp_path):
        # Blocked but no important_notes -> list stays empty (UI renders the Case B fallback box). The
        # refusal still logs the [ERROR] + pointer, so it is never silent even without a note.
        self._run(module, monkeypatch, tmp_path, installed="1.3.0", latest="1.6.0", gates=["1.4.0"])
        assert module._update_state["important_notes"] == []
        log = "\n".join(module._update_state["log"])
        assert "[ERROR] v1.6.0 cannot be installed by the web updater" in log
        assert "See the IMPORTANT note below" in log

    def test_important_notes_string_is_normalized_to_list(self, module, monkeypatch, tmp_path):
        # important_notes MAY be a single string -> normalized + trimmed to a one-element list for the box.
        self._run(module, monkeypatch, tmp_path, installed="1.3.4", latest="1.6.0",
                  gates=["1.4.0"], notes="  Reinstall via setup.sh.  ")
        assert module._update_state["important_notes"] == ["Reinstall via setup.sh."]

    def test_cli_only_versions_as_single_string_is_accepted(self, module, monkeypatch, tmp_path):
        # cli_only_versions MAY be a bare string (one gate) -> normalized + applied.
        self._run(module, monkeypatch, tmp_path, installed="1.3.4", latest="1.6.0", gates="1.4.0")
        assert module._update_state["installable"] is False

    def test_v_prefixed_gate_still_blocks(self, module, monkeypatch, tmp_path):
        # A gate written in the 'v1.4.0' TAG form (the natural typo) must STILL gate: the updater strips
        # the leading 'v' before comparing, so it can't silently fail open (parse to (0,4,0) -> never block).
        self._run(module, monkeypatch, tmp_path, installed="1.3.4", latest="1.6.0", gates=["v1.4.0"])
        st = module._update_state
        assert st["installable"] is False
        assert "manual-install-only version (v1.4.0)" in "\n".join(st["log"])   # normalized: a single 'v'

    def test_multiple_in_range_gates_listed_ascending(self, module, monkeypatch, tmp_path):
        # Several gates between installed and latest -> all named in ascending version order.
        self._run(module, monkeypatch, tmp_path, installed="1.2.0", latest="2.0.0",
                  gates=["1.6.0", "1.4.0"])
        assert module._update_state["installable"] is False
        assert "manual-install-only version (v1.4.0, v1.6.0)" in \
            "\n".join(module._update_state["log"])


class TestAwaitDecisionProceedDisabled:
    def test_decide_dict_carries_proceed_disabled(self, module, monkeypatch):
        # _await_decision writes the decide dict (read by api_update_status -> the UI) BEFORE it blocks.
        # A not-installable park passes proceed_disabled=True so the UI shows the apply button greyed.
        captured = {}
        def fake_wait(timeout):
            captured["decide"] = dict(module._update_state["decide"])   # snapshot before we resolve
            return True                                                 # resolve instantly (no 10-min block)
        monkeypatch.setattr(module._update_decision_event, "wait", fake_wait)
        module._update_decision_choice["choice"] = "revert"

        out = module._await_decision("msg", allow_proceed=False,
                                     proceed_label="UPDATE", proceed_disabled=True)

        assert out == "revert"
        assert captured["decide"] == {"allow_proceed": False, "proceed_label": "UPDATE",
                                      "proceed_disabled": True}


class TestRunUpdateSystemd:
    def test_systemd_path_launches_bootstrap(self, module, monkeypatch, tmp_path):
        # A managed (systemd) deployment hands the swap+restart to a detached /tmp bootstrap.
        manifest = {"version": "2.0.0",
                    "files": [{"path": "a.py", "sha256": _sha(b"x"), "bytes": 1}]}
        _wire_stage1(module, monkeypatch, tmp_path, manifest, {"a.py": b"x"})
        monkeypatch.setattr(module, "_service_skip_reason", lambda: None)   # -> use the service
        monkeypatch.setattr(module, "_await_decision", lambda *a, **k: "proceed")
        monkeypatch.setattr(module, "_write_bootstrap_script",
                            lambda *a, **k: str(tmp_path / "boot.sh"))
        popen = mock.Mock()
        monkeypatch.setattr(module.subprocess, "Popen", popen)
        _prime_state(module)

        module._run_update()

        popen.assert_called_once()                        # bootstrap detached
        assert popen.call_args[0][0][0] == "bash"         # invoked as `bash <script>`
        assert module._update_state["systemd"] is True
        assert module._update_state["phase"] == "restarting"
        # The pre-restart log was seeded to the shared log file for the post-restart modal.
        assert module._UPDATE_LOG.exists()

    def test_systemd_reason_logged_only_for_skip(self, module, monkeypatch, tmp_path):
        # When the service IS used, the plan line must NOT carry a skip reason.
        manifest = {"version": "2.0.0", "files": [{"path": "a.py", "sha256": _sha(b"x"), "bytes": 1}]}
        _wire_stage1(module, monkeypatch, tmp_path, manifest, {"a.py": b"x"})
        monkeypatch.setattr(module, "_service_skip_reason", lambda: None)
        monkeypatch.setattr(module, "_await_decision", lambda *a, **k: "proceed")
        monkeypatch.setattr(module, "_write_bootstrap_script", lambda *a, **k: str(tmp_path / "b.sh"))
        monkeypatch.setattr(module.subprocess, "Popen", mock.Mock())
        _prime_state(module)
        module._run_update()
        joined = "\n".join(module._update_state["log"])
        assert "systemd service" in joined
        assert "reason:" not in joined


class TestRunUpdateDev:
    def test_dev_path_swaps_and_reexecs(self, module, monkeypatch, tmp_path):
        # A non-systemd (dev) host swaps in-process then re-execs. The live file content must
        # hash to the manifest value so the post-swap on-disk verification passes.
        content = b"print('v2')\n"
        manifest = {"version": "2.0.0",
                    "files": [{"path": "a.py", "sha256": _sha(content), "bytes": len(content)}]}
        _wire_stage1(module, monkeypatch, tmp_path, manifest, {"a.py": content})
        monkeypatch.setattr(module, "_service_skip_reason", lambda: "no systemd (dev host)")
        monkeypatch.setattr(module, "_await_decision", lambda *a, **k: "proceed")
        monkeypatch.setattr(module, "_swap", lambda m, **k: None)   # live file already = content
        restart = mock.Mock()
        monkeypatch.setattr(module, "_schedule_process_restart", restart)
        _prime_state(module)

        module._run_update()

        restart.assert_called_once()
        assert module._update_state["systemd"] is False
        assert module._update_state["phase"] == "restarting"
        # A 'restarting' marker (NOT success) is written BEFORE re-exec -- the fresh process
        # promotes it at import, so a broken new build can't masquerade as success.
        marker = json.loads(module._UPDATE_RESULT.read_text())
        assert marker["status"] == "restarting" and marker["version"] == "2.0.0"
        joined = "\n".join(module._update_state["log"])
        assert "[SWAPPING]" in joined and "[VERIFYING SWAP]" in joined

    def test_dev_post_swap_hash_mismatch_rolls_back(self, module, monkeypatch, tmp_path):
        # If the on-disk file after the swap doesn't match the manifest hash, the run must roll
        # back from the backup zip (the process still holds the OLD code, so we stay reachable).
        live = b"actually-old\n"
        manifest = {"version": "2.0.0",
                    "files": [{"path": "a.py", "sha256": _sha(b"expected-new"), "bytes": 12}]}
        zpath = _wire_stage1(module, monkeypatch, tmp_path, manifest, {"a.py": live})
        monkeypatch.setattr(module, "_service_skip_reason", lambda: "dev host")
        # PROCEED past the staged gate, then REVERT when the post-swap failure parks the run.
        decisions = iter(["proceed", "revert"])
        monkeypatch.setattr(module, "_await_decision", lambda *a, **k: next(decisions))
        monkeypatch.setattr(module, "_swap", lambda m, **k: None)
        rollback = mock.Mock()
        monkeypatch.setattr(module, "_rollback", rollback)
        restart = mock.Mock()
        monkeypatch.setattr(module, "_schedule_process_restart", restart)
        _prime_state(module)

        module._run_update()

        rollback.assert_called_once_with(zpath)            # armed rollback fired
        restart.assert_not_called()                        # never re-exec a bad swap
        assert module._update_state["phase"] == "failed"
        assert module._update_state["error"] is not None
        assert "[ROLLBACK]" in "\n".join(module._update_state["log"])


class TestRunUpdateBestEffortCleanup:
    """The updater's cleanup/log-tail branches are best-effort: a failure there must never crash
    the run or leave it in a bad state. These force the OSErrors those `except` blocks swallow."""

    def test_revert_gate_staging_cleanup_error_is_swallowed(self, module, monkeypatch, tmp_path):
        # REVERT at the staged gate wipes the staging dir; if that rmtree fails, swallow it and
        # still finish the revert cleanly (nothing was applied).
        manifest = {"version": "2.0.0", "files": [{"path": "a.py", "sha256": _sha(b"x"), "bytes": 1}]}
        _wire_stage1(module, monkeypatch, tmp_path, manifest, {"a.py": b"x"})
        module._UPDATE_STAGING.mkdir()                     # exists -> the revert path tries rmtree
        monkeypatch.setattr(module, "_service_skip_reason", lambda: "dev host")
        monkeypatch.setattr(module, "_await_decision", lambda *a, **k: "revert")
        monkeypatch.setattr(module.shutil, "rmtree",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("dir busy")))
        _prime_state(module)

        module._run_update()                               # must not raise despite rmtree failing

        assert module._update_state["phase"] == "failed"
        assert "[REVERTED]" in "\n".join(module._update_state["log"])

    def test_systemd_seed_log_write_error_is_swallowed(self, module, monkeypatch, tmp_path):
        # The systemd path seeds the shared log file before launching the bootstrap; an OSError
        # writing it is non-fatal -- the bootstrap still launches and the run proceeds.
        manifest = {"version": "2.0.0", "files": [{"path": "a.py", "sha256": _sha(b"x"), "bytes": 1}]}
        _wire_stage1(module, monkeypatch, tmp_path, manifest, {"a.py": b"x"})
        monkeypatch.setattr(module, "_service_skip_reason", lambda: None)   # use the service
        monkeypatch.setattr(module, "_await_decision", lambda *a, **k: "proceed")
        monkeypatch.setattr(module, "_write_bootstrap_script", lambda *a, **k: str(tmp_path / "b.sh"))
        popen = mock.Mock()
        monkeypatch.setattr(module.subprocess, "Popen", popen)

        class _BadLog:                                     # write_text raises; mkdir happens on _BACKUP_DIR
            def write_text(self, *a, **k):
                raise OSError("read-only fs")
        monkeypatch.setattr(module, "_UPDATE_LOG", _BadLog())
        _prime_state(module)

        module._run_update()                               # must not raise despite the seed write failing

        popen.assert_called_once()                         # bootstrap still launched
        assert module._update_state["systemd"] is True
        assert module._update_state["phase"] == "restarting"

    def test_bootstrap_preexec_sets_niceness_and_swallows_oserror(self, module, monkeypatch, tmp_path):
        # The systemd bootstrap is launched with a preexec_fn that lowers CPU priority (os.nice(5))
        # in the child. Capture it and drive both its success and its OSError (swallowed) paths.
        manifest = {"version": "2.0.0", "files": [{"path": "a.py", "sha256": _sha(b"x"), "bytes": 1}]}
        _wire_stage1(module, monkeypatch, tmp_path, manifest, {"a.py": b"x"})
        monkeypatch.setattr(module, "_service_skip_reason", lambda: None)
        monkeypatch.setattr(module, "_await_decision", lambda *a, **k: "proceed")
        monkeypatch.setattr(module, "_write_bootstrap_script", lambda *a, **k: str(tmp_path / "b.sh"))
        popen = mock.Mock()
        monkeypatch.setattr(module.subprocess, "Popen", popen)
        _prime_state(module)

        module._run_update()

        preexec = popen.call_args.kwargs["preexec_fn"]     # the child-side niceness hook
        nice_calls = []
        monkeypatch.setattr(module.os, "nice", lambda n: nice_calls.append(n))
        preexec()
        assert nice_calls == [5]                            # +5 = polite but prompt for the swap
        monkeypatch.setattr(module.os, "nice",
                            mock.Mock(side_effect=OSError("not permitted")))
        preexec()                                           # OSError must be swallowed, not raised

    def test_error_path_staging_cleanup_error_is_swallowed(self, module, monkeypatch, tmp_path):
        # A hard error before any swap parks the run, then discards staging; if that discard fails,
        # swallow it and still land in the reverted/failed state.
        manifest = {"version": "2.0.0", "files": [{"path": "a.py", "sha256": _sha(b"x"), "bytes": 1}]}
        _wire_stage1(module, monkeypatch, tmp_path, manifest, {"a.py": b"x"})
        module._UPDATE_STAGING.mkdir()                     # exists -> error path tries to discard it
        monkeypatch.setattr(module, "_make_backup",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("backup failed")))
        monkeypatch.setattr(module, "_service_skip_reason", lambda: "dev host")
        monkeypatch.setattr(module, "_await_decision", lambda *a, **k: "revert")
        monkeypatch.setattr(module.shutil, "rmtree",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("cannot remove")))
        rollback = mock.Mock()
        monkeypatch.setattr(module, "_rollback", rollback)
        _prime_state(module)

        module._run_update()                               # must not raise despite cleanup failing

        rollback.assert_not_called()                       # nothing swapped -> nothing to roll back
        assert module._update_state["phase"] == "failed"
        assert "backup failed" in module._update_state["error"]


class TestRunUpdateDecisionAndErrors:
    def test_revert_at_staged_gate_applies_nothing(self, module, monkeypatch, tmp_path):
        manifest = {"version": "2.0.0", "files": [{"path": "a.py", "sha256": _sha(b"x"), "bytes": 1}]}
        _wire_stage1(module, monkeypatch, tmp_path, manifest, {"a.py": b"x"})
        module._UPDATE_STAGING.mkdir()                     # exists -> revert must clean it up
        monkeypatch.setattr(module, "_service_skip_reason", lambda: "dev host")
        monkeypatch.setattr(module, "_await_decision", lambda *a, **k: "revert")
        swap = mock.Mock()
        monkeypatch.setattr(module, "_swap", swap)
        restart = mock.Mock()
        monkeypatch.setattr(module, "_schedule_process_restart", restart)
        _prime_state(module)

        module._run_update()

        swap.assert_not_called()                           # cancelled before applying
        restart.assert_not_called()
        assert module._update_state["phase"] == "failed"
        assert "[REVERTED]" in "\n".join(module._update_state["log"])
        assert not module._UPDATE_STAGING.exists()         # staged download discarded

    def test_error_before_swap_parks_and_does_not_rollback(self, module, monkeypatch, tmp_path):
        # A failure BEFORE any swap (here: backup raises) parks for the user, then reverts with
        # NO rollback (nothing was swapped) and leaves the old version running.
        manifest = {"version": "2.0.0", "files": [{"path": "a.py", "sha256": _sha(b"x"), "bytes": 1}]}
        _wire_stage1(module, monkeypatch, tmp_path, manifest, {"a.py": b"x"})
        module._UPDATE_STAGING.mkdir()                     # exists -> the error path cleans it up

        def boom(*a, **k):
            raise RuntimeError("backup device full")
        monkeypatch.setattr(module, "_make_backup", boom)
        monkeypatch.setattr(module, "_service_skip_reason", lambda: "dev host")
        decided = []
        monkeypatch.setattr(module, "_await_decision",
                            lambda *a, **k: decided.append(k.get("allow_proceed")) or "revert")
        rollback = mock.Mock()
        monkeypatch.setattr(module, "_rollback", rollback)
        _prime_state(module)

        module._run_update()

        rollback.assert_not_called()                       # no swap happened -> nothing to roll back
        assert module._update_state["phase"] == "failed"
        assert decided == [False]                          # a hard error offers REVERT only
        assert "backup device full" in module._update_state["error"]
        assert not module._UPDATE_STAGING.exists()         # staged download discarded on abort


class TestServiceSkipReason:
    def test_service_disabled_in_config(self, module, monkeypatch):
        monkeypatch.setitem(module.CONFIG, "SERVICE_ENABLED", "false")
        assert "service disabled" in module._service_skip_reason()

    def test_autostart_disabled_in_config(self, module, monkeypatch):
        module.CONFIG.pop("SERVICE_ENABLED", None)          # don't trip the first check
        monkeypatch.setitem(module.CONFIG, "AUTOSTART", "off")
        assert "autostart disabled" in module._service_skip_reason()

    def test_no_service_unit(self, module, monkeypatch, tmp_path):
        module.CONFIG.pop("SERVICE_ENABLED", None)
        module.CONFIG.pop("AUTOSTART", None)
        monkeypatch.setattr(module, "_SERVICE_UNIT", tmp_path / "absent.service")
        monkeypatch.setattr(module.shutil, "which", lambda n: "/bin/systemctl")
        assert "no systemd service unit" in module._service_skip_reason()

    def test_no_systemctl(self, module, monkeypatch, tmp_path):
        module.CONFIG.pop("SERVICE_ENABLED", None)
        module.CONFIG.pop("AUTOSTART", None)
        unit = tmp_path / "u.service"
        unit.write_text("x")
        monkeypatch.setattr(module, "_SERVICE_UNIT", unit)
        monkeypatch.setattr(module.shutil, "which", lambda n: None)
        assert "systemctl not available" in module._service_skip_reason()

    def test_returns_none_when_managed(self, module, monkeypatch, tmp_path):
        module.CONFIG.pop("SERVICE_ENABLED", None)
        module.CONFIG.pop("AUTOSTART", None)
        unit = tmp_path / "u.service"
        unit.write_text("x")
        monkeypatch.setattr(module, "_SERVICE_UNIT", unit)
        monkeypatch.setattr(module.shutil, "which", lambda n: "/bin/systemctl")
        assert module._service_skip_reason() is None


class TestDeploymentHasSystemd:
    def test_true_when_unit_and_systemctl(self, module, monkeypatch, tmp_path):
        unit = tmp_path / "u.service"
        unit.write_text("x")
        monkeypatch.setattr(module, "_SERVICE_UNIT", unit)
        monkeypatch.setattr(module.shutil, "which", lambda n: "/bin/systemctl")
        assert module._deployment_has_systemd() is True

    def test_false_when_no_unit(self, module, monkeypatch, tmp_path):
        monkeypatch.setattr(module, "_SERVICE_UNIT", tmp_path / "absent.service")
        assert module._deployment_has_systemd() is False


class TestAwaitDecision:
    def test_timeout_defaults_to_revert(self, module, monkeypatch):
        # No decision arrives (wait times out) -> the SAFE default is revert.
        monkeypatch.setattr(module._update_decision_event, "wait", lambda t: False)
        assert module._await_decision("msg", allow_proceed=True) == "revert"

    def test_proceed_is_honored(self, module, monkeypatch):
        def wait(t):
            module._update_decision_choice["choice"] = "proceed"
            return True
        monkeypatch.setattr(module._update_decision_event, "wait", wait)
        assert module._await_decision("msg", allow_proceed=True) == "proceed"

    def test_unknown_choice_normalizes_to_revert(self, module, monkeypatch):
        def wait(t):
            module._update_decision_choice["choice"] = "banana"
            return True
        monkeypatch.setattr(module._update_decision_event, "wait", wait)
        assert module._await_decision("msg", allow_proceed=True) == "revert"


class TestUpdateLogAppend:
    def test_appends_to_last_line(self, module):
        with module._update_lock:
            module._update_state["log"] = ["[SECTION]"]
        module._update_log_append(" ok")
        assert module._update_state["log"][-1] == "[SECTION] ok"

    def test_starts_a_line_when_log_empty(self, module):
        with module._update_lock:
            module._update_state["log"] = []
        module._update_log_append("first")
        assert module._update_state["log"] == ["first"]


class TestPruneBackups:
    def test_keeps_only_newest(self, module, tmp_path):
        import os
        # Create 5 backups with strictly increasing mtimes so "newest" is deterministic.
        for i in range(5):
            z = tmp_path / f"backup-{i}.zip"
            z.write_text("z")
            os.utime(z, (1_000_000 + i, 1_000_000 + i))
        module._prune_backups(keep=2, backup_dir=tmp_path)
        remaining = sorted(p.name for p in tmp_path.glob("backup-*.zip"))
        assert remaining == ["backup-3.zip", "backup-4.zip"]   # the 2 newest survive

    def test_unlink_error_on_one_file_is_swallowed(self, module, tmp_path, monkeypatch):
        import os
        for i in range(3):
            z = tmp_path / f"backup-{i}.zip"
            z.write_text("z")
            os.utime(z, (1_000 + i, 1_000 + i))
        # An unlink failure on an over-cap file must not abort pruning (best-effort).
        monkeypatch.setattr(module.Path, "unlink",
                            lambda self, *a, **k: (_ for _ in ()).throw(OSError("busy")))
        module._prune_backups(keep=1, backup_dir=tmp_path)     # must not raise

    def test_glob_error_is_swallowed(self, module, tmp_path, monkeypatch):
        # A failure enumerating the backups dir is swallowed (pruning is never fatal).
        bad = mock.Mock()
        bad.glob.side_effect = OSError("dir vanished")
        module._prune_backups(keep=2, backup_dir=bad)          # must not raise


class TestWriteUpdateResult:
    def test_writes_marker_and_log(self, module, tmp_path, monkeypatch):
        monkeypatch.setattr(module, "_BACKUP_DIR", tmp_path)
        monkeypatch.setattr(module, "_UPDATE_RESULT", tmp_path / "r.json")
        monkeypatch.setattr(module, "_UPDATE_LOG", tmp_path / "r.log")
        module._write_update_result("success", "2.0.0", note="done", log_text="hello world")
        r = json.loads((tmp_path / "r.json").read_text())
        assert r["status"] == "success" and r["version"] == "2.0.0" and r["note"] == "done"
        assert (tmp_path / "r.log").read_text() == "hello world"

    def test_soft_fails_on_write_error(self, module, tmp_path, monkeypatch):
        monkeypatch.setattr(module, "_BACKUP_DIR", tmp_path)

        class _Bad:
            def write_text(self, *a, **k):
                raise OSError("read-only fs")
        monkeypatch.setattr(module, "_UPDATE_RESULT", _Bad())
        module._write_update_result("success", "1.0.0")    # must not raise


class TestSwapLogging:
    def test_swap_reports_new_and_replaced_files(self, module, tmp_path):
        staging = tmp_path / "stg"
        staging.mkdir()
        (staging / "a.py").write_text("NEWDATA")
        (staging / "b.py").write_text("BB")
        root = tmp_path / "root"
        root.mkdir()
        (root / "a.py").write_text("OLD")                  # existing -> "<old> →" form
        lines = []
        module._swap({"files": [{"path": "a.py"}, {"path": "b.py"}]},
                     staging=staging, dest_root=root, log_fn=lines.append)
        assert (root / "a.py").read_text() == "NEWDATA"
        assert (root / "b.py").read_text() == "BB"
        assert any("→" in ln for ln in lines)              # replaced-file report
        assert any(" new " in ln for ln in lines)          # added-file report


class TestBackupIntegrityGuards:
    """_make_backup re-opens the freshly-written zip and PROVES it is usable for rollback
    BEFORE returning -- a corrupt/truncated archive must be caught now, while the old files
    are still live, not discovered mid-rollback."""

    def test_raises_on_failed_testzip(self, module, tmp_path, monkeypatch):
        root = tmp_path / "root"
        root.mkdir()
        (root / "a.py").write_text("DATA")
        manifest = {"version": "2", "files": [{"path": "a.py"}]}
        # Simulate CRC failure on read-back: testzip() names a bad member (non-None).
        monkeypatch.setattr(module.zipfile.ZipFile, "testzip", lambda self: "a.py")
        with pytest.raises(OSError, match="integrity check"):
            module._make_backup(manifest, dest_root=root, backup_dir=tmp_path / "bk")

    def test_raises_when_archived_bytes_dont_match(self, module, tmp_path, monkeypatch):
        root = tmp_path / "root"
        root.mkdir()
        (root / "a.py").write_text("DATA")
        manifest = {"version": "2", "files": [{"path": "a.py"}]}
        # testzip passes, but a re-read yields different bytes than the live file -> reject.
        monkeypatch.setattr(module.zipfile.ZipFile, "read",
                            lambda self, name: b"tampered-on-readback")
        with pytest.raises(OSError, match="missing/corrupt"):
            module._make_backup(manifest, dest_root=root, backup_dir=tmp_path / "bk")


class TestRollbackEdges:
    def test_missing_added_json_defaults_empty(self, module, tmp_path):
        # A zip with no __added__.json still restores its files (added defaults to []).
        root = tmp_path / "root"
        root.mkdir()
        (root / "a.py").write_text("NEW")
        z = tmp_path / "b.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("a.py", "OLD")
        module._rollback(z, dest_root=root)
        assert (root / "a.py").read_text() == "OLD"

    def test_added_file_absent_unlink_is_swallowed(self, module, tmp_path):
        # An 'added' file already gone -> unlink OSError is swallowed (best-effort rollback).
        root = tmp_path / "root"
        root.mkdir()
        z = tmp_path / "b.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("__added__.json", json.dumps(["ghost.txt"]))
        module._rollback(z, dest_root=root)                # must not raise


class TestDownloadAndVerifyExtra:
    def test_wipes_stale_staging_and_compile_checks_main(self, module, tmp_path, monkeypatch):
        code = b"x = 1\n"
        monkeypatch.setattr(module, "_http_get_bytes", lambda url, **k: code)
        staging = tmp_path / "stg"
        staging.mkdir()
        (staging / "stale.txt").write_text("leftover from a prior run")
        # Use a PACKAGE path (genpi/__init__.py) so this exercises the real shipped layout: the
        # download must mkdir -p the "genpi/" subdir under staging, and the generalized compile
        # check must byte-compile the staged package module (not just a top-level file).
        manifest = {"version": "2", "files": [
            {"path": "genpi/__init__.py", "sha256": _sha(code), "bytes": len(code)}]}
        module._download_and_verify(manifest, base="http://x", staging=staging)
        assert not (staging / "stale.txt").exists()        # stale staging wiped first
        assert (staging / "genpi" / "__init__.py").read_bytes() == code   # subdir created + compiled OK


class TestHttpGetBytes:
    def test_returns_body(self, module, monkeypatch):
        class _Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n):
                return b"hello"
        monkeypatch.setattr(module.urllib.request, "urlopen", lambda req, timeout=30: _Resp())
        assert module._http_get_bytes("http://x") == b"hello"

    def test_rejects_oversized_body(self, module, monkeypatch):
        class _Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n):
                return b"x" * n                            # n == max_bytes+1 -> over the cap
        monkeypatch.setattr(module.urllib.request, "urlopen", lambda req, timeout=30: _Resp())
        with pytest.raises(ValueError, match="exceeds"):
            module._http_get_bytes("http://x", max_bytes=16)


class TestPreflightExtra:
    def test_logs_each_check_and_survives_disk_usage_error(self, module, tmp_path, monkeypatch):
        monkeypatch.setattr(module, "_BACKUP_DIR", tmp_path / "bk")
        monkeypatch.setattr(module, "_UPDATE_STAGING", tmp_path / ".stg")
        root = tmp_path / "root"
        root.mkdir()
        (root / "a.py").write_text("x")

        def raise_os(_p):
            raise OSError("statvfs failed")
        monkeypatch.setattr(module.shutil, "disk_usage", raise_os)
        lines = []
        module._preflight_check({"files": [{"path": "a.py", "bytes": 1}]},
                                dest_root=root, log=lines.append)
        # The per-check terminal lines were emitted...
        assert any("writable" in ln for ln in lines)
        # ...and a disk_usage failure degrades to "free unknown" (no raise, no disk line).
        assert not any("free disk" in ln for ln in lines)

    def test_raises_when_project_root_unwritable(self, module, tmp_path, monkeypatch):
        monkeypatch.setattr(module, "_BACKUP_DIR", tmp_path / "bk")
        root = tmp_path / "root"
        root.mkdir()
        (root / "a.py").write_text("x")
        real = module.os.access

        def fake_access(p, mode):
            if str(p) == str(root):
                return False                               # only the project root is read-only
            return real(p, mode)
        monkeypatch.setattr(module.os, "access", fake_access)
        with pytest.raises(PermissionError, match="project root"):
            module._preflight_check({"files": [{"path": "a.py"}]}, dest_root=root)

    def test_raises_when_staging_unwritable(self, module, tmp_path, monkeypatch):
        monkeypatch.setattr(module, "_BACKUP_DIR", tmp_path / "bk")
        staging = tmp_path / "stagingroot" / ".update_staging"
        monkeypatch.setattr(module, "_UPDATE_STAGING", staging)
        root = tmp_path / "root"
        root.mkdir()
        (root / "a.py").write_text("x")
        real = module.os.access

        def fake_access(p, mode):
            if str(p) == str(staging.parent):
                return False
            return real(p, mode)
        monkeypatch.setattr(module.os, "access", fake_access)
        with pytest.raises(PermissionError, match="staging"):
            module._preflight_check({"files": [{"path": "a.py"}]}, dest_root=root)

    def test_raises_when_target_directory_unwritable(self, module, tmp_path, monkeypatch):
        monkeypatch.setattr(module, "_BACKUP_DIR", tmp_path / "bk")
        monkeypatch.setattr(module, "_UPDATE_STAGING", tmp_path / ".stg")
        root = tmp_path / "root"
        sub = root / "sub"
        sub.mkdir(parents=True)                             # the target file's parent dir
        real = module.os.access

        def fake_access(p, mode):
            if str(p) == str(sub):
                return False                               # only the target's dir is read-only
            return real(p, mode)
        monkeypatch.setattr(module.os, "access", fake_access)
        with pytest.raises(PermissionError, match="target directory"):
            module._preflight_check({"files": [{"path": "sub/a.py"}]}, dest_root=root)


class TestUpdateResultEndpointEdges:
    def test_corrupt_marker_surfaces_unknown(self, client, module, tmp_path, monkeypatch):
        r = tmp_path / "r.json"
        r.write_text("{ this is not json")
        monkeypatch.setattr(module, "_UPDATE_RESULT", r)
        monkeypatch.setattr(module, "_UPDATE_LOG", tmp_path / "absent.log")
        d = client.get(_q("/api/update/result")).get_json()
        assert d["pending"] is True and d["status"] == "unknown"

    def test_log_read_error_is_swallowed(self, client, module, tmp_path, monkeypatch):
        r = tmp_path / "r.json"
        r.write_text(json.dumps({"status": "success", "version": "2"}))
        a_dir = tmp_path / "logdir"
        a_dir.mkdir()                                      # read_text on a directory raises
        monkeypatch.setattr(module, "_UPDATE_RESULT", r)
        monkeypatch.setattr(module, "_UPDATE_LOG", a_dir)
        d = client.get(_q("/api/update/result")).get_json()
        assert d["pending"] is True and d["log"] == ""

    def test_ack_swallows_missing_files(self, client, module, tmp_path, monkeypatch):
        monkeypatch.setattr(module, "_UPDATE_RESULT", tmp_path / "gone.json")
        monkeypatch.setattr(module, "_UPDATE_LOG", tmp_path / "gone.log")
        assert client.post(_q("/api/update/result/ack")).status_code == 200


class TestUpdateCheckLoop:
    def test_pushes_once_when_update_appears(self, module, monkeypatch):
        waits = []

        def fake_wait(t):
            waits.append(t)
            return len(waits) >= 2                         # False (30s), then True (3600s) -> stop
        monkeypatch.setattr(module._monitor_stop, "wait", fake_wait)
        monkeypatch.setattr(module, "_run_update_check",
                            lambda: {"latest": "9.9.9", "update_available": True})
        events = []
        monkeypatch.setattr(module, "record_event", lambda *a, **k: events.append(a))
        pushes = []
        monkeypatch.setattr(module, "send_push_async", lambda *a, **k: pushes.append(a))
        module.update_check_loop()
        assert waits == [30, 3600]                         # 30s warm-up, then hourly
        assert len(pushes) == 1 and len(events) == 1       # exactly one announcement

    def test_stops_before_first_check(self, module, monkeypatch):
        monkeypatch.setattr(module._monitor_stop, "wait", lambda t: True)
        checked = []
        monkeypatch.setattr(module, "_run_update_check", lambda: checked.append(1))
        module.update_check_loop()                         # returns immediately
        assert checked == []
