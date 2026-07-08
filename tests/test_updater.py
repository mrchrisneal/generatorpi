# test_updater.py -- the in-app self-updater (#8): manifest path validation, download +
# SHA-256 verify (abort on mismatch / uncompilable main), ZIP backup + EXACT-state rollback
# (the safety-critical path -- a failed update must restore the previous file set precisely),
# and the authed update endpoints. Network is always mocked; file ops use tmp dirs.
import hashlib
import json
import os
import zipfile

import pytest


API_KEY = "updater-test-key"


@pytest.fixture(autouse=True)
def _key(module):
    """Every updater endpoint is @auth_required -- configure a key for the whole module."""
    module.CONFIG["API_KEY"] = API_KEY


def _q(path):
    sep = "&" if "?" in path else "?"
    return f"{path}{sep}key={API_KEY}"


def _sha(b):
    return hashlib.sha256(b).hexdigest()


# ---------------------------------------------------------------------------
# Manifest path validation -- the single gate against writing outside the root
# ---------------------------------------------------------------------------
class TestManifestPathValidation:
    @pytest.mark.parametrize("bad", ["/etc/passwd", "../x.py", "a/../../b", "", "sub/../../e"])
    def test_rejects_unsafe(self, module, bad):
        with pytest.raises(ValueError):
            module._validate_manifest_paths({"files": [{"path": bad}]})

    def test_accepts_normal(self, module):
        module._validate_manifest_paths({"files": [{"path": "generator_control.py"},
                                                    {"path": "sub/mod.py"}]})


# ---------------------------------------------------------------------------
# Download + verify
# ---------------------------------------------------------------------------
class TestDownloadAndVerify:
    def test_downloads_and_stages_on_matching_hashes(self, module, tmp_path, monkeypatch):
        content = b"print('ok')\n"
        blobs = {"a.py": content, "VERSION": b"2.0.0\n"}
        monkeypatch.setattr(module, "_http_get_bytes",
                            lambda url, **k: blobs[url.rsplit("/", 1)[1]])
        manifest = {"version": "2.0.0", "files": [
            {"path": "a.py", "sha256": _sha(content), "bytes": len(content)},
            {"path": "VERSION", "sha256": _sha(b"2.0.0\n"), "bytes": 6},
        ]}
        staging = tmp_path / "stg"
        module._download_and_verify(manifest, base="http://x", staging=staging)
        assert (staging / "a.py").read_bytes() == content
        assert (staging / "VERSION").read_bytes() == b"2.0.0\n"

    def test_aborts_on_hash_mismatch(self, module, tmp_path, monkeypatch):
        monkeypatch.setattr(module, "_http_get_bytes", lambda url, **k: b"tampered")
        manifest = {"version": "2", "files": [
            {"path": "a.py", "sha256": _sha(b"expected"), "bytes": 8}]}
        with pytest.raises(ValueError, match="hash mismatch"):
            module._download_and_verify(manifest, base="http://x", staging=tmp_path / "s")

    def test_rejects_uncompilable_main(self, module, tmp_path, monkeypatch):
        bad = b"def (:\n"                                   # syntax error
        monkeypatch.setattr(module, "_http_get_bytes", lambda url, **k: bad)
        manifest = {"version": "2", "files": [
            {"path": "generator_control.py", "sha256": _sha(bad), "bytes": len(bad)}]}
        with pytest.raises(ValueError, match="compile"):
            module._download_and_verify(manifest, base="http://x", staging=tmp_path / "s")

    def test_empty_manifest_raises(self, module, tmp_path):
        with pytest.raises(ValueError):
            module._download_and_verify({"files": []}, base="http://x", staging=tmp_path / "s")


# ---------------------------------------------------------------------------
# Backup + rollback -- the safety-critical exact-state restore
# ---------------------------------------------------------------------------
class TestBackupRollback:
    def test_backup_captures_present_and_records_added(self, module, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        (root / "a.py").write_text("OLD A")
        manifest = {"version": "2", "files": [
            {"path": "a.py", "sha256": "x", "bytes": 1},
            {"path": "new.py", "sha256": "y", "bytes": 1},   # not present -> "added"
        ]}
        zpath, added = module._make_backup(manifest, dest_root=root, backup_dir=tmp_path / "bk")
        assert added == ["new.py"]
        with zipfile.ZipFile(zpath) as z:
            assert "a.py" in z.namelist()
            assert "new.py" not in z.namelist()              # wasn't present to back up
            assert json.loads(z.read("__added__.json")) == ["new.py"]

    def test_rollback_restores_exact_state(self, module, tmp_path):
        # THE critical test: after a (simulated) update modifies files + adds a new one, a
        # rollback must restore the OLD contents AND remove the added file -> exact prior state.
        root = tmp_path / "root"
        root.mkdir()
        (root / "a.py").write_text("OLD A")
        (root / "b.txt").write_text("OLD B")
        manifest = {"version": "2", "files": [
            {"path": "a.py", "sha256": "x", "bytes": 1},
            {"path": "b.txt", "sha256": "y", "bytes": 1},
            {"path": "c.new", "sha256": "z", "bytes": 1},    # added by the update
        ]}
        zpath, _added = module._make_backup(manifest, dest_root=root, backup_dir=tmp_path / "bk")
        # Simulate the swap: overwrite existing + create the new file.
        (root / "a.py").write_text("NEW A")
        (root / "b.txt").write_text("NEW B")
        (root / "c.new").write_text("NEW C")
        module._rollback(zpath, dest_root=root)
        assert (root / "a.py").read_text() == "OLD A"
        assert (root / "b.txt").read_text() == "OLD B"
        assert not (root / "c.new").exists()                 # update-added file removed
        # Exactly the two original files remain.
        assert sorted(p.name for p in root.iterdir()) == ["a.py", "b.txt"]

    def test_rollback_never_raises_on_bad_zip(self, module, tmp_path):
        bad = tmp_path / "not-a.zip"
        bad.write_text("garbage")
        module._rollback(bad, dest_root=tmp_path)             # must not raise


# ---------------------------------------------------------------------------
# Swap + backups-dir startup guard
# ---------------------------------------------------------------------------
class TestSwapAndBackupDir:
    def test_swap_copies_staged_over_live(self, module, tmp_path):
        staging = tmp_path / "stg"
        (staging).mkdir()
        (staging / "a.py").write_text("STAGED")
        root = tmp_path / "root"
        root.mkdir()
        (root / "a.py").write_text("LIVE")
        module._swap({"files": [{"path": "a.py"}]}, staging=staging, dest_root=root)
        assert (root / "a.py").read_text() == "STAGED"

    def test_ensure_backup_dir_creates_and_probes(self, module, tmp_path, monkeypatch):
        d = tmp_path / "backups"
        monkeypatch.setattr(module, "_BACKUP_DIR", d)
        module._ensure_backup_dir()
        assert d.is_dir()
        assert not (d / ".write_probe").exists()             # probe cleaned up


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
class TestUpdateEndpoints:
    def test_status_requires_auth(self, client):
        assert client.get("/api/update/status").status_code == 401

    def test_status_returns_state(self, client, module):
        with module._update_lock:
            module._update_state.update(phase="idle", message="", progress=0.0)
        d = client.get(_q("/api/update/status")).get_json()
        assert d["phase"] == "idle" and "progress" in d

    def test_changelog_requires_auth(self, client):
        assert client.get("/api/update/changelog").status_code == 401

    def test_changelog_returns_text(self, client, module, monkeypatch):
        monkeypatch.setattr(module, "_http_get_bytes", lambda url, **k: b"# Changelog\n- x")
        d = client.get(_q("/api/update/changelog")).get_json()
        assert "Changelog" in d["changelog"]

    def test_changelog_soft_fails(self, client, module, monkeypatch):
        def boom(*a, **k):
            raise OSError("offline")
        monkeypatch.setattr(module, "_http_get_bytes", boom)
        d = client.get(_q("/api/update/changelog")).get_json()
        assert d["changelog"] is None

    def test_start_requires_auth(self, client):
        assert client.post("/api/update/start").status_code == 401

    def test_start_launches_worker_and_sets_phase(self, client, module, monkeypatch):
        started = {}

        class FakeThread:
            def __init__(self, target=None, **k):
                started["target"] = target

            def start(self):
                started["started"] = True

        monkeypatch.setattr(module.threading, "Thread", FakeThread)
        with module._update_lock:
            module._update_state["phase"] = "idle"
        resp = client.post(_q("/api/update/start"))
        assert resp.status_code == 200 and resp.get_json()["success"] is True
        assert started.get("started") is True
        assert started["target"] is module._run_update

    def test_start_conflicts_when_already_running(self, client, module):
        with module._update_lock:
            module._update_state["phase"] = "downloading"
        try:
            assert client.post(_q("/api/update/start")).status_code == 409
        finally:
            with module._update_lock:
                module._update_state["phase"] = "idle"


class TestPreflight:
    def test_passes_when_writable(self, module, tmp_path, monkeypatch):
        monkeypatch.setattr(module, "_BACKUP_DIR", tmp_path / "bk")
        root = tmp_path / "root"
        root.mkdir()
        (root / "a.py").write_text("x")
        module._preflight_check({"files": [{"path": "a.py"}]}, dest_root=root)   # no raise

    def test_raises_on_readonly_target(self, module, tmp_path, monkeypatch):
        import os
        monkeypatch.setattr(module, "_BACKUP_DIR", tmp_path / "bk")
        root = tmp_path / "root"
        root.mkdir()
        f = root / "a.py"
        f.write_text("x")
        f.chmod(0o444)
        if os.access(str(f), os.W_OK):                    # root ignores perms
            pytest.skip("running as root; W_OK not enforced")
        with pytest.raises(PermissionError):
            module._preflight_check({"files": [{"path": "a.py"}]}, dest_root=root)


class TestResultEndpoints:
    def test_result_none_without_marker(self, client, module, tmp_path, monkeypatch):
        monkeypatch.setattr(module, "_UPDATE_RESULT", tmp_path / "none.json")
        assert client.get(_q("/api/update/result")).get_json()["pending"] is False

    def test_result_returns_marker_and_log(self, client, module, tmp_path, monkeypatch):
        r = tmp_path / "res.json"
        r.write_text(json.dumps({"status": "success", "version": "2", "note": "ok"}))
        lg = tmp_path / "res.log"
        lg.write_text("did the thing")
        monkeypatch.setattr(module, "_UPDATE_RESULT", r)
        monkeypatch.setattr(module, "_UPDATE_LOG", lg)
        d = client.get(_q("/api/update/result")).get_json()
        assert d["pending"] and d["status"] == "success" and "did the thing" in d["log"]

    def test_ack_clears_marker_serverside(self, client, module, tmp_path, monkeypatch):
        r = tmp_path / "res.json"
        r.write_text("{}")
        lg = tmp_path / "res.log"
        lg.write_text("x")
        monkeypatch.setattr(module, "_UPDATE_RESULT", r)
        monkeypatch.setattr(module, "_UPDATE_LOG", lg)
        assert client.post(_q("/api/update/result/ack")).status_code == 200
        assert not r.exists() and not lg.exists()          # gone for everyone


# ---------------------------------------------------------------------------
# Post-audit hardening (2nd Opus review): version charset, secret-file denylist,
# free-disk preflight, atomic swap, and the GENERATED bootstrap script's content.
# These lock in the fixes so a future edit can't silently reintroduce a brick/RCE.
# ---------------------------------------------------------------------------
class TestVersionValidation:
    @pytest.mark.parametrize("bad", ["1.0; rm -rf /", "1.0'`x", "a" * 65, "", "1 2", "v!", "$(x)"])
    def test_rejects_unsafe_version(self, module, bad):
        with pytest.raises(ValueError):
            module._validate_version(bad)

    @pytest.mark.parametrize("ok", ["1.0.0", "1.2.3-rc1", "v1.0+build.2", "0.0.1_beta"])
    def test_accepts_safe_version(self, module, ok):
        module._validate_version(ok)                       # no raise


class TestManifestDenylist:
    @pytest.mark.parametrize("bad", ["generator_control.env", ".env", "ssl_key.pem",
                                     "certs/server.pem", "a.key", "sub/secret.ENV"])
    def test_rejects_secret_targets(self, module, bad):
        with pytest.raises(ValueError, match="secret/cert"):
            module._validate_manifest_paths({"files": [{"path": bad}]})


class TestDiskPreflight:
    def test_raises_when_free_space_too_low(self, module, tmp_path, monkeypatch):
        monkeypatch.setattr(module, "_BACKUP_DIR", tmp_path / "bk")
        root = tmp_path / "root"
        root.mkdir()
        (root / "a.py").write_text("x")

        class _DU:                                          # fake shutil.disk_usage result
            free = 10                                       # far below need (bytes*3 + 5MB)
        monkeypatch.setattr(module.shutil, "disk_usage", lambda p: _DU)
        with pytest.raises(OSError, match="disk space"):
            module._preflight_check({"files": [{"path": "a.py", "bytes": 1000}]}, dest_root=root)


class TestAtomicSwap:
    def test_swap_replaces_and_leaves_no_temp(self, module, tmp_path):
        staging = tmp_path / "stg"
        staging.mkdir()
        (staging / "a.py").write_text("NEW")
        root = tmp_path / "root"
        root.mkdir()
        (root / "a.py").write_text("OLD")
        module._swap({"files": [{"path": "a.py"}]}, staging=staging, dest_root=root)
        assert (root / "a.py").read_text() == "NEW"
        assert not (root / "a.py.gpnew").exists()          # temp renamed away, none left behind


class TestBackupIntegrity:
    def test_fresh_backup_passes_internal_verification(self, module, tmp_path):
        # _make_backup now runs testzip() + per-file re-hash before returning; a good backup
        # must pass without raising and the archive must read back byte-identical.
        root = tmp_path / "root"
        root.mkdir()
        (root / "a.py").write_text("DATA A")
        (root / "b.txt").write_text("DATA B")
        manifest = {"version": "2", "files": [{"path": "a.py"}, {"path": "b.txt"}]}
        zpath, _ = module._make_backup(manifest, dest_root=root, backup_dir=tmp_path / "bk")
        with zipfile.ZipFile(zpath) as z:
            assert z.testzip() is None
            assert z.read("a.py") == b"DATA A"
            assert z.read("b.txt") == b"DATA B"


class TestBootstrapScriptHardening:
    def test_generated_script_is_hardened(self, module, tmp_path):
        manifest = {"version": "1.2.3",
                    "files": [{"path": "generator_control.py"}, {"path": "VERSION"}]}
        script = module._write_bootstrap_script(
            manifest, "1.2.3", tmp_path / "b.zip", tmp_path / "stg", "https://127.0.0.1:9400/")
        try:
            with open(script) as fh:
                body = fh.read()
            assert "VER=1.2.3" in body                      # version reaches shell only as VER
            assert 'write_result success "Updated to v$VER."' in body   # used only via "$VER"
            assert "SVC=generator_control.service" in body
            assert 'sudo systemctl restart "$SVC"' in body  # matches the NOPASSWD sudoers rule
            assert "mv -f" in body                           # atomic per-file swap (NEW-1)
            assert 'python3 - "$HEALTH_URL"' in body         # python3 health probe (NEW-2)
            assert "curl" not in body                        # curl dependency removed
            assert "trap on_exit EXIT" in body               # roll back on any non-success exit
            assert "setsid" not in body                      # no setsid argv dependency (NEW-6)
            # Stage-2 log lines match the Stage-1 terminal style: no [gp-update] prefix, no raw
            # timestamp; bracketed [TAG] headers + dim indented "  … ok" children.
            assert "gp-update" not in body                   # old prefix removed
            assert 'log() { echo "$*"; }' in body            # verbatim: no prefix, no timestamp
            assert "files swapped … ok" in body              # indented child line
            assert "[DONE] Application successfully updated to v$VER!" in body   # reworded final line
            assert "'update OK'" not in body                 # old wording gone
            # The generated script must be valid bash (syntax check only, never executed here).
            import subprocess as _sp
            _syn = _sp.run(["bash", "-n", script], capture_output=True, text=True)
            assert _syn.returncode == 0, "bootstrap is not valid bash:\n" + _syn.stderr
        finally:
            os.remove(script)

    def test_version_is_shell_quoted_when_unsafe_chars_slip_through(self, module, tmp_path):
        # Defense in depth: even if a caller bypassed _validate_version, shlex.quote must keep
        # a metacharacter-laden version from breaking out of the VER= assignment.
        manifest = {"version": "x", "files": [{"path": "VERSION"}]}
        script = module._write_bootstrap_script(
            manifest, "1.0; rm -rf /", tmp_path / "b.zip", tmp_path / "stg", "https://127.0.0.1/")
        try:
            with open(script) as fh:
                body = fh.read()
            assert "rm -rf /" in body                        # present...
            assert "VER=1.0; rm -rf /" not in body           # ...but NOT as a bare command
        finally:
            os.remove(script)


# ---------------------------------------------------------------------------
# REVERT/PROCEED decision endpoint + log reset (terminal-UX backend)
# ---------------------------------------------------------------------------
class TestDecideEndpoint:
    def test_decide_requires_auth(self, client):
        assert client.post("/api/update/decide").status_code == 401

    def test_decide_rejects_bad_choice(self, client, module):
        assert client.post(_q("/api/update/decide"), json={"choice": "maybe"}).status_code == 400

    def test_decide_409_when_nothing_pending(self, client, module):
        with module._update_lock:
            module._update_state["phase"] = "idle"
            module._update_state["decide"] = None
        assert client.post(_q("/api/update/decide"), json={"choice": "revert"}).status_code == 409

    def test_proceed_downgraded_to_revert_when_not_allowed(self, client, module):
        with module._update_lock:
            module._update_state["phase"] = "awaiting"
            module._update_state["decide"] = {"allow_proceed": False}
            module._update_decision_choice["choice"] = None
        module._update_decision_event.clear()
        try:
            r = client.post(_q("/api/update/decide"), json={"choice": "proceed"})
            assert r.status_code == 200 and r.get_json()["choice"] == "revert"
            assert module._update_decision_event.is_set()   # worker gets unblocked
        finally:
            with module._update_lock:
                module._update_state["phase"] = "idle"
                module._update_state["decide"] = None

    def test_proceed_honored_when_allowed(self, client, module):
        with module._update_lock:
            module._update_state["phase"] = "awaiting"
            module._update_state["decide"] = {"allow_proceed": True}
            module._update_decision_choice["choice"] = None
        module._update_decision_event.clear()
        try:
            r = client.post(_q("/api/update/decide"), json={"choice": "proceed"})
            assert r.status_code == 200 and r.get_json()["choice"] == "proceed"
        finally:
            with module._update_lock:
                module._update_state["phase"] = "idle"
                module._update_state["decide"] = None


class TestStartResetsTerminalLog:
    def test_start_clears_prior_log(self, client, module, monkeypatch):
        class FakeThread:
            def __init__(self, target=None, **k):
                pass

            def start(self):
                pass
        monkeypatch.setattr(module.threading, "Thread", FakeThread)
        with module._update_lock:
            module._update_state["phase"] = "idle"
            module._update_state["log"] = ["stale line from a previous run"]
        assert client.post(_q("/api/update/start")).status_code == 200
        with module._update_lock:
            assert module._update_state["log"] == []
            assert module._update_state["decide"] is None


def test_swap_preserves_executable_bit(module, tmp_path):
    """A swap must keep the LIVE file's permission bits -- setup.sh/update.sh stay executable even
    though the staged copy was written with the default (non-exec) umask mode (exec-bit fix)."""
    import stat as _stat
    staging = tmp_path / "staging"
    staging.mkdir()
    dest = tmp_path / "dest"
    dest.mkdir()
    live = dest / "setup.sh"
    live.write_text("#!/bin/bash\necho old\n")
    os.chmod(live, 0o755)                                # the live script is executable
    staged = staging / "setup.sh"
    staged.write_text("#!/bin/bash\necho new\n")
    os.chmod(staged, 0o644)                             # the staged copy is NOT executable
    module._swap({"files": [{"path": "setup.sh", "sha256": "x", "bytes": 0}]},
                 staging=staging, dest_root=dest)
    assert live.read_text() == "#!/bin/bash\necho new\n"           # content swapped
    assert _stat.S_IMODE(os.stat(live).st_mode) == 0o755          # exec bit preserved
