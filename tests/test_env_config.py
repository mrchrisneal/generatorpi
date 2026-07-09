# test_env_config.py -- parse_env_file() (password hashing, API-key auto-generation,
# config casting, atomic rewrite + 0600) and check_settings_file_security() (the
# startup ownership/permission guard). Both operate on the module's ENV_FILE /
# SCRIPT_DIR, which the `env_paths` fixture redirects to an isolated tmp dir.
import os
import stat

import pytest
from werkzeug.security import generate_password_hash, check_password_hash


def _mode(path):
    """Return the permission bits (low 9) of a path."""
    return stat.S_IMODE(os.stat(path).st_mode)


# ---------------------------------------------------------------------------
# parse_env_file
# ---------------------------------------------------------------------------
class TestParseEnvFileMissing:
    def test_missing_file_returns_empty_and_no_write(self, module, monkeypatch, tmp_path):
        missing = tmp_path / "nope.env"
        # ENV_FILE/SCRIPT_DIR + parse_env_file moved to genpi.config (#59 Stage 2) -- patch there.
        monkeypatch.setattr(module.config, "ENV_FILE", missing)
        monkeypatch.setattr(module.config, "SCRIPT_DIR", tmp_path)
        users = module.parse_env_file()
        assert users == {}
        assert not missing.exists()


class TestParseEnvFilePasswords:
    def test_plaintext_password_is_hashed_in_place(self, module, env_paths):
        # Preset an API key so the key-generation path stays out of the way.
        env_paths.write_text("API_KEY=preset\nUSER_bob=plaintextpw\n")
        users = module.parse_env_file()
        # In-memory: bob's stored value is a hash that verifies the plaintext.
        assert "bob" in users
        assert users["bob"].startswith(module.HASH_PREFIXES)
        assert check_password_hash(users["bob"], "plaintextpw")
        # On-disk: the file was rewritten with the hash, not the plaintext.
        contents = env_paths.read_text()
        assert "plaintextpw" not in contents
        assert "USER_bob=" in contents
        assert _mode(env_paths) == 0o600

    def test_already_hashed_password_preserved(self, module, env_paths):
        existing = generate_password_hash("secret")
        env_paths.write_text(f"API_KEY=preset\nUSER_bob={existing}\n")
        users = module.parse_env_file()
        assert users["bob"] == existing
        # No re-hash: exact same hash string is still on disk.
        assert existing in env_paths.read_text()

    def test_empty_username_line_preserved_and_skipped(self, module, env_paths):
        env_paths.write_text("API_KEY=preset\nUSER_=orphan\n")
        users = module.parse_env_file()
        assert users == {}
        # The malformed line is preserved verbatim.
        assert "USER_=orphan" in env_paths.read_text()


class TestParseEnvFileApiKey:
    def test_generates_key_in_place_when_enabled_and_empty(self, module, env_paths):
        env_paths.write_text("API_KEY_ENABLED=1\nAPI_KEY=\n")
        module.parse_env_file()
        generated = module.CONFIG["API_KEY"]
        assert generated  # non-empty
        # token_urlsafe(32) yields ~43 URL-safe chars.
        assert len(generated) >= 40
        contents = env_paths.read_text()
        # Filled in place: exactly the existing API_KEY= line now carries the key.
        assert f"API_KEY={generated}" in contents
        assert _mode(env_paths) == 0o600

    def test_appends_key_block_when_no_api_key_line(self, module, env_paths):
        # No API_KEY line at all -> a documented block is appended.
        env_paths.write_text("RELAY_PIN=27\n")
        module.parse_env_file()
        generated = module.CONFIG["API_KEY"]
        assert generated
        contents = env_paths.read_text()
        assert f"API_KEY={generated}" in contents
        assert "# API key for machine callers" in contents
        assert _mode(env_paths) == 0o600

    def test_does_not_regenerate_when_key_present(self, module, env_paths):
        # With BOTH the API key and a VAPID keypair already present, parse rewrites
        # nothing -- neither secret is regenerated (VAPID auto-gen only fires when the
        # private key is empty, so pre-setting it keeps the file byte-identical).
        content = (
            "API_KEY=already-set-key\n"
            "VAPID_PUBLIC_KEY=preset-pub\n"
            "VAPID_PRIVATE_KEY=preset-priv\n"
        )
        env_paths.write_text(content)
        module.parse_env_file()
        assert module.CONFIG["API_KEY"] == "already-set-key"
        # File unchanged (no rewrite needed) -> still exactly the preset secrets.
        assert env_paths.read_text() == content

    def test_does_not_generate_when_disabled(self, module, env_paths):
        env_paths.write_text("API_KEY_ENABLED=0\nAPI_KEY=\n")
        module.parse_env_file()
        assert module.CONFIG["API_KEY"] == ""
        # No key was written into the file.
        assert "API_KEY=\n" in env_paths.read_text()


class TestParseEnvFileBooleanConfig:
    @pytest.mark.parametrize("word", ["true", "yes", "on", "TRUE", "On"])
    def test_boolean_word_enables(self, module, env_paths, word):
        # FIX #2: integer toggles accept boolean words. true/yes/on -> 1.
        env_paths.write_text(f"API_KEY=preset\nAPI_KEY_ENABLED={word}\n")
        module.parse_env_file()
        assert module.CONFIG["API_KEY_ENABLED"] == 1

    @pytest.mark.parametrize("word", ["false", "no", "off", "FALSE", "Off"])
    def test_boolean_word_disables_and_rejects_key(self, module, env_paths, word):
        # FIX #2: false/no/off -> 0, which actually turns key auth OFF -- a valid
        # configured key must then be rejected by check_api_key.
        env_paths.write_text(f"API_KEY=validkey\nAPI_KEY_ENABLED={word}\n")
        module.parse_env_file()
        assert module.CONFIG["API_KEY_ENABLED"] == 0
        # Key auth is disabled: even the correct key does not authenticate.
        with module.app.test_request_context("/api/status?key=validkey"):
            assert module.check_api_key() is False

    def test_bad_boolean_value_keeps_default_and_warns(self, module, env_paths, capsys):
        # A value that is neither a boolean word nor an int keeps the default (1)
        # and prints the "Invalid value" warning.
        default = module.CONFIG["API_KEY_ENABLED"]
        env_paths.write_text("API_KEY=preset\nAPI_KEY_ENABLED=maybe\n")
        module.parse_env_file()
        assert module.CONFIG["API_KEY_ENABLED"] == default
        out = capsys.readouterr().out
        assert "Invalid value for API_KEY_ENABLED" in out


class TestParseEnvFileDuplicateApiKey:
    def test_first_nonempty_key_wins_duplicate_dropped_and_stable(
        self, module, env_paths
    ):
        # FIX #3: with a real key followed by a stray empty API_KEY= duplicate, the
        # FIRST (real) key wins and the duplicate is dropped on rewrite -- otherwise
        # the empty line would blank the key and force regeneration on EVERY restart,
        # silently breaking HomeAssistant.
        env_paths.write_text("API_KEY=realkey\nAPI_KEY=\n")
        module.parse_env_file()
        assert module.CONFIG["API_KEY"] == "realkey"
        contents = env_paths.read_text()
        # Exactly one API_KEY= line survives (the duplicate was removed).
        assert contents.count("API_KEY=") == 1
        assert "API_KEY=realkey" in contents
        assert _mode(env_paths) == 0o600

        # Simulate a RESTART: a fresh process starts with an empty CONFIG key and
        # re-parses the rewritten file. The key must stay stable -- NOT regenerate.
        module.CONFIG["API_KEY"] = ""
        module.parse_env_file()
        assert module.CONFIG["API_KEY"] == "realkey"
        assert env_paths.read_text().count("API_KEY=") == 1

    def test_first_NONempty_wins_empty_leading_line_is_skipped(
        self, module, env_paths
    ):
        # The winner is the first NON-EMPTY API_KEY (guard is `if CONFIG["API_KEY"]`).
        # So an empty leading `API_KEY=` does not lock in emptiness: the next
        # non-empty value ("straydupe") becomes the effective key, and because a
        # real key is now set, no fresh key is auto-generated.
        env_paths.write_text("API_KEY=\nAPI_KEY=straydupe\n")
        module.parse_env_file()
        assert module.CONFIG["API_KEY"] == "straydupe"


class TestParseEnvFileConfig:
    def test_int_override(self, module, env_paths):
        env_paths.write_text("API_KEY=preset\nRELAY_PIN=13\n")
        module.parse_env_file()
        assert module.CONFIG["RELAY_PIN"] == 13
        assert isinstance(module.CONFIG["RELAY_PIN"], int)

    def test_float_override(self, module, env_paths):
        env_paths.write_text("API_KEY=preset\nPRIME_DELAY=1.5\n")
        module.parse_env_file()
        assert module.CONFIG["PRIME_DELAY"] == 1.5
        assert isinstance(module.CONFIG["PRIME_DELAY"], float)

    def test_string_override(self, module, env_paths):
        env_paths.write_text("API_KEY=preset\nHOST=127.0.0.1\n")
        module.parse_env_file()
        assert module.CONFIG["HOST"] == "127.0.0.1"

    def test_invalid_int_keeps_default(self, module, env_paths):
        default = module.CONFIG["RELAY_PIN"]
        env_paths.write_text("API_KEY=preset\nRELAY_PIN=notanint\n")
        module.parse_env_file()
        assert module.CONFIG["RELAY_PIN"] == default

    def test_unknown_key_preserved_and_ignored(self, module, env_paths):
        env_paths.write_text("API_KEY=preset\nTOTALLY_UNKNOWN=value\n")
        module.parse_env_file()
        assert "TOTALLY_UNKNOWN" not in module.CONFIG
        assert "TOTALLY_UNKNOWN=value" in env_paths.read_text()

    def test_comments_blanks_and_no_equals_preserved(self, module, env_paths):
        env_paths.write_text(
            "# a comment\n\nlinewithoutequals\nAPI_KEY=preset\nUSER_bob=pw\n"
        )
        module.parse_env_file()
        # Rewrite happens (bob hashed); comment/blank/no-equals lines survive.
        contents = env_paths.read_text()
        assert "# a comment" in contents
        assert "linewithoutequals" in contents


class TestParseEnvFileRewriteFailure:
    def test_rewrite_oserror_exits(self, module, env_paths, monkeypatch):
        # A plaintext password forces needs_rewrite=True. If os.rename fails, the
        # function must clean up the temp file and sys.exit(1) rather than silently
        # dropping the generated key / hashes.
        env_paths.write_text("API_KEY=preset\nUSER_bob=plaintext\n")

        def boom(*a, **k):
            raise OSError("disk full")

        monkeypatch.setattr(module.os, "rename", boom)
        with pytest.raises(SystemExit) as exc:
            module.parse_env_file()
        assert exc.value.code == 1
        # No leftover temp files in the SCRIPT_DIR.
        leftovers = [p for p in env_paths.parent.iterdir()
                     if p.name.startswith(".env_tmp_")]
        assert leftovers == []

    def test_chmod_failure_is_swallowed(self, module, env_paths, monkeypatch):
        # The belt-and-suspenders os.chmod after rename is best-effort: an OSError
        # there must NOT crash the parse (the rename already succeeded).
        env_paths.write_text("API_KEY=preset\nUSER_bob=plaintext\n")
        real_chmod = module.os.chmod

        def selective_chmod(path, mode):
            # Fail only on the final env-file chmod; allow mkstemp's internal use.
            if str(path) == str(env_paths):
                raise OSError("no chmod")
            return real_chmod(path, mode)

        monkeypatch.setattr(module.os, "chmod", selective_chmod)
        users = module.parse_env_file()  # must not raise
        assert "bob" in users


# ---------------------------------------------------------------------------
# check_settings_file_security
# ---------------------------------------------------------------------------
class TestSettingsSecurity:
    def test_missing_file_is_ok(self, module, monkeypatch, tmp_path):
        monkeypatch.setattr(module.config, "ENV_FILE", tmp_path / "absent.env")
        # Must simply return without raising.
        assert module.check_settings_file_security() is None

    def test_good_file_passes(self, module, env_paths):
        env_paths.write_text("API_KEY=x\n")
        os.chmod(env_paths, 0o600)
        # Owner matches (we created it), perms are already 0600 -> no problems.
        assert module.check_settings_file_security() is None

    def test_wrong_owner_exits(self, module, env_paths, monkeypatch):
        env_paths.write_text("API_KEY=x\n")
        os.chmod(env_paths, 0o600)
        real_uid = os.stat(env_paths).st_uid
        # Pretend the process runs as a different uid than the file owner.
        monkeypatch.setattr(module.os, "geteuid", lambda: real_uid + 1)
        with pytest.raises(SystemExit) as exc:
            module.check_settings_file_security()
        assert exc.value.code == 1

    def test_unreadable_exits(self, module, env_paths, monkeypatch):
        env_paths.write_text("API_KEY=x\n")
        os.chmod(env_paths, 0o600)
        # Owner matches, but os.access reports the file unreadable.
        monkeypatch.setattr(module.os, "access", lambda p, m: False)
        with pytest.raises(SystemExit) as exc:
            module.check_settings_file_security()
        assert exc.value.code == 1

    def test_loose_perms_tightened_in_place(self, module, env_paths):
        env_paths.write_text("API_KEY=x\n")
        os.chmod(env_paths, 0o644)  # group/other readable
        # Should tighten to 0600 in place and NOT exit.
        assert module.check_settings_file_security() is None
        assert _mode(env_paths) == 0o600

    def test_loose_perms_that_cannot_be_tightened_exit(self, module, env_paths, monkeypatch):
        env_paths.write_text("API_KEY=x\n")
        os.chmod(env_paths, 0o644)
        monkeypatch.setattr(module.os, "access", lambda p, m: True)

        def no_chmod(*a, **k):
            raise OSError("read-only fs")

        monkeypatch.setattr(module.os, "chmod", no_chmod)
        with pytest.raises(SystemExit) as exc:
            module.check_settings_file_security()
        assert exc.value.code == 1

    def test_symlinked_env_file_exits(self, module, monkeypatch, tmp_path):
        # FIX #6a: refuse a symlinked settings file (a swapped symlink could
        # redirect our chmod/rewrite at another file). The real target is fine
        # (owned by us, 0600) so the symlink itself is the sole reason to exit.
        target = tmp_path / "real.env"
        target.write_text("API_KEY=x\n")
        os.chmod(target, 0o600)
        link = tmp_path / "link.env"
        link.symlink_to(target)
        monkeypatch.setattr(module.config, "ENV_FILE", link)
        with pytest.raises(SystemExit) as exc:
            module.check_settings_file_security()
        assert exc.value.code == 1

    def test_root_skips_ownership_requirement(self, module, env_paths, monkeypatch):
        # FIX #6b: a root-run service (euid 0, common for GPIO) can chmod/rewrite any
        # file, so the ownership check is skipped. A file NOT owned by root (owned by
        # us) with good perms must NOT cause an exit under root.
        env_paths.write_text("API_KEY=x\n")
        os.chmod(env_paths, 0o600)
        real_uid = os.stat(env_paths).st_uid
        assert real_uid != 0  # sanity: the file is owned by a non-root user
        monkeypatch.setattr(module.os, "geteuid", lambda: 0)  # pretend we are root
        # Must return cleanly despite the uid mismatch (root can manage it).
        assert module.check_settings_file_security() is None
