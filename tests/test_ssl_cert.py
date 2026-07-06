# test_ssl_cert.py -- SSL cert provisioning: path resolution, SubjectAltName building,
# and the auto (self-signed, auto-provision/renew) vs manual (operator-provided, never
# overwrite) modes of ensure_ssl_cert(). The openssl-invoking generation is mocked in
# the mode-logic tests (fast, hermetic); one test runs real openssl to prove the SAN
# actually lands in the generated cert.
import os
import subprocess

import pytest


@pytest.fixture
def ssl_paths(module, monkeypatch, tmp_path):
    """Point the module's cert/key paths at an isolated tmp dir so tests never touch
    the real ssl_cert.pem/ssl_key.pem next to the script."""
    cert = tmp_path / "c.pem"
    key = tmp_path / "k.pem"
    monkeypatch.setattr(module, "SSL_CERT_PATH", cert)
    monkeypatch.setattr(module, "SSL_KEY_PATH", key)
    return cert, key


# ---------------------------------------------------------------------------
# _resolve_ssl_path
# ---------------------------------------------------------------------------
class TestResolveSslPath:
    def test_absolute_used_as_is(self, module):
        # An absolute path is returned unchanged.
        assert str(module._resolve_ssl_path("/etc/ssl/mycert.pem")) == "/etc/ssl/mycert.pem"

    def test_relative_is_under_script_dir(self, module):
        # A relative path resolves under SCRIPT_DIR.
        p = module._resolve_ssl_path("ssl_cert.pem")
        assert p == module.SCRIPT_DIR / "ssl_cert.pem"


# ---------------------------------------------------------------------------
# _build_san
# ---------------------------------------------------------------------------
class TestBuildSan:
    def test_includes_localhost_and_loopback(self, module):
        san = module._build_san()
        assert "DNS:localhost" in san
        assert "IP:127.0.0.1" in san

    def test_includes_hostname(self, module, monkeypatch):
        # Hostname (+ its .local form) is included.
        monkeypatch.setattr(module.socket, "gethostname", lambda: "genpi")
        san = module._build_san()
        assert "DNS:genpi" in san
        assert "DNS:genpi.local" in san

    def test_parses_operator_extras(self, module):
        # SSL_SAN extras are appended verbatim.
        module.CONFIG["SSL_SAN"] = "DNS:gen.home, IP:192.168.1.50"
        san = module._build_san()
        assert "DNS:gen.home" in san
        assert "IP:192.168.1.50" in san

    def test_dedups_preserving_order(self, module, monkeypatch):
        # A duplicate entry (hostname == localhost) is not repeated.
        monkeypatch.setattr(module.socket, "gethostname", lambda: "localhost")
        module.CONFIG["SSL_SAN"] = "DNS:localhost"
        parts = module._build_san().split(",")
        assert parts.count("DNS:localhost") == 1

    def test_hostname_failure_is_tolerated(self, module, monkeypatch):
        # If gethostname() raises, SAN building still yields the loopback defaults.
        def boom():
            raise OSError("no hostname")
        monkeypatch.setattr(module.socket, "gethostname", boom)
        san = module._build_san()
        assert "DNS:localhost" in san and "IP:127.0.0.1" in san


# ---------------------------------------------------------------------------
# ensure_ssl_cert -- auto mode
# ---------------------------------------------------------------------------
class TestEnsureAutoMode:
    def test_generates_when_missing(self, module, monkeypatch, ssl_paths):
        # No cert on disk -> self-signed generation is invoked.
        module.CONFIG["SSL_CERT_MODE"] = "auto"
        called = {}
        monkeypatch.setattr(module, "_generate_self_signed",
                            lambda: called.setdefault("gen", True))
        module.ensure_ssl_cert()
        assert called.get("gen") is True

    def test_keeps_valid_cert(self, module, monkeypatch, ssl_paths):
        # Cert exists and is NOT expiring -> no regeneration.
        cert, key = ssl_paths
        cert.write_text("x"); key.write_text("y")
        monkeypatch.setattr(module, "_cert_expires_within", lambda days: False)
        gen = {"n": 0}
        monkeypatch.setattr(module, "_generate_self_signed",
                            lambda: gen.__setitem__("n", gen["n"] + 1))
        module.ensure_ssl_cert()
        assert gen["n"] == 0

    def test_renews_when_expiring(self, module, monkeypatch, ssl_paths):
        # Cert exists but IS expiring -> regenerate.
        cert, key = ssl_paths
        cert.write_text("x"); key.write_text("y")
        monkeypatch.setattr(module, "_cert_expires_within", lambda days: True)
        called = {}
        monkeypatch.setattr(module, "_generate_self_signed",
                            lambda: called.setdefault("gen", True))
        module.ensure_ssl_cert()
        assert called.get("gen") is True

    def test_unknown_mode_falls_back_to_auto(self, module, monkeypatch, ssl_paths):
        # An unrecognized mode behaves like auto (generates when missing).
        module.CONFIG["SSL_CERT_MODE"] = "weird"
        called = {}
        monkeypatch.setattr(module, "_generate_self_signed",
                            lambda: called.setdefault("gen", True))
        module.ensure_ssl_cert()
        assert called.get("gen") is True


# ---------------------------------------------------------------------------
# ensure_ssl_cert -- manual mode
# ---------------------------------------------------------------------------
class TestEnsureManualMode:
    def test_uses_provided_without_regen(self, module, monkeypatch, ssl_paths):
        # Manual mode with both files present + valid -> never generates/overwrites.
        cert, key = ssl_paths
        cert.write_text("operator-cert"); key.write_text("operator-key")
        module.CONFIG["SSL_CERT_MODE"] = "manual"
        monkeypatch.setattr(module, "_cert_expires_within", lambda days: False)
        # If generation were attempted, fail loudly.
        monkeypatch.setattr(module, "_generate_self_signed",
                            lambda: pytest.fail("must not regenerate in manual mode"))
        module.ensure_ssl_cert()
        # Operator files are untouched.
        assert cert.read_text() == "operator-cert"
        assert key.read_text() == "operator-key"

    def test_missing_files_fail_fast(self, module, ssl_paths):
        # Manual mode with missing files -> refuse to start (no silent self-sign).
        module.CONFIG["SSL_CERT_MODE"] = "manual"
        with pytest.raises(SystemExit):
            module.ensure_ssl_cert()

    def test_expiring_warns_but_does_not_regen(self, module, monkeypatch, ssl_paths, caplog):
        # Manual mode + expiring cert -> warn, but never overwrite the operator's cert.
        import logging
        cert, key = ssl_paths
        cert.write_text("operator-cert"); key.write_text("operator-key")
        module.CONFIG["SSL_CERT_MODE"] = "manual"
        monkeypatch.setattr(module, "_cert_expires_within", lambda days: True)
        monkeypatch.setattr(module, "_generate_self_signed",
                            lambda: pytest.fail("must not regenerate in manual mode"))
        with caplog.at_level(logging.WARNING, logger="generator_control"):
            module.ensure_ssl_cert()
        assert any("expires within" in r.message for r in caplog.records)
        assert cert.read_text() == "operator-cert"


# ---------------------------------------------------------------------------
# Real generation (openssl) -- proves the SAN lands in the cert
# ---------------------------------------------------------------------------
class TestGenerateSelfSignedReal:
    def test_cert_has_san_and_key_is_owner_only(self, module, ssl_paths):
        cert, key = ssl_paths
        module.CONFIG["SSL_SAN"] = "DNS:gen.home,IP:192.168.1.50"
        module._generate_self_signed()
        assert cert.exists() and key.exists()
        # Key is owner read/write only.
        assert (os.stat(key).st_mode & 0o777) == 0o600
        # The cert carries the SubjectAltName we asked for.
        out = subprocess.run(
            ["openssl", "x509", "-in", str(cert), "-noout", "-ext", "subjectAltName"],
            capture_output=True, text=True,
        )
        assert "gen.home" in out.stdout
        assert "192.168.1.50" in out.stdout
        assert "127.0.0.1" in out.stdout
