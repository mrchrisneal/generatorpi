# test_ssl_main.py -- SSL cert helpers (_cert_expires_within, ensure_ssl_cert) and
# the main() entry point. subprocess.run is always mocked, so openssl is never
# invoked and no real certs are generated. app.run is mocked so no server binds.
import subprocess
from unittest import mock

import pytest


class TestCertExpiresWithin:
    def test_returns_false_when_valid(self, module, monkeypatch):
        # openssl -checkend exit 0 => still valid beyond the window => not expiring.
        fake = mock.Mock(returncode=0, stdout="", stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **k: fake)
        assert module._cert_expires_within(30) is False

    def test_returns_true_when_expiring(self, module, monkeypatch):
        # exit 1 => expires within the window.
        fake = mock.Mock(returncode=1, stdout="", stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **k: fake)
        assert module._cert_expires_within(30) is True

    def test_assumes_expired_on_exception(self, module, monkeypatch):
        # Any error checking the cert => fail safe (treat as expired -> regenerate).
        def boom(*a, **k):
            raise subprocess.TimeoutExpired(cmd="openssl", timeout=5)

        monkeypatch.setattr(subprocess, "run", boom)
        assert module._cert_expires_within(30) is True


class TestEnsureSslCert:
    def test_skips_when_cert_valid(self, module, monkeypatch, tmp_path):
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        cert.write_text("x")
        key.write_text("y")
        monkeypatch.setattr(module, "SSL_CERT_PATH", cert)
        monkeypatch.setattr(module, "SSL_KEY_PATH", key)
        # Cert not expiring -> early return, no openssl invocation.
        monkeypatch.setattr(module, "_cert_expires_within", lambda d: False)
        run = mock.Mock()
        monkeypatch.setattr(subprocess, "run", run)
        module.ensure_ssl_cert()
        run.assert_not_called()

    def test_generates_when_missing(self, module, monkeypatch, tmp_path):
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"  # neither exists
        monkeypatch.setattr(module, "SSL_CERT_PATH", cert)
        monkeypatch.setattr(module, "SSL_KEY_PATH", key)
        run = mock.Mock(return_value=mock.Mock(returncode=0, stderr=""))
        monkeypatch.setattr(subprocess, "run", run)
        # Key file isn't really created (openssl mocked), so chmod is a no-op mock.
        monkeypatch.setattr(module.os, "chmod", mock.Mock())
        module.ensure_ssl_cert()
        run.assert_called_once()
        # The generation command is an openssl req -x509 invocation.
        argv = run.call_args[0][0]
        assert argv[0] == "openssl" and "req" in argv and "-x509" in argv

    def test_regenerates_when_expiring(self, module, monkeypatch, tmp_path):
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        cert.write_text("x")
        key.write_text("y")
        monkeypatch.setattr(module, "SSL_CERT_PATH", cert)
        monkeypatch.setattr(module, "SSL_KEY_PATH", key)
        monkeypatch.setattr(module, "_cert_expires_within", lambda d: True)
        run = mock.Mock(return_value=mock.Mock(returncode=0, stderr=""))
        monkeypatch.setattr(subprocess, "run", run)
        monkeypatch.setattr(module.os, "chmod", mock.Mock())
        module.ensure_ssl_cert()
        run.assert_called_once()

    def test_raises_on_generation_failure(self, module, monkeypatch, tmp_path):
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        monkeypatch.setattr(module, "SSL_CERT_PATH", cert)
        monkeypatch.setattr(module, "SSL_KEY_PATH", key)
        run = mock.Mock(return_value=mock.Mock(returncode=1, stderr="boom"))
        monkeypatch.setattr(subprocess, "run", run)
        with pytest.raises(RuntimeError, match="SSL certificate generation failed"):
            module.ensure_ssl_cert()


class TestMain:
    def test_main_ssl_enabled_runs_server(self, module, monkeypatch):
        module.CONFIG["SSL_ENABLED"] = 1
        monkeypatch.setattr(module, "ensure_ssl_cert", mock.Mock())
        monkeypatch.setattr(module.os, "access", lambda p, m: True)  # cert readable
        run = mock.Mock()
        monkeypatch.setattr(module.app, "run", run)
        module.main()
        run.assert_called_once()
        # ssl_context tuple (cert, key) must be passed when SSL is enabled.
        assert run.call_args.kwargs["ssl_context"] is not None
        # Relay closed on shutdown (finally block).
        assert module.relay_start_stop.close.called

    def test_main_ssl_disabled_skips_cert(self, module, monkeypatch):
        module.CONFIG["SSL_ENABLED"] = 0
        ensure = mock.Mock()
        monkeypatch.setattr(module, "ensure_ssl_cert", ensure)
        run = mock.Mock()
        monkeypatch.setattr(module.app, "run", run)
        module.main()
        ensure.assert_not_called()
        assert run.call_args.kwargs["ssl_context"] is None

    def test_main_exits_when_ssl_file_unreadable(self, module, monkeypatch):
        module.CONFIG["SSL_ENABLED"] = 1
        monkeypatch.setattr(module, "ensure_ssl_cert", mock.Mock())
        # cert/key not readable -> critical exit before app.run.
        monkeypatch.setattr(module.os, "access", lambda p, m: False)
        run = mock.Mock()
        monkeypatch.setattr(module.app, "run", run)
        with pytest.raises(SystemExit) as exc:
            module.main()
        assert exc.value.code == 1
        run.assert_not_called()

    def test_main_handles_keyboard_interrupt(self, module, monkeypatch):
        module.CONFIG["SSL_ENABLED"] = 0
        monkeypatch.setattr(module.app, "run", mock.Mock(side_effect=KeyboardInterrupt))
        # Must be caught cleanly; relay still closed in finally.
        module.main()
        assert module.relay_start_stop.close.called
