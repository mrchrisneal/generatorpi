# test_ssl_main.py -- SSL cert helpers (_cert_expires_within, ensure_ssl_cert) and
# the main() entry point. subprocess.run is always mocked, so openssl is never
# invoked and no real certs are generated. _serve is mocked so no server binds.
import subprocess
import threading
from unittest import mock

import pytest
import werkzeug.serving


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
        monkeypatch.setattr(module, "_serve", run)
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
        monkeypatch.setattr(module, "_serve", run)
        module.main()
        ensure.assert_not_called()
        assert run.call_args.kwargs["ssl_context"] is None

    def test_main_exits_when_ssl_file_unreadable(self, module, monkeypatch):
        module.CONFIG["SSL_ENABLED"] = 1
        monkeypatch.setattr(module, "ensure_ssl_cert", mock.Mock())
        # cert/key not readable -> critical exit before app.run.
        monkeypatch.setattr(module.os, "access", lambda p, m: False)
        run = mock.Mock()
        monkeypatch.setattr(module, "_serve", run)
        with pytest.raises(SystemExit) as exc:
            module.main()
        assert exc.value.code == 1
        run.assert_not_called()

    def test_main_handles_keyboard_interrupt(self, module, monkeypatch):
        module.CONFIG["SSL_ENABLED"] = 0
        monkeypatch.setattr(module, "_serve", mock.Mock(side_effect=KeyboardInterrupt))
        # Must be caught cleanly; relay still closed in finally.
        module.main()
        assert module.relay_start_stop.close.called


class TestServeAndRestart:
    """The non-systemd restart fix: _serve keeps a handle on the WSGI server so
    _schedule_process_restart can RELEASE the listening socket before os.execv -- otherwise the
    re-exec'd image inherits the socket, can't rebind the port, and the app stays down."""

    def test_serve_marks_socket_noninheritable_and_serves(self, module, monkeypatch):
        fake_sock = mock.Mock()
        fake_srv = mock.Mock(socket=fake_sock)
        # serve_forever blocks forever in reality; raise to fall straight through the finally.
        fake_srv.serve_forever.side_effect = KeyboardInterrupt
        monkeypatch.setattr(werkzeug.serving, "make_server", mock.Mock(return_value=fake_srv))
        with pytest.raises(KeyboardInterrupt):
            module._serve("127.0.0.1", 5999, threaded=True)
        fake_sock.set_inheritable.assert_called_once_with(False)  # exec drops the FD
        fake_srv.serve_forever.assert_called_once()

    def test_serve_retries_only_address_in_use(self, module, monkeypatch):
        # EADDRINUSE is retried (a draining old socket); a non-bind OSError surfaces immediately
        # so a cert/permission error isn't buried under 10 pointless retries (audit review #6).
        import errno as _errno
        monkeypatch.setattr(module.time, "sleep", lambda s: None)
        boom = OSError(_errno.EACCES, "permission denied")
        monkeypatch.setattr(werkzeug.serving, "make_server", mock.Mock(side_effect=boom))
        with pytest.raises(OSError) as exc:
            module._serve("127.0.0.1", 5999)
        assert exc.value.errno == _errno.EACCES

    def test_restart_closes_listening_socket_before_reexec(self, module, monkeypatch):
        # The socket MUST be closed before execv so the new image can rebind the port.
        calls = []
        fake_sock = mock.Mock()
        fake_sock.close.side_effect = lambda: calls.append("close")
        monkeypatch.setattr(module, "_WSGI_SERVER", mock.Mock(socket=fake_sock))
        monkeypatch.setattr(module.time, "sleep", lambda s: None)
        done = threading.Event()

        def fake_execv(*a, **k):
            calls.append("execv")
            done.set()

        monkeypatch.setattr(module.os, "execv", fake_execv)
        module._schedule_process_restart(delay=0)
        assert done.wait(2), "restart thread never ran"
        assert calls == ["close", "execv"], f"socket must close BEFORE execv, got {calls}"
