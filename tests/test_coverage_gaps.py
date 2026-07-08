# test_coverage_gaps.py -- targeted tests for the error/edge branches that the main
# suites don't reach: the push-subscription store's conn-missing + swallowed-error paths,
# the VERSION reader, the /api/state version fields, the _serve bind-retry SUCCESS path
# (the actual #41 fix), the restart re-exec failure fallbacks, factory-reset log-truncate
# failure, the update-check version helpers, the log-tail readers, and the soft-fail
# branches of the /proc + vcgencmd system-metric readers. Everything is mocked -- no
# sockets bind, no processes exec, no hardware is touched.
import builtins
import errno
import io
import threading
from unittest import mock

import pytest
import werkzeug.serving


API_KEY = "gaps-test-key"


# ---------------------------------------------------------------------------
# Push subscription store -- conn-missing early-returns + swallowed DB errors
# ---------------------------------------------------------------------------
class TestSubscriptionStoreEdges:
    def test_add_is_noop_without_conn(self, module, monkeypatch):
        monkeypatch.setattr(module, "_event_conn", None)
        module.add_subscription("e", "p", "a")             # returns quietly, no raise

    def test_remove_is_noop_without_conn(self, module, monkeypatch):
        monkeypatch.setattr(module, "_event_conn", None)
        module.remove_subscription("e")

    def test_get_returns_empty_without_conn(self, module, monkeypatch):
        monkeypatch.setattr(module, "_event_conn", None)
        assert module.get_subscriptions() == []

    def test_count_is_zero_without_conn(self, module, monkeypatch):
        monkeypatch.setattr(module, "_event_conn", None)
        assert module.subscription_count() == 0

    def test_add_swallows_db_error(self, module, monkeypatch):
        class _Boom:
            def execute(self, *a, **k):
                raise RuntimeError("db locked")
        monkeypatch.setattr(module, "_event_conn", _Boom())
        module.add_subscription("e", "p", "a")             # must not raise into the caller

    def test_remove_swallows_db_error(self, module, monkeypatch):
        class _Boom:
            def execute(self, *a, **k):
                raise RuntimeError("db locked")
        monkeypatch.setattr(module, "_event_conn", _Boom())
        module.remove_subscription("e")

    def test_get_swallows_db_error(self, module, monkeypatch):
        class _Boom:
            def execute(self, *a, **k):
                raise RuntimeError("db locked")
        monkeypatch.setattr(module, "_event_conn", _Boom())
        assert module.get_subscriptions() == []

    def test_count_swallows_db_error(self, module, monkeypatch):
        class _Boom:
            def execute(self, *a, **k):
                raise RuntimeError("db locked")
        monkeypatch.setattr(module, "_event_conn", _Boom())
        assert module.subscription_count() == 0


# ---------------------------------------------------------------------------
# VERSION reader
# ---------------------------------------------------------------------------
class TestReadAppVersion:
    def test_missing_file_falls_back(self, module, tmp_path, monkeypatch):
        monkeypatch.setattr(module, "SCRIPT_DIR", tmp_path)     # no VERSION file present
        assert module._read_app_version() == "0.0.0"

    def test_empty_file_falls_back(self, module, tmp_path, monkeypatch):
        monkeypatch.setattr(module, "SCRIPT_DIR", tmp_path)
        (tmp_path / "VERSION").write_text("   \n")
        assert module._read_app_version() == "0.0.0"

    def test_reads_trimmed_value(self, module, tmp_path, monkeypatch):
        monkeypatch.setattr(module, "SCRIPT_DIR", tmp_path)
        (tmp_path / "VERSION").write_text("  3.4.5\n")
        assert module._read_app_version() == "3.4.5"


# ---------------------------------------------------------------------------
# /api/state -- the version + start-time fields the client uses for restart detection
# ---------------------------------------------------------------------------
class TestStateVersionFields:
    @pytest.fixture(autouse=True)
    def _key(self, module):
        module.CONFIG["API_KEY"] = API_KEY

    def test_app_version_and_started_at_present(self, client, module):
        d = client.get(f"/api/state?key={API_KEY}").get_json()
        assert d["app_version"] == module.APP_VERSION
        assert isinstance(d["app_version"], str)
        # started_at is this process's import-time unix clock (float) -- the restart signal.
        assert d["started_at"] == module._STARTED_AT
        assert isinstance(d["started_at"], (int, float))


# ---------------------------------------------------------------------------
# _serve bind-retry -- the #41 fix: a first EADDRINUSE is RETRIED, not fatal
# ---------------------------------------------------------------------------
class TestServeBindRetry:
    def test_first_eaddrinuse_is_retried_then_succeeds(self, module, monkeypatch):
        # The core of the fix: make_server raises EADDRINUSE once (old socket still draining),
        # then succeeds on the second attempt. Both are must-haves: exactly 2 calls + 1 sleep.
        fake_sock = mock.Mock()
        fake_srv = mock.Mock(socket=fake_sock)
        fake_srv.serve_forever.side_effect = KeyboardInterrupt      # fall through the finally
        calls = {"n": 0}

        def make(*a, **k):
            calls["n"] += 1
            if calls["n"] == 1:
                raise OSError(errno.EADDRINUSE, "address in use")
            return fake_srv
        monkeypatch.setattr(werkzeug.serving, "make_server", make)
        sleeps = []
        monkeypatch.setattr(module.time, "sleep", lambda s: sleeps.append(s))
        with pytest.raises(KeyboardInterrupt):
            module._serve("127.0.0.1", 5999)
        assert calls["n"] == 2                              # retried exactly once
        assert len(sleeps) == 1                             # slept between the two attempts
        fake_srv.serve_forever.assert_called_once()         # the second server actually served
        fake_sock.set_inheritable.assert_called_once_with(False)

    def test_raises_after_retries_exhausted(self, module, monkeypatch):
        # Persistent EADDRINUSE -> after the bounded retries, the last error surfaces.
        monkeypatch.setattr(werkzeug.serving, "make_server",
                            mock.Mock(side_effect=OSError(errno.EADDRINUSE, "busy")))
        monkeypatch.setattr(module.time, "sleep", lambda s: None)
        with pytest.raises(OSError) as exc:
            module._serve("127.0.0.1", 5999)
        assert exc.value.errno == errno.EADDRINUSE

    def test_set_inheritable_error_is_nonfatal(self, module, monkeypatch):
        # A set_inheritable failure must not stop the server from serving (closing the socket
        # before exec is the primary guarantee anyway).
        fake_sock = mock.Mock()
        fake_sock.set_inheritable.side_effect = OSError("not supported")
        fake_srv = mock.Mock(socket=fake_sock)
        fake_srv.serve_forever.side_effect = KeyboardInterrupt
        monkeypatch.setattr(werkzeug.serving, "make_server", mock.Mock(return_value=fake_srv))
        with pytest.raises(KeyboardInterrupt):
            module._serve("127.0.0.1", 5999)
        fake_srv.serve_forever.assert_called_once()


# ---------------------------------------------------------------------------
# _schedule_process_restart -- socket-close error swallowed; execv-failure fallback
# ---------------------------------------------------------------------------
class TestRestartFallbacks:
    def test_socket_close_error_does_not_block_execv(self, module, monkeypatch):
        fake_sock = mock.Mock()
        fake_sock.close.side_effect = OSError("already closed")
        monkeypatch.setattr(module, "_WSGI_SERVER", mock.Mock(socket=fake_sock))
        monkeypatch.setattr(module.time, "sleep", lambda s: None)
        done = threading.Event()
        monkeypatch.setattr(module.os, "execv", lambda *a: done.set())
        module._schedule_process_restart(delay=0)
        assert done.wait(2)                                # execv still ran despite close error

    def test_execv_failure_falls_back_to_hard_exit(self, module, monkeypatch):
        monkeypatch.setattr(module, "_WSGI_SERVER", None)  # no socket to close
        monkeypatch.setattr(module.time, "sleep", lambda s: None)

        def bad_execv(*a):
            raise OSError("execv unavailable")
        monkeypatch.setattr(module.os, "execv", bad_execv)
        done = threading.Event()
        seen = {}

        def fake_exit(code):
            seen["code"] = code
            done.set()
        monkeypatch.setattr(module.os, "_exit", fake_exit)
        module._schedule_process_restart(delay=0)
        assert done.wait(2)
        assert seen["code"] == 1                            # os._exit(1) so a supervisor respawns


# ---------------------------------------------------------------------------
# factory_reset -- log-truncate failure must be swallowed
# ---------------------------------------------------------------------------
class TestFactoryResetLogError:
    def test_log_truncate_error_swallowed(self, module, monkeypatch):
        monkeypatch.setattr(module, "_event_conn", None)   # skip the DB deletes for isolation
        real_open = builtins.open

        def bad_open(path, *a, **k):
            mode = a[0] if a else k.get("mode", "r")
            if "w" in mode:                                 # the log-truncate open(log_path,"w")
                raise OSError("read-only filesystem")
            return real_open(path, *a, **k)
        monkeypatch.setattr(builtins, "open", bad_open)
        module.factory_reset()                              # must not raise
        # State globals were still reset despite the log write failing.
        assert module.generator_state["total_run_hours"] == 0.0


# ---------------------------------------------------------------------------
# Update-check version helpers
# ---------------------------------------------------------------------------
class TestVersionHelpers:
    def test_version_tuple_degrades_nonnumeric_to_zero(self, module):
        assert module._version_tuple("1.a.3") == (1, 0, 3)

    def test_fetch_latest_version_trims_body(self, module, monkeypatch):
        class _Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n):
                return b"  2.5.0 \n"
        monkeypatch.setattr(module.urllib.request, "urlopen", lambda req, timeout=5: _Resp())
        assert module._fetch_latest_version() == "2.5.0"

    def test_fetch_latest_version_none_on_failure(self, module, monkeypatch):
        def boom(req, timeout=5):
            raise OSError("offline")
        monkeypatch.setattr(module.urllib.request, "urlopen", boom)
        assert module._fetch_latest_version() is None


# ---------------------------------------------------------------------------
# Log-tail readers (the APP LOG feed helpers)
# ---------------------------------------------------------------------------
class TestLogTailReaders:
    def test_tail_lines_empty_for_missing_file(self, module, tmp_path):
        assert module._tail_lines(tmp_path / "nope.log", 5) == []

    def test_read_log_range_missing_file(self, module, tmp_path):
        assert module._read_log_range(tmp_path / "nope.log", 0, 10, 5) == ([], 0)

    def test_read_log_range_caps_to_last_n(self, module, tmp_path):
        p = tmp_path / "a.log"
        p.write_bytes(b"l1\nl2\nl3\nl4\nl5\n")
        lines, cursor = module._read_log_range(p, 0, p.stat().st_size, 2)
        assert lines == ["l4", "l5"]                        # burst capped to the last n complete lines
        assert cursor == p.stat().st_size                   # cursor advanced past the final newline


# ---------------------------------------------------------------------------
# System-metric readers -- the soft-fail (None) branches on malformed sources
# ---------------------------------------------------------------------------
class TestSystemMetricSoftFails:
    def test_read_cpu_times_none_when_not_cpu_line(self, module, monkeypatch):
        monkeypatch.setattr(builtins, "open", lambda *a, **k: io.StringIO("intr 1 2 3\n"))
        assert module._read_cpu_times() is None

    def test_cpu_pct_seeds_then_computes_delta(self, module, monkeypatch):
        seq = [(1000, 900), (1100, 950)]
        monkeypatch.setattr(module, "_read_cpu_times", lambda: seq.pop(0))
        monkeypatch.setattr(module, "_prev_cpu", None)
        assert module._cpu_pct() is None                    # first call only seeds the baseline
        assert module._cpu_pct() == 50.0                    # second call yields the delta

    def test_read_mem_pct_none_without_available(self, module, monkeypatch):
        fake = "MemTotal: 1000 kB\nMemFree: 100 kB\n"       # no MemAvailable line
        monkeypatch.setattr(builtins, "open", lambda *a, **k: io.StringIO(fake))
        assert module._read_mem_pct() is None

    def test_read_mem_pct_none_on_parse_error(self, module, monkeypatch):
        fake = "MemTotal: notanumber kB\nMemAvailable: 5 kB\n"
        monkeypatch.setattr(builtins, "open", lambda *a, **k: io.StringIO(fake))
        assert module._read_mem_pct() is None

    def test_auto_temp_path_returns_cached(self, module, monkeypatch):
        monkeypatch.setitem(module.CONFIG, "SYSTEM_TEMP_PATH", "")
        monkeypatch.setattr(module, "_temp_path_cache", "/cached/zone/temp")
        assert module._auto_temp_path() == "/cached/zone/temp"

    def test_auto_temp_path_skips_unreadable_zone(self, module, monkeypatch):
        monkeypatch.setitem(module.CONFIG, "SYSTEM_TEMP_PATH", "")
        monkeypatch.setattr(module, "_temp_path_cache", None)
        import glob
        monkeypatch.setattr(glob, "glob", lambda p: ["/sys/class/thermal/thermal_zone0/type"])

        def bad_open(*a, **k):
            raise OSError("permission denied")              # type file unreadable -> skip zone
        monkeypatch.setattr(builtins, "open", bad_open)
        # No cpu-like zone matched -> falls back to the first zone's temp file.
        assert module._auto_temp_path() == "/sys/class/thermal/thermal_zone0/temp"

    def test_auto_temp_path_glob_error_falls_back_to_default(self, module, monkeypatch):
        monkeypatch.setitem(module.CONFIG, "SYSTEM_TEMP_PATH", "")
        monkeypatch.setattr(module, "_temp_path_cache", None)
        import glob

        def boom(p):
            raise RuntimeError("sysfs exploded")
        monkeypatch.setattr(glob, "glob", boom)
        assert module._auto_temp_path() == "/sys/class/thermal/thermal_zone0/temp"

    def test_read_wifi_none_pair_when_iface_not_found(self, module, monkeypatch):
        monkeypatch.setitem(module.CONFIG, "SYSTEM_WIFI_IFACE", "wlan9")
        fake = ("hdr1\nhdr2\n"
                " wlan0: 0000   40.  -70.  -256   0 0 0\n")
        monkeypatch.setattr(builtins, "open", lambda *a, **k: io.StringIO(fake))
        assert module._read_wifi() == (None, None)          # named iface absent -> soft null

    def test_vcgencmd_none_on_nonzero_return(self, module, monkeypatch):
        import subprocess
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **k: mock.Mock(returncode=1, stdout="x"))
        assert module._vcgencmd("get_throttled") is None

    def test_vcgencmd_strips_stdout_on_success(self, module, monkeypatch):
        import subprocess
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **k: mock.Mock(returncode=0, stdout=" throttled=0x0 \n"))
        assert module._vcgencmd("get_throttled") == "throttled=0x0"


class TestSystemMonitorLoop:
    def test_samples_each_cycle_and_survives_errors(self, module, monkeypatch):
        # Two loop iterations: the first samples cleanly, the second raises (must be swallowed),
        # then the stop event ends the loop. Proves the loop never dies on a sampler error.
        waits = []

        def fake_wait(interval):
            waits.append(interval)
            return len(waits) >= 3                          # two iterations, then stop
        monkeypatch.setattr(module._monitor_stop, "wait", fake_wait)
        calls = {"n": 0}

        def sample():
            calls["n"] += 1
            if calls["n"] == 2:
                raise RuntimeError("thermal read blew up")
        monkeypatch.setattr(module, "_sample_system", sample)
        module.system_monitor_loop()
        assert calls["n"] == 2                              # both iterations ran; error swallowed


# ---------------------------------------------------------------------------
# _push_endpoint_error -- the SSRF guard on subscription endpoints
# ---------------------------------------------------------------------------
class TestPushEndpointError:
    def test_empty_endpoint_rejected(self, module):
        assert module._push_endpoint_error("") == "missing endpoint or keys"
        assert module._push_endpoint_error(None) == "missing endpoint or keys"

    def test_no_host_rejected(self, module):
        # A well-formed https URL with no host component (e.g. "https:///path").
        assert module._push_endpoint_error("https:///path") == "endpoint has no host"

    def test_public_ip_literal_allowed(self, module):
        # A routable public IP literal passes the private/loopback/reserved screen.
        assert module._push_endpoint_error("https://8.8.8.8/wp/xyz") is None

    def test_private_ip_literal_blocked(self, module):
        assert module._push_endpoint_error("https://192.168.1.5/x") is not None

    def test_ordinary_hostname_allowed(self, module):
        assert module._push_endpoint_error("https://fcm.googleapis.com/fcm/send/abc") is None


# ---------------------------------------------------------------------------
# SSL cert generation -- key chmod failure is best-effort (swallowed)
# ---------------------------------------------------------------------------
class TestSslChmodError:
    def test_key_chmod_error_is_swallowed(self, module, monkeypatch, tmp_path):
        import subprocess
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"                          # neither exists -> generation runs
        monkeypatch.setattr(module, "SSL_CERT_PATH", cert)
        monkeypatch.setattr(module, "SSL_KEY_PATH", key)
        monkeypatch.setattr(subprocess, "run",
                            mock.Mock(return_value=mock.Mock(returncode=0, stderr="")))
        monkeypatch.setattr(module.os, "chmod", mock.Mock(side_effect=OSError("op not permitted")))
        module.ensure_ssl_cert()                            # chmod failure must not raise
