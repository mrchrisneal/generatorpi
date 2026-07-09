# test_system_metrics.py -- the in-memory SYSTEM perf-history sampler: cheap /proc &
# sysfs readers, the vcgencmd parsers, the ring buffer, and the /api/system/history
# endpoint. Every reader must fail SOFT (return None) when its source is missing, so
# the sampler survives on a dev laptop that has no thermal zone / vcgencmd / wlan0.
import builtins
import io
import subprocess

import pytest


class TestCpuPercent:
    def test_cpu_delta_pct_basic(self, module):
        # total goes 1000 -> 1100 (delta 100), idle goes 900 -> 950 (delta 50).
        # busy = 100 - 50 = 50 -> 50.0 %.
        assert module.sysmon._cpu_delta_pct((1000, 900), (1100, 950)) == 50.0

    def test_cpu_delta_pct_first_sample_is_none(self, module):
        # No previous reading yet -> cannot compute a delta.
        assert module.sysmon._cpu_delta_pct(None, (1100, 950)) is None

    def test_cpu_delta_pct_zero_total_is_none(self, module):
        # No elapsed jiffies (total delta <= 0) -> guard against divide-by-zero.
        assert module.sysmon._cpu_delta_pct((1000, 900), (1000, 900)) is None

    def test_read_cpu_times_parses_proc_stat(self, module, monkeypatch):
        fake = "cpu  100 0 50 900 20 0 0 0 0 0\ncpu0 100 0 50 900 20 0 0 0 0 0\n"
        monkeypatch.setattr(builtins, "open", lambda *a, **k: io.StringIO(fake))
        # total = 100+0+50+900+20 = 1070 ; idle = idle(900)+iowait(20) = 920
        assert module.sysmon._read_cpu_times() == (1070, 920)

    def test_read_cpu_times_missing_file_is_none(self, module, monkeypatch):
        def boom(*a, **k):
            raise FileNotFoundError
        monkeypatch.setattr(builtins, "open", boom)
        assert module.sysmon._read_cpu_times() is None


class TestProcReaders:
    def test_read_loadavg(self, module, monkeypatch):
        monkeypatch.setattr(builtins, "open",
                            lambda *a, **k: io.StringIO("0.58 0.42 0.30 1/123 4567\n"))
        assert module.sysmon._read_loadavg() == (0.58, 0.42)

    def test_read_loadavg_missing_is_none_pair(self, module, monkeypatch):
        def boom(*a, **k):
            raise FileNotFoundError
        monkeypatch.setattr(builtins, "open", boom)
        assert module.sysmon._read_loadavg() == (None, None)

    def test_read_mem_pct(self, module, monkeypatch):
        fake = "MemTotal:     1000 kB\nMemFree: 100 kB\nMemAvailable:  250 kB\n"
        monkeypatch.setattr(builtins, "open", lambda *a, **k: io.StringIO(fake))
        # used% = 100*(1 - 250/1000) = 75.0
        assert module.sysmon._read_mem_pct() == 75.0

    def test_read_temp_c(self, module, monkeypatch):
        # Force the path via override so the read is deterministic (no zone auto-scan).
        monkeypatch.setitem(module.CONFIG, "SYSTEM_TEMP_PATH", "/x/temp")
        monkeypatch.setattr(builtins, "open", lambda *a, **k: io.StringIO("58200\n"))
        assert module.sysmon._read_temp_c() == 58.2

    def test_read_temp_missing_is_none(self, module, monkeypatch):
        monkeypatch.setitem(module.CONFIG, "SYSTEM_TEMP_PATH", "/x/temp")

        def boom(*a, **k):
            raise FileNotFoundError
        monkeypatch.setattr(builtins, "open", boom)
        assert module.sysmon._read_temp_c() is None

    def test_read_wifi(self, module, monkeypatch):
        fake = (
            "Inter-| sta-|   Quality        |   Discarded packets\n"
            " face | tus | link level noise |  nwid  crypt   frag\n"
            " wlan0: 0000   48.  -62.  -256        0      0      0\n"
        )
        monkeypatch.setattr(builtins, "open", lambda *a, **k: io.StringIO(fake))
        assert module.sysmon._read_wifi() == (-62, 48)

    def test_read_wifi_missing_is_none_pair(self, module, monkeypatch):
        def boom(*a, **k):
            raise FileNotFoundError
        monkeypatch.setattr(builtins, "open", boom)
        assert module.sysmon._read_wifi() == (None, None)


class TestSensorSelection:
    def test_temp_path_override_wins(self, module, monkeypatch):
        monkeypatch.setitem(module.CONFIG, "SYSTEM_TEMP_PATH", "/custom/zoneX/temp")
        assert module.sysmon._auto_temp_path() == "/custom/zoneX/temp"

    def test_auto_temp_path_picks_cpu_zone(self, module, monkeypatch):
        monkeypatch.setitem(module.CONFIG, "SYSTEM_TEMP_PATH", "")
        monkeypatch.setattr(module.sysmon, "_temp_path_cache", None)
        import glob
        # zone0 = some sink; zone1 = the cpu zone -> auto-detect should choose zone1.
        monkeypatch.setattr(glob, "glob", lambda p: [
            "/sys/class/thermal/thermal_zone0/type",
            "/sys/class/thermal/thermal_zone1/type"])
        types = {"/sys/class/thermal/thermal_zone0/type": "acpitz",
                 "/sys/class/thermal/thermal_zone1/type": "x86_pkg_temp"}
        monkeypatch.setattr(builtins, "open",
                            lambda p, *a, **k: io.StringIO(types[p]))
        assert module.sysmon._auto_temp_path() == "/sys/class/thermal/thermal_zone1/temp"

    def test_auto_temp_path_falls_back_to_first(self, module, monkeypatch):
        monkeypatch.setitem(module.CONFIG, "SYSTEM_TEMP_PATH", "")
        monkeypatch.setattr(module.sysmon, "_temp_path_cache", None)
        import glob
        monkeypatch.setattr(glob, "glob", lambda p: [
            "/sys/class/thermal/thermal_zone0/type"])
        monkeypatch.setattr(builtins, "open",
                            lambda p, *a, **k: io.StringIO("some-unknown-sink"))
        # No cpu-like zone -> falls back to the first zone's temp file.
        assert module.sysmon._auto_temp_path() == "/sys/class/thermal/thermal_zone0/temp"

    def test_wifi_iface_override_selects_named(self, module, monkeypatch):
        monkeypatch.setitem(module.CONFIG, "SYSTEM_WIFI_IFACE", "wlan1")
        fake = (
            "hdr1\nhdr2\n"
            " wlan0: 0000   40.  -70.  -256   0 0 0\n"
            " wlan1: 0000   55.  -50.  -256   0 0 0\n"
        )
        monkeypatch.setattr(builtins, "open", lambda *a, **k: io.StringIO(fake))
        # Must skip wlan0 and return wlan1's (rssi, qual).
        assert module.sysmon._read_wifi() == (-50, 55)


class TestVcgencmd:
    def test_parse_volts(self, module):
        assert module.sysmon._parse_volts("volt=1.3500V") == 1.35

    def test_parse_volts_garbage_is_none(self, module):
        assert module.sysmon._parse_volts("nonsense") is None

    def test_parse_volts_none_is_none(self, module):
        # _vcgencmd returns None off-Pi; the parser must pass that through safely.
        assert module.sysmon._parse_volts(None) is None

    def test_parse_throttled(self, module):
        # 0x50005 = bits 0,2,16,18 set (undervolt now+since, throttle now+since).
        assert module.sysmon._parse_throttled("throttled=0x50005") == 0x50005

    def test_parse_throttled_garbage_is_none(self, module):
        assert module.sysmon._parse_throttled("throttled=xyz") is None

    def test_vcgencmd_missing_binary_is_none(self, module, monkeypatch):
        def boom(*a, **k):
            raise FileNotFoundError  # binary not present (dev laptop)
        monkeypatch.setattr(subprocess, "run", boom)
        assert module.sysmon._vcgencmd("measure_volts", "core") is None

    def test_read_volt_uses_vcgencmd(self, module, monkeypatch):
        monkeypatch.setattr(module.sysmon, "_vcgencmd", lambda *a: "volt=1.2000V")
        assert module.sysmon._read_volt() == 1.2

    def test_read_throttled_none_when_vcgencmd_none(self, module, monkeypatch):
        monkeypatch.setattr(module.sysmon, "_vcgencmd", lambda *a: None)
        assert module.sysmon._read_throttled() is None


class TestSampleAssembly:
    def test_sample_appends_point_with_all_keys(self, module, monkeypatch):
        # Stub every reader so the sample is deterministic and hardware-free.
        monkeypatch.setattr(module.sysmon, "_cpu_pct", lambda: 42.0)
        monkeypatch.setattr(module.sysmon, "_read_mem_pct", lambda: 61.0)
        monkeypatch.setattr(module.sysmon, "_read_loadavg", lambda: (0.58, 0.42))
        monkeypatch.setattr(module.sysmon, "_read_temp_c", lambda: 58.2)
        monkeypatch.setattr(module.sysmon, "_read_volt", lambda: 1.35)
        monkeypatch.setattr(module.sysmon, "_read_throttled", lambda: 0)
        monkeypatch.setattr(module.sysmon, "_read_wifi", lambda: (-62, 48))
        module._sys_history.clear()
        module.sysmon._sample_system()
        assert len(module._sys_history) == 1
        p = module._sys_history[0]
        assert set(p) == {"t", "cpu", "mem", "load1", "load5",
                          "temp", "volt", "thr", "rssi", "qual"}
        assert p["cpu"] == 42.0 and p["load5"] == 0.42 and p["rssi"] == -62

    def test_ring_buffer_evicts_oldest(self, module, monkeypatch):
        # Shrink capacity to prove maxlen eviction without 240 iterations. _sys_history +
        # the readers live in genpi.sysmon now (#59 Stage 7), so patch them THERE -- that is
        # the ring buffer + the bindings _sample_system actually appends to / calls.
        monkeypatch.setattr(module.sysmon, "_sys_history",
                            module.collections.deque(maxlen=3))
        for fn in ("_cpu_pct", "_read_mem_pct", "_read_temp_c",
                   "_read_volt", "_read_throttled"):
            monkeypatch.setattr(module.sysmon, fn, lambda: 1)
        monkeypatch.setattr(module.sysmon, "_read_loadavg", lambda: (1, 1))
        monkeypatch.setattr(module.sysmon, "_read_wifi", lambda: (1, 1))
        for _ in range(5):
            module.sysmon._sample_system()
        # Read the rebound deque on sysmon (module._sys_history is now a stale re-export).
        assert len(module.sysmon._sys_history) == 3  # capped, oldest dropped


class TestHistoryEndpoint:
    API_KEY = "sys-test-key"

    @pytest.fixture(autouse=True)
    def _key(self, module):
        module.CONFIG["API_KEY"] = self.API_KEY

    def test_requires_auth(self, client):
        assert client.get("/api/system/history").status_code == 401

    def test_returns_shape_and_points(self, client, module):
        module._sys_history.clear()
        with module._sys_hist_lock:
            module._sys_history.append({"t": 1, "cpu": 42.0, "mem": 61.0,
                                        "load1": 0.5, "load5": 0.4, "temp": 58.2,
                                        "volt": 1.35, "thr": 0, "rssi": -62,
                                        "qual": 48})
        resp = client.get(f"/api/system/history?key={self.API_KEY}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["sample_seconds"] == 15
        assert data["capacity"] == module._sys_history.maxlen
        assert "server_now" in data
        # COLUMNAR contract: `count` rows, `cols` has exactly the SYS_FIELDS keys, and
        # every column is an array of length == count (so colsToRows can zip them).
        assert data["count"] == 1
        assert set(data["cols"]) == set(module.SYS_FIELDS)
        assert all(len(v) == data["count"] for v in data["cols"].values())
        assert data["cols"]["cpu"][0] == 42.0 and data["cols"]["t"][0] == 1

    def test_since_returns_only_newer_points(self, client, module):
        module._sys_history.clear()
        with module._sys_hist_lock:
            for t in (10, 20, 30):
                module._sys_history.append({"t": t, "cpu": t, "mem": None,
                                            "load1": None, "load5": None, "temp": None,
                                            "volt": None, "thr": None, "rssi": None,
                                            "qual": None})
        resp = client.get(f"/api/system/history?since=20&key={self.API_KEY}")
        assert resp.status_code == 200
        assert resp.get_json()["cols"]["t"] == [30]  # only t > 20

    def test_bad_since_returns_full_buffer(self, client, module):
        module._sys_history.clear()
        with module._sys_hist_lock:
            module._sys_history.append({"t": 5, "cpu": 1, "mem": None, "load1": None,
                                        "load5": None, "temp": None, "volt": None,
                                        "thr": None, "rssi": None, "qual": None})
        resp = client.get(f"/api/system/history?since=notanumber&key={self.API_KEY}")
        assert resp.status_code == 200
        assert resp.get_json()["count"] == 1  # malformed 'since' -> full buffer
