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
        assert module._cpu_delta_pct((1000, 900), (1100, 950)) == 50.0

    def test_cpu_delta_pct_first_sample_is_none(self, module):
        # No previous reading yet -> cannot compute a delta.
        assert module._cpu_delta_pct(None, (1100, 950)) is None

    def test_cpu_delta_pct_zero_total_is_none(self, module):
        # No elapsed jiffies (total delta <= 0) -> guard against divide-by-zero.
        assert module._cpu_delta_pct((1000, 900), (1000, 900)) is None

    def test_read_cpu_times_parses_proc_stat(self, module, monkeypatch):
        fake = "cpu  100 0 50 900 20 0 0 0 0 0\ncpu0 100 0 50 900 20 0 0 0 0 0\n"
        monkeypatch.setattr(builtins, "open", lambda *a, **k: io.StringIO(fake))
        # total = 100+0+50+900+20 = 1070 ; idle = idle(900)+iowait(20) = 920
        assert module._read_cpu_times() == (1070, 920)

    def test_read_cpu_times_missing_file_is_none(self, module, monkeypatch):
        def boom(*a, **k):
            raise FileNotFoundError
        monkeypatch.setattr(builtins, "open", boom)
        assert module._read_cpu_times() is None


class TestProcReaders:
    def test_read_loadavg(self, module, monkeypatch):
        monkeypatch.setattr(builtins, "open",
                            lambda *a, **k: io.StringIO("0.58 0.42 0.30 1/123 4567\n"))
        assert module._read_loadavg() == (0.58, 0.42)

    def test_read_loadavg_missing_is_none_pair(self, module, monkeypatch):
        def boom(*a, **k):
            raise FileNotFoundError
        monkeypatch.setattr(builtins, "open", boom)
        assert module._read_loadavg() == (None, None)

    def test_read_mem_pct(self, module, monkeypatch):
        fake = "MemTotal:     1000 kB\nMemFree: 100 kB\nMemAvailable:  250 kB\n"
        monkeypatch.setattr(builtins, "open", lambda *a, **k: io.StringIO(fake))
        # used% = 100*(1 - 250/1000) = 75.0
        assert module._read_mem_pct() == 75.0

    def test_read_temp_c(self, module, monkeypatch):
        monkeypatch.setattr(builtins, "open", lambda *a, **k: io.StringIO("58200\n"))
        assert module._read_temp_c() == 58.2

    def test_read_temp_missing_is_none(self, module, monkeypatch):
        def boom(*a, **k):
            raise FileNotFoundError
        monkeypatch.setattr(builtins, "open", boom)
        assert module._read_temp_c() is None

    def test_read_wifi(self, module, monkeypatch):
        fake = (
            "Inter-| sta-|   Quality        |   Discarded packets\n"
            " face | tus | link level noise |  nwid  crypt   frag\n"
            " wlan0: 0000   48.  -62.  -256        0      0      0\n"
        )
        monkeypatch.setattr(builtins, "open", lambda *a, **k: io.StringIO(fake))
        assert module._read_wifi() == (-62, 48)

    def test_read_wifi_missing_is_none_pair(self, module, monkeypatch):
        def boom(*a, **k):
            raise FileNotFoundError
        monkeypatch.setattr(builtins, "open", boom)
        assert module._read_wifi() == (None, None)


class TestVcgencmd:
    def test_parse_volts(self, module):
        assert module._parse_volts("volt=1.3500V") == 1.35

    def test_parse_volts_garbage_is_none(self, module):
        assert module._parse_volts("nonsense") is None

    def test_parse_volts_none_is_none(self, module):
        # _vcgencmd returns None off-Pi; the parser must pass that through safely.
        assert module._parse_volts(None) is None

    def test_parse_throttled(self, module):
        # 0x50005 = bits 0,2,16,18 set (undervolt now+since, throttle now+since).
        assert module._parse_throttled("throttled=0x50005") == 0x50005

    def test_parse_throttled_garbage_is_none(self, module):
        assert module._parse_throttled("throttled=xyz") is None

    def test_vcgencmd_missing_binary_is_none(self, module, monkeypatch):
        def boom(*a, **k):
            raise FileNotFoundError  # binary not present (dev laptop)
        monkeypatch.setattr(subprocess, "run", boom)
        assert module._vcgencmd("measure_volts", "core") is None

    def test_read_volt_uses_vcgencmd(self, module, monkeypatch):
        monkeypatch.setattr(module, "_vcgencmd", lambda *a: "volt=1.2000V")
        assert module._read_volt() == 1.2

    def test_read_throttled_none_when_vcgencmd_none(self, module, monkeypatch):
        monkeypatch.setattr(module, "_vcgencmd", lambda *a: None)
        assert module._read_throttled() is None
