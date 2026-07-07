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
