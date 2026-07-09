# genpi/sysmon.py -- System performance monitor for GeneratorPi (roadmap #59, Stage 7). LAYER 3:
# depends on genpi.config (cadence + sensor overrides), genpi.logg (log), genpi.state (the shared
# _monitor_stop Event), and the stdlib. Imported by genpi/__init__.py after state.
#
# A single background daemon (system_monitor_loop) samples cheap host metrics -- CPU%, load, memory,
# temperature, voltage, throttle flags, Wi-Fi RSSI/quality -- into a fixed-size in-memory ring
# buffer (_sys_history, bounded by maxlen so RAM is capped regardless of uptime). RAM ONLY: nothing
# here ever writes the SD card. Every reader fails SOFT (returns None) so a missing source (no
# thermal zone / no vcgencmd / no wlan0 on a dev box) degrades to a null series instead of crashing.
#
# Copyright (C) 2026 Chris Neal <https://neal.media> and Alex Neal <https://neal.tools>
# SPDX-License-Identifier: AGPL-3.0-or-later
import time                       # sample timestamps + CPU-delta timing
import collections                # the bounded deque ring buffer
import threading                  # _sys_hist_lock guards snapshot-vs-append
import subprocess                 # vcgencmd (volt/throttle) + iwconfig (Wi-Fi) shell-outs
from .config import CONFIG        # SYSTEM_HISTORY_* cadence/size + sensor path overrides
from .logg import log             # monitor start + per-iteration warnings
from .state import _monitor_stop  # shared stop Event -- clean shutdown of the daemon loop

# ---------------------------------------------------------------------------
# SYSTEM perf history -- an in-memory ring buffer of cheap host metrics sampled
# on ONE background daemon thread. RAM only: nothing here ever touches the SD
# card. Every reader below fails SOFT (returns None) so a missing source (no
# thermal zone / no vcgencmd / no wlan0 on a dev box) degrades to a null series
# instead of crashing the sampler.
# ---------------------------------------------------------------------------

# The metric fields in a single history point, in a FIXED order. This tuple is the
# single source of truth shared by _sample_system() (which builds each point) and the
# columnar /api/system/history serializer (which emits one array per field). The
# frontend's colsToRows() rebuilds row objects assuming this exact set of keys.
SYS_FIELDS = ("t", "cpu", "mem", "load1", "load5", "temp", "volt", "thr", "rssi", "qual")

# Fixed-size history. maxlen evicts the oldest point automatically, so memory is
# bounded regardless of uptime. Guarded by _sys_hist_lock for snapshot-vs-append.
_sys_history = collections.deque(maxlen=int(CONFIG.get("SYSTEM_HISTORY_POINTS", 240)))
_sys_hist_lock = threading.Lock()

# Previous (total, idle) jiffies from /proc/stat, held between samples so CPU% is a
# DELTA computed by the sampler -- never a per-request cost.
_prev_cpu = None


def _read_cpu_times():
    """Return (total_jiffies, idle_jiffies) from the aggregate 'cpu' line of
    /proc/stat, or None if it can't be read/parsed. idle counts idle+iowait."""
    try:
        with open("/proc/stat") as f:
            line = f.readline()
        parts = line.split()
        if not parts or parts[0] != "cpu":
            return None
        vals = [int(x) for x in parts[1:]]
        # Fields: user nice system idle iowait irq softirq steal guest guest_nice
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)  # idle + iowait
        return (sum(vals), idle)
    except (OSError, ValueError, IndexError):
        return None


def _cpu_delta_pct(prev, cur):
    """Utilization % between two (total, idle) samples, or None when it can't be
    computed (no previous sample yet, or no elapsed time)."""
    if prev is None or cur is None:
        return None
    total_d = cur[0] - prev[0]
    idle_d = cur[1] - prev[1]
    if total_d <= 0:
        return None
    return round(100.0 * (total_d - idle_d) / total_d, 1)


def _cpu_pct():
    """Stateful CPU% for the sampler: reads /proc/stat, diffs against the previous
    read, stores the new read. Returns None on the first call (seeds the baseline)
    and on any read failure."""
    global _prev_cpu
    cur = _read_cpu_times()
    prev, _prev_cpu = _prev_cpu, cur
    return _cpu_delta_pct(prev, cur)


def _read_loadavg():
    """(1-min, 5-min) load averages from /proc/loadavg, or (None, None)."""
    try:
        with open("/proc/loadavg") as f:
            parts = f.read().split()
        return (round(float(parts[0]), 2), round(float(parts[1]), 2))
    except (OSError, ValueError, IndexError):
        return (None, None)


def _read_mem_pct():
    """Used-memory percentage from /proc/meminfo: 100*(1 - MemAvailable/MemTotal),
    or None. MemAvailable (not MemFree) is the kernel's honest 'free-ish' figure."""
    try:
        total = avail = None
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    total = float(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    avail = float(line.split()[1])
                if total is not None and avail is not None:
                    break
        if not total or avail is None:
            return None
        return round(100.0 * (1.0 - avail / total), 1)
    except (OSError, ValueError, IndexError):
        return None


# Cached auto-detected thermal-zone path (resolved once; scanning every sample is waste).
_temp_path_cache = None


def _auto_temp_path():
    """Pick the best thermal-zone temp file in Python: honor SYSTEM_TEMP_PATH if set,
    else scan /sys/class/thermal for a zone whose `type` looks like the CPU/SoC sensor
    (cpu/soc/x86_pkg/arm), falling back to the first zone, then thermal_zone0. Cached so
    the scan runs once."""
    global _temp_path_cache
    override = CONFIG.get("SYSTEM_TEMP_PATH", "")
    if override:
        return override
    if _temp_path_cache is not None:
        return _temp_path_cache
    default = "/sys/class/thermal/thermal_zone0/temp"
    chosen = default
    try:
        import glob
        first = None
        for zt in sorted(glob.glob("/sys/class/thermal/thermal_zone*/type")):
            base = zt.rsplit("/", 1)[0] + "/temp"
            if first is None:
                first = base
            try:
                kind = open(zt).read().strip().lower()
            except OSError:
                continue
            if any(k in kind for k in ("cpu", "soc", "x86_pkg", "arm")):
                chosen = base
                break
        else:
            chosen = first or default
    except Exception:
        chosen = default
    _temp_path_cache = chosen
    return chosen


def _read_temp_c():
    """SoC/CPU temperature in degrees C (millidegrees / 1000), or None. Reads the
    auto-selected (or SYSTEM_TEMP_PATH-overridden) thermal zone."""
    try:
        with open(_auto_temp_path()) as f:
            return round(int(f.read().strip()) / 1000.0, 1)
    except (OSError, ValueError):
        return None


def _read_wifi():
    """(rssi_dbm, link_quality) from /proc/net/wireless, or (None, None). The first
    two lines are headers; an interface data line has the form:
        wlan0: 0000   48.  -62.  -256   ...
    where col 2 = link quality and col 3 = signal level (dBm). Uses SYSTEM_WIFI_IFACE
    if set, else the first interface found. Trailing dots are stripped before int()."""
    want = CONFIG.get("SYSTEM_WIFI_IFACE", "")
    try:
        with open("/proc/net/wireless") as f:
            lines = f.readlines()
        for line in lines[2:]:
            if ":" in line:
                name = line.split(":", 1)[0].strip()
                if want and name != want:
                    continue
                fields = line.split()
                qual = int(float(fields[2].rstrip(".")))
                rssi = int(float(fields[3].rstrip(".")))
                return (rssi, qual)
        return (None, None)
    except (OSError, ValueError, IndexError):
        return (None, None)


def _vcgencmd(*args):
    """Run `vcgencmd <args>` and return stripped stdout, or None if the binary is
    absent (dev laptop) or the call errors/times out. Pi-only; cheap (~ms)."""
    try:
        res = subprocess.run(["vcgencmd", *args],
                             capture_output=True, text=True, timeout=2)
        if res.returncode != 0:
            return None
        return res.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def _parse_volts(s):
    """'volt=1.3500V' -> 1.35 (V), or None (incl. a None input from _vcgencmd)."""
    try:
        return round(float(s.strip().split("=")[1].rstrip("V")), 3)
    except (ValueError, IndexError, AttributeError):
        return None


def _read_volt():
    """Core voltage in volts via vcgencmd, or None off-Pi."""
    return _parse_volts(_vcgencmd("measure_volts", "core"))


def _parse_throttled(s):
    """'throttled=0x50005' -> 0x50005 (int bitmask), or None (incl. a None input).
    Bits of interest: 0 = under-voltage NOW, 2 = throttled NOW,
    16 = under-voltage since boot, 18 = throttled since boot."""
    try:
        return int(s.strip().split("=")[1], 16)
    except (ValueError, IndexError, AttributeError):
        return None


def _read_throttled():
    """get_throttled bitmask via vcgencmd, or None off-Pi."""
    return _parse_throttled(_vcgencmd("get_throttled"))


def _sample_system():
    """Read every metric once and append a single compact point to the in-memory
    ring buffer. Each reader already fails soft to None, so a missing source just
    yields a null field. Never raises for a normal missing-source condition."""
    load1, load5 = _read_loadavg()
    rssi, qual = _read_wifi()
    point = {
        "t": int(time.time()),
        "cpu": _cpu_pct(),        # stateful delta; None on the very first sample
        "mem": _read_mem_pct(),
        "load1": load1,
        "load5": load5,
        "temp": _read_temp_c(),
        "volt": _read_volt(),
        "thr": _read_throttled(),
        "rssi": rssi,
        "qual": qual,
    }
    with _sys_hist_lock:
        _sys_history.append(point)


def system_monitor_loop():
    """Background daemon: sample host metrics into the ring buffer every
    SYSTEM_HISTORY_SECONDS. Stops cleanly when _monitor_stop is set. RAM only --
    never writes to disk."""
    interval = max(5, int(CONFIG.get("SYSTEM_HISTORY_SECONDS", 15)))
    log.info(f"System monitor started (every {interval}s)")
    while not _monitor_stop.wait(interval):
        try:
            _sample_system()
        except Exception as e:
            log.warning(f"System monitor iteration error: {e}")
