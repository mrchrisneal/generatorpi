#!/usr/bin/env python3
# =============================================================================
#  gp-monitor.py  --  on-device Wi-Fi + performance correlator for Raspberry Pi
# =============================================================================
#
#  WHAT IT DOES
#  ------------
#  Samples EVERY candidate cause of Wi-Fi flakiness on a Pi, once every few
#  seconds, on the same timeline, so you can see what actually moves when the
#  link stalls. Purpose-built to answer "why does my Pi's Wi-Fi keep dropping?"
#  without guessing. Per tick it records:
#     link    : ping to the default gateway (the Pi's own link health),
#               signal (dBm), TX bitrate, TX retries/failed delta, beacon loss
#     driver  : new brcmfmac "-110" control-channel timeouts (Broadcom SDIO Wi-Fi)
#     power   : vcgencmd throttle flags (UNDER-VOLTAGE!), core voltage, SoC temp
#     host    : load average, free RAM, top CPU processes
#  Plus a start/end context block: the neighbouring-AP scan (channel congestion),
#  recent deauth/disconnect events, and recent driver errors.
#
#  It runs ENTIRELY ON THE PI and writes to a local file, so it keeps recording
#  even while the network is dead -- then you read the log afterwards. That's the
#  whole point: the moment the link recovers, the evidence is already captured.
#
#  WHY THESE SIGNALS
#  -----------------
#  Wi-Fi "flakiness" gets blamed on the wrong thing constantly. This tool lets
#  you RULE OUT the usual suspects with data:
#    * voltage flag != 0x0 during a stall  -> power/PSU problem (brownout)
#    * high CPU/load during a stall         -> compute contention
#    * signal drops during a stall          -> range/obstruction problem
#    * signal FINE but bitrate collapses +
#      retries climb during a stall         -> 2.4GHz airtime CONGESTION
#    * -110 storm during a stall            -> driver/firmware control-channel jam
#    * deauth/disassoc events               -> the AP is kicking the client
#
#  REQUIREMENTS
#  ------------
#    * Raspberry Pi OS (or similar). Wi-Fi interface assumed to be "wlan0".
#    * Run as root (sudo): needs `dmesg` and `vcgencmd`.
#    * Tools used (all standard on Pi OS): iw, ping, ip, nmcli, dmesg, vcgencmd,
#      journalctl. Missing ones degrade gracefully (that field shows -1/blank).
#    * `vcgencmd` is Raspberry-Pi-specific; on non-Pi hardware the power columns
#      simply read as unavailable and everything else still works.
#
#  USAGE
#  -----
#    # 5-minute run (default), logging to a file, detached so it survives SSH drops:
#    setsid sudo python3 gp-monitor.py 300 > /home/pi/gp-monitor.log 2>&1 < /dev/null &
#
#    # then read the results (now, or after the link recovers):
#    cat /home/pi/gp-monitor.log
#
#    # or run it in the foreground for a quick 60-second look:
#    sudo python3 gp-monitor.py 60
#
#    Argument 1 = duration in seconds (default 420). Sampling interval = STEP (5s).
#
#  READING THE OUTPUT
#  ------------------
#    Each line: clock t=<sec> L=<load> f=<freeMB> gw=<ping>ms 110+=<n> sig=<dBm>
#               rate=<Mbit> rtry+=<n> fail+=<n> bcn=<n> thr=<hex> v=<volts>
#               T=<tempC>  <top-2 CPU procs>   [<<<flags>>>]
#    Flags: <<<STALL (ping >1s or lost) · <<<THROTTLE/UV! (voltage/thermal!) ·
#           <<<-110storm (>=3 driver timeouts this tick).
#    A row of sig=-1/rate=-1 means the stall was so complete the stats query
#    itself couldn't get through -- itself a strong "link is dead right now" signal.
#
#  See gp-monitor.md (next to this file) for a checklist of the Pi + AP config
#  knobs that actually move Wi-Fi reliability.
# =============================================================================
import time, os, glob, subprocess, re, sys

DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 420   # total run length (s)
STEP = 5                                                    # sample interval (s)
IFACE = os.environ.get('GP_IFACE', 'wlan0')                 # Wi-Fi interface
HZ = os.sysconf('SC_CLK_TCK')                               # jiffies/sec (usually 100)

def sh(args, t=4):
    """Run a command, return stdout ('' on any failure/timeout)."""
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=t).stdout
    except Exception:
        return ''

def default_gw():
    for l in sh(['ip', 'route']).splitlines():
        if l.startswith('default'):
            return l.split()[2]
    return None

def ping(host):
    if not host:
        return None
    out = sh(['ping', '-c', '1', '-W', '2', host], t=4)
    m = re.search(r'time=([\d.]+)', out)
    return float(m.group(1)) if m else -1.0  # -1.0 == loss/timeout

def dmesg_110():
    out = sh(['dmesg'], t=6)
    return out.count('-110') if out else -1

def wlan_tx_err():
    try:
        for l in open('/proc/net/dev'):
            if IFACE in l:
                return int(l.split(':')[1].split()[10])  # tx errors column
    except Exception:
        pass
    return -1

def free_mb():
    try:
        for l in open('/proc/meminfo'):
            if l.startswith('MemAvailable'):
                return int(l.split()[1]) // 1024
    except Exception:
        pass
    return -1

def rf_snap():
    # signal(dBm), tx_bitrate(Mbit), tx_retries, tx_failed, beacon_loss.
    # retries/failed are cumulative counters -> caller diffs them.
    out = sh(['iw', 'dev', IFACE, 'station', 'dump'], t=4)
    def grab(pat, cast=int, d=-1):
        m = re.search(pat, out)
        return cast(m.group(1)) if m else d
    return {
        'sig': grab(r'signal:\s*(-?\d+)'),
        'rate': grab(r'tx bitrate:\s*([\d.]+)', float),
        'rtry': grab(r'tx retries:\s*(\d+)'),
        'fail': grab(r'tx failed:\s*(\d+)'),
        'bcn': grab(r'beacon loss:\s*(\d+)'),
    }

def power_snap():
    # Raspberry-Pi-specific. throttle flags: bit0=under-voltage NOW,
    # bit16=under-voltage has occurred, bit2/bit18=throttled now/occurred.
    thr = sh(['vcgencmd', 'get_throttled']).strip()
    m = re.search(r'throttled=(0x[0-9a-fA-F]+)', thr)
    thr_hex = m.group(1) if m else '?'
    mv = re.search(r'volt=([\d.]+)', sh(['vcgencmd', 'measure_volts']))
    volt = float(mv.group(1)) if mv else -1.0
    mt = re.search(r'temp=([\d.]+)', sh(['vcgencmd', 'measure_temp']))
    temp = float(mt.group(1)) if mt else -1.0
    return thr_hex, volt, temp

def cpu_snap():
    # pid -> total CPU jiffies (utime+stime). Robust to comm containing spaces/parens.
    d = {}
    for p in glob.glob('/proc/[0-9]*/stat'):
        try:
            line = open(p).read()
        except Exception:
            continue
        pid = p.split('/')[2]
        rest = line[line.rfind(')') + 2:].split()
        try:
            d[pid] = int(rest[11]) + int(rest[12])
        except Exception:
            continue
    return d

def comm(pid):
    try:
        return open(f'/proc/{pid}/comm').read().strip()
    except Exception:
        return pid

def context(tag):
    print(f"# ---- {tag} CONTEXT ----", flush=True)
    print("# iw link:", " ".join(sh(['iw', 'dev', IFACE, 'link']).split()), flush=True)
    print("# nmcli:", sh(['nmcli', '-t', '-f', 'STATE,CONNECTIVITY', 'general']).strip(), flush=True)
    print("# 2.4GHz neighbours (CHAN SIGNAL SSID) -- co-channel congestion check:", flush=True)
    scan = sh(['nmcli', '-f', 'CHAN,SIGNAL,SSID', 'dev', 'wifi', 'list'], t=8)
    for l in sorted(scan.splitlines()[1:])[:22]:
        print("#   " + l.rstrip(), flush=True)
    print("# recent deauth/disconnect (journal, confounder check):", flush=True)
    j = sh(['journalctl', '-u', 'NetworkManager', '-u', 'wpa_supplicant', '--since', '-8 min', '--no-pager'], t=8)
    for l in [x for x in j.splitlines() if re.search(r'deauth|disassoc|disconn|CTRL-EVENT-DISCON', x, re.I)][-5:]:
        print("#   " + l.strip()[-160:], flush=True)
    print("# recent -110 (dmesg):", flush=True)
    for l in [x for x in sh(['dmesg']).splitlines() if '-110' in x][-3:]:
        print("#   " + l, flush=True)

GW = default_gw()
print(f"# gp-monitor start {time.strftime('%Y-%m-%d %H:%M:%S')}  iface={IFACE} gw={GW} HZ={HZ} dur={DURATION}s step={STEP}s", flush=True)
context("START")
print("# cols: clock t load free(MB) gwPing 110+ sig rate rtry+ fail+ bcn THROTTLE volt temp  top2cpu", flush=True)

prev110 = dmesg_110()
prevtx = wlan_tx_err()
prevrf = rf_snap()
prevcpu = cpu_snap()
prevt = time.time()
t0 = time.time()

while time.time() - t0 < DURATION:
    time.sleep(STEP)
    now = time.time()
    dt = max(0.1, now - prevt)
    prevt = now
    try:
        load1 = open('/proc/loadavg').read().split()[0]
    except Exception:
        load1 = '?'
    fm = free_mb()
    p = ping(GW)
    c110 = dmesg_110()
    d110 = (c110 - prev110) if (c110 >= 0 and prev110 >= 0) else -1
    if d110 < 0 and c110 >= 0:
        d110 = 0
    prev110 = c110 if c110 >= 0 else prev110
    tx = wlan_tx_err()
    dtx = (tx - prevtx) if (tx >= 0 and prevtx >= 0) else 0
    prevtx = tx if tx >= 0 else prevtx
    rf = rf_snap()
    drtry = (rf['rtry'] - prevrf['rtry']) if (rf['rtry'] >= 0 and prevrf['rtry'] >= 0) else -1
    dfail = (rf['fail'] - prevrf['fail']) if (rf['fail'] >= 0 and prevrf['fail'] >= 0) else -1
    prevrf = rf
    thr, volt, temp = power_snap()
    cur = cpu_snap()
    deltas = []
    for pid, j in cur.items():
        dj = j - prevcpu.get(pid, j)
        if dj > 0:
            deltas.append((dj / HZ / dt * 100.0, pid))
    prevcpu = cur
    deltas.sort(reverse=True)
    top = " ".join(f"{comm(pid)}:{pct:.0f}%" for pct, pid in deltas[:2])
    pstr = "LOSS " if (p is None or p < 0) else f"{p:6.0f}"
    flags = ""
    if p is not None and (p < 0 or p > 1000):
        flags += " <<<STALL"
    if thr not in ('0x0', '?'):
        flags += " <<<THROTTLE/UV!"
    if d110 >= 3:
        flags += " <<<-110storm"
    print(f"{time.strftime('%H:%M:%S')} t={int(now-t0):>4} L={load1:>4} f={fm:>3} gw={pstr}ms 110+={d110:>2} "
          f"sig={rf['sig']:>4} rate={rf['rate']:>5} rtry+={drtry:>3} fail+={dfail:>3} bcn={rf['bcn']:>2} "
          f"thr={thr} v={volt} T={temp}  {top}{flags}", flush=True)

context("END")
print(f"# gp-monitor done {time.strftime('%Y-%m-%d %H:%M:%S')}", flush=True)
