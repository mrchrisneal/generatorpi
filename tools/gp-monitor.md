# gp-monitor.py — Raspberry Pi Wi-Fi / performance diagnostic

A single on-device script that samples **every** likely cause of Wi-Fi flakiness on a Raspberry Pi
on one timeline, so you can prove *what's actually wrong* instead of guessing. It runs on the Pi and
logs to a local file, so it keeps recording **even while the network is down** — you read the log
after the fact.

Built while chasing intermittent stalls/dropouts on a Pi Zero W; useful for any Pi with a
Broadcom/`brcmfmac` Wi-Fi chip (Zero W/2 W, Pi 3, Pi 4, etc.).

## Quick start

```bash
# Copy it to the Pi, then run a 5-minute capture, detached so it survives an SSH drop:
setsid sudo python3 gp-monitor.py 300 > /home/pi/gp-monitor.log 2>&1 < /dev/null &

# Read results (any time — during or after the run; it flushes every line):
cat /home/pi/gp-monitor.log
```

- **Run as root** (`sudo`) — it needs `dmesg` and `vcgencmd`.
- Argument 1 = duration in seconds (default `420`). Samples every 5 s.
- Foreground quick look: `sudo python3 gp-monitor.py 60`
- Different interface: `GP_IFACE=wlan1 sudo python3 gp-monitor.py 120`

## What each column means

The samples print as a table — a header row, a `---` divider, then one row per tick:

```
clock     t(s)   load  freeMB  gw(ms)  110+   sig    rate  rtry+  fail+    bcn      thr   volt   temp  top-2 CPU
```

| Column | Meaning |
|---|---|
| `clock` / `t(s)` | wall-clock time · seconds since the run started |
| `load` / `freeMB` | 1-minute load average · `MemAvailable` in MB |
| `gw(ms)` | ping to the default gateway from the Pi (`LOSS` = timed out) — the Pi's own link health |
| `110+` | new `brcmfmac` `-110` control-channel timeouts since last sample (driver/firmware jam) |
| `sig` | Wi-Fi signal, dBm (`-1` = the query itself couldn't get through = link fully dead now) |
| `rate` | TX data rate, Mbit/s — **collapsing rate at good signal = airtime congestion** |
| `rtry+` / `fail+` | TX retries / failed frames since last sample |
| `bcn` | beacon-loss counter |
| `thr` | `vcgencmd` throttle flag — **`0x0` = healthy**, anything else = under-voltage/thermal |
| `volt` / `temp` | core voltage · SoC temperature (°C) |
| `top-2 CPU` | the two busiest processes this tick, then any flags |

Flags (appended to a row): `<<<STALL` (ping >1 s or lost) · `<<<THROTTLE/UV!` (power/thermal!) · `<<<-110storm` (≥3 driver timeouts this tick).

The START/END **context** blocks print as tables too: a **link** summary (SSID with its **channel**, frequency, BSSID, signal, rate) and a **neighbour scan sorted by channel** so co-channel congestion is obvious at a glance.

## How to read it (rule things out with the data)

| What you see during a stall | Conclusion |
|---|---|
| `thr` ≠ `0x0` / voltage dips | **Power/PSU** — get a better 5 V/2.5 A supply + short thick cable |
| high `L`/CPU% | **Compute contention** — nice/cap the hog, remove background load |
| `sig` drops with the stall | **Range/obstruction** — move the Pi / add an antenna |
| `sig` steady **but** `rate` craters + retries climb | **2.4 GHz airtime congestion** (see AP fixes below) |
| `110+` bursts (≥3) | **Driver/firmware control jam** — `roamoff`, reduce station polling |
| deauth/disassoc in the context block | **AP is kicking the client** — check AP inactivity/PMF/band-steering |

---

## Config areas that actually move Pi Wi-Fi reliability

A checklist of the knobs worth touching, roughly high-to-low leverage. (Back up `config.txt` /
`cmdline.txt` before editing — a typo there = no-boot, recoverable only by editing the SD on another
machine.)

### Pi side

1. **Free RAM from the idle CMA/GPU reserve** — `/boot/firmware/config.txt`
   `dtoverlay=vc4-kms-v3d,cma-64` · `gpu_mem=16` · `camera_auto_detect=0` (headless).
   A 256 MB CMA pool on a 512 MB board can starve the kernel and make it OOM-kill the Wi-Fi driver;
   `cma-64` hands ~192 MB back. *(Reboot required.)*
2. **Enable the memory cgroup** so `MemoryMax=` on services is actually enforced —
   `/boot/firmware/cmdline.txt`, append `cgroup_enable=memory cgroup_memory=1` (keep it ONE line).
   Then cap a leaky app via a systemd drop-in: `[Service]` `MemoryMax=256M`. *(Reboot required.)*
3. **Disable Wi-Fi power-save** — drop-in `/etc/NetworkManager/conf.d/wifi-powersave-off.conf`:
   `[connection]` / `wifi.powersave = 2`; also pin on the profile:
   `nmcli con mod <conn> 802-11-wireless.powersave 2`.
4. **Stop firmware roam scans** (single-AP networks) — `/etc/modprobe.d/brcmfmac.conf`:
   `options brcmfmac roamoff=1`. *(Reboot / module reload.)*
5. **Disable Bluetooth** (it shares the one antenna) — `dtoverlay=disable-bt` in `config.txt`, or
   live: `rfkill block bluetooth` + `systemctl disable --now bluetooth`.
6. **Set the Wi-Fi country** correctly — `raspi-config nonint do_wifi_country US` (unlocks the proper
   channel set + TX power).
7. **Reduce background scanning** — NetworkManager runs wpa_supplicant `bgscan` (off-channel scans
   that briefly stall data). Pinning `nmcli con mod <conn> 802-11-wireless.bssid <AP-MAC>` disables
   roaming scans (only helps a single fixed AP; note it also disables roaming).
8. **Give the network stack CPU priority** on a single-core Pi — systemd drop-ins on CPU hogs:
   `Nice=10`, `CPUWeight=`, `CPUQuota=` (so nothing starves the `brcmf_wq` Wi-Fi worker).
9. **Tame periodic timers** that spike CPU/network — reschedule/mask `apt-daily`,
   `apt-daily-upgrade`, `man-db` (e.g. pin them to 3 AM with an `OnCalendar` drop-in).
10. **Check power** — `vcgencmd get_throttled` (want `0x0`); under-voltage silently corrupts the
    SDIO Wi-Fi bus. Use a solid 5 V/2.5 A supply and a short, thick cable.
11. **Antenna** — the Pi Zero W's PCB antenna is weak; the U.FL external-antenna mod (the *original*
    Zero W is the easy one — reposition a 0-ohm resistor) hugely improves link margin.

### Access-point / router side (often the biggest lever, and free)

12. **Fixed 2.4 GHz channel of 1, 6, or 11** (never "auto", never 2–5/7–10). Pick the emptiest with a
    Wi-Fi analyzer. These are the only non-overlapping channels.
13. **Put co-located APs/SSIDs on different channels** (e.g. two of your own networks both on ch 1 =
    they steal each other's airtime).
14. **20 MHz channel width** on 2.4 GHz (not 40 MHz/auto).
15. **Disable band-steering / "smart connect"** — it shoves simple clients around.
16. **Disable 802.11ax (Wi-Fi 6) on 2.4 GHz** (keep b/g/n) — old single-stream chips do worse with it.

### How to confirm a fix

Re-run `gp-monitor.py` after each change and compare the `gw`/`rate`/`STALL` columns before vs after —
same tool, apples-to-apples.

---

## Example run

A representative 60-second capture (`sudo python3 gp-monitor.py 60`). This is the tool's real output —
**network identifiers (SSIDs, BSSID) have been replaced with placeholders** (`MyNetwork`,
`MyNetwork-IoT`, `Neighbor-A`…`Neighbor-H`, `AA:BB:CC:DD:EE:FF`); nothing else is edited.

The link was healthy across this window — `gw(ms)` stays in the single digits, `thr=0x0` and `volt=1.35`
never move (**power is fine**), and `sig` holds at ~-60 dBm (**signal is fine**). The story here is in
the **neighbour scan**: the Pi is on **channel 11**, which it shares with two other strong networks — a
classic setup for intermittent **2.4 GHz airtime congestion** under load. When a stall *does* hit you'd
see `gw(ms)` jump to `LOSS` / four digits with a `<<<STALL` flag while `sig`/`thr`/`volt` hold steady —
the fingerprint that rules out power, range, and compute in one glance.

```text
# gp-monitor start 2026-07-08 17:15:04  iface=wlan0 gw=192.168.1.1 HZ=100 dur=60s step=5s
# ---- START CONTEXT ----
# LINK          VALUE
# ------------  -----------------
# SSID          MyNetwork
# Channel       11
# Frequency     2462.0 MHz
# BSSID (AP)    AA:BB:CC:DD:EE:FF
# Signal        -60 dBm
# RX / TX rate  19.5 / 57.7 Mbit
# NM state      connected:full
# neighbours (sorted by channel) -- co-channel congestion check:
#   CHAN  SIGNAL  SSID
#   ----  ------  -------------
#      1      60  --
#      1      59  MyNetwork
#      1      15  --
#      1      14  --
#      6      65  --
#      6      65  --
#      6      47  Neighbor-A
#      6      24  --
#      7      40  Neighbor-D
#      8      77  Neighbor-C
#      8      59  Neighbor-D
#      9      85  Neighbor-B
#     11      70  MyNetwork
#     11      67  MyNetwork-IoT
#     11      14  Neighbor-H
# recent deauth/disconnect (journal, confounder check):
# recent -110 (dmesg):
clock      t(s)   load  freeMB  gw(ms)  110+   sig    rate  rtry+  fail+    bcn      thr   volt   temp  top-2 CPU
--------  -----  -----  ------  ------  ----  ----  ------  -----  -----  -----  -------  -----  -----  ---------
17:15:11      5   0.62     264      21     0   -60    57.7     -1      0     -1      0x0   1.35   39.0  avahi-daemon:4% python3:3%
17:15:17     10   0.65     264       8     0   -61    57.7     -1      0     -1      0x0   1.35   38.5  python3:3% avahi-daemon:1%
17:15:22     15   0.60     264      10     0   -60    57.7     -1      0     -1      0x0   1.35   39.0  python3:3% avahi-daemon:2%
17:15:27     20   0.55     264       7     0   -60    52.0     -1      0     -1      0x0   1.35   39.0  python3:3% python3:2%
17:15:33     26   0.51     264       5     0   -60    57.7     -1      0     -1      0x0   1.35   39.0  python3:3% tailscaled:2%
17:15:38     31   0.47     264       6     0   -61    57.7     -1      0     -1      0x0   1.35   39.0  python3:3% tailscaled:2%
17:15:43     36   0.43     264       8     0   -60    58.5     -1      0     -1      0x0   1.35   38.5  python3:3% tailscaled:2%
17:15:49     42   0.39     264      14     0   -60    65.0     -1      0     -1      0x0   1.35   39.0  python3:3% tailscaled:1%
17:15:54     47   0.36     264       6     0   -60    65.0     -1      0     -1      0x0   1.35   39.0  python3:3% avahi-daemon:2%
17:15:59     52   0.33     264       6     0   -60    65.0     -1      0     -1      0x0   1.35   39.0  python3:3% tailscaled:2%
17:16:05     58   0.31     264       5     0   -61    65.0     -1      0     -1      0x0   1.35   39.0  python3:3% avahi-daemon:2%
17:16:10     63   0.36     264      20     0   -60    65.0     -1      0     -1      0x0   1.35   39.0  avahi-daemon:4% python3:3%
# ---- END CONTEXT ----
# LINK          VALUE
# ------------  -----------------
# SSID          MyNetwork
# Channel       11
# Frequency     2462.0 MHz
# BSSID (AP)    AA:BB:CC:DD:EE:FF
# Signal        -60 dBm
# RX / TX rate  13.0 / 65.0 Mbit
# NM state      connected:full
# neighbours (sorted by channel) -- co-channel congestion check:
#   CHAN  SIGNAL  SSID
#   ----  ------  -------------
#      1      59  --
#      1      49  MyNetwork
#      1      25  Neighbor-G
#      1      15  --
#      1      14  --
#      6      65  --
#      6      65  --
#      6      47  Neighbor-A
#      6      25  Neighbor-E
#      6      24  --
#      7      37  Neighbor-D
#      8      74  Neighbor-C
#      8      60  Neighbor-D
#      9      85  Neighbor-B
#     11      70  MyNetwork
#     11      67  MyNetwork-IoT
#     11      14  Neighbor-H
# recent deauth/disconnect (journal, confounder check):
# recent -110 (dmesg):
# gp-monitor done 2026-07-08 17:16:12
```

Every column holds its width, so the header, the `---` divider, and every row line up — including `LOSS`
rows, and on larger Pis where free-MB is four digits or Wi-Fi rates exceed 1000. The context blocks
render as tables too: the **link** table shows the SSID *with its channel*, and the **neighbours** table
is **sorted by channel** so co-channel congestion jumps out.

*(`rtry+`/`fail+`/`bcn` show `-1` when the station-stats query itself is momentarily blocked by a stall —
itself a signal that the link is jammed at that instant.)*
