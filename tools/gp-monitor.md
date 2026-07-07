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

```
clock t=<sec> L=<load> f=<freeMB> gw=<ping>ms 110+=<n> sig=<dBm> rate=<Mbit>
      rtry+=<n> fail+=<n> bcn=<n> thr=<hex> v=<volts> T=<tempC>  <top-2 CPU procs>  <<<flags
```

| Field | Meaning |
|---|---|
| `gw` | ping to the default gateway from the Pi (`LOSS` = timed out) — the Pi's own link health |
| `110+` | new `brcmfmac` `-110` control-channel timeouts since last sample (driver/firmware jam) |
| `sig` | Wi-Fi signal, dBm (`-1` = the query itself couldn't get through = link fully dead now) |
| `rate` | TX data rate, Mbit/s — **collapsing rate at good signal = airtime congestion** |
| `rtry+/fail+` | TX retries / failed frames since last sample |
| `thr` | `vcgencmd` throttle flag — **`0x0` = healthy**, anything else = under-voltage/thermal |
| `v`,`T` | core voltage / SoC temperature |

Flags: `<<<STALL` (ping >1 s or lost) · `<<<THROTTLE/UV!` (power/thermal!) · `<<<-110storm`.

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

## Example run (verbatim)

A real 90-second capture from a Pi Zero W in a congested 2.4 GHz environment
(`sudo python3 gp-monitor.py 90`). This is exactly what the tool prints — nothing edited.

Read the story in the columns: `thr=0x0` and `v=1.35` never move (**power is fine**), `sig` holds at
~-62/-63 dBm (**signal is fine**), CPU load is low, and there are no deauth events — yet `gw` swings from
single-digit milliseconds to `LOSS`. That combination is the fingerprint of **2.4 GHz airtime congestion**,
corroborated by the START/END neighbour scans showing the AP (`ASQUARED`) sharing channel 1 with other
strong networks.

```text
# gp-monitor start 2026-07-07 03:47:15  iface=wlan0 gw=192.168.1.1 HZ=100 dur=90s step=5s
# ---- START CONTEXT ----
# iw link: Connected to 22:0b:8b:50:54:55 (on wlan0) SSID: ASQUARED freq: 2412.0 signal: -63 dBm rx bitrate: 43.3 MBit/s tx bitrate: 43.3 MBit/s dtim period: 1 beacon int: 100
# nmcli: connected:full
# 2.4GHz neighbours (CHAN SIGNAL SSID) -- co-channel congestion check:
#   1     62      ASQUARED
#   1     67      ASIOT
#   6     69      --
#   6     70      --
#   8     69      WTC#E_6C
#   9     80      WTC#E_2.4GEXT
#   11    69      --
#   11    72      ASIOT
#   ...(15+ networks across the band)...
# recent deauth/disconnect (journal, confounder check):
# recent -110 (dmesg):
#   [ 7102.735121] ieee80211 phy0: brcmf_proto_bcdc_query_dcmd: brcmf_proto_bcdc_msg failed w/status -110
# cols: clock t load free(MB) gwPing 110+ sig rate rtry+ fail+ bcn THROTTLE volt temp  top2cpu
03:47:23 t=   5 L=0.59 f=273 gw=    68ms 110+= 0 sig= -63 rate= 43.3 rtry+= -1 fail+=  0 bcn=-1 thr=0x0 v=1.35 T=33.6  tailscaled:4% python3:3%
03:47:28 t=  10 L=0.54 f=273 gw=     6ms 110+= 0 sig= -63 rate= 43.3 rtry+= -1 fail+=  1 bcn=-1 thr=0x0 v=1.35 T=33.6  python3:3% tailscaled:2%
03:47:36 t=  15 L=0.53 f=273 gw=LOSS ms 110+= 0 sig= -64 rate= 43.3 rtry+= -1 fail+=  0 bcn=-1 thr=0x0 v=1.35 T=33.1  python3:3% tailscaled:3% <<<STALL
03:47:41 t=  23 L=0.65 f=273 gw=    95ms 110+= 0 sig= -62 rate= 52.0 rtry+= -1 fail+=  0 bcn=-1 thr=0x0 v=1.35 T=33.6  python3:2% tailscaled:1%
03:47:47 t=  28 L=0.60 f=273 gw=    99ms 110+= 0 sig= -63 rate= 39.0 rtry+= -1 fail+=  0 bcn=-1 thr=0x0 v=1.35 T=33.6  python3:3% tailscaled:2%
03:47:52 t=  33 L=0.55 f=273 gw=    67ms 110+= 0 sig= -63 rate= 28.8 rtry+= -1 fail+=  0 bcn=-1 thr=0x0 v=1.35 T=33.6  python3:3% tailscaled:2%
03:47:58 t=  39 L=0.59 f=273 gw=   372ms 110+= 0 sig= -63 rate= 26.0 rtry+= -1 fail+=  0 bcn=-1 thr=0x0 v=1.35 T=32.6  python3:3% tailscaled:2%
03:48:04 t=  45 L=0.54 f=273 gw=  1262ms 110+= 0 sig= -63 rate= 28.8 rtry+= -1 fail+=  0 bcn=-1 thr=0x0 v=1.35 T=32.6  tailscaled:3% python3:3% <<<STALL
03:48:12 t=  51 L=0.45 f=273 gw=LOSS ms 110+= 0 sig= -62 rate= 28.8 rtry+= -1 fail+=  0 bcn=-1 thr=0x0 v=1.35 T=32.6  python3:2% avahi-daemon:2% <<<STALL
03:48:17 t=  59 L=0.42 f=273 gw=    90ms 110+= 0 sig= -62 rate= 39.0 rtry+= -1 fail+=  0 bcn=-1 thr=0x0 v=1.35 T=32.6  python3:2% tailscaled:1%
03:48:25 t=  64 L=0.38 f=273 gw=LOSS ms 110+= 0 sig= -62 rate= 43.3 rtry+= -1 fail+=  0 bcn=-1 thr=0x0 v=1.35 T=32.6  tailscaled:4% python3:3% <<<STALL
03:48:31 t=  71 L=0.33 f=273 gw=  1340ms 110+= 2 sig= -63 rate= 43.3 rtry+= -1 fail+=  0 bcn=-1 thr=0x0 v=1.35 T=33.1  tailscaled:4% python3:2% <<<STALL
03:48:37 t=  78 L=0.30 f=273 gw=    31ms 110+= 0 sig= -62 rate= 43.3 rtry+= -1 fail+=  0 bcn=-1 thr=0x0 v=1.35 T=32.6  python3:2% tailscaled:1%
03:48:45 t=  83 L=0.27 f=273 gw=LOSS ms 110+= 0 sig= -62 rate= 43.3 rtry+= -1 fail+=  0 bcn=-1 thr=0x0 v=1.35 T=32.6  tailscaled:11% python3:3% <<<STALL
03:48:53 t=  92 L=0.23 f=273 gw=LOSS ms 110+= 0 sig= -62 rate= 43.3 rtry+= -1 fail+=  0 bcn=-1 thr=0x0 v=1.35 T=32.6  tailscaled:4% python3:2% <<<STALL
# ---- END CONTEXT ----
# 2.4GHz neighbours: channel 1 still shared by ASQUARED(64) + ASIOT(55); band packed 6/7/8/9/11
# recent deauth/disconnect (journal, confounder check):    <-- none (client stayed associated)
# gp-monitor done 2026-07-07 03:48:57
```

*(`rtry+`/`fail+`/`bcn` show `-1` when the station-stats query itself is momentarily blocked by the stall —
itself a signal that the link is jammed at that instant.)*
