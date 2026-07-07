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
