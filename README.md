# Generator Pi

Remote start/stop controller for a **Powermate PM9400E** generator via a Raspberry Pi, a relay module, and a simple web UI.

The Pi triggers the generator's electric start button through a GPIO-controlled relay. A Flask web server provides both a browser interface and a REST API for starting, stopping, and checking status from any device on the network.

## How It Works

```
Browser / Phone                Raspberry Pi                     Generator
     |                              |                               |
     |--- HTTP Basic Auth --------->|                               |
     |--- POST /api/start --------->|                               |
     |                              |-- GPIO relay ON (0.25s) ----->| (prime)
     |                              |-- wait 0.75s                  |
     |                              |-- GPIO relay ON (0.25s) ----->| (start)
     |                              |                               |
     |<-- { "success": true } ------|                               |
```

The generator cannot report its own state back, so status tracking is manual. After sending a start or stop command, verify the generator visually or audibly.

## Quick Start

SSH into the Pi and install prerequisites:

```bash
sudo apt update && sudo apt install -y git openssl python3 python3-flask python3-gpiozero python3-lgpio python3-cryptography
```

`python3-cryptography` is only needed for **Web Push notifications** (optional). The
installer also best-effort-installs the `pywebpush` library; if you don't want push you
can skip both — the controller runs fine without them. See
[Web Push notifications](#web-push-notifications).

Then clone and install:

```bash
git clone https://github.com/mrchrisneal/generatorpi.git ~/generatorpi && ~/generatorpi/setup.sh install
```

This will:
1. Clone the repo to `~/generatorpi`
2. Create a config file from the example and open it in `nano`
3. **Add your login credentials** (edit the `USER_` lines at the bottom, then save and exit)
4. Install and enable the systemd service (starts now and on every boot)

The web UI will be available at `https://<pi-hostname>:9400`. Your browser will show a certificate warning on first visit (self-signed) -- accept it once and you're set.

## Configuration

Everything is configured in `generator_control.env`. The installer creates this from the example file on first run.

### Credentials

Each user gets a line in the format `USER_<name>=<password>`:

```
USER_chris=mysecretpassword
USER_alex=hispassword
```

Plaintext passwords are **automatically hashed** on first startup. The file is rewritten in place so plaintext is never stored for long. After the first run, those lines will look like:

```
USER_chris=scrypt:32768:8:1$...
USER_alex=scrypt:32768:8:1$...
```

To add a new user later, just append a new `USER_` line with a plaintext password and restart the service.

### Application Settings

All settings have sensible defaults. Uncomment and change as needed:

| Setting | Default | Description |
|---------|---------|-------------|
| `RELAY_PIN` | `27` | GPIO pin connected to the relay module |
| `MAX_START_RETRIES` | `1` | Number of start attempts per command |
| `BUTTON_PRESS_DURATION` | `0.25` | Seconds the relay is held closed per press |
| `PRIME_DELAY` | `0.75` | Seconds between prime press and start press |
| `RETRY_DELAY` | `5.0` | Seconds between retry attempts |
| `HOST` | `0.0.0.0` | Web server bind address |
| `PORT` | `9400` | Web server port |
| `SSL_ENABLED` | `1` | `1` = HTTPS (auto-generates cert), `0` = plain HTTP |
| `SSL_CERT_DAYS` | `365` | Validity period for generated certs |
| `SSL_RENEW_DAYS` | `30` | Regenerate cert when fewer than this many days remain |
| `API_KEY_ENABLED` | `1` | `1` = accept API-key auth alongside Basic Auth, `0` = disable it (accepts `0/1/true/false/yes/no/on/off`) |
| `API_KEY` | *(auto)* | Machine-caller API key; **auto-generated** on first startup when enabled and empty (see [API authentication](#api-authentication)) |
| `RATE_LIMIT_MAX_FAILURES` | `5` | Failed login attempts before IP lockout |
| `RATE_LIMIT_LOCKOUT_SECONDS` | `300` | Lockout duration in seconds (5 min) |
| `RATE_LIMIT_CLEANUP_SECONDS` | `600` | Interval to purge expired lockouts |
| `RATE_LIMIT_MAX_TRACKED_IPS` | `1000` | Hard cap on tracked IPs (prevents memory exhaustion) |
| `LOG_FILE` | `generator_control.log` | Log file name (relative to script dir) |
| `LOG_MAX_BYTES` | `10485760` | Max log file size before rotation (10 MB) |
| `LOG_BACKUP_COUNT` | `3` | Number of rotated log files to keep |
| `LOG_LEVEL` | `INFO` | Logging verbosity (DEBUG, INFO, WARNING, ERROR) |
| `VAPID_PUBLIC_KEY` / `VAPID_PRIVATE_KEY` | *(auto)* | Web Push keypair; **auto-generated** on first startup when push is available (see [Web Push](#web-push-notifications)). Private key is secret. |
| `VAPID_SUBJECT` | `mailto:admin@localhost` | VAPID `sub` claim sent to push services |
| `FUEL_MONITOR_SECONDS` | `60` | How often the background monitor re-checks the fuel projection for a low-fuel push |

## API

All endpoints require authentication: a valid **API key OR HTTP Basic Auth**. The
API key is checked first; if it is absent or wrong, the request falls back to Basic
Auth (the browser login). A present-but-wrong key counts as a failed login attempt
and feeds the same IP lockout as a bad password.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Web UI (single self-contained page) |
| `POST` | `/api/start` | Start the generator |
| `POST` | `/api/stop` | Stop the generator |
| `GET` | `/api/status` | Get current state as JSON (legacy/HomeAssistant shape) |
| `GET` | `/api/state` | Full state snapshot for the web UI (state + fuel + alerts + `server_now`) |
| `POST` | `/api/set_running` | Manually override the tracked running state |
| `GET` | `/api/events` | Read the persistent event log (newest-first) |
| `POST` | `/api/fuel/reading` | Record an observed tank level (`{"level": %}`), refining the drain estimate |
| `POST` | `/api/fuel/rate` | Set the drain rate directly (`{"rate": %/hr}`) |
| `POST` | `/api/fuel/rate/reset` | Restore the drain rate to its default |
| `POST` | `/api/fuel/fill` | "Add gas": reset the baseline fill level (`{"level": %}`) |
| `POST` | `/api/alerts` | Update fuel/alert config (`{"enabled": bool, "threshold": 5–40, "fuel_enabled": bool}`) |
| `GET`  | `/sw.js` | Push service worker (no auth; no secrets) |
| `POST` | `/api/push/subscribe` | Register a browser's Web Push subscription |
| `POST` | `/api/push/unsubscribe` | Remove a push subscription (`{"endpoint": …}`) |
| `POST` | `/api/push/test` | Send a test push to all subscribed devices |

Basic Auth example (browser login credentials):

```bash
curl -k -u chris:mypassword https://generatorpi:9400/api/status
```

API-key example (query parameter):

```bash
curl -k "https://generatorpi:9400/api/status?key=<key>"
```

API-key example (header — preferred, see the security note below):

```bash
curl -k -H "X-API-Key: <key>" https://generatorpi:9400/api/status
```

### API authentication

Machine callers (e.g. HomeAssistant) authenticate with a static API key instead of
a username and password. The key may be passed either way:

- **Query parameter:** append `?key=<key>` to the URL.
- **Header:** send `X-API-Key: <key>`.

**Enable / disable.** API-key auth is controlled by `API_KEY_ENABLED` in
`generator_control.env` (default `1`). Set it to `0` to turn key auth off entirely
and require Basic Auth for every request.

**Auto-generation.** When key auth is enabled and `API_KEY` is empty, a strong random
key is generated and written back into `generator_control.env` on the first startup.
You do not have to invent one yourself — start the service once and read the key out
of the file.

**Rotation.** To roll the key, clear its value (leave `API_KEY=` with nothing after
it) or delete the `API_KEY=` line entirely, then restart the service:

```bash
sudo systemctl restart generator_control
```

A fresh key is generated and written back on startup. **After rotating, update
HomeAssistant's stored key to match** — the old key stops working immediately. If the
file somehow contains more than one `API_KEY=` line, the first non-empty value wins
and the extras are dropped.

### Event log

The controller keeps a **persistent, on-disk log** of notable events (starts, stops,
manual overrides, and rejected commands). It lives in a small SQLite database
(`events.db`, next to the script) so it **survives restarts**. The store is **capped at
10,000 rows** — once full, the oldest events are evicted automatically, so the file can
never grow without bound. (The cap and DB filename are configurable via `EVENT_LOG_MAX`
and `EVENT_LOG_DB` in `generator_control.env`.)

Each event has:

- `seq` — a **monotonic, ever-increasing integer ID** that is never reused, even after
  old rows are evicted. Use it as a stable cursor for paging.
- `ts` — a **unix timestamp** (float seconds) of when the event was recorded.
- `type` — one of `startup`, `start`, `start_complete`, `start_rejected`, `stop`,
  `set_running`, `fuel`, `push`.
- `message` — a short human-readable description.

**`GET /api/events`** returns events **newest-first**. Query parameters:

| Param | Default | Description |
|-------|---------|-------------|
| `limit` | `100` | How many events to return (clamped to `1`–`1000`). |
| `before` | — | Only events with `seq < before` — page **backwards** into older history. |
| `after` | — | Only events with `seq > after` — fetch what's **new since** a cursor you already hold. |

Response shape:

```json
{
  "events": [
    {"seq": 42, "ts": 1751692800.123, "type": "start", "message": "Start sequence initiated"}
  ],
  "latest_seq": 42
}
```

`latest_seq` is the highest `seq` in the store (or `0` if empty), so a client can cheaply
poll for new activity. Example — fetch the 100 most recent events:

```bash
curl -k -H "X-API-Key: <key>" "https://generatorpi:9400/api/events?limit=100"
```

Page backwards from the oldest event you've seen (`seq` = 42):

```bash
curl -k -H "X-API-Key: <key>" "https://generatorpi:9400/api/events?before=42"
```

### State snapshot

**`GET /api/state`** returns everything the web UI renders, in one call:

```json
{
  "running": false,
  "last_command": "stop",
  "last_start_time": "2026-07-05T19:31:00",
  "last_stop_time": "2026-07-05T20:04:00",
  "start_attempts": 1,
  "message": "Stop command sent",
  "current_run_started_at": null,
  "total_run_hours": 12.4,
  "fuel": {"fill_level": 100.0, "fill_run_hours": 8.0, "drain_rate": 6.4, "default_rate": 6.4},
  "alerts": {"alerts_on": true, "alert_threshold": 20, "fuel_enabled": true},
  "fuel_enabled": true,
  "push": {"supported": true, "vapid_public_key": "BJ…", "subscriptions": 2},
  "server_now": 1751745840.5
}
```

`server_now` is the server's unix clock; the UI aligns its live uptime / odometer to
it rather than the (possibly-skewed) browser clock. `/api/status` is retained
unchanged for HomeAssistant and other machine callers.

### Total runtime

The controller accumulates **lifetime run-hours** across every run. Each run's
elapsed time is banked into `total_run_hours` when it stops (whether via the stop
command or a manual "mark stopped"), and the value is **persisted** to a small kv
table in `events.db` so it survives restarts. The UI shows it on a mechanical
odometer that ticks live while running.

### Fuel projection

A lightweight **linear drain model** projects the tank level and warns before it runs
low. It assumes fuel drops at a roughly constant rate while the engine runs:

```
projected_level = fill_level − drain_rate × (total_run_hours − fill_run_hours)
```

- **Record an observed level** (`POST /api/fuel/reading {"level": 48}`) to refine the
  `drain_rate` — each reading is blended 50/50 with the running estimate, so more
  readings on one tank converge on the real consumption. Returns the new `drain_rate`.
- **Set the rate directly** (`POST /api/fuel/rate {"rate": 6.4}`) or **reset** it to the
  default (`POST /api/fuel/rate/reset`).
- **"Add gas"** (`POST /api/fuel/fill {"level": 100}`) resets the baseline fill to the
  entered %, marking the current run-hour as the new baseline; the drain rate is kept.
- **Low-fuel alerts** (`POST /api/alerts {"enabled": true, "threshold": 20}`): when the
  projected level reaches the threshold (5–40%), the UI shows a low-fuel banner. The
  fuel model + alert config are persisted like the run-hours total.

All fuel/alert mutations append a `fuel`-type event to the log.

### Web UI

The page at `/` is a **single self-contained file** — inline CSS + inline vanilla JS,
no framework, no build step, and **no external requests** (all icons are inline SVG),
so it loads instantly on a Pi and a phone under a strict Content-Security-Policy. It
presents an industrial control-panel aesthetic: a hero power switch (flip **up** to
start — with a safety confirmation — **down** to stop), a live current-run readout, the
total-runtime odometer, the event log (with infinite scroll), and two sliding drawers
for **Fuel Projection** and **Advanced** manual state overrides (which correct the
*tracked* state only and never touch the relay). It is keyboard-accessible and works on
phone, tablet, and desktop.

### Web Push notifications

The controller can send **Web Push notifications** to your phone/desktop so you're
alerted about the generator **even when no browser tab is open**. Notifications fire on:

- **Start** and **Stop** (relay commands *and* the manual "mark running/stopped").
- **Low fuel** — when the fuel projection crosses the alert threshold (edge-triggered:
  one push per crossing; it re-arms after you refuel or the level recovers). A background
  monitor evaluates this on the server, so the low-fuel push works with **no tab open**.
- A manual **test notification** (a button in the Advanced drawer).

Push is **entirely optional** — if it's unavailable the in-page low-fuel **banner** still
works whenever a tab is open, and the app degrades gracefully.

#### Requirements (read this — push has real prerequisites)

1. **The `pywebpush` library** on the Pi. The installer best-effort-installs it; to do it
   manually:
   ```bash
   sudo apt install -y python3-cryptography
   sudo pip3 install --break-system-packages pywebpush
   sudo systemctl restart generator_control
   ```
   Without it, push is simply unavailable server-side (the app still runs). The startup
   log prints `Web Push: available` or `unavailable`.

2. **A TRUSTED secure context in the browser — this is the common gotcha.** Browsers only
   register the service worker that receives pushes on a *secure context*:
   - **`https://` with a certificate the browser trusts**, **or**
   - **`http://localhost` / `http://127.0.0.1`** (treated as secure) — only useful when
     browsing *on the Pi itself*.

   This controller ships a **self-signed** certificate. On the phone/laptop you actually
   use, that cert is **not trusted by default**, so the service worker may **refuse to
   register** and push can't be enabled. To use push you must either:
   - **Trust the self-signed cert on each device** (import/accept it so the origin is no
     longer flagged "not secure"). Behavior varies by browser — after accepting the cert,
     Chrome/Firefox will generally register the worker; some versions still block it. Or
   - **Use a proper certificate** for the Pi's hostname (e.g. a cert from your own LAN CA,
     or a real domain + Let's Encrypt if the Pi is reachable). This is the reliable path.

   If the origin isn't a trusted secure context, the **PUSH NOTIFICATIONS** toggle shows
   *"Push unavailable … using in-page alerts"* and you simply rely on the banner. Nothing
   breaks.

3. **Outbound HTTPS from the Pi.** The Pi sends each push through the browser vendor's push
   service (Google FCM / Mozilla / Apple). The Pi needs outbound internet; a firewall that
   blocks it will prevent delivery.

4. **Notification permission** granted in the browser (you'll be prompted when enabling).

5. **Browser support.** Chrome, Edge, and Firefox (desktop + Android) support Web Push.
   **iOS/iPadOS** support it only in **Safari 16.4+ and only when the site is added to the
   Home Screen as a web app** (Share → *Add to Home Screen*, then open it from the icon);
   a normal Safari tab cannot subscribe.

#### Enabling push (per device)

Open the **Advanced** drawer → flip **PUSH NOTIFICATIONS** on → allow the permission
prompt. Each browser/device subscribes itself (the toggle reflects *this* device). Use
**SEND TEST NOTIFICATION** to confirm delivery. Flip it off to unsubscribe that device.
The helper text under the toggle tells you the current state: *enabled*, *available —
flip to enable*, *blocked* (permission denied), or *unavailable* (no secure context /
library).

#### Fuel-projection toggle

The Advanced drawer also has a **FUEL PROJECTION** switch (default **on**). Turning it off
hides the entire Fuel Projection panel and suppresses the low-fuel monitor, banner, and
pushes — useful if you don't want fuel tracking. It's a shared setting (affects everyone).

#### VAPID keys (push identity)

On first startup — when push is available — a **VAPID keypair** is generated and written
into `generator_control.env` (`VAPID_PUBLIC_KEY`, `VAPID_PRIVATE_KEY`, `VAPID_SUBJECT`).
The **private key is secret** and, like the API key, the settings file is forced to `0600`
and never served. **To rotate:** clear both key values (or delete both lines) and restart;
a fresh pair is generated. Rotation invalidates existing browser subscriptions — clients
re-subscribe automatically on their next visit.

#### Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| Toggle says *"Push not configured on the server"* | `pywebpush` isn't installed, or no VAPID key. Install it (above) and restart. |
| Toggle says *"Push unavailable … using in-page alerts"* | Not a trusted secure context. Trust the cert or use a real one (see requirement #2). |
| Toggle says *"Notifications are blocked"* | You denied the browser permission. Re-allow it in the browser's site settings. |
| Enabled, but no test notification arrives | Check the Pi has outbound internet; check the browser allows notifications; on iOS, add the site to the Home Screen first. |
| Pushes stop after a while | Subscriptions can expire; the server prunes dead ones automatically. Just re-enable the toggle to re-subscribe. |

### Security

- The settings file (`generator_control.env`) holds secret material (the API key, the
  VAPID push private key, and password hashes), so it is forced
  to **`0600` (owner read/write only)** and is **never served over HTTP** — Flask's
  static file serving is disabled, so no file on disk is reachable through the web
  server.
- The service **fails fast on startup** and refuses to run if the settings file has
  wrong ownership or permissions, is a symlink, or is not readable/writable — closing
  off tampered-config attacks. (These checks are root-aware and won't false-positive
  when the service runs as root.)
- The Werkzeug access log is suppressed so a `?key=` in a request URL never lands in
  the logs.
- **In a browser, use the login prompt (Basic Auth) — do NOT put `?key=` in the URL.**
  The `?key=` / `X-API-Key` path is for machine callers like HomeAssistant. When you
  do use a key programmatically, **prefer the `X-API-Key` header over the query
  string** where possible: query strings leak more easily via browser history, proxy
  logs, and referrers.

## Management

### Service Control

```bash
./setup.sh status      # Check if installed, running, and boot-enabled
./setup.sh install     # Install, enable on boot, and start
./setup.sh reinstall   # Same as install, but non-interactive (no editor prompts)
./setup.sh uninstall   # Stop, disable, and remove the service
```

### Restarting the Service

After any config change (adding users, changing settings), restart to pick up the changes:

```bash
sudo systemctl restart generator_control
```

### Adding a User

1. Edit the config file:
   ```bash
   nano ~/generatorpi/generator_control.env
   ```
2. Add a line with the new username and password:
   ```
   USER_newperson=theirpassword
   ```
3. Restart the service (the plaintext password is auto-hashed on startup):
   ```bash
   sudo systemctl restart generator_control
   ```

### Removing a User

1. Edit the config file and delete the `USER_` line for that user
2. Restart the service:
   ```bash
   sudo systemctl restart generator_control
   ```

### Changing a Password

1. Edit the config file and replace the user's hash with a new plaintext password:
   ```
   USER_chris=mynewpassword
   ```
2. Restart -- the plaintext is auto-hashed on startup:
   ```bash
   sudo systemctl restart generator_control
   ```

### Changing the Port or Other Settings

1. Edit the config file and uncomment/change the value:
   ```bash
   nano ~/generatorpi/generator_control.env
   ```
2. Restart:
   ```bash
   sudo systemctl restart generator_control
   ```

### Updating to Latest Version

Pull the latest code and restart (can be run locally or over SSH):

```bash
~/generatorpi/update.sh
```

From another machine:

```bash
ssh pi@generatorpi "~/generatorpi/update.sh"
```

### Logs

```bash
# Application log (rotating file)
tail -f ~/generatorpi/generator_control.log

# Systemd journal
journalctl -u generator_control -f

# Last 50 lines
journalctl -u generator_control -n 50 --no-pager
```

### Checking if It's Running

```bash
sudo systemctl status generator_control
```

Or from another machine:

```bash
ssh pi@generatorpi "sudo systemctl status generator_control"
```

## Running the tests

The test suite runs off-device (no GPIO or Pi required — the hardware is mocked).
From the repo root, create a virtualenv, install the dev dependencies, and run
pytest with coverage:

```bash
python3 -m venv .venv
.venv/bin/pip install -r tests/requirements-dev.txt
.venv/bin/python -m pytest --cov=generator_control
```

The current suite is **255 tests at 99% coverage**.

## Hardware

- **Raspberry Pi** (any model with GPIO)
- **SunFounder relay module** (or equivalent, LOW-triggered)
- **Powermate PM9400E** generator with electric start

### Wiring

| Pi GPIO | Relay Module | Notes |
|---------|-------------|-------|
| GPIO 27 | CH1 IN | Signal (configurable via `RELAY_PIN`) |
| 5V | VCC | Relay power |
| GND | GND | Common ground |

The relay's normally-open (NO) contacts are wired in parallel with the generator's start/stop button.

## Credits & License

Built by **[Alex Neal](https://neal.tools)** and **[Chris Neal](https://neal.media)**.

Source: <https://github.com/mrchrisneal/generatorpi>

Licensed under the **GNU Affero General Public License v3.0** — see [`LICENSE`](LICENSE)
or <https://www.gnu.org/licenses/agpl-3.0.html>. The AGPL's network-use clause means
that if you run a modified version of this controller as a network service, you must
offer its corresponding source to users of that service.
