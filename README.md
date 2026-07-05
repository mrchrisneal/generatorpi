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
sudo apt update && sudo apt install -y git openssl python3 python3-flask python3-gpiozero python3-lgpio
```

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

## API

All endpoints require authentication: a valid **API key OR HTTP Basic Auth**. The
API key is checked first; if it is absent or wrong, the request falls back to Basic
Auth (the browser login). A present-but-wrong key counts as a failed login attempt
and feeds the same IP lockout as a bad password.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Web UI |
| `POST` | `/api/start` | Start the generator |
| `POST` | `/api/stop` | Stop the generator |
| `GET` | `/api/status` | Get current state as JSON |
| `POST` | `/api/set_running` | Manually override the running state |

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

### Security

- The settings file (`generator_control.env`) holds secret material, so it is forced
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

The current suite is **132 tests at 99% coverage**.

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
