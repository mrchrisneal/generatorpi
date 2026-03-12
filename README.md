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
sudo apt update && sudo apt install -y git python3 python3-flask python3-gpiozero python3-lgpio
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

The web UI will be available at `http://<pi-hostname>:9400`.

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
| `RATE_LIMIT_MAX_FAILURES` | `5` | Failed login attempts before IP lockout |
| `RATE_LIMIT_LOCKOUT_SECONDS` | `300` | Lockout duration in seconds (5 min) |
| `RATE_LIMIT_CLEANUP_SECONDS` | `600` | Interval to purge expired lockouts |
| `LOG_FILE` | `generator_control.log` | Log file name (relative to script dir) |
| `LOG_MAX_BYTES` | `10485760` | Max log file size before rotation (10 MB) |
| `LOG_BACKUP_COUNT` | `3` | Number of rotated log files to keep |
| `LOG_LEVEL` | `INFO` | Logging verbosity (DEBUG, INFO, WARNING, ERROR) |

## API

All endpoints require HTTP Basic Auth.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Web UI |
| `POST` | `/api/start` | Start the generator |
| `POST` | `/api/stop` | Stop the generator |
| `GET` | `/api/status` | Get current state as JSON |
| `POST` | `/api/set_running` | Manually override the running state |

Example:

```bash
curl -u chris:mypassword http://generatorpi:9400/api/status
```

## Management

### Service Control

```bash
./setup.sh status      # Check if installed, running, and boot-enabled
./setup.sh install     # Install, enable on boot, and start
./setup.sh uninstall   # Stop, disable, and remove the service
```

### Updating

Pull the latest code and restart:

```bash
~/generatorpi/update.sh
```

Or from another machine:

```bash
ssh pi@generatorpi "~/generatorpi/update.sh"
```

### Logs

```bash
# Application log (rotating file)
tail -f ~/generatorpi/generator_control.log

# Systemd journal
journalctl -u generator_control -f
```

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
