# GeneratorPi

[![CI](https://github.com/mrchrisneal/generatorpi/actions/workflows/ci.yml/badge.svg)](https://github.com/mrchrisneal/generatorpi/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/mrchrisneal/generatorpi/main/.github/badges/coverage.json)](../../wiki/Installation)
[![Python](https://img.shields.io/badge/python-3.11+-blue?logo=python&logoColor=white)](https://www.python.org)
[![Flask](https://img.shields.io/badge/Flask-black?logo=flask)](https://flask.palletsprojects.com)
[![Raspberry Pi](https://img.shields.io/badge/Raspberry%20Pi-A22846?logo=raspberrypi&logoColor=white)](https://www.raspberrypi.com)
[![License](https://img.shields.io/github/license/mrchrisneal/generatorpi)](LICENSE)
[![Version](https://img.shields.io/github/v/release/mrchrisneal/generatorpi?label=version&color=blue)](https://github.com/mrchrisneal/generatorpi/releases)

GeneratorPi is a self-hosted, secure remote starter for the Powermate PM9400E generator. Driven by a Raspberry Pi and a relay, it exposes a responsive web UI and a REST API. Features include automated linear fuel tracking, Web Push notifications, auto-hashing user credentials, and an integrated self-updater.

<p align="center">
  <img src="https://raw.githubusercontent.com/mrchrisneal/generatorpi/main/docs/screenshots/web-ui.png" alt="GeneratorPi web UI — industrial control panel showing RUNNING status, the hero power switch, a current-run timer and total-runtime odometer, system registers, a live event log, and collapsible Fuel Projection and System modules" width="640">
</p>

> [!CAUTION]
> This system cannot auto-detect the real generator state. Always verify the unit visually and audibly before relying on this readout.

> [!WARNING]
> This software is provided **as-is**, with no warranty, and is under **active development** — expect changes, rough edges, and breaking updates. **Use caution**, test thoroughly on your own hardware, and never rely on it as your only safeguard around a running generator.

<details>
<summary><b>📸 More screenshots</b></summary>

<p align="center">
  <img src="https://raw.githubusercontent.com/mrchrisneal/generatorpi/main/docs/screenshots/fuel-projection.png" alt="Fuel Projection module — tank gauge with level, drain rate, and time-to-empty projections" width="520"><br>
  <em>Fuel Projection — live drain-rate model with time-to-empty estimates</em>
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/mrchrisneal/generatorpi/main/docs/screenshots/system-metrics.png" alt="System module — CPU/memory and load charts plus temperature and Wi-Fi link sensors" width="520"><br>
  <em>System metrics — CPU/memory and load charts, temperature and Wi-Fi link</em>
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/mrchrisneal/generatorpi/main/docs/screenshots/updater-staged.png" alt="Update modal — staged and verified, ready to apply" width="380">
  <img src="https://raw.githubusercontent.com/mrchrisneal/generatorpi/main/docs/screenshots/updater-complete.png" alt="Update modal — update completed successfully" width="380"><br>
  <em>One-click self-updater — verified against the manifest, then applied in place</em>
</p>

</details>

## Features

* **Remote Power Control**: MOMENTARY relay pulses mimic physical engine start/stop button actions.
* **Predictive Fuel Tracking**: Linear drain model monitors fuel remaining and estimates running hours to empty.
* **Web Push Alerts**: Out-of-browser notifications deliver status updates and low-fuel alerts directly to your devices.
* **Security & Isolation**: Automatic hashing of credential configurations, fail-fast permission checks, and silenced access logging.
* **Monitoring & Event History**: Real-time metrics (CPU temperature, throttling state, load, Wi-Fi signal) alongside a persistent, SQLite-backed event log that's capped to keep disk usage bounded.
* **Tuned for Single-Core Hardware**: A single-flight, priority-with-fairness poll queue keeps control-critical status fresh without ever dogpiling the weak core, while an ECDSA P-256 certificate with threaded serving cuts TLS handshakes from *seconds* to sub-second on a Raspberry Pi Zero 2 W.
* **One-Click Self-Updater**: In-app updates verified against a manifest (SHA-256), applied by an atomic file swap with automatic backup, rollback-on-failure, and a live two-stage progress terminal.
* **Home Assistant Integration**: Exposes the generator as a switch plus sensors, ready to drop into dashboards and automations.

---

## Quick Start

SSH into the Pi and install the prerequisite system packages:

```bash
sudo apt update && sudo apt install -y git openssl python3 python3-flask python3-gpiozero python3-lgpio python3-cryptography python3-cheroot
```

Clone the repository and run the installation script:

```bash
git clone https://github.com/mrchrisneal/generatorpi.git ~/generatorpi && ~/generatorpi/setup.sh install
```

The script copies the configuration template, opens the credential editor, and registers the background systemd service. Access the interface at `https://<pi-hostname>:9400`.

---

## Under the Hood

GeneratorPi is tuned for the hardware most people already have on hand — a **Raspberry Pi Zero 2 W**: one modest CPU core and an onboard Wi-Fi radio that can be temperamental. Nearly every non-obvious design choice falls out of that single constraint:

* The browser talks to the Pi through a **single-flight poll queue** that runs one request at a time (so the weak core is never dogpiled), always prioritizes the generator's live status, coalesces redundant polls, and *ages* waiting jobs so a fast-refreshing status poll can never starve the heavier history/event fetches.
* TLS uses an **ECDSA P-256** certificate with threaded serving, because an RSA-2048 handshake on a single Arm core cost whole seconds under load — this took per-request time from *seconds* to sub-second.
* Because the box is usually headless and remote, the **self-updater** is built to be crash-safe: verify against a SHA-256 manifest *before* touching anything, swap files atomically, and roll back automatically if any step fails — it is designed to never leave the app unreachable.

For the full rationale and every optimization in depth, see **[Architecture & Performance](../../wiki/Architecture-&-Performance)** in the wiki. A companion on-device diagnostic, [`gp-monitor.py`](tools/gp-monitor.md), samples every likely cause of Pi Wi-Fi flakiness on one timeline so you can prove *what's* wrong instead of guessing.

---

## Requirements

**Hardware:** a Raspberry Pi (tested on the Pi Zero 2 W), a relay on a GPIO pin, and the Powermate
PM9400E generator — see [Hardware & Wiring](../../wiki/Hardware-&-Wiring).

**Software** (Raspberry Pi OS; installed via `apt` — the system Python has no `pip`):

| Package | Purpose |
|---|---|
| `python3` (3.11+) | runtime |
| `python3-flask` | web framework / REST API |
| `python3-gpiozero`, `python3-lgpio` | GPIO relay control |
| `python3-cryptography` | TLS / password hashing |
| `python3-cheroot` | HTTP server with keep-alive + TLS (app falls back to a no-keep-alive server if absent) |
| `python3-pywebpush` *(optional)* | Web Push notifications |
| `openssl` | self-signed certificate generation |

`setup.sh install` validates and installs these automatically. Versions are also pinned in
`requirements.txt` (for CI/dev via pip); on the Pi they come from `apt`.

---

## 📖 Documentation

For detailed information, refer to the project wiki pages:

* **Setup & Wiring**:
  * [Installation](../../wiki/Installation) — Installation steps, service control, and testing.
  * [Hardware & Wiring](../../wiki/Hardware-&-Wiring) — Relay pins and electrical layout.
* **System Operations**:
  * [Configuration](../../wiki/Configuration) — Complete settings reference and user additions.
  * [Web UI Guide](../../wiki/Web-UI-Guide) — Interface control panels, manual overrides, and metrics.
  * [Fuel Projection & Alerts](../../wiki/Fuel-Projection-and-Alerts) — Consumption modeling and alert calibration.
  * [Web Push Notifications](../../wiki/Web-Push-Notifications) — Browser configurations and requirements.
* **Developer Reference**:
  * [REST API](../../wiki/REST-API) — API authentication protocols and CSRF safety.
  * [API Reference](../../wiki/API-Reference) — Request and response JSON schema reference.
  * [Home Assistant Integration](../../wiki/Home-Assistant-Integration) — Wire GeneratorPi in as a switch and sensors.
  * [Self Updater](../../wiki/Self-Updater) — Automated updates, checksum checks, and backup staging.
* **Under the Hood**:
  * [Architecture & Performance](../../wiki/Architecture-&-Performance) — Why it's built this way + every optimization (the poll queue, TLS, self-updater).
  * [Wi-Fi Diagnostics](../../wiki/Wi-Fi-Diagnostics) — The bundled `gp-monitor.py` tool for diagnosing Pi Wi-Fi flakiness.
* **Support**:
  * [TLS & Security](../../wiki/TLS-&-Security) — Certificate behaviors and access safety rules.
  * [Troubleshooting](../../wiki/Troubleshooting) — System logs, common failures, and fixes.
  * [FAQ](../../wiki/FAQ) — System limits and design answers.

---

## Credits & License

Built by [Chris Neal](https://neal.media) and [Alex Neal](https://neal.tools).

Source code is available at <https://github.com/mrchrisneal/generatorpi>.

Licensed under the **GNU Affero General Public License v3.0** — see [LICENSE](LICENSE) or <https://www.gnu.org/licenses/agpl-3.0.html> for details.
The 3D power-switch styling is adapted from [empty-snail-69 by Nawsome](https://uiverse.io/Nawsome/empty-snail-69) under the MIT License — see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
