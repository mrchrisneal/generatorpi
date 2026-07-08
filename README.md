# GeneratorPi

[![CI](https://github.com/mrchrisneal/generatorpi/actions/workflows/ci.yml/badge.svg)](https://github.com/mrchrisneal/generatorpi/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/mrchrisneal/generatorpi/main/.github/badges/coverage.json)](../../wiki/Installation)
[![Python](https://img.shields.io/badge/python-3.11+-blue?logo=python&logoColor=white)](https://www.python.org)
[![Flask](https://img.shields.io/badge/Flask-black?logo=flask)](https://flask.palletsprojects.com)
[![Raspberry Pi](https://img.shields.io/badge/Raspberry%20Pi-A22846?logo=raspberrypi&logoColor=white)](https://www.raspberrypi.com)
[![License](https://img.shields.io/github/license/mrchrisneal/generatorpi)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.2.0-blue)](https://github.com/mrchrisneal/generatorpi/releases)

GeneratorPi is a self-hosted, secure remote starter for the Powermate PM9400E generator. Driven by a Raspberry Pi and a relay, it exposes a responsive web UI and a REST API. Features include automated linear fuel tracking, Web Push notifications, auto-hashing user credentials, and an integrated self-updater.

<p align="center">
  <img src="https://raw.githubusercontent.com/mrchrisneal/generatorpi/main/docs/screenshots/web-ui.png" alt="GeneratorPi web UI — industrial control panel with status annunciator, hero power switch, current-run readout, total-runtime odometer, event log, and collapsible Fuel Projection and Advanced drawers" width="640">
</p>

## Features

* **Remote Power Control**: MOMENTARY relay pulses mimic physical engine start/stop button actions.
* **Predictive Fuel Tracking**: Linear drain model monitors fuel remaining and estimates running hours to empty.
* **Web Push Alerts**: Out-of-browser notifications deliver status updates and low-fuel alerts directly to your devices.
* **Security & Isolation**: Automatic hashing of credential configurations, fail-fast permission checks, and silenced access logging.
* **System Metrics Annunciator**: Live monitoring of CPU temperatures, throttled states, load, and Wi-Fi signal quality.
* **Persistent Event Log**: SQLite-backed history, capped to keep disk usage bounded.

---

## Quick Start

SSH into the Pi and install the prerequisite system packages:

```bash
sudo apt update && sudo apt install -y git openssl python3 python3-flask python3-gpiozero python3-lgpio python3-cryptography
```

Clone the repository and run the installation script:

```bash
git clone https://github.com/mrchrisneal/generatorpi.git ~/generatorpi && ~/generatorpi/setup.sh install
```

The script copies the configuration template, opens the credential editor, and registers the background systemd service. Access the interface at `https://<pi-hostname>:9400`.

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
