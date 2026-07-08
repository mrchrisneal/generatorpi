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
  <img src="https://raw.githubusercontent.com/mrchrisneal/generatorpi/main/docs/screenshots/web-ui.png" alt="GeneratorPi web UI — industrial control panel with status annunciator, hero power switch, current-run readout, total-runtime odometer, event log, and collapsible Fuel Projection and Advanced drawers" width="640">
</p>

## Features

* **Remote Power Control**: MOMENTARY relay pulses mimic physical engine start/stop button actions.
* **Predictive Fuel Tracking**: Linear drain model monitors fuel remaining and estimates running hours to empty.
* **Web Push Alerts**: Out-of-browser notifications deliver status updates and low-fuel alerts directly to your devices.
* **Security & Isolation**: Automatic hashing of credential configurations, fail-fast permission checks, and silenced access logging.
* **System Metrics Annunciator**: Live monitoring of CPU temperatures, throttled states, load, and Wi-Fi signal quality.
* **Persistent Event Log**: SQLite-backed history, capped to keep disk usage bounded.
* **Resilient Networking**: A single-flight, priority-with-fairness poll queue — purpose-built for one CPU core on a flaky Wi-Fi link — keeps control-critical status fresh, coalesces stale requests, and ages waiting jobs so nothing starves.
* **Fast HTTPS on Modest Hardware**: An ECDSA P-256 certificate plus concurrent (threaded) request handling cut TLS handshakes from *seconds* to sub-second on a Raspberry Pi Zero 2 W.
* **One-Click Self-Updater**: In-app updates verified against a manifest (SHA-256), applied by an atomic file swap with automatic backup, rollback-on-failure, and a live two-stage progress terminal.
* **Home Assistant Integration**: Exposes the generator as a switch plus sensors, ready to drop into dashboards and automations.

---

## Under the Hood

GeneratorPi is tuned for the hardware most people already have on hand — a **Raspberry Pi Zero 2 W**: one modest CPU core and an onboard Wi-Fi radio that can be temperamental. Nearly every non-obvious design choice falls out of that single constraint:

* The browser talks to the Pi through a **single-flight poll queue** that runs one request at a time (so the weak core is never dogpiled), always prioritizes the generator's live status, coalesces redundant polls, and *ages* waiting jobs so a fast-refreshing status poll can never starve the heavier history/event fetches.
* TLS uses an **ECDSA P-256** certificate with threaded serving, because an RSA-2048 handshake on a single Arm core cost whole seconds under load — this took per-request time from *seconds* to sub-second.
* Because the box is usually headless and remote, the **self-updater** is built to be crash-safe: verify against a SHA-256 manifest *before* touching anything, swap files atomically, and roll back automatically if any step fails — it is designed to never leave the app unreachable.

For the full rationale and every optimization in depth, see **[Architecture & Performance](../../wiki/Architecture-&-Performance)** in the wiki. A companion on-device diagnostic, [`gp-monitor.py`](tools/gp-monitor.md), samples every likely cause of Pi Wi-Fi flakiness on one timeline so you can prove *what's* wrong instead of guessing.

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
