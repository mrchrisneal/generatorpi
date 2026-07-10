## 1.5.2
Released on July 10, 2026

- **SEC:** Web Push subscription endpoints are now checked against DNS rebinding — a subscription whose hostname *resolves* to a private, loopback, link-local, or otherwise non-routable address is rejected (previously only literal internal IPs were caught), and a hostname that fails to resolve is rejected fail-closed. This closes a server-side request-forgery vector where a crafted endpoint could point the server's push delivery at an internal service.
- **FEAT:** The Event Log now attributes each command to the user who issued it — start/stop, manual "mark running/stopped", the run-hours override, fuel changes, the test push, restart, and factory reset all record "(by \<user>)", so the durable audit trail shows *who* did *what*, not just what happened.
- **FEAT:** When a browser reports that notifications are unavailable on that device (blocked in site settings, unsupported, or a non-HTTPS context), it now records a durable diagnostic entry in the Event Log — so you can see *why* pushes aren't arriving without opening the browser's developer tools. The browser only sends a fixed status code and the server supplies the wording, so nothing typed by a client ever reaches the log.
- **FEAT:** Startup now logs the service's boot-autostart status — the configured preference plus the actual systemd "is-enabled" state — so you can confirm from the log whether GeneratorPi will come back on its own after a reboot, without SSHing in to run `systemctl`.
- **FIX:** The update dialog now scrolls when it is taller than the screen (instead of being clipped when centered) and is about 30% wider, so long update notices — especially a manual-install blocker on a small phone screen — are fully readable.
- **FIX:** When an update is blocked because a manual-install-only version sits between your version and the latest, the notice now shows only the *latest* blocker's reason instead of stacking every intermediate one.
- **FIX:** After an update is staged, the "staged and verified" banner now reflects what actually happened during the checks — green only when the staging was completely clean, amber when there were warnings, and red (with the counts) when there were any errors — instead of always showing the green "ready to apply" state.
- **FIX:** Cancelling ("revert") a staged update now shows a single confirmation and settles cleanly on "Update aborted by user." — a race could previously flash a second, stale dialog after the revert.
- **FIX:** The installer's post-restart health probe waits longer (about 15 seconds) for the web server to bind before warning, so a normal slow start on the Raspberry Pi no longer produces a spurious warning during install/update.

---

## 1.5.1
Released on July 9, 2026

- **FIX:** The installer (`setup.sh`) now validates the in-app updater's scoped `sudoers` rule **as root** before installing it — `visudo` needs root privileges to run its syntax check, so on a **fresh** install the previous version could silently skip the rule, leaving the in-app updater unable to restart the service without a password. Existing installs are unaffected (their rule was already in place); found and fixed during the on-device 1.5.0 rollout.
- **FIX:** The installer stages the generated `systemd` unit under a `.service`-suffixed temporary name so the advisory `systemd-analyze verify` check runs cleanly instead of emitting a spurious "Invalid argument" warning during install.

---

## 1.5.0
Released on July 9, 2026

- **CHORE:** The **`genpi/` package split** begun in 1.4.0 is now **complete** — the former ~6,760-line `generator_control.py` monolith is fully decomposed into ~20 focused, eagerly-imported submodules (configuration, logging, the inline UI, the SQLite event store, shared state, SSL certificate management, rate-limiting, authentication, the relay, generator control, fuel projection, system metrics, the server lifecycle, the self-updater, the Flask app, and four route blueprints), with `genpi/__init__.py` reduced from the bulk of the app to a small aggregator. Behavior is **byte-identical** — same UI, REST API, and relay/auth/fuel logic (verified module by module) — and test coverage stays at **100%**.
- **CHORE:** The "all application code is loaded into RAM at startup" guarantee is now **explicit and enforced**: importing the package fails fast if any submodule is missing, startup logs `Eager-import OK: N modules resident` as a self-check, and a test asserts every packaged file is listed in the release manifest so a module can never be silently dropped from an update.
- **CHORE:** Like 1.4.0, this release must be installed **manually, not via the in-app Update button** — because it is such a large internal restructure, the in-app updater intentionally blocks it (showing an "install manually" notice with the reason) and you update by pulling and re-running `./setup.sh reinstall` (or `./update.sh`). After this release, the in-app updater applies future versions normally again.
- **CHORE:** The manual updater (`./update.sh`) is now self-healing and safe to run from any device state: it snapshots the current install to `backups/` first, resets the checkout to **exactly** match the release (your credentials, event database, and TLS certificates are never touched), re-runs the full setup, health-checks the app, and **automatically rolls back** to the previous version if anything goes wrong. The installer (`./setup.sh`) was hardened alongside it — it backs up and validates the systemd unit before installing, stages and validates the scoped sudoers rule before it touches the system, health-checks the service (failing closed so an update can roll back), and degrades with clear warnings on non-Raspberry-Pi hosts.

---

## 1.4.0
Released on July 9, 2026

- **CHORE:** GeneratorPi's single ~6,760-line `generator_control.py` is being split into an eagerly-imported **`genpi/` package** (a long-planned maintainability effort). This release lands the package foundation: the app now runs as `python3 -m genpi`, every module is loaded into RAM at startup, and the package is pre-compiled at install (`compileall`) for a faster first boot. There are **no behavior changes** — identical UI, REST API, and relay/auth/fuel logic (verified byte-identical) — and test coverage stays at 100%.
- **CHORE:** Updating to this release needs a **reinstall, not the in-app Update button.** Because the systemd entrypoint changed (to `python3 -m genpi`), the in-app updater — which only restarts the existing service — would relaunch the old code and report a false success. Update by pulling and re-running `./setup.sh reinstall` (or `./update.sh`); after this one release, the in-app updater works normally again.
- **CHORE:** Hardening for the new layout: the self-updater now byte-compiles **every** staged `.py` before swapping (not just the main file), and the release manifest enumerates the whole `genpi/` package automatically, so a newly added module can never be silently left out of an update.

---

## 1.3.4
Released on July 9, 2026

- **FIX:** The self-updater log now colours the WHOLE warning/error line (amber for warnings, red for errors) instead of only the `[TAG]`, so a problem stands out. Missing dependencies in the Stage-1 check read as clear `WARNING:` / `ERROR:` lines, and the hint tells you to run the shown apt command over SSH and restart the application to resolve. Cosmetic only — no behaviour change.
