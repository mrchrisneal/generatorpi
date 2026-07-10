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

---

## 1.3.3
Released on July 9, 2026

- **FIX:** Web Push notifications now work on Raspberry Pi OS. The app previously relied on the `pywebpush` library, which has no Raspberry Pi OS package and can't be installed on the Pi's pip-free system Python, so push silently never worked on-device. It now sends notifications itself using three apt-available libraries — **py-vapid** (VAPID signing), **http-ece** (aes128gcm payload encryption), and **requests** — so the device stays 100% apt-only. Install them with `sudo apt install python3-py-vapid python3-http-ece python3-requests`; a VAPID keypair is auto-generated on first start.
- **FIX:** The push status now tells you *why* it's off instead of a misleading blanket "no VAPID keys" — it distinguishes the server libraries not being installed, no VAPID keypair yet, and an invalid key, each with the right guidance and a link to the setup guide.
- **FEAT:** The in-app updater now checks the release's declared dependencies during Stage 1 and, if any are missing on the device, lists them with a copy-able `sudo apt install …` one-liner so you can install them before applying. It never auto-installs anything — the update swaps files + restarts, so run the shown command (or `./setup.sh reinstall`) to add new dependencies.
- **FEAT:** The update log now ends each stage with a colored count of any warnings (yellow) and errors (red) encountered, so a problem can't be missed, and scrolls to the newest lines at each stage boundary.
- **SEC:** Web Push requests now refuse HTTP redirects (defense in depth against a redirector endpoint) and use a bounded time-to-live, so an alert still arrives if your phone was briefly offline.
- **CHORE:** The updater's in-app changelog renders cleaner — no preamble, a horizontal rule between releases, and no mid-sentence line breaks. Test coverage of `generator_control.py` stays at 100%.

---

## 1.3.2
Released on July 8, 2026

- **FEAT:** New **TOTAL RUNTIME** control in Settings ▸ SYSTEM lets you manually set (override) the lifetime run-hours odometer — for example, to match the engine's own hour meter — and it is saved to disk. Like the MARK RUNNING / MARK STOPPED overrides, it corrects the **tracked** value only: it never cranks or stops the engine and never touches the relay. The fuel projection is preserved across the change (the tank gauge doesn't jump), and setting it while the generator is running re-baselines the current run so the odometer reads your value immediately.
- **CHORE:** New tests cover the override end-to-end — the run-hours math, disk persistence across a restart, input validation, authentication + CSRF, and a relay-safety check — keeping app line coverage at 100%.
