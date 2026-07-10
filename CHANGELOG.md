# Changelog

Full, canonical history of GeneratorPi releases. The in-app updater downloads only the most recent
releases from **CHANGELOG-RECENT.md** (generated from this file by `tools/changelog.py`). Format:
each release is `## X.Y.Z` with `Released on Month D, YYYY` directly below, and its changes are tagged
— **FEAT** (new), **PERF** (speed), **FIX** (bug), **SEC** (security), **DOCS**, **CHORE**.

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

---

## 1.3.1
Released on July 8, 2026

- **FIX:** Eliminated an iOS/Safari-only scroll jump. Parked at the bottom of the page with the Fuel Projection or Settings drawer open, every background poll (~every 3s) nudged the page upward and clipped the footer; desktop browsers were never affected. The entire live-render path is now *idempotent* — it writes to the DOM only when a value actually changed — which removes the trigger completely (and does less work each poll, a small win on the Pi's single core).
- **FIX:** Rocker switch renders correctly on older WebKit (desktop Safari / older iPadOS). The 3D top cap and bottom lip use CSS 3D transforms that old WebKit flattens, which exposed the switch's black background as voids above and below the red face. The exposed area is now backed by the button colour, and the top gets a flat trapezoidal bevel highlight on engines that can't render the real 3D cap; modern Safari, Chrome, and Firefox are visually unchanged.
- **CHORE:** Test coverage of `generator_control.py` is now **100%**, and CI hard-fails below 98% (`--cov-fail-under=98`) so coverage can never silently regress.
- **CHORE:** The local dev launcher (`dev.sh`) byte-compiles the app before every (re)start and refuses to launch on a syntax error, so a restart never leaves the dev box down on broken code.

### Root-cause & debugging notes — the iOS scroll jump

The jump was WebKit-specific and left almost no fingerprints. On-device instrumentation showed the page's total height never changed (`scrollHeight` constant), no element ever resized (even sampled once per animation frame), no scroll API was ever called, and the visual viewport never moved — yet `scrollY` still shifted by tens of pixels on each poll. That combination ruled out every "obvious" cause in turn: not a reflow, not the fixed/sticky headers, not the 3D switch's compositing layer, not a CSS animation, and not the existing scroll-anchor net (disabling it changed nothing). The real mechanism: WebKit has no CSS scroll anchoring, and it treats *any* DOM mutation during a poll — even a no-op, such as rewriting a text node to the identical string or re-setting an attribute to its current value — as a change worth a style/layout recalculation, and that recalculation nudges the scroll position when the user is pinned to the bottom of the page.

We isolated it by bisecting the page's timers on a live device: clearing the ~3-second state-poll interval stopped the jump outright, while the 1-second clock tick (which re-renders far less) never triggered it — proving the culprit was the *volume* of redundant writes the state poll made every cycle, not any single element or value. WebKit's own Timelines recording confirmed a burst of style/layout invalidations on each poll with no accompanying size change. The fix routes every render-path write through small guarded helpers (`txt` / `clsIf` / `attrIf` / `styIf` / `htmlIf` / `propIf`) that skip the assignment when the value is unchanged; with nothing mutating while the generator sits idle, there is no recalculation for WebKit to react to. Verified clean on desktop WebKit and modern iOS (iOS 26). A small residual jump can still occur on very old iOS WebKit (e.g. iPadOS 16.7) — documented as a known issue.

---

## 1.3.0
Released on July 8, 2026

- **PERF:** Big CPU drop on the Pi. Web-UI HTTP Basic-auth verification (scrypt) was re-run on *every* request, so an open browser pinned the Raspberry Pi Zero 2 W's core near 100%. Successful verifications are now cached in memory for a short TTL — with a browser connected and polling, CPU fell from ~95% to ~2.5% (measured on hardware). Wrong passwords still re-run the hash (brute-force protection intact) and a password change invalidates the cache immediately.
- **PERF/FEAT:** New HTTP server (**cheroot**) with real keep-alive and built-in TLS — an HTTPS poll reuses one TLS session instead of a fresh handshake every request. Falls back to the previous server automatically if cheroot isn't installed.
- **FEAT:** Bundled **gp-monitor**, an on-device Wi-Fi + performance diagnostic tool (in `tools/`), documented on the wiki (Wi-Fi Diagnostics).
- **DOCS:** New wiki pages (Architecture & Performance, Wi-Fi Diagnostics); a README "Under the Hood" section, Requirements list, and expanded Features; auto-updating version badge.
- **CHORE:** `setup.sh` installs/validates dependencies via apt (the Pi's system Python has no pip); the changelog is split into the full history (this file) plus a short `CHANGELOG-RECENT.md` that the updater downloads; tag-driven release automation.

---

## 1.2.3

- **Cleaner Stage-2 update log**: the systemd update path's progress lines now match the rest of the update terminal — no more `[gp-update]` prefix or raw ISO timestamps, and correct coloring. Each step reads as a dim indented `… ok` child under its bright section header, and the run ends with `[DONE] Application successfully updated to vX.Y.Z!`.
- **Settings polish**: the section headers (MANUAL OVERRIDE, SYSTEM, LOG VIEWER, RESET) are brighter and slightly larger with clearer spacing between sections, and the push-notification button is now labelled "TEST NOTIFICATION".

---

## 1.2.2

- **Much faster HTTPS on the Pi**: three changes cut per-request time on a Raspberry Pi Zero 2 W from seconds to well under a second under load. (1) The self-signed certificate now uses an **ECDSA P-256** key instead of RSA-2048 — the TLS handshake is far cheaper on a weak ARM core. (2) The server now handles requests **concurrently** (threaded) instead of one at a time, so a slow handshake no longer blocks every other request. (3) The frontend poll queue now **ages** waiting requests so a constantly-refreshing `state` poll can no longer starve `events`/`system` — every endpoint gets its turn. Existing installs regenerate the cert as ECDSA on next start (browsers will prompt once to trust the new self-signed certificate).

---

## 1.2.1

- **Update timing**: the update log now reports how long the apply took — e.g. "Update finished in
  4.2 seconds" (or "Update failed after N seconds" on a rollback) — right before the final result,
  on both the in-process and systemd update paths.

---

## 1.2.0

- **Documentation**: a full GitHub wiki (installation, configuration, hardware & wiring, REST API,
  self-updater, TLS & security, Home Assistant integration, fuel projection, troubleshooting, FAQ),
  a slimmed README that links into it, and status badges (build, coverage, license, version).
- **CI pipeline**: GitHub Actions runs the full test suite on every push, regenerates the update
  manifest, and refreshes the coverage badge automatically.
- **Updater**: preserves the executable bit on shell scripts across an update swap, and shows a
  loading spinner beside "Loading changelog…" in the update modal.
- Consolidates the 1.1.x self-updater hardening — reliable non-systemd restart, detailed two-stage
  progress with a live "Restarting" view, and robust API-based restart detection — into this release.

---

## 1.1.3

- **UI polish**: the RESTART APP button is now amber (red is reserved for Factory Reset), and in
  the update banner only the version string links to the GitHub releases page — the surrounding
  status text is a plain label and "Update now" opens the in-app updater.
- **Quality**: test coverage raised to 98% (575 tests) with broad new coverage of the self-updater
  flow, the restart/serve paths, and error branches.

---

## 1.1.2

- **Force update (dev/testing)**: when already up-to-date, the footer now offers a "Force update"
  link, and the browser console exposes `gpForceUpdate()` — both re-run the full update flow against
  the current release without needing a version bump, which makes exercising the update UX easy.
- Footer polish: the update status text ("Version up-to-date") is dimmed to match the rest of the
  footer, so only actual links stand out.

---

## 1.1.1

- **Update restart UX**: while the app restarts, the log is hidden in favor of a large rotating
  "Restarting" spinner and an elapsed timer; restart completion is now detected robustly through
  the API — the state endpoint reports the running version and the process start time, so the page
  knows exactly when the app has fully restarted. Delayed restarts surface inline notices ("still
  updating…", and past five minutes an unresponsive warning). Minor log-wording cleanups.

---

## 1.1.0

- **Reliable self-update restart (critical)**: on non-systemd installs the updater now releases
  its listening socket before re-exec (plus `SO_REUSEADDR` and a startup bind-retry), so the app
  reliably comes back on the new version instead of failing to rebind its port and staying down.
- **Detailed Stage-2 progress**: applying an update now streams a full, itemised log — each file
  swapped (old→new size), on-disk hash re-verification, and the restart handoff — matching the
  detail of the download/verify stage, with a clear "Application successfully updated to vX.Y.Z".
- **Clearer update UX**: a large "Restarting" spinner while the app comes back (with a delayed
  "still updating" notice and, past 5 minutes, an unresponsive warning), and a success/failure
  banner above the Dismiss button on the result screen.
- **Bounded update time**: an update that wedges is force-rolled-back after 10 minutes (was 30).

---

## 1.0.3

- **Footer "Update now" opens the in-app updater directly**: the update banner no longer
  links out to the GitHub releases page — clicking "Update now" (or the banner) spawns the
  in-app update modal, where the changelog and the guided update flow live.

---

## 1.0.2

- **In-app self-updater hardening**: two-stage go/no-go update with a live progress
  terminal, staged verify-before-swap (SHA-256 + compile), atomic file swap with backup
  and automatic rollback, a 30-minute apply watchdog, and env-controlled service behaviour
  (`SERVICE_ENABLED` / `AUTOSTART`). A generous central client request timeout keeps the UI
  responsive on slow links.

---

## 1.0.1

- **Version + update checking**: the footer shows the installed version and, when a
  newer release is published, a "vX.Y.Z available! → Update now" banner with a pulsing
  caution icon. Clicking the version does a manual check (up-to-date / checking / failed
  states). The server also checks hourly and pushes a one-time notification.
- **SYSTEM drawer**: in-memory performance history with stylized COMPUTE / LOAD / VITALS /
  LINK charts, collapsible via the header caret, latest readings shown when collapsed.
- **EVENT LOG ↔ APP LOG**: toggle (in Settings ▸ Log Viewer) between the curated event
  store and a live tail of the raw application log, with an incremental delta feed, a
  routine-HTTP-traffic display filter, and scroll-pause.
- **Settings ▸ Reset**: reset local preferences, restart the app, and factory-reset
  (wipes event store + logs + run-hours/fuel/alert state — never your env or certs), each
  behind a confirmation.
- Spinners on all async controls, client↔server latency indicator, columnar
  `/api/system/history` on a single serial poll queue, and persisted UI state.

---

## 1.0.0

- Initial release: remote start/stop of a Powermate generator via a Pi GPIO relay,
  tracked run-state, fuel projection, low-fuel alerts, Web Push notifications, and the
  HomeAssistant integration.
