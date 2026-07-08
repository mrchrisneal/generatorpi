# Changelog

All notable changes to GeneratorPi. The in-app updater shows the entry for the
release it's about to install.

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

## 1.1.3

- **UI polish**: the RESTART APP button is now amber (red is reserved for Factory Reset), and in
  the update banner only the version string links to the GitHub releases page — the surrounding
  status text is a plain label and "Update now" opens the in-app updater.
- **Quality**: test coverage raised to 98% (575 tests) with broad new coverage of the self-updater
  flow, the restart/serve paths, and error branches.

## 1.1.2

- **Force update (dev/testing)**: when already up-to-date, the footer now offers a "Force update"
  link, and the browser console exposes `gpForceUpdate()` — both re-run the full update flow against
  the current release without needing a version bump, which makes exercising the update UX easy.
- Footer polish: the update status text ("Version up-to-date") is dimmed to match the rest of the
  footer, so only actual links stand out.

## 1.1.1

- **Update restart UX**: while the app restarts, the log is hidden in favor of a large rotating
  "Restarting" spinner and an elapsed timer; restart completion is now detected robustly through
  the API — the state endpoint reports the running version and the process start time, so the page
  knows exactly when the app has fully restarted. Delayed restarts surface inline notices ("still
  updating…", and past five minutes an unresponsive warning). Minor log-wording cleanups.

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

## 1.0.3

- **Footer "Update now" opens the in-app updater directly**: the update banner no longer
  links out to the GitHub releases page — clicking "Update now" (or the banner) spawns the
  in-app update modal, where the changelog and the guided update flow live.

## 1.0.2

- **In-app self-updater hardening**: two-stage go/no-go update with a live progress
  terminal, staged verify-before-swap (SHA-256 + compile), atomic file swap with backup
  and automatic rollback, a 30-minute apply watchdog, and env-controlled service behaviour
  (`SERVICE_ENABLED` / `AUTOSTART`). A generous central client request timeout keeps the UI
  responsive on slow links.

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

## 1.0.0

- Initial release: remote start/stop of a Powermate generator via a Pi GPIO relay,
  tracked run-state, fuel projection, low-fuel alerts, Web Push notifications, and the
  HomeAssistant integration.
