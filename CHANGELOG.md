# Changelog

All notable changes to GeneratorPi. The in-app updater shows the entry for the
release it's about to install.

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
