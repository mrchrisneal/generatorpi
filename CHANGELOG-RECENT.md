# Changelog (recent)

The 5 most recent GeneratorPi releases -- this short file is what the in-app updater downloads
on a version check. It is GENERATED from the full history in [CHANGELOG.md](CHANGELOG.md) by
`tools/changelog.py`; do NOT edit it by hand.

## 1.3.0
Released on July 8, 2026

- **PERF:** Big CPU drop on the Pi. Web-UI HTTP Basic-auth verification (scrypt) was re-run on *every*
  request, so an open browser pinned the Raspberry Pi Zero 2 W's core near 100%. Successful
  verifications are now cached in memory for a short TTL — with a browser connected and polling, CPU
  fell from ~95% to ~2.5% (measured on hardware). Wrong passwords still re-run the hash (brute-force
  protection intact) and a password change invalidates the cache immediately.
- **PERF/FEAT:** New HTTP server (**cheroot**) with real keep-alive and built-in TLS — an HTTPS poll
  reuses one TLS session instead of a fresh handshake every request. Falls back to the previous
  server automatically if cheroot isn't installed.
- **FEAT:** Bundled **gp-monitor**, an on-device Wi-Fi + performance diagnostic tool (in `tools/`),
  documented on the wiki (Wi-Fi Diagnostics).
- **DOCS:** New wiki pages (Architecture & Performance, Wi-Fi Diagnostics); a README "Under the Hood"
  section, Requirements list, and expanded Features; auto-updating version badge.
- **CHORE:** `setup.sh` installs/validates dependencies via apt (the Pi's system Python has no pip);
  the changelog is split into the full history (this file) plus a short `CHANGELOG-RECENT.md` that the
  updater downloads; tag-driven release automation.
## 1.2.3

- **Cleaner Stage-2 update log**: the systemd update path's progress lines now match the rest of the
  update terminal — no more `[gp-update]` prefix or raw ISO timestamps, and correct coloring. Each
  step reads as a dim indented `… ok` child under its bright section header, and the run ends with
  `[DONE] Application successfully updated to vX.Y.Z!`.
- **Settings polish**: the section headers (MANUAL OVERRIDE, SYSTEM, LOG VIEWER, RESET) are brighter
  and slightly larger with clearer spacing between sections, and the push-notification button is now
  labelled "TEST NOTIFICATION".
## 1.2.2

- **Much faster HTTPS on the Pi**: three changes cut per-request time on a Raspberry Pi Zero 2 W from
  seconds to well under a second under load. (1) The self-signed certificate now uses an **ECDSA
  P-256** key instead of RSA-2048 — the TLS handshake is far cheaper on a weak ARM core. (2) The
  server now handles requests **concurrently** (threaded) instead of one at a time, so a slow
  handshake no longer blocks every other request. (3) The frontend poll queue now **ages** waiting
  requests so a constantly-refreshing `state` poll can no longer starve `events`/`system` — every
  endpoint gets its turn. Existing installs regenerate the cert as ECDSA on next start (browsers
  will prompt once to trust the new self-signed certificate).
## 1.2.1

- **Update timing**: the update log now reports how long the apply took — e.g. "Update finished in
  4.2 seconds" (or "Update failed after N seconds" on a rollback) — right before the final result,
  on both the in-process and systemd update paths.
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
