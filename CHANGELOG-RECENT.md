# Changelog (recent)

The 5 most recent GeneratorPi releases -- this short file is what the in-app updater downloads
on a version check. It is GENERATED from the full history in [CHANGELOG.md](CHANGELOG.md) by
`tools/changelog.py`; do NOT edit it by hand.

## 1.3.1
Released on July 8, 2026

- **FIX:** Eliminated an iOS/Safari-only scroll jump. Parked at the bottom of the page with the Fuel
  Projection or Settings drawer open, every background poll (~every 3s) nudged the page upward and
  clipped the footer; desktop browsers were never affected. The entire live-render path is now
  *idempotent* — it writes to the DOM only when a value actually changed — which removes the trigger
  completely (and does less work each poll, a small win on the Pi's single core).
- **FIX:** Rocker switch renders correctly on older WebKit (desktop Safari / older iPadOS). The 3D top
  cap and bottom lip use CSS 3D transforms that old WebKit flattens, which exposed the switch's black
  background as voids above and below the red face. The exposed area is now backed by the button colour,
  and the top gets a flat trapezoidal bevel highlight on engines that can't render the real 3D cap;
  modern Safari, Chrome, and Firefox are visually unchanged.
- **CHORE:** Test coverage of `generator_control.py` is now **100%**, and CI hard-fails below 98%
  (`--cov-fail-under=98`) so coverage can never silently regress.
- **CHORE:** The local dev launcher (`dev.sh`) byte-compiles the app before every (re)start and refuses
  to launch on a syntax error, so a restart never leaves the dev box down on broken code.

### Root-cause & debugging notes — the iOS scroll jump

The jump was WebKit-specific and left almost no fingerprints. On-device instrumentation showed the
page's total height never changed (`scrollHeight` constant), no element ever resized (even sampled once
per animation frame), no scroll API was ever called, and the visual viewport never moved — yet `scrollY`
still shifted by tens of pixels on each poll. That combination ruled out every "obvious" cause in turn:
not a reflow, not the fixed/sticky headers, not the 3D switch's compositing layer, not a CSS animation,
and not the existing scroll-anchor net (disabling it changed nothing). The real mechanism: WebKit has no
CSS scroll anchoring, and it treats *any* DOM mutation during a poll — even a no-op, such as rewriting a
text node to the identical string or re-setting an attribute to its current value — as a change worth a
style/layout recalculation, and that recalculation nudges the scroll position when the user is pinned to
the bottom of the page.

We isolated it by bisecting the page's timers on a live device: clearing the ~3-second state-poll
interval stopped the jump outright, while the 1-second clock tick (which re-renders far less) never
triggered it — proving the culprit was the *volume* of redundant writes the state poll made every cycle,
not any single element or value. WebKit's own Timelines recording confirmed a burst of style/layout
invalidations on each poll with no accompanying size change. The fix routes every render-path write
through small guarded helpers (`txt` / `clsIf` / `attrIf` / `styIf` / `htmlIf` / `propIf`) that skip the
assignment when the value is unchanged; with nothing mutating while the generator sits idle, there is no
recalculation for WebKit to react to. Verified clean on desktop WebKit and modern iOS (iOS 26). A small
residual jump can still occur on very old iOS WebKit (e.g. iPadOS 16.7) — documented as a known issue.
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
