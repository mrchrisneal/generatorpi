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
