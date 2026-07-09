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
