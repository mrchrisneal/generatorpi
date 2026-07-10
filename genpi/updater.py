# genpi/updater.py -- upstream version check + the self-updater for GeneratorPi (roadmap #59, Stage 8).
# LAYER: depends on genpi.config (CONFIG/APP_VERSION/SCRIPT_DIR), genpi.logg (log), genpi.store
# (record_event + the qualified store.send_push_async), genpi.lifecycle (the post-swap process restart),
# and genpi.state (_monitor_stop for the loop's clean shutdown). Imported by genpi/__init__ after all of
# those; the Flask routes that DRIVE the updater stay in __init__ and call these functions + share the
# progress state (_update_state / _update_lock / the decision Event + holder) BY REFERENCE.
#
# Two halves. (1) The cheap version check: _fetch_latest_version pulls the repo's raw VERSION, and
# _run_update_check caches installed-vs-latest so the footer never hammers GitHub. (2) The
# belt-and-suspenders self-updater (#8): download every manifest-listed file -> verify EVERY file's
# SHA-256 -> pre-swap py_compile of EVERY staged .py -> full ZIP backup -> atomic swap -> re-verify ->
# 127.0.0.1 health-probe -> auto-rollback on any failure -> bootstrap the restart. The #72 CLI-only
# gate refuses a web apply that would jump a manual-only release. NONE of this touches the relay.
#
# The updater calls its OWN helpers internally (e.g. _run_update -> _await_decision / _http_get_bytes /
# _preflight_check / _download_and_verify / _swap / _rollback / _write_bootstrap_script); tests that
# intercept those calls must patch them on THIS module (module.updater.<fn>), since __init__'s re-export
# is a separate binding the internal callers never read.
#
# Copyright (C) 2026 Chris Neal <https://neal.media> and Alex Neal <https://neal.tools>
# SPDX-License-Identifier: AGPL-3.0-or-later
import os              # path/fs ops, file modes, process env for the bootstrap
import sys             # sys.executable / sys.argv for the health probe + restart
import time            # cache timestamps + retry backoff
import json            # manifest + result-marker (de)serialization
import re              # manifest version/charset validation
import hashlib         # SHA-256 verification of every downloaded file
import importlib.util  # find_spec: is a manifest-declared dependency importable?
import shutil          # staging dir management + disk-usage checks
import stat            # preserve the exec bit across an update swap
import shlex           # safe quoting when generating the bootstrap shell script
import zipfile         # ZIP backup of the project root before a swap (rollback source)
import tempfile        # the bootstrap swap script runs from a temp file
import subprocess      # systemctl probing + the detached bootstrap launch
import threading       # the update lock + the REVERT/PROCEED decision Event
import urllib.request  # server-side fetch of raw release files from GitHub
from datetime import datetime          # human-readable timestamps in the result marker
from pathlib import Path               # the service-unit path + staging/backup paths
from .config import CONFIG, APP_VERSION, SCRIPT_DIR   # runtime config + paths + installed version
from .logg import log                  # updater progress + warnings
from . import store                    # store.send_push_async (qualified) for the "update available" push
from .store import record_event        # durable event-log entry when a new version appears
from . import lifecycle                # lifecycle._schedule_process_restart after a successful swap
from .state import _monitor_stop       # shared stop Event -> clean shutdown of update_check_loop


# Base for all release fetches -- the repo's default branch over HTTPS. Every updater URL
# is built from this FIXED base + a fixed suffix (never request-derived), so there is no
# SSRF surface. TLS gives MITM protection; the manifest's per-file SHA-256 gives integrity.
_RAW_BASE = "https://raw.githubusercontent.com/mrchrisneal/generatorpi/main"
_LATEST_VERSION_URL = _RAW_BASE + "/VERSION"
_MANIFEST_URL = _RAW_BASE + "/manifest.json"


def _version_tuple(v):
    """Parse a dotted version like '1.2.3' into a comparable int tuple (1,2,3). Non-numeric
    parts degrade to 0 so a malformed value can't raise into the caller."""
    out = []
    for part in str(v).split("."):
        try:
            out.append(int(part))
        except ValueError:
            out.append(0)
    return tuple(out)


def _fetch_latest_version():
    """Fetch the latest published version string from the repo's raw VERSION file.
    Returns the trimmed string, or None on ANY failure (offline Pi, private/renamed repo,
    timeout) -- the caller treats None as 'could not check', never as an error."""
    try:
        req = urllib.request.Request(_LATEST_VERSION_URL,
                                     headers={"User-Agent": "GeneratorPi-update-check"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            # Read a small, bounded amount -- a VERSION file is a few bytes; cap defensively.
            return resp.read(64).decode("utf-8", "replace").strip() or None
    except Exception as e:                       # noqa: BLE001 -- network/parse errors are non-fatal
        log.info(f"Update check failed: {e}")
        return None


# Cached result of the most recent GitHub update check. The footer refreshes on a 5-minute
# timer by READING THIS CACHE (no network) -- only the server loop, the on-load check, and a
# manual "Check again" actually reach out to the repo, so an open browser never hammers GitHub.
_update_check_cache = {"latest": None, "update_available": False, "checked_at": None}


def _run_update_check():
    """Hit the repo, compute availability, UPDATE THE CACHE, and return the result. The ONLY
    path that performs the network call for an update check (loop / on-load / manual)."""
    latest = _fetch_latest_version()
    available = latest is not None and _version_tuple(latest) > _version_tuple(APP_VERSION)
    with _update_lock:
        _update_check_cache.update(latest=latest, update_available=bool(available),
                                   checked_at=time.time())
    return {"installed": APP_VERSION, "latest": latest, "update_available": bool(available)}


# ============================================================================
# SELF-UPDATER (#8) -- download a release, verify EVERY file's SHA-256 against the
# published manifest, full-backup, swap, then restart. TLS + hash (no signing); files
# come from the repo raw base per the manifest. Verify-before-swap is mandatory; any
# failure aborts and restores the backup (we keep running the old version).
# ============================================================================
_UPDATE_STAGING = SCRIPT_DIR / ".update_staging"   # downloaded (then verified) release files
_BACKUP_DIR = SCRIPT_DIR / "backups"               # ZIP snapshots taken before each update
# Result marker + log written by the swap step and READ on the next startup, so we can show
# the user "the update just succeeded/failed" + the log in a modal even though the process
# restarted in between. Cleared once the client acknowledges it.
_UPDATE_RESULT = _BACKUP_DIR / "last_update.json"
_UPDATE_LOG = _BACKUP_DIR / "last_update.log"
# systemd unit written by setup.sh on a real install; absent in dev. Presence tells a
# managed-service deploy (restart via systemctl) from a run-it-yourself one (re-exec).
_SERVICE_UNIT = Path("/etc/systemd/system/generator_control.service")

# Live progress the UI polls. phase: idle/checking/downloading/verifying/backing_up/
# swapping/restarting/done/failed. Its own lock (touched from the worker thread).
_update_state = {"phase": "idle", "message": "", "progress": 0.0, "error": None,
                 "version": None, "systemd": None, "log": [], "decide": None,
                 # Stage-1 dependency check results (populated during [CHECKING DEPENDENCIES]).
                 # missing_deps: [{apt, feature, required}, ...]; deps_install_cmd: the apt one-liner.
                 "missing_deps": [], "deps_install_cmd": "",
                 # Manifest-declared update constraints (populated during [VALIDATING RELEASE]).
                 # installable: False => the release refuses in-app apply (greyed button); important_notes:
                 # operator guidance shown as "IMPORTANT: <note>" lines. Default installable True so an
                 # older manifest (no key) stays applicable (forward-compatible).
                 "installable": True, "important_notes": [],
                 # Which stage the worker is in (1 = pre-apply checks, 2 = apply/swap/restart) + a
                 # per-stage tally of warning/error lines -> the end-of-stage colored summary lines.
                 "stage": 1, "counts": {"stage1": {"warn": 0, "err": 0}, "stage2": {"warn": 0, "err": 0}}}
_update_lock = threading.Lock()
# Decision gate: when the run hits an error/warning it parks on phase "awaiting" and BLOCKS on
# this event until the user clicks REVERT or PROCEED (default REVERT on timeout). One update runs
# at a time, so a single event + holder is sufficient.
_update_decision_event = threading.Event()
_update_decision_choice = {"choice": None}


def _update_log(line):
    """Append one line to the live terminal log the progress view + result modal render."""
    with _update_lock:
        _update_state["log"].append(line)


def _update_log_append(text):
    """Append `text` to the CURRENT last log line (e.g. tack ' ok' onto a '[SECTION]' header
    once its step finishes, so it renders as '[SECTION] ok' on one line)."""
    with _update_lock:
        if _update_state["log"]:
            _update_state["log"][-1] += text
        else:
            _update_state["log"].append(text)


# Severity markers prefixed onto a log line so the terminal colours the WHOLE line (amber for a
# warning, red for an error) even when it carries no visible "WARNING:"/"ERROR:" label or "[TAG]".
# _fmtLogLine in the UI strips the marker before rendering, so it never displays or gets copied.
_SEV_MARK = {"warn": "", "err": ""}


def _update_sev(line, sev):
    """Log a line flagged with a severity marker so the terminal colours the whole line. Does NOT
    tally -- for label-less detail lines (e.g. the copy-clean install command)."""
    _update_log(_SEV_MARK.get(sev, "") + line)


def _update_warn(line):
    """Log a WARNING line AND tally it against the CURRENT stage for the end-of-stage summary. The
    caller includes the visible 'WARNING:' label (which the terminal colours amber); this logs +
    counts."""
    _update_log(line)
    with _update_lock:
        _update_state["counts"]["stage2" if _update_state.get("stage") == 2 else "stage1"]["warn"] += 1


def _update_err(line):
    """Log an ERROR line AND tally it against the CURRENT stage (see _update_warn; the caller
    includes the visible 'ERROR:' label, coloured red)."""
    _update_log(line)
    with _update_lock:
        _update_state["counts"]["stage2" if _update_state.get("stage") == 2 else "stage1"]["err"] += 1


def _stage_summary(stage):
    """Emit up to TWO colored summary lines as the LAST lines of a stage: a yellow [WARNING] count
    (only if any warnings were tallied) and a red [ERROR] count (only if any errors). Zero of a kind
    -> no line for it, so a clean stage adds nothing. Purely additive to the existing warning banner
    + log; the UI also one-time-scrolls to the bottom when a stage ends so these can't be missed."""
    with _update_lock:
        c = _update_state["counts"].get(f"stage{stage}", {"warn": 0, "err": 0})
        w, e = c["warn"], c["err"]
    if w:
        _update_log(f"[WARNING] Stage {stage}: {w} warning{'' if w == 1 else 's'} encountered")
    if e:
        _update_log(f"[ERROR] Stage {stage}: {e} error{'' if e == 1 else 's'} encountered")


def _await_decision(message, allow_proceed, proceed_label="PROCEED", proceed_disabled=False):
    """Park the run: show `message`, offer REVERT (+ a proceed button labelled `proceed_label`
    iff allow_proceed), and BLOCK until the user decides. Returns 'proceed' or 'revert' (defaults
    to the SAFE 'revert' on timeout so an unattended browser can never leave the updater hung
    mid-run). Requests to the Pi stay sequential -- the worker just waits; only the status poll
    continues. The caller already logs a terminal line for the situation, so we do NOT re-log
    `message` here (that would duplicate the line); it's kept only as the phase message.

    `proceed_disabled` (used for a release the manifest declares NOT web-installable) makes the UI
    SHOW the apply button but GREYED/disabled -- distinct from a plain error park, which hides it --
    so the operator sees the action exists yet is refused. allow_proceed stays False in that case,
    so the backend also rejects a proceed even if the disabled button were somehow clicked."""
    with _update_lock:
        _update_state.update(phase="awaiting", message=message,
                             decide={"allow_proceed": bool(allow_proceed),
                                     "proceed_label": proceed_label,
                                     "proceed_disabled": bool(proceed_disabled)})
        _update_decision_choice["choice"] = None
    _update_decision_event.clear()
    got = _update_decision_event.wait(600)               # up to 10 min for a human decision
    with _update_lock:
        choice = _update_decision_choice["choice"] if got else "revert"
        if choice not in ("proceed", "revert"):
            choice = "revert"
        _update_state["decide"] = None
    _update_log(f"→ {choice.upper()}")
    return choice


def _deployment_has_systemd():
    """True on a systemd-managed install (unit file present AND systemctl available). False
    in dev, where we still swap the files but re-exec this process instead of a service."""
    return _SERVICE_UNIT.exists() and shutil.which("systemctl") is not None


def _service_skip_reason():
    """Decide whether the update restarts via the systemd SERVICE or swaps in-process, and say
    WHY. Returns None to use the service; otherwise a human-readable reason for skipping ALL
    service/systemd steps (swap in-process + re-exec instead). Honors the operator's env/config
    (a disabled service or autostart) BEFORE falling back to host detection, so the updater obeys
    the same preferences the rest of the app does."""
    def _off(v):
        return str(v).strip().lower() in ("false", "0", "no", "off", "disabled")
    # 1) Explicit operator opt-out in the env/config wins (obey preferences).
    if "SERVICE_ENABLED" in CONFIG and _off(CONFIG.get("SERVICE_ENABLED")):
        return "service disabled in config (SERVICE_ENABLED is off)"
    if "AUTOSTART" in CONFIG and _off(CONFIG.get("AUTOSTART")):
        return "autostart disabled in config (AUTOSTART is off)"
    # 2) Otherwise detect a non-systemd host / uninstalled unit.
    if not _SERVICE_UNIT.exists():
        return "no systemd service unit installed (not a service-managed install)"
    if shutil.which("systemctl") is None:
        return "systemctl not available (not a systemd / Raspberry Pi OS host)"
    return None


def _http_get_bytes(url, timeout=30, max_bytes=12_000_000):
    """GET a URL, return the (bounded) body. Raises on any HTTP/size error -- the updater
    treats every failure as 'abort + keep the old version'."""
    req = urllib.request.Request(url, headers={"User-Agent": "GeneratorPi-updater"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"response exceeds {max_bytes} bytes")
    return data


def _update_phase(name, msg, prog, error=None):
    with _update_lock:
        _update_state.update(phase=name, message=msg, progress=round(prog, 3), error=error)


def check_manifest_dependencies(manifest):
    """Return the manifest-DECLARED runtime dependencies that are NOT importable on THIS device.

    The manifest carries a `dependencies` list (module import-name, apt package, feature,
    required-ness). During update Stage 1 the updater checks each so it can warn the operator --
    with a copy-able install command -- about anything missing BEFORE the apply, WITHOUT ever
    installing it (auto-apt on a headless box would need broad privileged access + can hang the
    update). Importability is checked with importlib.util.find_spec, which resolves the module
    WITHOUT importing/executing it (no side effects, safe to run mid-update). An older manifest
    with no `dependencies` key -> [] (nothing to check). A find_spec that raises (a broken/partial
    install, e.g. a namespace-package shadow) is treated as MISSING, fail-safe."""
    missing = []
    for dep in manifest.get("dependencies") or []:
        mod = dep.get("module")
        # Only plain TOP-LEVEL module names are ever passed to find_spec. A dotted name ("a.b")
        # would make find_spec IMPORT the parent package ("a"), executing its __init__ -- so
        # restricting to a single identifier keeps this fully side-effect-free even against a
        # hostile/garbled manifest. Every real declared dep is top-level, so this never skips one.
        if not isinstance(mod, str) or not mod.isidentifier():
            continue
        try:
            present = importlib.util.find_spec(mod) is not None
        except Exception:
            present = False   # ImportError/ValueError from a broken install -> treat as missing
        if not present:
            missing.append(dep)
    return missing


# Valid Debian/apt package-name charset. dependency_install_command only ever emits names matching
# this, so a hostile/garbled manifest cannot smuggle shell metacharacters into the copy-able install
# one-liner. The app never RUNS the command, but a user might paste it -- defense in depth.
_APT_PKG_RE = re.compile(r"^[a-z0-9][a-z0-9+.\-]*$")


def dependency_install_command(missing):
    """Build the copy-able apt one-liner that installs the given missing dependencies. Packages are
    deduped + sorted for a stable, tidy command, and ONLY well-formed apt package names (see
    _APT_PKG_RE) are included so a garbled/hostile manifest can't inject shell metacharacters into a
    string a user might paste. Returns "" when nothing installable is missing."""
    pkgs = sorted({d.get("apt") for d in missing
                   if isinstance(d.get("apt"), str) and _APT_PKG_RE.match(d.get("apt"))})
    if not pkgs:
        return ""
    return "sudo apt install -y " + " ".join(pkgs)


def _download_and_verify(manifest, base=None, staging=None):
    """Download every manifest file to a FRESH staging dir and verify its SHA-256. Raises
    on the FIRST mismatch/failure (nothing live is touched). Also compile-checks EVERY staged
    .py -- a file that hashes fine but won't compile would brick the swap.
    `base`/`staging` are injectable for tests."""
    base = base or _RAW_BASE
    staging = staging or _UPDATE_STAGING
    files = manifest.get("files") or []
    if not files:
        raise ValueError("manifest lists no files")
    _validate_manifest_paths(manifest)                 # never write outside the project root
    if staging.exists():
        shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True, exist_ok=True)
    n = len(files)
    # STAGE 'DOWNLOADING': fetch every file into staging (nothing live is touched). The caller
    # logs the [DOWNLOADING] header; we log one child line per file as it lands.
    for i, f in enumerate(files):
        rel, size = f["path"], int(f.get("bytes", 0))
        _update_phase("downloading", f"Downloading {rel}…", 0.10 + 0.40 * (i / n))
        data = _http_get_bytes(base + "/" + rel, max_bytes=max(size + 4096, 8192))
        dest = staging / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        _update_log(f"  {rel} … {len(data)} bytes")
    # STAGE 'VERIFYING': re-hash each staged file against the manifest, then compile-check every
    # staged .py. All verification is on the staged copies -- nothing live is touched until it passes.
    _update_log(f"[VERIFYING] SHA-256 of {n} files")
    _update_phase("verifying", "Verifying SHA-256…", 0.66)
    for f in files:
        rel, want = f["path"], f["sha256"]
        got = hashlib.sha256((staging / rel).read_bytes()).hexdigest()
        if got != want:
            raise ValueError(f"hash mismatch for {rel}: expected {want[:12]}…, got {got[:12]}…")
        _update_log(f"  {rel} … ok")
    # Compile-check EVERY staged .py before the swap is allowed to proceed. The app is now a
    # PACKAGE (genpi/…), so a single-file check is no longer enough: a submodule that hashes
    # fine but won't compile (a bad merge, a truncated download that still matched a stale hash)
    # would break the eager-import at startup and force a post-swap rollback. Catching it HERE --
    # on the staged copies, before anything live is touched -- keeps the apply safe.
    import py_compile
    py_files = [f["path"] for f in files if f["path"].endswith(".py")]
    for rel in py_files:
        try:
            py_compile.compile(str(staging / rel), doraise=True)
        except py_compile.PyCompileError as e:
            raise ValueError(f"staged {rel} failed to compile: {e}")
    if py_files:
        _update_log(f"  {len(py_files)} .py file(s) compile … ok")
    return staging


# Files a manifest must NEVER be allowed to overwrite even with an otherwise-valid in-root path
# -- operator secrets/config/certs. Clobbering these wouldn't leave the app unreachable, but it
# would destroy credentials / lock users out, so we deny them as defense-in-depth (audit NEW-7).
# No shipped file legitimately ends in any of these, so the denylist can never block a real release.
_MANIFEST_DENY_SUFFIXES = (".env", ".pem", ".key")


def _validate_manifest_paths(manifest):
    """Reject a manifest whose file paths could escape the project root (absolute or
    containing '..'), or that target operator secrets/certs. These paths drive downloads,
    staging, backup, swap AND zip extraction, so this single gate is what stops a hostile/garbled
    manifest writing outside SCRIPT_DIR or clobbering .env / TLS material."""
    for f in manifest.get("files") or []:
        p = f.get("path", "")
        if (not p) or p.startswith("/") or p.startswith("\\") or ".." in Path(p).parts:
            raise ValueError(f"unsafe manifest path: {p!r}")
        low = p.lower()
        if low.endswith(_MANIFEST_DENY_SUFFIXES) or low.endswith("generator_control.env"):
            raise ValueError(f"manifest may not overwrite a secret/cert file: {p!r}")


# Version strings are interpolated into the bootstrap shell script + JSON marker, so restrict
# them to an obviously-safe charset (defends against shell/JSON injection from a hostile or
# garbled manifest -- audit H1).
_VERSION_RE = re.compile(r"^[A-Za-z0-9.+_-]{1,64}$")


def _validate_version(version):
    if not (version and _VERSION_RE.match(str(version))):
        raise ValueError(f"unsafe manifest version: {version!r}")


def _ensure_backup_dir():
    """Create backups/ and PROVE it's writable (write+delete a probe). Called at startup so a
    permission problem is an immediate, loud failure -- we must never discover mid-update that
    we can't take a backup. Raises on any failure (the caller fails the process fast)."""
    _BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    probe = _BACKUP_DIR / ".write_probe"
    probe.write_text("ok")
    probe.unlink()


def _preflight_check(manifest, dest_root=None, log=None):
    """FINAL sanity check BEFORE any download/swap: prove we can actually write everywhere the
    update will touch -- the backups dir, the staging area, the project root, and EVERY target
    file's directory (and the file itself if it already exists) -- plus enough free disk. Raises
    with a clear message on the first problem so we abort before changing anything, never
    half-applying an update we can't finish. `dest_root` is injectable for tests; `log`, if given,
    receives one '  <check> … ok' terminal line per passed sub-check."""
    dest_root = dest_root or SCRIPT_DIR

    def writable(p):
        return os.access(str(p), os.W_OK)

    def _ok(msg):
        if log:
            log(f"  {msg} … ok")

    _ensure_backup_dir()                                  # backups/ creatable + writable (rollback)
    _ok("backups directory writable (rollback path)")
    if not writable(dest_root):
        raise PermissionError(f"project root is not writable: {dest_root}")
    _ok("project root writable")
    if not writable(_UPDATE_STAGING.parent):
        raise PermissionError(f"cannot write the staging area under: {_UPDATE_STAGING.parent}")
    _ok("staging area writable")
    files = manifest.get("files") or []
    for f in files:
        target = dest_root / f["path"]
        d = target.parent
        if d.exists() and not writable(d):
            raise PermissionError(f"target directory is not writable: {d}")
        if target.exists() and not writable(target):
            raise PermissionError(f"target file is not writable: {target}")
    _ok(f"all {len(files)} target files writable")
    # Free space: we need room for the download staging + the backup zip + the swap. Require the
    # summed file sizes with generous headroom so we never run out mid-swap (audit H2).
    need = sum(int(f.get("bytes", 0)) for f in files) * 3 + 5_000_000
    try:
        free = shutil.disk_usage(str(dest_root)).free
    except OSError:
        free = None
    if free is not None and free < need:
        raise OSError(f"insufficient free disk space for update: need ~{need}, have {free}")
    if free is not None:
        _ok(f"free disk space ({free // 1_000_000} MB free, need ~{need // 1_000_000} MB)")


def _write_update_result(status, version, note="", log_text=None, started_ts=None):
    """Persist an update outcome ({status, version, note, ts}) + optional log to backups/ so
    the NEXT startup can show the user how the update went (a restart happens in between).
    `started_ts` is the apply-start unix time; it's stored so the post-restart startup can compute
    how long the update took (the restart happens in between, so it can't measure it directly).
    Best-effort -- never raises into the update flow."""
    try:
        _BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        _UPDATE_RESULT.write_text(json.dumps({
            "status": status, "version": version, "note": note,
            "ts": datetime.now().isoformat(timespec="seconds"),
            "started_ts": started_ts,
        }))
        if log_text is not None:
            _UPDATE_LOG.write_text(log_text)
    except Exception as e:                               # noqa: BLE001 -- marker is best-effort
        log.error(f"could not write update result marker: {e}")


def _make_backup(manifest, dest_root=None, backup_dir=None):
    """Snapshot the CURRENT state of every manifest file into a timestamped ZIP in backups/
    (which is never itself in the manifest, so never backed up or swapped). Also record --
    inside the zip -- the manifest files that DON'T yet exist ('added'), so a rollback can
    DELETE them and land on the exact pre-update file set (presence/names/count, not just
    contents). Returns (zip_path, added)."""
    dest_root = dest_root or SCRIPT_DIR
    backup_dir = backup_dir or _BACKUP_DIR
    backup_dir.mkdir(parents=True, exist_ok=True)
    paths = [f["path"] for f in (manifest.get("files") or [])]
    present = [p for p in paths if (dest_root / p).is_file()]
    added = [p for p in paths if not (dest_root / p).exists()]
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    zpath = backup_dir / f"backup-{ts}-v{APP_VERSION}.zip"
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for p in present:
            z.write(dest_root / p, p)                    # arcname = relative path
        z.writestr("__added__.json", json.dumps(added))
    # VERIFY the backup before anyone relies on it for rollback (audit H3): a corrupt/truncated
    # zip must be caught NOW, while the old files are still live, not discovered mid-rollback.
    with zipfile.ZipFile(zpath) as z:
        if z.testzip() is not None:
            raise OSError(f"backup archive failed integrity check: {zpath}")
        names = set(z.namelist())
        for p in present:                                # every backed-up file must read back
            if p not in names or hashlib.sha256(z.read(p)).hexdigest() != \
                    hashlib.sha256((dest_root / p).read_bytes()).hexdigest():
                raise OSError(f"backup archive is missing/corrupt for {p}")
    _prune_backups(backup_dir=backup_dir)                # cap retained backups (newest 20)
    return zpath, added


def _prune_backups(keep=20, backup_dir=None):
    """Keep at most `keep` most-recent backup zips and delete the rest, so backups/ can never
    grow without bound across many updates. Best-effort -- never raises into the update flow."""
    backup_dir = backup_dir or _BACKUP_DIR
    try:
        zips = sorted(backup_dir.glob("backup-*.zip"),
                      key=lambda p: p.stat().st_mtime, reverse=True)
        for old in zips[keep:]:
            try:
                old.unlink()
            except OSError:
                pass
    except Exception as e:                                # noqa: BLE001 -- pruning is best-effort
        log.warning(f"backup prune failed: {e}")


def _swap(manifest, staging=None, dest_root=None, log_fn=None):
    """Copy verified staged files over the live ones (the DEV path; the systemd path swaps
    from the /tmp bootstrap while the service is stopped). Each file is replaced ATOMICALLY --
    copy to a sibling temp, then os.replace (rename) over the live file -- so an interruption
    can never leave a half-written live file (mirrors the bootstrap's cp→mv, audit NEW-1).
    If `log_fn` is given, each swapped file is reported (old→new bytes) so Stage 2's terminal
    shows exactly what was replaced, at Stage-1-level detail."""
    staging = staging or _UPDATE_STAGING
    dest_root = dest_root or SCRIPT_DIR
    for f in manifest.get("files") or []:
        live = dest_root / f["path"]
        live.parent.mkdir(parents=True, exist_ok=True)
        existed = live.exists()
        old_bytes = live.stat().st_size if existed else 0   # for the "old→new" report
        # Preserve the LIVE file's permission bits (e.g. the +x on setup.sh/update.sh): the staged
        # copy was written via write_bytes() with the default umask mode, so without this the swap
        # would silently drop the executable bit on shell scripts (audit: exec-bit preservation).
        orig_mode = stat.S_IMODE(live.stat().st_mode) if existed else None
        tmp = live.with_name(live.name + ".gpnew")       # sibling temp on the same filesystem
        shutil.copy2(staging / f["path"], tmp)
        if orig_mode is not None:
            os.chmod(tmp, orig_mode)                     # re-apply the original permissions
        os.replace(tmp, live)                            # atomic rename over the live file
        if log_fn:                                       # per-file line: "<path> … 332385 → 333025 bytes … ok"
            new_bytes = live.stat().st_size
            verb = "new" if old_bytes == 0 else f"{old_bytes} →"
            log_fn(f"  {f['path']} … {verb} {new_bytes} bytes … ok")


def _rollback(zip_path, dest_root=None):
    """Restore the EXACT pre-update state from a backup zip: delete update-added files, then
    extract the backed-up files over the live ones. Best-effort, never raises."""
    dest_root = dest_root or SCRIPT_DIR
    try:
        with zipfile.ZipFile(zip_path) as z:
            try:
                added = json.loads(z.read("__added__.json").decode("utf-8"))
            except Exception:
                added = []
            for p in added:
                try:
                    (dest_root / p).unlink()
                except OSError:
                    pass
            for name in z.namelist():
                if name != "__added__.json":
                    z.extract(name, dest_root)
    except Exception as e:                               # noqa: BLE001 -- rollback is best-effort
        log.error(f"Rollback from {zip_path} failed: {e}")


def _write_bootstrap_script(manifest, version, zip_path, staging, health_url, t_apply=None):
    """Write a STANDALONE swap+restart+rollback script to /tmp; return its path.

    Runs from /tmp -- OUTSIDE the project root -- so it can replace EVERY project file,
    including the genpi/ package that houses this updater code itself. Robustness (post-audit):
      * The unit is installed with KillMode=process (setup.sh), so a `systemctl restart`
        kills only the OLD main process, NOT this detached child -- fixing the cgroup
        self-kill that previously bricked every update (audit C1).
      * HEALTH = an actual HTTP request to the listener (any response, even a 401 auth
        challenge, proves it bound + is serving), required 3 times consecutively -- NOT
        `systemctl is-active`, which reports active the instant a Type=simple process forks
        and would pass a broken build (audit C2).
      * An EXIT trap rolls back on ANY non-success exit -- swap error, failed restart, failed
        health check, or an unexpected death mid-run (audit M2). Rollback restores the backup
        zip (delete-added + extract), restarts the OLD version, and re-verifies it is healthy,
        recording whether recovery itself succeeded (audit H5).
      * `version` is validated (charset) upstream and referenced only via the quoted $VER
        shell var, never interpolated raw (audit H1)."""
    q = shlex.quote
    paths = [f["path"] for f in (manifest.get("files") or [])]
    # ATOMIC per-file swap (audit NEW-1): copy the staged file to a sibling temp on the SAME
    # filesystem, then `mv` (rename(2)) it over the live file. The live file is therefore only
    # ever replaced all-at-once -- a power loss mid-copy leaves a harmless *.gpnew temp, never a
    # truncated genpi module that would crash-loop the service on reboot.
    # Also preserve the live file's mode (e.g. +x on setup.sh/update.sh) onto the replacement,
    # best-effort via `chmod --reference` -- otherwise the swap would drop the exec bit like the
    # dev _swap did before its fix. The ( …; true ) subshell can't fail the &&-chain, so mv always
    # proceeds even if the reference/chmod is unavailable.
    copies = "\n".join(
        f'mkdir -p "$ROOT/$(dirname {q(p)})" && '
        f'cp -f {q(str(staging))}/{q(p)} "$ROOT"/{q(p)}.gpnew && '
        f'( [ -e "$ROOT"/{q(p)} ] && chmod --reference="$ROOT"/{q(p)} "$ROOT"/{q(p)}.gpnew 2>/dev/null; true ) && '
        f'mv -f "$ROOT"/{q(p)}.gpnew "$ROOT"/{q(p)}'
        for p in paths
    )
    # Rollback via system python3 (independent of the project files being swapped).
    py_rollback = (
        "python3 - " + q(str(zip_path)) + " \"$ROOT\" <<'PY'\n"
        "import sys, zipfile, json, os\n"
        "zp, root = sys.argv[1], sys.argv[2]\n"
        "z = zipfile.ZipFile(zp)\n"
        "try: added = json.loads(z.read('__added__.json'))\n"
        "except Exception: added = []\n"
        "for p in added:\n"
        "    try: os.remove(os.path.join(root, p))\n"
        "    except OSError: pass\n"
        "for n in z.namelist():\n"
        "    if n != '__added__.json': z.extract(n, root)\n"
        "PY"
    )
    body = (
        "#!/bin/bash\n"
        "# GeneratorPi self-update bootstrap (generated). Detached + KillMode=process, so a\n"
        "# service restart can't kill it; replaces every file incl. the updater; HTTP health-\n"
        "# checks the new version; EXIT-trap rolls back to the backup on ANY failure.\n"
        f"ROOT={q(str(SCRIPT_DIR))}\n"
        f"VER={q(version)}\n"
        f"HEALTH_URL={q(health_url)}\n"
        "SVC=generator_control.service\n"
        "mkdir -p \"$ROOT/backups\"\n"
        "RESULT=\"$ROOT/backups/last_update.json\"\n"
        "exec >> \"$ROOT/backups/last_update.log\" 2>&1\n"          # APPEND to the seeded pre-restart log
        # Emit lines verbatim so they match the Stage-1 terminal style: a bracketed [TAG] renders as
        # a bright header, a leading-space '  … ok' as a dim child. No prefix, no timestamp.
        "log() { echo \"$*\"; }\n"
        "write_result() { printf '{\"status\":\"%s\",\"version\":\"%s\",\"ts\":\"%s\",\"note\":\"%s\"}\\n'"
        " \"$1\" \"$VER\" \"$(date -Iseconds)\" \"$2\" > \"$RESULT\"; }\n"
        # Any HTTP response (incl. a 401 challenge) proves the listener bound + is serving.
        # Probe via python3 -- the app's OWN runtime, so it's guaranteed present (curl is not
        # on every base image; a missing curl would fail every health check and needlessly roll
        # back good updates -- audit NEW-2). TLS verification is intentionally DISABLED here and
        # ONLY here: this is a 127.0.0.1 liveness probe against the app's OWN self-signed cert,
        # where we care whether it ANSWERS, not its identity (same reason the old curl used -k).
        # It is NOT a data fetch -- the actual manifest/file downloads use full TLS verification.
        "health() { python3 - \"$HEALTH_URL\" <<'PY'\n"
        "import sys, urllib.request, urllib.error, ssl\n"
        "try:\n"
        "    urllib.request.urlopen(sys.argv[1], timeout=3, context=ssl._create_unverified_context())\n"
        "except urllib.error.HTTPError:\n"
        "    pass          # any HTTP status (401 etc.) means the server is up + serving\n"
        "except Exception:\n"
        "    sys.exit(1)   # connection refused / timeout -> not serving yet\n"
        "PY\n"
        "}\n"
        "wait_healthy() { local c=0 i; for i in $(seq 1 30); do if health; then c=$((c+1)); "
        "[ $c -ge 3 ] && return 0; else c=0; fi; sleep 2; done; return 1; }\n"
        "rollback() {\n"
        "  log '[ROLLBACK] restoring backup + restarting the previous version'\n"
        f"  {py_rollback}\n"
        "  sudo systemctl restart \"$SVC\" 2>/dev/null || true\n"
        "  [ \"$T_APPLY\" != 0 ] && log \"Update failed after $(( $(date +%s) - T_APPLY )) seconds\"\n"
        "  if wait_healthy; then write_result failed 'Update failed - rolled back to the previous version.';\n"
        "  else write_result failed 'Update failed AND rollback did not become healthy - manual check needed.'; fi\n"
        "}\n"
        # Apply-start unix time (stamped in Python at [APPLYING]) so the bootstrap can report how
        # long the update took; 0 means unknown -> the timing line is skipped.
        f"T_APPLY={int(t_apply) if t_apply else 0}\n"
        # Roll back on ANY exit that didn't reach SUCCEEDED=1 (covers unexpected deaths too).
        "SUCCEEDED=0\n"
        "DONE_FLAG=\"$ROOT/backups/.gp_update_done\"; rm -f \"$DONE_FLAG\"\n"
        "on_exit() { [ \"$SUCCEEDED\" = 1 ] && return; log '[ROLLBACK] update did not complete — rolling back'; rollback; }\n"
        "trap on_exit EXIT\n"
        # WATCHDOG (audit M-3): guarantee a BOUNDED recovery. An update should never run long --
        # owner cap is 10 minutes TOPS. If the whole apply isn't done within 10 min (a wedged
        # systemctl restart / stuck mount leaving the app down), force a rollback and tear down this
        # run's process group so we never hang indefinitely. $$ is the session leader's PID (setsid),
        # so -$$ targets the bootstrap's group -- NOT the restarted service.
        "( sleep 600; [ -f \"$DONE_FLAG\" ] && exit 0; log '[WATCHDOG] 10m elapsed — forcing rollback'; rollback; kill -9 -$$ 2>/dev/null ) &\n"
        "WATCHDOG=$!\n"
        # Bound a stuck restart with `timeout` when it's available (dependency-free: fall back to a
        # plain restart if `timeout` isn't installed, so a missing coreutils never fails the update).
        "do_restart() { if command -v timeout >/dev/null 2>&1; then timeout 150 sudo systemctl restart \"$SVC\"; else sudo systemctl restart \"$SVC\"; fi; }\n"
        "sleep 1\n"
        # Swap while the OLD process is still running its in-memory code (safe for a python app),
        # then restart -- KillMode=process spares this detached bootstrap.
        f"( set -e\n{copies}\n) || exit 1\n"
        "log '  files swapped … ok'\n"
        "do_restart 2>/dev/null || exit 1\n"
        "log '  service restarted … ok'\n"
        "wait_healthy || exit 1\n"
        "log '  new version is serving … ok'\n"
        "[ \"$T_APPLY\" != 0 ] && log \"Update finished in $(( $(date +%s) - T_APPLY )) seconds\"\n"
        "log \"[DONE] Application successfully updated to v$VER!\"\n"
        "SUCCEEDED=1\n"
        "touch \"$DONE_FLAG\"\n"                                    # tell the watchdog we finished
        "kill \"$WATCHDOG\" 2>/dev/null\n"                          # cancel the watchdog
        "write_result success \"Updated to v$VER.\"\n"
        f"rm -f \"$DONE_FLAG\"; rm -rf {q(str(staging))}; rm -f \"$0\"\n"
    )
    fd, tmp = tempfile.mkstemp(prefix="gp-update-", suffix=".sh")
    os.close(fd)
    Path(tmp).write_text(body)
    os.chmod(tmp, 0o755)
    return tmp


def _run_update():
    """Background worker. DEV (no systemd): download+verify+backup, swap in-process, then
    re-exec -- safe because the running process holds the OLD code in memory until re-exec.
    SYSTEMD: download+verify+backup, then hand swap+restart to a /tmp bootstrap that can
    replace even the genpi/ package itself and self-heals (rollback + restart) on failure. Errors
    before any swap abort cleanly; a failed same-process swap rolls back from the backup zip."""
    manifest = None
    zpath = None
    swapped = False
    t_apply = None                                        # set when Stage 2 (apply/swap) actually begins
    with _update_lock:                                    # fresh per-run stage + warn/err tally + dep
        _update_state["stage"] = 1                        # results (belt-and-suspenders: self-contained
        _update_state["counts"] = {"stage1": {"warn": 0, "err": 0},  # even if a caller skipped the
                                   "stage2": {"warn": 0, "err": 0}}   # api_update_start reset)
        _update_state["missing_deps"] = []
        _update_state["deps_install_cmd"] = ""
        _update_state["installable"] = True               # optimistic default; the manifest may lower it
        _update_state["important_notes"] = []
    try:
        # Terminal log format: bracketed [SECTION] headers (bright, left-aligned) get ' ok' or an
        # error tacked on when their step finishes; detail lines are indented two spaces.
        _update_log(f"[UPDATE] GeneratorPi — installed v{APP_VERSION}")
        _update_log("[CONTACTING GITHUB]")
        _update_phase("checking", "Reaching GitHub…", 0.03)
        manifest = json.loads(_http_get_bytes(_MANIFEST_URL, max_bytes=1_000_000).decode("utf-8"))
        version = manifest.get("version") or "?"
        nfiles = len(manifest.get("files") or [])
        _update_log_append(" ok")
        _update_log(f"  manifest v{version} · {nfiles} files")
        # Validate the manifest BEFORE trusting any of it (each check aborts the run on failure).
        _update_log("[VALIDATING RELEASE]")
        _validate_manifest_paths(manifest)               # traversal + secret/cert denylist
        _update_log("  file paths safe (no traversal, no secret/cert targets) … ok")
        _validate_version(version)                       # charset-safe before it hits shell/JSON
        _update_log("  version string well-formed … ok")
        with _update_lock:
            _update_state["version"] = version
        # CLI-ONLY / INCOMPATIBLE-VERSION GATE: the manifest's incompatible_versions is an APPEND-ONLY map
        # { version -> reason } of releases the web updater must REFUSE (a systemd-entrypoint / package-
        # layout change it can't perform, or a restructure too large to swap in place). The KEYS are the
        # gates; each VALUE is the guidance shown in the IMPORTANT box. If ANY gate G falls STRICTLY ABOVE
        # the installed version and AT-OR-BELOW the latest (installed < G <= latest), a manual gate sits
        # between where we are and where we'd land -- so we REFUSE the web apply HERE, before downloading or
        # touching anything, and surface THAT version's reason. This stops a very old install from web-
        # JUMPING across a gate and failing hard; the operator installs manually instead (which jumps
        # straight to latest, crossing every gate at once). Absent/empty -> nothing gates -> applicable
        # (forward-compatible with older manifests). A bare list (keys only) or a single string is tolerated
        # so an unexpected manifest shape can never crash the check.
        _incompat = manifest.get("incompatible_versions")
        if isinstance(_incompat, str):
            _incompat = {_incompat: ""}
        elif isinstance(_incompat, (list, tuple, set)):
            _incompat = {str(v): "" for v in _incompat}
        elif not isinstance(_incompat, dict):
            _incompat = {}
        # Normalize a gate version for comparison: trim + tolerate a 'v'-tagged form ("v1.4.0" -> "1.4.0").
        # Releases are TAGGED vX.Y.Z, so that typo is the natural mistake -- left as-is it would parse to
        # (0,4,0) and silently NEVER block (fail-OPEN), letting exactly the old install this protects
        # web-jump a gate and brick. (gen-manifest.py ALSO rejects a malformed KEY at generation time.)
        def _gate_ver(g):
            g = str(g).strip()
            return g[1:] if g[:1] in ("v", "V") else g
        _cur_t, _latest_t = _version_tuple(APP_VERSION), _version_tuple(version)
        # The blocking gate versions (normalized, de-duped, version-sorted) sitting in (installed, latest].
        _blocking = sorted({_gate_ver(g) for g in _incompat
                            if _gate_ver(g) and _cur_t < _version_tuple(_gate_ver(g)) <= _latest_t},
                           key=_version_tuple)
        # Each blocking gate's reason, matched by NORMALIZED version key. A gate with a blank/missing message
        # still blocks -- the IMPORTANT box then falls back to its generic single-sentence text (Case B).
        _msg_by_ver = {_gate_ver(k): str(v).strip() for k, v in _incompat.items()}
        _notes = [_msg_by_ver[g] for g in _blocking if _msg_by_ver.get(g)]
        with _update_lock:
            _update_state["installable"] = not _blocking
            # Rendered in the UI's dedicated IMPORTANT box: with notes -> the intro + note(s) + a divider
            # + the release/repo links (Case A); empty -> the single-sentence fallback with the links
            # (Case B). Either way the box carries the message, so the log only points to it.
            _update_state["important_notes"] = _notes
        if _blocking:
            # The terminal log only POINTS to the box; the note TEXT itself is shown in the dedicated
            # bordered "IMPORTANT" box below the log (the UI reads it from _update_state.important_notes).
            _update_log(f"[ERROR] v{version} cannot be installed by the web updater")
            _update_sev(f"  A manual-install-only version ({', '.join('v' + g for g in _blocking)}) is "
                        f"between your v{APP_VERSION} and v{version}.", "err")
            _update_sev("  Nothing has changed. See the IMPORTANT note below, then install it "
                        "manually (e.g. ./setup.sh reinstall).", "err")
            _update_phase("staged", f"v{version} is not installable via the web updater.", 0.85)
            # Park: apply button SHOWN but greyed/disabled + REVERT/CLOSE; allow_proceed False so the
            # backend refuses proceed even if the disabled button were clicked (belt-and-suspenders).
            _await_decision(f"v{version} cannot be installed by the web updater.",
                            allow_proceed=False, proceed_label="UPDATE", proceed_disabled=True)
            _update_log(f"[ERROR] not applied. Still on v{APP_VERSION}.")
            _update_phase("failed", "This release must be installed manually.", 0.0)
            return
        # Restart path + WHY up front (obeys env/config; honest about non-systemd hosts).
        _svc_skip = _service_skip_reason()
        _update_log("[DEPLOYMENT PLAN] " + (
            "systemd service — will restart the service to apply"
            if not _svc_skip else "in-process swap + re-exec"))
        if _svc_skip:
            _update_log(f"  reason: {_svc_skip}")
        _update_log(f"  installed v{APP_VERSION} → target v{version}")
        _update_log(f"  backups dir: {_BACKUP_DIR}")
        # Detailed system-readiness checks (writability of every target + free disk space).
        _update_log("[CHECKING SYSTEM]")
        _update_phase("checking", "Validating permissions + free space…", 0.06)
        _preflight_check(manifest, log=_update_log)      # logs each sub-check; aborts on first failure
        # Stage-1 DEPENDENCY CHECK: the manifest DECLARES the runtime deps this release needs. Report
        # any not importable on THIS device + a copy-able apt one-liner so the operator can install
        # them. The updater NEVER installs them itself (auto-apt on a headless box needs broad
        # privileged access + can hang the update). This is a WARNING, not a gate -- a missing
        # OPTIONAL dep just means that feature (e.g. Web Push) stays off until it's installed.
        _update_log("[CHECKING DEPENDENCIES]")
        _update_phase("checking", "Checking declared dependencies…", 0.07)
        _missing_deps = check_manifest_dependencies(manifest)
        _deps_cmd = dependency_install_command(_missing_deps)
        with _update_lock:
            _update_state["missing_deps"] = [
                {"apt": d.get("apt", ""), "feature": d.get("feature", ""),
                 "required": bool(d.get("required"))}
                for d in _missing_deps
            ]
            _update_state["deps_install_cmd"] = _deps_cmd
        if not _missing_deps:
            _update_log("  all declared dependencies present … ok")
        else:
            _any_required = any(d.get("required") for d in _missing_deps)
            for d in _missing_deps:
                _req = bool(d.get("required"))
                # A missing REQUIRED dep is an ERROR (red); a missing OPTIONAL one (e.g. a Web Push
                # library) is a WARNING (amber) -- that feature just stays off. The visible
                # WARNING:/ERROR: label drives the terminal colour; both feed the stage tally.
                _line = (f"  {'ERROR' if _req else 'WARNING'}: Missing "
                         f"({'required' if _req else 'optional'}) dependency: "
                         f"{d.get('apt', '?')} ({d.get('feature', '')})")
                (_update_err if _req else _update_warn)(_line)
            # Colour the remedy note + copy-clean command with the block's overall severity (a
            # missing REQUIRED dep makes the whole block red) WITHOUT tallying them as extra items;
            # the command carries no visible label so it stays clean to select/copy.
            _sev = "err" if _any_required else "warn"
            _update_sev("  The updater will NOT install these — run the following command over SSH, then restart the application to resolve:", _sev)
            _update_sev(f"    {_deps_cmd}", _sev)
        # Two logged stages: download to staging, then verify SHA-256 + compile-check.
        _update_log(f"[DOWNLOADING] {nfiles} files")
        _update_phase("downloading", "Downloading files…", 0.1)
        staging = _download_and_verify(manifest)         # logs per-file download, then [VERIFYING]
        _update_log("[BACKING UP]")
        _update_phase("backing_up", "Backing up current files…", 0.8)
        zpath, _added = _make_backup(manifest)
        _update_log_append(" ok")
        _update_log(f"  {zpath.name} (integrity-verified)")
        # ── END OF STAGE 1 ── everything is downloaded, hash-verified, and backed up, but NOTHING
        # live has changed yet. Park for the user's go/no-go before STAGE 2 (the swap + restart):
        # UPDATE applies it, REVERT cancels cleanly (this is the last point a cancel is free).
        _update_log("[STAGED]")
        _update_log_append(" ok")
        _update_log(f"  v{version} ready to apply — nothing has changed yet")
        _stage_summary(1)          # colored warning/error count lines (if any) as the last Stage-1 lines
        _update_phase("staged", f"Ready to apply v{version}.", 0.85)
        choice = _await_decision(
            f"Ready to apply v{version}.", allow_proceed=True, proceed_label="UPDATE")
        if choice == "revert":
            try:
                if _UPDATE_STAGING.exists():
                    shutil.rmtree(_UPDATE_STAGING, ignore_errors=True)
            except Exception:                            # noqa: BLE001 -- cleanup is best-effort
                pass
            _update_log(f"[REVERTED] canceled before applying — still on v{APP_VERSION}")
            _update_phase("failed", "Update canceled before applying.", 0.0)
            return
        _update_log(f"[APPLYING] stage 2 — installing v{version}")
        with _update_lock:                               # subsequent warn/err lines tally to Stage 2
            _update_state["stage"] = 2
        t_apply = time.time()                            # start timing the apply (past the go/no-go gate)
        if not _svc_skip:
            with _update_lock:
                _update_state["systemd"] = True
            _update_log("[RESTARTING] swapping files + restarting the service…")
            _update_phase("restarting", f"Applying v{version} + restarting service…", 0.92)
            # Seed the shared log with everything so far, so the post-restart result terminal
            # shows the FULL run (these pre-restart lines + the bootstrap's swap/restart/health
            # lines, which the bootstrap APPENDS to this same file).
            with _update_lock:
                _seed = "\n".join(_update_state["log"])
            try:
                _BACKUP_DIR.mkdir(parents=True, exist_ok=True)
                _UPDATE_LOG.write_text(_seed + "\n")
            except OSError:
                pass
            # Health URL the bootstrap probes to confirm the NEW version actually serves.
            scheme = "https" if CONFIG.get("SSL_ENABLED") else "http"
            health_url = f"{scheme}://127.0.0.1:{CONFIG['PORT']}/"
            script = _write_bootstrap_script(manifest, version, zpath, staging, health_url, t_apply=t_apply)
            # Run the bootstrap at a gentle (mild) CPU niceness so it never starves the generator
            # controller / other work while it swaps + restarts. os.nice() in preexec_fn keeps it
            # dependency-free (no `nice` binary needed); +5 is polite but still prompt for the swap.
            def _be_nice():
                try:
                    os.nice(5)
                except OSError:
                    pass
            # Detach the bootstrap into its own session so it outlives this process. Use ONLY
            # start_new_session=True (it calls setsid(2) directly) -- no "setsid" argv, which
            # would add a needless binary dependency whose absence fails the launch (audit NEW-6).
            # KillMode=process spares the child regardless of session anyway.
            subprocess.Popen(["bash", script],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True, preexec_fn=_be_nice)
        else:
            with _update_lock:
                _update_state["systemd"] = False
            _update_phase("swapping", "Applying update…", 0.86)
            # ---- STAGE 2 (non-systemd): in-process atomic swap + re-exec, logged in DETAIL so the
            # terminal shows exactly what changed -- parity with Stage 1's download/verify sections.
            # Arm rollback BEFORE the swap: if _swap raises partway (file k of n), the except path
            # MUST restore from the backup, else the disk is left with a mixed old/new file set that
            # would brick the next restart (audit H-1). The running process still holds the OLD code
            # in RAM, so restoring the backup + not re-exec'ing keeps us reachable.
            swapped = True
            _update_log(f"  rollback point armed: {zpath.name}")
            _update_log(f"[SWAPPING] {nfiles} files (atomic replace)")
            _swap(manifest, log_fn=_update_log)          # per-file: "<path> … old → new bytes … ok"
            # Confirm the swap actually landed: re-hash each LIVE file against the manifest. A bad
            # on-disk file raises -> the except path rolls back from the backup zip.
            _update_log("[VERIFYING SWAP] on-disk SHA-256")
            for f in manifest.get("files") or []:
                rel, want = f["path"], f["sha256"]
                got = hashlib.sha256((SCRIPT_DIR / rel).read_bytes()).hexdigest()
                if got != want:
                    raise ValueError(f"post-swap hash mismatch for {rel}")
                _update_log(f"  {rel} … ok")
            # In-process Stage 2 only. The systemd path's Stage 2 runs in the detached bootstrap
            # (its own colored [DONE]/[ROLLBACK]/[WATCHDOG] lines), so it has no in-app summary here.
            _stage_summary(2)          # colored Stage-2 warning/error counts (if any) before re-exec
            _update_log("[RESTARTING] in-process re-exec")
            _update_log("  releasing the listening socket, then re-exec'ing this process")
            with _update_lock:
                _full_log = "\n".join(_update_state["log"])
            # Mark 'restarting' (NOT success) BEFORE re-exec; the freshly-started process flips
            # it to success at startup, so an import failure in the new code can't masquerade as
            # a successful update (audit M1). The captured log is the whole terminal, so the
            # result modal shows the same lines the user just watched.
            _write_update_result(
                "restarting", version,
                note="Files were swapped directly (non-systemd); the app is restarting.",
                log_text=_full_log, started_ts=t_apply)
            _update_phase("restarting",
                          f"Updated to v{version}. Restarting the app process…", 0.95)
            lifecycle._schedule_process_restart(1.5)
    except Exception as e:
        # Any failure BEFORE the restart lands here. Show it in the terminal and PARK for the
        # user's decision (hard errors can't be safely proceeded past, so REVERT only). REVERT
        # rolls back any partial swap, discards staging, and leaves the OLD version running.
        log.error(f"Self-update failed: {e}")
        _update_log(f"[ERROR] {e}")
        _await_decision(f"Update failed: {e}", allow_proceed=False)
        if swapped and zpath is not None:                # same-process swap failed -> restore
            _update_log("[ROLLBACK] restoring the previous version…")
            _rollback(zpath)
        try:                                             # discard the staged download
            if _UPDATE_STAGING.exists():
                shutil.rmtree(_UPDATE_STAGING, ignore_errors=True)
        except Exception:                                # noqa: BLE001 -- cleanup is best-effort
            pass
        if t_apply is not None:                          # only if we'd started applying (past the gate)
            _update_log(f"Update failed after {max(0.0, time.time() - t_apply):.1f} seconds")
        _update_log(f"[REVERTED] no changes applied — still on v{APP_VERSION}")
        _update_phase("failed", f"Update reverted: {e}", 0.0, error=str(e))


# FAIL FAST at startup: the updater must always be able to write a rollback backup, so a
# missing/unwritable backups/ dir is a hard stop here rather than a nasty surprise mid-update.
try:
    _ensure_backup_dir()
except OSError as _e:  # pragma: no cover - import-time fail-fast; the backups dir is writable in dev/CI, so this hard-stop branch isn't reachable without a module reload against a broken filesystem
    log.critical(
        f"Cannot create or write the backups directory ({_BACKUP_DIR}): {_e}. Fix the "
        f"permissions and restart -- refusing to run without a working rollback path."
    )
    raise SystemExit(1)


# If the DEV (re-exec) update path left a 'restarting' marker, reaching HERE proves the new
# code imported + started cleanly, so promote it to 'success'. If the new code had failed to
# import we'd never get here and the marker would stay 'restarting' (honest -- not a false
# success). The systemd path writes its own result from the bootstrap, so leave those alone.
try:  # pragma: no cover - import-time-only marker promotion (runs in the fresh process after a dev self-update re-exec); no 'restarting' marker exists during tests and it can't be re-triggered without a full module reload
    if _UPDATE_RESULT.exists():
        _r = json.loads(_UPDATE_RESULT.read_text())
        if _r.get("status") == "restarting":
            _r["status"] = "success"
            _ver = _r.get("version", APP_VERSION)
            _r["note"] = f"Application successfully updated to v{_ver}."
            _UPDATE_RESULT.write_text(json.dumps(_r))
            # How long the apply took, measured ACROSS the re-exec: started_ts was stamped at
            # [APPLYING] before the restart, so elapsed = now - started_ts.
            _st = _r.get("started_ts")
            _took = (f"\nUpdate finished in {max(0.0, time.time() - _st):.1f} seconds"
                     if isinstance(_st, (int, float)) else "")
            # Append the FINAL confirmation to the captured terminal log so the result modal ends
            # with a clear, green "[DONE]" line (the log was captured just before re-exec; reaching
            # here proves the new version imported + is serving) -- Stage 2 finishes with a result.
            try:
                _prev = _UPDATE_LOG.read_text() if _UPDATE_LOG.exists() else ""
                _UPDATE_LOG.write_text(
                    _prev.rstrip("\n")
                    + "\n[HEALTH] checking if the application is back up … ok"
                    + _took
                    + f"\n[DONE] Application successfully updated to v{_ver}!"
                )
            except Exception:                             # noqa: BLE001 -- log tail is best-effort
                pass
except Exception as _e:                                    # pragma: no cover - import-time-only guard around the marker-promotion block above; unreachable in tests (no marker) and not re-triggerable without a module reload
    log.warning(f"could not promote update result marker: {_e}")


def update_check_loop():
    """Hourly background update check (production). On finding a NEWER published version --
    higher than installed and not one already announced this run -- record an event and,
    if push is configured, send a push so operators learn of it with no browser open.
    Daemon thread; _monitor_stop ends it promptly on shutdown. The FRONTEND does its own
    on-load check via /api/check-update; this loop is the no-browser-open path.

    ONE-SHOT per run: we push (and log an event) AT MOST ONCE per application start, even
    if further releases appear later -- the operator hears about it once, not hourly. The
    flag resets naturally when the app restarts."""
    pushed = False
    if _monitor_stop.wait(30):                        # first check 30s after startup
        return
    while True:
        # Refresh the footer cache every cycle (so cached footer reads stay reasonably current)
        # and push exactly once per run when a newer version first appears.
        result = _run_update_check()
        latest = result["latest"]
        if not pushed and result["update_available"]:
            pushed = True                             # exactly one update push per restart
            log.info(f"Update available: v{latest} (installed v{APP_VERSION})")
            record_event("update", f"Update available: v{latest} (installed v{APP_VERSION})")
            store.send_push_async(
                "Update available",
                f"GeneratorPi v{latest} is available (you have v{APP_VERSION}).",
                tag="update",
            )
        if _monitor_stop.wait(3600):                  # ~hourly repo check; True == stop requested
            return
