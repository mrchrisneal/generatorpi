#!/usr/bin/env python3
"""Generate manifest.json for the in-app self-updater (#8).

Lists each shipped CODE file with its SHA-256 + size so the updater can download a
release from the repo (raw GitHub, per the owner's chosen mechanism) and verify EVERY
file against these hashes before swapping. Run at release time -- and by the CI pipeline
(#11) -- then commit + push manifest.json so running instances can fetch it and compare.

Deliberately EXCLUDES runtime/secret files (generator_control.env, TLS certs, events.db,
logs) and dev-only trees (tests/, scratchpads/): an update must NEVER touch operator data
or credentials. From tools/ ONLY the bundled gp-monitor tool is shipped (gen-manifest.py +
__pycache__ stay out). The FULL CHANGELOG.md is NOT shipped -- only the generated, short
CHANGELOG-RECENT.md (which is also what the updater's version check downloads).

Usage:  python3 tools/gen-manifest.py   (writes ./manifest.json)
"""
import hashlib
import json
import re
import sys
from pathlib import Path

# A CLI-only gate must be a CLEAN dotted-numeric version (X.Y.Z) -- NOT the 'v1.4.0' tag form. A malformed
# gate would parse to a tiny version tuple and silently NEVER block the updater (fail-OPEN), defeating the
# whole feature, so we reject it LOUDLY at manifest-generation time (below) rather than ship an inert gate.
_GATE_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")

# Repo root = parent of this tools/ dir. All manifest paths are relative to it.
ROOT = Path(__file__).resolve().parent.parent

# The app is the genpi/ PACKAGE (not a single file any more): every code + asset file under
# it ships and is hash-verified/swapped by the updater. Enumerate it by GLOB so a newly added
# submodule or frontend asset can NEVER be silently left out of a release -- a missing file would
# break the in-app update. Sorted for a stable, reproducible manifest ordering; __pycache__ (the
# compiled .pyc cache) is excluded -- it is rebuilt by `compileall` at install, never shipped.
_PKG_EXTS = (".py", ".css", ".js", ".html")
_PACKAGE_FILES = sorted(
    str(p.relative_to(ROOT))
    for p in (ROOT / "genpi").rglob("*")
    if p.is_file() and p.suffix in _PKG_EXTS and "__pycache__" not in p.parts
)

# The exact set of files that constitute a release -- what the updater downloads + swaps.
# Keep this list in sync with what a fresh install needs; anything NOT here is preserved
# untouched on the target during an update.
SHIPPED_FILES = _PACKAGE_FILES + [
    "requirements.txt",       # pip deps (setup.sh reinstall picks up changes)
    "setup.sh",               # (re)install / systemd wiring
    "update.sh",              # git-pull fallback updater
    "VERSION",                # single source of truth for the version
    "CHANGELOG-RECENT.md",    # short generated release notes (updater fetches this, not the full log)
    "tools/gp-monitor.py",    # bundled Wi-Fi/perf diagnostic tool (installs into tools/ on the Pi)
    "tools/gp-monitor.md",    # gp-monitor docs (mirrors the wiki Wi-Fi-Diagnostics page)
]


# Runtime dependencies this release needs, DECLARED in the manifest so the in-app updater can
# check them during Stage 1 (before the apply) and tell the operator exactly what to install --
# it never installs them itself (that would need broad privileged apt access on a headless box).
# `module` is the import name (checked via importlib.util.find_spec, no side effects); `apt` is
# the Raspberry Pi OS package; `required` False = an optional feature that degrades gracefully.
# Keep in sync with setup.sh's check_dep calls (install-time) -- same set, same packages.
DEPENDENCIES = [
    {"module": "flask",        "apt": "python3-flask",        "required": True,  "feature": "web server + REST API"},
    {"module": "gpiozero",     "apt": "python3-gpiozero",     "required": True,  "feature": "GPIO relay control"},
    {"module": "lgpio",        "apt": "python3-lgpio",        "required": True,  "feature": "GPIO backend (lgpio)"},
    {"module": "cryptography", "apt": "python3-cryptography", "required": True,  "feature": "TLS certificate, VAPID keys, password hashing"},
    {"module": "cheroot",      "apt": "python3-cheroot",      "required": False, "feature": "HTTP keep-alive server (faster HTTPS)"},
    {"module": "py_vapid",     "apt": "python3-py-vapid",     "required": False, "feature": "Web Push notifications"},
    {"module": "http_ece",     "apt": "python3-http-ece",     "required": False, "feature": "Web Push notifications"},
    {"module": "requests",     "apt": "python3-requests",     "required": False, "feature": "Web Push notifications"},
]


# Per-release UPDATE CONSTRAINTS surfaced to the in-app web updater (added v1.5.0).
#
# CLI_ONLY_VERSIONS: versions that can ONLY be installed via the CLI (`./setup.sh reinstall` or
# `./update.sh`) -- e.g. a release that changes the systemd entrypoint / package layout, which the
# in-app updater cannot do (its scoped sudo can't rewrite the unit). This is an APPEND-ONLY list of
# every such "gate" release. The in-app updater REFUSES to apply the latest release when ANY listed
# version G falls STRICTLY ABOVE the device's installed version and AT-OR-BELOW the latest
# (installed < G <= latest) -- i.e. a manual gate sits between where the user is and where they'd land.
# This is what stops a very old install from web-JUMPING across a gate and failing hard: it's blocked
# and told to install manually (which always jumps straight to latest, crossing every gate at once, so
# nobody is ever stuck). Append a version here whenever you cut such a release. If the LATEST release is
# itself a gate, include it too (then everyone below it is blocked -> all install via the CLI).
#
# IMPORTANT_NOTES: operator guidance shown in the updater's IMPORTANT box when a release is blocked
# (list of strings; a single string is also accepted). Older clients ignore both keys (forward-compat).
CLI_ONLY_VERSIONS = ["1.4.0"]   # v1.4.0 restructured the app into a package + repointed the systemd entrypoint
IMPORTANT_NOTES = []


def _sha256(path):
    """Streaming SHA-256 of a file (64 KiB chunks) so a large file never loads whole."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_manifest(root=ROOT, files=SHIPPED_FILES):
    """Return the manifest dict for the given root. Missing files are skipped with a
    warning (a release should have them all, but we never crash on a packaging slip)."""
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    # Fail LOUD on a malformed CLI-only gate (e.g. the natural 'v1.4.0' typo, or garbage) -- it would
    # parse to a tiny tuple in the updater and silently never block, defeating the feature. Better a
    # broken release build than an inert gate that lets an old install web-jump across it and brick.
    _bad = [g for g in CLI_ONLY_VERSIONS if not _GATE_VERSION_RE.match(str(g))]
    if _bad:
        raise ValueError(f"CLI_ONLY_VERSIONS has malformed entries {_bad!r}: each must be a clean "
                         f"dotted-numeric version like '1.4.0' (NOT 'v1.4.0'). A bad gate fails OPEN.")
    entries = []
    for rel in files:
        p = root / rel
        if not p.exists():
            print(f"WARN: {rel} not found -- skipping", file=sys.stderr)
            continue
        entries.append({"path": rel, "sha256": _sha256(p), "bytes": p.stat().st_size})
    return {"version": version, "files": entries, "dependencies": DEPENDENCIES,
            "cli_only_versions": CLI_ONLY_VERSIONS,
            "important_notes": IMPORTANT_NOTES}


def main():
    manifest = build_manifest()
    out = ROOT / "manifest.json"
    out.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {out.name}: version {manifest['version']}, {len(manifest['files'])} files")


if __name__ == "__main__":
    main()
