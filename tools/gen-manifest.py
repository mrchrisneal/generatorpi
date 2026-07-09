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
import sys
from pathlib import Path

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
    entries = []
    for rel in files:
        p = root / rel
        if not p.exists():
            print(f"WARN: {rel} not found -- skipping", file=sys.stderr)
            continue
        entries.append({"path": rel, "sha256": _sha256(p), "bytes": p.stat().st_size})
    return {"version": version, "files": entries, "dependencies": DEPENDENCIES}


def main():
    manifest = build_manifest()
    out = ROOT / "manifest.json"
    out.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {out.name}: version {manifest['version']}, {len(manifest['files'])} files")


if __name__ == "__main__":
    main()
