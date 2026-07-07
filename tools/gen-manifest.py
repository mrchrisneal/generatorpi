#!/usr/bin/env python3
"""Generate manifest.json for the in-app self-updater (#8).

Lists each shipped CODE file with its SHA-256 + size so the updater can download a
release from the repo (raw GitHub, per the owner's chosen mechanism) and verify EVERY
file against these hashes before swapping. Run at release time -- and by the CI pipeline
(#11) -- then commit + push manifest.json so running instances can fetch it and compare.

Deliberately EXCLUDES runtime/secret files (generator_control.env, TLS certs, events.db,
logs) and dev-only trees (tests/, scratchpads/, tools/): an update must NEVER touch
operator data or credentials, so those are simply never in the manifest and never fetched.

Usage:  python3 tools/gen-manifest.py   (writes ./manifest.json)
"""
import hashlib
import json
import sys
from pathlib import Path

# Repo root = parent of this tools/ dir. All manifest paths are relative to it.
ROOT = Path(__file__).resolve().parent.parent

# The exact set of files that constitute a release -- what the updater downloads + swaps.
# Keep this list in sync with what a fresh install needs; anything NOT here is preserved
# untouched on the target during an update.
SHIPPED_FILES = [
    "generator_control.py",   # the app (single file)
    "requirements.txt",       # pip deps (setup.sh reinstall picks up changes)
    "setup.sh",               # (re)install / systemd wiring
    "update.sh",              # git-pull fallback updater
    "VERSION",                # single source of truth for the version
    "CHANGELOG.md",           # release notes shown in the update modal
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
    return {"version": version, "files": entries}


def main():
    manifest = build_manifest()
    out = ROOT / "manifest.json"
    out.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {out.name}: version {manifest['version']}, {len(manifest['files'])} files")


if __name__ == "__main__":
    main()
