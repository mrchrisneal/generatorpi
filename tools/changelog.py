#!/usr/bin/env python3
"""Generate CHANGELOG-RECENT.md -- the SHORT changelog the in-app updater downloads on every version
check -- from the full CHANGELOG.md.

CHANGELOG.md stays the complete, canonical, ever-growing history. CHANGELOG-RECENT.md holds only the
N most recent releases, so a version check isn't a full-history download. Run at release time (after
editing CHANGELOG.md) and commit both files; a CI --check gate keeps them in sync.

Usage:
  python3 tools/changelog.py            # regenerate CHANGELOG-RECENT.md (5 most recent releases)
  python3 tools/changelog.py --keep 5   # keep a different number
  python3 tools/changelog.py --check    # exit 1 if CHANGELOG-RECENT.md is out of date (CI gate)
"""
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FULL = ROOT / "CHANGELOG.md"
RECENT = ROOT / "CHANGELOG-RECENT.md"
KEEP = 5

# Header for the generated file (do-not-edit + points back at the full history).
RECENT_HEADER = (
    "# Changelog (recent)\n"
    "\n"
    "The {n} most recent GeneratorPi releases -- this short file is what the in-app updater downloads\n"
    "on a version check. It is GENERATED from the full history in [CHANGELOG.md](CHANGELOG.md) by\n"
    "`tools/changelog.py`; do NOT edit it by hand.\n"
)


def split_sections(text):
    """Return (header_before_first_release, [release_section, ...]). A release heading starts with
    '## <digit>' (e.g. '## 1.3.0 -- July 8, 2026'), so prose headings in the intro aren't matched."""
    marks = list(re.finditer(r"(?m)^## \d\S*", text))
    if not marks:
        return text, []
    header = text[:marks[0].start()]
    sections = []
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        sections.append(text[m.start():end].rstrip() + "\n")
    return header, sections


def render(keep):
    """Build the CHANGELOG-RECENT.md text from the top `keep` releases of CHANGELOG.md."""
    _, sections = split_sections(FULL.read_text())
    top = sections[:keep]
    body = "\n".join(s.rstrip() for s in top)
    return RECENT_HEADER.format(n=len(top)) + "\n" + body + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--keep", type=int, default=KEEP, help="number of recent releases to keep")
    ap.add_argument("--check", action="store_true", help="exit 1 if CHANGELOG-RECENT.md is stale (CI)")
    args = ap.parse_args()

    want = render(args.keep)
    if args.check:
        have = RECENT.read_text() if RECENT.exists() else ""
        if have != want:
            print("::error::CHANGELOG-RECENT.md is stale -- run: python3 tools/changelog.py", file=sys.stderr)
            return 1
        print("CHANGELOG-RECENT.md is up to date.")
        return 0

    RECENT.write_text(want)
    print(f"Wrote {RECENT.name} with the {min(args.keep, len(split_sections(FULL.read_text())[1]))} "
          f"most recent release(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
