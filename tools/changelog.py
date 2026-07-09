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
    """Build the CHANGELOG-RECENT.md text from the top `keep` releases of CHANGELOG.md.

    The in-app updater downloads this file and displays it VERBATIM in the update modal, so the
    output is shaped for that view:
      * NO preamble/header -- a "do-not-edit" notice would just render as noise at the top of the
        modal, so the file starts straight at the newest release heading.
      * Release sections are separated by a blank line, a '---' rule, and a blank line, so each
        release is visually delimited from the previous one.
      * Bullet/paragraph text is copied VERBATIM. CHANGELOG.md must therefore keep each bullet (and
        each prose paragraph) on a SINGLE line with NO hard wrapping: the updater applies its own
        word-wrap, and an embedded newline forces a premature break that mangles the formatting."""
    _, sections = split_sections(FULL.read_text())
    top = sections[:keep]
    return "\n\n---\n\n".join(s.rstrip() for s in top) + "\n"


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
