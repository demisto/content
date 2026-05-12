#!/usr/bin/env python3
"""
sync_yaml.py — copy Darkmon.py into Darkmon_Dev.yml's embedded script block.

XSOAR runs the script embedded inside the YAML, NOT the standalone Darkmon.py.
Run this whenever you edit Darkmon.py, before committing or importing the YAML.

Usage:
    python sync_yaml.py            # sync Darkmon.py -> Darkmon_Dev.yml
    python sync_yaml.py --check    # verify in sync; non-zero exit if drift

Idempotent: running again when already synced reports "no changes" and exits 0.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "Darkmon.py"
YML = HERE / "Darkmon.yml"
INDENT = "    "  # 4 spaces - the indent inside `  script: |` (which is at 2 spaces)
START = "\n  script: |\n"
END = "\n  type: python\n"


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


def _embed(src_text: str) -> str:
    return "\n".join((INDENT + ln) if ln else "" for ln in src_text.splitlines())


def _extract_block(yml_text: str) -> tuple[int, int, str]:
    i = yml_text.find(START)
    if i == -1:
        raise SystemExit(f"ERROR: could not find '{START.strip()}' in {YML}")
    j = yml_text.find(END, i)
    if j == -1:
        raise SystemExit(f"ERROR: could not find '{END.strip()}' after script block in {YML}")
    body_start = i + len(START)
    body_end = j + 1  # include trailing newline before END
    return body_start, body_end, yml_text[body_start:body_end]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true",
                        help="Verify in-sync without writing. Non-zero exit on drift.")
    args = parser.parse_args()

    if not SRC.exists():
        raise SystemExit(f"ERROR: {SRC} not found")
    if not YML.exists():
        raise SystemExit(f"ERROR: {YML} not found")

    src_text = SRC.read_text(encoding="utf-8")
    yml_text = YML.read_text(encoding="utf-8")

    body_start, body_end, current_body = _extract_block(yml_text)
    new_body = _embed(src_text.rstrip("\n")) + "\n"

    src_lines = src_text.rstrip("\n").splitlines()
    print(f"Darkmon.py:           {len(src_lines):>5} lines, sha {_sha(src_text)}")
    print(f"YAML embedded:    {len(current_body.rstrip(chr(10)).splitlines()):>5} lines, sha {_sha(current_body)}")

    if current_body == new_body:
        print("In sync. No changes needed.")
        return 0

    if args.check:
        # Find and report the first differing line for actionability.
        cur_lines = current_body.rstrip("\n").splitlines()
        new_lines = new_body.rstrip("\n").splitlines()
        for i, (a, b) in enumerate(zip(cur_lines, new_lines), start=1):
            if a != b:
                print(f"\nDRIFT at script line {i}:")
                print(f"  YAML embedded: {a!r}")
                print(f"  Darkmon.py:        {b!r}")
                break
        else:
            shorter = "YAML" if len(cur_lines) < len(new_lines) else "Darkmon.py"
            print(f"\nDRIFT: {shorter} is shorter "
                  f"({len(cur_lines)} vs {len(new_lines)} lines).")
        print("\nRun without --check to re-sync.")
        return 1

    new_yml = yml_text[:body_start] + new_body + yml_text[body_end:]
    YML.write_text(new_yml, encoding="utf-8")
    print(f"Synced {len(src_lines)} lines -> {YML.name}")
    print(f"YAML  {len(yml_text)} chars -> {len(new_yml)} chars")
    return 0


if __name__ == "__main__":
    sys.exit(main())
