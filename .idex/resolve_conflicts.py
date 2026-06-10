#!/usr/bin/env python3
"""Resolve git merge conflicts by preserving all data from both sides.

Strategy:
- If one side is empty/whitespace-only -> keep the non-empty side.
- If both sides are identical -> keep one copy.
- If both sides differ -> keep both, in order (HEAD first, then theirs).

This is a "union" merge that never loses data. The user can review
afterwards. Does not touch files without conflict markers.
"""
import sys
import os
import re
from pathlib import Path

CONFLICT_START = re.compile(r"^<<<<<<<\s")
CONFLICT_MID = re.compile(r"^=======\s*$")
CONFLICT_END = re.compile(r"^>>>>>>>\s")


def resolve_file(path: str):
    with open(path, "r", encoding="utf-8", errors="surrogateescape") as f:
        lines = f.readlines()

    out = []
    i = 0
    n = len(lines)
    total = identical = one_empty = both_kept = 0

    while i < n:
        line = lines[i]
        if CONFLICT_START.match(line):
            head = []
            i += 1
            while i < n and not CONFLICT_MID.match(lines[i]):
                if CONFLICT_START.match(lines[i]) or CONFLICT_END.match(lines[i]):
                    raise RuntimeError(
                        f"Nested/malformed conflict in {path} at line {i + 1}"
                    )
                head.append(lines[i])
                i += 1
            if i >= n:
                raise RuntimeError(f"Unterminated conflict (no '=======') in {path}")
            i += 1
            theirs = []
            while i < n and not CONFLICT_END.match(lines[i]):
                if CONFLICT_START.match(lines[i]) or CONFLICT_MID.match(lines[i]):
                    raise RuntimeError(
                        f"Nested/malformed conflict in {path} at line {i + 1}"
                    )
                theirs.append(lines[i])
                i += 1
            if i >= n:
                raise RuntimeError(f"Unterminated conflict (no '>>>>>>>') in {path}")
            i += 1
            total += 1

            head_str = "".join(head)
            theirs_str = "".join(theirs)
            head_empty = head_str.strip() == ""
            theirs_empty = theirs_str.strip() == ""

            if head_str == theirs_str:
                out.extend(head)
                identical += 1
            elif head_empty and not theirs_empty:
                out.extend(theirs)
                one_empty += 1
            elif theirs_empty and not head_empty:
                out.extend(head)
                one_empty += 1
            elif head_empty and theirs_empty:
                identical += 1
            else:
                out.extend(head)
                out.extend(theirs)
                both_kept += 1
        else:
            out.append(line)
            i += 1

    with open(path, "w", encoding="utf-8", errors="surrogateescape") as f:
        f.writelines(out)

    return total, identical, one_empty, both_kept


def main(paths):
    grand = [0, 0, 0, 0]
    for p in paths:
        if not os.path.isfile(p):
            print(f"SKIP (missing): {p}")
            continue
        try:
            total, identical, one_empty, both_kept = resolve_file(p)
        except Exception as e:
            print(f"ERROR {p}: {e}")
            return 2
        grand[0] += total
        grand[1] += identical
        grand[2] += one_empty
        grand[3] += both_kept
        print(
            f"{p}: total={total} identical={identical} "
            f"one_empty={one_empty} both_kept={both_kept}"
        )
    print("---")
    print(
        f"GRAND TOTAL: conflicts={grand[0]} identical={grand[1]} "
        f"one_empty={grand[2]} both_kept={grand[3]}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
