#!/usr/bin/env python3
"""Detect invisible Unicode characters in files.

Usage: python check_invisible_chars.py <file1> [file2] ...
Exit codes: 0 = clean, 1 = issues found
"""

import sys
import unicodedata

INVISIBLE_RANGES = [
    (0x0000, 0x0008),  # Control chars
    (0x000B, 0x000C),  # VT, FF
    (0x000E, 0x001F),  # Control chars
    (0x007F, 0x007F),  # DEL
    (0x00A0, 0x00A0),  # Non-breaking space
    (0x2000, 0x200F),  # Various spaces + zero-width chars
    (0x2028, 0x202F),  # Separators + narrow no-break space
    (0x2060, 0x206F),  # Invisible operators
    (0xFEFF, 0xFEFF),  # BOM
]


def log(msg: str) -> None:
    """Write message to stderr (allowed by ruff)."""
    sys.stderr.write(msg + "\n")


def check_file(path: str) -> tuple[list[tuple[int, int, str]], str | None]:
    """Return (issues, error) where issues is list of (line, col, char_desc)."""
    issues: list[tuple[int, int, str]] = []
    try:
        with open(path, encoding="utf-8", errors="strict") as f:
            for line_num, line in enumerate(f, 1):
                for col, char in enumerate(line, 1):
                    code = ord(char)
                    if any(start <= code <= end for start, end in INVISIBLE_RANGES):
                        try:
                            name = unicodedata.name(char)
                        except ValueError:
                            name = "UNKNOWN"
                        issues.append((line_num, col, f"U+{code:04X} ({name})"))
    except UnicodeDecodeError as e:
        return [], f"UTF-8 decode error: {e}"
    except OSError as e:
        return [], f"File error: {e}"
    return issues, None


def main() -> int:
    if len(sys.argv) < 2:
        log("No files provided")
        return 0

    failed = False
    for path in sys.argv[1:]:
        log(f"Checking: {path}")
        issues, error = check_file(path)
        if error:
            log(f"  ::error file={path}::{error}")
            failed = True
        elif issues:
            failed = True
            for line, col, desc in issues:
                log(f"  ::error file={path},line={line},col={col}::{desc}")
        else:
            log("  ✓ Clean")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
