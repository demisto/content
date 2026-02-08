#!/usr/bin/env python3
"""Check for invisible/problematic Unicode characters in AGENTS.md files.

This script detects invisible characters that can cause issues in code and documentation,
such as zero-width spaces, non-breaking spaces, and bidirectional text markers.

Usage:
    python check_invisible_chars.py <file1> [file2] ...

Only files named 'AGENTS.md' will be checked. Other files are skipped.

Exit codes:
    0 - All files passed (no invisible characters found)
    1 - Invisible characters detected or error occurred
"""

import sys
import unicodedata
from pathlib import Path

# Only check files with this name
ALLOWED_FILENAME = "AGENTS.md"

# Define invisible/problematic Unicode character ranges
INVISIBLE_RANGES = [
    (0x0000, 0x0008),  # Control characters (NUL to BS)
    (0x000B, 0x000C),  # Vertical tab, form feed
    (0x000E, 0x001F),  # Control characters (SO to US)
    (0x007F, 0x007F),  # DEL
    (0x00A0, 0x00A0),  # Non-breaking space
    (0x200B, 0x200F),  # Zero-width spaces, directional marks
    (0x2028, 0x202F),  # Line/paragraph separators, directional formatting
    (0x2060, 0x206F),  # Word joiner, invisible operators
    (0xFEFF, 0xFEFF),  # Byte order mark (BOM)
    (0xFFF9, 0xFFFC),  # Interlinear annotation anchors
]


def is_invisible(char: str) -> bool:
    """Check if a character is in the invisible/problematic ranges."""
    code = ord(char)
    return any(start <= code <= end for start, end in INVISIBLE_RANGES)


def get_char_description(char: str) -> str:
    """Get a human-readable description of a Unicode character."""
    code = ord(char)
    try:
        name = unicodedata.name(char)
    except ValueError:
        name = "UNKNOWN"
    return f"U+{code:04X} ({name})"


def check_file(filepath: str) -> bool:
    """Check a file for invisible characters.

    Args:
        filepath: Path to the file to check.

    Returns:
        True if the file is clean, False if invisible characters were found.
    """
    print(f"Checking: {filepath}")
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"::error file={filepath}::File not found")
        return False
    except UnicodeDecodeError as e:
        print(f"::error file={filepath}::Unicode decode error: {e}")
        return False
    except Exception as e:
        print(f"::error file={filepath}::Error reading file: {e}")
        return False

    file_is_clean = True
    for line_num, line in enumerate(lines, 1):
        for col, char in enumerate(line, 1):
            if is_invisible(char):
                desc = get_char_description(char)
                print(f"::error file={filepath},line={line_num},col={col}::Found invisible character {desc}")
                file_is_clean = False

    if file_is_clean:
        print(f"✓ No invisible characters found in {filepath}")

    return file_is_clean


def main() -> int:
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python check_invisible_chars.py <file1> [file2] ...")
        print("No files provided.")
        return 0

    files = sys.argv[1:]
    all_clean = True

    # Validate all files are AGENTS.md
    for filepath in files:
        if Path(filepath).name != ALLOWED_FILENAME:
            print(f"::error::Invalid file: {filepath}")
            print(f"This script only accepts {ALLOWED_FILENAME} files.")
            return 1

    for filepath in files:
        if not check_file(filepath):
            all_clean = False

    if not all_clean:
        print()
        print("::error::Invisible characters detected! Please remove them before merging.")
        print("Common invisible characters include:")
        print("  - Zero-width space (U+200B)")
        print("  - Non-breaking space (U+00A0)")
        print("  - Zero-width non-joiner (U+200C)")
        print("  - Zero-width joiner (U+200D)")
        print("  - Byte order mark (U+FEFF)")
        return 1

    print("✓ All files passed invisible character check")
    return 0


if __name__ == "__main__":
    sys.exit(main())
