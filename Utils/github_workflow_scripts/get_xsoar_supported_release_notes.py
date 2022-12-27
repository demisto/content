#!/usr/bin/env python3
"""
This script is used in the Review Release Notes GitHub workflow.
It accepts a list of changed files (pack_metadata and release notes)
and returns the release notes of XSOAR-supported Packs.
"""

from typing import Dict, Any, List
import json
from pathlib import Path
import argparse
import sys


def is_pack_xsoar_supported(pack_name: str) -> bool:
    """
    Checks whether the supplied Pack is from a XSOAR-supported

    Args:
        - `pack_name` (``str``): The name of the Pack

    Returns:
        `bool` representing whether Pack is XSOAR-supported or not
    """

    pack_metadata = Path("Packs", pack_name, "pack_metadata.json")

    if pack_metadata.exists():
        with pack_metadata.open(encoding="UTF-8") as pm:
            metadata: Dict[str, Any] = json.load(pm)
            if metadata.get("support") == "xsoar":
                return True

    return False


def convert_files_to_paths(files: List[str]) -> List[Path]:
    """
    Converts a list of relative file paths to a list of `Path` object for
    easier navigation of filesystem.

    Args:
        - `files` (``List[str]``): The relative paths to the file.

    Returns:
        `List[Path]` representing a list of filesystem files.
    """

    return list(map(lambda f: Path(f), files))


def main(args: argparse.Namespace) -> None:
    arg_dict: Dict[str, Any] = vars(args)

    delimiter: str = arg_dict.get("delimiter")
    release_notes_arg: List[Path] = convert_files_to_paths(arg_dict.get("release_notes").split(delimiter))

    # Create new list to hold release notes to review
    release_notes_to_review: List[str] = []

    for rn in release_notes_arg:
        pack_name = rn.parts[1]
        if is_pack_xsoar_supported(pack_name):
            release_notes_to_review.append(str(rn))

    if release_notes_to_review:
        print(",".join(release_notes_to_review))

    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("release_notes", help="Comma separated list of release notes paths")
    parser.add_argument('-d', '--delimiter', help="The delimiter that separates the changed files names,"
                                                  " defined in yq 'env.CHANGED_FILES_DELIMITER' .github/workflows/"
                                                  "review-release-notes.yml", default=",")

    args = parser.parse_args()
    sys.exit(main(args))
