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


def is_pack_xsoar_supported(pack_name: str) -> bool:
    """
    Checks whether the supplied Pack is from a XSOAR-supported

    Args:
        - `pack_name` (``str``): The name of the Pack

    Returns:
        `bool` representing whether Pack is XSOAR-supported or not
    """

    pack_metadata = Path("Packs", pack_name, "pack_metadata.json")

    with pack_metadata.open(encoding="UTF-8") as pm:
        metadata: Dict[str, Any] = json.load(pm)
        if metadata.get("support") == "xsoar":
            return True

    return False


def convert_file_to_path(release_note_path: str) -> Path:
    """
    Converts a relative file path to a `Path` object for 
    easier navigation of filesystem.

    Args:
        - `release_note_path` (``str``): The relative path to the file.

    Returns:
        `Path` representing the filesystem of the provided file.
    """
    return Path(release_note_path)


def main(args: argparse.Namespace) -> None:
    arg_dict: Dict[str, Any] = vars(args)

    release_notes: List[Path] = map(convert_file_to_path, arg_dict.get("release_notes").split(","))
    release_notes_to_review: List[str] = []

    for rn in release_notes:
        # parts returns Tuple[str], e.g. ('Packs', 'HelloWorld', 'ReleaseNotes', '1_3_0.md')
        pack_name = rn.parts[1]
        if is_pack_xsoar_supported(pack_name):
            release_notes_to_review.append(str(rn))

    print(",".join(release_notes_to_review))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("release_notes", help="Comma separated list of release notes paths")
    parser.add_argument('-d', '--delimiter', help="The delimiter that separates the changed files names,"
                                                  " defined in yq 'env.CHANGED_FILES_DELIMITER' .github/workflows/"
                                                  "review-release-notes.yml", default=",")

    args = parser.parse_args()
    main(args)
