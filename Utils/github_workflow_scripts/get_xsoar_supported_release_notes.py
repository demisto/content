#!/usr/bin/env python3
"""
This script is used in the Review Release Notes GitHub workflow.
It accepts a list of changed files (release notes)
and returns the release notes of XSOAR-supported Packs.
"""

from typing import Dict, Any, List
import json
from pathlib import Path
import argparse
import sys
import traceback


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
    Converts a list of relative file paths to a list of `Path` objects for
    easier navigation of filesystem.

    Args:
        - `files` (``List[str]``): The relative paths to the file.

    Returns:
        `List[Path]` representing a list of filesystem files.
    """

    return list(map(lambda f: Path(f), files))


def format_output(rns_to_review: List[str], delimiter: str = ",") -> str:
    """
    Convert the list of release notes to review into a comma-separated string
    in preparation for output.

    Args:
        - `rns_to_review` (``List[str]``): List of release note paths.
        - `delimiter` (`str`): The delimiter to separate the release note paths

    Returns"
        `str` of joined release notes to review
    """

    return delimiter.join(rns_to_review)


def main(args: argparse.Namespace) -> str:  # pragma: no cover

    """
    Receives the delimiter and release note arguments,
    parses the release notes into a paths and checks whether they are part
    of an XSOAR-supported Pack.

    Returns the output, list of paths of release notes requiring review.

    """

    arg_dict: Dict[str, Any] = vars(args)

    delimiter: str = arg_dict.get("delimiter", ",")
    release_notes_arg: List[Path] = convert_files_to_paths(arg_dict.get("release_notes", []).split(delimiter))

    # Create new list to hold release notes to review
    release_notes_to_review: List[str] = []

    # Iterate over all release notes provided in the args
    # If the Pack is XSOAR-supported, we want to add it to
    # the list of RNs we want to review.

    if release_notes_arg:
        for rn in release_notes_arg:
            pack_name = rn.parts[1]
            if is_pack_xsoar_supported(pack_name):
                release_notes_to_review.append(str(rn))

        if release_notes_to_review:
            return format_output(release_notes_to_review, delimiter)
        else:
            return ""
    else:
        return ""


if __name__ == "__main__":  # pragma: no cover
    parser = argparse.ArgumentParser()

    parser.add_argument("release_notes", help="Comma separated list of release notes paths")
    parser.add_argument('-d', '--delimiter', help="The delimiter that separates the changed files names,"
                                                  " defined in yq 'env.CHANGED_FILES_DELIMITER' .github/workflows/"
                                                  "review-release-notes.yml", default=",")

    args = parser.parse_args()

    try:
        output = main(args)
        print(output)
        sys.exit(0)
    except Exception:
        print(f"Script terminated, reason:\n{traceback.format_exc()}")
        sys.exit(1)
