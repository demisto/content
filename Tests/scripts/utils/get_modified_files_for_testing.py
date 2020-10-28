"""
This class replaces the old get_modified_files_for_testing function in collect_tests_and_content_packs
"""
import glob
import os
import re
from enum import Enum
from typing import Dict, Set, Optional, Tuple, List

import demisto_sdk.commands.common.constants as constants
from demisto_sdk.commands.common import tools

from Tests.scripts.utils.collect_helpers import (
    COMMON_YML_LIST,
    is_pytest_file,
)


class FileType(constants.FileType, Enum):
    CONF_JSON = "confjson"
    METADATA = "metadata"


def resolve_type(file_path: str) -> Optional[FileType]:
    """Will classify file_path that tools.find_type could not find types for.

    Args:
        file_path: file path to classify

    Returns:
        FileType. Conf.json and Metadata files.
    """
    if re.match(constants.CONF_PATH, file_path, re.IGNORECASE):
        return FileType.CONF_JSON
    # if is not part of packs meta file name or whitelisted
    elif any(
        file in file_path
        for file in (
            constants.PACKS_PACK_META_FILE_NAME,
            constants.PACKS_WHITELIST_FILE_NAME,
        )
    ):
        return FileType.METADATA
    return None


def create_type_to_file(files_string) -> Dict[FileType, Set[str]]:
    """Classified the diff list using tools.find_type

    Returns:
        A dict of {FileType: Set of files}
    """
    types_to_files: Dict[FileType, Set[str]] = dict()
    for line in files_string.split("\n"):
        if line:
            file_status, file_path = line.split(maxsplit=1)
            file_status = file_status.lower()
            # Get to right file_path on renamed
            if file_status.startswith("r"):
                _, file_path = file_path.split(maxsplit=1)
            file_status = file_status.lower()
            # ignoring deleted files.
            # also, ignore files in ".circle", ".github" and ".hooks" directories and .
            if file_path:
                if (
                    file_status in ("m", "a") or file_status.startswith("r")
                ) and not file_path.startswith("."):
                    file_type = tools.find_type(file_path) or resolve_type(file_path)
                    if file_type in types_to_files:
                        types_to_files[file_type].add(file_path)
                    elif file_type is not None:
                        types_to_files[file_type] = {file_path}

    # Get corresponding yml files and types from PY files.
    py_to_be_removed = set()
    for file_path in types_to_files.get(FileType.PYTHON_FILE, set()):
        yml_path = get_corresponding_yml_file(file_path)
        # There's a yml path
        if yml_path is not None:
            yml_type = tools.find_type(yml_path) or resolve_type(file_path)
            if yml_type is not None:
                if yml_type in types_to_files:
                    types_to_files[yml_type].add(yml_path)
                else:
                    types_to_files[yml_type] = {yml_path}
                py_to_be_removed.add(file_path)

    # remove python files
    if py_to_be_removed:
        types_to_files[FileType.PYTHON_FILE] = types_to_files[FileType.PYTHON_FILE] - py_to_be_removed

    return types_to_files


def get_modified_files_for_testing(
    git_diff: str,
) -> Tuple[List[str], List[str], List[str], bool, List[str], set, bool, bool]:
    """
    Gets git diff string and filters those files into tests:

    Args:
        git_diff: a git diff output (with --name-only flag)
    Returns:
        modified_files: Modified YMLs for testing (Integrations, Scripts, Playbooks).
        modified_tests: Test playbooks.
        changed_common: Globally used YMLs (Like CommonServerPython).
        is_conf_json: If Tests/Conf.json has been changed.
        sample_tests: Files to test, Like the infrastructures files.
        modified_metadata: Metadata files.
        is_reputations_json: If any reputation file changed.
        is_indicator_json: If any indicator file changed.
    """
    sample_tests: Set[str] = set()
    modified_metadata: Set[str] = set()
    modified_files: Set[str] = set()
    types_to_files: Dict[FileType, Set[str]] = create_type_to_file(git_diff)

    # Checks if any common file represents in it
    changed_common = get_common_files(
            types_to_files.get(FileType.INTEGRATION, set()),
            types_to_files.get(FileType.SCRIPT, set())
    )

    # Remove common files from the sets
    for file_path in changed_common:
        file_type = tools.find_type(file_path)
        try:
            types_to_files[file_type].remove(file_path)
        except KeyError:
            # Can be a python file that changed and now the yml representing. Will ignore
            pass

    # Remove pytest files
    pytest_files = set(filter(is_pytest_file, types_to_files.get(FileType.PYTHON_FILE, {})))
    if pytest_files:
        types_to_files[FileType.PYTHON_FILE] = types_to_files[FileType.PYTHON_FILE] - pytest_files

    # Sample tests are the remaining python files
    sample_tests = sample_tests.union(types_to_files.get(FileType.PYTHON_FILE, set()))

    # Modified files = YMLs of integrations, scripts and playbooks
    modified_files = modified_files.union(
        types_to_files.get(FileType.INTEGRATION, set()),
        types_to_files.get(FileType.SCRIPT, set()),
        types_to_files.get(FileType.PLAYBOOK, set()),
    )

    # Metadata packs
    for file_path in types_to_files.get(FileType.METADATA, set()):
        modified_metadata.add(tools.get_pack_name(file_path))

    # Modified tests are test playbooks
    modified_tests: Set[str] = types_to_files.get(FileType.TEST_PLAYBOOK, set())

    # Booleans. If this kind of file is inside, its exists
    is_conf_json = FileType.CONF_JSON in types_to_files

    is_reputations_json = FileType.REPUTATION in types_to_files

    is_indicator_json = FileType.INDICATOR_FIELD in types_to_files

    return (
        list(modified_files),
        list(modified_tests),
        list(changed_common),
        is_conf_json,
        list(sample_tests),
        modified_metadata,
        is_reputations_json,
        is_indicator_json,
    )


def get_corresponding_yml_file(file_path: str) -> Optional[str]:
    """Gets yml files from file path.

    Args:
        file_path

    Returns:
        file path of the yml file if exists else None.
    """
    try:
        # Py files, Integration, script, playbook ymls
        dir_path = os.path.dirname(file_path)
        file_path = glob.glob(dir_path + "/*.yml")[0]
        return file_path
    except IndexError:  # Not matching yml - sample test
        return None


def get_common_files(*args: Set[str]) -> Set[str]:
    unified_args: Set[str] = set()
    for arg in args:
        unified_args = unified_args.union(arg)
    return set(arg for arg in unified_args if arg in COMMON_YML_LIST)
