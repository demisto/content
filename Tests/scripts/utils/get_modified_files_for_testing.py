"""
This class replaces the old get_modified_files_for_testing function in collect_tests_and_content_packs
"""
import glob
import os
from enum import Enum
from typing import Dict, Set, Optional, Tuple, List

import demisto_sdk.commands.common.constants as constants
from demisto_sdk.commands.common import tools

from Tests.scripts.utils.collect_helpers import (
    COMMON_YML_LIST,
    is_pytest_file, checked_type, SECRETS_WHITE_LIST,
)


class FileType(constants.FileType, Enum):
    CONF_JSON = "confjson"
    METADATA = "metadata"
    WHITE_LIST = 'whitelist'


def resolve_type(file_path: str) -> Optional[FileType]:
    """Will classify file_path that tools.find_type could not find types for.

    Args:
        file_path: file path to classify

    Returns:
        FileType. Conf.json and Metadata files.
    """
    # if conf.json file
    if checked_type(file_path, [constants.CONF_PATH]):
        return FileType.CONF_JSON
    # MetaData files
    elif any(
        file in file_path
        for file in (
            constants.PACKS_PACK_META_FILE_NAME,
            constants.PACKS_WHITELIST_FILE_NAME,
        )
    ):
        return FileType.METADATA
    # Whitelist file type
    elif checked_type(file_path, [SECRETS_WHITE_LIST]):
        return FileType.WHITE_LIST
    return None


def remove_python_files(types_to_files: Dict[FileType, Set[str]]):
    """Get corresponding yml files and types from PY files.
    If a corresponding yml found, will remove the py file

    Args:
        types_to_files: Mapping of FileType: file_paths

    Returns:
        Filtered types_to_files
    """
    py_to_be_removed = set()
    for file_path in types_to_files.get(FileType.PYTHON_FILE, set()):
        if not is_pytest_file(file_path):
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
        else:
            py_to_be_removed.add(file_path)

    # remove python files
    if py_to_be_removed:
        types_to_files[FileType.PYTHON_FILE] = types_to_files[FileType.PYTHON_FILE] - py_to_be_removed

    return types_to_files


def create_type_to_file(files_string: str) -> Dict[FileType, Set[str]]:
    """Classifies the files in the diff list (files_string) using tools.find_type

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

    types_to_files = remove_python_files(types_to_files)

    return types_to_files


def remove_common_files(
        types_to_files: Dict[FileType, Set[str]], changed_common_files: Set[str]) -> Dict[FileType, Set[str]]:
    if changed_common_files:
        types_to_files[FileType.SCRIPT] = types_to_files[FileType.SCRIPT] - changed_common_files
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
        changed_common_files: Globally used YMLs (Like CommonServerPython).
        is_conf_json: If Tests/Conf.json has been changed.
        sample_tests: Files to test, Like the infrastructures files.
        modified_metadata: Pack names of changed metadata files.
        is_reputations_json: If any reputation file changed.
        is_indicator_json: If any indicator file changed.
    """
    types_to_files: Dict[FileType, Set[str]] = create_type_to_file(git_diff)  # Mapping of the files FileType: file path

    # Checks if any common file exists in types_to_file
    changed_common_files = get_common_files(types_to_files.get(FileType.SCRIPT, set()))
    types_to_files = remove_common_files(types_to_files, changed_common_files)
    # Sample tests are the remaining python files
    sample_tests = types_to_files.get(FileType.PYTHON_FILE, set())

    # Modified files = YMLs of integrations, scripts and playbooks
    modified_files: Set[str] = types_to_files.get(FileType.INTEGRATION, set()).union(
        types_to_files.get(FileType.SCRIPT, set()),
        types_to_files.get(FileType.PLAYBOOK, set()))  # Modified YMLs for testing (Integrations, Scripts, Playbooks).

    # Metadata packs
    modified_metadata: Set[str] = set()
    for file_path in types_to_files.get(FileType.METADATA, set()):
        modified_metadata.add(tools.get_pack_name(file_path))

    modified_tests: Set[str] = types_to_files.get(FileType.TEST_PLAYBOOK, set())  # Modified tests are test playbooks

    # Booleans. If this kind of file is inside, its exists
    is_conf_json = FileType.CONF_JSON in types_to_files

    is_reputations_json = FileType.REPUTATION in types_to_files

    is_indicator_json = FileType.INDICATOR_FIELD in types_to_files

    return (
        list(modified_files),
        list(modified_tests),
        list(changed_common_files),
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


def get_common_files(paths_set: Set[str]) -> Set[str]:
    """Gets paths of files and return only the common yml files

    Args:
        paths_set: A path to find common yml files on

    Returns:
        intersection of the Common files list
    """
    common_yml = set(COMMON_YML_LIST)
    return paths_set.intersection(common_yml)
