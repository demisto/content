"""
This class replaces the old get_modified_files_for_testing function in collect_tests_and_content_packs
"""
import glob
import os
import re
from enum import Enum
from typing import Dict, Set, Optional, Tuple

import demisto_sdk.commands.common.constants as constants
from demisto_sdk.commands.common import tools

from Tests.scripts.utils.collect_helpers import (
    COMMON_YML_LIST,
    is_pytest_file,
)


class FileType(constants.FileType, Enum):
    CONF_JSON = 'confjson'
    METADATA = 'metadata'


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


def create_diff_list(files_string) -> Dict[FileType, Set[str]]:
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
                    # Common YML files
                    if file_type in types_to_files:
                        types_to_files[file_type].add(file_path)
                    else:
                        types_to_files[file_type] = {file_path}
    return types_to_files


def get_modified_files_for_testing(files_string):
    """Get a string of the modified files"""
    sample_tests: Set[str] = set()
    modified_metadata_list: Set[str] = set()
    changed_common: Set[str] = set()
    modified_files: Set[str] = set()
    modified_tests: Set[str] = set()
    files_to_types: Dict[FileType, Set[str]] = create_diff_list(files_string)

    changed_common = changed_common.union(get_common_files(
        files_to_types.get(FileType.INTEGRATION, set()),
        files_to_types.get(FileType.SCRIPT, set())
    ))

    for file_path in changed_common:
        file_type = tools.find_type(file_path)
        files_to_types[file_type].remove(file_path)

    yml_corresponding_to_python, new_sample_tests = get_corresponding_yml_file(
        files_to_types.get(FileType.PYTHON_FILE, set())
    )

    sample_tests = new_sample_tests.union(sample_tests)

    modified_files = modified_files.union(
        yml_corresponding_to_python,
        files_to_types.get(FileType.INTEGRATION, set()),
        files_to_types.get(FileType.SCRIPT, set()),
        files_to_types.get(FileType.PLAYBOOK, set())
    )

    metadata_changed_pack = set()
    for file_path in files_to_types.get(FileType.METADATA, set()):
        metadata_changed_pack.add(tools.get_pack_name(file_path))

    modified_metadata_list = modified_metadata_list.union(metadata_changed_pack)

    is_conf_json = FileType.CONF_JSON in files_to_types

    modified_tests = modified_tests.union(files_to_types.get(FileType.TEST_PLAYBOOK, set()))

    is_reputations_json = FileType.REPUTATION in files_to_types

    is_indicator_json = FileType.INDICATOR_FIELD in files_to_types

    return (
        list(modified_files), list(modified_tests), list(changed_common),
        is_conf_json, list(sample_tests), modified_metadata_list,
        is_reputations_json, is_indicator_json
    )


def get_corresponding_yml_file(*args: set) -> Tuple[Set[str], Set[str]]:
    """Filtering out Python files that should not be tested.

    Currently:
    - Pytest files: Will be removed from files_to_types[FileType.PYTHON_FILE].
    - Python files belongs to integration/script: YMl file will be added to modified_file_list
    - All other files: Will be added to sample_tests.

    """
    py_files = set()
    sample_files = set()
    for arg in args:
        py_files = py_files.union(arg)
    yml_paths = set()
    for file_path in py_files:
        if not is_pytest_file(file_path):
            try:
                # Py files, Integration, script, playbook ymls
                dir_path = os.path.dirname(file_path)
                file_path = glob.glob(dir_path + "/*.yml")[0]
                yml_paths.add(file_path)
            except IndexError:  # Not matching yml - sample test
                sample_files.add(file_path)
    return yml_paths, sample_files


def get_common_files(*args: Set[str]) -> Set[str]:
    unified_args = set()
    for arg in args:
        unified_args = unified_args.union(arg)
    return set(arg for arg in unified_args if arg in COMMON_YML_LIST)
