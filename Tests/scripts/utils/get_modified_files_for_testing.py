"""
This class replaces the old get_modified_files_for_testing function in collect_tests_and_content_packs
"""
import glob
import os
import re
from typing import Dict, List, Set, Tuple

import demisto_sdk.commands.common.constants as constants
from demisto_sdk.commands.common.constants import FileType
from demisto_sdk.commands.common import tools

from Tests.scripts.utils.collect_helpers import (
    COMMON_YML_LIST, FILES_IN_SCRIPTS_OR_INTEGRATIONS_DIRS_REGEXES,
    SECRETS_WHITE_LIST, checked_type, is_pytest_file)


class GetModifiedFilesForTesting:
    def __init__(self, files_string: str):
        self.files_string = files_string
        self.files_to_filter: List[Tuple[str, FileType]] = self.create_diff_list()
        self.is_conf_json = False
        self.is_reputations_json = False
        self.is_indicator_json = False
        self.sample_tests: Set[str] = set()
        self.modified_metadata_list: Set[str] = set()
        self.changed_common: Set[str] = set()
        self.modified_files: Set[str] = set()
        self.modified_tests: Set[str] = set()
        self.files_to_types: Dict[FileType, Set[str]] = dict()
        self.build_files()

    def create_diff_list(self) -> List[Tuple[str, FileType]]:
        """Classified the diff list using tools.find_type

        Returns: 
            Tuple of file_path, FileType
        """
        files = list()
        for line in self.files_string.split("\n"):
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
                        files.append((file_path, tools.find_type(file_path)))
        return files

    def check_no_type(self, file_path: str):
        """Will classify file_path that tools.find_type could not find types for.

        Args:
            file_path: file path to classify

        if file_path is a reputation:
            self.is_reputations_json = True
        elif conf.json:
            self.is_conf_json = True
        elif  file_type one of constants.PACKS_PACK_META_FILE_NAME, constants.PACKS_WHITELIST_FILE_NAME:
            will be added to self.modified_metadata_list
        elif the file extension not in constants.FILE_TYPES_FOR_TESTING:
            will ignore
        elif file path is not a secrets white list:
            file will be added to self.sample_tests
        """
        # reputations.json
        if checked_type(file_path, [
            constants.INDICATOR_TYPES_REPUTATIONS_REGEX,
            constants.PACKS_INDICATOR_TYPES_REPUTATIONS_REGEX,
            constants.PACKS_INDICATOR_TYPE_JSON_REGEX
        ]):
            self.is_reputations_json = True

        elif re.match(
            constants.CONF_PATH,
            file_path,
            re.IGNORECASE,
        ):
            self.is_conf_json = True
        # if is not part of packs meta file name or whitelisted
        elif any(
            file in file_path
            for file in (
                    constants.PACKS_PACK_META_FILE_NAME,
                    constants.PACKS_WHITELIST_FILE_NAME,
            )
        ):
            self.modified_metadata_list.add(tools.get_pack_name(file_path))
        elif checked_type(file_path, FILES_IN_SCRIPTS_OR_INTEGRATIONS_DIRS_REGEXES):
            if (
                os.path.splitext(file_path)[-1]
                not in constants.FILE_TYPES_FOR_TESTING
            ):
                return
        # If is not whitelist
        elif SECRETS_WHITE_LIST not in file_path:
            self.sample_tests.add(file_path)

    def build_files(self):
        """Get a string of the modified files"""
        for file_path, file_type in self.files_to_filter:
            if checked_type(file_path, COMMON_YML_LIST):
                self.changed_common.add(file_path)
            elif file_type is None:
                self.check_no_type(file_path)
            else:
                if file_type in self.files_to_types:
                    self.files_to_types[file_type].add(file_path)
                else:
                    self.files_to_types[file_type] = {file_path}

        self.modified_files = self.modified_files.union(
            self.files_to_types.get(
                FileType.INTEGRATION, set()
            ),
            self.files_to_types.get(
                FileType.SCRIPT, set()
            ),
            self.files_to_types.get(
                FileType.PLAYBOOK, set()
            ),
        )

        self.filter_python_files()

        self.modified_tests = self.files_to_types.get(
            FileType.TEST_PLAYBOOK, {}
        )

        self.is_reputations_json = (
                FileType.REPUTATION
                in self.files_to_types
        )

        self.is_indicator_json = (
                FileType.INDICATOR_FIELD
                in self.files_to_types
        )

    def filter_python_files(self):
        """Filtering out Python files that should not be tested.

        Currently:
        - Pytest files: Will be removed from self.files_to_types[FileType.PYTHON_FILE].
        - Python files belongs to integration/script: YMl file will be added to modified_file_list
        - All other files: Will be added to self.sample_tests.

        """
        yml_paths = set()
        pytest_files = set()
        for file_path in self.files_to_types.get(
            FileType.PYTHON_FILE, {}
        ):
            if is_pytest_file(file_path):
                pytest_files.add(file_path)
            elif not checked_type(
                file_path, constants.CODE_FILES_REGEX
            ):
                self.sample_tests.add(file_path)
            else:
                # Py files, Integration, script, playbook ymls
                dir_path = os.path.dirname(file_path)
                file_path = glob.glob(dir_path + "/*.yml")[0]
                yml_paths.add(file_path)

        if FileType.PYTHON_FILE in self.files_to_types:
            self.files_to_types[
                FileType.PYTHON_FILE
            ] = (
                self.files_to_types[
                    FileType.PYTHON_FILE
                ]
                - self.sample_tests
            )
            self.files_to_types[
                FileType.PYTHON_FILE
            ] = (
                self.files_to_types[
                    FileType.PYTHON_FILE
                ]
                - pytest_files
            )
        self.modified_files = self.modified_files.union(yml_paths)
