"""
This class replaces the old get_modified_files_for_testing function in collect_tests_and_content_packs
"""
import os
from typing import Tuple, Dict, Set

from demisto_sdk.commands.common import tools

from demisto_sdk.commands.common.constants import *  # noqa: E402

from Tests.scripts.collect_tests_and_content_packs import FILES_IN_SCRIPTS_OR_INTEGRATIONS_DIRS_REGEXES, \
    SECRETS_WHITE_LIST, COMMON_YML_LIST
from Tests.scripts.utils.collect_helpers import checked_type


class GetModifiedFilesForTesting:
    def __init__(self, files_string: str):
        self.files_string = files_string
        self.files_to_filter: List[Tuple[str, FileType]] = self.create_diff_list()
        self.is_conf_json = False
        self.is_reputations_json = False
        self.is_indicator_json = False
        self.sample_tests = set()
        self.modified_metadata_list = set()
        self.changed_common = set()
        self.modified_files_list = set()
        self.modified_tests_list = set()
        self.files_to_types: Dict[FileType, Set[str]] = dict()
        self.build_files()

    def create_diff_list(self) -> List[Tuple[str, FileType]]:
        files = list()
        for line in self.files_string.split('\n'):
            file_status, file_path = line.split(maxsplit=1)
            file_status = file_status.lower()
            # Get to right file_path on renamed
            if file_status.startswith('r'):
                _, file_path = file_path.split(maxsplit=1)
            file_status = file_status.lower()
            # ignoring deleted files.
            # also, ignore files in ".circle", ".github" and ".hooks" directories and .
            if file_path:
                if (file_status in ('m', 'a') or file_status.startswith('r')) and not file_path.startswith('.'):
                    files.append((file_path, tools.find_type(file_path)))
        return files

    def check_no_type(self, file_path: str):
        # reputations.json
        if re.match(INDICATOR_TYPES_REPUTATIONS_REGEX, file_path, re.IGNORECASE) or \
             re.match(PACKS_INDICATOR_TYPES_REPUTATIONS_REGEX, file_path, re.IGNORECASE) or \
             re.match(PACKS_INDICATOR_TYPE_JSON_REGEX, file_path, re.IGNORECASE):
            self.is_reputations_json = True

        elif re.match(CONF_PATH, file_path, re.IGNORECASE):
            self.is_conf_json = True
        # if is not part of packs meta file name or whitelisted
        elif any(file in file_path for file in (PACKS_PACK_META_FILE_NAME, PACKS_WHITELIST_FILE_NAME)):
            self.modified_metadata_list.add(tools.get_pack_name(file_path))
        elif checked_type(file_path, FILES_IN_SCRIPTS_OR_INTEGRATIONS_DIRS_REGEXES):
            if os.path.splitext(file_path)[-1] not in FILE_TYPES_FOR_TESTING:
                pass
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

        self.modified_files_list = self.modified_files_list.union(
            self.files_to_types.get(FileType.INTEGRATION, set()),
            self.files_to_types.get(FileType.SCRIPT, set()),
            self.files_to_types.get(FileType.PLAYBOOK, set()),
        )

        yml_paths = set()

        for file_path in self.files_to_types.get(FileType.PYTHON_FILE, {}):
            if not ('test_' in file_path or '_test' in file_path):
                # Py files, Integration, script, playbook ymls
                dir_path = os.path.dirname(file_path)
                file_path = glob.glob(dir_path + "/*.yml")[0]
                yml_paths.add(file_path)

        self.modified_files_list = self.modified_files_list.union(yml_paths)

        self.modified_tests_list = self.files_to_types.get(FileType.TEST_PLAYBOOK, {})

        self.is_reputations_json = FileType.REPUTATION in self.files_to_types

        self.is_indicator_json = FileType.INDICATOR_FIELD in self.files_to_types
