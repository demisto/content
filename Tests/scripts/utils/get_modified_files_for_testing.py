"""
This class replaces the old get_modified_files_for_testing function in collect_tests_and_content_packs
"""
import glob
import os
from typing import Dict, Set, Optional
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging

import demisto_sdk.commands.common.constants as constants
from demisto_sdk.commands.common.tools import get_content_path
# TODO: remove try except clause when demisto-sdk 1.7.3 is released
try:
    import demisto_sdk.commands.common.content_constant_paths as content_constant_paths
    IS_UP_TO_DATE = True
except ImportError:
    IS_UP_TO_DATE = False

from demisto_sdk.commands.common.constants import FileType
from Tests.scripts.utils.collect_helpers import (
    COMMON_YML_LIST,
    is_code_test_file, checked_type, SECRETS_WHITE_LIST, LANDING_PAGE_SECTIONS_JSON_PATH,
)
from demisto_sdk.commands.common import tools
install_logging('Collect_Tests_And_Content_Packs.log', logger=logging)


class ModifiedFiles:
    def __init__(self,
                 modified_files: list,
                 modified_tests: list,
                 changed_common_files: list,
                 is_conf_json: bool,
                 sample_tests: list,
                 modified_metadata: set,
                 is_reputations_json: bool,
                 is_indicator_json: bool,
                 is_landing_page_sections_json: bool):
        """
        A holder for the 'get_modified_files_for_testing' method's response
        Args:
            modified_files: Modified YMLs for testing (Integrations, Scripts, Playbooks).
            modified_tests: Test playbooks.
            changed_common_files: Globally used YMLs (Like CommonServerPython).
            is_conf_json: If Tests/Conf.json has been changed.
            sample_tests: Files to test, Like the infrastructures files.
            modified_metadata: Pack names of changed metadata files.
            is_reputations_json: If any reputation file changed.
            is_indicator_json: If any indicator file changed.
            is_landing_page_sections_json: If Tests/Marketplace/landingPage_sections.json has been changed
        """
        self.modified_files = modified_files
        self.modified_tests = modified_tests
        self.changed_common_files = changed_common_files
        self.is_conf_json = is_conf_json
        self.sample_tests = sample_tests
        self.modified_metadata = modified_metadata
        self.is_reputations_json = is_reputations_json
        self.is_indicator_json = is_indicator_json
        self.is_landing_page_sections_json = is_landing_page_sections_json


def resolve_type(file_path: str) -> Optional[FileType]:
    """Will classify file_path that tools.find_type could not find types for.

    Args:
        file_path: file path to classify

    Returns:
        FileType. Conf.json and Metadata files.
    """
    # if conf.json file
    # TODO: remove "if" statement when demisto-sdk 1.7.3 is released
    if checked_type(file_path, [str(content_constant_paths.CONF_PATH.relative_to(get_content_path()))
                                if IS_UP_TO_DATE else constants.CONF_PATH]):
        return FileType.CONF_JSON
    # landingPage_sections.json file
    if checked_type(file_path, [LANDING_PAGE_SECTIONS_JSON_PATH]):
        return FileType.LANDING_PAGE_SECTIONS_JSON
    # MetaData files
    elif any(file in file_path
             for file in (constants.PACKS_PACK_META_FILE_NAME, constants.PACKS_WHITELIST_FILE_NAME,)):
        return FileType.METADATA
    # Whitelist file type
    elif checked_type(file_path, [SECRETS_WHITE_LIST]):
        return FileType.WHITE_LIST
    return None


def remove_code_files_by_types(types_to_files: Dict[FileType, Set[str]], file_type: FileType):
    """Get corresponding yml files and types from PY, JS and PS files.
    If a corresponding yml found, will remove the py file

    Args:
        types_to_files: Mapping of FileType: file_paths
        file_type: It the file we want to find its yml file is python, powershell or javascript

    Returns:
        Filtered types_to_files
    """
    code_files_to_be_removed = set()
    code_files = types_to_files.get(file_type, set())
    for file_path in code_files:
        if not is_code_test_file(file_path):
            yml_path = get_corresponding_yml_file(file_path)
            # There's a yml path
            if yml_path is not None:
                yml_type = tools.find_type(yml_path) or resolve_type(file_path)
                if yml_type is not None:
                    if yml_type in types_to_files:
                        types_to_files[yml_type].add(yml_path)
                    else:
                        types_to_files[yml_type] = {yml_path}
                    code_files_to_be_removed.add(file_path)
        else:
            code_files_to_be_removed.add(file_path)

    # remove python files
    if code_files_to_be_removed:
        types_to_files[file_type] = types_to_files[file_type] - code_files_to_be_removed

    return types_to_files


def remove_code_files(types_to_files: Dict[FileType, Set[str]]):
    """ Sending PY, JS and PS files to remove_code_files_by_types function with specific file type.
    If a corresponding yml found, will remove the py, js or ps file

    Args:
        types_to_files: Mapping of FileType: file_paths

    Returns:
        Filtered types_to_files
    """

    for file_type in [FileType.PYTHON_FILE, FileType.POWERSHELL_FILE, FileType.JAVASCRIPT_FILE]:
        types_to_files = remove_code_files_by_types(types_to_files, file_type)

    return types_to_files


def create_type_to_file(files_string: str) -> Dict[FileType, Set[str]]:
    """Classifies the files in the diff list (files_string) using tools.find_type

    Returns:
        A dict of {FileType: Set of files}
    """
    types_to_files: Dict[FileType, Set[str]] = dict()
    for line in files_string.split("\n"):
        if line:
            file_status, file_path = get_status_and_file_path_from_line_in_git_diff(line)
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

    types_to_files = remove_code_files(types_to_files)

    return types_to_files


def filter_modified_files_for_specific_marketplace_version(files_string: str, id_set: dict,
                                                           marketplace_version: str) -> str:
    """filter out the files in the diff list (files_string) that are not only supported in specific marketplace version
    Args:
        files_string (str): The modified files.
        id_set (dict): The id set object.
        marketplace_version (str): The marketplace version.
    Returns:
        string list of diff files that are supported only in marketplace_version
    """
    out_files_string = ''
    for line in files_string.split("\n"):
        if line:
            if 'Tests/scripts/collect_tests' in line:  # quick and dirty, for merging the new collect_tests in
                logging.info(f'>>> skipping {line}')
                continue
            else:
                logging.info(f'>>> not skipping {line}')
            file_status, file_path = get_status_and_file_path_from_line_in_git_diff(line)
            # ignoring deleted files.
            # also, ignore all files that are not in a pack
            if file_path:
                if (file_status in ("m", "a") or file_status.startswith("r")) and file_path.startswith("Packs/"):
                    file_path = strip_file_path(file_path)
                    artifact_type = get_artifact_type(file_path)
                    for artifacts in id_set.get(artifact_type, []):
                        for artifact_value in artifacts.values():
                            if file_path in artifact_value.get('file_path') and \
                                    artifact_value.get('marketplaces') == [marketplace_version]:
                                out_files_string += f'{line}\n'
                                break
    return out_files_string


def strip_file_path(file_path):
    if file_path.endswith('.py'):
        return file_path.rstrip('py')
    elif file_path.endswith('_description.md'):
        return file_path.rstrip('_description.md')
    elif file_path.endswith('_image.png'):
        return file_path.rstrip('_image.png')
    elif file_path.endswith('xif'):
        return file_path.rstrip('xif')
    return file_path


def get_status_and_file_path_from_line_in_git_diff(line):
    file_status, file_path = line.split(maxsplit=1)
    file_status = file_status.lower()
    # Get to right file_path on renamed
    if file_status.startswith("r"):
        _, file_path = file_path.split(maxsplit=1)
    return file_status, file_path


def get_artifact_type(file_path: str):
    if len(file_path.split('/')) < 2:
        return None
    artifact_type = file_path.split('/')[2]
    if artifact_type in ['Scripts', 'Playbooks', 'Integrations']:
        artifact_type = artifact_type.lower()
    return artifact_type


def remove_common_files(
        types_to_files: Dict[FileType, Set[str]], changed_common_files: Set[str]) -> Dict[FileType, Set[str]]:
    if changed_common_files:
        types_to_files[FileType.SCRIPT] = types_to_files[FileType.SCRIPT] - changed_common_files
    return types_to_files


def get_modified_files_for_testing(git_diff: str) -> ModifiedFiles:
    """
    Gets git diff string and filters those files into tests:

    Args:
        git_diff: a git diff output (with --name-only flag)
    Returns:
        ModifiedFiles instance
    """
    git_diff = '\n'.join(filter(lambda line: '/collect_tests/' not in line, git_diff.split('\n')))
    types_to_files: Dict[FileType, Set[str]] = create_type_to_file(git_diff)  # Mapping of the files FileType: file path

    # Checks if any common file exists in types_to_file
    changed_common_files = get_common_files(types_to_files.get(FileType.SCRIPT, set()))
    types_to_files = remove_common_files(types_to_files, changed_common_files)
    # Sample tests are the remaining python files
    sample_tests = types_to_files.get(FileType.PYTHON_FILE, set())

    # Modified files = YMLs of integrations, scripts and playbooks
    modified_files: Set[str] = types_to_files.get(FileType.INTEGRATION, set()).union(
        types_to_files.get(FileType.SCRIPT, set()),
        types_to_files.get(FileType.BETA_INTEGRATION, set()),
        types_to_files.get(FileType.PLAYBOOK, set()))  # Modified YMLs for testing (Integrations, Scripts, Playbooks).

    # Metadata packs
    modified_metadata: Set[str] = set()
    for file_path in types_to_files.get(FileType.METADATA, set()):
        if pack_name := tools.get_pack_name(file_path):
            modified_metadata.add(pack_name)

    modified_tests: Set[str] = types_to_files.get(FileType.TEST_PLAYBOOK, set())  # Modified tests are test playbooks

    # Booleans. If this kind of file is inside, its exists
    is_conf_json = FileType.CONF_JSON in types_to_files

    is_landing_page_sections_json = FileType.LANDING_PAGE_SECTIONS_JSON in types_to_files

    is_reputations_json = FileType.REPUTATION in types_to_files

    is_indicator_json = FileType.INDICATOR_FIELD in types_to_files

    modified_files_instance = ModifiedFiles(
        list(modified_files),
        list(modified_tests),
        list(changed_common_files),
        is_conf_json,
        list(sample_tests),
        modified_metadata,
        is_reputations_json,
        is_indicator_json,
        is_landing_page_sections_json)

    return modified_files_instance


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
