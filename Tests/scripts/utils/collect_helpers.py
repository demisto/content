"""
Helper functions for collect_tests.
"""
import re
from typing import Iterable

import demisto_sdk.commands.common.constants as constants

# Search Keyword for the changed file
NO_TESTS_FORMAT = 'No test( - .*)?'
PACKS_SCRIPT_REGEX = r'{}/([^/]+)/{}/(script-[^\\/]+)\.yml$'.format(constants.PACKS_DIR, constants.SCRIPTS_DIR)
FILE_IN_INTEGRATIONS_DIR_REGEX = r'{}/(.+)'.format(constants.INTEGRATIONS_DIR)
FILE_IN_SCRIPTS_DIR_REGEX = r'{}/(.+)'.format(constants.SCRIPTS_DIR)
FILE_IN_PACKS_INTEGRATIONS_DIR_REGEX = r'{}/([^/]+)/{}/(.+)'.format(
    constants.PACKS_DIR, constants.INTEGRATIONS_DIR)
FILE_IN_PACKS_SCRIPTS_DIR_REGEX = r'{}/([^/]+)/{}/(.+)'.format(
    constants.PACKS_DIR, constants.SCRIPTS_DIR)

TEST_DATA_INTEGRATION_YML_REGEX = r'Tests\/scripts\/infrastructure_tests\/tests_data\/mock_integrations\/.*\.yml'
INTEGRATION_REGEXES = [
    constants.PACKS_INTEGRATION_PY_REGEX,
    constants.PACKS_INTEGRATION_PS_TEST_REGEX,
    TEST_DATA_INTEGRATION_YML_REGEX
]
TEST_DATA_SCRIPT_YML_REGEX = r'Tests/scripts/infrastructure_tests/tests_data/mock_scripts/.*.yml'
SCRIPT_REGEXES = [
    TEST_DATA_SCRIPT_YML_REGEX
]
INCIDENT_FIELD_REGEXES = [
    constants.PACKS_INCIDENT_FIELD_JSON_REGEX
]
FILES_IN_SCRIPTS_OR_INTEGRATIONS_DIRS_REGEXES = [
    FILE_IN_INTEGRATIONS_DIR_REGEX,
    FILE_IN_SCRIPTS_DIR_REGEX,
    FILE_IN_PACKS_INTEGRATIONS_DIR_REGEX,
    FILE_IN_PACKS_SCRIPTS_DIR_REGEX
]
CHECKED_TYPES_REGEXES = [
    # Integrations
    constants.PACKS_INTEGRATION_PY_REGEX,
    constants.PACKS_INTEGRATION_YML_REGEX,
    constants.PACKS_INTEGRATION_NON_SPLIT_YML_REGEX,
    constants.PACKS_INTEGRATION_PS_REGEX,

    # Scripts
    PACKS_SCRIPT_REGEX,
    constants.PACKS_SCRIPT_YML_REGEX,
    constants.PACKS_SCRIPT_NON_SPLIT_YML_REGEX,

    # Playbooks
    constants.PLAYBOOK_REGEX,
    constants.PLAYBOOK_YML_REGEX
]

# File names
COMMON_YML_LIST = ["scripts/script-CommonIntegration.yml", "scripts/script-CommonIntegrationPython.yml",
                   "Packs/Base/Scripts/script-CommonServer.yml", "scripts/script-CommonServerUserPython.yml",
                   "scripts/script-CommonUserServer.yml",
                   "Packs/Base/Scripts/CommonServerPython/CommonServerPython.yml"]

# secrets white list file to be ignored in tests to prevent full tests running each time it is updated
SECRETS_WHITE_LIST = 'secrets_white_list.json'


def checked_type(file_path: str, regex_list: Iterable[str]) -> bool:
    """
    Check if the file_path is from the regex list
    """
    for regex in regex_list:
        if re.match(regex, file_path, re.IGNORECASE):
            return True
    return False


def is_pytest_file(file_path: str) -> bool:
    """Whatever is a pytest file or not depends on the file name.

    Args:
        file_path: File path to check
    """
    return '_test' in file_path or 'test_' in file_path
