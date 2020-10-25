"""
Helper functions for collect_tests.
"""
from demisto_sdk.commands.common.constants import *  # noqa: E402
import re
from typing import List

# Search Keyword for the changed file
NO_TESTS_FORMAT = 'No test( - .*)?'
PACKS_SCRIPT_REGEX = r'{}/([^/]+)/{}/(script-[^\\/]+)\.yml$'.format(PACKS_DIR, SCRIPTS_DIR)
FILE_IN_INTEGRATIONS_DIR_REGEX = r'{}/(.+)'.format(INTEGRATIONS_DIR)
FILE_IN_SCRIPTS_DIR_REGEX = r'{}/(.+)'.format(SCRIPTS_DIR)
FILE_IN_PACKS_INTEGRATIONS_DIR_REGEX = r'{}/([^/]+)/{}/(.+)'.format(
    PACKS_DIR, INTEGRATIONS_DIR)
FILE_IN_PACKS_SCRIPTS_DIR_REGEX = r'{}/([^/]+)/{}/(.+)'.format(
    PACKS_DIR, SCRIPTS_DIR)

TEST_DATA_INTEGRATION_YML_REGEX = r'Tests\/scripts\/infrastructure_tests\/tests_data\/mock_integrations\/.*\.yml'
INTEGRATION_REGEXES = [
    PACKS_INTEGRATION_PY_REGEX,
    PACKS_INTEGRATION_PS_TEST_REGEX,
    TEST_DATA_INTEGRATION_YML_REGEX
]
TEST_DATA_SCRIPT_YML_REGEX = r'Tests/scripts/infrastructure_tests/tests_data/mock_scripts/.*.yml'
SCRIPT_REGEXES = [
    TEST_DATA_SCRIPT_YML_REGEX
]
INCIDENT_FIELD_REGEXES = [
    PACKS_INCIDENT_FIELD_JSON_REGEX
]
FILES_IN_SCRIPTS_OR_INTEGRATIONS_DIRS_REGEXES = [
    FILE_IN_INTEGRATIONS_DIR_REGEX,
    FILE_IN_SCRIPTS_DIR_REGEX,
    FILE_IN_PACKS_INTEGRATIONS_DIR_REGEX,
    FILE_IN_PACKS_SCRIPTS_DIR_REGEX
]
CHECKED_TYPES_REGEXES = [
    # Integrations
    PACKS_INTEGRATION_PY_REGEX,
    PACKS_INTEGRATION_YML_REGEX,
    PACKS_INTEGRATION_NON_SPLIT_YML_REGEX,
    PACKS_INTEGRATION_PS_REGEX,

    # Scripts
    PACKS_SCRIPT_REGEX,
    PACKS_SCRIPT_YML_REGEX,
    PACKS_SCRIPT_NON_SPLIT_YML_REGEX,

    # Playbooks
    PLAYBOOK_REGEX,
    PLAYBOOK_YML_REGEX
]

# File names
COMMON_YML_LIST = ["scripts/script-CommonIntegration.yml", "scripts/script-CommonIntegrationPython.yml",
                   "Packs/Base/Scripts/script-CommonServer.yml", "scripts/script-CommonServerUserPython.yml",
                   "scripts/script-CommonUserServer.yml",
                   "Packs/Base/Scripts/CommonServerPython/CommonServerPython.yml"]

# secrets white list file to be ignored in tests to prevent full tests running each time it is updated
SECRETS_WHITE_LIST = 'secrets_white_list.json'


def checked_type(file_path: str, regex_list: List[str]) -> bool:
    """
    Check if the file_path is from the regex list
    """
    for regex in regex_list:
        if re.match(regex, file_path, re.IGNORECASE):
            return True
    return False
