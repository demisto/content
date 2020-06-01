#!/usr/bin/env python
"""
This script is used to create a filter_file.txt file which will run only the needed the tests for a given change.
Overview can be found at: https://confluence.paloaltonetworks.com/display/DemistoContent/Configure+Test+Filter
"""
import os
import re
import sys
import json
import glob
import random
import argparse
from typing import Dict
import demisto_sdk.commands.common.tools as tools

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONTENT_DIR = os.path.abspath(SCRIPT_DIR + '/../..')
sys.path.append(CONTENT_DIR)

from demisto_sdk.commands.common.constants import *  # noqa: E402
from demisto_sdk.commands.common.tools import get_yaml, str2bool, get_from_version, get_to_version, \
    collect_ids, get_script_or_integration_id, LOG_COLORS, print_error, print_color, \
    print_warning, server_version_compare  # noqa: E402


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
    INTEGRATION_REGEX,
    BETA_INTEGRATION_REGEX,
    PACKS_INTEGRATION_REGEX,
    TEST_DATA_INTEGRATION_YML_REGEX
]
TEST_DATA_SCRIPT_YML_REGEX = r'Tests/scripts/infrastructure_tests/tests_data/mock_scripts/.*.yml'
SCRIPT_REGEXES = [
    TEST_DATA_SCRIPT_YML_REGEX
]
INCIDENT_FIELD_REGEXES = [
    INCIDENT_FIELD_REGEX,
    PACKS_INCIDENT_FIELDS_REGEX
]
FILES_IN_SCRIPTS_OR_INTEGRATIONS_DIRS_REGEXES = [
    FILE_IN_INTEGRATIONS_DIR_REGEX,
    FILE_IN_SCRIPTS_DIR_REGEX,
    FILE_IN_PACKS_INTEGRATIONS_DIR_REGEX,
    FILE_IN_PACKS_SCRIPTS_DIR_REGEX
]
CHECKED_TYPES_REGEXES = [
    # Integrations
    INTEGRATION_REGEX,
    INTEGRATION_YML_REGEX,
    BETA_INTEGRATION_REGEX,
    PACKS_INTEGRATION_REGEX,
    PACKS_INTEGRATION_YML_REGEX,
    # Scripts
    SCRIPT_REGEX,
    SCRIPT_YML_REGEX,
    PACKS_SCRIPT_REGEX,
    PACKS_SCRIPT_YML_REGEX,
    # Playbooks
    PLAYBOOK_REGEX,
    BETA_PLAYBOOK_REGEX,
    PACKS_PLAYBOOK_YML_REGEX
]

# File names
COMMON_YML_LIST = ["scripts/script-CommonIntegration.yml", "scripts/script-CommonIntegrationPython.yml",
                   "Packs/Base/Scripts/script-CommonServer.yml", "scripts/script-CommonServerUserPython.yml",
                   "scripts/script-CommonUserServer.yml",
                   "Packs/Base/Scripts/CommonServerPython/CommonServerPython.yml"]

# secrets white list file to be ignored in tests to prevent full tests running each time it is updated
SECRETS_WHITE_LIST = 'secrets_white_list.json'

# number of random tests to run when there're no runnable tests
RANDOM_TESTS_NUM = 3

# Global used to indicate if failed during any of the validation states
_FAILED = False


def is_runnable_in_server_version(from_v, server_v, to_v):
    """
    Checks whether an obj is runnable in a version
    Args:
        from_v (string): string representing Demisto version (fromversion comparable)
        server_v (string): string representing Demisto version (version to be ran on)
        to_v (string): string representing Demisto version (toversion comparable)

    Returns:
        bool. true if obj is runnable
    """
    return server_version_compare(from_v, server_v) <= 0 and server_version_compare(server_v, to_v) <= 0


def checked_type(file_path, regex_list):
    """Check if the file_path is from the regex list"""
    for regex in regex_list:
        if re.match(regex, file_path, re.IGNORECASE):
            return True

    return False


def validate_not_a_package_test_script(file_path):
    return '_test' not in file_path and 'test_' not in file_path


def get_modified_files(files_string):
    """Get a string of the modified files"""
    is_conf_json = False
    is_reputations_json = False
    is_indicator_json = False

    sample_tests = []
    changed_common = []
    modified_files_list = []
    modified_tests_list = []
    all_files = files_string.split('\n')

    for _file in all_files:
        file_data = _file.split()
        if not file_data:
            continue
        file_status = file_data[0]
        if file_status.lower().startswith('r'):
            file_path = file_data[2]
        else:
            file_path = file_data[1]

        # ignoring deleted files.
        # also, ignore files in ".circle", ".github" and ".hooks" directories and .gitignore
        if ((file_status.lower() == 'm' or file_status.lower() == 'a' or file_status.lower().startswith('r'))
                and not file_path.startswith('.')):
            if checked_type(file_path, CODE_FILES_REGEX) and validate_not_a_package_test_script(file_path):
                dir_path = os.path.dirname(file_path)
                file_path = glob.glob(dir_path + "/*.yml")[0]

            # Common scripts (globally used so must run all tests)
            if checked_type(file_path, COMMON_YML_LIST):
                changed_common.append(file_path)

            # integrations, scripts, playbooks, test-scripts
            elif checked_type(file_path, CHECKED_TYPES_REGEXES):
                modified_files_list.append(file_path)

            # tests
            elif checked_type(file_path, YML_TEST_PLAYBOOKS_REGEXES):
                modified_tests_list.append(file_path)

            # reputations.json
            elif re.match(INDICATOR_TYPES_REPUTATIONS_REGEX, file_path, re.IGNORECASE) or \
                    re.match(PACKS_INDICATOR_TYPES_REPUTATIONS_REGEX, file_path, re.IGNORECASE) or \
                    re.match(INDICATOR_TYPES_REGEX, file_path, re.IGNORECASE) or \
                    re.match(PACKS_INDICATOR_TYPES_REGEX, file_path, re.IGNORECASE):
                is_reputations_json = True

            elif checked_type(file_path, INCIDENT_FIELD_REGEXES):
                is_indicator_json = True

            # conf.json
            elif re.match(CONF_PATH, file_path, re.IGNORECASE):
                is_conf_json = True

            # docs and test files do not influence integration tests filtering
            elif checked_type(file_path, FILES_IN_SCRIPTS_OR_INTEGRATIONS_DIRS_REGEXES):
                if os.path.splitext(file_path)[-1] not in FILE_TYPES_FOR_TESTING:
                    continue

            elif re.match(DOCS_REGEX, file_path) or os.path.splitext(file_path)[-1] in ['.md', '.png']:
                continue

            elif all(file not in file_path for file in
                     (SECRETS_WHITE_LIST, PACKS_PACK_META_FILE_NAME, PACKS_WHITELIST_FILE_NAME)):
                sample_tests.append(file_path)

    return (modified_files_list, modified_tests_list, changed_common, is_conf_json, sample_tests, is_reputations_json,
            is_indicator_json)


def get_name(file_path):
    data_dictionary = get_yaml(file_path)

    if data_dictionary:
        return data_dictionary.get('name', '-')


def get_tests(file_path):
    """Collect tests mentioned in file_path"""
    data_dictionary = get_yaml(file_path)
    # inject no tests to whitelist so adding values to white list will not force all tests
    if data_dictionary:
        return data_dictionary.get('tests', [])


def collect_tests_and_content_packs(
        script_ids, playbook_ids, integration_ids, catched_scripts, catched_playbooks, tests_set, id_set, conf
):
    """Collect tests for the affected script_ids,playbook_ids,integration_ids.

    :param script_ids: The ids of the affected scripts in your change set.
    :param playbook_ids: The ids of the affected playbooks in your change set.
    :param integration_ids: The ids of the affected integrations in your change set.
    :param catched_scripts: The names of the scripts we already identified a test for.
    :param catched_playbooks: The names of the scripts we already v a test for.
    :param tests_set: The names of the tests we alredy identified.
    :param id_set: The id_set json.
    :param conf: The conf json.

    :return: (test_ids, missing_ids) - All the names of possible tests, the ids we didn't match a test for.
    """
    caught_missing_test = False
    catched_intergrations = set([])

    test_ids = conf.get_test_playbook_ids()
    skipped_tests = conf.get_skipped_tests()
    skipped_integrations = conf.get_skipped_integrations()

    if not id_set:
        with open("./Tests/id_set.json", 'r') as id_set_file:
            id_set = json.load(id_set_file)

    integration_set = id_set['integrations']
    test_playbooks_set = id_set['TestPlaybooks']
    integration_to_command, _ = get_integration_commands(integration_ids, integration_set)

    for test_playbook in test_playbooks_set:
        detected_usage = False
        test_playbook_id = list(test_playbook.keys())[0]
        test_playbook_data = list(test_playbook.values())[0]
        test_playbook_name = test_playbook_data.get('name')
        for script in test_playbook_data.get('implementing_scripts', []):
            if script in script_ids:
                detected_usage = True
                tests_set.add(test_playbook_id)
                catched_scripts.add(script)

        for playbook in test_playbook_data.get('implementing_playbooks', []):
            if playbook in playbook_ids:
                detected_usage = True
                tests_set.add(test_playbook_id)
                catched_playbooks.add(playbook)

        if integration_to_command:
            command_to_integration = test_playbook_data.get('command_to_integration', {})
            for command in test_playbook_data.get('command_to_integration', {}).keys():
                for integration_id, integration_commands in integration_to_command.items():
                    if command in integration_commands:
                        if not command_to_integration.get(command) or \
                                command_to_integration.get(command) == integration_id:
                            detected_usage = True
                            tests_set.add(test_playbook_id)
                            catched_intergrations.add(integration_id)

        if detected_usage and test_playbook_id not in test_ids and test_playbook_id not in skipped_tests:
            caught_missing_test = True
            print_error("The playbook {} does not appear in the conf.json file, which means no test with it will run."
                        "please update the conf.json file accordingly".format(test_playbook_name))

    missing_ids = update_missing_sets(catched_intergrations, catched_playbooks, catched_scripts,
                                      integration_ids, playbook_ids, script_ids)

    # remove skipped integrations from the list
    missing_ids = missing_ids - set(skipped_integrations)

    packs_to_install = set()
    id_set_test_playbooks = id_set.get('TestPlaybooks', [])
    for test_playbook in id_set_test_playbooks:
        test_playbook_id = list(test_playbook.keys())[0]
        test_playbook_object = test_playbook[test_playbook_id]
        if test_playbook_id in tests_set:
            test_playbook_pack = test_playbook_object.get('pack')
            if test_playbook_pack:
                print(
                    f'Found test playbook {test_playbook_id} in pack {test_playbook_pack} - adding to packs to install'
                )
                packs_to_install.add(test_playbook_pack)
            else:
                print_warning(f'Found test playbook {test_playbook_id} without pack - not adding to packs to install')

    return test_ids, missing_ids, caught_missing_test, packs_to_install


def update_missing_sets(catched_intergrations, catched_playbooks, catched_scripts, integration_ids, playbook_ids,
                        script_ids):
    missing_integrations = integration_ids - catched_intergrations
    missing_playbooks = playbook_ids - catched_playbooks
    missing_scripts = script_ids - catched_scripts
    missing_ids = missing_integrations.union(missing_playbooks).union(missing_scripts)
    return missing_ids


class TestConf(object):
    __test__ = False  # pytest will not try to run it just because it has Test prefix

    def __init__(self, conf):
        #  (dict) -> None

        self._conf = conf

    def get_skipped_integrations(self):
        return list(self._conf['skipped_integrations'].keys())

    def get_skipped_tests(self):
        return list(self._conf['skipped_tests'].keys())

    def get_tests(self):
        return self._conf.get('tests', {})

    def get_test_playbook_ids(self):
        conf_tests = self._conf['tests']
        test_ids = []

        for t in conf_tests:
            playbook_id = t['playbookID']
            test_ids.append(playbook_id)

        return test_ids

    def get_all_tested_integrations(self):
        all_integrations = []
        conf_tests = self._conf['tests']

        for t in conf_tests:
            if 'integrations' in t:
                if isinstance(t['integrations'], list):
                    all_integrations.extend(t['integrations'])
                else:
                    all_integrations.append(t['integrations'])

        return all_integrations

    def get_test_playbooks_configured_with_integration(self, integration_id):
        test_playbooks = []
        conf_tests = self._conf['tests']

        for t in conf_tests:
            if 'integrations' in t:
                if integration_id in t['integrations']:
                    test_playbooks.append(t['playbookID'])

        return test_playbooks


def load_tests_conf(conf=None):
    """Get the test ids from conf.json

    Keyword Arguments:
        check_nightly_status {bool} -- if we are running nightly test (default: {False})

    Returns:
        tuple: (test_ids, skipped_tests)
    """
    if not conf:
        with open("./Tests/conf.json", 'r') as conf_file:
            conf = json.load(conf_file)

    return TestConf(conf)


def get_integration_commands(integration_ids, integration_set):
    integration_to_command = {}
    deprecated_message = ''
    deprecated_commands_string = ''
    for integration in integration_set:
        integration_id = list(integration.keys())[0]
        integration_data = list(integration.values())[0]
        if integration_id in integration_ids:
            integration_commands = set(integration_data.get('commands', []))
            integration_deprecated_commands = set(integration_data.get('deprecated_commands', []))
            if integration_deprecated_commands:
                deprecated_names = ', '.join(integration_deprecated_commands)
                deprecated_commands_string += '{}: {}\n'.format(integration_id, deprecated_names)

            relevant_commands = list(integration_commands - integration_deprecated_commands)
            integration_to_command[integration_id] = relevant_commands

    if deprecated_commands_string:
        deprecated_message = 'The following integration commands are deprecated and are not taken ' \
                             'into account in the test collection:\n{}'.format(deprecated_commands_string)

    return integration_to_command, deprecated_message


def is_integration_fetching_incidents(integration_yml_path):
    integration_yml_dict = get_yaml(integration_yml_path)

    return integration_yml_dict.get('script').get('isfetch', False) is True


def id_set__get_test_playbook(id_set, test_playbook_id):
    for test_playbook in id_set.get('TestPlaybooks', []):
        if test_playbook_id in test_playbook.keys():
            return test_playbook[test_playbook_id]


def id_set__get_integration_file_path(id_set, integration_id):
    for integration in id_set.get('integrations', []):
        if integration_id in integration.keys():
            return integration[integration_id]['file_path']


def check_if_fetch_incidents_is_tested(missing_ids, integration_ids, id_set, conf, tests_set):
    # If integration is mentioned/used in one of the test configurations, it means that integration is tested.
    # For example there could be a test playbook that tests fetch incidents command of some integration
    # so the test playbook will use FetchFromInstance script in the playbook, which is not direct command of a specific
    # integration

    missing_integration_ids = missing_ids & integration_ids
    for missing_id in missing_integration_ids:
        integration_file_path = id_set__get_integration_file_path(id_set, missing_id)
        is_fetching = is_integration_fetching_incidents(integration_file_path)
        if not is_fetching:
            continue

        test_playbook_ids = conf.get_test_playbooks_configured_with_integration(missing_id)
        if len(test_playbook_ids) == 0:
            # there are no test playbooks for this integration configured
            continue

        for test_playbook_id in test_playbook_ids:
            test_playbook = id_set__get_test_playbook(id_set, test_playbook_id)
            if test_playbook and 'FetchFromInstance' in test_playbook.get('implementing_scripts', []):
                missing_ids = missing_ids - {missing_id}
                tests_set.add(test_playbook_id)

    return missing_ids, tests_set


def find_tests_and_content_packs_for_modified_files(modified_files, conf, id_set):
    script_names = set([])
    playbook_names = set([])
    integration_ids = set([])

    tests_set, catched_scripts, catched_playbooks, packs_to_install = collect_changed_ids(
        integration_ids, playbook_names, script_names, modified_files, id_set)

    test_ids, missing_ids, caught_missing_test, test_packs_to_install = collect_tests_and_content_packs(
        script_names, playbook_names, integration_ids, catched_scripts, catched_playbooks, tests_set, id_set, conf)

    packs_to_install.update(test_packs_to_install)

    missing_ids = update_with_tests_sections(missing_ids, modified_files, test_ids, tests_set)

    missing_ids, tests_set = check_if_fetch_incidents_is_tested(missing_ids, integration_ids, id_set, conf, tests_set)

    if len(missing_ids) > 0:
        test_string = '\n'.join(missing_ids)
        message = "You've failed to provide tests for:\n{0}".format(test_string)
        print_color(message, LOG_COLORS.RED)

    if caught_missing_test or len(missing_ids) > 0:
        global _FAILED
        _FAILED = True

    return tests_set, packs_to_install


def update_with_tests_sections(missing_ids, modified_files, test_ids, tests):
    test_ids.append(RUN_ALL_TESTS_FORMAT)
    # Search for tests section
    for file_path in modified_files:
        tests_from_file = get_tests(file_path)
        for test in tests_from_file:
            if test in test_ids or re.match(NO_TESTS_FORMAT, test, re.IGNORECASE):
                if checked_type(file_path, INTEGRATION_REGEXES):
                    _id = get_script_or_integration_id(file_path)

                else:
                    _id = get_name(file_path)

                missing_ids = missing_ids - {_id}
                tests.add(test)

            else:
                message = "The test '{0}' does not exist in the conf.json file, please re-check your code".format(test)
                print_color(message, LOG_COLORS.RED)
                global _FAILED
                _FAILED = True

    return missing_ids


def collect_content_packs_to_install(id_set: Dict, integration_ids: set, playbook_names: set, script_names: set) -> set:
    """Iterates all content entities in the ID set and extract the pack names for the modified ones.

    Args:
        id_set (Dict): Structure which holds all content entities to extract pack names from.
        integration_ids (set): Set of integration IDs to get pack names for.
        playbook_names (set): Set of playbook names to get pack names for.
        script_names (set): Set of script names to get pack names for.

    Returns:
        set. Pack names to install.
    """
    packs_to_install = set()

    id_set_integrations = id_set.get('integrations', [])
    for integration in id_set_integrations:
        integration_id = list(integration.keys())[0]
        integration_object = integration[integration_id]
        if integration_id in integration_ids:
            integration_pack = integration_object.get('pack')
            if integration_pack:
                print(f'Found integration {integration_id} in pack {integration_pack} - adding to packs to install')
                packs_to_install.add(integration_object.get('pack'))
            else:
                print_warning(f'Found integration {integration_id} without pack - not adding to packs to install')

    id_set_playbooks = id_set.get('playbooks', [])
    for playbook in id_set_playbooks:
        playbook_object = list(playbook.values())[0]
        playbook_name = playbook_object.get('name')
        if playbook_name in playbook_names:
            playbook_pack = playbook_object.get('pack')
            if playbook_pack:
                print(f'Found playbook {playbook_name} in pack {playbook_pack} - adding to packs to install')
                packs_to_install.add(playbook_pack)
            else:
                print_warning(f'Found playbook {playbook_name} without pack - not adding to packs to install')

    id_set_script = id_set.get('scripts', [])
    for script in id_set_script:
        script_id = list(script.keys())[0]
        script_object = script[script_id]
        if script_id in script_names:
            script_pack = script_object.get('pack')
            if script_pack:
                print(f'Found script {script_id} in pack {script_pack} - adding to packs to install')
                packs_to_install.add(script_object.get('pack'))
            else:
                print_warning(f'Found script {script_id} without pack - not adding to packs to install')

    return packs_to_install


def collect_changed_ids(integration_ids, playbook_names, script_names, modified_files, id_set):
    tests_set = set([])
    updated_script_names = set([])
    updated_playbook_names = set([])
    catched_scripts, catched_playbooks = set([]), set([])

    script_to_version = {}
    playbook_to_version = {}
    integration_to_version = {}
    for file_path in modified_files:
        if checked_type(file_path, SCRIPT_REGEXES + YML_SCRIPT_REGEXES):
            name = get_name(file_path)
            script_names.add(name)
            script_to_version[name] = (get_from_version(file_path), get_to_version(file_path))

            package_name = os.path.dirname(file_path)
            if glob.glob(package_name + "/*_test.py"):
                catched_scripts.add(name)
                tests_set.add('Found a unittest for the script {}'.format(package_name))

        elif checked_type(file_path, YML_PLAYBOOKS_NO_TESTS_REGEXES):
            name = get_name(file_path)
            playbook_names.add(name)
            playbook_to_version[name] = (get_from_version(file_path), get_to_version(file_path))

        elif checked_type(file_path, INTEGRATION_REGEXES + YML_INTEGRATION_REGEXES):
            _id = get_script_or_integration_id(file_path)
            integration_ids.add(_id)
            integration_to_version[_id] = (get_from_version(file_path), get_to_version(file_path))

    if not id_set:
        with open("./Tests/id_set.json", 'r') as conf_file:
            id_set = json.load(conf_file)

    script_set = id_set['scripts']
    playbook_set = id_set['playbooks']
    integration_set = id_set['integrations']

    deprecated_msgs = exclude_deprecated_entities(script_set, script_names,
                                                  playbook_set, playbook_names,
                                                  integration_set, integration_ids)

    for script_id in script_names:
        enrich_for_script_id(script_id, script_to_version[script_id], script_names, script_set, playbook_set,
                             playbook_names, updated_script_names, updated_playbook_names, catched_scripts,
                             catched_playbooks, tests_set)

    integration_to_command, deprecated_commands_message = get_integration_commands(integration_ids, integration_set)
    for integration_id, integration_commands in integration_to_command.items():
        enrich_for_integration_id(integration_id, integration_to_version[integration_id], integration_commands,
                                  script_set, playbook_set, playbook_names, script_names, updated_script_names,
                                  updated_playbook_names, catched_scripts, catched_playbooks, tests_set)

    for playbook_id in playbook_names:
        enrich_for_playbook_id(playbook_id, playbook_to_version[playbook_id], playbook_names, script_set, playbook_set,
                               updated_playbook_names, catched_playbooks, tests_set)

    for new_script in updated_script_names:
        script_names.add(new_script)

    for new_playbook in updated_playbook_names:
        playbook_names.add(new_playbook)

    affected_ids_strings = {
        'scripts': '',
        'playbooks': '',
        'integrations': ''
    }
    if script_names:
        affected_ids_strings['scripts'] += 'Scripts:\n' + '\n'.join(script_names)
    if playbook_names:
        affected_ids_strings['playbooks'] += 'Playbooks:\n' + '\n'.join(playbook_names)
    if integration_ids:
        affected_ids_strings['integrations'] += 'Integrations:\n' + '\n'.join(integration_ids)

    print('The following ids are affected due to the changes you made:')
    for entity in ['scripts', 'playbooks', 'integrations']:
        print(affected_ids_strings[entity])
        print_color(deprecated_msgs[entity], LOG_COLORS.YELLOW)

    if deprecated_commands_message:
        print_color(deprecated_commands_message, LOG_COLORS.YELLOW)

    packs_to_install = collect_content_packs_to_install(id_set, integration_ids, playbook_names, script_names)

    return tests_set, catched_scripts, catched_playbooks, packs_to_install


def exclude_deprecated_entities(script_set, script_names,
                                playbook_set, playbook_names,
                                integration_set, integration_ids):
    """Removes deprecated entities from the affected entities sets.

    :param script_set: The set of existing scripts within Content repo.
    :param script_names: The names of the affected scripts in your change set.
    :param playbook_set: The set of existing playbooks within Content repo.
    :param playbook_names: The ids of the affected playbooks in your change set.
    :param integration_set: The set of existing integrations within Content repo.
    :param integration_ids: The ids of the affected integrations in your change set.

    :return: deprecated_messages_dict - A dict of messages specifying of all the deprecated entities.
    """
    deprecated_messages_dict = {
        'scripts': '',
        'playbooks': '',
        'integrations': ''
    }

    deprecated_entities_strings_dict = {
        'scripts': '',
        'playbooks': '',
        'integrations': ''
    }

    # Iterates over three types of entities: scripts, playbooks and integrations and removes deprecated entities
    for entity_set, entity_names, entity_type in [(script_set, script_names, 'scripts'),
                                                  (playbook_set, playbook_names, 'playbooks'),
                                                  (integration_set, integration_ids, 'integrations')]:
        for entity in entity_set:
            # integrations are defined by their ids while playbooks and scripts and scripts are defined by names
            if entity_type == 'integrations':
                entity_name = list(entity.keys())[0]
            else:
                entity_name = list(entity.values())[0].get('name', '')

            if entity_name in entity_names:
                entity_data = list(entity.values())[0]
                if entity_data.get('deprecated', False):
                    deprecated_entities_strings_dict[entity_type] += entity_name + '\n'
                    entity_names.remove(entity_name)

        if deprecated_entities_strings_dict[entity_type]:
            deprecated_messages_dict[entity_type] = 'The following {} are deprecated ' \
                                                    'and are not taken into account in the test collection:' \
                                                    '\n{}'.format(entity_type,
                                                                  deprecated_entities_strings_dict[entity_type])

    return deprecated_messages_dict


def enrich_for_integration_id(integration_id, given_version, integration_commands, script_set, playbook_set,
                              playbook_names, script_names, updated_script_names, updated_playbook_names,
                              catched_scripts, catched_playbooks, tests_set):
    """Enrich the list of affected scripts/playbooks by your change set.

    :param integration_id: The name of the integration we changed.
    :param given_version: the version of the integration we changed.
    :param integration_commands: The commands of the changed integation
    :param script_set: The set of existing scripts within Content repo.
    :param playbook_set: The set of existing playbooks within Content repo.
    :param playbook_names: The names of the playbooks affected by your changes.
    :param script_names: The names of the scripts affected by your changes.
    :param updated_script_names: The names of scripts we identify as affected to your change set.
    :param updated_playbook_names: The names of playbooks we identify as affected to your change set.
    :param catched_scripts: The names of scripts we found tests for.
    :param catched_playbooks: The names of playbooks we found tests for.
    :param tests_set: The names of the caught tests.
    """
    for playbook in playbook_set:
        playbook_data = list(playbook.values())[0]
        if playbook_data.get('deprecated', False):
            continue
        playbook_name = playbook_data.get('name')
        playbook_fromversion = playbook_data.get('fromversion', '0.0.0')
        playbook_toversion = playbook_data.get('toversion', '99.99.99')
        command_to_integration = playbook_data.get('command_to_integration', {})
        implementing_commands = command_to_integration.keys()
        for integration_command in integration_commands:
            if integration_command in implementing_commands and playbook_toversion >= given_version[1]:
                if playbook_name not in playbook_names and playbook_name not in updated_playbook_names:
                    if not command_to_integration.get(integration_command) or \
                            command_to_integration.get(integration_command) == integration_id:

                        tests = set(playbook_data.get('tests', []))
                        if tests:
                            catched_playbooks.add(playbook_name)
                            update_test_set(tests, tests_set)

                        updated_playbook_names.add(playbook_name)
                        new_versions = (playbook_fromversion, playbook_toversion)
                        enrich_for_playbook_id(playbook_name, new_versions, playbook_names, script_set, playbook_set,
                                               updated_playbook_names, catched_playbooks, tests_set)

    for script in script_set:
        script_data = list(script.values())[0]
        if script_data.get('deprecated', False):
            continue
        script_name = script_data.get('name')
        script_file_path = script_data.get('file_path')
        script_fromversion = script_data.get('fromversion', '0.0.0')
        script_toversion = script_data.get('toversion', '99.99.99')
        command_to_integration = script_data.get('command_to_integration', {})
        for integration_command in integration_commands:
            if integration_command in script_data.get('depends_on', []):
                if integration_command in command_to_integration.keys() and \
                        command_to_integration[integration_command] == integration_id and \
                        script_toversion >= given_version[1]:

                    if script_name not in script_names and script_name not in updated_script_names:
                        tests = script_data.get('tests', [])
                        if tests:
                            catched_scripts.add(script_name)
                            update_test_set(tests, tests_set)

                        package_name = os.path.dirname(script_file_path)
                        if glob.glob(package_name + "/*_test.py"):
                            catched_scripts.add(script_name)
                            tests_set.add('Found a unittest for the script {}'.format(script_name))

                        updated_script_names.add(script_name)
                        new_versions = (script_fromversion, script_toversion)
                        enrich_for_script_id(script_name, new_versions, script_names, script_set, playbook_set,
                                             playbook_names, updated_script_names, updated_playbook_names,
                                             catched_scripts, catched_playbooks, tests_set)


def enrich_for_playbook_id(given_playbook_id, given_version, playbook_names, script_set, playbook_set,
                           updated_playbook_names, catched_playbooks, tests_set):
    for playbook in playbook_set:
        playbook_data = list(playbook.values())[0]
        if playbook_data.get('deprecated', False):
            continue
        playbook_name = playbook_data.get('name')
        playbook_fromversion = playbook_data.get('fromversion', '0.0.0')
        playbook_toversion = playbook_data.get('toversion', '99.99.99')
        if given_playbook_id in playbook_data.get('implementing_playbooks', []) and \
                playbook_toversion >= given_version[1]:

            if playbook_name not in playbook_names and playbook_name not in updated_playbook_names:
                tests = set(playbook_data.get('tests', []))
                if tests:
                    catched_playbooks.add(playbook_name)
                    update_test_set(tests, tests_set)

                updated_playbook_names.add(playbook_name)
                new_versions = (playbook_fromversion, playbook_toversion)
                enrich_for_playbook_id(playbook_name, new_versions, playbook_names, script_set, playbook_set,
                                       updated_playbook_names, catched_playbooks, tests_set)


def enrich_for_script_id(given_script_id, given_version, script_names, script_set, playbook_set, playbook_names,
                         updated_script_names, updated_playbook_names, catched_scripts, catched_playbooks, tests_set):
    for script in script_set:
        script_data = list(script.values())[0]
        if script_data.get('deprecated', False):
            continue
        script_name = script_data.get('name')
        script_file_path = script_data.get('file_path')
        script_fromversion = script_data.get('fromversion', '0.0.0')
        script_toversion = script_data.get('toversion', '99.99.99')
        if given_script_id in script_data.get('script_executions', []) and script_toversion >= given_version[1]:
            if script_name not in script_names and script_name not in updated_script_names:
                tests = set(script_data.get('tests', []))
                if tests:
                    catched_scripts.add(script_name)
                    update_test_set(tests, tests_set)

                package_name = os.path.dirname(script_file_path)
                if glob.glob(package_name + "/*_test.py"):
                    catched_scripts.add(script_name)
                    tests_set.add('Found a unittest for the script {}'.format(script_name))

                updated_script_names.add(script_name)
                new_versions = (script_fromversion, script_toversion)
                enrich_for_script_id(script_name, new_versions, script_names, script_set, playbook_set, playbook_names,
                                     updated_script_names, updated_playbook_names, catched_scripts, catched_playbooks,
                                     tests_set)

    for playbook in playbook_set:
        playbook_data = list(playbook.values())[0]
        if playbook_data.get('deprecated', False):
            continue
        playbook_name = playbook_data.get('name')
        playbook_fromversion = playbook_data.get('fromversion', '0.0.0')
        playbook_toversion = playbook_data.get('toversion', '99.99.99')
        if given_script_id in playbook_data.get('implementing_scripts', []) and playbook_toversion >= given_version[1]:
            if playbook_name not in playbook_names and playbook_name not in updated_playbook_names:
                tests = set(playbook_data.get('tests', []))
                if tests:
                    catched_playbooks.add(playbook_name)
                    update_test_set(tests, tests_set)

                updated_playbook_names.add(playbook_name)
                new_versions = (playbook_fromversion, playbook_toversion)
                enrich_for_playbook_id(playbook_name, new_versions, playbook_names, script_set, playbook_set,
                                       updated_playbook_names, catched_playbooks, tests_set)


def update_test_set(tests, tests_set):
    for test in tests:
        tests_set.add(test)


def get_test_conf_from_conf(test_id, server_version, conf=None):
    """Gets first occurrence of test conf with matching playbookID value to test_id with a valid from/to version"""
    if not conf:
        with open("./Tests/conf.json", 'r') as conf_file:
            conf = TestConf(json.load(conf_file))

    test_conf_lst = conf.get_tests()
    # return None if nothing is found
    test_conf = next((test_conf for test_conf in test_conf_lst if (
        test_conf.get('playbookID') == test_id
        and is_runnable_in_server_version(from_v=test_conf.get('fromversion', '0'),
                                          server_v=server_version,
                                          to_v=test_conf.get('toversion', '99.99.99'))
    )), None)
    return test_conf


def extract_matching_object_from_id_set(obj_id, obj_set, server_version='0'):
    """Gets first occurrence of object in the object's id_set with matching id/name and valid from/to version"""
    for obj_wrpr in obj_set:
        # try to get object by id
        if obj_id in obj_wrpr:
            obj = obj_wrpr.get(obj_id)

        # try to get object by name
        else:
            obj_keys = list(obj_wrpr.keys())
            if not obj_keys:
                continue
            obj = obj_wrpr[obj_keys[0]]
            if obj.get('name') != obj_id:
                continue

        # check if object is runnable
        fromversion = obj.get('fromversion', '0')
        toversion = obj.get('toversion', '99.99.99')
        if is_runnable_in_server_version(from_v=fromversion, server_v=server_version, to_v=toversion):
            return obj
    return None


def get_test_from_conf(branch_name, conf=None):
    tests = set([])
    changed = set([])
    change_string = tools.run_command("git diff origin/master...{} Tests/conf.json".format(branch_name))
    added_groups = re.findall(r'(\+[ ]+")(.*)(":)', change_string)
    if added_groups:
        for group in added_groups:
            changed.add(group[1])

    deleted_groups = re.findall(r'(-[ ]+")(.*)(":)', change_string)
    if deleted_groups:
        for group in deleted_groups:
            changed.add(group[1])

    if not conf:
        with open("./Tests/conf.json", 'r') as conf_file:
            conf = TestConf(json.load(conf_file))

    conf_tests = conf.get_tests()
    for t in conf_tests:
        playbook_id = t['playbookID']
        integrations_conf = t.get('integrations', [])
        if playbook_id in changed:
            tests.add(playbook_id)
            continue

        if not isinstance(integrations_conf, list):
            integrations_conf = [integrations_conf]

        for integration in integrations_conf:
            if integration in changed:
                tests.add(playbook_id)

    if not tests:
        tests.add('changed skip section')

    return tests


def is_test_runnable(test_id, id_set, conf, server_version):
    """Checks whether the test is runnable
    1. Test is not skipped.
    2. Test playbook / integration is not skipped.
    3. Test fromversion is earlier or equal to server_version
    4. Test toversion is greater or equal to server_version
    4. If test has integrations, then all integrations
        a. fromversion is earlier or equal to server_version
        b. toversion is after or equal to server_version
    """
    skipped_tests = conf.get_skipped_tests()
    warning_prefix = f'{test_id} is not runnable on {server_version}'
    # check if test is skipped
    if test_id in skipped_tests:
        print_warning(f'{warning_prefix} - skipped')
        return False
    test_conf = get_test_conf_from_conf(test_id, server_version, conf)

    # check if there's a test to run
    if not test_conf:
        print_warning(f'{warning_prefix} - couldn\'t find test in conf.json')
        return False
    conf_fromversion = test_conf.get('fromversion', '0')
    conf_toversion = test_conf.get('toversion', '99.99.99')
    test_playbooks_set = id_set.get('TestPlaybooks', [])
    test_playbook_obj = extract_matching_object_from_id_set(test_id, test_playbooks_set, server_version)

    # check whether the test is runnable in id_set
    if not test_playbook_obj:
        print_warning(f'{warning_prefix} - couldn\'t find the test in id_set.json')
        return False

    # check used integrations available
    if not is_test_integrations_available(server_version, test_conf, conf, id_set):
        print_warning(f'{warning_prefix} - no active integration found')
        return False

    # check conf from/to
    if not is_runnable_in_server_version(conf_fromversion, server_version, conf_toversion):
        print_warning(f'{warning_prefix} - conf.json from/to version')
        return False

    return True


def is_test_integrations_available(server_version, test_conf, conf, id_set):
    """
    Check if all used integrations are skipped / available
    """
    test_integration_ids = test_conf.get('integrations')
    if test_integration_ids:
        if not isinstance(test_integration_ids, list):
            test_integration_ids = [test_integration_ids]
        if not is_test_uses_active_integration(test_integration_ids, conf):
            return False
        # check if all integration from/toversion is valid with server_version
        integrations_set = id_set.get('integrations', [])
        if any(extract_matching_object_from_id_set(integration_id, integrations_set, server_version) is None for
               integration_id in
               test_integration_ids):
            return False
    return True


def is_test_uses_active_integration(integration_ids, conf=None):
    """Checks whether there's an an integration in test_integration_ids that's not skipped"""
    if not conf:
        with open("./Tests/conf.json", 'r') as conf_file:
            conf = TestConf(json.load(conf_file))

    skipped_integrations = conf.get_skipped_integrations()
    # check if all integrations are skipped
    if all(integration_id in skipped_integrations for integration_id in integration_ids):
        return False

    return True


def is_any_test_runnable(test_ids, conf, id_set=None, server_version='0'):
    """Checks whether there's a runnable test in tests"""
    if test_ids and isinstance(test_ids, set):
        if not id_set:
            with open("./Tests/id_set.json", 'r') as conf_file:
                id_set = json.load(conf_file)
        for test_id in test_ids:
            if is_test_runnable(test_id, id_set, conf, server_version):
                return True
    return False


def get_random_tests(tests_num, rand, conf=None, id_set=None, server_version='0'):
    """Gets runnable tests for the server version"""
    if not id_set:
        with open("./Tests/id_set.json", 'r') as conf_file:
            id_set = json.load(conf_file)

    tests = set([])
    test_ids = conf.get_test_playbook_ids()

    while len(tests) < tests_num:
        test = rand.choice(test_ids)
        if is_test_runnable(test, id_set, conf, server_version):
            tests.add(test)
    return tests


def get_content_pack_name_of_test(tests: set, id_set: Dict = None) -> set:
    """Returns the content packs names in which given test playbooks are in.

    Args:
        tests (set): The names of the tests to find their content packs.
        id_set (Dict): Structure which holds all content entities to extract pack names from.

    Returns:
        str. The content pack name in which the test playbook is in.
    """
    if not id_set:
        with open("./Tests/id_set.json", 'r') as conf_file:
            id_set = json.load(conf_file)

    content_packs = set()

    for test_playbook_object in id_set.get('TestPlaybooks', []):
        test_playbook_name = list(test_playbook_object.keys())[0]
        test_playbook_data = list(test_playbook_object.values())[0]
        if test_playbook_name in tests:
            pack_name = test_playbook_data.get('pack')
            if pack_name:
                content_packs.add(pack_name)
                if len(tests) == len(content_packs):
                    # we found all content packs for all tests we were looking for
                    break

    return content_packs


def get_test_list_and_content_packs_to_install(files_string, branch_name, two_before_ga_ver='0', conf=None, id_set=None):
    """Create a test list that should run"""
    (modified_files, modified_tests_list, changed_common, is_conf_json, sample_tests, is_reputations_json,
     is_indicator_json) = get_modified_files(files_string)

    tests = set([])
    packs_to_install = set([])
    if modified_files:
        tests, packs_to_install = find_tests_and_content_packs_for_modified_files(modified_files, conf, id_set)

    # Adding a unique test for a json file.
    if is_reputations_json:
        tests.add('FormattingPerformance - Test')
        tests.add('reputations.json Test')
        tests.add('Indicators reputation-.json Test')

    if is_indicator_json:
        tests.add('Test IP Indicator Fields')

    for file_path in modified_tests_list:
        test = collect_ids(file_path)
        if test not in tests:
            tests.add(test)

    if is_conf_json:
        tests = tests.union(get_test_from_conf(branch_name, conf))

    if not tests:
        rand = random.Random(branch_name)
        tests = get_random_tests(
            tests_num=RANDOM_TESTS_NUM, rand=rand, conf=conf, id_set=id_set, server_version=two_before_ga_ver)
        packs_to_install = get_content_pack_name_of_test(tests, id_set)
        if changed_common:
            print_warning('Adding 3 random tests due to: {}'.format(','.join(changed_common)))
        elif sample_tests:  # Choosing 3 random tests for infrastructure testing
            print_warning('Collecting sample tests due to: {}'.format(','.join(sample_tests)))
        else:
            print_warning("Running Sanity check only")
            tests.add('DocumentationTest')  # test with integration configured
            tests.add('TestCommonPython')  # test with no integration configured

    if changed_common:
        tests.add('TestCommonPython')

    return tests, packs_to_install


def create_filter_envs_file(tests, two_before_ga, one_before_ga, ga, conf, id_set):
    """Create a file containing all the envs we need to run for the CI"""
    # always run master and PreGA
    envs_to_test = {
        'Server Master': True,
        'Demisto PreGA': True,
        'Demisto two before GA': is_any_test_runnable(test_ids=tests, server_version=two_before_ga, conf=conf, id_set=id_set),
        'Demisto one before GA': is_any_test_runnable(test_ids=tests, server_version=one_before_ga, conf=conf, id_set=id_set),
        'Demisto GA': is_any_test_runnable(test_ids=tests, server_version=ga, conf=conf, id_set=id_set),
    }
    print("Creating filter_envs.json with the following envs: {}".format(envs_to_test))
    with open("./Tests/filter_envs.json", "w") as filter_envs_file:
        json.dump(envs_to_test, filter_envs_file)


def create_test_file(is_nightly, skip_save=False):
    """Create a file containing all the tests we need to run for the CI"""
    tests_string = ''
    packs_to_install_string = ''
    if not is_nightly:
        branches = tools.run_command("git branch")
        branch_name_reg = re.search(r"\* (.*)", branches)
        branch_name = branch_name_reg.group(1)

        print("Getting changed files from the branch: {0}".format(branch_name))
        if branch_name != 'master':
            files_string = tools.run_command("git diff --name-status origin/master...{0}".format(branch_name))
        else:
            commit_string = tools.run_command("git log -n 2 --pretty='%H'")
            commit_string = commit_string.replace("'", "")
            last_commit, second_last_commit = commit_string.split()
            files_string = tools.run_command("git diff --name-status {}...{}".format(second_last_commit, last_commit))

        with open('./Tests/ami_builds.json', 'r') as ami_builds:
            # get versions to check if tests are runnable on those envs
            ami_builds = json.load(ami_builds)
            two_before_ga = ami_builds.get('TwoBefore-GA', '0').split('-')[0]
            one_before_ga = ami_builds.get('OneBefore-GA', '0').split('-')[0]
            ga = ami_builds.get('GA', '0').split('-')[0]

        conf = load_tests_conf()
        with open("./Tests/id_set.json", 'r') as conf_file:
            id_set = json.load(conf_file)
        tests, packs_to_install = get_test_list_and_content_packs_to_install(
            files_string, branch_name, two_before_ga, conf, id_set
        )
        create_filter_envs_file(tests, two_before_ga, one_before_ga, ga, conf, id_set)

        tests_string = '\n'.join(tests)
        if tests_string:
            print('Collected the following tests:\n{0}\n'.format(tests_string))
        else:
            print('No filter configured, running all tests')

        packs_to_install_string = '\n'.join(packs_to_install)
        if packs_to_install_string:
            print('Collected the following content packs to install:\n{0}\n'.format(packs_to_install_string))
        else:
            print('Did not find content packs to install')

    if not skip_save:
        print("Creating filter_file.txt")
        with open("./Tests/filter_file.txt", "w") as filter_file:
            filter_file.write(tests_string)
        print("Creating content_packs_to_install.txt")
        with open("./Tests/content_packs_to_install.txt", "w") as content_packs_to_install:
            content_packs_to_install.write(packs_to_install_string)


if __name__ == "__main__":
    print_color("Starting creation of test filter file", LOG_COLORS.GREEN)

    parser = argparse.ArgumentParser(description='Utility CircleCI usage')
    parser.add_argument('-n', '--nightly', type=str2bool, help='Is nightly or not')
    parser.add_argument('-s', '--skip-save', type=str2bool,
                        help='Skipping saving the test filter file (good for simply doing validation)')
    options = parser.parse_args()

    # Create test file based only on committed files
    create_test_file(options.nightly, options.skip_save)
    if not _FAILED:
        print_color("Finished test configuration", LOG_COLORS.GREEN)
        sys.exit(0)
    else:
        print_color("Failed test configuration. See previous errors.", LOG_COLORS.RED)
        sys.exit(1)
