#!/usr/bin/env python3
"""
This script is used to create a filter_file.txt file which will run only the needed the tests for a given change.
Overview can be found at: https://confluence.paloaltonetworks.com/display/DemistoContent/Configure+Test+Filter
"""
import argparse
import glob
import json
import logging
import os
import sys
from copy import deepcopy
from distutils.version import LooseVersion
from typing import Dict, Tuple, Union, Optional

import demisto_sdk.commands.common.tools as tools
from demisto_sdk.commands.common.constants import *  # noqa: E402

from Tests.Marketplace.marketplace_services import IGNORED_FILES
from Tests.scripts.utils import collect_helpers
from Tests.scripts.utils.content_packs_util import should_test_content_pack, get_pack_metadata
from Tests.scripts.utils.get_modified_files_for_testing import get_modified_files_for_testing
from Tests.scripts.utils.log_util import install_logging


class TestConf(object):
    __test__ = False  # required because otherwise pytest will try to run it as it has Test prefix

    def __init__(self, conf: dict) -> None:

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

    def get_tested_integrations_for_collected_tests(self, collected_tests):
        tested_integrations = []
        conf_tests = self._conf['tests']

        for t in conf_tests:
            if t.get('playbookID') not in collected_tests:
                continue

            if 'integrations' in t:
                if isinstance(t['integrations'], list):
                    tested_integrations.extend(t['integrations'])
                else:
                    tested_integrations.append(t['integrations'])

        return tested_integrations

    # This function is the same function exactly as 'get_content_pack_name_of_test' and therefore should be removed
    def get_packs_of_collected_tests(self, collected_tests, id_set):
        packs = set([])
        if collected_tests:
            for test_obj in id_set.get('TestPlaybooks', []):
                for test_id, test_data in test_obj.items():
                    test_obj_name = test_obj[test_id].get('name')
                    test_obj_pack = test_obj[test_id].get('pack')
                    if test_obj_name in collected_tests and test_obj_pack:
                        packs.add(test_obj_pack)
        return packs

    def get_packs_of_tested_integrations(self, collected_tests, id_set):
        packs = set([])
        tested_integrations = self.get_tested_integrations_for_collected_tests(collected_tests)
        for integration in tested_integrations:
            try:
                int_path = id_set__get_integration_file_path(id_set, integration)
                pack = tools.get_pack_name(int_path)
                if pack:
                    packs.add(pack)
            except TypeError:
                err_msg = f'Error occurred when trying to determine the pack of integration "{integration}"'
                err_msg += f' with path "{int_path}"' if int_path else ''
                logging.exception(err_msg)
        return packs

    def get_test_playbooks_configured_with_integration(self, integration_id):
        test_playbooks = []
        conf_tests = self._conf['tests']

        for t in conf_tests:
            if 'integrations' in t:
                if integration_id in t['integrations']:
                    test_playbooks.append(t['playbookID'])

        return test_playbooks


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONTENT_DIR = os.path.abspath(SCRIPT_DIR + '/../..')
sys.path.append(CONTENT_DIR)

# Global used to indicate if failed during any of the validation states
_FAILED = False
AMI_BUILDS = {}
ID_SET = {}
CONF: Union[TestConf, dict] = {}
if os.path.isfile('./Tests/ami_builds.json'):
    with open('./Tests/ami_builds.json', 'r') as ami_builds_file:
        # get versions to check if tests are runnable on those envs
        AMI_BUILDS = json.load(ami_builds_file)

if os.path.isfile('./Tests/id_set.json'):
    with open('./Tests/id_set.json', 'r') as conf_file:
        ID_SET = json.load(conf_file)

if os.path.isfile('./Tests/conf.json'):
    with open('./Tests/conf.json', 'r') as conf_file:
        CONF = TestConf(json.load(conf_file))


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
    return tools.server_version_compare(from_v, server_v) <= 0 and tools.server_version_compare(server_v, to_v) <= 0


def get_name(file_path):
    data_dictionary = tools.get_yaml(file_path)

    if data_dictionary:
        return data_dictionary.get('name', '-')


def get_tests(file_path):
    """Collect tests mentioned in file_path"""
    data_dictionary = tools.get_yaml(file_path)
    # inject no tests to whitelist so adding values to white list will not force all tests
    if data_dictionary:
        return data_dictionary.get('tests', [])


def collect_tests_and_content_packs(
        script_ids,
        playbook_ids,
        integration_ids,
        catched_scripts,
        catched_playbooks,
        tests_set,
        id_set=deepcopy(ID_SET),
        conf=deepcopy(CONF)
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
            logging.error("The playbook {} does not appear in the conf.json file,"
                          " which means no test with it will run. please update the conf.json file accordingly"
                          .format(test_playbook_name))

    ids_with_no_tests = update_missing_sets(catched_intergrations, catched_playbooks, catched_scripts,
                                            integration_ids, playbook_ids, script_ids)

    # remove skipped integrations from the list
    ids_with_no_tests = ids_with_no_tests - set(skipped_integrations)
    packs_to_install = set()
    id_set_test_playbooks = id_set.get('TestPlaybooks', [])
    for test_playbook in id_set_test_playbooks:
        test_playbook_id = list(test_playbook.keys())[0]
        test_playbook_object = test_playbook[test_playbook_id]
        if test_playbook_id in tests_set:
            test_playbook_pack = test_playbook_object.get('pack')
            if test_playbook_pack:
                logging.info(
                    f'Found test playbook {test_playbook_id} in pack {test_playbook_pack} - adding to packs to install')
                packs_to_install.add(test_playbook_pack)
            else:
                logging.warning(f'Found test playbook {test_playbook_id} without pack - not adding to packs to install')

    return test_ids, ids_with_no_tests, caught_missing_test, packs_to_install


def update_missing_sets(catched_intergrations, catched_playbooks, catched_scripts, integration_ids, playbook_ids,
                        script_ids):
    missing_integrations = integration_ids - catched_intergrations
    missing_playbooks = playbook_ids - catched_playbooks
    missing_scripts = script_ids - catched_scripts
    missing_ids = missing_integrations.union(missing_playbooks).union(missing_scripts)
    return missing_ids


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
    integration_yml_dict = tools.get_yaml(integration_yml_path)

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


def find_tests_and_content_packs_for_modified_files(modified_files, conf=deepcopy(CONF), id_set=deepcopy(ID_SET)):
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
        message = "Was not able to find tests for:\n{0}".format(test_string)
        logging.error(message)

    if caught_missing_test or len(missing_ids) > 0:
        global _FAILED
        _FAILED = True

    return tests_set, packs_to_install


def update_with_tests_sections(missing_ids, modified_files, test_ids, tests):
    # Search for tests section
    for file_path in modified_files:
        tests_from_file = get_tests(file_path)
        for test in tests_from_file:
            if test in test_ids or re.match(collect_helpers.NO_TESTS_FORMAT, test, re.IGNORECASE):
                if collect_helpers.checked_type(file_path, collect_helpers.INTEGRATION_REGEXES):
                    _id = tools.get_script_or_integration_id(file_path)

                else:
                    _id = get_name(file_path)

                missing_ids = missing_ids - {_id}
                tests.add(test)

            else:
                message = "The test '{0}' does not exist in the conf.json file, please re-check your code".format(test)
                logging.error(message)
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
                logging.info(
                    f'Found integration {integration_id} in pack {integration_pack} - adding to packs to install')
                packs_to_install.add(integration_object.get('pack'))
            else:
                logging.warning(f'Found integration {integration_id} without pack - not adding to packs to install')

    id_set_playbooks = id_set.get('playbooks', [])
    for playbook in id_set_playbooks:
        playbook_object = list(playbook.values())[0]
        playbook_name = playbook_object.get('name')
        if playbook_name in playbook_names:
            playbook_pack = playbook_object.get('pack')
            if playbook_pack:
                logging.info(f'Found playbook {playbook_name} in pack {playbook_pack} - adding to packs to install')
                packs_to_install.add(playbook_pack)
            else:
                logging.warning(f'Found playbook {playbook_name} without pack - not adding to packs to install')

    id_set_script = id_set.get('scripts', [])
    for script in id_set_script:
        script_id = list(script.keys())[0]
        script_object = script[script_id]
        if script_id in script_names:
            script_pack = script_object.get('pack')
            if script_pack:
                logging.info(f'Found script {script_id} in pack {script_pack} - adding to packs to install')
                packs_to_install.add(script_object.get('pack'))
            else:
                logging.warning(f'Found script {script_id} without pack - not adding to packs to install')

    return packs_to_install


def get_api_module_integrations(changed_api_modules, integration_set):
    integration_to_version = {}
    integration_ids_to_test = set([])
    for integration in integration_set:
        integration_data = list(integration.values())[0]
        if integration_data.get('api_modules', '') in changed_api_modules:
            file_path = integration_data.get('file_path')
            integration_id = tools.get_script_or_integration_id(file_path)
            integration_ids_to_test.add(integration_id)
            integration_to_version[integration_id] = (tools.get_from_version(file_path),
                                                      tools.get_to_version(file_path))

    return integration_ids_to_test, integration_to_version


def collect_changed_ids(integration_ids, playbook_names, script_names, modified_files, id_set=deepcopy(ID_SET)):
    tests_set = set([])
    updated_script_names = set([])
    updated_playbook_names = set([])
    catched_scripts, catched_playbooks = set([]), set([])
    changed_api_modules = set([])

    script_to_version = {}
    playbook_to_version = {}
    integration_to_version = {}
    for file_path in modified_files:
        if collect_helpers.checked_type(file_path, collect_helpers.SCRIPT_REGEXES + YML_SCRIPT_REGEXES):
            name = get_name(file_path)
            script_names.add(name)
            script_to_version[name] = (tools.get_from_version(file_path), tools.get_to_version(file_path))

            package_name = os.path.dirname(file_path)
            if glob.glob(package_name + "/*_test.py"):
                catched_scripts.add(name)
                tests_set.add('Found a unittest for the script {}'.format(package_name))

        elif collect_helpers.checked_type(file_path, YML_PLAYBOOKS_NO_TESTS_REGEXES):
            name = get_name(file_path)
            playbook_names.add(name)
            playbook_to_version[name] = (tools.get_from_version(file_path), tools.get_to_version(file_path))

        elif collect_helpers.checked_type(file_path, collect_helpers.INTEGRATION_REGEXES + YML_INTEGRATION_REGEXES):
            _id = tools.get_script_or_integration_id(file_path)
            integration_ids.add(_id)
            integration_to_version[_id] = (tools.get_from_version(file_path), tools.get_to_version(file_path))

        if collect_helpers.checked_type(file_path, API_MODULE_REGEXES):
            api_module_name = tools.get_script_or_integration_id(file_path)
            changed_api_modules.add(api_module_name)

    script_set = id_set['scripts']
    playbook_set = id_set['playbooks']
    integration_set = id_set['integrations']

    if changed_api_modules:
        integration_ids_to_test, integration_to_version_to_add = get_api_module_integrations(changed_api_modules,
                                                                                             integration_set)
        integration_ids = integration_ids.union(integration_ids_to_test)
        integration_to_version = {**integration_to_version, **integration_to_version_to_add}

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

    logging.info('The following ids are affected due to the changes you made:')
    for entity in ['scripts', 'playbooks', 'integrations']:
        logging.info(affected_ids_strings[entity])
        logging.warning(deprecated_msgs[entity])

    if deprecated_commands_message:
        logging.warning(deprecated_commands_message)

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


def get_test_conf_from_conf(test_id, server_version, conf=deepcopy(CONF)):
    """Gets first occurrence of test conf with matching playbookID value to test_id with a valid from/to version"""
    test_conf_lst = conf.get_tests()
    # return None if nothing is found
    test_conf = next((test_conf for test_conf in test_conf_lst if (
        test_conf.get('playbookID') == test_id
        and is_runnable_in_server_version(
            from_v=test_conf.get('fromversion', '0.0'),
            server_v=server_version,
            to_v=test_conf.get('toversion', '99.99.99')))), None)
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
        fromversion = obj.get('fromversion', '0.0')
        toversion = obj.get('toversion', '99.99.99')
        if is_runnable_in_server_version(from_v=fromversion, server_v=server_version, to_v=toversion):
            return obj
    return None


def get_test_from_conf(branch_name, conf=deepcopy(CONF)):
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
        logging.debug(f'{warning_prefix} - skipped')
        return False
    test_conf = get_test_conf_from_conf(test_id, server_version, conf)

    # check if there's a test to run
    if not test_conf:
        logging.debug(f'{warning_prefix} - couldn\'t find test in conf.json')
        return False
    conf_fromversion = test_conf.get('fromversion', '0.0')
    conf_toversion = test_conf.get('toversion', '99.99.99')
    test_playbooks_set = id_set.get('TestPlaybooks', [])
    test_playbook_obj = extract_matching_object_from_id_set(test_id, test_playbooks_set, server_version)

    # check whether the test is runnable in id_set
    if not test_playbook_obj:
        logging.debug(f'{warning_prefix} - couldn\'t find the test in id_set.json')
        return False

    # check used integrations available
    if not is_test_integrations_available(server_version, test_conf, conf, id_set):
        logging.debug(f'{warning_prefix} - no active integration found')
        return False

    # check conf from/to
    if not is_runnable_in_server_version(conf_fromversion, server_version, conf_toversion):
        logging.debug(f'{warning_prefix} - conf.json from/to version')
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


def is_test_uses_active_integration(integration_ids, conf=deepcopy(CONF)):
    """Checks whether there's an an integration in test_integration_ids that's not skipped"""
    skipped_integrations = conf.get_skipped_integrations()
    # check if all integrations are skipped
    if all(integration_id in skipped_integrations for integration_id in integration_ids):
        return False

    return True


def get_tests_for_pack(pack_path):
    pack_yml_files = tools.get_files_in_dir(pack_path, ['yml'])
    pack_test_playbooks = [tools.collect_ids(file) for file in pack_yml_files if
                           collect_helpers.checked_type(file, YML_TEST_PLAYBOOKS_REGEXES)]
    return pack_test_playbooks


def get_content_pack_name_of_test(tests: set, id_set: Optional[Dict] = None) -> set:
    """Returns the content packs names in which given test playbooks are in.

    Args:
        tests (set): The names of the tests to find their content packs.
        id_set (Dict): Structure which holds all content entities to extract pack names from.

    Returns:
        str. The content pack name in which the test playbook is in.
    """
    content_packs = set()
    if id_set is not None:
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


def get_modified_packs(files_string):
    modified_packs = set()
    all_files = files_string.splitlines()

    for _file in all_files:
        file_data = _file.split()
        if not file_data:
            continue
        file_status = file_data[0]
        if file_status.lower().startswith('r'):
            file_path = file_data[2]
        else:
            file_path = file_data[1]

        if file_path.startswith('Documentation'):
            modified_packs.add('Base')

        elif file_path.startswith('Packs'):
            modified_packs.add(tools.get_pack_name(file_path))

    return modified_packs


def remove_ignored_tests(tests: set, id_set: dict) -> set:
    """Filters out test playbooks, which are in .pack-ignore, from the given tests set

    Args:
        tests (set): Tests set to remove the tests to ignore from
        id_set (dict): The id set object

    Return:
         set: The filtered tests set
    """
    ignored_tests_set = set()
    content_packs = get_content_pack_name_of_test(tests, id_set)
    for pack in content_packs:
        ignored_tests_set.update(tools.get_ignore_pack_skipped_tests(pack))

    if ignored_tests_set:
        readable_ignored_tests = "\n".join(map(str, ignored_tests_set))
        logging.debug(f"Skipping tests that were ignored via .pack-ignore:\n{readable_ignored_tests}")
        tests.difference_update(ignored_tests_set)

    return tests


def remove_tests_for_non_supported_packs(tests: set, id_set: dict) -> set:
    """Filters out test playbooks, which are not XSOAR supported or not relevant for tests (DeprecatedContent,
        NonSupported)

        Args:
            tests (set): Tests set to remove the tests to ignore from
            id_set (dict): The id set object

        Return:
             set: The filtered tests set
        """
    tests_that_should_not_be_tested = set()
    for test in tests:
        content_pack_name_list = list(get_content_pack_name_of_test({test}, id_set))
        if content_pack_name_list:
            id_set_test_playbook_pack_name = content_pack_name_list[0]

            # We don't want to test playbooks from Non-certified partners.
            if not should_test_content_pack(id_set_test_playbook_pack_name):
                tests_that_should_not_be_tested.add(test)

    if tests_that_should_not_be_tested:
        logging.debug('The following test playbooks are not supported and will not be tested: \n{} '.format(
            '\n'.join(tests_that_should_not_be_tested)))
        tests.difference_update(tests_that_should_not_be_tested)
    return tests


def filter_tests(tests: set, id_set: json) -> set:
    """
    Filter tests out from the test set if they are a.Ignored b.Non XSOAR or non-supported packs.
    Args:
        tests (set): Set of tests collected so far.
        id_set (dict): The ID set.
    Returns:
        (set): Set of tests without ignored and non supported tests.
    """
    tests_without_ignored = remove_ignored_tests(tests, id_set)
    tests_without_non_supported = remove_tests_for_non_supported_packs(tests_without_ignored, id_set)

    return tests_without_non_supported


def is_documentation_changes_only(files_string: str) -> bool:
    """

    Args:
        files_string: The modified files.

    Returns: True is only documentation related files has been changed else False.

    """
    # Check if only README file in file string, if so, no need to create the servers.
    files = [s for s in files_string.split('\n') if s]
    documentation_changes_only = \
        all(map(lambda s: s.endswith('.md') or s.endswith('.png') or s.endswith('.jpg') or s.endswith('.mp4'), files))
    if documentation_changes_only:
        return True
    else:
        return False


def get_test_list_and_content_packs_to_install(files_string, branch_name, minimum_server_version='0',
                                               conf=deepcopy(CONF),
                                               id_set=deepcopy(ID_SET)):
    """Create a test list that should run"""
    (modified_files_with_relevant_tests, modified_tests_list, changed_common, is_conf_json, sample_tests,
     modified_packs, is_reputations_json, is_indicator_json) = get_modified_files_for_testing(files_string)

    all_modified_files_paths = set(
        modified_files_with_relevant_tests + modified_tests_list + changed_common + sample_tests
    )

    from_version, to_version = get_from_version_and_to_version_bounderies(all_modified_files_paths,
                                                                          id_set,
                                                                          modified_packs=modified_packs,
                                                                          )

    # Check if only README file in file string, if so, no need to create the servers.
    documentation_changes_only = is_documentation_changes_only(files_string)
    create_filter_envs_file(from_version, to_version, documentation_changes_only=documentation_changes_only)

    tests = set([])
    packs_to_install = set([])

    # Get packs and tests for changed scripts integration and playbooks
    if modified_files_with_relevant_tests:
        tests, packs_to_install = find_tests_and_content_packs_for_modified_files(modified_files_with_relevant_tests,
                                                                                  conf, id_set)

    # Adding a unique test for a json file.
    if is_reputations_json:
        tests.add('FormattingPerformance - Test')
        tests.add('reputations.json Test')
        tests.add('Indicators reputation-.json Test')

    if is_indicator_json:
        tests.add('Test IP Indicator Fields')

    for file_path in modified_tests_list:
        test = tools.collect_ids(file_path)
        if test not in tests:
            tests.add(test)

    if is_conf_json:
        tests = tests.union(get_test_from_conf(branch_name, conf))

    if changed_common:
        tests.add('TestCommonPython')

    # get all modified packs - not just tests related
    # TODO: need to move the logic of collecting packs of all items to be inside get_modified_files_for_testing
    modified_packs = get_modified_packs(files_string)
    if modified_packs:
        packs_to_install = packs_to_install.union(modified_packs)

    # Get packs of integrations corresponding to each test, as listed in conf.json
    packs_of_tested_integrations = conf.get_packs_of_tested_integrations(tests, id_set)
    packs_to_install = packs_to_install.union(packs_of_tested_integrations)

    # Get packs that contains each of the collected tests
    packs_of_collected_tests = get_content_pack_name_of_test(tests, id_set)
    packs_to_install = packs_to_install.union(packs_of_collected_tests)

    # All filtering out of packs should be done here
    packs_to_install = {pack_to_install for pack_to_install in packs_to_install if pack_to_install not in IGNORED_FILES}

    # All filtering out of tests should be done here
    tests = filter_tests(tests, id_set)

    if not tests:
        logging.info("No tests found running sanity check only")

        sanity_tests = {
            "Sanity Test - Playbook with no integration",
            "Sanity Test - Playbook with integration",
            "Sanity Test - Playbook with mocked integration",
            "Sanity Test - Playbook with Unmockable Integration"
        }
        logging.debug(f"Adding sanity tests: {sanity_tests}")
        tests.update(sanity_tests)
        logging.debug("Adding HelloWorld to tests as most of the sanity tests requires it.")
        logging.debug(
            "Adding Gmail to packs to install as 'Sanity Test - Playbook with Unmockable Integration' uses it"
        )
        packs_to_install.update(["HelloWorld", "Gmail"])

    # We add Base andDeveloperTools packs for every build
    packs_to_install.update(["DeveloperTools", "Base"])

    return tests, packs_to_install


def get_from_version_and_to_version_bounderies(all_modified_files_paths: set,
                                               id_set: dict,
                                               modified_packs: set = None) -> Tuple[str, str]:
    """Computes the lowest from version of the modified files, the highest from version and the highest to version of
    the modified files.
    In case that max_from_version is higher than max to version - to version will be the the highest default.

    Args:
        all_modified_files_paths: All modified files
        id_set: The content of the id.set_json
        modified_packs: A set of modified pack names

    Returns:
        (string, string). The boundaries of the lowest from version (defaults to 0.0.0)
         and highest to version (defaults to 99.99.99)
    """
    modified_packs = modified_packs if modified_packs else set([])
    max_to_version = LooseVersion('0.0.0')
    min_from_version = LooseVersion('99.99.99')
    max_from_version = LooseVersion('0.0.0')

    for pack_name in modified_packs:
        pack_metadata_path = os.path.join(tools.pack_name_to_path(pack_name), PACKS_PACK_META_FILE_NAME)
        pack_metadata = get_pack_metadata(pack_metadata_path)
        from_version = pack_metadata.get('serverMinVersion')
        to_version = pack_metadata.get('serverMaxVersion')
        if from_version:
            min_from_version = min(min_from_version, LooseVersion(from_version))
            max_from_version = max(max_from_version, LooseVersion(from_version))
        if to_version:
            max_to_version = max(max_to_version, LooseVersion(to_version))

    for artifacts in id_set.values():
        for artifact_dict in artifacts:
            for artifact_details in artifact_dict.values():
                if artifact_details.get('file_path') in all_modified_files_paths:
                    from_version = artifact_details.get('fromversion')
                    to_version = artifact_details.get('toversion')
                    if from_version:
                        min_from_version = min(min_from_version, LooseVersion(from_version))
                        max_from_version = max(max_from_version, LooseVersion(from_version))
                    if to_version:
                        max_to_version = max(max_to_version, LooseVersion(to_version))

    if max_to_version.vstring == '0.0.0' or max_to_version < max_from_version:
        max_to_version = LooseVersion('99.99.99')
    if min_from_version.vstring == '99.99.99':
        min_from_version = LooseVersion('0.0.0')
    logging.debug(f'modified files are {all_modified_files_paths}')
    logging.debug(f'lowest from version found is {min_from_version}')
    logging.debug(f'highest from version found is {max_from_version}')
    logging.debug(f'highest to version found is {max_to_version}')
    return min_from_version.vstring, max_to_version.vstring


def create_filter_envs_file(from_version: str, to_version: str, two_before_ga: str = None, one_before_ga: str = None,
                            ga: str = None, documentation_changes_only: bool = False):
    """
    Create a file containing all the envs we need to run for the CI
    Args:
        from_version: Server from_version
        to_version: Server to_version
        two_before_ga: Server version two_before_ga
        one_before_ga: Server version one_before_ga (5.0)
        ga: Server Version ga (6.0)
        documentation_changes_only: If the build is for documentations changes only - no need to create instances.

    """
    # always run master and PreGA
    one_before_ga = one_before_ga or AMI_BUILDS.get('OneBefore-GA', '0').split('-')[0]
    ga = ga or AMI_BUILDS.get('GA', '0').split('-')[0]
    """
    The environment naming is being phased out due to it being difficult to follow. In this case,
    Demisto 6.0 is the GA, Demisto PreGA is (5.5), Demisto GA is one before GA (5.0), Demisto one
    before GA is two before GA (4.5)
    """
    envs_to_test = {
        'Demisto PreGA': True,
        'Demisto Marketplace': True,
        'Demisto GA': is_runnable_in_server_version(from_version, one_before_ga, to_version),
        'Demisto 6.0': is_runnable_in_server_version(from_version, ga, to_version),
    }

    if documentation_changes_only:
        # No need to create the instances.
        envs_to_test = {
            'Demisto PreGA': False,
            'Demisto Marketplace': False,
            'Demisto GA': False,
            'Demisto 6.0': False,
        }
    logging.info("Creating filter_envs.json with the following envs: {}".format(envs_to_test))
    with open("./Tests/filter_envs.json", "w") as filter_envs_file:
        json.dump(envs_to_test, filter_envs_file)


def get_list_of_files_in_the_pack(path_to_pack):
    file_paths = []
    for root, dirs, files in os.walk(path_to_pack):
        for file in files:
            file_paths.append(os.path.join(root, file))
    return file_paths


def changed_files_to_string(changed_files):
    files_with_status = []

    for file_path in changed_files:
        file_with_status = f'M\t{file_path}'
        files_with_status.append(file_with_status)

    return '\n'.join(files_with_status)


def create_test_file(is_nightly, skip_save=False, path_to_pack=''):
    """Create a file containing all the tests we need to run for the CI"""
    if is_nightly:
        packs_to_install = set(filter(should_test_content_pack, os.listdir(PACKS_DIR)))
        tests = filter_tests(set(CONF.get_test_playbook_ids()), id_set=deepcopy(ID_SET))
        logging.info("Nightly - collected all tests that appear in conf.json and all packs from content repo that "
                     "should be tested")
    else:
        branches = tools.run_command("git branch")
        branch_name_reg = re.search(r"\* (.*)", branches)
        branch_name = branch_name_reg.group(1)

        logging.info("Getting changed files from the branch: {0}".format(branch_name))
        if path_to_pack:
            changed_files = get_list_of_files_in_the_pack(path_to_pack)
            files_string = changed_files_to_string(changed_files)
        elif branch_name != 'master':
            files_string = tools.run_command("git diff --name-status origin/master...{0}".format(branch_name))
            # Checks if the build is for contributor PR and if so add it's pack.
            if os.getenv('CONTRIB_BRANCH'):
                packs_diff = tools.run_command("git diff --name-status HEAD -- Packs")
                files_string += f"\n{packs_diff}"
        else:
            commit_string = tools.run_command("git log -n 2 --pretty='%H'")
            commit_string = commit_string.replace("'", "")
            last_commit, second_last_commit = commit_string.split()
            files_string = tools.run_command("git diff --name-status {}...{}".format(second_last_commit, last_commit))
        logging.debug(f'Files string: {files_string}')
        minimum_server_version = AMI_BUILDS.get('OneBefore-GA', '0').split('-')[0]

        tests, packs_to_install = get_test_list_and_content_packs_to_install(files_string, branch_name,
                                                                             minimum_server_version)

    tests_string = '\n'.join(tests)
    packs_to_install_string = '\n'.join(packs_to_install)

    if not skip_save:
        logging.info("Creating filter_file.txt")
        with open("./Tests/filter_file.txt", "w") as filter_file:
            filter_file.write(tests_string)
        # content_packs_to_install.txt is not used in nightly build
        logging.info("Creating content_packs_to_install.txt")
        with open("./Tests/content_packs_to_install.txt", "w") as content_packs_to_install:
            content_packs_to_install.write(packs_to_install_string)

    if is_nightly:
        logging.debug('Collected the following tests:\n{0}\n'.format(tests_string))

    else:
        if tests_string:
            logging.success('Collected the following tests:\n{0}\n'.format(tests_string))
        else:
            logging.error('Did not find tests to run')

        if packs_to_install_string:
            logging.success('Collected the following content packs to install:\n{0}\n'.format(packs_to_install_string))
        else:
            logging.error('Did not find content packs to install')


if __name__ == "__main__":
    install_logging('Collect_Tests_And_Content_Packs.log')
    logging.info("Starting creation of test filter file")

    parser = argparse.ArgumentParser(description='Utility CircleCI usage')
    parser.add_argument('-n', '--nightly', type=tools.str2bool, help='Is nightly or not')
    parser.add_argument('-s', '--skip-save', type=tools.str2bool,
                        help='Skipping saving the test filter file (good for simply doing validation)')
    parser.add_argument('-p', '--changed_pack_path', type=str, help='A string representing the changed files')
    options = parser.parse_args()

    # Create test file based only on committed files
    create_test_file(options.nightly, options.skip_save, options.changed_pack_path)
    if not _FAILED:
        logging.info("Finished test configuration")
        sys.exit(0)
    else:
        logging.error("Failed test configuration. See previous errors.")
        sys.exit(1)
