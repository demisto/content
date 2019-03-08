"""
This script is used to create a filter_file.txt file which will run only the needed the tests for a given change.
"""
import re
import os
import sys
import json
import glob
import random
import argparse

from Tests.scripts.constants import *
from Tests.test_utils import get_json, str2bool, get_from_version, get_to_version, \
    collect_ids, get_script_or_integration_id, run_command, LOG_COLORS, print_error, print_color

# Search Keyword for the changed file
RUN_ALL_TESTS_FORMAT = 'Run all tests'
NO_TESTS_FORMAT = 'No test( - .*)?'

CHECKED_TYPES_REGEXES = [INTEGRATION_REGEX, PLAYBOOK_REGEX, SCRIPT_REGEX, TEST_NOT_PLAYBOOK_REGEX,
                         BETA_INTEGRATION_REGEX, BETA_SCRIPT_REGEX, BETA_PLAYBOOK_REGEX, SCRIPT_YML_REGEX,
                         INTEGRATION_YML_REGEX]

# File names
ALL_TESTS = ["scripts/script-CommonIntegration.yml", "scripts/script-CommonIntegrationPython.yml",
             "scripts/script-CommonServer.yml", "scripts/script-CommonServerPython.yml",
             "scripts/script-CommonServerUserPython.yml", "scripts/script-CommonUserServer.yml"]

# secrets white list file to be ignored in tests to prevent full tests running each time it is updated
SECRETS_WHITE_LIST = 'secrets_white_list.json'


def checked_type(file_path, regex_list):
    """Check if the file_path is from the regex list"""
    for regex in regex_list:
        if re.match(regex, file_path, re.IGNORECASE):
            return True

    return False


def get_modified_files(files_string):
    """Get a string of the modified files"""
    is_conf_json = False
    infra_tests = False

    all_tests = []
    modified_files_list = []
    modified_tests_list = []
    all_files = files_string.split('\n')

    for file in all_files:
        file_data = file.split()
        if not file_data:
            continue

        file_path = file_data[1]
        file_status = file_data[0]

        if (file_status.lower() == 'm' or file_status.lower() == 'a') and not file_path.startswith('.'):
            if checked_type(file_path, CODE_FILES_REGEX):
                dir_path = os.path.dirname(file_path)
                file_path = glob.glob(dir_path + "/*.yml")[0]

            if checked_type(file_path, ALL_TESTS):
                all_tests.append(file_path)
            elif checked_type(file_path, CHECKED_TYPES_REGEXES):
                modified_files_list.append(file_path)
            elif re.match(TEST_PLAYBOOK_REGEX, file_path, re.IGNORECASE):
                modified_tests_list.append(file_path)
            elif re.match(CONF_REGEX, file_path, re.IGNORECASE):
                is_conf_json = True
            elif file_status.lower() == 'm' and ('id_set.json' not in file_path or SECRETS_WHITE_LIST not in file_path):
                if re.match("/Tests/.*.py", file_path) or re.match("/Tests/.*.sh", file_path) or \
                        file_path == ".hooks/pre-commit":
                    infra_tests = True
                else:
                    all_tests.append(file_path)

    return modified_files_list, modified_tests_list, all_tests, is_conf_json, infra_tests


def get_name(file_path):
    data_dictionary = get_json(file_path)

    if data_dictionary:
        return data_dictionary.get('name', '-')


def get_tests(file_path):
    """Collect tests mentioned in file_path"""
    data_dictionary = get_json(file_path)
    # inject no tests to whitelist so adding values to white list will not force all tests
    if data_dictionary:
        return data_dictionary.get('tests', [])


def collect_tests(script_ids, playbook_ids, integration_ids, catched_scripts, catched_playbooks, tests_set):
    """Collect tests for the affected script_ids,playbook_ids,integration_ids.

    :param script_ids: The ids of the affected scripts in your change set.
    :param playbook_ids: The ids of the affected playbooks in your change set.
    :param integration_ids: The ids of the affected integrations in your change set.
    :param catched_scripts: The names of the scripts we already identified a test for.
    :param catched_playbooks: The names of the scripts we already v a test for.
    :param tests_set: The names of the tests we alredy identified.

    :return: (test_ids, missing_ids) - All the names of possible tests, the ids we didn't match a test for.
    """
    caught_missing_test = False
    catched_intergrations = set([])

    test_ids = get_test_ids()

    with open("./Tests/id_set.json", 'r') as conf_file:
        id_set = json.load(conf_file)

    integration_set = id_set['integrations']
    test_playbooks_set = id_set['TestPlaybooks']
    integration_to_command = get_integration_commands(integration_ids, integration_set)

    for test_playbook in test_playbooks_set:
        detected_usage = False
        test_playbook_id = test_playbook.keys()[0]
        test_playbook_data = test_playbook.values()[0]
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

        if detected_usage and test_playbook_id not in test_ids:
            caught_missing_test = True
            print_error("The playbook {} does not appear in the conf.json file, which means no test with it will run."
                        "pleae update the conf.json file accordingly".format(test_playbook_name))

    missing_ids = update_missing_sets(catched_intergrations, catched_playbooks, catched_scripts,
                                      integration_ids, playbook_ids, script_ids)

    return test_ids, missing_ids, caught_missing_test


def update_missing_sets(catched_intergrations, catched_playbooks, catched_scripts, integration_ids, playbook_ids,
                        script_ids):
    missing_integrations = integration_ids - catched_intergrations
    missing_playbooks = playbook_ids - catched_playbooks
    missing_scripts = script_ids - catched_scripts
    missing_ids = missing_integrations.union(missing_playbooks).union(missing_scripts)
    return missing_ids


def get_test_ids(check_nightly_status=False):
    test_ids = []
    with open("./Tests/conf.json", 'r') as conf_file:
        conf = json.load(conf_file)

    conf_tests = conf['tests']
    for t in conf_tests:
        if not check_nightly_status or not t.get('nightly', False):
            playbook_id = t['playbookID']
            test_ids.append(playbook_id)

    return test_ids


def get_integration_commands(integration_ids, integration_set):
    integration_to_command = {}
    for integration in integration_set:
        integration_id = integration.keys()[0]
        integration_data = integration.values()[0]
        if integration_id in integration_ids:
            integration_to_command[integration_id] = integration_data.get('commands', [])

    return integration_to_command


def find_tests_for_modified_files(modified_files):
    script_names = set([])
    playbook_names = set([])
    integration_ids = set([])

    tests_set, catched_scripts, catched_playbooks = collect_changed_ids(integration_ids, playbook_names,
                                                                        script_names, modified_files)
    test_ids, missing_ids, caught_missing_test = collect_tests(script_names, playbook_names, integration_ids,
                                                               catched_scripts, catched_playbooks, tests_set)
    missing_ids = update_with_tests_sections(missing_ids, modified_files, test_ids, tests_set)

    if len(missing_ids) > 0:
        test_string = '\n'.join(missing_ids)
        message = "You've failed to provide tests for:\n{0}".format(test_string)
        print_color(message, LOG_COLORS.RED)

    if caught_missing_test or len(missing_ids) > 0:
        sys.exit(1)

    return tests_set


def update_with_tests_sections(missing_ids, modified_files, test_ids, tests):
    test_ids.append(RUN_ALL_TESTS_FORMAT)
    # Search for tests section
    for file_path in modified_files:
        tests_from_file = get_tests(file_path)
        for test in tests_from_file:
            if test in test_ids or re.match(NO_TESTS_FORMAT, test, re.IGNORECASE):
                if re.match(INTEGRATION_REGEX, file_path, re.IGNORECASE) or \
                        re.match(BETA_INTEGRATION_REGEX, file_path, re.IGNORECASE):
                    id = get_script_or_integration_id(file_path)

                else:
                    id = get_name(file_path)

                missing_ids = missing_ids - set([id])
                tests.add(test)

            else:
                message = "The test '{0}' does not exist in the conf.json file, please re-check your code".format(test)
                print_color(message, LOG_COLORS.RED)
                sys.exit(1)

    return missing_ids


def collect_changed_ids(integration_ids, playbook_names, script_names, modified_files):
    script_to_version = {}
    playbook_to_version = {}
    integration_to_version = {}
    for file_path in modified_files:
        if re.match(SCRIPT_TYPE_REGEX, file_path, re.IGNORECASE):
            name = get_name(file_path)
            script_names.add(name)
            script_to_version[name] = (get_from_version(file_path), get_to_version(file_path))
        elif re.match(PLAYBOOK_REGEX, file_path, re.IGNORECASE):
            name = get_name(file_path)
            playbook_names.add(name)
            playbook_to_version[name] = (get_from_version(file_path), get_to_version(file_path))
        elif re.match(INTEGRATION_REGEX, file_path, re.IGNORECASE) or \
                re.match(BETA_INTEGRATION_REGEX, file_path, re.IGNORECASE):
            id = get_script_or_integration_id(file_path)
            integration_ids.add(id)
            integration_to_version[id] = (get_from_version(file_path), get_to_version(file_path))

    with open("./Tests/id_set.json", 'r') as conf_file:
        id_set = json.load(conf_file)

    script_set = id_set['scripts']
    playbook_set = id_set['playbooks']
    integration_set = id_set['integrations']

    catched_scripts, catched_playbooks = set([]), set([])
    updated_script_names = set([])
    updated_playbook_names = set([])
    tests_set = set([])

    for script_id in script_names:
        enrich_for_script_id(script_id, script_to_version[script_id], script_names, script_set, playbook_set,
                             playbook_names, updated_script_names, updated_playbook_names, catched_scripts,
                             catched_playbooks, tests_set)

    integration_to_command = get_integration_commands(integration_ids, integration_set)
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

    affected_ids_string = ""
    if script_names:
        affected_ids_string += 'Scripts:\n' + '\n'.join(script_names) + '\n\n'
    if playbook_names:
        affected_ids_string += 'Playbooks:\n' + '\n'.join(playbook_names) + '\n\n'
    if integration_ids:
        affected_ids_string += 'Integrations:\n' + '\n'.join(integration_ids) + '\n\n'

    print('The following ids are affected due to the changes you made:\n{}'.format(affected_ids_string))
    return tests_set, catched_scripts, catched_playbooks


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
        playbook_data = playbook.values()[0]
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

                        tests = playbook_data.get('tests', [])
                        if tests:
                            catched_playbooks.add(playbook_name)
                            update_test_set(tests, tests_set)

                        updated_playbook_names.add(playbook_name)
                        new_versions = (playbook_fromversion, playbook_toversion)
                        enrich_for_playbook_id(playbook_name, new_versions, playbook_names, script_set, playbook_set,
                                               updated_playbook_names, catched_playbooks, tests_set)

    for script in script_set:
        script_data = script.values()[0]
        script_name = script_data.get('name')
        script_fromversion = script_data.get('fromversion', '0.0.0')
        script_toversion = script_data.get('toversion', '99.99.99')
        command_to_integration = script_data.get('command_to_integration', {})
        for integration_command in integration_commands:
            if integration_command in script_data.get('depends_on', []) and not script_data.get('deprecated'):
                if integration_command in command_to_integration.keys() and \
                        command_to_integration[integration_command] == integration_id and \
                        script_toversion >= given_version[1]:

                    if script_name not in script_names and script_name not in updated_script_names:
                        tests = script_data.get('tests', [])
                        if tests:
                            catched_scripts.add(script_name)
                            update_test_set(tests, tests_set)

                        updated_script_names.add(script_name)
                        new_versions = (script_fromversion, script_toversion)
                        enrich_for_script_id(script_name, new_versions, script_names, script_set, playbook_set,
                                             playbook_names, updated_script_names, updated_playbook_names,
                                             catched_scripts, catched_playbooks, tests_set)


def enrich_for_playbook_id(given_playbook_id, given_version, playbook_names, script_set, playbook_set,
                           updated_playbook_names, catched_playbooks, tests_set):
    for playbook in playbook_set:
        playbook_data = playbook.values()[0]
        playbook_name = playbook_data.get('name')
        playbook_fromversion = playbook_data.get('fromversion', '0.0.0')
        playbook_toversion = playbook_data.get('toversion', '99.99.99')
        if given_playbook_id in playbook_data.get('implementing_playbooks', []) and \
                playbook_toversion >= given_version[1]:

            if playbook_name not in playbook_names and playbook_name not in updated_playbook_names:
                tests = playbook_data.get('tests', [])
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
        script_data = script.values()[0]
        script_name = script_data.get('name')
        script_fromversion = script_data.get('fromversion', '0.0.0')
        script_toversion = script_data.get('toversion', '99.99.99')
        if given_script_id in script_data.get('script_executions', []) and not script_data.get('deprecated') and \
                script_toversion >= given_version[1]:
            if script_name not in script_names and script_name not in updated_script_names:
                tests = script_data.get('tests', [])
                if tests:
                    catched_scripts.add(script_name)
                    update_test_set(tests, tests_set)

                updated_script_names.add(script_name)
                new_versions = (script_fromversion, script_toversion)
                enrich_for_script_id(script_name, new_versions, script_names, script_set, playbook_set, playbook_names,
                                     updated_script_names, updated_playbook_names, catched_scripts, catched_playbooks,
                                     tests_set)

    for playbook in playbook_set:
        playbook_data = playbook.values()[0]
        playbook_name = playbook_data.get('name')
        playbook_fromversion = playbook_data.get('fromversion', '0.0.0')
        playbook_toversion = playbook_data.get('toversion', '99.99.99')
        if given_script_id in playbook_data.get('implementing_scripts', []) and playbook_toversion >= given_version[1]:
            if playbook_name not in playbook_names and playbook_name not in updated_playbook_names:
                tests = playbook_data.get('tests', [])
                if tests:
                    catched_playbooks.add(playbook_name)
                    update_test_set(tests, tests_set)

                updated_playbook_names.add(playbook_name)
                new_versions = (playbook_fromversion, playbook_toversion)
                enrich_for_playbook_id(playbook_name, new_versions, playbook_names, script_set, playbook_set,
                                       updated_playbook_names, catched_playbooks, tests_set)


def update_test_set(tests_set, tests):
    for test in tests:
        tests_set.add(test)


def get_test_from_conf(branch_name):
    tests = set([])
    changed = set([])
    change_string = run_command("git diff origin/master...{} Tests/conf.json".format(branch_name))
    added_groups = re.findall('(\+[ ]+")(.*)(":)', change_string)
    if added_groups:
        for group in added_groups:
            changed.add(group[1])

    deleted_groups = re.findall('(\-[ ]+")(.*)(":)', change_string)
    if deleted_groups:
        for group in deleted_groups:
            changed.add(group[1])

    with open("./Tests/conf.json", 'r') as conf_file:
        conf = json.load(conf_file)

    conf_tests = conf['tests']
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


def get_test_list(files_string, branch_name):
    """Create a test list that should run"""
    modified_files, modified_tests_list, all_tests, is_conf_json, infra_tests = get_modified_files(files_string)

    tests = set([])
    if modified_files:
        tests = find_tests_for_modified_files(modified_files)

    for file_path in modified_tests_list:
        test = collect_ids(file_path)
        if test not in tests:
            tests.add(test)

    if is_conf_json:
        tests = tests.union(get_test_from_conf(branch_name))

    if all_tests:
        tests.add("Run all tests")

    if infra_tests:  # Choosing 3 random tests for infrastructure testing
        test_ids = get_test_ids(check_nightly_status=True)
        for _ in range(3):
            tests.add(test_ids[random.randint(0, len(test_ids))])

    if not tests and (modified_files or modified_tests_list or all_tests):
        print_color("There are no tests that check the changes you've done, please make sure you write one",
                    LOG_COLORS.RED)
        sys.exit(1)

    return tests


def create_test_file(is_nightly):
    """Create a file containing all the tests we need to run for the CI"""
    tests_string = ''
    if not is_nightly:
        branches = run_command("git branch")
        branch_name_reg = re.search("\* (.*)", branches)
        branch_name = branch_name_reg.group(1)

        print("Getting changed files from the branch: {0}".format(branch_name))
        if branch_name != 'master':
            files_string = run_command("git diff --name-status origin/master...{0}".format(branch_name))
        else:
            commit_string = run_command("git log -n 2 --pretty='%H'")
            commit_string = commit_string.replace("'", "")
            last_commit, second_last_commit = commit_string.split()
            files_string = run_command("git diff --name-status {}...{}".format(second_last_commit, last_commit))

        tests = get_test_list(files_string, branch_name)

        tests_string = '\n'.join(tests)
        if tests_string:
            print('Collected the following tests:\n{0}\n'.format(tests_string))
        else:
            print('No filter configured, running all tests')

    print("Creating filter_file.txt")
    with open("./Tests/filter_file.txt", "w") as filter_file:
        filter_file.write(tests_string)


if __name__ == "__main__":
    print_color("Starting creation of test filter file", LOG_COLORS.GREEN)

    parser = argparse.ArgumentParser(description='Utility CircleCI usage')
    parser.add_argument('-n', '--nightly', type=str2bool, help='Is nightly or not')
    options = parser.parse_args()

    # Create test file based only on committed files
    create_test_file(options.nightly)

    print_color("Finished creation of the test filter file", LOG_COLORS.GREEN)
    sys.exit(0)
