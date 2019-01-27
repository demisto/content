"""
This script is used to create a filter_file.txt file which will run only the needed the tests for a given change.
"""
import re
import os
import sys
import json
import glob
import argparse
from subprocess import Popen, PIPE

try:
    import yaml
except ImportError:
    print "Please install pyyaml, you can do it by running: `pip install pyyaml`"
    sys.exit(1)

# Search Keyword for the changed file
RUN_ALL_TESTS_FORMAT = 'Run all tests'
NO_TESTS_FORMAT = 'No test( - .*)?'

# file types regexes
CONF_REGEX = "Tests/conf.json"
SCRIPT_PY_REGEX = "scripts.*.py"
SCRIPT_JS_REGEX = "scripts.*.js"
SCRIPT_YML_REGEX = "scripts.*.yml"
SCRIPT_REGEX = "scripts.*script-.*.yml"
INTEGRATION_PY_REGEX = "integrations.*.py"
INTEGRATION_JS_REGEX = "integrations.*.js"
INTEGRATION_YML_REGEX = "integrations.*.yml"
PLAYBOOK_REGEX = "(?!Test)playbooks.*playbook-.*.yml"
INTEGRATION_REGEX = "integrations.*integration-.*.yml"
TEST_PLAYBOOK_REGEX = "TestPlaybooks.*playbook-.*.yml"
TEST_NOT_PLAYBOOK_REGEX = "TestPlaybooks.(?!playbook).*-.*.yml"
BETA_SCRIPT_REGEX = "beta_integrations.*script-.*.yml"
BETA_PLAYBOOK_REGEX = "beta_integrations.*playbook-.*.yml"
BETA_INTEGRATION_REGEX = "beta_integrations.*integration-.*.yml"

CHECKED_TYPES_REGEXES = [INTEGRATION_REGEX, PLAYBOOK_REGEX, SCRIPT_REGEX, TEST_NOT_PLAYBOOK_REGEX,
                         BETA_INTEGRATION_REGEX, BETA_SCRIPT_REGEX, BETA_PLAYBOOK_REGEX, SCRIPT_YML_REGEX,
                         INTEGRATION_YML_REGEX]

CODE_FILES_REGEX = [INTEGRATION_JS_REGEX, INTEGRATION_PY_REGEX, SCRIPT_PY_REGEX, SCRIPT_JS_REGEX]

# File type regex
SCRIPT_TYPE_REGEX = ".*script-.*.yml"

# File names
ALL_TESTS = ["scripts/script-CommonIntegration.yml", "scripts/script-CommonIntegrationPython.yml",
             "scripts/script-CommonServer.yml", "scripts/script-CommonServerPython.yml",
             "scripts/script-CommonServerUserPython.yml", "scripts/script-CommonUserServer.yml"]


class LOG_COLORS:
    NATIVE = '\033[m'
    RED = '\033[01;31m'
    GREEN = '\033[01;32m'


# print srt in the given color
def print_color(msg, color):
    print(str(color) + str(msg) + LOG_COLORS.NATIVE)


def print_error(error_str):
    print_color(error_str, LOG_COLORS.RED)


def run_git_command(command):
    p = Popen(command.split(), stdout=PIPE, stderr=PIPE)
    p.wait()
    if p.returncode != 0:
        print_error("Failed to run git command " + command)
        sys.exit(1)
    return p.stdout.read()


def checked_type(file_path, regex_list):
    """Check if the file_path is from the regex list"""
    for regex in regex_list:
        if re.match(regex, file_path, re.IGNORECASE):
            return True

    return False


def str2bool(v):
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


def get_modified_files(files_string):
    """Get a string of the modified files"""
    is_conf_json = False
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
            elif file_status.lower() == 'm' and 'id_set.json' not in file_path:
                all_tests.append(file_path)

    return modified_files_list, modified_tests_list, all_tests, is_conf_json


def collect_ids(file_path):
    """Collect id mentioned in file_path"""
    data_dictionary = get_json(file_path)

    if data_dictionary:
        return data_dictionary.get('id', '-')


def get_name(file_path):
    data_dictionary = get_json(file_path)

    if data_dictionary:
        return data_dictionary.get('name', '-')


def get_from_version(file_path):
    data_dictionary = get_json(file_path)

    if data_dictionary:
        return data_dictionary.get('fromversion', '0.0.0')


def get_to_version(file_path):
    data_dictionary = get_json(file_path)

    if data_dictionary:
        return data_dictionary.get('toversion', '99.99.99')


def get_tests(file_path):
    """Collect tests mentioned in file_path"""
    data_dictionary = get_json(file_path)

    if data_dictionary:
        return data_dictionary.get('tests', [])


def get_script_or_integration_id(file_path):
    data_dictionary = get_json(file_path)

    if data_dictionary:
        commonfields = data_dictionary.get('commonfields', {})
        return commonfields.get('id', ['-', ])


def get_json(file_path):
    data_dictionary = None
    with open(os.path.expanduser(file_path), "r") as f:
        if file_path.endswith(".yaml") or file_path.endswith('.yml'):
            try:
                data_dictionary = yaml.safe_load(f)
            except Exception as e:
                print_error(file_path + " has yml structure issue. Error was: " + str(e))
                return []

    if type(data_dictionary) is dict:
        return data_dictionary
    else:
        return {}


def collect_tests(script_ids, playbook_ids, integration_ids, catched_scripts, catched_playbooks, tests_set):
    """Collect tests for the affected script_ids,playbook_ids,integration_ids.

    :param script_ids: The ids of the affected scripts in your change set.
    :param playbook_ids: The ids of the affected playbooks in your change set.
    :param integration_ids: The ids of the affected integrations in your change set.
    :param catched_scripts: The names of the scripts we already identified a test for.
    :param catched_playbooks: The names of the scripts we already v a test for.
    :param tests_set: The names of the tests we alredy identified.

    :return: (test_names, missing_ids) - All the names of possible tests, the ids we didn't match a test for.
    """
    catched_intergrations = set([])

    test_names = get_test_names()

    with open("./Tests/id_set.json", 'r') as conf_file:
        id_set = json.load(conf_file)

    integration_set = id_set['integrations']
    test_playbooks_set = id_set['TestPlaybooks']
    integration_to_command = get_integration_commands(integration_ids, integration_set)

    for test_playbook in test_playbooks_set:
        test_playbook_id = test_playbook.keys()[0]
        test_playbook_data = test_playbook.values()[0]
        for script in test_playbook_data.get('implementing_scripts', []):
            if script in script_ids:
                tests_set.add(test_playbook_id)
                catched_scripts.add(script)

        for playbook in test_playbook_data.get('implementing_playbooks', []):
            if playbook in playbook_ids:
                tests_set.add(test_playbook_id)
                catched_playbooks.add(playbook)

        if integration_to_command:
            command_to_integration = test_playbook_data.get('command_to_integration', {})
            for command in test_playbook_data.get('command_to_integration', {}).keys():
                for integration_id, integration_commands in integration_to_command.items():
                    if command in integration_commands:
                        if not command_to_integration.get(command) or \
                                command_to_integration.get(command) == integration_id:

                            tests_set.add(test_playbook_id)
                            catched_intergrations.add(integration_id)

    missing_ids = update_missing_sets(catched_intergrations, catched_playbooks, catched_scripts,
                                      integration_ids, playbook_ids, script_ids)

    return test_names, missing_ids


def update_missing_sets(catched_intergrations, catched_playbooks, catched_scripts, integration_ids, playbook_ids,
                        script_ids):
    missing_integrations = integration_ids - catched_intergrations
    missing_playbooks = playbook_ids - catched_playbooks
    missing_scripts = script_ids - catched_scripts
    missing_ids = missing_integrations.union(missing_playbooks).union(missing_scripts)
    return missing_ids


def get_test_names():
    test_names = []
    with open("./Tests/conf.json", 'r') as conf_file:
        conf = json.load(conf_file)

    conf_tests = conf['tests']
    for t in conf_tests:
        playbook_id = t['playbookID']
        test_names.append(playbook_id)

    return test_names


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
    test_names, missing_ids = collect_tests(script_names, playbook_names, integration_ids,
                                            catched_scripts, catched_playbooks, tests_set)
    missing_ids = update_with_tests_sections(missing_ids, modified_files, test_names, tests_set)

    if len(missing_ids) > 0:
        test_string = '\n'.join(missing_ids)
        message = "You've failed to provide tests for:\n{0}".format(test_string)
        print_color(message, LOG_COLORS.RED)
        sys.exit(1)

    return tests_set


def update_with_tests_sections(missing_ids, modified_files, test_names, tests):
    test_names.append(RUN_ALL_TESTS_FORMAT)
    # Search for tests section
    for file_path in modified_files:
        tests_from_file = get_tests(file_path)
        for test in tests_from_file:
            if test in test_names or re.match(NO_TESTS_FORMAT, test, re.IGNORECASE):
                if re.match(INTEGRATION_REGEX, file_path, re.IGNORECASE) or \
                        re.match(BETA_INTEGRATION_REGEX, file_path, re.IGNORECASE):
                    id = get_script_or_integration_id(file_path)

                else:
                    id = get_name(file_path)

                missing_ids = missing_ids - set([id])
                tests.add(test)

            else:
                message = "The test '{0}' does not exist, please re-check your code".format(test)
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
    change_string = run_git_command("git diff origin/master...{} Tests/conf.json".format(branch_name))
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


def get_test_list(modified_files, modified_tests_list, all_tests, is_conf_json, branch_name):
    """Create a test list that should run"""
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

    if not tests and (modified_files or modified_tests_list or all_tests):
        print_color("There are no tests that check the changes you've done, please make sure you write one",
                    LOG_COLORS.RED)
        sys.exit(1)

    return tests


def create_test_file(is_nightly):
    """Create a file containing all the tests we need to run for the CI"""
    tests_string = ''
    if not is_nightly:
        branches = run_git_command("git branch")
        branch_name_reg = re.search("\* (.*)", branches)
        branch_name = branch_name_reg.group(1)

        print("Getting changed files from the branch: {0}".format(branch_name))
        if branch_name != 'master':
            files_string = run_git_command("git diff --name-status origin/master...{0}".format(branch_name))
        else:
            commit_string = run_git_command("git log -n 2 --pretty='%H'")
            commit_string = commit_string.replace("'", "")
            last_commit, second_last_commit = commit_string.split()
            files_string = run_git_command("git diff --name-status {}...{}".format(second_last_commit, last_commit))

        modified_files, modified_tests_list, all_tests, is_conf_json = get_modified_files(files_string)
        tests = get_test_list(modified_files, modified_tests_list, all_tests, is_conf_json, branch_name)

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
