"""
This script is used to create a filter_file.txt file which will run only the needed the tests for a given change.
"""
try:
    import yaml
except ImportError:
    print "Please install pyyaml, you can do it by running: `pip install pyyaml`"
    sys.exit(1)


import re
import os
import sys
import json
import argparse
from subprocess import Popen, PIPE

# Search Keyword for the changed file
RUN_ALL_TESTS_FORMAT = 'Run all tests'
NO_TESTS_FORMAT = 'No test( - .*)?'

# file types regexes
CONF_REGEX = "Tests/conf.json"
SCRIPT_REGEX = "scripts.*script-.*.yml"
PLAYBOOK_REGEX = "(?!Test)playbooks.*playbook-.*.yml"
INTEGRATION_REGEX = "integrations.*integration-.*.yml"
TEST_PLAYBOOK_REGEX = "TestPlaybooks.*playbook-.*.yml"
TEST_NOT_PLAYBOOK_REGEX = "TestPlaybooks.(?!playbook).*-.*.yml"
BETA_SCRIPT_REGEX = "beta_integrations.*script-.*.yml"
BETA_PLAYBOOK_REGEX = "beta_integrations.*playbook-.*.yml"
BETA_INTEGRATION_REGEX = "beta_integrations.*integration-.*.yml"

CHECKED_TYPES_REGEXES = [INTEGRATION_REGEX, PLAYBOOK_REGEX, SCRIPT_REGEX, TEST_NOT_PLAYBOOK_REGEX, BETA_INTEGRATION_REGEX, BETA_SCRIPT_REGEX, BETA_PLAYBOOK_REGEX]


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
    print(str(color) +str(msg) + LOG_COLORS.NATIVE)


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
            if checked_type(file_path, ALL_TESTS):
                all_tests.append(file_path)
            elif checked_type(file_path, CHECKED_TYPES_REGEXES):
                modified_files_list.append(file_path)
            elif re.match(TEST_PLAYBOOK_REGEX, file_path, re.IGNORECASE):
                modified_tests_list.append(file_path)
            elif re.match(CONF_REGEX, file_path, re.IGNORECASE):
                is_conf_json = True
            elif file_status.lower() == 'm':
                all_tests.append(file_path)

    return modified_files_list, modified_tests_list, all_tests, is_conf_json


def collect_ids(file_path):
    """Collect id mentioned in file_path"""
    data_dictionary = get_json(file_path)

    if data_dictionary:
        return data_dictionary.get('id', '-')


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


def collect_tests(script_ids, playbook_ids, intergration_ids):
    test_names = []
    tests = set([])
    catched_scripts = set([])
    catched_playbooks = set([])
    catched_intergrations = set([])
    with open("./Tests/conf.json", 'r') as conf_file:
        conf = json.load(conf_file)

    conf_tests = conf['tests']
    for t in conf_tests:
        playbook_id = t['playbookID']
        integrations_conf = t.get('integrations', [])

        test_names.append(playbook_id)
        if not isinstance(integrations_conf, list):
            integrations_conf = [integrations_conf]

        for integration in integrations_conf:
            if integration in intergration_ids:
                tests.add(playbook_id)
                catched_intergrations.add(integration)

    # Searching for the appropriate test according to scriptName or playbookName
    for filename in os.listdir('./TestPlaybooks'):
        file_path = 'TestPlaybooks/' + filename

        if re.match(TEST_PLAYBOOK_REGEX, file_path, re.IGNORECASE):
            data_dict = get_json(file_path)
            tasks = data_dict.get('tasks', [])

            for task in tasks.values():
                task_details = task.get('task', {})

                script_name = task_details.get('scriptName', '')
                if script_name in script_ids:
                    tests.add(data_dict.get('id'))
                    catched_scripts.add(script_name)

                playbook_name = task_details.get('playbookName', '')
                if playbook_name in playbook_ids:
                    tests.add(data_dict.get('id'))
                    catched_playbooks.add(playbook_name)

    missing_integrations = intergration_ids - catched_intergrations
    missing_playbooks = playbook_ids - catched_playbooks
    missing_scripts = script_ids - catched_scripts
    missing_ids = missing_integrations.union(missing_playbooks).union(missing_scripts)

    return tests, test_names, missing_ids


def find_tests_for_modified_files(modified_files):
    script_ids = set([])
    playbook_ids = set([])
    intergration_ids = set([])
    for file_path in modified_files:
        if re.match(SCRIPT_TYPE_REGEX, file_path, re.IGNORECASE):
            id = get_script_or_integration_id(file_path)
            script_ids.add(id)
        elif re.match(PLAYBOOK_REGEX, file_path, re.IGNORECASE):
            id = collect_ids(file_path)
            playbook_ids.add(id)
        elif re.match(INTEGRATION_REGEX, file_path, re.IGNORECASE) or \
                re.match(BETA_INTEGRATION_REGEX, file_path, re.IGNORECASE):
            id = get_script_or_integration_id(file_path)
            intergration_ids.add(id)

    tests, test_names, missing_ids = collect_tests(script_ids, playbook_ids, intergration_ids)

    test_names.append(RUN_ALL_TESTS_FORMAT)
    # Search for tests section
    for file_path in modified_files:
        tests_from_file = get_tests(file_path)
        for test in tests_from_file:
            if test in test_names or re.match(NO_TESTS_FORMAT, test, re.IGNORECASE):
                if re.match(SCRIPT_TYPE_REGEX, file_path, re.IGNORECASE) or \
                        re.match(INTEGRATION_REGEX, file_path, re.IGNORECASE) or \
                        re.match(BETA_INTEGRATION_REGEX, file_path, re.IGNORECASE):
                    id = get_script_or_integration_id(file_path)

                else:
                    id = collect_ids(file_path)

                missing_ids = missing_ids - set([id])
                tests.add(test)

            else:
                message = "The test '{0}' does not exist, please re-check your code".format(test)
                print_color(message, LOG_COLORS.RED)
                sys.exit(1)

    if len(missing_ids) > 0:
        test_string = '\n'.join(missing_ids)
        message = "You've failed to provide tests for:\n{0}".format(test_string)
        print_color(message, LOG_COLORS.RED)
        sys.exit(1)

    return tests


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
        print_color("There are no tests that check the changes you've done, please make sure you write one", LOG_COLORS.RED)
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
            print('Collected the following tests:\n{0}'.format(tests_string))
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
