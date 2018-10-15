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
import pip
import sys
from subprocess import Popen, PIPE

# Search Keyword for the changed file
TEST_ID = 'id'
TESTS_LIST = 'tests'

# file types regexes
SCRIPT_REGEX = "scripts.*script-.*.yml"
PLAYBOOK_REGEX = "(?!Test)playbooks.*playbook-.*.yml"
INTEGRATION_REGEX = "integrations.*integration-.*.yml"
TEST_PLAYBOOK_REGEX = "TestPlaybooks.*playbook-.*.yml"
TEST_NOT_PLAYBOOK_REGEX = "TestPlaybooks.(?!playbook).*-.*.yml"

CHECKED_TYPES_REGEXES = [INTEGRATION_REGEX, PLAYBOOK_REGEX, SCRIPT_REGEX, TEST_NOT_PLAYBOOK_REGEX]


# File type regex
SCRIPT_TYPE_REGEX = ".*script-.*.yml"

# File names
ALL_TESTS = ["scripts.script-CommonIntegration.yml", "scripts.script-CommonIntegrationPython.yml",
             "scripts.script-CommonServer.yml", "scripts.script-CommonServerPython.yml",
             "scripts.script-CommonServerUserPython.yml", "scripts.script-CommonUserServer.yml", "Tests.conf.json"]


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


def checked_type(file_path):
    """Check if the file_path is from the CHECKED_TYPES_REGEXES list"""
    for regex in CHECKED_TYPES_REGEXES:
        if re.match(regex, file_path, re.IGNORECASE):
            return True

    return False


def get_modified_files(files_string):
    """Get a string of the modified files"""
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
            if file_path in ALL_TESTS:
                all_tests.append(file_path)
            elif checked_type(file_path):
                modified_files_list.append(file_path)
            elif re.match(TEST_PLAYBOOK_REGEX, file_path, re.IGNORECASE):
                modified_tests_list.append(file_path)

    return modified_files_list, modified_tests_list, all_tests


def collect_ids(file_path):
    """Collect tests mentioned in file_path"""
    data_dictionary = get_json(file_path)

    if data_dictionary:
        return data_dictionary.get('id', ['-', ])


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

    return data_dictionary


def collect_tests(script_ids, playbook_ids):
    tests = []
    for filename in os.listdir('./TestPlaybooks'):
        if re.match(TEST_PLAYBOOK_REGEX, filename, re.IGNORECASE):
            data_dict = get_json(filename)
            tasks = data_dict.get('tasks', [])
            for task in tasks:
                task_details = task.get('task', {})

                script_name = task_details.get('scriptName', '')
                if script_name in script_ids:
                    tests.append(data_dict.get('id'))

                playbook_name = task_details.get('playbookName', '')
                if playbook_name in playbook_ids:
                    tests.append(data_dict.get('id'))

    return tests


def find_tests_for_modified_files(modified_files):
    script_ids = []
    playbook_ids = []
    intergration_ids = []
    for file_path in modified_files:
        if re.match(SCRIPT_TYPE_REGEX, file_path, re.IGNORECASE):
            script_ids.append(get_script_or_integration_id(file_path))
        elif re.match(PLAYBOOK_REGEX, file_path, re.IGNORECASE):
            playbook_ids.append(collect_ids(file_path))
        elif re.match(INTEGRATION_REGEX, file_path, re.IGNORECASE):
            intergration_ids.append(get_script_or_integration_id(file_path))

    return collect_tests(script_ids, playbook_ids), intergration_ids


def get_test_list(modified_files, modified_tests_list, all_tests):
    """Create a test list that should run"""
    tests, integrations = find_tests_for_modified_files(modified_files)

    for file_path in modified_tests_list:
        test = collect_ids(file_path)
        if test not in tests:
            tests.append(test)

    if all_tests:
        tests.append("Run all tests")

    return tests, integrations


def create_test_file():
    """Create a file containing all the tests we need to run for the CI"""
    branches = run_git_command("git branch")
    branch_name_reg = re.search("\* (.*)", branches)
    branch_name = branch_name_reg.group(1)

    print("Getting changed files from the branch: {0}".format(branch_name))
    tests_string = ''
    integrations_string = ''
    if branch_name != 'master':
        files_string = run_git_command("git diff --name-status origin/master...{0}".format(branch_name))

        modified_files, modified_tests_list, all_tests = get_modified_files(files_string)
        tests, integrations = get_test_list(modified_files, modified_tests_list, all_tests)

        tests_string = '\n'.join(tests)
        integrations_string = '\n'.join(integrations)
        if tests != 'None' or integrations != 'None':
            if tests != 'None':
                print('Collected the following tests:\n{0}'.format(tests_string))
            if integrations != 'None':
                print('Collected the following integrations:\n{0}'.format(integrations_string))
        else:
            print('No filter configured, not running any tests')

    print("Creating filter_file.txt")
    with open("./Tests/filter_file.txt", "w") as filter_file:
        filter_file.write(tests_string)

    print("Creating filter_file.txt")
    with open("./Tests/integrations_file.txt", "w") as integrations_file:
        integrations_file.write(integrations_string)


if __name__ == "__main__":
   print_color("Starting creation of test filter file", LOG_COLORS.GREEN)

   # Create test file based only on committed files
   create_test_file()

   print_color("Finished creation of the test filter file", LOG_COLORS.GREEN)
   sys.exit(0)
