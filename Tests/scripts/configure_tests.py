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
            if checked_type(file_path):
                modified_files_list.append(file_path)
            elif re.match(TEST_PLAYBOOK_REGEX, file_path, re.IGNORECASE):
                modified_tests_list.append(file_path)

    return modified_files_list, modified_tests_list


def collect_tests(file_path, search_key):
    """Collect tests mentioned in file_path"""
    data_dictionary = None

    with open(os.path.expanduser(file_path), "r") as f:
        if file_path.endswith(".yaml") or file_path.endswith('.yml'):
            try:
                data_dictionary = yaml.safe_load(f)
            except Exception as e:
                print_error(file_path + " has yml structure issue. Error was: " + str(e))
                return []

    if data_dictionary:
        return data_dictionary.get(search_key, ['-', ])


def get_test_list(modified_files, modified_tests_list):
    """Create a test list that should run"""
    tests = []
    for file_path in modified_files:
        # print "Gathering tests from {}".format(file_path)
        for test in collect_tests(file_path, TESTS_LIST):
            if test not in tests:
                tests.append(test)

    for file_path in modified_tests_list:
        test = collect_tests(file_path, TEST_ID)
        if test not in tests:
            tests.append(test)

    if '-' in tests:
        tests = []

    return tests


def create_test_file():
    """Create a file containing all the tests we need to run for the CI"""
    branches = run_git_command("git branch")
    branch_name_reg = re.search("(?<=\* )\w+", branches)
    branch_name = branch_name_reg.group(0)

    print("Getting changed files from the branch: {0}".format(branch_name))
    tests_string = ''
    if branch_name != 'master':
        files_string = run_git_command("git diff --name-status origin/master...{0}".format(branch_name))

        modified_files, modified_tests_list = get_modified_files(files_string)

        tests = get_test_list(modified_files, modified_tests_list)
        tests_string = '\n'.join(tests)
        print('Collected the following tests:\n{0}'.format(tests_string))

    print("Creating filter_file.txt")
    with open("./Tests/filter_file.txt", "w") as filter_file:
        filter_file.write(tests_string)


if __name__ == "__main__":
   print_color("Starting creation of test filter file", LOG_COLORS.GREEN)

   # Create test file based only on committed files
   create_test_file()

   print_color("Finished creation of the test filter file", LOG_COLORS.GREEN)
   sys.exit(0)
