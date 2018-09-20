"""
This script is used to create a temp_conf.json file which will run only the needed the tests for a given change.#############################################
"""
import pip
import sys

try:
    import yaml
except ImportError:
    print "Please install pyyaml, you can do it by running: `pip install pyyaml`"
    sys.exit(1)

try:
    import pykwalify
except ImportError:
    print "Please install pykwalify, you can do it by running: `pip install -I pykwalify`"
    sys.exit(1)

import re
import os
import json
from subprocess import Popen, PIPE

# dirs
MISC_DIR = "Misc"
SCRIPTS_DIR = "Scripts"
REPORTS_DIR = "Reports"
WIDGETS_DIR = "Widgets"
LAYOUTS_DIR = "Layouts"
PLAYBOOKS_DIR = "Playbooks"
DASHBOARDS_DIR = "Dashboards"
CLASSIFIERS_DIR = "Classifiers"
CONNECTIONS_DIR = "Connections"
INTEGRATIONS_DIR = "Integrations"
TEST_PLAYBOOKS_DIR = "TestPlaybooks"
INCIDENT_FIELDS_DIR = "IncidentFields"

# file types regexes
SCRIPT_REGEX = "{}.*script-.*.yml".format(SCRIPTS_DIR)
MISC_REGEX = "{}.*reputations.*.json".format(MISC_DIR)
REPORT_REGEX = "{}.*report-.*.json".format(REPORTS_DIR)
LAYOUT_REGEX = "{}.*layout-.*.json".format(LAYOUTS_DIR)
WIDGETS_REGEX = "{}.*widget-.*.json".format(WIDGETS_DIR)
PLAYBOOK_REGEX = "{}.*playbook-.*.yml".format(PLAYBOOKS_DIR)
DASHBOARD_REGEX = "{}.*dashboard-.*.json".format(DASHBOARDS_DIR)
CLASSIFIER_REGEX = "{}.*classifier-.*.json".format(CLASSIFIERS_DIR)
INTEGRATION_REGEX = "{}.*integration-.*.yml".format(INTEGRATIONS_DIR)
TEST_PLAYBOOK_REGEX = "{}.*playbook-.*.yml".format(TEST_PLAYBOOKS_DIR)
INCIDENT_FIELDS_REGEX = "{}.*incidentfields.*.json".format(INCIDENT_FIELDS_DIR)
CONNECTIONS_REGEX = "{}.*canvas-context-connections.*.json".format(CONNECTIONS_DIR)

CHECKED_TYPES_REGEXES = [INTEGRATION_REGEX, PLAYBOOK_REGEX, SCRIPT_REGEX, WIDGETS_REGEX, DASHBOARD_REGEX,
                         CONNECTIONS_REGEX, CLASSIFIER_REGEX, LAYOUT_REGEX, INCIDENT_FIELDS_REGEX, MISC_REGEX,
                         REPORT_REGEX]

SKIPPED_SCHEMAS = [MISC_REGEX, REPORT_REGEX]

KNOWN_FILE_STATUSES = ['a', 'm', 'd']

REGEXES_TO_SCHEMA_DIC = {LAYOUT_REGEX:"layout",
                         SCRIPT_REGEX: "script",
                         WIDGETS_REGEX: "widget",
                         PLAYBOOK_REGEX: "playbook",
                         DASHBOARD_REGEX:"dashboard",
                         CLASSIFIER_REGEX: "classifier",
                         INTEGRATION_REGEX: "integration",
                         TEST_PLAYBOOK_REGEX:"test-playbook",
                         INCIDENT_FIELDS_REGEX:"incidentfields",
                         CONNECTIONS_REGEX: "canvas-context-connections"}

SCHEMAS_PATH = "Tests/schemas/"

DIRS = [INTEGRATIONS_DIR, SCRIPTS_DIR, PLAYBOOKS_DIR, REPORTS_DIR, DASHBOARDS_DIR, WIDGETS_DIR, INCIDENT_FIELDS_DIR,
        LAYOUTS_DIR, CLASSIFIERS_DIR, MISC_DIR]

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
    all_files = files_string.split('\n')

    for f in all_files:
        file_data = f.split()
        if not file_data:
            continue

        file_path = file_data[1]
        file_status = file_data[0]

        if file_status.lower() == 'm' and checked_type(file_path) and not file_path.startswith('.'):
            modified_files_list.append(file_path)
        if file_status.lower() not in KNOWN_FILE_STATUSES:
            print_error("{0} file status is an unknown known one, "
                        "please check. File status was: {1}".format(file_path,file_status))

    return modified_files_list


def collect_tests(file_path):
    """Collect tests mentioned in file_path"""
    data_dictionary = None

    with open(os.path.expanduser(file_path), "r") as f:
        if file_path.endswith(".json"):
            data_dictionary = json.load(f)
        elif file_path.endswith(".yaml") or file_path.endswith('.yml'):
            try:
                data_dictionary = yaml.safe_load(f)
            except Exception as e:
                print_error(file_path + " has yml structure issue. Error was: " + str(e))
                return False

    if data_dictionary and data_dictionary.get('tests') is not None:
        return data_dictionary.get('tests')


def create_test_file():
    """Create a file containing all the tests we need to run for the CI"""
    branch_name = run_git_command("git branch | grep \* | cut -d ' ' -f2")
    files_string = run_git_command("git diff --name-only master {0}".format(branch_name))
    modified_files = get_modified_files(files_string)

    tests = []
    for file_path in modified_files:
        print "Gathering tests from {}".format(file_path)
        for test in collect_tests(file_path):
            if test not in tests:
                tests.append(test)

    if "-" in tests:
        tests = ["-", ]

    with open("../filter_file.txt", "w") as filter_file:
        filter_file.write('\n'.join(tests))


def main():
    print_color("Starting creation of test filter file", LOG_COLORS.GREEN)

    # Create test file based only on committed files
    create_test_file()

    print_color("Finished creation of the test filter file", LOG_COLORS.GREEN)
    sys.exit(0)


if __name__ == "__main__":
   main()
