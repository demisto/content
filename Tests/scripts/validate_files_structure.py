"""
This script is used to validate the files in Content repository. Specifically for each file:
1) Proper prefix
2) Proper suffix
3) Valid yml/json schema
4) Having ReleaseNotes if applicable.

It can be run to check only commited changes (if the first argument is 'true') or all the files in the repo.
Note - if it is run for all the files in the repo it won't check releaseNotes, use `setContentDescriptor.sh` for that task.
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
import glob
import json
from subprocess import Popen, PIPE
from pykwalify.core import Core

# Magic Numbers
IMAGE_MAX_SIZE = 10 * 1024  # 10kB

# dirs
INTEGRATIONS_DIR = "Integrations"
SCRIPTS_DIR = "Scripts"
PLAYBOOKS_DIR = "Playbooks"
TEST_PLAYBOOKS_DIR = "TestPlaybooks"
REPORTS_DIR = "Reports"
DASHBOARDS_DIR = "Dashboards"
WIDGETS_DIR = "Widgets"
INCIDENT_FIELDS_DIR = "IncidentFields"
LAYOUTS_DIR = "Layouts"
CLASSIFIERS_DIR = "Classifiers"
MISC_DIR = "Misc"
CONNECTIONS_DIR = "Connections"

# file types regexes
INTEGRATION_REGEX = "{}.*integration-.*.yml".format(INTEGRATIONS_DIR)
PLAYBOOK_REGEX = "{}.*playbook-.*.yml".format(PLAYBOOKS_DIR)
TEST_PLAYBOOK_REGEX = "{}.*playbook-.*.yml".format(TEST_PLAYBOOKS_DIR)
SCRIPT_REGEX = "{}.*script-.*.yml".format(SCRIPTS_DIR)
WIDGETS_REGEX = "{}.*widget-.*.json".format(WIDGETS_DIR)
DASHBOARD_REGEX = "{}.*dashboard-.*.json".format(DASHBOARDS_DIR)
CONNECTIONS_REGEX = "{}.*canvas-context-connections.*.json".format(CONNECTIONS_DIR)
CLASSIFIER_REGEX = "{}.*classifier-.*.json".format(CLASSIFIERS_DIR)
LAYOUT_REGEX = "{}.*layout-.*.json".format(LAYOUTS_DIR)
INCIDENT_FIELDS_REGEX = "{}.*incidentfields.*.json".format(INCIDENT_FIELDS_DIR)
MISC_REGEX = "{}.*reputations.*.json".format(MISC_DIR)
REPORT_REGEX = "{}.*report-.*.json".format(REPORTS_DIR)

CHECKED_TYPES_REGEXES = [INTEGRATION_REGEX, PLAYBOOK_REGEX, SCRIPT_REGEX, WIDGETS_REGEX, DASHBOARD_REGEX, CONNECTIONS_REGEX,
                 CLASSIFIER_REGEX, LAYOUT_REGEX, INCIDENT_FIELDS_REGEX, MISC_REGEX, REPORT_REGEX]

SKIPPED_SCHEMAS = [MISC_REGEX, REPORT_REGEX]

KNOWN_FILE_STATUSES = ['a', 'm', 'd']

REGEXES_TO_SCHEMA_DIC={INTEGRATION_REGEX: "integration", PLAYBOOK_REGEX: "playbook", TEST_PLAYBOOK_REGEX:"test-playbook",
             SCRIPT_REGEX: "script", WIDGETS_REGEX: "widget", DASHBOARD_REGEX:"dashboard", CONNECTIONS_REGEX: "canvas-context-connections",
             CLASSIFIER_REGEX: "classifier", LAYOUT_REGEX:"layout", INCIDENT_FIELDS_REGEX:"incidentfields"}

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
    for regex in CHECKED_TYPES_REGEXES:
        if re.match(regex, file_path, re.IGNORECASE):
            return True
    return False


def get_modified_files(files_string):
    all_files = files_string.split('\n')
    added_files_list = set([])
    modified_files_list = set([])
    for f in all_files:
        file_data = f.split()
        if not file_data:
            continue

        file_status = file_data[0]
        file_path = file_data[1]

        if file_status.lower() == 'm' and checked_type(file_path) and not file_path.startswith('.'):
            modified_files_list.add(file_path)
        if file_status.lower() == 'a' and checked_type(file_path) and not file_path.startswith('.'):
            added_files_list.add(file_path)
        if file_status.lower() not in KNOWN_FILE_STATUSES:
            print_error(file_path + " file status is an unknown known one, please check. File status was: " + file_status)

    return modified_files_list, added_files_list


def validate_file_release_notes(file_path):
    data_dictionary = None
    if re.match(TEST_PLAYBOOK_REGEX, file_path, re.IGNORECASE):
        return True # Test playbooks don't need releaseNotes

    if os.path.isfile(file_path):
        with open(os.path.expanduser(file_path), "r") as f:
            if file_path.endswith(".json"):
                data_dictionary = json.load(f)
            elif file_path.endswith(".yaml") or file_path.endswith('.yml'):
                try:
                    data_dictionary = yaml.safe_load(f)
                except Exception as e:
                    print_error(file_path + " has yml structure issue. Error was: " + str(e))
                    return False

        if data_dictionary and data_dictionary.get('releaseNotes') is None:
            print_error("File " + file_path + " is missing releaseNotes, please add.")
            return False

    return True

def validate_schema(file_path, matching_regex=None):
    if matching_regex is None:
        for regex in CHECKED_TYPES_REGEXES:
            if re.match(regex, file_path, re.IGNORECASE):
                matching_regex = regex
                break

    if matching_regex in SKIPPED_SCHEMAS:
        return True

    if not os.path.isfile(file_path):
        return True

    if matching_regex is not None and REGEXES_TO_SCHEMA_DIC.get(matching_regex):
        c = Core(source_file=file_path, schema_files=[SCHEMAS_PATH + REGEXES_TO_SCHEMA_DIC.get(matching_regex) + '.yml'])
        try:
            c.validate(raise_exception=True)
            return True
        except Exception as err:
            print_error('Failed: %s failed' % (file_path,))
            print_error(err)
            return False

    print file_path + " doesn't match any of the known supported file prefix/suffix, please make sure that its naming is correct."
    return True


def changed_id(file_path):
    change_string = run_git_command("git diff HEAD {0}".format(file_path))
    if re.search("[+-](  )?id: .*", change_string):
        print_error("You've changed the ID of the file {0} please undo.".format(file_path))
        return True

    return False


def is_added_required_fields(file_path):
    change_string = run_git_command("git diff HEAD {0}".format(file_path))
    if re.search("\+  name: .*\n.*\n.*\n   required: true", change_string) or re.search("\-  name: .*\n.*\n.*\n-  required: true", change_string) or re.search("\+  required: true", change_string):
        print_error("You've changed the required fields in the integration file {}".format(file_path))
        return True

    return False


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


def collect_ids(file_path):
    """Collect id mentioned in file_path"""
    data_dictionary = get_json(file_path)

    if data_dictionary:
        return data_dictionary.get('id', '-')


def is_test_in_conf_json(file_path):
    file_id = collect_ids(file_path)

    with open("./Tests/conf.json") as data_file:
        conf = json.load(data_file)

    conf_tests = conf['tests']
    for test in conf_tests:
        playbook_id = test['playbookID']
        if file_id == playbook_id:
            return True

    return False


def oversize_image(file_path):
    data_dictionary = get_json(file_path)
    image = data_dictionary.get('image', '')
    if image == '':
        return False

    if ((len(image) - 22) / 4.0) * 3 > IMAGE_MAX_SIZE:
         print_error("{} has too large logo, please update the logo to be under 10kB".format(file_path))
         return True

    return False


def has_duplicated_ids(id_to_file):
    has_duplicate = False
    with open('./Tests/id_set.json', 'r') as id_set_file:
        id_list = json.load(id_set_file)

    for id in id_to_file.keys():
        if id in id_list:
            print_error("The ID {0} already exists, please update the file {1}".format(id, id_to_file[id]))
            has_duplicate = True

    return has_duplicate


def validate_committed_files(branch_name):
    files_string = run_git_command("git diff --name-status --no-merges HEAD")
    modified_files, added_files = get_modified_files(files_string)
    has_schema_problem = False
    for file_path in modified_files:
        if re.match(PLAYBOOK_REGEX, file_path, re.IGNORECASE) or re.match(SCRIPT_REGEX, file_path, re.IGNORECASE) or re.match(TEST_PLAYBOOK_REGEX, file_path, re.IGNORECASE):
            if changed_id(file_path):
                has_schema_problem = True
        if re.match(INTEGRATION_REGEX, file_path, re.IGNORECASE):
            if changed_id(file_path):
                has_schema_problem = True
            if oversize_image(file_path):
                has_schema_problem = True
            if is_added_required_fields(file_path):
                has_schema_problem = True

        print "Validating {}".format(file_path)
        if not validate_file_release_notes(file_path):
            has_schema_problem = True

        if not validate_schema(file_path):
            has_schema_problem = True

    id_to_file = {}
    for file_path in added_files:
        print "Validating {}".format(file_path)
        if not validate_schema(file_path):
            has_schema_problem = True

        if re.match(TEST_PLAYBOOK_REGEX, file_path, re.IGNORECASE):
            if not is_test_in_conf_json(file_path):
                has_schema_problem = True
                print_error("You've failed to add the {0} to conf.json".format(file_path))

        if re.match(SCRIPT_REGEX, file_path, re.IGNORECASE) or re.match(INTEGRATION_REGEX, file_path, re.IGNORECASE):
            id_to_file[get_script_or_integration_id(file_path)] = file_path
        elif re.match(PLAYBOOK_REGEX, file_path, re.IGNORECASE) or re.match(TEST_PLAYBOOK_REGEX, file_path, re.IGNORECASE):
            id_to_file[collect_ids(file_path)] = file_path

    if has_schema_problem or has_duplicated_ids(id_to_file):
        sys.exit(1)


def validate_all_files():
    id_list = []
    found_wrong_name = False
    duplicated_id = False
    wrong_schema = False

    for regex in CHECKED_TYPES_REGEXES:
        splitted_regex = regex.split(".*")
        directory = splitted_regex[0]
        prefix = splitted_regex[1]
        suffix = splitted_regex[2]
        for root, dirs, files in os.walk(directory):
            print_color("Validating {} directory:".format(directory), LOG_COLORS.GREEN)
            for file_name in files:
                file_path = os.path.join(root, file_name)
                # skipping hidden files
                if file_name.startswith('.'):
                    continue
                print "Validating " + file_name
                if not file_name.lower().endswith(suffix):
                     print_error("file " + file_path + " should end with " + suffix)
                     found_wrong_name = True
                if not file_name.lower().startswith(prefix):
                     print_error("file " + file_path + " should start with " + prefix)
                     found_wrong_name = True
                if not validate_schema(file_path, regex):
                    print_error("file " + file_path + " schema is wrong.")
                    wrong_schema = True
                if re.match(SCRIPT_REGEX, file_path, re.IGNORECASE) or re.match(INTEGRATION_REGEX, file_path, re.IGNORECASE):
                    _id = get_script_or_integration_id(file_path)
                    if _id in id_list:
                        print_error("ID {0} has appeared more than once, look at the file {1}".format(_id, file_path))
                        duplicated_id = True
                if re.match(PLAYBOOK_REGEX, file_path, re.IGNORECASE) or re.match(TEST_PLAYBOOK_REGEX, file_path, re.IGNORECASE):
                    _id = collect_ids(file_path)
                    if _id in id_list:
                        print_error("ID {0} has appeared more than once, look at the file {1}".format(_id, file_path))
                        duplicated_id = True

    if wrong_schema or found_wrong_name or duplicated_id:
        sys.exit(1)


def validate_conf_json():
    with open("./Tests/conf.json") as data_file:
        conf = json.load(data_file)

    skipped_tests_conf = conf['skipped_tests']
    skipped_integrations_conf = conf['skipped_integrations']

    problemtic_tests = []
    problemtic_integrations = []

    for test, description in skipped_tests_conf.items():
        if description == "":
            problemtic_tests.append(test)

    for integration, description in skipped_integrations_conf.items():
        if description == "":
            problemtic_integrations.append(integration)

    if problemtic_tests:
        print("Those tests don't have description:\n{0}".format('\n'.join(problemtic_tests)))

    if problemtic_integrations:
        print("Those integrations don't have description:\n{0}".format('\n'.join(problemtic_integrations)))

    if problemtic_integrations or problemtic_tests:
        sys.exit(1)


def main():
    '''
    This script runs both in a local and a remote environment. In a local environment we don't have any
    logger assigned, and then pykwalify raises an error, since it is logging the validation results.
    Therefore, if we are in a local env, we set up a logger. Also, we set the logger's level to critical
    so the user won't be disturbed by non critical loggings
    '''
    branches = run_git_command("git branch")
    branch_name_reg = re.search("\* (.*)", branches)
    branch_name = branch_name_reg.group(1)

    print_color("Starting validating files structure", LOG_COLORS.GREEN)
    validate_conf_json()
    if branch_name != 'master':
        import logging
        logging.basicConfig(level=logging.CRITICAL)

        # validates only committed files
        validate_committed_files(branch_name)
    else:
        # validates all of Content repo directories according to their schemas
        validate_all_files()
    print_color("Finished validating files structure", LOG_COLORS.GREEN)
    sys.exit(0)


if __name__ == "__main__":
    main()