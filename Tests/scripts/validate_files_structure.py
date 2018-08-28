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
import json
import re
import os
from subprocess import Popen, PIPE
from pykwalify.core import Core

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
    modified_files_list = []
    for f in all_files:
        file_data = f.split()
        if not file_data:
            continue
        file_status = file_data[0]
        file_path = file_data[1]
        if file_status.lower() == 'm' and checked_type(file_path) and not file_path.startswith('.'):
            modified_files_list.append(file_path)
        if file_status.lower() not in KNOWN_FILE_STATUSES:
            print_error(file_path + " file status is an unknown known one, please check. File status was: " + file_status)
    return modified_files_list


def validate_file_release_notes(file_path):
    data_dictionary = None
    if re.match(TEST_PLAYBOOK_REGEX, file_path, re.IGNORECASE):
        return True # Test playbooks don't need releaseNotes
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

def validate_committed_files():
    files_string = run_git_command("git diff-index --name-status --cached HEAD")
    modified_files = get_modified_files(files_string)
    missing_release_notes = False
    wrong_schema = False
    for file_path in modified_files:
        print "Validating {}".format(file_path)
        if not validate_file_release_notes(file_path):
            missing_release_notes = True

        if not validate_schema(file_path):
            wrong_schema = True

    if missing_release_notes or wrong_schema:
        sys.exit(1)

def validate_all_files():
    found_wrong_name = False
    wrong_schema = False

    for regex in CHECKED_TYPES_REGEXES:
        splitted_regex = regex.split(".*")
        directory = splitted_regex[0]
        prefix = splitted_regex[1]
        suffix = splitted_regex[2]
        for root, dirs, files in os.walk(directory):
            print_color("Validating {} directory:".format(directory), LOG_COLORS.GREEN)
            for file_name in files:
                # skipping hidden files
                if file_name.startswith('.'):
                    continue
                print "Validating " + file_name
                if not file_name.lower().endswith(suffix):
                     print_error("file " + os.path.join(root, file_name) + " should end with " + suffix)
                     found_wrong_name = True
                if not file_name.lower().startswith(prefix):
                     print_error("file " + os.path.join(root, file_name) + " should start with " + prefix)
                     found_wrong_name = True
                if not validate_schema(os.path.join(root, file_name), regex):
                    print_error("file " + os.path.join(root, file_name) + " schema is wrong.")
                    wrong_schema = True
 
    if wrong_schema or found_wrong_name:
        sys.exit(1)    

def main(argv):
    ''' 
    This script runs both in a local and a remote environment. In a local environment we don't have any 
    logger assigned, and then pykwalify raises an error, since it is logging the validation results.
    Therefore, if we are in a local env, we set up a logger. Also, we set the logger's level to critical
    so the user won't be disturbed by non critical loggings
    '''
    only_committed_files = False
    if len(argv) > 0:
        only_committed_files = argv[0] and (argv[0] == True or argv[0].lower() == 'true')

    print_color("Starting validating files structure", LOG_COLORS.GREEN)
    if only_committed_files:
        import logging
        logging.basicConfig(level=logging.CRITICAL)

        # validates only committed files
        validate_committed_files()
    else:
        # validates all of Content repo directories according to their schemas
        validate_all_files()
    print_color("Finished validating files structure", LOG_COLORS.GREEN)
    sys.exit(0)


if __name__ == "__main__":
   main(sys.argv[1:])
