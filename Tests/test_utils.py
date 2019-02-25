import re
import os
import sys
import yaml
import argparse
from subprocess import Popen, PIPE


CONTENT_GIT_HUB_LINK = "https://raw.githubusercontent.com/demisto/content/master/"

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
IMAGE_REGEX = r".*\.png"
SCRIPT_YML_REGEX = r"{}.*\.yml".format(SCRIPTS_DIR)
SCRIPT_PY_REGEX = r"{}.*\.py".format(SCRIPTS_DIR)
SCRIPT_JS_REGEX = r"{}.*\.js".format(SCRIPTS_DIR)
INTEGRATION_YML_REGEX = r"{}.*\.yml".format(INTEGRATIONS_DIR)
INTEGRATION_REGEX = r"{}.*integration-.*\.yml".format(INTEGRATIONS_DIR)
PLAYBOOK_REGEX = r"{}.*playbook-.*\.yml".format(PLAYBOOKS_DIR)
TEST_SCRIPT_REGEX = r"{}.*script-.*\.yml".format(TEST_PLAYBOOKS_DIR)
TEST_PLAYBOOK_REGEX = r"{}.*playbook-.*\.yml".format(TEST_PLAYBOOKS_DIR)
SCRIPT_REGEX = r"{}.*script-.*\.yml".format(SCRIPTS_DIR)
WIDGETS_REGEX = r"{}.*widget-.*\.json".format(WIDGETS_DIR)
DASHBOARD_REGEX = r"{}.*dashboard-.*\.json".format(DASHBOARDS_DIR)
CONNECTIONS_REGEX = r"{}.*canvas-context-connections.*\.json".format(CONNECTIONS_DIR)
CLASSIFIER_REGEX = r"{}.*classifier-.*\.json".format(CLASSIFIERS_DIR)
LAYOUT_REGEX = r"{}.*layout-.*\.json".format(LAYOUTS_DIR)
INCIDENT_FIELDS_REGEX = r"{}.*incidentfields.*\.json".format(INCIDENT_FIELDS_DIR)
INCIDENT_FIELD_REGEX = r"{}.*incidentfield-.*\.json".format(INCIDENT_FIELDS_DIR)
MISC_REGEX = r"{}.*reputations.*\.json".format(MISC_DIR)
REPORT_REGEX = r"{}.*report-.*\.json".format(REPORTS_DIR)

CHECKED_TYPES_REGEXES = [INTEGRATION_REGEX, PLAYBOOK_REGEX, SCRIPT_REGEX, INTEGRATION_YML_REGEX,
                         WIDGETS_REGEX, DASHBOARD_REGEX, CONNECTIONS_REGEX, CLASSIFIER_REGEX, SCRIPT_YML_REGEX,
                         LAYOUT_REGEX, INCIDENT_FIELDS_REGEX, INCIDENT_FIELD_REGEX, MISC_REGEX, REPORT_REGEX]

KNOWN_FILE_STATUSES = ['a', 'm', 'd', 'r100']


class LOG_COLORS:
    NATIVE = '\033[m'
    RED = '\033[01;31m'
    GREEN = '\033[01;32m'
    YELLOW = '\033[0;33m'


# print srt in the given color
def print_color(str, color):
    print(color + str + LOG_COLORS.NATIVE)


def print_error(error_str):
    print_color(error_str, LOG_COLORS.RED)


def print_warning(warning_str):
    print_color(warning_str, LOG_COLORS.YELLOW)


def run_git_command(command):
    p = Popen(command.split(), stdout=PIPE, stderr=PIPE)
    output, err = p.communicate()
    if err:
        print_error("Failed to run git command " + command)
        sys.exit(1)
    return output


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


def get_script_or_integration_id(file_path):
    data_dictionary = get_json(file_path)

    if data_dictionary:
        commonfields = data_dictionary.get('commonfields', {})
        return commonfields.get('id', ['-', ])


def collect_ids(file_path):
    """Collect id mentioned in file_path"""
    data_dictionary = get_json(file_path)

    if data_dictionary:
        return data_dictionary.get('id', '-')


def get_from_version(file_path):
    data_dictionary = get_json(file_path)

    if data_dictionary:
        from_version = data_dictionary.get('fromversion', '0.0.0')
        if from_version == "":
            return "0.0.0"

        if not re.match(r"^\d{1,2}\.\d{1,2}\.\d{1,2}$", from_version):
            raise ValueError("{} fromversion is invalid \"{}\". "
                             "Should be of format: 4.0.0 or 4.5.0".format(file_path, from_version))

        return from_version


def get_to_version(file_path):
    data_dictionary = get_json(file_path)

    if data_dictionary:
        to_version = data_dictionary.get('fromversion', '99.99.99')
        if not re.match(r"^\d{1,2}\.\d{1,2}\.\d{1,2}$", to_version):
            raise ValueError("{} toversion is invalid \"{}\". "
                             "Should be of format: 4.0.0 or 4.5.0".format(file_path, to_version))

        return to_version


def str2bool(v):
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


def checked_type(file_path):
    for regex in CHECKED_TYPES_REGEXES:
        if re.match(regex, file_path, re.IGNORECASE):
            return True
    return False


def get_modified_files(files_string):
    all_files = files_string.split('\n')
    deleted_files = set([])
    added_files_list = set([])
    modified_files_list = set([])
    for f in all_files:
        file_data = f.split()
        if not file_data:
            continue

        file_status = file_data[0]
        file_path = file_data[1]

        if file_path.endswith('.js') or file_path.endswith('.py'):
            continue
        if file_status.lower() == 'm' and checked_type(file_path) and not file_path.startswith('.'):
            modified_files_list.add(file_path)
        elif file_status.lower() == 'a' and checked_type(file_path) and not file_path.startswith('.'):
            added_files_list.add(file_path)
        elif file_status.lower() == 'd' and checked_type(file_path) and not file_path.startswith('.'):
            deleted_files.add(file_path)
        elif file_status.lower() == 'r100' and checked_type(file_path):
            modified_files_list.add(file_data[2])
        elif file_status.lower() not in KNOWN_FILE_STATUSES:
            print_error(file_path + " file status is an unknown known one, "
                                    "please check. File status was: " + file_status)

    return modified_files_list, added_files_list, deleted_files


def get_modified_and_added_files(branch_name, is_circle):
    all_changed_files_string = run_git_command("git diff --name-status origin/master...{}".format(branch_name))
    modified_files, added_files, _ = get_modified_files(all_changed_files_string)

    if not is_circle:
        files_string = run_git_command("git diff --name-status --no-merges HEAD")

        non_committed_modified_files, non_committed_added_files, non_committed_deleted_files = \
            get_modified_files(files_string)
        all_changed_files_string = run_git_command("git diff --name-status origin/master")
        modified_files_from_master, added_files_from_master, _ = get_modified_files(all_changed_files_string)

        for mod_file in modified_files_from_master:
            if mod_file in non_committed_modified_files:
                modified_files.add(mod_file)

        for add_file in added_files_from_master:
            if add_file in non_committed_added_files:
                added_files.add(add_file)

        for deleted_file in non_committed_deleted_files:
            modified_files = modified_files - {deleted_file}
            added_files = added_files - {deleted_file}

        for non_commited_mod_file in non_committed_modified_files:
            added_files = added_files - {non_commited_mod_file}

        new_added_files = set([])
        for added_file in added_files:
            if added_file in non_committed_added_files:
                new_added_files.add(added_file)

        added_files = new_added_files

    return modified_files, added_files
