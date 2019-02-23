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