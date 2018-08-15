import pip

try:
    import yaml
except ImportError:
    pip.main(['install', 'pyyaml'])
    import yaml
import json
import sys
import re
from subprocess import Popen, PIPE

# file types regexes
INTEGRATION_REGEX = "(integration-).*(.yml)"
PLAYBOOK_REGEX = "^(?!testPlaybooks).*(playbook-).*(.yml)"
TEST_PLAYBOOK_REGEX = "^(testPlaybooks).*(playbook-).*(.yml)"
SCRIPT_REGEX = "(script-).*(.yml)"
WIDGETS_REGEX = "(widget-).*(.json)"
DASHBOARD_REGEX = "(dashboard-).*(.json)"
CONNECTIONS_REGEX = "(canvas-context-connections-).*(.json)"
CLASSIFIER_REGEX = "(classifier-).*(.json)"
LAYOUT_REGEX = "(layout-).*(.json)"
INCIDENT_FIELDS_REGEX = "(incidentfields-).*(.json)"
MISC_REGEX = "(reputations).*(.json)"
REPORT_REGEX = "(report-).*(.json)"

KNOWN_REGEXES = [INTEGRATION_REGEX, PLAYBOOK_REGEX, SCRIPT_REGEX, WIDGETS_REGEX, DASHBOARD_REGEX, CONNECTIONS_REGEX,
                 CLASSIFIER_REGEX, LAYOUT_REGEX, INCIDENT_FIELDS_REGEX, MISC_REGEX, REPORT_REGEX]

ACTIONABLE_FILE_STATUSES = ['M', 'R100', 'R094', 'R093', 'R098', 'R078']

def run_git_command(command):
    p = Popen(command.split(), stdout=PIPE, stderr=PIPE)
    p.wait()
    if p.returncode != 0:
        print "Failed to run git command " + command
        sys.exit(1)
    return p.stdout.read()


def known_filetype(file_path):
    for regex in KNOWN_REGEXES:
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
        if file_status in ACTIONABLE_FILE_STATUSES and not re.match(TEST_PLAYBOOK_REGEX, file_path, re.IGNORECASE) \
                and known_filetype(file_path):
            modified_files_list.append(file_path)

    return modified_files_list


def validate_file_release_notes(file_path):
    data_dictionary = None
    with open(file_path, "r") as f:
        if file_path.endswith(".json"):
            data_dictionary = json.load(f)
        elif file_path.endswith(".yaml") or file_path.endswith('.yml'):
            data_dictionary = yaml.safe_load(f)

    if data_dictionary and data_dictionary.get('releaseNotes') is None:
        print "File " + file_path + " is missing releaseNotes, please add."
        return False
    return True


def main():
    files_string = run_git_command("git diff-index --name-status --cached HEAD")
    modified_files = get_modified_files(files_string)
    missing_release_notes = False
    for f in modified_files:
        if not validate_file_release_notes(f):
            missing_release_notes = True

    if missing_release_notes:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
