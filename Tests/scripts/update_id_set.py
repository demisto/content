import re
import os
import sys
import glob
import json
import yaml
from subprocess import Popen, PIPE


SCRIPT_REGEX = "scripts.*script-.*.yml"
PLAYBOOK_REGEX = "(?!Test)playbooks.*playbook-.*.yml"
INTEGRATION_REGEX = "integrations.*integration-.*.yml"
TEST_PLAYBOOK_REGEX = "TestPlaybooks.*playbook-.*.yml"

CHECKED_TYPES_REGEXES = [INTEGRATION_REGEX, PLAYBOOK_REGEX, SCRIPT_REGEX, TEST_PLAYBOOK_REGEX]


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


def get_added_files(files_string):
    all_files = files_string.split('\n')
    added_files_list = set([])
    for f in all_files:
        file_data = f.split()
        if not file_data:
            continue

        file_status = file_data[0]
        file_path = file_data[1]

        if file_status.lower() == 'a' and checked_type(file_path) and not file_path.startswith('.'):
            added_files_list.add(file_path)

    return added_files_list


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


def get_script_or_integration_id(file_path):
    data_dictionary = get_json(file_path)

    if data_dictionary:
        commonfields = data_dictionary.get('commonfields', {})
        return commonfields.get('id', '-')


def get_from_version(file_path):
    data_dictionary = get_json(file_path)

    if data_dictionary:
        return data_dictionary.get('fromversion', '0')


def get_to_version(file_path):
    data_dictionary = get_json(file_path)

    if data_dictionary:
        return data_dictionary.get('toversion', '99.99.99')


def re_create_id_set():
    id_list = []
    for file in glob.glob(os.path.join('Integrations', '*')):
        id = get_script_or_integration_id(file)
        versioning = {
            "fromversion": get_from_version(file),
            "toversion": get_to_version(file)
        }
        id_dict = {
            id: versioning
        }
        id_list.append(id_dict)

    for file in glob.glob(os.path.join('Playbooks', '*')):
        id = collect_ids(file)
        versioning = {
            "fromversion": get_from_version(file),
            "toversion": get_to_version(file)
        }
        id_dict = {
            id: versioning
        }
        id_list.append(id_dict)

    for file in glob.glob(os.path.join('Scripts', '*')):
        id = get_script_or_integration_id(file)
        versioning = {
            "fromversion": get_from_version(file),
            "toversion": get_to_version(file)
        }
        id_dict = {
            id: versioning
        }
        id_list.append(id_dict)

    with open('./Tests/id_set.json', 'w') as id_set_file:
        json.dump(id_list, id_set_file, indent=4)


def update_id_set(git_sha):
    branches = run_git_command("git branch")
    branch_name_reg = re.search("\* (.*)", branches)
    branch_name = branch_name_reg.group(1)

    print("Getting added files")
    files_string = run_git_command("git diff --name-status {}".format(git_sha))
    second_files_string = run_git_command("git diff --name-status origin/master...{}".format(branch_name))
    added_files = get_added_files(files_string + '\n' + second_files_string)

    if added_files:
        print("Updating id_set.json")

        with open('./Tests/id_set.json', 'r') as id_set_file:
            id_list = json.load(id_set_file)

        for file_path in added_files:
            if re.match(SCRIPT_REGEX, file_path, re.IGNORECASE) or re.match(INTEGRATION_REGEX, file_path, re.IGNORECASE):
                id = get_script_or_integration_id(file_path)
                versioning = {
                    "fromversion": get_from_version(file_path),
                    "toversion": get_to_version(file_path)
                }
                id_dict = {
                    id: versioning
                }
                id_list.append(id_dict)
                print("Adding {0} to id_set".format(id))
            if re.match(PLAYBOOK_REGEX, file_path, re.IGNORECASE) or re.match(TEST_PLAYBOOK_REGEX, file_path, re.IGNORECASE):
                id = collect_ids(file_path)
                versioning = {
                    "fromversion": get_from_version(file_path),
                    "toversion": get_to_version(file_path)
                }
                id_dict = {
                    id: versioning
                }
                id_list.append(id_dict)
                print("Adding {0} to id_set".format(id))

        with open('./Tests/id_set.json', 'w') as id_set_file:
            json.dump(id_list, id_set_file, indent=4)

        print("Finished updating id_set.json")
