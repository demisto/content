import re
import os
import sys
import glob
import json
import yaml
from subprocess import Popen, PIPE
from collections import OrderedDict


SCRIPT_YML_REGEX = "scripts.*.yml"
SCRIPT_PY_REGEX = "scripts.*.py"
SCRIPT_JS_REGEX = "scripts.*.js"
SCRIPT_REGEX = "scripts.*script-.*.yml"
INTEGRATION_YML_REGEX = "integrations.(?!integration)*.yml"
PLAYBOOK_REGEX = "(?!Test)playbooks.*playbook-.*.yml"
INTEGRATION_REGEX = "integrations.*integration-.*.yml"
TEST_PLAYBOOK_REGEX = "TestPlaybooks.*playbook-.*.yml"
TEST_SCRIPT_REGEX = "TestPlaybooks.*script-.*.yml"

CHECKED_TYPES_REGEXES = [INTEGRATION_REGEX, PLAYBOOK_REGEX, SCRIPT_REGEX,
                         TEST_PLAYBOOK_REGEX, INTEGRATION_YML_REGEX]

SCRIPTS_REGEX_LIST = [SCRIPT_YML_REGEX, SCRIPT_PY_REGEX, SCRIPT_JS_REGEX]

TYPE_TO_EXTENSION = {
    'python': '.py',
    'javascript': '.js'
}


class LOG_COLORS:
    NATIVE = '\033[m'
    RED = '\033[01;31m'
    GREEN = '\033[01;32m'


# print srt in the given color
def print_color(msg, color):
    print(str(color) + str(msg) + LOG_COLORS.NATIVE)


def print_error(error_str):
    print_color(error_str, LOG_COLORS.RED)


def run_git_command(command):
    p = Popen(command.split(), stdout=PIPE, stderr=PIPE)
    output, err = p.communicate()
    if err and 'CRLF will be replaced by LF' not in err:
        print_error("Failed to run git command " + command)
        sys.exit(1)
    return output


def checked_type(file_path, regex_list=CHECKED_TYPES_REGEXES):
    for regex in regex_list:
        if re.match(regex, file_path, re.IGNORECASE):
            return True
    return False


def get_changed_files(files_string):
    all_files = files_string.split('\n')
    added_files_list = set([])
    added_script_list = set([])
    modified_script_list = set([])
    modified_files_list = set([])
    for f in all_files:
        file_data = f.split()
        if not file_data:
            continue

        file_status = file_data[0]
        file_path = file_data[1]

        if file_status.lower() == 'a' and checked_type(file_path) and not file_path.startswith('.'):
            added_files_list.add(file_path)
        elif file_status.lower() == 'm' and checked_type(file_path) and not file_path.startswith('.'):
            modified_files_list.add(file_path)
        elif file_status.lower() == 'a' and checked_type(file_path, SCRIPTS_REGEX_LIST):
            added_script_list.add(os.path.dirname(file_path))
        elif file_status.lower() == 'm' and checked_type(file_path, SCRIPTS_REGEX_LIST):
            modified_script_list.add(os.path.dirname(file_path))

    return added_files_list, modified_files_list, added_script_list, modified_script_list


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
        return data_dictionary.get('fromversion', '0.0.0')


def get_to_version(file_path):
    data_dictionary = get_json(file_path)

    if data_dictionary:
        return data_dictionary.get('toversion', '99.99.99')


def get_integration_commands(file_path):
    cmd_list = []
    data_dictionary = get_json(file_path)
    commands = data_dictionary.get('script', {}).get('commands', [])
    for command in commands:
        cmd_list.append(command.get('name'))

    return cmd_list


def get_task_ids_from_playbook(param_to_enrich_by, data_dict):
    implementing_ids = set([])
    tasks = data_dict.get('tasks', {})

    for task in tasks.values():
        task_details = task.get('task', {})

        enriched_id = task_details.get(param_to_enrich_by)
        if enriched_id:
            implementing_ids.add(enriched_id)

    return list(implementing_ids)


def get_commmands_from_playbook(data_dict):
    command_to_integration = {}
    tasks = data_dict.get('tasks', [])

    for task in tasks.values():
        task_details = task.get('task', {})

        command = task_details.get('script')
        if command:
            splitted_cmd = command.split('|')

            if 'Builtin' not in command:
                command_to_integration[splitted_cmd[-1]] = splitted_cmd[0]

    return command_to_integration


def get_integration_data(file_path):
    integration_data = OrderedDict()
    data_dictionary = get_json(file_path)
    id = data_dictionary.get('commonfields', {}).get('id', '-')
    name = data_dictionary.get('name', '-')

    tests = data_dictionary.get('tests')
    toversion = data_dictionary.get('toversion')
    fromversion = data_dictionary.get('fromversion')
    commands = data_dictionary.get('script', {}).get('commands', [])
    cmd_list = [command.get('name') for command in commands]

    integration_data['name'] = name
    if toversion:
        integration_data['toversion'] = toversion
    if fromversion:
        integration_data['fromversion'] = fromversion
    if cmd_list:
        integration_data['commands'] = cmd_list
    if tests:
        integration_data['tests'] = tests

    return {id: integration_data}


def get_playbook_data(file_path):
    playbook_data = OrderedDict()
    data_dictionary = get_json(file_path)
    id = data_dictionary.get('id', '-')
    name = data_dictionary.get('name', '-')

    tests = data_dictionary.get('tests')
    toversion = data_dictionary.get('toversion')
    fromversion = data_dictionary.get('fromversion')
    implementing_scripts = get_task_ids_from_playbook('scriptName', data_dictionary)
    implementing_playbooks = get_task_ids_from_playbook('playbookName', data_dictionary)
    command_to_integration = get_commmands_from_playbook(data_dictionary)

    playbook_data['name'] = name
    if toversion:
        playbook_data['toversion'] = toversion
    if fromversion:
        playbook_data['fromversion'] = fromversion
    if implementing_scripts:
        playbook_data['implementing_scripts'] = implementing_scripts
    if implementing_playbooks:
        playbook_data['implementing_playbooks'] = implementing_playbooks
    if command_to_integration:
        playbook_data['command_to_integration'] = command_to_integration
    if tests:
        playbook_data['tests'] = tests

    return {id: playbook_data}


def get_script_data(file_path, script_code=None):
    script_data = OrderedDict()
    data_dictionary = get_json(file_path)
    id = data_dictionary.get('commonfields', {}).get('id', '-')
    if script_code is None:
        script_code = data_dictionary.get('script', '')

    name = data_dictionary.get('name', '-')

    tests = data_dictionary.get('tests')
    toversion = data_dictionary.get('toversion')
    deprecated = data_dictionary.get('deprecated')
    fromversion = data_dictionary.get('fromversion')
    depends_on, command_to_integration = get_depends_on(data_dictionary)
    script_executions = sorted(list(set(re.findall("demisto.executeCommand\(['\"](\w+)['\"].*", script_code))))

    script_data['name'] = name
    if toversion:
        script_data['toversion'] = toversion
    if fromversion:
        script_data['fromversion'] = fromversion
    if deprecated:
        script_data['deprecated'] = deprecated
    if depends_on:
        script_data['depends_on'] = depends_on
    if script_executions:
        script_data['script_executions'] = script_executions
    if command_to_integration:
        script_data['command_to_integration'] = command_to_integration
    if tests:
        script_data['tests'] = tests

    return {id: script_data}


def get_depends_on(data_dict):
    depends_on = data_dict.get('dependson', {}).get('must', [])
    depends_on_list = list(set([cmd.split('|')[-1] for cmd in depends_on]))
    command_to_integration = {}
    for cmd in depends_on:
        splitted_cmd = cmd.split('|')
        if splitted_cmd[0] and '|' in cmd:
            command_to_integration[splitted_cmd[-1]] = splitted_cmd[0]

    return depends_on_list, command_to_integration


def update_object_in_id_set(obj_id, obj_data, file_path, instances_set):
    change_string = run_git_command("git diff HEAD {0}".format(file_path))
    is_added_from_version = True if re.search('\+fromversion: .*', change_string) else False
    is_added_to_version = True if re.search('\+toversion: .*', change_string) else False

    file_to_version = get_to_version(file_path)
    file_from_version = get_from_version(file_path)

    for instance in instances_set:
        instance_id = instance.keys()[0]
        integration_to_version = instance[instance_id].get('toversion', '99.99.99')
        integration_from_version = instance[instance_id].get('fromversion', '0.0.0')
        if obj_id == instance_id:
            if is_added_from_version or (not is_added_from_version and file_from_version == integration_from_version):
                if is_added_to_version or (not is_added_to_version and file_to_version == integration_to_version):
                    instance[obj_id] = obj_data[obj_id]
                    break


def add_new_object_to_id_set(obj_id, obj_data, instances_set):
    obj_in_set = False

    dict_value = obj_data.values()[0]
    file_to_version = dict_value.get('toversion', '99.99.99')
    file_from_version = dict_value.get('fromversion', '0.0.0')

    for instance in instances_set:
        instance_id = instance.keys()[0]
        integration_to_version = instance[instance_id].get('toversion', '99.99.99')
        integration_from_version = instance[instance_id].get('fromversion', '0.0.0')
        if obj_id == instance_id and file_from_version == integration_from_version and \
                file_to_version == integration_to_version:
            instance[obj_id] = obj_data[obj_id]
            obj_in_set = True

    if not obj_in_set:
        instances_set.append(obj_data)


def get_script_package_data(package_path):
    yml_path = glob.glob(package_path + '*.yml')[0]
    code_type = get_json(yml_path).get('type')
    code_path = glob.glob(package_path + '*' + TYPE_TO_EXTENSION[code_type])[0]
    with open(code_path, 'r') as code_file:
        code = code_file.read()

    return yml_path, code


def re_create_id_set():
    scripts_list = []
    playbooks_list = []
    integration_list = []
    testplaybooks_list = []

    print_color("Starting the creation of the id_set", LOG_COLORS.GREEN)
    print_color("Starting iterating over Integrations", LOG_COLORS.GREEN)
    for file in glob.glob(os.path.join('Integrations', '*')):
        print("adding {0} to id_set".format(file))
        integration_list.append(get_integration_data(file))

    print_color("Starting iterating over Playbooks", LOG_COLORS.GREEN)
    for file in glob.glob(os.path.join('Playbooks', '*')):
        print("adding {0} to id_set".format(file))
        playbooks_list.append(get_playbook_data(file))

    print_color("Starting iterating over Scripts", LOG_COLORS.GREEN)
    for file in glob.glob(os.path.join('Scripts', '*')):
        print("adding {0} to id_set".format(file))
        scripts_list.append(get_script_data(file))

    print_color("Starting iterating over TestPlaybooks", LOG_COLORS.GREEN)
    for file in glob.glob(os.path.join('TestPlaybooks', '*')):
        print("adding {0}".format(file))
        if re.match(TEST_SCRIPT_REGEX, file, re.IGNORECASE):
            scripts_list.append(get_script_data(file))
        elif re.match(TEST_PLAYBOOK_REGEX, file, re.IGNORECASE):
            testplaybooks_list.append(get_playbook_data(file))

    ids_dict = OrderedDict()
    ids_dict['scripts'] = scripts_list
    ids_dict['playbooks'] = playbooks_list
    ids_dict['integrations'] = integration_list
    ids_dict['TestPlaybooks'] = testplaybooks_list

    print_color("Finished the creation of the id_set", LOG_COLORS.GREEN)
    with open('./Tests/id_set.json', 'w') as id_set_file:
        json.dump(ids_dict, id_set_file, indent=4)


def update_id_set():
    branches = run_git_command("git branch")
    branch_name_reg = re.search("\* (.*)", branches)
    branch_name = branch_name_reg.group(1)

    print("Getting added files")
    files_string = run_git_command("git diff --name-status HEAD")
    second_files_string = run_git_command("git diff --name-status origin/master...{}".format(branch_name))
    added_files, modified_files, added_scripts, modified_scripts = \
        get_changed_files(files_string + '\n' + second_files_string)

    if added_files or modified_files:
        print("Updating id_set.json")

        with open('./Tests/id_set.json', 'r') as id_set_file:
            ids_dict = json.load(id_set_file, object_pairs_hook=OrderedDict)

        test_playbook_set = ids_dict['TestPlaybooks']
        integration_set = ids_dict['integrations']
        playbook_set = ids_dict['playbooks']
        script_set = ids_dict['scripts']

    if added_files:
        for file_path in added_files:
            if re.match(INTEGRATION_REGEX, file_path, re.IGNORECASE) or \
                    re.match(INTEGRATION_YML_REGEX, file_path, re.IGNORECASE):
                add_new_object_to_id_set(get_script_or_integration_id(file_path), get_integration_data(file_path),
                                         integration_set)
                print("Adding {0} to id_set".format(get_script_or_integration_id(file_path)))
            if re.match(SCRIPT_REGEX, file_path, re.IGNORECASE):
                add_new_object_to_id_set(get_script_or_integration_id(file_path), get_script_data(file_path),
                                         script_set)
                print("Adding {0} to id_set".format(get_script_or_integration_id(file_path)))
            if re.match(PLAYBOOK_REGEX, file_path, re.IGNORECASE):
                add_new_object_to_id_set(collect_ids(file_path), get_playbook_data(file_path),
                                         playbook_set)
                print("Adding {0} to id_set".format(collect_ids(file_path)))
            if re.match(TEST_PLAYBOOK_REGEX, file_path, re.IGNORECASE):
                add_new_object_to_id_set(collect_ids(file_path), get_playbook_data(file_path),
                                         test_playbook_set)
                print("Adding {0} to id_set".format(collect_ids(file_path)))
            if re.match(TEST_SCRIPT_REGEX, file_path, re.IGNORECASE):
                add_new_object_to_id_set(get_script_or_integration_id(file_path), get_script_data(file_path),
                                         script_set)
                print("Adding {0} to id_set".format(collect_ids(file_path)))

    if modified_files:
        for file_path in modified_files:
            if re.match(INTEGRATION_REGEX, file_path, re.IGNORECASE) or \
                    re.match(INTEGRATION_YML_REGEX, file_path, re.IGNORECASE):
                id = get_script_or_integration_id(file_path)
                integration_data = get_integration_data(file_path)
                update_object_in_id_set(id, integration_data, file_path, integration_set)
                print("updated {0} in id_set".format(id))
            if re.match(SCRIPT_REGEX, file_path, re.IGNORECASE) or re.match(TEST_SCRIPT_REGEX,
                                                                            file_path, re.IGNORECASE):
                id = get_script_or_integration_id(file_path)
                script_data = get_script_data(file_path)
                update_object_in_id_set(id, script_data, file_path, script_set)
                print("updated {0} in id_set".format(id))
            if re.match(PLAYBOOK_REGEX, file_path, re.IGNORECASE):
                id = collect_ids(file_path)
                playbook_data = get_playbook_data(file_path)
                update_object_in_id_set(id, playbook_data, file_path, playbook_set)
                print("updated {0} in id_set".format(id))
            if re.match(TEST_PLAYBOOK_REGEX, file_path, re.IGNORECASE):
                id = collect_ids(file_path)
                playbook_data = get_playbook_data(file_path)
                update_object_in_id_set(id, playbook_data, file_path, test_playbook_set)
                print("updated {0} in id_set".format(id))

    if added_scripts:
        for added_script_package in added_scripts:
            yml_path, code = get_script_package_data(added_script_package)
            add_new_object_to_id_set(get_script_or_integration_id(yml_path),
                                     get_script_data(yml_path, script_code=code), script_set)
            print("Adding {0} to id_set".format(get_script_or_integration_id(yml_path)))

    if modified_scripts:
        for modified_script_package in added_scripts:
            yml_path, code = get_script_package_data(modified_script_package)
            update_object_in_id_set(get_script_or_integration_id(yml_path),
                                    get_script_data(yml_path, script_code=code), yml_path, script_set)
            print("Adding {0} to id_set".format(get_script_or_integration_id(yml_path)))

    if added_files or modified_files:
        new_ids_dict = OrderedDict()
        new_ids_dict['scripts'] = script_set
        new_ids_dict['playbooks'] = playbook_set
        new_ids_dict['integrations'] = integration_set
        new_ids_dict['TestPlaybooks'] = test_playbook_set

        with open('./Tests/id_set.json', 'w') as id_set_file:
            json.dump(new_ids_dict, id_set_file, indent=4)

    print("Finished updating id_set.json")


if __name__ == '__main__':
    update_id_set()
