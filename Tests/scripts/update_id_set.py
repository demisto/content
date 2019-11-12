
# !/usr/bin/env python
import itertools
import re
import os
import glob
import json
import argparse
from collections import OrderedDict
from multiprocessing import Pool, cpu_count
from distutils.version import LooseVersion
import time
import sys


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONTENT_DIR = os.path.abspath(SCRIPT_DIR + '/../..')
sys.path.append(CONTENT_DIR)

from Tests.scripts.constants import *  # noqa: E402
from Tests.test_utils import get_yaml, get_to_version, get_from_version, collect_ids, get_script_or_integration_id, \
    LOG_COLORS, print_color, run_command, print_error, print_warning  # noqa: E402


CHECKED_TYPES_REGEXES = (
    # Integrations
    INTEGRATION_REGEX,
    INTEGRATION_YML_REGEX,
    PACKS_INTEGRATION_YML_REGEX,
    PACKS_INTEGRATION_REGEX,
    # Scripts
    SCRIPT_REGEX,
    PACKS_SCRIPT_YML_REGEX,
    # Playbooks
    PLAYBOOK_REGEX,
    TEST_PLAYBOOK_REGEX,
    PACKS_PLAYBOOK_YML_REGEX,
    PACKS_TEST_PLAYBOOKS_REGEX
)


def checked_type(file_path, regex_list=CHECKED_TYPES_REGEXES):
    for regex in regex_list:
        if re.match(regex, file_path, re.IGNORECASE):
            return True
    return False


def get_changed_files(files_string):
    all_files = files_string.split('\n')
    deleted_files = set([])
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
            added_script_list.add(os.path.join(os.path.dirname(file_path), ''))
        elif file_status.lower() == 'm' and checked_type(file_path, SCRIPTS_REGEX_LIST):
            modified_script_list.add(os.path.join(os.path.dirname(file_path), ''))
        elif file_status.lower() == 'd' and checked_type(file_path, SCRIPTS_REGEX_LIST):
            deleted_files.add(os.path.join(os.path.dirname(file_path), ''))
        elif file_status.lower() == 'd' and checked_type(file_path):
            deleted_files.add(file_path)

    for deleted_file in deleted_files:
        added_files_list = added_files_list - {deleted_file}
        modified_files_list = modified_files_list - {deleted_file}
        added_script_list = added_script_list - {deleted_file}
        modified_script_list = modified_script_list - {deleted_file}

    return added_files_list, modified_files_list, added_script_list, modified_script_list


def get_integration_commands(file_path):
    cmd_list = []
    data_dictionary = get_yaml(file_path)
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
    data_dictionary = get_yaml(file_path)
    id = data_dictionary.get('commonfields', {}).get('id', '-')
    name = data_dictionary.get('name', '-')

    tests = data_dictionary.get('tests')
    toversion = data_dictionary.get('toversion')
    fromversion = data_dictionary.get('fromversion')
    commands = data_dictionary.get('script', {}).get('commands', [])
    cmd_list = [command.get('name') for command in commands]

    integration_data['name'] = name
    integration_data['file_path'] = file_path
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
    data_dictionary = get_yaml(file_path)
    id = data_dictionary.get('id', '-')
    name = data_dictionary.get('name', '-')

    tests = data_dictionary.get('tests')
    toversion = data_dictionary.get('toversion')
    fromversion = data_dictionary.get('fromversion')
    implementing_scripts = get_task_ids_from_playbook('scriptName', data_dictionary)
    implementing_playbooks = get_task_ids_from_playbook('playbookName', data_dictionary)
    command_to_integration = get_commmands_from_playbook(data_dictionary)

    playbook_data['name'] = name
    playbook_data['file_path'] = file_path
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
    data_dictionary = get_yaml(file_path)
    id = data_dictionary.get('commonfields', {}).get('id', '-')
    if script_code is None:
        script_code = data_dictionary.get('script', '')

    name = data_dictionary.get('name', '-')

    tests = data_dictionary.get('tests')
    toversion = data_dictionary.get('toversion')
    deprecated = data_dictionary.get('deprecated')
    fromversion = data_dictionary.get('fromversion')
    depends_on, command_to_integration = get_depends_on(data_dictionary)
    script_executions = sorted(list(set(re.findall(r"demisto.executeCommand\(['\"](\w+)['\"].*", script_code))))

    script_data['name'] = name
    script_data['file_path'] = file_path
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
    change_string = run_command("git diff HEAD {0}".format(file_path))
    is_added_from_version = True if re.search(r'\+fromversion: .*', change_string) else False
    is_added_to_version = True if re.search(r'\+toversion: .*', change_string) else False

    file_to_version = get_to_version(file_path)
    file_from_version = get_from_version(file_path)

    updated = False
    for instance in instances_set:
        instance_id = instance.keys()[0]
        integration_to_version = instance[instance_id].get('toversion', '99.99.99')
        integration_from_version = instance[instance_id].get('fromversion', '0.0.0')

        if obj_id == instance_id:
            if is_added_from_version or (not is_added_from_version and file_from_version == integration_from_version):
                if is_added_to_version or (not is_added_to_version and file_to_version == integration_to_version):
                    instance[obj_id] = obj_data[obj_id]
                    updated = True
                    break

    if not updated:
        # in case we didn't found then we need to create one
        add_new_object_to_id_set(obj_id, obj_data, instances_set)


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


def get_code_file(package_path, script_type):
    """Return the first code file in the specified directory path
    TODO: COPIED from: package_creator.py. Need to refactor to use shared code

    :param package_path: directory to search for code file
    :type package_path: str
    :param script_type: script type: .py or .js
    :type script_type: str
    :return: path to found code file
    :rtype: str
    """

    ignore_regex = r'^CommonServerPython\.py|^CommonServerUserPython\.py|demistomock\.py|test_.*\.py|_test\.py'
    script_path = list(filter(lambda x: not re.search(ignore_regex, x),
                              glob.glob(package_path + '*' + script_type)))[0]
    return script_path


def get_script_package_data(package_path):
    if package_path[-1] != os.sep:
        package_path = os.path.join(package_path, '')
    yml_files = glob.glob(package_path + '*.yml')
    if not yml_files:
        raise Exception("No yml files found in package path: {}. "
                        "Is this really a package dir? If not remove it.".format(package_path))
    yml_path = yml_files[0]
    code_type = get_yaml(yml_path).get('type')
    code_path = get_code_file(package_path, TYPE_TO_EXTENSION[code_type])
    with open(code_path, 'r') as code_file:
        code = code_file.read()

    return yml_path, code


def process_integration(file_path):
    """
    Process integration dir or file

    Arguments:
        file_path {string} -- file path to integration file

    Returns:
        list -- integration data list (may be empty)
    """
    res = []
    if os.path.isfile(file_path):
        if checked_type(file_path, (INTEGRATION_REGEX, BETA_INTEGRATION_REGEX, PACKS_INTEGRATION_REGEX)):
            print("adding {0} to id_set".format(file_path))
            res.append(get_integration_data(file_path))
    else:
        if os.path.isfile(file_path):
            if checked_type(file_path, PACKS_INTEGRATION_YML_REGEX):
                print("adding {0} to id_set".format(file_path))
                res.append(get_integration_data(file_path))
        else:
            for yml_file in glob.glob(os.path.join(file_path, os.path.basename(file_path) + '.yml')):
                print("adding {0} to id_set".format(yml_file))
                res.append(get_integration_data(yml_file))
    return res


def process_script(file_path):
    res = []
    if os.path.isfile(file_path):
        if checked_type(file_path, (SCRIPT_REGEX, PACKS_SCRIPT_YML_REGEX)):
            print("adding {0} to id_set".format(file_path))
            res.append(get_script_data(file_path))
    else:
        yml_path, code = get_script_package_data(file_path)
        print("adding {0} to id_set".format(file_path))
        res.append(get_script_data(yml_path, script_code=code))
    return res


def process_playbook(file_path):
    res = []
    if os.path.isfile(file_path):
        if checked_type(file_path, (PACKS_PLAYBOOK_YML_REGEX, PLAYBOOK_REGEX, BETA_PLAYBOOK_REGEX)):
            print('adding {0} to id_set'.format(file_path))
            res.append(get_playbook_data(file_path))
    else:
        for yml_file in glob.glob(os.path.join(file_path, '*.yml')):
            print("adding {0} to id_set".format(yml_file))
            res.append(get_playbook_data(yml_file))
    return res


def process_testplaybook_path(file_path):
    """
    Process a yml file in the testplyabook dir. Maybe either a script or playbook

    Arguments:
        file_path {string} -- path to yaml file

    Returns:
        pair -- first element is a playbook second is a script. each may be None
    """
    print("adding {0} to id_set".format(file_path))
    script = None
    playbook = None
    if checked_type(file_path, (TEST_SCRIPT_REGEX, PACKS_TEST_PLAYBOOKS_REGEX)):
        script = get_script_data(file_path)
    elif checked_type(file_path, (TEST_PLAYBOOK_REGEX, PACKS_TEST_PLAYBOOKS_REGEX)):
        playbook = get_playbook_data(file_path)

    return playbook, script


def get_integrations_paths():
    path_list = [
        ['Integrations', '*'],
        ['Beta_Integrations', '*'],
        ['Packs', '*', 'Integrations', '*']
    ]
    integration_files = list()
    for path in path_list:
        integration_files.extend(glob.glob(os.path.join(*path)))

    return integration_files


def get_scripts_paths():
    path_list = [
        ['Scripts', '*'],
        ['Packs', '*', 'Scripts', '*']
    ]
    script_files = list()
    for path in path_list:
        script_files.extend(glob.glob(os.path.join(*path)))

    return script_files


def get_playbooks_paths():
    path_list = [
        ['Playbooks', '*.yml'],
        ['Packs', '*', 'Playbooks', '*.yml'],
        ['Beta_Integrations', '*.yml']
    ]

    playbook_files = list()
    for path in path_list:
        playbook_files.extend(glob.glob(os.path.join(*path)))

    return playbook_files


def get_test_playbooks_paths():
    path_list = [
        ['TestPlaybooks', '*'],
        ['Packs', '*', 'TestPlaybooks', '*.yml']
    ]
    test_playbook_files = list()
    for path in path_list:
        test_playbook_files.extend(glob.glob(os.path.join(*path)))

    return test_playbook_files


def re_create_id_set():
    start_time = time.time()
    scripts_list = []
    playbooks_list = []
    integration_list = []
    testplaybooks_list = []

    pool = Pool(processes=cpu_count() * 2)

    print_color("Starting the creation of the id_set", LOG_COLORS.GREEN)
    print_color("Starting iterating over Integrations", LOG_COLORS.GREEN)
    for arr in pool.map(process_integration, get_integrations_paths()):
        integration_list.extend(arr)

    print_color("Starting iterating over Playbooks", LOG_COLORS.GREEN)
    for arr in pool.map(process_playbook, get_playbooks_paths()):
        playbooks_list.extend(arr)

    print_color("Starting iterating over Scripts", LOG_COLORS.GREEN)
    for arr in pool.map(process_script, get_scripts_paths()):
        scripts_list.extend(arr)

    print_color("Starting iterating over TestPlaybooks", LOG_COLORS.GREEN)
    for pair in pool.map(process_testplaybook_path, get_test_playbooks_paths()):
        if pair[0]:
            testplaybooks_list.append(pair[0])
        if pair[1]:
            scripts_list.append(pair[1])

    new_ids_dict = OrderedDict()
    # we sort each time the whole set in case someone manually changed something
    # it shouldn't take too much time
    new_ids_dict['scripts'] = sort(scripts_list)
    new_ids_dict['playbooks'] = sort(playbooks_list)
    new_ids_dict['integrations'] = sort(integration_list)
    new_ids_dict['TestPlaybooks'] = sort(testplaybooks_list)

    with open('./Tests/id_set.json', 'w') as id_set_file:
        json.dump(new_ids_dict, id_set_file, indent=4)
    exec_time = time.time() - start_time
    print_color("Finished the creation of the id_set. Total time: {} seconds".format(exec_time), LOG_COLORS.GREEN)

    duplicates = find_duplicates(new_ids_dict)
    if any(duplicates):
        print_error('The following duplicates were found: {}'.format(duplicates))


def find_duplicates(id_set):
    scripts = id_set['scripts']
    script_ids = set([script.keys()[0] for script in scripts])

    scripts_list = []
    for script_id in script_ids:
        if has_duplicate(scripts, script_id):
            scripts_list.append(script_id)

    integrations = id_set['integrations']
    integration_ids = set([integration.keys()[0] for integration in integrations])

    integration_list = []
    for integration_id in integration_ids:
        if has_duplicate(integrations, integration_id):
            integration_list.append(integration_id)

    playbooks = id_set['playbooks']
    playbook_ids = set([playbook.keys()[0] for playbook in playbooks])

    playbooks_list = []
    for playbook_id in playbook_ids:
        if has_duplicate(playbooks, playbook_id):
            integration_list.append(playbook_id)

    test_playbooks = id_set['TestPlaybooks']
    test_playbook_ids = set([test_playbook.keys()[0] for test_playbook in test_playbooks])

    test_playbooks_list = []
    for test_playbook_id in test_playbook_ids:
        if has_duplicate(test_playbooks, test_playbook_id):
            test_playbooks_list.append(test_playbook_id)

    return scripts_list, integration_list, playbooks_list, test_playbooks_list


def has_duplicate(id_set, id_to_check):
    duplicates = [duplicate for duplicate in id_set if duplicate.get(id_to_check)]

    if len(duplicates) < 2:
        return False

    for dup1, dup2 in itertools.combinations(duplicates, 2):
        dict1 = dup1.values()[0]
        dict2 = dup2.values()[0]
        dict1_from_version = LooseVersion(dict1.get('fromversion', '0.0.0'))
        dict2_from_version = LooseVersion(dict2.get('fromversion', '0.0.0'))
        dict1_to_version = LooseVersion(dict1.get('toversion', '99.99.99'))
        dict2_to_version = LooseVersion(dict2.get('toversion', '99.99.99'))

        if dict1['name'] != dict2['name']:
            print_warning('The following objects has the same ID but different names: '
                          '"{}", "{}".'.format(dict1['name'], dict2['name']))
        is_duplicate = True
        if dict1_from_version >= dict2_to_version or \
                dict2_to_version > dict1_to_version or \
                dict2_from_version > dict1_to_version or \
                dict1_from_version > dict2_from_version:
            is_duplicate = False
    return is_duplicate


def sort(data):
    data.sort(key=lambda r: list(r.keys())[0].lower())  # Sort data by key value
    return data


def update_id_set():
    branches = run_command("git branch")
    branch_name_reg = re.search(r"\* (.*)", branches)
    branch_name = branch_name_reg.group(1)

    print("Getting added files")
    files_string = run_command("git diff --name-status HEAD")
    second_files_string = run_command("git diff --name-status origin/master...{}".format(branch_name))
    added_files, modified_files, added_scripts, modified_scripts = \
        get_changed_files(files_string + '\n' + second_files_string)

    if added_files or modified_files or added_scripts or modified_scripts:
        print("Updating id_set.json")

        with open('./Tests/id_set.json', 'r') as id_set_file:
            try:
                ids_dict = json.load(id_set_file, object_pairs_hook=OrderedDict)
            except ValueError as ex:
                if "Expecting property name" in ex.message:
                    # if we got this error it means we have corrupted id_set.json
                    # usually it will happen if we merged from master and we had a conflict in id_set.json
                    # so we checkout the id_set.json to be exact as in master and then run update_id_set
                    run_command("git checkout origin/master Tests/id_set.json")
                    with open('./Tests/id_set.json', 'r') as id_set_file_from_master:
                        ids_dict = json.load(id_set_file_from_master, object_pairs_hook=OrderedDict)
                else:
                    raise ex

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
        # we sort each time the whole set in case someone manually changed something
        # it shouldn't take too much time
        new_ids_dict['scripts'] = sort(script_set)
        new_ids_dict['playbooks'] = sort(playbook_set)
        new_ids_dict['integrations'] = sort(integration_set)
        new_ids_dict['TestPlaybooks'] = sort(test_playbook_set)

        with open('./Tests/id_set.json', 'w') as id_set_file:
            json.dump(new_ids_dict, id_set_file, indent=4)

    print("Finished updating id_set.json")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Utility CircleCI usage')
    parser.add_argument('-r', '--reCreate', action='store_true', help='Is re-create id_set or update it')
    options = parser.parse_args()

    if options.reCreate:
        print("Re creating the id_set.json")
        re_create_id_set()

    else:
        if os.path.isfile('./Tests/id_set.json'):
            print("Updating the id_set.json")
            update_id_set()
        else:
            print("./Tests/id_set.json is missing. Recreating...")
            re_create_id_set()
