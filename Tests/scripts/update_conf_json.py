#!/usr/bin/env python3
import os
from pprint import pformat

import yaml
import json
from distutils.version import LooseVersion
import logging

from pebble import ProcessPool

from Tests.scripts.utils.log_util import install_logging
from demisto_sdk.commands.common.tools import find_type
from demisto_sdk.commands.common.constants import TEST_PLAYBOOKS_DIR, INTEGRATIONS_DIR, CONF_PATH, PACKS_DIR, \
    FileType

INITIAL_FROM_VERSION = "4.5.0"
NEW_CONF_JSON_OBJECT = []


def get_integration_data(file_path):
    with open(file_path) as data_file:
        yaml_file = yaml.safe_load(data_file)
        return yaml_file['commonfields']['id'], yaml_file.get('fromversion', '0.0.0')


def get_playbook_data(file_path):
    with open(file_path) as data_file:
        yaml_file = yaml.safe_load(data_file)
        return yaml_file['id'], yaml_file.get('fromversion', '0.0.0')


def get_fromversion(integrations):
    max_fromversion = INITIAL_FROM_VERSION
    for integration_id, fromversion in integrations:
        if LooseVersion(fromversion) > LooseVersion(max_fromversion):
            max_fromversion = fromversion

    return max_fromversion


def calc_conf_json_object(integrations, test_playbooks):
    fromversion = get_fromversion(integrations)
    conf_objects = [{'playbookID': test_playbook, 'fromversion': test_fromversion}
                    for test_playbook, test_fromversion in test_playbooks]
    integrations = [integration_id for integration_id, _ in integrations]

    for conf_object in conf_objects:
        if integrations:
            conf_object['integrations'] = integrations
        if LooseVersion(conf_object['fromversion']) < fromversion:
            conf_object['fromversion'] = fromversion

    return conf_objects


def add_to_conf_json(conf_objects):
    with open(CONF_PATH) as data_file:
        conf = json.load(data_file)

    conf['tests'].extend(conf_objects)

    with open(CONF_PATH, 'w') as conf_file:
        json.dump(conf, conf_file, indent=4)


def load_test_data_from_conf_json():
    test_playbooks = []
    with open(CONF_PATH) as data_file:
        conf = json.load(data_file)

    for conf_test in conf['tests']:
        test_playbooks.append(conf_test['playbookID'])

    return test_playbooks


def generate_pack_tests_configuration(pack_name, existing_test_playbooks):
    install_logging('Update_Tests_step.log', include_process_name=True)
    pack_integrations = []
    pack_test_playbooks = []

    pack_path = os.path.join(PACKS_DIR, pack_name)

    integration_dir_path = os.path.join(pack_path, INTEGRATIONS_DIR)
    test_playbook_dir_path = os.path.join(pack_path, TEST_PLAYBOOKS_DIR)
    if not os.path.isdir(test_playbook_dir_path) or not os.listdir(test_playbook_dir_path):
        return pack_integrations, pack_test_playbooks, pack_name

    logging.info(f'Going over {pack_name}')
    if os.path.exists(integration_dir_path):
        for file_or_dir in os.listdir(integration_dir_path):
            if os.path.isdir(os.path.join(integration_dir_path, file_or_dir)):
                inner_dir_path = os.path.join(integration_dir_path, file_or_dir)
                for integration_file in os.listdir(inner_dir_path):
                    is_yml_file = integration_file.endswith('.yml')
                    file_path = os.path.join(inner_dir_path, integration_file)
                    if is_yml_file:
                        pack_integrations.append(get_integration_data(file_path))
            else:
                is_yml_file = file_or_dir.endswith('.yml')
                file_path = os.path.join(integration_dir_path, file_or_dir)
                if is_yml_file:
                    pack_integrations.append(get_integration_data(file_path))

    for file_path in os.listdir(test_playbook_dir_path):
        is_yml_file = file_path.endswith('.yml')
        file_path = os.path.join(test_playbook_dir_path, file_path)
        if is_yml_file and find_type(file_path) == FileType.TEST_PLAYBOOK:
            test_playbook_id, fromversion = get_playbook_data(file_path)
            if test_playbook_id not in existing_test_playbooks:
                pack_test_playbooks.append((test_playbook_id, fromversion))
    return pack_integrations, pack_test_playbooks, pack_name


def update_new_conf_json(future):
    try:
        pack_integrations, pack_test_playbooks, pack_name = future.result()  # blocks until results ready
        if pack_test_playbooks:
            NEW_CONF_JSON_OBJECT.extend(calc_conf_json_object(pack_integrations, pack_test_playbooks))
    except Exception:
        logging.exception('Failed to collect pack test configurations')


def main():
    install_logging('Update_Tests_step.log', include_process_name=True)
    existing_test_playbooks = load_test_data_from_conf_json()
    with ProcessPool(max_workers=os.cpu_count(), max_tasks=100) as pool:
        for pack_name in os.listdir(PACKS_DIR):
            future_object = pool.schedule(generate_pack_tests_configuration,
                                          args=(pack_name, existing_test_playbooks), timeout=20)
            future_object.add_done_callback(update_new_conf_json)

    add_to_conf_json(NEW_CONF_JSON_OBJECT)
    logging.success(f'Added {len(NEW_CONF_JSON_OBJECT)} tests to the conf.json')
    logging.success(f'Added the following objects to the conf.json:\n{pformat(NEW_CONF_JSON_OBJECT)}')


if __name__ == '__main__':
    main()
