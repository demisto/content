import os
import yaml
import json
from distutils.version import LooseVersion

PACKS_DIR = './Packs'
CONF_JSON_PATH = './Tests/conf.json'
INTEGRATIONS_DIR = 'Integrations'
TEST_PLAYBOOKS_DIR = 'TestPlaybooks'


def get_integration_data(file_path):
    with open(file_path) as data_file:
        yaml_file = yaml.safe_load(data_file)
        return yaml_file['commonfields']['id'], yaml_file.get('fromversion', '0.0.0')


def get_playbook_id(file_path):
    with open(file_path) as data_file:
        yaml_file = yaml.safe_load(data_file)
        return yaml_file['id']


def get_fromversion(integrations):
    max_fromversion = '0.0.0'
    for integration_id, fromversion in integrations:
        if LooseVersion(fromversion) > LooseVersion(max_fromversion):
            max_fromversion = fromversion

    return max_fromversion


def calc_conf_json_object(integrations, test_playbooks):
    conf_objects = [{'playbookID': test_playbook} for test_playbook in test_playbooks]
    fromverion = get_fromversion(integrations)
    integrations = [integration_id for integration_id, _ in integrations]
    if len(integrations) == 1:
        integrations = integrations[0]

    for conf_object in conf_objects:
        if integrations:
            conf_object['integrations'] = integrations
        conf_object['fromversion'] = fromverion

    return conf_objects


def add_to_conf_json(conf_objects):
    with open(CONF_JSON_PATH) as data_file:
        conf = json.load(data_file)

    conf['tests'].extend(conf_objects)

    with open(CONF_JSON_PATH, 'w') as conf_file:
        json.dump(conf, conf_file, indent=4)


def load_test_data_from_conf_json():
    test_playbooks = []
    with open(CONF_JSON_PATH) as data_file:
        conf = json.load(data_file)

    for conf_test in conf['tests']:
        test_playbooks.append(conf_test['playbookID'])

    return test_playbooks


def run():
    new_conf_json_objects = []
    existing_test_playbooks = load_test_data_from_conf_json()

    for pack_name in os.listdir(PACKS_DIR):
        pack_path = os.path.join(PACKS_DIR, pack_name)

        pack_integrations = []
        pack_test_playbooks = []
        for dir_name in os.listdir(pack_path):
            dir_path = os.path.join(pack_path, dir_name)

            if dir_name not in [INTEGRATIONS_DIR, TEST_PLAYBOOKS_DIR]:
                continue

            for file_or_dir in os.listdir(dir_path):
                if os.path.isdir(os.path.join(dir_path, file_or_dir)) and dir_name == INTEGRATIONS_DIR:
                    inner_dir_path = os.path.join(dir_path, file_or_dir)
                    for integration_file in os.listdir(inner_dir_path):
                        is_yml_file = integration_file.endswith('.yml')
                        file_path = os.path.join(inner_dir_path, integration_file)
                        if is_yml_file:
                            if dir_name == INTEGRATIONS_DIR:
                                pack_integrations.append(get_integration_data(file_path))
                else:
                    is_yml_file = file_or_dir.endswith('.yml')
                    file_path = os.path.join(dir_path, file_or_dir)
                    if is_yml_file:
                        if dir_name == INTEGRATIONS_DIR:
                            pack_integrations.append(get_integration_data(file_path))

                        if dir_name == TEST_PLAYBOOKS_DIR:
                            test_playbook_id = get_playbook_id(file_path)
                            if test_playbook_id not in existing_test_playbooks:
                                pack_test_playbooks.append(test_playbook_id)

        if pack_test_playbooks:
            new_conf_json_objects.extend(calc_conf_json_object(pack_integrations, pack_test_playbooks))

    add_to_conf_json(new_conf_json_objects)


if __name__ == '__main__':
    run()
