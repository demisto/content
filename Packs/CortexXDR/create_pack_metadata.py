import os
import glob
import json
import yaml
from datetime import datetime
from collections import OrderedDict

DIR_NAME_TO_CONTENT_TYPE = {
    "Scripts": "Automations",
    "IncidentFields": "Incident Fields",
    "Playbooks": "Playbooks",
    "Integrations": "Integrations",
    "IncidentTypes": "Incident Types",
    "Layouts": "Incident Layouts"
}

YML_SUPPORTED_DIRS = [
    "Scripts",
    "Integrations",
    "Playbooks"
]

DIR_OF_PACKAGES = [
    "Scripts",
    "Integrations"
]


def extract_dir_data(directory, dir_path, dir_data):
    dir_files = glob.glob(os.path.join(dir_path, '*.json')) + glob.glob(os.path.join(dir_path, '*.yml'))
    for file_path in dir_files:
        file_info = {}
        with open(file_path, 'r') as file_data:
            if directory in YML_SUPPORTED_DIRS:
                new_data = yaml.safe_load(file_data)
            else:
                new_data = json.load(file_data)

            file_info['name'] = new_data.get('TypeName', '') if directory == "Layouts" else new_data.get('name', '')

            if new_data.get('description', ''):
                file_info['description'] = new_data.get('description', '')
            if new_data.get('comment', ''):
                file_info['description'] = new_data.get('comment', '')

            dir_data.append(file_info)


def gather_content_items_data(pack_path):
    # TODO: fill this out
    data = {}

    for directory in os.listdir(pack_path):
        if not os.path.isdir(os.path.join(pack_path, directory)) or directory == "TestPlaybooks":
            continue

        dir_data = []
        dir_path = os.path.join(pack_path, directory)
        if directory in DIR_OF_PACKAGES:
            for sub_dir in os.listdir(dir_path):
                if not os.path.isdir(os.path.join(pack_path, directory)):
                    continue

                extract_dir_data(directory, os.path.join(dir_path, sub_dir), dir_data)

        else:
            extract_dir_data(directory, dir_path, dir_data)

        data[DIR_NAME_TO_CONTENT_TYPE[directory]] = dir_data

    return data


def extract_display_name(integration_path):
    integration_yml_path = glob.glob(os.path.join(integration_path, '*.yml'))[0]
    with open(integration_yml_path, 'r') as file_data:
        new_data = yaml.safe_load(file_data)

    return new_data['display']


def gather_integration_display_names(pack_path):
    if 'Integrations' not in os.listdir(pack_path):
        return []

    integration_display_names = []
    intetgration_dir = os.path.join(pack_path, 'Integrations')
    for sub_dir in os.listdir(intetgration_dir):
        if not os.path.isdir(os.path.join(intetgration_dir, sub_dir)):
            continue

        integration_display_names.append(extract_display_name(os.path.join(intetgration_dir, sub_dir)))

    return integration_display_names


def extract_tags(script_path):
    script_yml_path = glob.glob(os.path.join(script_path, '*.yml'))[0]
    with open(script_yml_path, 'r') as file_data:
        new_data = yaml.safe_load(file_data)

    return set(new_data.get('tags'))


def gather_script_tags(pack_path):
    if 'Scripts' not in os.listdir(pack_path):
        return []

    script_tags = set([])
    scripts_dir_path = os.path.join(pack_path, 'Scripts')
    for sub_dir in os.listdir(scripts_dir_path):
        if not os.path.isdir(os.path.join(scripts_dir_path, sub_dir)):
            continue

        script_tags = script_tags.union(extract_tags(os.path.join(scripts_dir_path, sub_dir)))

    return script_tags


def create_pack_metadata(pack_path):
    pack_metdadata = OrderedDict()
    pack_metdadata['id'] = '##### Fill this in #####'
    pack_metdadata['displayName'] = '##### Fill this in #####'
    pack_metdadata['description'] = '##### Fill this in #####'
    pack_metdadata['updated'] = datetime.strftime(datetime.utcnow(), '%Y-%m-%dT%H:%M:%SZ')
    pack_metdadata['support'] = '##### Fill this in ##### - options are demisto / partner / developer / community'
    pack_metdadata['beta'] = "##### Fill this in ##### True or False"
    pack_metdadata['deprecated'] = "##### Fill this in ##### True or False"
    pack_metdadata['certification'] = '##### Fill this in ##### - certified or verified'
    pack_metdadata['serverMinVersion'] = '##### Fill this in #####'
    pack_metdadata['serverLicense'] = "##### Fill this in ##### standard or premium"
    pack_metdadata['currentVersion'] = '##### Fill this in #####'

    pack_metdadata['supportDetails'] = OrderedDict()
    pack_metdadata['supportDetails']['author'] = '##### Fill this in #####'
    pack_metdadata['supportDetails']['url'] = '##### Fill this in ##### Should represent your GitHub account'
    pack_metdadata['supportDetails']['email'] = '##### Fill this in ##### Should represent the email ' \
                                                'in which you can be contacted in'

    pack_metdadata['general'] = ['##### Fill this in #####']
    pack_metdadata['tags'] = list(gather_script_tags(pack_path))
    pack_metdadata['categories'] = ['##### Fill this in #####']
    pack_metdadata['contentItems'] = gather_content_items_data(pack_path)
    pack_metdadata["contentItemTypes"] = list(pack_metdadata['contentItems'].keys())
    pack_metdadata["integrations"] = gather_integration_display_names(pack_path)
    pack_metdadata["useCases"] = ['##### Fill this in #####']
    pack_metdadata["keywords"] = ["##### Fill this in #####"]
    pack_metdadata["dependencies"] = {}  # TODO: fill this out

    with open('./testing.json', 'w') as pack_metdadata_file:
        json.dump(pack_metdadata, pack_metdadata_file, indent=4)


def update_pack_metadata(pack_path):
    with open('./testing.json', 'r') as pack_metdadata_file:
        pack_metdadata = json.load(pack_metdadata_file, object_pairs_hook=OrderedDict)

    pack_metdadata['updated'] = datetime.strftime(datetime.utcnow(), '%Y-%m-%dT%H:%M:%SZ')
    pack_metdadata['tags'] = list(gather_script_tags(pack_path))
    pack_metdadata['contentItems'] = gather_content_items_data(pack_path)
    pack_metdadata["contentItemTypes"] = list(pack_metdadata['contentItems'].keys())
    pack_metdadata["integrations"] = gather_integration_display_names(pack_path)

    with open('./testing.json', 'w') as pack_metdadata_file:
        json.dump(pack_metdadata, pack_metdadata_file, indent=4)


if __name__ == '__main__':
    pack_path = "Packs/CortexXDR/"

    # create_pack_metadata(pack_path)
    update_pack_metadata(pack_path)
