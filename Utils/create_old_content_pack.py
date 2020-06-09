import json
import shutil
import sys
import os
import click
import yaml
import io
from pkg_resources import parse_version
from datetime import datetime

from typing import Dict

DIR_LIST = ['Integrations', 'Scripts', 'IncidentFields', 'IncidentTypes', 'IndicatorFields',
            'Playbooks', 'Layouts', 'TestPlaybooks', 'Classifiers', 'Connections', 'Dashboards',
            'IndicatorTypes', 'Reports', 'Widgets', 'doc_files']

COPY_DIR_LIST = ['Playbooks', 'TestPlaybooks', 'Layouts', 'IncidentFields', 'IncidentTypes']

arguments = sys.argv
old_version = arguments[1]

click.secho("Cleaning access files (unified, demistomock and so on...)")
os.system('git clean -X -f -q')

click.secho(f"Starting old pack creation for {old_version}")

# create a new pack
pack_path = os.path.join('Packs', str(old_version))
os.mkdir(pack_path)

for directory in DIR_LIST:
    dir_path = os.path.join(pack_path, directory)
    os.mkdir(dir_path)

fp = open(os.path.join(pack_path, 'README.md'), 'a')
fp.close()

fp = open(os.path.join(pack_path, '.secrets-ignore'), 'a')
fp.close()

fp = open(os.path.join(pack_path, '.pack-ignore'), 'a')
fp.close()

metadata_path = os.path.join(pack_path, 'pack_metadata.json')
with open(metadata_path, 'a') as fp:
    pack_metadata = {
        'name': old_version,
        'description': f'Cortex XSOAR content version {old_version}',
        'support': 'xsoar',
        'currentVersion': '1.0.0',
        'author': "Cortex XSOAR",
        'url': "https://www.paloaltonetworks.com/cortex",
        'email': '',
        'created': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
        'categories': [],
        'tags': [],
        'useCases': [],
        'keywords': []
    }

    json.dump(pack_metadata, fp, indent=4)

click.secho("Finished base pack creation", fg="green")
click.secho("Coping content entities to pack")


def copytree(src, dst):
    for item in os.listdir(src):
        s = os.path.join(src, item)
        d = os.path.join(dst, item)
        if not os.path.exists(d):
            if os.path.isdir(s):
                os.mkdir(d)
                copytree(s, d)

            else:
                shutil.copy(s, d)


def get_file(method, file_path, type_of_file):
    data_dictionary = None
    with open(os.path.expanduser(file_path), mode="r", encoding="utf8") as f:
        if file_path.endswith(type_of_file):
            read_file = f.read()
            replaced = read_file.replace("simple: =", "simple: '='")
            # revert str to stream for loader
            stream = io.StringIO(replaced)
            try:
                data_dictionary = method(stream)
            except Exception as e:
                click.secho("{} has a structure issue of file type{}. Error was: {}".format(file_path, type_of_file, str(e)), fg="red")
                return {}
    if type(data_dictionary) is dict:
        return data_dictionary
    return {}


def get_yaml(file_path):
    return get_file(yaml.safe_load, file_path, ('yml', 'yaml'))

def handle_yml_file(file_path):
    yml_content = get_yaml(file_path)
    if 'toversion' in yml_content:
        if parse_version(str(yml_content['toversion'])) < parse_version(yml_old_version):
            return False

    if 'fromversion' in yml_content:
        if parse_version(str(yml_content['fromversion'])) > parse_version(yml_old_version):
            return False

    yml_content['toversion'] = yml_old_version
    with open(file_path, 'w') as f:
        yaml.dump(yml_content, f)
        print(f"Updating {file_path}")

    return True

def delete_playbook(file_path):
    os.remove(file_path)
    print(f"Deleting {file_path}")

    changelog_file = os.path.join(os.path.splitext(file_path)[0] + '_CHANGELOG.md')
    readme_file = os.path.join(os.path.splitext(file_path)[0] + '_README.md')
    if os.path.isfile(changelog_file):
        os.remove(changelog_file)

    if os.path.isfile(readme_file):
        os.remove(readme_file)


def delete_script_or_integration(path):
    if os.path.isfile(path):
        os.remove(path)
        changelog_file = os.path.splitext(path)[0] + '_CHANGELOG.md'
        if os.path.isfile(changelog_file):
            os.remove(changelog_file)

    else:
        shutil.rmtree(path)
    print(f"Deleting {path}")


for copied_pack_name in os.listdir('Packs'):
    if copied_pack_name != old_version and copied_pack_name != 'NonSupported':
        copied_pack_path = os.path.join('Packs', copied_pack_name)

        for dir_name in os.listdir(copied_pack_path):
            dir_path = os.path.join(copied_pack_path, dir_name)
            if os.path.isfile(dir_path) or dir_path.endswith('ReleaseNotes'):
                continue

            old_pack_directory = os.path.join(pack_path, dir_name)
            if not os.path.exists(old_pack_directory):
                os.mkdir(old_pack_directory)

            copytree(dir_path, old_pack_directory)

click.secho("Finished content copy", fg="green")

if old_version.count('.') == 1:
    yml_old_version = old_version + ".9"

click.secho("Starting file editing")
for content_dir in os.listdir(pack_path):
    dir_path = os.path.join(pack_path, content_dir)
    if content_dir in ['Playbooks', 'TestPlaybooks']:
        for file_name in os.listdir(dir_path):
            file_path = os.path.join(dir_path, file_name)
            if file_path.endswith('md'):
                continue

            if os.path.isfile(file_path):
                if file_path.endswith('.yml'):
                    if not handle_yml_file(file_path):
                        delete_playbook(file_path)

            else:
                inner_dir_path = file_path
                for inner_file_name in os.listdir(inner_dir_path):
                    file_path = os.path.join(inner_dir_path, inner_file_name)
                    if file_path.endswith('.yml'):
                        if not handle_yml_file(file_path):
                            delete_playbook(file_path)

    if content_dir in ['Scripts', 'Integrations']:
        for script_name in os.listdir(dir_path):
            path = os.path.join(dir_path, script_name)
            if path.endswith('.md'):
                continue

            if os.path.isfile(path):
                yml_file_path = path

            else:
                yml_file_path = os.path.join(path, script_name + '.yml')
            if not handle_yml_file(yml_file_path):
                delete_script_or_integration(path)


click.secho("Finished file editing", fg='green')
