import json
import shutil
import sys
import os
import click
from datetime import datetime
from typing import Dict

DIR_LIST = ['Integrations', 'Scripts', 'IncidentFields', 'IncidentTypes', 'IndicatorFields',
            'Playbooks', 'Layouts', 'TestPlaybooks', 'Classifiers', 'Connections', 'Dashboards',
            'IndicatorTypes', 'Reports', 'Widgets', 'doc_files']

COPY_DIR_LIST = ['Playbooks', 'TestPlaybooks', 'Layouts', 'IncidentFields', 'IncidentTypes']

arguments = sys.argv
old_version = arguments[1]
new_from_version = arguments[2]

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


for copied_pack_name in os.listdir('Packs'):
    if copied_pack_name != old_version:
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
