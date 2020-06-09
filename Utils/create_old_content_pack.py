import json
import shutil
import sys
import os
from datetime import datetime
from typing import Dict

DIR_LIST = ['Integrations', 'Scripts', 'IncidentFields', 'IncidentTypes', 'IndicatorFields',
            'Playbooks', 'Layouts', 'TestPlaybooks', 'Classifiers', 'Connections', 'Dashboards',
            'IndicatorTypes', 'Reports', 'Widgets', 'doc_files']

COPY_DIR_LIST = ['Playbooks', 'TestPlaybooks', 'Layouts', 'IncidentFields', 'IncidentTypes']

arguments = sys.argv
old_version = arguments[1]
new_from_version = arguments[2]

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


def copytree(src, dst):
    for item in os.listdir(src):
        s = os.path.join(src, item)
        d = os.path.join(dst, item)
        if os.path.isdir(s):
            shutil.copytree(s, d)

        else:
            shutil.copy2(s, d)


for copied_pack_name in os.listdir('Packs'):
    if copied_pack_name != old_version:
        copied_pack_path = os.path.join('Packs', copied_pack_name)

        if not os.path.isdir(copied_pack_path):
            # there are files that are not directories but returned from listdir like Packs/.DS_Store
            # skip them
            continue

        for dir_name in os.listdir(copied_pack_path):
            dir_path = os.path.join(copied_pack_path, dir_name)
            dst_path = os.path.join(pack_path, dir_name)

            if dir_name in COPY_DIR_LIST:
                copytree(dir_path, dst_path)
                continue

            if dir_name not in DIR_LIST and dir_name != 'ReleaseNotes' and os.path.isdir(dir_path):
                DIR_LIST.append(dir_path)
                COPY_DIR_LIST.append(dir_name)
                os.mkdir(dst_path)
                copytree(dir_path, dst_path)

            if dir_name == 'ReleaseNotes':
                continue

            if not os.path.isdir(dir_path):
                # ignore - .secrets-ignore, .pack-ignore, pack_metadata, readme files
                continue

            for internal_dir_name in os.listdir(dir_path):
                src_path = os.path.join(dir_path, internal_dir_name)
                if os.path.isfile(src_path):
                    shutil.copy(src_path, dst_path)

                else:
                    dst_path = os.path.join(dst_path, internal_dir_name)
                    os.mkdir(dst_path)
                    copytree(src_path, dst_path)
