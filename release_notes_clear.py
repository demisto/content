# remove all releaseNotes from files in: Itegrations, Playbooks, Reports and Scripts.
# Note: using yaml will destroy the file structures so filtering as regular text-file.\
# Note2: file must be run from root directory with 4 sub-directories: Integration, Playbook, Reports, Scripts
# Usage: python release_notes_clear.py
import os
import glob
import sys
import yaml
import json
import re

from Tests.test_utils import server_version_compare
from Tests.test_utils import print_error


def yml_remove_releaseNote_record(file_path, current_server_version):
    """
    locate and remove release notes from a yaml file.
    :param file_path: path of the file
    :param current_server_version: current server GA version
    :return: True if file was changed, otherwise False.
    """
    with open(file_path, 'r') as f:
        yml_text = f.read()
        f.seek(0)
        yml_data = yaml.safe_load(f)

    v = yml_data.get('fromversion') or yml_data.get('fromVersion')
    if v and server_version_compare(current_server_version, str(v)) < 0:
        print('keeping release notes for ({})\nto be published on {} version release'.format(
            file_path,
            current_server_version
        ))
        return False

    rn = yml_data.get('releaseNotes')
    if rn:
        yml_text = re.sub(r'\n?releaseNotes: [\'"]?{}[\'"]?'.format(re.escape(rn).replace(r'\ ', r'\s+')), '', yml_text)
        with open(file_path, 'w') as f:
            f.write(yml_text)

        return True

    return False


def json_remove_releaseNote_record(file_path, current_server_version):
    """
    locate and remove release notes from a json file.
    :param file_path: path of the file
    :param current_server_version: current server GA version
    :return: True if file was changed, otherwise False.
    """
    with open(file_path, 'r') as f:
        json_text = f.read()
        f.seek(0)
        json_data = json.load(f)

    v = json_data.get('fromversion') or json_data.get('fromVersion')
    if v and server_version_compare(current_server_version, str(v)) < 0:
        print('keeping release notes for ({})\nto be published on {} version release'.format(
            file_path,
            current_server_version
        ))
        return False

    rn = json_data.get('releaseNotes')
    if rn:
        # try to remove with preceding comma
        json_text = re.sub(r'\s*"releaseNotes"\s*:\s*"{}",'.format(re.escape(rn)), '', json_text)
        # try to remove with leading comma (last value in json)
        json_text = re.sub(r',\s*"releaseNotes"\s*:\s*"{}"'.format(re.escape(rn)), '', json_text)
        with open(file_path, 'w') as f:
            f.write(json_text)

        return True

    return False


FILE_EXTRACTER_DICT = {
    '*.yml': yml_remove_releaseNote_record,
    '*.json': json_remove_releaseNote_record,
}


def remove_releaseNotes_folder(folder_path, files_extension,
                               current_server_version="0.0.0"):
    """
    scan folder and remove all references to release notes
    :param folder_path: path of the folder
    :param files_extension: type of file to look for (json or yml)
    :param current_server_version: current server version
    """
    scan_files = glob.glob(os.path.join(folder_path, files_extension))
    # support packages (subdirectories)
    scan_files += glob.glob(os.path.join(folder_path, '*', files_extension))

    count = 0
    for path in scan_files:
        if FILE_EXTRACTER_DICT[files_extension](path, current_server_version):
            count += 1

    print('--> Changed {} out of {} files'.format(count, len(scan_files)))


def main(argv):
    if len(argv) < 2:
        print_error("<Server version>")
        sys.exit(1)

    root_dir = argv[0]
    current_server_version = argv[1]

    yml_folders_to_scan = ['Integrations', 'Playbooks', 'Scripts', 'TestPlaybooks']  # yml
    json_folders_to_scan = ['Reports', 'Misc', 'Dashboards', 'Widgets',
                            'Classifiers', 'Layouts', 'IncidentFields']  # json

    for folder in yml_folders_to_scan:
        print('Scanning directory: "{}"'.format(folder))
        remove_releaseNotes_folder(os.path.join(root_dir, folder), '*.yml', current_server_version)

    for folder in json_folders_to_scan:
        print('Scanning directory: "{}"'.format(folder))
        remove_releaseNotes_folder(os.path.join(root_dir, folder), '*.json', current_server_version)


if __name__ == '__main__':
    main([os.path.dirname(__file__)] + sys.argv[1:])
