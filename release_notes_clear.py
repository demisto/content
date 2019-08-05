import os
import yaml
import json
import argparse
import datetime

from Tests.scripts.validate_files import FilesValidator
from Tests.test_utils import server_version_compare, run_command, get_release_notes_file_path
from Tests.scripts.constants import UNRELEASE_HEADER


CHANGE_LOG_FORMAT = UNRELEASE_HEADER + '\n\n## [{version}] - {date}'


def yml_should_skip_clearing(file_path, current_server_version):
    """
    locate and remove release notes from a yaml file.
    :param file_path: path of the file
    :param current_server_version: current server GA version
    :return: True if file was changed, otherwise False.
    """
    with open(file_path, 'r') as f:
        yml_data = yaml.safe_load(f)

    v = yml_data.get('fromversion') or yml_data.get('fromVersion')
    if v and server_version_compare(current_server_version, str(v)) < 0:
        print('keeping release notes for ({})\nto be published on {} version release'.format(
            file_path,
            current_server_version
        ))
        return False

    return True


def json_should_skip_clearing(file_path, current_server_version):
    """
    locate and remove release notes from a json file.
    :param file_path: path of the file
    :param current_server_version: current server GA version
    :return: True if file was changed, otherwise False.
    """
    with open(file_path, 'r') as f:
        json_data = json.load(f)

    v = json_data.get('fromversion') or json_data.get('fromVersion')
    if v and server_version_compare(current_server_version, str(v)) < 0:
        print('keeping release notes for ({})\nto be published on {} version release'.format(
            file_path,
            current_server_version
        ))
        return False

    return True


FILE_TYPE_DICT = {
    '.yml': yml_should_skip_clearing,
    '.json': json_should_skip_clearing,
}


def should_skip_clearing(file_path, current_server_version="0.0.0"):
    """
    scan folder and remove all references to release notes
    :param file_path: path of the yml/json file
    :param current_server_version: current server version
    """
    extension = os.path.splitext(file_path)[1]
    return FILE_TYPE_DICT[extension](file_path, current_server_version)


def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('version', help='Release version')
    arg_parser.add_argument('git_sha1', help='commit sha1 to compare changes with')
    arg_parser.add_argument('server_version', help='Server version')
    args = arg_parser.parse_args()

    date = datetime.now().strftime('%Y-%m-%d')

    # get changed yaml/json files (filter only relevant changed files)
    fv = FilesValidator()
    change_log = run_command('git diff --name-status {}'.format(args.git_sha1))
    modified_files, added_files, _, _ = fv.get_modified_files(change_log)

    for file_path in modified_files.union(added_files):
        if should_skip_clearing(file_path, args.server_version):
            continue
        rn_path = get_release_notes_file_path(file_path)
        if os.path.isfile(rn_path):
            # if file exist, mark the current notes as release relevant
            with open(rn_path, 'r+') as rn_file:
                text = rn_file.read()
                rn_file.seek(0)
                text = text.replace(UNRELEASE_HEADER, CHANGE_LOG_FORMAT.format(args.version, date))
                rn_file.write(text)


if __name__ == '__main__':
    main()
