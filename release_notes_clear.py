import os
import json
import argparse
from datetime import datetime
import yaml

from Tests.scripts.validate_files import FilesValidator
from Tests.test_utils import server_version_compare, run_command, get_release_notes_file_path, print_warning
from Tests.scripts.constants import UNRELEASE_HEADER


CHANGE_LOG_FORMAT = UNRELEASE_HEADER + '\n\n## [{version}] - {date}\n'

FILE_TYPE_DICT = {
    '.yml': yaml.safe_load,
    '.json': json.load,
}


def get_changed_content_entities(modified_files, added_files):
    # when renaming a file, it will appear as a tuple of (old path, new path) under modified_files
    return added_files.union([(file_path[1] if isinstance(file_path, tuple) else file_path)
                              for file_path in modified_files])


def should_clear(file_path, current_server_version="0.0.0"):
    """
    scan folder and remove all references to release notes
    :param file_path: path of the yml/json file
    :param current_server_version: current server version
    """
    extension = os.path.splitext(file_path)[1]
    if extension not in FILE_TYPE_DICT:
        return False

    load_function = FILE_TYPE_DICT[extension]
    with open(file_path, 'r') as file_obj:
        data = load_function(file_obj)

    version = data.get('fromversion') or data.get('fromVersion')
    if version and server_version_compare(current_server_version, str(version)) < 0:
        print_warning('keeping release notes for ({})\nto be published on {} version release'.format(file_path,
                                                                                                     version))
        return False

    return True


def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('version', help='Release version')
    arg_parser.add_argument('git_sha1', help='commit sha1 to compare changes with')
    arg_parser.add_argument('server_version', help='Server version')
    arg_parser.add_argument('-d', '--date', help='release date in the format %Y-%m-%d', required=False)
    args = arg_parser.parse_args()

    date = args.date if args.date else datetime.now().strftime('%Y-%m-%d')

    # get changed yaml/json files (filter only relevant changed files)
    files_validator = FilesValidator()
    change_log = run_command('git diff --name-status {}'.format(args.git_sha1))
    modified_files, added_files, _, _ = files_validator.get_modified_files(change_log)

    for file_path in get_changed_content_entities(modified_files, added_files):
        if not should_clear(file_path, args.server_version):
            continue
        rn_path = get_release_notes_file_path(file_path)
        if os.path.isfile(rn_path):
            # if file exist, mark the current notes as release relevant
            with open(rn_path, 'r+') as rn_file:
                text = rn_file.read()
                rn_file.seek(0)
                text = text.replace(UNRELEASE_HEADER, CHANGE_LOG_FORMAT.format(version=args.version, date=date))
                rn_file.write(text)


if __name__ == '__main__':
    main()
