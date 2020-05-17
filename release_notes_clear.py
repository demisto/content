import os
import json
import argparse
from datetime import datetime
import yaml

from demisto_sdk.commands.common.constants import UNRELEASE_HEADER, INTEGRATIONS_DIR, SCRIPTS_DIR, PLAYBOOKS_DIR, \
    REPORTS_DIR, DASHBOARDS_DIR, WIDGETS_DIR, INCIDENT_FIELDS_DIR, LAYOUTS_DIR, CLASSIFIERS_DIR, INDICATOR_TYPES_DIR
from demisto_sdk.commands.common.tools import server_version_compare, run_command, get_release_notes_file_path, \
    print_warning
from demisto_sdk.commands.validate.file_validator import FilesValidator
from release_notes import LAYOUT_TYPE_TO_NAME


CHANGE_LOG_FORMAT = UNRELEASE_HEADER + '\n\n## [{version}] - {date}\n'

FILE_TYPE_DICT = {
    '.yml': yaml.safe_load,
    '.json': json.load,
}


def get_changed_content_entities(modified_files, added_files):
    # when renaming a file, it will appear as a tuple of (old path, new path) under modified_files
    return added_files.union([(file_path[1] if isinstance(file_path, tuple) else file_path)
                              for file_path in modified_files])


def get_file_data(file_path):
    extension = os.path.splitext(file_path)[1]
    if extension not in FILE_TYPE_DICT:
        return {}

    load_function = FILE_TYPE_DICT[extension]
    with open(file_path, 'r') as file_obj:
        data = load_function(file_obj)

    return data


def should_clear(file_path, current_server_version="0.0.0"):
    """
    scan folder and remove all references to release notes
    :param file_path: path of the yml/json file
    :param current_server_version: current server version
    """
    data = get_file_data(file_path)
    if not data:
        return False

    version = data.get('fromversion') or data.get('fromVersion')
    if version and server_version_compare(current_server_version, str(version)) < 0:
        print_warning('keeping release notes for ({})\nto be published on {} version release'.format(file_path,
                                                                                                     version))
        return False

    return True


def get_new_header(file_path):
    data = get_file_data(file_path)
    mapping = {
        # description
        INTEGRATIONS_DIR: ('Integration', data.get('description', '')),
        PLAYBOOKS_DIR: ('Playbook', data.get('description', '')),
        REPORTS_DIR: ('Report', data.get('description', '')),
        DASHBOARDS_DIR: ('Dashboard', data.get('description', '')),
        WIDGETS_DIR: ('Widget', data.get('description', '')),

        # comment
        SCRIPTS_DIR: ('Script', data.get('comment', '')),

        # custom
        LAYOUTS_DIR: ('Layout', '{} - {}'.format(data.get('typeId'), LAYOUT_TYPE_TO_NAME.get(data.get('kind', '')))),

        # should have RN when added
        INCIDENT_FIELDS_DIR: ('Incident Field', data.get('name', '')),
        CLASSIFIERS_DIR: ('Classifier', data.get('brandName', '')),
        # reputations.json has name at first layer
        INDICATOR_TYPES_DIR: ('Reputation', data.get('id', data.get('name', ''))),
    }

    for entity_dir in mapping:
        if entity_dir in file_path:
            entity_type, description = mapping[entity_dir]
            return '#### New {}\n{}'.format(entity_type, description)

    # should never get here
    return '#### New Content File'


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
        else:
            # if file doesn't exist, create it with new header
            with open(rn_path, 'w') as rn_file:
                text = CHANGE_LOG_FORMAT.format(version=args.version, date=date) + get_new_header(file_path)
                rn_file.write(text)
            run_command('git add {}'.format(rn_path))


if __name__ == '__main__':
    main()
