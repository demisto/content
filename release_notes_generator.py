from __future__ import print_function
import os
import sys
import json
import argparse

from datetime import datetime
from distutils.version import LooseVersion
from demisto_sdk.commands.common.tools import print_error, get_pack_name, run_command


IGNORE_RN = '-'
PACKS_DIR = 'Packs'
DATE_FORMAT = '%d %B %Y'
PACK_METADATA = 'pack_metadata.json'
PACKS_RN_FILES_FORMAT = '*/ReleaseNotes/*.md'
RELEASE_NOTES_FILE = 'release-notes-test.md'


def get_all_modified_release_note_files(git_sha1):
    try:
        diff_cmd = 'git diff --diff-filter=AM --name-only {} {}'.format(git_sha1, PACKS_RN_FILES_FORMAT)
        diff_result = run_command(diff_cmd, exit_on_error=False)
        release_notes_files = list(filter(None, diff_result.split('\n')))
        return release_notes_files

    except RuntimeError:
        print_error('Unable to get the SHA1 of the commit in which the version was released. This can happen if your '
                    'branch is not updated with origin master. Merge from origin master and, try again.\n'
                    'If you\'re not on a fork, run "git merge origin/master".\n'
                    'If you are on a fork, first set https://github.com/demisto/content to be '
                    'your upstream by running "git remote add upstream https://github.com/demisto/content". After '
                    'setting the upstream, run "git fetch upstream", and then run "git merge upstream/master". Doing '
                    'these steps will merge your branch with content master as a base.')
        sys.exit(1)


def get_pack_name_from_metdata(file_path):
    pack_dir = get_pack_name(file_path)
    pack_metadata_path = os.path.join(PACKS_DIR, pack_dir, PACK_METADATA)
    with open(pack_metadata_path, 'r') as json_file:
        pack_metadata = json.load(json_file)
        pack_name = pack_metadata.get('name')
    return pack_name


def get_pack_version_from_path(file_path):
    # example: from filepath `<path>/1_0_1.md`, the next line will produce `1.0.1`
    pack_version = os.path.basename(os.path.splitext(file_path)[0]).replace('_', '.')
    return pack_version


def get_release_notes_dict(release_notes_files):
    release_notes_dict = {}
    for file_path in release_notes_files:
        pack_version = get_pack_version_from_path(file_path)
        with open(file_path, 'r') as rn:
            release_note = rn.read()
            if release_note and release_note.strip() != IGNORE_RN:
                pack_name = get_pack_name_from_metdata(file_path)
                release_notes_dict.setdefault(pack_name, {})[pack_version] = release_note
                print('Adding release notes for pack {} {}...'.format(pack_name, pack_version))
            else:
                print('Ignoring release notes for pack {} {}...'.format(pack_name, pack_version))
    return release_notes_dict


def generate_release_notes_summary(release_notes_dict, version, asset_id):
    release_notes = '## Cortex XSOAR Content Release Notes for version {} ({})\n'.format(version, asset_id)
    current_date = datetime.now().strftime(DATE_FORMAT)
    release_notes += '##### Published on {}\n'.format(current_date)

    for pack_name, pack_versions_dict in sorted(release_notes_dict.items()):
        for pack_version, pack_release_notes in sorted(pack_versions_dict.items(),
                                                       key=lambda pack_item: LooseVersion(pack_item[0])):
            release_notes += '### {} {}\n{}\n'.format(pack_name, pack_version, pack_release_notes)

    with open(RELEASE_NOTES_FILE, 'w') as outfile:
        outfile.write(release_notes)


def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('version', help='Release version')
    arg_parser.add_argument('git_sha1', help='commit sha1 to compare changes with')
    arg_parser.add_argument('asset_id', help='Asset ID')
    # arg_parser.add_argument('--github-token', help='Github token')
    args = arg_parser.parse_args()

    release_notes_files = get_all_modified_release_note_files(args.git_sha1)
    release_notes_dict = get_release_notes_dict(release_notes_files)
    generate_release_notes_summary(release_notes_dict, args.version, args.asset_id)
    sys.exit(0)


if __name__ == "__main__":
    main()
