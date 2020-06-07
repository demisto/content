from __future__ import print_function
import re
import os
import sys
import json
import glob
import argparse
import requests

from datetime import datetime
from distutils.version import LooseVersion
from demisto_sdk.commands.common.tools import run_command, print_error, print_warning, get_dict_from_file


COMMENT_REGEX = r'<!--(.*?)-->'
PACKS_DIR = 'Packs'
DATE_FORMAT = '%d %B %Y'
PACK_METADATA = 'pack_metadata.json'
PACKS_RN_FILES_FORMAT = '*/ReleaseNotes/*.md'

LAYOUT_TYPE_TO_NAME = {
    "details": "Summary",
    "edit": "New/Edit",
    "close": "Close",
    "quickView": "Quick View",
    "indicatorsDetails": "Indicator Details",
    "mobile": "Mobile",
}


def get_new_packs(git_sha1):
    """ Gets all the existing modified/added file paths in the format */ReleaseNotes/*.md.

        Args:
            git_sha1 (str): The branch to make the diff with.

        Returns:
            (list) A list of the new/modified release notes file paths.
        """
    diff_cmd = f'git diff --diff-filter=A --name-only {git_sha1} */{PACK_METADATA}'
    try:
        diff_result = run_command(diff_cmd, exit_on_error=False)
    except RuntimeError:
        print_error('Unable to get the SHA1 of the commit in which the version was released. This can happen if your '
                    'branch is not updated with origin master. Merge from origin master and, try again.\n'
                    'If you\'re not on a fork, run "git merge origin/master".\n'
                    'If you are on a fork, first set https://github.com/demisto/content to be '
                    'your upstream by running "git remote add upstream https://github.com/demisto/content". After '
                    'setting the upstream, run "git fetch upstream", and then run "git merge upstream/master". Doing '
                    'these steps will merge your branch with content master as a base.')
        sys.exit(1)

    pack_paths = [os.path.dirname(file_path) for file_path in diff_result.split('\n')
                  if file_path.startswith(PACKS_DIR)]
    return pack_paths


def get_new_entity_record(entity_path : str) -> (str, str):
    data, _ = get_dict_from_file(entity_path)

    if 'layouts' in entity_path.lower():
        layout_kind = LAYOUT_TYPE_TO_NAME.get(data.get('kind', ''))
        type_id = data.get('typeId', '')
        return f'{type_id} - {layout_kind}', ''

    name = data.get('name', '')
    if not name:
        print_error(f'missing name for {entity_path}')

    # script entities has "comment" instead of "description"
    description = data.get('description', '') or data.get('comment', '')
    if not description:
        print_warning(f'missing description for {entity_path}')

    return name, description


def get_pack_entities(pack_path):
    print(f'Processing "{pack_path}" files:')
    pack_entities = (glob.glob(f'{pack_path}/*/*.json') +
                     glob.glob(f'{pack_path}/*/*.yml') +
                     glob.glob(f'{pack_path}/*/*/*.yml'))
    pack_entities.sort()

    entities_data = {}
    for entity_path in pack_entities:
        # ignore test files
        if 'test' in entity_path.lower():
            print(f'skipping test file: {entity_path}')
            continue

        match = re.match(f'{pack_path}/([^/]*)/.*', entity_path)
        if match:
            entity_type = match.group(1)
        else:
            # should not get here
            entity_type = 'Extras'

        name, description = get_new_entity_record(entity_path)
        entities_data.setdefault(entity_type, {})[name] = description

    release_notes = ''
    for entity_type, entities_description in sorted(entities_data.items()):
        release_notes += f'\n#### {entity_type}\n'
        for name, description in entities_description.items():
            release_notes += f'##### {name}\n - {description}\n'

    print('Finished processing pack')
    return release_notes


def get_all_modified_release_note_files(git_sha1):
    """ Gets all the existing modified/added file paths in the format */ReleaseNotes/*.md.

    Args:
        git_sha1 (str): The branch to make the diff with.

    Returns:
        (list) A list of the new/modified release notes file paths.
    """
    diff_cmd = f'git diff --diff-filter=AM --name-only {git_sha1} {PACKS_RN_FILES_FORMAT}'
    try:
        diff_result = run_command(diff_cmd, exit_on_error=False)
    except RuntimeError:
        print_error('Unable to get the SHA1 of the commit in which the version was released. This can happen if your '
                    'branch is not updated with origin master. Merge from origin master and, try again.\n'
                    'If you\'re not on a fork, run "git merge origin/master".\n'
                    'If you are on a fork, first set https://github.com/demisto/content to be '
                    'your upstream by running "git remote add upstream https://github.com/demisto/content". After '
                    'setting the upstream, run "git fetch upstream", and then run "git merge upstream/master". Doing '
                    'these steps will merge your branch with content master as a base.')
        sys.exit(1)

    release_notes_files = list(filter(None, diff_result.split('\n')))
    return release_notes_files


def get_pack_name_from_metdata(pack_path):
    pack_metadata_path = os.path.join(pack_path, PACK_METADATA)
    with open(pack_metadata_path, 'r') as json_file:
        pack_metadata = json.load(json_file)
        pack_name = pack_metadata.get('name')

    return pack_name


def get_pack_name_from_release_note(file_path):
    match = re.search(r'(.*)/ReleaseNotes/.*', file_path)
    if match:
        return get_pack_name_from_metdata(match.group(1))

    raise ValueError('Pack name was not found for file path {}'.format(file_path))


def get_pack_version_from_path(file_path):
    # example: from file path `<path>/1_0_1.md`, the next line will produce `1.0.1`
    pack_version = os.path.basename(os.path.splitext(file_path)[0]).replace('_', '.')
    return pack_version


def read_and_format_release_note(rn_file):
    with open(rn_file, 'r') as stream:
        release_notes = stream.read()

    ignored_rn_regex = re.compile(COMMENT_REGEX)
    if ignored_rn_regex.match(release_notes):
        return ''

    empty_lines_regex = r'\s*-\s*\n'
    release_notes = re.sub(empty_lines_regex, '', release_notes)

    return release_notes


def get_release_notes_dict(release_notes_files):
    """ Gets a dictionary that holds the new/modified release notes content.

    Args:
        release_notes_files (list): A list of the new/modified release notes file paths.

    Returns:
        (dict) A mapping from pack names to dictionaries of pack versions to release notes.
    """
    release_notes_dict = {}
    for file_path in release_notes_files:
        pack_name = get_pack_name_from_release_note(file_path)
        pack_version = get_pack_version_from_path(file_path)

        release_note = read_and_format_release_note(file_path)
        if release_note:
            release_notes_dict.setdefault(pack_name, {})[pack_version] = release_note
            print('Adding release notes for pack {} {}...'.format(pack_name, pack_version))
        else:
            print('Ignoring release notes for pack {} {}...'.format(pack_name, pack_version))

    return release_notes_dict


def generate_release_notes_summary(new_packs_release_notes, modified_release_notes_dict, version, asset_id,
                                   release_notes_file):
    """ Creates a release notes summary markdown file.

    Args:
        new_packs_release_notes (dict): A mapping from pack names to pack summary.
        modified_release_notes_dict (dict): A mapping from pack names to dictionaries of pack versions to release notes.
        version (str): Content version.
        asset_id (str): The asset ID.
        release_notes_file (str): release notes output file path

    Returns:
        (str). The release notes summary string.
    """
    current_date = datetime.now().strftime(DATE_FORMAT)
    release_notes = f'# Cortex XSOAR Content Release Notes for version {version} ({asset_id})\n' \
        f'##### Published on {current_date}\n'

    if new_packs_release_notes:
        release_notes += '## New Content\n'
        for pack_name, pack_summary in sorted(new_packs_release_notes.items()):
            release_notes += f'### {pack_name} Pack v1.0.0\n' \
                             f'{pack_summary}\n---\n\n'

    if modified_release_notes_dict:
        release_notes += '## Improved Content\n'
    for pack_name, pack_versions_dict in sorted(modified_release_notes_dict.items()):
        for pack_version, pack_release_notes in sorted(pack_versions_dict.items(),
                                                       key=lambda pack_item: LooseVersion(pack_item[0])):
            release_notes += f'### {pack_name} Pack v{pack_version}\n' \
                f'{pack_release_notes}\n---\n\n'

    if release_notes.endswith('---\n\n'):
        release_notes = release_notes[:-5]

    with open(release_notes_file, 'w') as outfile:
        outfile.write(release_notes)

    return release_notes


def get_release_notes_draft(github_token, asset_id):
    """
    if possible, download current release draft from content repository in github.

    :param github_token: github token with push permission (in order to get the draft).
    :param asset_id: content build's asset id.
    :return: draft text (or empty string on error).
    """
    if github_token is None:
        print_warning('Unable to download draft without github token.')
        return ''

    # Disable insecure warnings
    requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

    try:
        res = requests.get('https://api.github.com/repos/demisto/content/releases',
                           verify=False,  # guardrails-disable-line
                           headers={'Authorization': 'token {}'.format(github_token)})
    except requests.exceptions.ConnectionError as exc:
        print_warning(f'Unable to get release draft, reason:\n{str(exc)}')
        return ''

    if res.status_code != 200:
        print_warning(f'Unable to get release draft ({res.status_code}), reason:\n{res.text}')
        return ''

    drafts = [release for release in res.json() if release.get('draft', False)]
    if drafts:
        if len(drafts) == 1:
            draft_body = drafts[0]['body']
            raw_asset = re.findall(r'Release Notes for version .* \((\d{5,}|xxxxx)\)', draft_body, re.IGNORECASE)
            if raw_asset:
                draft_body = draft_body.replace(raw_asset[0], asset_id)

            return draft_body

        print_warning(f'Too many drafts to choose from ({len(drafts)}), skipping update.')

    return ''


def create_content_descriptor(release_notes, version, asset_id, github_token):
    # time format example 2017 - 06 - 11T15:25:57.0 + 00:00
    current_date = datetime.now().strftime(DATE_FORMAT)

    content_descriptor = {
        "installDate": "0001-01-01T00:00:00Z",
        "assetId": int(asset_id),
        "releaseNotes": release_notes,
        "modified": current_date,
        "ignoreGit": False,
        "releaseDate": current_date,
        "version": -1,
        "release": version,
        "id": ""
    }

    draft = get_release_notes_draft(github_token, asset_id)
    if draft:
        content_descriptor['releaseNotes'] = draft

    with open('content-descriptor.json', 'w') as outfile:
        json.dump(content_descriptor, outfile)


def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('version', help='Release version')
    arg_parser.add_argument('git_sha1', help='commit sha1 to compare changes with')
    arg_parser.add_argument('asset_id', help='Asset ID')
    arg_parser.add_argument('--output', help='Output file, default is ./packs-release-notes.md',
                            default='./packs-release-notes.md')
    arg_parser.add_argument('--github-token', help='Github token')
    args = arg_parser.parse_args()

    new_packs = get_new_packs(args.git_sha1)
    new_packs_release_notes = {}
    for pack in new_packs:
        pack_name = get_pack_name_from_metdata(pack)
        new_packs_release_notes[pack_name] = get_pack_entities(pack)

    modified_release_notes = get_all_modified_release_note_files(args.git_sha1)
    modified_release_notes_dict = get_release_notes_dict(modified_release_notes)
    release_notes = generate_release_notes_summary(new_packs_release_notes, modified_release_notes_dict,
                                                   args.version, args.asset_id, args.output)
    create_content_descriptor(release_notes, args.version, args.asset_id, args.github_token)


if __name__ == "__main__":
    main()
