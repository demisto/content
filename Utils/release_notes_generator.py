import re
import os
import sys
import json
import glob
import argparse
from datetime import datetime
from typing import Dict, Tuple
import logging

from distutils.version import LooseVersion
import requests
from demisto_sdk.commands.common.tools import run_command, get_dict_from_file
from Tests.scripts.utils.log_util import install_logging

PACKS_DIR = 'Packs'
DATE_FORMAT = '%d %B %Y'
PACK_METADATA = 'pack_metadata.json'
PACKS_RN_FILES_FORMAT = '*/ReleaseNotes/*.md'

EMPTY_LINES_REGEX = re.compile(r'\s*-\s*\n')
IGNORED_LINES_REGEX = re.compile(r'<!-[\W\w]*?-->')
ENTITY_TYPE_SECTION_REGEX = re.compile(r'^#### ([\w ]+)$\n([\w\W]*?)(?=^#### )|^#### ([\w ]+)$\n([\w\W]*)', re.M)
ENTITY_SECTION_REGEX = re.compile(r'^##### (.+)$\n([\w\W]*?)(?=^##### )|^##### (.+)$\n([\w\W]*)|'
                                  r'^- \*\*(.+)\*\*$\n([\w\W]*)', re.M)

LAYOUT_TYPE_TO_NAME = {
    "details": "Summary",
    "edit": "New/Edit",
    "close": "Close",
    "quickView": "Quick View",
    "indicatorsDetails": "Indicator Details",
    "mobile": "Mobile",
}


def get_new_packs(git_sha1):
    """
    Gets all the existing modified/added file paths in the format */ReleaseNotes/*.md.

    Args:
        git_sha1 (str): The branch to make the diff with.

    Returns:
        (list) A list of the new/modified release notes file paths.
    """
    diff_cmd = f'git diff --diff-filter=A --name-only {git_sha1} */{PACK_METADATA}'
    try:
        diff_result = run_command(diff_cmd, exit_on_error=False)
    except RuntimeError:
        logging.critical(
            'Unable to get the SHA1 of the commit in which the version was released. This can happen if your '
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


def get_new_entity_record(entity_path: str) -> Tuple[str, str]:
    data, _ = get_dict_from_file(entity_path)

    if 'layouts' in entity_path.lower():
        layout_kind = LAYOUT_TYPE_TO_NAME.get(data.get('kind', ''))
        type_id = data.get('typeId', '')
        return f'{type_id} - {layout_kind}', ''

    name = data.get('name', entity_path)
    if 'integrations' in entity_path.lower() and data.get('display'):
        name = data.get('display')

    if 'classifiers' in entity_path.lower():
        name = data.get('name')
        if not name:
            name = data.get('brandName')

    if name == entity_path:
        logging.error(f'missing name for {entity_path}')

    # script entities has "comment" instead of "description"
    description = data.get('description', '') or data.get('comment', '')
    if not description:
        logging.warning(f'missing description for {entity_path}')

    return name, description


def construct_entities_block(entities_data: dict) -> str:
    """
    convert entities information to a pack release note block

    Args:
        entities_data (dict): dictionary of the form:
            {
                Integrations: {
                    Integration1: <description>,
                    Integration2:<description>,
                },
                Scripts: {
                    Script1:<description>,
                    Script2:<description>,
                },
                ...
            }

    Returns:
        release note block string

    """
    release_notes = ''
    for entity_type, entities_description in sorted(entities_data.items()):
        pretty_entity_type = re.sub(r'(\w)([A-Z])', r'\1 \2', entity_type)
        release_notes += f'#### {pretty_entity_type}\n'
        for name, description in entities_description.items():
            if entity_type in ('Connections', 'IncidentTypes', 'IndicatorTypes', 'Layouts', 'IncidentFields',
                               'Incident Types', 'Indicator Types', 'Incident Fields'):
                release_notes += f'- **{name}**\n{description}\n'
            else:
                release_notes += f'##### {name}\n{description}\n'

    return release_notes


def get_pack_entities(pack_path):
    logging.info(f'Processing "{pack_path}" files:')
    pack_entities = sum([
        glob.glob(f'{pack_path}/*/*.json'),
        glob.glob(f'{pack_path}/*/*.yml'),
        glob.glob(f'{pack_path}/*/*/*.yml')], [])
    pack_entities.sort()

    entities_data: Dict = {}
    for entity_path in pack_entities:
        # ignore test files
        if 'test' in entity_path.lower():
            logging.info(f'skipping test file: {entity_path}')
            continue

        match = re.match(f'{pack_path}/([^/]*)/.*', entity_path)
        if match:
            entity_type = match.group(1)
        else:
            # should not get here
            entity_type = 'Extras'

        name, description = get_new_entity_record(entity_path)
        entities_data.setdefault(entity_type, {})[name] = description

    release_notes = construct_entities_block(entities_data)

    logging.info('Finished processing pack')
    return release_notes


def get_all_modified_release_note_files(git_sha1):
    """
    Gets all the existing modified/added file paths in the format */ReleaseNotes/*.md.

    Args:
        git_sha1 (str): The branch to make the diff with.

    Returns:
        (list) A list of the new/modified release notes file paths.
    """
    diff_cmd = f'git diff --diff-filter=AM --name-only {git_sha1} {PACKS_RN_FILES_FORMAT}'
    try:
        diff_result = run_command(diff_cmd, exit_on_error=False)
    except RuntimeError:
        logging.critical(
            'Unable to get the SHA1 of the commit in which the version was released. This can happen if your '
            'branch is not updated with origin master. Merge from origin master and, try again.\n'
            'If you\'re not on a fork, run "git merge origin/master".\n'
            'If you are on a fork, first set https://github.com/demisto/content to be '
            'your upstream by running "git remote add upstream https://github.com/demisto/content". After '
            'setting the upstream, run "git fetch upstream", and then run "git merge upstream/master". Doing '
            'these steps will merge your branch with content master as a base.')
        sys.exit(1)

    release_notes_files = [file_path for file_path in diff_result.split('\n')
                           if file_path.startswith(PACKS_DIR)]
    return release_notes_files


def get_pack_metadata(pack_path):
    pack_metadata_path = os.path.join(pack_path, PACK_METADATA)
    with open(pack_metadata_path, 'r') as json_file:
        pack_metadata = json.load(json_file)

    return pack_metadata


def is_support_type_in_metadata(metadata, support_type):
    return metadata and metadata.get('support') == support_type


def is_partner_supported_in_metadata(metadata):
    return is_support_type_in_metadata(metadata, 'partner')


def is_community_supported_in_metadata(metadata):
    return is_support_type_in_metadata(metadata, 'community')


def get_pack_path_from_release_note(file_path):
    match = re.search(r'(.*)/ReleaseNotes/.*', file_path)
    if match:
        return match.group(1)

    raise ValueError('Pack name was not found for file path {}'.format(file_path))


def get_pack_version_from_path(file_path):
    # example: from file path `<path>/1_0_1.md`, the next line will produce `1.0.1`
    pack_version = os.path.basename(os.path.splitext(file_path)[0]).replace('_', '.')
    return pack_version


def read_and_format_release_note(rn_file):
    with open(rn_file, 'r') as stream:
        release_notes = stream.read()

    release_notes = EMPTY_LINES_REGEX.sub('', release_notes)
    release_notes = IGNORED_LINES_REGEX.sub('', release_notes)

    return release_notes.strip()


def get_release_notes_dict(release_notes_files):
    """ Gets a dictionary that holds the new/modified release notes content.

    Args:
        release_notes_files (list): A list of the new/modified release notes file paths.

    Returns:
        (dict) A mapping from pack names to dictionaries of pack versions to release notes.
        (dict) A mapping from pack name to the pack metadata object
    """
    release_notes_dict = {}
    packs_metadata_dict = {}
    for file_path in release_notes_files:
        pack_path = get_pack_path_from_release_note(file_path)
        pack_metadata = get_pack_metadata(pack_path)
        pack_name = pack_metadata.get('name')
        packs_metadata_dict[pack_name] = pack_metadata
        pack_version = get_pack_version_from_path(file_path)

        release_note = read_and_format_release_note(file_path)
        if release_note:
            release_notes_dict.setdefault(pack_name, {})[pack_version] = release_note
            logging.info('Adding release notes for pack {} {}...'.format(pack_name, pack_version))
        else:
            logging.info('Ignoring release notes for pack {} {}...'.format(pack_name, pack_version))

    return release_notes_dict, packs_metadata_dict


def aggregate_release_notes_for_marketplace(pack_versions_dict: dict):
    """
    merge several pack release note versions into a single block - marketplace format.

    Args:
        pack_versions_dict: a mapping from a pack version to a release notes file content.

    Returns:
        a single pack release note block

    """
    pack_release_notes, _ = merge_version_blocks(pack_versions_dict)
    pack_release_notes = f'{pack_release_notes}\n' if not pack_release_notes.endswith('\n') else pack_release_notes
    pack_release_notes = f'\n{pack_release_notes}' if not pack_release_notes.startswith('\n') else pack_release_notes
    return pack_release_notes


def aggregate_release_notes(pack_name: str, pack_versions_dict: dict, pack_metadata: dict):
    """
    merge several pack release note versions into a single block.

    Args:
        pack_name: pack name
        pack_versions_dict: a mapping from a pack version to a release notes file content.
        pack_metadata: the pack metadata contents

    Returns:
        a single pack release note block

    """
    pack_release_notes, latest_version = merge_version_blocks(pack_versions_dict)
    pack_version_title = latest_version
    if is_partner_supported_in_metadata(pack_metadata):
        pack_version_title += ' (Partner Supported)'
    elif is_community_supported_in_metadata(pack_metadata):
        pack_version_title += ' (Community Contributed)'
    return (f'### {pack_name} Pack v{pack_version_title}\n'
            f'{pack_release_notes}')


def merge_version_blocks(pack_versions_dict: dict) -> Tuple[str, str]:
    """
    merge several pack release note versions into a single block.

    Args:
        pack_versions_dict: a mapping from a pack version to a release notes file content.

    Returns:
        str: a single pack release note block
        str: the pack's latest version

    """
    latest_version = '1.0.0'
    entities_data = {}
    for pack_version, version_release_notes in sorted(pack_versions_dict.items(),
                                                      key=lambda pack_item: LooseVersion(pack_item[0])):
        latest_version = pack_version
        version_release_notes = version_release_notes.strip()
        # extract release notes sections by content types (all playbooks, all scripts, etc...)
        # assuming all entity titles start with level 4 header ("####") and then a list of all comments
        sections = ENTITY_TYPE_SECTION_REGEX.findall(version_release_notes)
        for section in sections:
            # one of scripts, playbooks, integrations, layouts, incident fields, etc...
            entity_type = section[0] or section[2]
            # blocks of entity name and related release notes comments
            entity_section = section[1] or section[3]
            entities_data.setdefault(entity_type, {})

            # extract release notes comments by entity
            # assuming all entity titles start with level 5 header ("#####") and then a list of all comments
            entity_comments = ENTITY_SECTION_REGEX.findall(entity_section)
            for entity in entity_comments:
                # name of the script, integration, playbook, etc...
                entity_name = entity[0] or entity[2] or entity[4]
                entity_name = entity_name.replace('__', '')
                # release notes of the entity
                entity_comment = entity[1] or entity[3] or entity[5]
                if entity_name in entities_data[entity_type]:
                    entities_data[entity_type][entity_name] += f'{entity_comment.strip()}\n'
                else:
                    entities_data[entity_type][entity_name] = f'{entity_comment.strip()}\n'

    pack_release_notes = construct_entities_block(entities_data).strip()

    return pack_release_notes, latest_version


def generate_release_notes_summary(new_packs_release_notes, modified_release_notes_dict, packs_metadata_dict, version,
                                   asset_id, release_notes_file):
    """ Creates a release notes summary markdown file.

    Args:
        new_packs_release_notes (dict): A mapping from pack names to pack summary.
        modified_release_notes_dict (dict): A mapping from pack names to dictionaries of pack versions to release notes.
        packs_metadata_dict (dict): A mapping from pack names to the packs metadata
        version (str): Content version.
        asset_id (str): The asset ID.
        release_notes_file (str): release notes output file path

    Returns:
        (str). The release notes summary string.
    """
    current_date = datetime.now().strftime(DATE_FORMAT)
    release_notes = f'# Cortex XSOAR Content Release Notes for version {version} ({asset_id})\n' \
        f'##### Published on {current_date}\n'

    pack_rn_blocks = []
    for pack_name, pack_summary in sorted(new_packs_release_notes.items()):
        pack_metadata = packs_metadata_dict[pack_name]
        partner = ' (Partner Supported)' if is_partner_supported_in_metadata(pack_metadata) else ''
        pack_rn_blocks.append(f'### New: {pack_name} Pack v1.0.0{partner}\n'
                              f'{pack_summary}')

    for pack_name, pack_versions_dict in sorted(modified_release_notes_dict.items()):
        pack_metadata = packs_metadata_dict[pack_name]
        pack_rn_blocks.append(aggregate_release_notes(pack_name, pack_versions_dict, pack_metadata))
        # for pack_version, pack_release_notes in sorted(pack_versions_dict.items(),
        #                                                key=lambda pack_item: LooseVersion(pack_item[0])):
        #     pack_rn_blocks.append(f'### {pack_name} Pack v{pack_version}\n'
        #                           f'{pack_release_notes.strip()}')

    release_notes += '\n\n---\n\n'.join(pack_rn_blocks)

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
        logging.warning('Unable to download draft without github token.')
        return ''

    # Disable insecure warnings
    requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

    try:
        res = requests.get('https://api.github.com/repos/demisto/content/releases',
                           verify=False,  # guardrails-disable-line
                           headers={'Authorization': 'token {}'.format(github_token)})
    except requests.exceptions.ConnectionError as exc:
        logging.warning(f'Unable to get release draft, reason:\n{str(exc)}')
        return ''

    if res.status_code != 200:
        logging.warning(f'Unable to get release draft ({res.status_code}), reason:\n{res.text}')
        return ''

    drafts = [release for release in res.json() if release.get('draft', False)]
    if drafts:
        if len(drafts) == 1:
            draft_body = drafts[0]['body']
            raw_asset = re.findall(r'Release Notes for version .* \((\d{5,}|xxxxx)\)', draft_body, re.IGNORECASE)
            if raw_asset:
                draft_body = draft_body.replace(raw_asset[0], asset_id)

            return draft_body

        logging.warning(f'Too many drafts to choose from ({len(drafts)}), skipping update.')

    return ''


def create_content_descriptor(release_notes, version, asset_id, github_token):
    # time format example 2017 - 06 - 11T15:25:57.0 + 00:00
    current_date = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.0+00:00")

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
    install_logging('Build_Content_Descriptor.log')
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
    new_packs_metadata = {}
    for pack in new_packs:
        pack_metadata = get_pack_metadata(pack)
        pack_name = pack_metadata.get('name')
        new_packs_release_notes[pack_name] = get_pack_entities(pack)
        new_packs_metadata[pack_name] = pack_metadata

    packs_metadata_dict = {}
    modified_release_notes = get_all_modified_release_note_files(args.git_sha1)
    modified_release_notes_dict, modified_packs_metadata = get_release_notes_dict(modified_release_notes)
    packs_metadata_dict.update(new_packs_metadata)
    packs_metadata_dict.update(modified_packs_metadata)
    release_notes = generate_release_notes_summary(new_packs_release_notes, modified_release_notes_dict,
                                                   packs_metadata_dict, args.version, args.asset_id, args.output)
    create_content_descriptor(release_notes, args.version, args.asset_id, args.github_token)


if __name__ == "__main__":
    main()
