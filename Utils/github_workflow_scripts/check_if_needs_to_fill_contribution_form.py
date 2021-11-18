#!/usr/bin/env python3

import argparse
import os
import sys
import re
import json
import base64
import urllib3
from github import Github
from github.PullRequest import PullRequest
from github.Repository import Repository
from github.ContentFile import ContentFile
from github.Branch import Branch

from utils import load_json, CONTENT_ROOT_PATH, timestamped_print

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
print = timestamped_print

METADATA = 'pack_metadata.json'
PACKS = 'Packs'
SUPPORT = 'support'
XSOAR_SUPPORT = 'xsoar'
PACK_NAME_REGEX = re.compile(r'Packs/([A-Za-z0-9-_.]+)/')


def get_metadata_filename_from_pr(pr_files, pack_name) -> str:
    """ Iterates over all pr files and return the pr metadata.json filename if exists, else None

    Args:
        pr_files (PaginatedList[File]): The list of pr files
        pack_name (str): The pack name

    Returns:
        The pr metadata.json filename if exists, else None

    """
    pack_metadata_path = os.path.join(PACKS, pack_name, METADATA)
    print(f'Searching for a {pack_metadata_path} file in the PR.')

    for file in pr_files:
        if pack_metadata_path in file.filename:
            print(f'Found {METADATA} file in PR for pack {pack_name}: {file.filename}.')
            return file.filename

    print(f'Did not find a {pack_metadata_path} file in the PR.')
    return ''


def get_pack_support_type_from_pr_metadata_file(pr_metadata_filename: str, pr: PullRequest):
    """ Retrieves the support type from the pr metadata.json file

    Args:
        pr_metadata_filename: The pr metadata.json filename
        pr: The pr

    Returns:
        The support type

    """
    print(f'Getting support type from {pr_metadata_filename}.')
    _, branch_name = pr.head.label.split(':')
    print(f'Branch name is: {branch_name}')
    contributor_repo: Repository = pr.head.repo
    branch: Branch = contributor_repo.get_branch(branch=branch_name)
    metadata_file: ContentFile = \
        contributor_repo.get_contents(path=pr_metadata_filename, ref=branch.commit.sha)  # type: ignore[assignment]
    metadata_file_content: dict = json.loads(base64.b64decode(metadata_file.content))  # type: ignore[arg-type]
    return metadata_file_content.get(SUPPORT)


def get_pack_names_from_pr(pr_files) -> set:
    """ Extracts the pack names from the pr files

    Args:
        pr_files (PaginatedList[File]): The list of pr files

    Returns:
        The set of pack names

    """
    pack_names = set()

    for file in pr_files:
        if PACKS in file.filename:
            pack_names.add(re.findall(PACK_NAME_REGEX, file.filename)[0])

    if not pack_names:
        raise Exception('PR does not contains files prefixed with "Packs".')

    return pack_names


def get_pack_support_type_from_repo_metadata_file(pack_name):
    """ Retrieves the support type from the repo metadata.json file

    Args:
        pack_name (str): The pack name

    Returns:
        The support type

    """
    print('Getting support type from the repo.')
    repo_pack_metadata_path: str = os.path.join(CONTENT_ROOT_PATH, PACKS, pack_name, METADATA)
    print(f'{pack_name} pack {METADATA} file is at path: {repo_pack_metadata_path}')
    repo_pack_metadata: dict = load_json(repo_pack_metadata_path)
    return repo_pack_metadata.get(SUPPORT)


def arguments_handler():
    """ Validates and parses script arguments.

     Returns:
        Namespace: Parsed arguments object.

     """
    parser = argparse.ArgumentParser(description='Check if the contribution form needs to be filled.')
    parser.add_argument('-p', '--pr_number', help='The PR number to check if the contribution form needs to be filled.')
    parser.add_argument('-g', '--github_token', help='The GitHub token to authenticate the GitHub client.')
    return parser.parse_args()


def main():
    options = arguments_handler()
    pr_number = options.pr_number
    github_token = options.github_token

    org_name: str = 'demisto'
    repo_name: str = 'content'
    exit_status = 0
    packs_without_metadata_or_support = set()
    not_filled_packs = set()

    github_client: Github = Github(github_token, verify=False)
    content_repo: Repository = github_client.get_repo(f'{org_name}/{repo_name}')
    pr: PullRequest = content_repo.get_pull(int(pr_number))
    pr_files = pr.get_files()

    for pack_name in get_pack_names_from_pr(pr_files):
        if pr_metadata_filename := get_metadata_filename_from_pr(pr_files, pack_name):
            support_type = get_pack_support_type_from_pr_metadata_file(pr_metadata_filename, pr)
        else:
            support_type = get_pack_support_type_from_repo_metadata_file(pack_name)

        if not support_type:
            packs_without_metadata_or_support.add(pack_name)
            exit_status = 1
        elif support_type == XSOAR_SUPPORT:
            print(f'\n{pack_name} pack is XSOAR supported. Contribution form should not be filled for XSOAR supported '
                  f'contributions.')
        else:
            not_filled_packs.add(pack_name)
            print(f'{pack_name} pack is {support_type} supported.')
            exit_status = 1

    if packs_without_metadata_or_support:
        print(f'ERROR: {METADATA} file / pack support is missing for the following packs: '
              f'{packs_without_metadata_or_support}')

    if not_filled_packs:
        print(f'\nERROR: Contribution form was not filled for PR: {pr_number}.\nMake sure to register your contribution'
              f' by filling the contribution registration form in - https://forms.gle/XDfxU4E61ZwEESSMA')

    sys.exit(exit_status)


if __name__ == "__main__":
    main()
