#!/usr/bin/env python3
import sys
from github import Github
from blessings import Terminal
import argparse
import urllib3
from github.Repository import Repository
from github.PullRequest import PullRequest
from utils import timestamped_print, Checkout
from git import Repo
import os
from pathlib import Path
from demisto_sdk.commands.common.tools import get_pack_metadata, get_pack_name

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
print = timestamped_print

PARTNER_APPROVED_LABEL = 'Partner-Approved'


def arguments_handler():
    """ Validates and parses script arguments.

     Returns:
        Namespace: Parsed arguments object.
    """
    parser = argparse.ArgumentParser(description='Check if Partner-Approved label exists.')
    parser.add_argument('-p', '--pr_number', help='The PR number to check if the label exists.')
    parser.add_argument('-g', '--github_token', help='The GitHub token to authenticate the GitHub client.')
    return parser.parse_args()


def get_support_level(pack_dirs: set[str]) -> set[str]:
    """
    Get the pack support levels from the pack metadata.

    Args:
        pack_dirs (set): paths to the packs that were changed
    """
    packs_support_levels = set()

    for pack_dir in pack_dirs:
        if pack_support_level := get_pack_metadata(pack_dir).get('support'):
            print(f'Pack support level for pack {pack_dir} is {pack_support_level}')
            packs_support_levels.add(pack_support_level)
        else:
            print(f'Could not find pack support level for pack {pack_dir}')

    return packs_support_levels


def get_pack_support_level(file_paths: list[str], external_pr_branch: str) -> str:
    pack_dirs_to_check_support_levels_labels = set()

    for file_path in file_paths:
        try:
            if 'Packs' in file_path and (pack_name := get_pack_name(file_path)):
                pack_dirs_to_check_support_levels_labels.add(f'Packs/{pack_name}')
        except Exception as err:
            print(f'Could not retrieve pack name from file {file_path}, {err=}')

    print(f'{pack_dirs_to_check_support_levels_labels=}')

    # # we need to check out to the contributor branch in his forked repo in order to retrieve the files cause workflow
    # runs on demisto master while the contributions changes are on the contributors branch
    # print(
    #     f'Trying to checkout to forked branch {external_pr_branch} '
    #     f'to retrieve support level of {pack_dirs_to_check_support_levels_labels}'
    # )
    packs_support_levels = get_support_level(pack_dirs_to_check_support_levels_labels)
    # try:
    #     fork_owner = os.getenv('GITHUB_ACTOR')
    #     with Checkout(
    #         repo=Repo(Path().cwd(), search_parent_directories=True),
    #         branch_to_checkout=external_pr_branch,
    #         # in marketplace contributions the name of the owner should be xsoar-contrib
    #         fork_owner=fork_owner if fork_owner != 'xsoar-bot' else 'xsoar-contrib'
    #     ):
    #         packs_support_levels = get_support_level(pack_dirs_to_check_support_levels_labels)
    # except Exception as error:
    #     # in case we were not able to checkout correctly, fallback to the files in the master branch to retrieve support labels
    #     # in case those files exist.
    #     print(f'Received error when trying to checkout to {external_pr_branch} \n{error=}')
    #     print('Trying to retrieve support levels from the master branch')
    #     packs_support_levels = get_support_level(pack_dirs_to_check_support_levels_labels)

    return packs_support_levels

def main():
    options = arguments_handler()
    pr_number = options.pr_number
    github_token = options.github_token

    org_name = 'demisto'
    repo_name = 'content'

    github_client: Github = Github(github_token, verify=False)
    content_repo: Repository = github_client.get_repo(f'{org_name}/{repo_name}')
    pr: PullRequest = content_repo.get_pull(int(pr_number))
    t = Terminal()

    pr_label_names = [label.name for label in pr.labels]
    pr_files = [file.filename for file in pr.get_files()]
    print(f'pr files are {pr_files}')
    support_level = get_pack_support_level(pr_files, pr.head.ref)
    print (f'support level is: {support_level}')
    partner_approved = PARTNER_APPROVED_LABEL in pr_label_names

    if "partner" not in support_level:
        print("PR is not from partner, approving the flow and exiting")
        sys.exit(0)
    else:
        print(f'{t.cyan}Checking if {PARTNER_APPROVED_LABEL} label exist in PR {pr_number}')
        if not partner_approved:
            print(
                f'{t.red}ERROR: Label Partner-Approved was not added to PR: {pr_number}')
            sys.exit(1)

        print(f'{t.cyan}PR labels {pr_label_names} are valid for PR: {pr_number}')
        sys.exit(0)


if __name__ == "__main__":
    main()
