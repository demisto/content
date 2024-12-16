#!/usr/bin/env python3
import sys
from github import Github
from blessings import Terminal
import argparse
import urllib3
from github.Repository import Repository
from github.PullRequest import PullRequest
from demisto_sdk.commands.common.tools import get_pack_name
from utils import timestamped_print, get_support_level

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


def get_pack_support_level(file_paths: list[str]) -> set[str]:
    """
    :param file_paths: The paths of files modified in PR
    :return: pack support level
    """
    pack_dirs_to_check_support_levels_labels = set()

    for file_path in file_paths:
        try:
            if 'Packs' in file_path and (pack_name := get_pack_name(file_path)):
                pack_dirs_to_check_support_levels_labels.add(f'Packs/{pack_name}')
        except Exception as err:
            print(f'Could not retrieve pack name from file {file_path}, {err=}')

    print(f'{pack_dirs_to_check_support_levels_labels=}')
    packs_support_levels = get_support_level(pack_dirs_to_check_support_levels_labels)
    return packs_support_levels


def main():
    """
    This script is checking that "partner-approved" label exists for a PR in case
    the label exists the workflow will pass, if the label is missing the workflow will fail.
    """
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
    support_level = get_pack_support_level(pr_files)
    print(f'support level is: {support_level}')
    partner_approved = PARTNER_APPROVED_LABEL in pr_label_names

    if "partner" not in support_level:
        print("PR doesn't include changes in partner-supported packs, approving the flow and exiting")
        sys.exit(0)
    else:  # PR contains changes in Partner-supported packs
        print(f'{t.cyan}Checking if {PARTNER_APPROVED_LABEL} label exist in PR {pr_number}')
        if not partner_approved:
            print(
                f'{t.red}ERROR: Label Partner-Approved was not added to PR: {pr_number}. Please ask the partner to review'
                f' the code and add the label after his approval.')
            sys.exit(1)

        print(f'{t.cyan}PR labels {pr_label_names} are valid for PR: {pr_number}')
        sys.exit(0)


if __name__ == "__main__":
    main()
