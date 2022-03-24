#!/usr/bin/env python3

import argparse
import sys
import urllib3
from blessings import Terminal
from github import Github
from github.PullRequest import PullRequest
from github.Repository import Repository


from utils import timestamped_print

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
print = timestamped_print

CONTRIBUTION_FORM_FILLED_LABEL = 'Contribution Form Filled'
COMMUNITY_LABEL = 'Community'
PARTNER_LABEL = 'Partner'
INTERNAL_LABEL = 'Internal'


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

    org_name = 'demisto'
    repo_name = 'content'
    exit_status = 0

    github_client: Github = Github(github_token, verify=False)
    content_repo: Repository = github_client.get_repo(f'{org_name}/{repo_name}')
    pr: PullRequest = content_repo.get_pull(int(pr_number))
    t = Terminal()

    pr_label_names = [label.name for label in pr.labels]

    is_contribution_form_filled_label_exist = CONTRIBUTION_FORM_FILLED_LABEL in pr_label_names
    is_community_label_exist = COMMUNITY_LABEL in pr_label_names
    is_partner_label_exist = PARTNER_LABEL in pr_label_names
    is_internal_label_exist = INTERNAL_LABEL in pr_label_names

    print(f'{t.cyan}Check that {CONTRIBUTION_FORM_FILLED_LABEL} label exist in PR {pr_number}')
    if not is_contribution_form_filled_label_exist:
        print(
            f'\n{t.red}ERROR: Contribution form was not filled for PR: {pr_number}.\nMake sure to register your'
            f' contribution by filling the contribution registration form in - https://forms.gle/XDfxU4E61ZwEESSMA'
        )
        exit_status = 1

    print(f'{t.cyan}Check that one of Community/Partner/Internal labels exist in PR {pr_number}')
    if not (is_community_label_exist ^ is_partner_label_exist ^ is_internal_label_exist):
        print(
            f'{t.red}ERROR: PR labels {pr_label_names} '
            f'must contain one of {COMMUNITY_LABEL}/{PARTNER_LABEL}/{INTERNAL_LABEL} labels'
        )
        exit_status = 1

    print(f'{t.cyan}PR labels {pr_label_names} are valid')
    print(f'{t.cyan} Contribution form was filled successfully for PR: {pr_number}')
    sys.exit(exit_status)


if __name__ == "__main__":
    main()
