#!/usr/bin/env python3
import sys
from github import Github
from blessings import Terminal
import argparse
import urllib3
from github.Repository import Repository
from github.PullRequest import PullRequest
from utils import timestamped_print

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

    partner_approved = PARTNER_APPROVED_LABEL in pr_label_names

    print(f'{t.cyan}Checking if {PARTNER_APPROVED_LABEL} label exist in PR {pr_number}')
    if not partner_approved:
        print(
            f'{t.red}ERROR: Label Partner-Approved was not added to PR: {pr_number}')
        sys.exit(1)

    print(f'{t.cyan}PR labels {pr_label_names} are valid for PR: {pr_number}')
    sys.exit(0)


if __name__ == "__main__":
    main()