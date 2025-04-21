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

DOCS_APPROVED_LABEL = 'docs-approved'


def arguments_handler():
    """ Validates and parses script arguments.

     Returns:
        Namespace: Parsed arguments object.
    """
    parser = argparse.ArgumentParser(description='Check if docs-approved label exists.')
    parser.add_argument('-p', '--pr_number', help='The PR number to check if the label exists.')
    parser.add_argument('-g', '--github_token', help='The GitHub token to authenticate the GitHub client.')
    return parser.parse_args()


def main():
    """
    This script is checking that "docs-approved" label exists for a PR in case
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
    docs_approved = DOCS_APPROVED_LABEL in pr_label_names

    print(f'{t.cyan}Checking if {DOCS_APPROVED_LABEL} label exist in PR {pr_number}')
    if not docs_approved:
        print(
            f'{t.red}ERROR: Label docs-approved was not added to PR: {pr_number}. Please ask the owner to review'
            f' the documentation and add the label after his approval.')
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
