import sys
from github import Github
import argparse
import urllib3
from github.Repository import Repository
from github.PullRequest import PullRequest
from utils import timestamped_print

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
print = timestamped_print

SUPPORTED_MODULES_APPROVED_LABEL = "supported-modules-approved"


def arguments_handler():
    """Validates and parses script arguments.

    Returns:
       Namespace: Parsed arguments object.
    """
    parser = argparse.ArgumentParser(description="Check if supported-modules-approved label exists.")
    parser.add_argument("-p", "--pr_number", help="The PR number to check if the label exists.")
    parser.add_argument("-g", "--github_token", help="The GitHub token to authenticate the GitHub client.")
    return parser.parse_args()


def check_pr_contains_yml_or_json(pr: PullRequest) -> bool:
    """
    Check if the PR contains any YAML or JSON file changes.

    Args:
        pr: GitHub PullRequest object

    Returns:
        bool: True if PR contains YAML or JSON files, False otherwise
    """
    try:
        # Get the list of files changed in the PR
        files = pr.get_files()
        pr_contains_yml_or_json = False
        for file in files:
            if file.filename.lower().endswith(('.yml', '.yaml', '.json')):
                print(f"Found YAML/JSON file in PR: {file.filename}")
                pr_contains_yml_or_json = True
        return pr_contains_yml_or_json
    except Exception as e:
        print(f"Error checking PR files: {str(e)}")
        # Default to True to be safe if we can't check
        return True


def main():
    """
    This script is checking that "supported-modules-approved" label exists for a PR in case
    the label exists the workflow will pass, if the label is missing the workflow will fail.
    """
    options = arguments_handler()
    pr_number = options.pr_number
    github_token = options.github_token

    org_name = "demisto"
    repo_name = "content"

    github_client: Github = Github(github_token, verify=False)
    content_repo: Repository = github_client.get_repo(f"{org_name}/{repo_name}")
    pr: PullRequest = content_repo.get_pull(int(pr_number))

    pr_label_names = [label.name for label in pr.labels]

    supported_modules_approved = SUPPORTED_MODULES_APPROVED_LABEL in pr_label_names

    print(f"Checking if {SUPPORTED_MODULES_APPROVED_LABEL} label exist in PR {pr_number}")
    if not supported_modules_approved:

        # First check if the PR contains YAML or JSON files
        has_yml_or_json = check_pr_contains_yml_or_json(pr)
        if has_yml_or_json:
            print(
                f"❌ ERROR: Required label '{SUPPORTED_MODULES_APPROVED_LABEL}' is missing from PR #{pr_number}.\n"
                "   This PR contains YAML or JSON file changes that require PM review.\n"
                "   Please ask a Product Manager to review the changes and add the label if approved."
            )
            sys.exit(1)
        else:
            print(
                "ℹ️  PR does not contain any YAML or JSON file changes.\n"
                "   The 'supported-modules-approved' label is not required for this PR."
            )
            sys.exit(0)

    print(f"✅ PR #{pr_number} has the required label: {SUPPORTED_MODULES_APPROVED_LABEL}")
    sys.exit(0)


if __name__ == "__main__":
    main()
