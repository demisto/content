import sys
from github import Github
import argparse
import urllib3
from github.Repository import Repository
from github.PullRequest import PullRequest
from utils import timestamped_print

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
print = timestamped_print

RESEARCH_MAPPING_APPROVED_LABEL = "research-mapping-approve"
RESEARCH_MAPPING_PACKS = {
    "VMwareVCenter",
    "VMwareESXi",
}


def arguments_handler():
    """Validates and parses script arguments.
    Returns:
       Namespace: Parsed arguments object.
    """
    parser = argparse.ArgumentParser(description="Check if research-mapping-approve label exists.")
    parser.add_argument("-p", "--pr_number", help="The PR number to check if the label exists.")
    parser.add_argument("-g", "--github_token", help="The GitHub token to authenticate the GitHub client.")
    parser.add_argument("-c", "--changed_files", nargs="*", help="The path of modified files")
    return parser.parse_args()


def main():
    """
    This script is checking that "research-mapping-approve" label exists for a PR in case
    the label exists the workflow will pass, if the label is missing the workflow will fail.
    """
    org_name = "demisto"
    repo_name = "content"
    options = arguments_handler()
    pr_number = options.pr_number
    github_token = options.github_token
    changed_files = options.changed_files

    github_client: Github = Github(github_token, verify=False)
    content_repo: Repository = github_client.get_repo(f"{org_name}/{repo_name}")
    pr: PullRequest = content_repo.get_pull(int(pr_number))

    pr_label_names = [label.name for label in pr.labels]
    research_mapping_approved = RESEARCH_MAPPING_APPROVED_LABEL in pr_label_names

    watched_folders = RESEARCH_MAPPING_PACKS
    watched_folders = {folder.lower() for folder in watched_folders if folder}
    # Detect if watched folder changed
    folder_changed = any(file.split("/")[1].lower() in watched_folders for file in changed_files)
    # Validation logic
    if folder_changed and not research_mapping_approved:
        print(
            f"❌ Missing {RESEARCH_MAPPING_APPROVED_LABEL} label: This pack has XSIAM content that requires research mapping "
            f"approval, please verify."
        )
        sys.exit(1)

    if not folder_changed and research_mapping_approved:
        print(f"❌ Label '{RESEARCH_MAPPING_APPROVED_LABEL}' added, but no changes found in research mapping packs")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
