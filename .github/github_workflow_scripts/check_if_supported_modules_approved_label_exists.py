import sys
from github import Github
import argparse
import urllib3
from github.Repository import Repository
from github.PullRequest import PullRequest
from utils import timestamped_print
import yaml
import json
from typing import Any
import requests

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


def parse_yml_or_json(content: str, file_path: str) -> dict[str, Any] | None:
    """
    Parse YAML or JSON content into a Python dictionary.

    Args:
        content: File content as string
        file_path: Path of the file (for error reporting)

    Returns:
        Parsed content as dictionary or None if parsing fails
    """
    try:
        if file_path.lower().endswith((".yml", ".yaml")):
            return yaml.safe_load(content)
        elif file_path.lower().endswith(".json"):
            return json.loads(content)
    except (yaml.YAMLError, json.JSONDecodeError) as e:
        print(f"Warning: Failed to parse {file_path}: {str(e)}")
    return None


def has_supported_modules_field(file_content: dict[str, Any]) -> bool:
    """
    Recursively check if the dictionary contains a 'supportedModules' field.

    Args:
        file_content: Parsed YAML/JSON content as dictionary

    Returns:
        bool: True if 'supportedModules' field is found, False otherwise
    """
    if isinstance(file_content, dict):
        if "supportedModules" in file_content:
            return True
        for value in file_content.values():
            if has_supported_modules_field(value):
                return True
    elif isinstance(file_content, list):
        for item in file_content:
            if has_supported_modules_field(item):
                return True
    return False


def check_pr_contains_supported_modules(pr: PullRequest) -> bool:
    """
    Check if the PR contains any YAML or JSON files with 'supportedModules' field.

    Args:
        pr: GitHub PullRequest object

    Returns:
        bool: True if PR contains files with 'supportedModules' field, False otherwise
    """
    try:
        files = pr.get_files()
        for file in files:
            if not file.filename.lower().endswith((".yml", ".yaml", ".json")):
                continue

            try:
                # Get the file content
                response = requests.get(file.raw_url, timeout=10)
                response.raise_for_status()
                content = response.text

                # Parse the content
                parsed_content = parse_yml_or_json(content, file.filename)
                if parsed_content is None:
                    continue

                # Check for supportedModules field
                if has_supported_modules_field(parsed_content):
                    print(f"Found 'supportedModules' in file: {file.filename}")
                    return True

            except Exception as e:
                print(f"Warning: Error processing {file.filename}: {str(e)}")
                continue

        return False

    except Exception as e:
        print(f"Error checking PR files: {str(e)}")
        return True  # Default to True to be safe if we can't check


def get_file_diff(pr: PullRequest, file_path: str) -> str:
    """
    Get the unified diff for a specific file in the PR.

    Args:
        pr: GitHub PullRequest object
        file_path: Path of the file to get diff for

    Returns:
        str: Unified diff string or empty string if not found
    """
    try:
        # Get the specific file's diff
        for file in pr.get_files():
            if file.filename == file_path:
                return file.patch or ""
        return ""
    except Exception as e:
        print(f"Warning: Could not get diff for {file_path}: {str(e)}")
        return ""


def is_supported_modules_modified(pr: PullRequest, file_path: str) -> bool:
    """
    Check if the 'supportedModules' field or its contents were modified in the PR.

    Args:
        pr: GitHub PullRequest object
        file_path: Path of the file to check

    Returns:
        bool: True if 'supportedModules' or its contents were modified, False otherwise
    """

    # Get file extension
    file_ext = file_path[file_path.rfind(".") :].lower()
    if file_ext not in (".yaml", ".yml", ".json"):
        return False

    # Get the file content before and after the PR
    try:
        repo = pr.base.repo
        base_sha = pr.base.sha
        head_sha = pr.head.sha

        # Get base version (before PR)
        base_content = repo.get_contents(file_path, ref=base_sha).decoded_content.decode("utf-8")
        base_data = parse_yml_or_json(base_content, file_path)

        # Get head version (after PR)
        head_content = repo.get_contents(file_path, ref=head_sha).decoded_content.decode("utf-8")
        head_data = parse_yml_or_json(head_content, file_ext)

        if not base_data or not head_data:
            return False

        # Compare the supportedModules field
        base_modules = base_data.get("supportedModules", [])
        head_modules = head_data.get("supportedModules", [])

        # Convert to sets for comparison
        base_set = set(base_modules) if isinstance(base_modules, list) else set()
        head_set = set(head_modules) if isinstance(head_modules, list) else set()
        # Check if there are any differences
        return base_set != head_set

    except Exception as e:
        print(f"Error comparing file {file_path}: {str(e)}")
        return False


def check_pr_contains_supported_modules_changes(pr: PullRequest) -> bool:
    """
    Check if the PR contains any changes to 'supportedModules' field in YAML/JSON files.
    This includes new files that contain 'supportedModules' field.

    Args:
        pr: GitHub PullRequest object

    Returns:
        bool: True if PR contains changes to 'supportedModules' field, False otherwise
    """
    try:
        files = pr.get_files()
        modified_files = []

        for file in files:
            if not file.filename.lower().endswith((".yml", ".yaml", ".json")):
                continue

            try:
                # For new files, just check if they contain supportedModules
                if file.status == "added":
                    response = requests.get(file.raw_url, timeout=10)
                    response.raise_for_status()
                    content = response.text
                    parsed_content = parse_yml_or_json(content, file.filename)
                    if parsed_content and has_supported_modules_field(parsed_content):
                        modified_files.append(f"- New file with 'supportedModules': {file.filename}")
                # For modified files, check if supportedModules was modified
                elif file.status == "modified":
                    if is_supported_modules_modified(pr, file.filename):
                        modified_files.append(f"- Modified 'supportedModules' in file: {file.filename}")

            except Exception as e:
                print(f"Warning: Error processing {file.filename}: {str(e)}")
                continue

        # If we found any modified files, print all of them and return True
        if modified_files:
            print("\nThe following files have changes to 'supportedModules':")
            for msg in modified_files:
                print(msg)
            print("\nThis PR modifies the 'supportedModules' field which requires PM review.")
            return True

        return False

    except Exception as e:
        print(f"Error checking PR files: {str(e)}")
        return True  # Default to True to be safe if we can't check


def main():
    """
    This script is checking that "supported-modules-approved" label exists for a PR (if needed), in case
    the label exists the workflow will pass, if the label is missing (and needed) the workflow will fail.
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
        # Check if the PR contains changes to 'supportedModules' field
        has_supported_modules_changes = check_pr_contains_supported_modules_changes(pr)

        if has_supported_modules_changes:
            print(
                f"ERROR: Required label '{SUPPORTED_MODULES_APPROVED_LABEL}' is missing from PR #{pr_number}.\n"
                "   This PR modifies the 'supportedModules' field which requires PM review.\n"
                "   Please ask a Product Manager to review the changes and add the label if approved."
            )
            sys.exit(1)
        else:
            print(
                "INFO: PR does not modify any 'supportedModules' fields.\n"
                "   The 'supported-modules-approved' label is not required for this PR."
            )
            sys.exit(0)

    print(f"SUCCESS: PR #{pr_number} has the required label: {SUPPORTED_MODULES_APPROVED_LABEL}")
    sys.exit(0)


if __name__ == "__main__":
    main()
