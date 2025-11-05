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
                print(f"⚠️  Warning: Error processing {file.filename}: {str(e)}")
                continue

        return False

    except Exception as e:
        print(f"⚠️  Error checking PR files: {str(e)}")
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
        print(f"⚠️  Warning: Could not get diff for {file_path}: {str(e)}")
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
    diff = get_file_diff(pr, file_path)
    if not diff:
        return False

    # First check if the 'supportedModules' field itself was modified
    if any(line.strip().startswith(('+', '-')) and 'supportedModules' in line for line in diff.split('\n')):
        return True

    # Then check for modifications inside the array
    in_supported_modules = False
    lines = diff.split('\n')

    for line in lines:
        line = line.strip()

        # Check if we're entering the supportedModules section
        if 'supportedModules' in line and ':' in line:
            in_supported_modules = True
            continue

        # If we're in the supportedModules section, check for any modifications
        if in_supported_modules:
            # If we hit a line that's not part of the array (new top-level key), we're done
            if line.startswith(('  ', '\t')) and all(
                c not in line for c in '[]{}'
            ):
                continue
            if line.startswith(('+', '-', ' ')) and any(c in line for c in ['[', ']', '- ']):
                # Check if this is a modification to the array elements
                if any(x in line for x in ['+', '-']):
                    # Skip the opening bracket line if it's just the bracket
                    if line.strip() in ('+[', '-[', '+ [', '- [', ']', '+]', '-]'):
                        continue
                    # Check if this is a real modification to the array elements
                    if any(x in line for x in ['"', "'"]):
                        return True
            elif line.startswith(('+', '-')):
                # If we hit a line that's not part of the array, we're done
                break

    return False


def check_pr_contains_supported_modules_changes(pr: PullRequest) -> bool:
    """
    Check if the PR contains any changes to 'supportedModules' field in YAML/JSON files.

    Args:
        pr: GitHub PullRequest object

    Returns:
        bool: True if PR contains changes to 'supportedModules' field, False otherwise
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

                # Check if file contains supportedModules
                if has_supported_modules_field(parsed_content) and is_supported_modules_modified(pr, file.filename):
                    print(f"Found modified 'supportedModules' in file: {file.filename}")
                    return True

            except Exception as e:
                print(f"Warning: Error processing {file.filename}: {str(e)}")
                continue

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
