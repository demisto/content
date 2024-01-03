#!/usr/bin/env python3

import argparse
import json
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# def has_file_changed(
#     repo_owner: str = "",
#     repo_name: str = "content",
#     files,
#     branch: str = "master",
#     access_token
# ):
#     api_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/commits/{branch}"

#     headers = {"Authorization": f"token {access_token}"} if access_token else {}

#     response = requests.get(api_url, headers=headers)
#     response.raise_for_status()

#     commit_details = response.json()

#     files_changed = commit_details.get("files", [])
#     return any(file["filename"] in files for file in files_changed)


def get_open_pull_requests(repo_owner, repo_name, access_token=None):
    api_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/pulls"

    headers = {"Authorization": f"token {access_token}"} if access_token else {}

    params = {"state": "open"}
    response = requests.get(api_url, headers=headers, params=params)
    response.raise_for_status()

    pull_requests = response.json()
    return pull_requests


def trigger_workflow(repo_owner, repo_name, workflow_name, access_token):
    api_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/dispatches"

    headers = {
        "Accept": "application/vnd.github.everest-preview+json",
        "Authorization": f"token {access_token}",
    }

    payload = {
        "event_type": "trigger-workflow-event",
        "client_payload": {
            "workflow_name": workflow_name,
        },
    }

    response = requests.post(api_url, headers=headers, json=payload)
    response.raise_for_status()

    print(f"Workflow triggered successfully. Status code: {response.status_code}")


def trigger_workflow_for_pr(
    repo_owner, repo_name, workflow_name, pr_name, access_token=None
):
    api_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/actions/workflows/{workflow_name}/dispatches"

    headers = (
        {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": f"Bearer {access_token}",
        }
        if access_token
        else {"Accept": "application/vnd.github.v3+json"}
    )

    payload = {
        "ref": pr_name,
    }

    response = requests.post(api_url, headers=headers, data=payload)
    response.raise_for_status()
    print("Workflow triggered successfully. Status code: 200")

    return response.json()


def arguments_handler():
    """Validates and parses script arguments.

    Returns:
       Namespace: Parsed arguments object.

    """
    parser = argparse.ArgumentParser(
        description="Triggers the pre-commit workflow for all PRs that are open when infrastructure files are merged into master."
    )
    parser.add_argument(
        "-g",
        "--github_token",
        help="The GitHub token to authenticate the GitHub client.",
    )
    return parser.parse_args()


def main():
    options = arguments_handler()
    print(f"aaaaaaaaaaaaaaaaaaaa0000000{options.github_token}")
    trigger_workflow_for_pr(
        "demisto",
        "content",
        "pre-commit-reuse.yml",
        "workflow_trigger_when_infrastructure_are_changed",
        options.github_token,
    )


if __name__ == "__main__":
    main()
