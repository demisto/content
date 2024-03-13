#!/usr/bin/env python3
import argparse
import os
import sys

import requests
import urllib3
from collections import namedtuple

urllib3.disable_warnings()


OWNER = "demisto"
REPO = "content"
GITHUB_TRIGGER_BUILD_LABEL = "ready-for-instance-test"
GITLAB_SERVER_URL = os.getenv(
    "CI_SERVER_URL", "https://gitlab.xdr.pan.local"
)  # disable-secrets-detection
GITHUB_SEARCH_REQUEST_ENDPOINT = "https://api.github.com/search/issues"
GITHUB_DELETE_LABEL_ENDPOINT = "https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}/labels/{label_name}"
GITHUB_QUERY_LABELS = {
    "label": ["Contribution", GITHUB_TRIGGER_BUILD_LABEL],
    "-label": ["Internal PR"],
}


def get_contribution_prs(github_token: str):
    """Get all contribution PRs with the relevant labels using a query.

    Args:
        github_token (str): The Github token.

    Returns:
        list[dicr]: A list of prs matching the query.
    """
    query_labels = " ".join(
        [
            f'{label}:"{item}"'
            for label, lst in GITHUB_QUERY_LABELS.items()
            for item in lst
        ]
    ).strip()

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {github_token}",
    }

    params = {"q": "is:pr state:open " + f"{query_labels}"}

    response = requests.get(
        GITHUB_SEARCH_REQUEST_ENDPOINT, headers=headers, params=params
    )

    if response.status_code == 200:
        return response.json()
    else:
        print(
            f"Trigger contribution build script failed with request status code: {response.status_code}"
        )
        sys.exit(1)


def delete_trigger_build_label_from_pr(github_token: str, pr: dict):
    issue_number = str(pr.get("number"))

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {github_token}",
    }

    response = requests.delete(
        GITHUB_DELETE_LABEL_ENDPOINT.format(
            owner=OWNER,
            repo=REPO,
            issue_number=issue_number,
            label_name=GITHUB_TRIGGER_BUILD_LABEL,
        ),
        headers=headers,
    )
    title = pr.get("title")
    if response.status_code == 200:
        print(
            f"{GITHUB_TRIGGER_BUILD_LABEL} label removed for PR number: {title}, issue number: {issue_number}"
        )
    else:
        print(
            f"Could not remove {GITHUB_TRIGGER_BUILD_LABEL} label for PR number: {title}, issue number: {issue_number}"
        )


def add_comment_to_contribution_pr(github_token: str, pr: dict):
    pass


def trigger_build_for_contribution_pr(gitlab_api_token: str, pr: dict):
    pass


def arguments_handler():
    """Validates and parses script arguments.

    Returns:
       Namespace: Parsed arguments object.

    """
    parser = argparse.ArgumentParser(description="Trigger contribution build.")
    parser.add_argument("--github-token", help="Github api token")
    parser.add_argument("--gitlab-api-token", help="Gitlab api token")
    return parser.parse_args()


def main():
    args = arguments_handler()
    response = get_contribution_prs(args.github_token)

    if items := response.get("items"):
        pr_numbers: list[str] = []
        for pr in items:
            trigger_build_for_contribution_pr(args.gitlab_api_token, pr)
            delete_trigger_build_label_from_pr(args.github_token, pr)
            add_comment_to_contribution_pr(args.github_token, pr)
            pr_numbers.append(str(pr.get("number")))
        print(f"Build triggered for the following contribution PRs: {pr_numbers}")
    else:
        print("No Contribution PRs builds were trigger.")
        return


if __name__ == "__main__":
    main()
