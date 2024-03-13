#!/usr/bin/env python3
import argparse
import os
import sys
from collections import namedtuple

import requests
import urllib3

urllib3.disable_warnings()


OWNER = "demisto"
REPO = "content"
GITHUB_TRIGGER_BUILD_LABEL = "ready-for-instance-test"
GITLAB_SERVER_URL = os.getenv(
    "CI_SERVER_URL", "https://gitlab.xdr.pan.local"
)  # disable-secrets-detection
GITHUB_SEARCH_REQUEST_ENDPOINT = "https://api.github.com/search/issues"
GITHUB_DELETE_LABEL_ENDPOINT = "https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}/labels/{label_name}"
GITHUB_POST_COMMENT_ENDPOINT = (
    "https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}/comments"
)
GITHUB_QUERY_LABELS = {
    "label": ["Contribution", GITHUB_TRIGGER_BUILD_LABEL],
    "-label": ["Internal PR"],
}

MESSAGES = namedtuple(
    "MESSAGES",
    ["build_request_accepted", "build_triggered", "cant_trigger_build"],
)
PR_COMMENT_MESSAGES = MESSAGES(
    "For the Reviewer: Trigger build request has been accepted and will be handled in the next polling.",
    "For the Reviewer: Successfully created a pipeline in Gitlab with url: {url}",
    "For the Reviewer: Build was not triggered for this PR since a current pipeline already running.",
)


def get_contribution_prs(github_request_headers: dict[str, str]):
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

    params = {"q": "is:pr state:open " + f"{query_labels}"}

    response = requests.get(
        GITHUB_SEARCH_REQUEST_ENDPOINT, headers=github_request_headers, params=params
    )

    if response.status_code == 200:
        return response.json()
    else:
        print(
            f"Trigger contribution build script failed with request status code: {response.status_code}"
        )
        sys.exit(1)


def delete_label_from_contribution_pr(github_request_headers: dict[str, str], pr: dict):
    issue_number = str(pr.get("number"))

    response = requests.delete(
        GITHUB_DELETE_LABEL_ENDPOINT.format(
            owner=OWNER,
            repo=REPO,
            issue_number=issue_number,
            label_name=GITHUB_TRIGGER_BUILD_LABEL,
        ),
        headers=github_request_headers,
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


def post_comment_to_contribution_pr(
    github_request_headers: dict[str, str], pr: dict, message: str
):
    issue_number = str(pr.get("number"))

    response = requests.post(
        GITHUB_POST_COMMENT_ENDPOINT.format(
            owner=OWNER,
            repo=REPO,
            issue_number=issue_number,
            label_name=GITHUB_TRIGGER_BUILD_LABEL,
        ),
        headers=github_request_headers,
    )


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

    github_headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {args.github_token}",
    }

    gitlab_headers = {}

    if items := response.get("items"):
        pr_numbers: list[str] = []
        for pr in items:
            if is_pipeline_already_running():
                post_comment_to_contribution_pr(
                    github_headers, pr, PR_COMMENT_MESSAGES.cant_trigger_build
                )
            else:
                post_comment_to_contribution_pr(
                    github_headers, pr, PR_COMMENT_MESSAGES.build_request_accepted
                )
                trigger_build_for_contribution_pr(args.gitlab_api_token, pr)
                delete_label_from_contribution_pr(github_headers, pr)
                post_comment_to_contribution_pr(
                    github_headers, pr, PR_COMMENT_MESSAGES.build_triggered
                )
            pr_numbers.append(str(pr.get("number")))
        print(f"Build triggered for the following contribution PRs: {pr_numbers}")
    else:
        print("No Contribution PRs builds were trigger.")
        return


if __name__ == "__main__":
    main()
