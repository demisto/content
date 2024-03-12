#!/usr/bin/env python3
import argparse
import os
import sys

import requests
import urllib3

from Utils.github_workflow_scripts.utils import get_env_var

urllib3.disable_warnings()


OWNER = 'demisto'
REPO = 'content'
GITHUB_TRIGGER_BUILD_LABEL = "ready-for-instance-test"
GITLAB_SERVER_URL = os.getenv('CI_SERVER_URL', 'https://gitlab.xdr.pan.local')  # disable-secrets-detection
GITHUB_SEARCH_REQUEST_ENDPOINT = 'https://api.github.com/search/issues'
GITHUB_DELETE_LABEL_ENDPOINT = "https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}/labels/{label_name}"
GITHUB_QUERY_LABELS = {
    "label": ["Contribution", GITHUB_TRIGGER_BUILD_LABEL],
    "-label": ["Internal PR"],
}


class GithubClient():

    def __init__(self, github_token:str):
        self.github_token = github_token
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.github_token}",
        }

    def collect_contribution_prs_for_build(self):
        query_labels = ' '.join([f'{label}:"{item}"' for label, lst in GITHUB_QUERY_LABELS.items() for item in lst])

        params = {
            "q": 'is:pr state:open ' + f'{query_labels}'
        }

        response = requests.get(
            GITHUB_SEARCH_REQUEST_ENDPOINT, headers=self.headers, params=params
        )

        if response.status_code == 200:
            return response.json()
        else:
            print(
                f"Trigger Contribution build script failed with request status code: {response.status_code}")
            sys.exit(1)

    def delete_trigger_build_label_from_pr(self, pr: dict):
        issue_number = str(pr.get("number"))
        response = requests.delete(
            GITHUB_DELETE_LABEL_ENDPOINT.format(
                owner=OWNER,
                repo=REPO,
                issue_number=issue_number,
                label_name=GITHUB_TRIGGER_BUILD_LABEL,
            ),
            headers=self.headers,
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


class GitlabClient:

    def __init__(self, gitlab_api_token:str):
        self.gitlab_api_token = gitlab_api_token

    def trigger_build_for_contribution(self, pr):
        ...


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
    github_client, gitlab_client = GithubClient(args.github_token), GitlabClient(args.gitlab_api_token)
    response = github_client.collect_contribution_prs_for_build()

    if items := response.get('items'):
        # for pr in items:
        #     gitlab_client.trigger_build_for_contribution(pr)
        #     github_client.delete_trigger_build_label_from_pr(pr)
        github_client.delete_trigger_build_label_from_pr(pr={"number": 33308, 'title': 'Test PR'})
    else:
        return


if __name__ == "__main__":
    main()
