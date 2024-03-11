#!/usr/bin/env python3
import os
import argparse
import sys

import requests
import urllib3
from Utils.github_workflow_scripts.utils import get_env_var

urllib3.disable_warnings()
OWNER = 'demisto'
REPO = 'content'
GITLAB_SERVER_URL = get_env_var('CI_SERVER_URL', 'https://gitlab.xdr.pan.local')  # disable-secrets-detection
GITHUB_SEARCH_REQUEST_ENDPOINT = 'https://api.github.com/search/issues'
GITHUB_DELETE_LABEL_ENDPOINT = 'https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}/labels/{lable_name}'
GITHUB_QUERY_LABELS = {'label': ['Contribution', 'ready-for-instance-test'], '-label': ['Internal PR']}


def arguments_handler():
    """Validates and parses script arguments.

    Returns:
       Namespace: Parsed arguments object.

    """
    parser = argparse.ArgumentParser(description="Trigger contribution build.")
    parser.add_argument('-g', '--github-token', help='Github api token')
    parser.add_argument('-g', '--gitlab-api-token', help='Gitlab api token')
    parser.add_argument('-p', '--pr_number', help='The PR number to check if it includes secrets.')
    parser.add_argument('-b', '--base_branch', help='The Base branch name.')
    parser.add_argument('-c', '--contrib_branch', help='The contribution branch name.')
    parser.add_argument('-cr', '--contrib_repo', help='The contribution repository name.')
    return parser.parse_args()


class GithubClient():

    def __init__(self, github_token:str):
        self.github_token = github_token

    def collect_contribution_prs_for_build(self):
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {self.github_token}"}
        query_labels = ' '.join([f'{label}:"{item}"' for label, lst in GITHUB_QUERY_LABELS.items() for item in lst])

        params = {
            "q": 'is:pr state:open ' + f'{query_labels}'
        }

        response = requests.get(GITHUB_SEARCH_REQUEST_ENDPOINT, headers=headers, params=params)

        if response.status_code == 200:
            return response.json()
        else:
            print(
                f"Trigger Contribution build script failed with request status code: {response.status_code}")
            sys.exit(1)

    def delete_trigger_build_label(self, pr):
        ...

class GitlabClient()

    def __init__(self, gitlab_api_token:str):
        self.gitlab_api_token = gitlab_api_token

    def trigger_build_for_contribution_pr(self):
        ...



def main():
    args = arguments_handler()
    github_client, gitlab_client = GithubClient(args.github_token), GitlabClient(args.gitlab_api_token)
    response = github_client.collect_contribution_prs_for_build()


    if items := response.get('items'):
        for pr in items:
            gitlab_client.trigger_build_for_contribution_pr()
            github_client.delete_trigger_build_label()
    else:
        return



if __name__ == "__main__":
    main()
