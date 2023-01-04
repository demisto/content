#!/usr/bin/env python3

import argparse
import sys

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def arguments_handler():

    """ Validates and parses script arguments.

     Returns:
        Namespace: Parsed arguments object.

     """
    parser = argparse.ArgumentParser(description='Trigger contribution build.')
    parser.add_argument('-p', '--pr_number', help='The PR number to check if it includes secrets.')
    parser.add_argument('-b', '--base_branch', help='The Base branch name.')
    parser.add_argument('-c', '--contrib_branch', help='The contribution branch name.')
    parser.add_argument('-u', '--username', help='The instance username.')
    parser.add_argument('-s', '--password', help='The instance password.')
    parser.add_argument('-gs', '--gold_server_url', help='The content gold instance url.')
    return parser.parse_args()


def trigger_generic_webhook(options):
    pr_number = options.pr_number
    base_branch = options.base_branch
    contrib_branch = options.contrib_branch
    username = options.username
    password = options.password
    gold_server_url = options.gold_server_url
    contribution_build_instance_url = f"{gold_server_url}/instance/" \
                                      "execute/GenericWebhook_trigger_contribution_build"

    body = {
        "name": "GenericWebhook_trigger_contribution_build",
        "raw_json": {"BaseBranch": base_branch, "PullRequestNumber": pr_number, "ContribBranch": contrib_branch,
                     "ProjectID": "2596"},
    }
    # post to Content Gold
    res = requests.post(contribution_build_instance_url, json=body, auth=(username, password))

    if res.status_code != 200:
        print(
            f"Trigger Contribution Build playbook failed. Post request to Content"
            f" Gold has status code of {res.status_code}")
        sys.exit(1)


def main():
    options = arguments_handler()
    trigger_generic_webhook(options)


if __name__ == "__main__":
    main()
