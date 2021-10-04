#!/usr/bin/env python3

import argparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def arguments_handler():
    """ Validates and parses script arguments.

     Returns:
        Namespace: Parsed arguments object.

     """
    parser = argparse.ArgumentParser(description='Run secrets detection.')
    parser.add_argument('-p', '--pr_number', help='The PR number to check if the contribution form needs to be filled.')
    parser.add_argument('-b', '--branch_name', help='The branch name.')
    parser.add_argument('-u', '--username', help='The instance username.')
    parser.add_argument('-s', '--password', help='The instance password.')
    return parser.parse_args()


def main():
    options = arguments_handler()
    pr_number = options.pr_number
    branch_name = options.branch_name
    username = options.username
    password = options.password
    secrets_instance_url = "https://content-gold.paloaltonetworks.com/instance/execute/GenericWebhook_Secrets"
    body = {
        "name": "GenericWebhook_Secrets",
        "raw_json": {"BranchName": branch_name, "PullRequestNumber": pr_number}
    }
    # post to Content Gold
    res = requests.post(secrets_instance_url, json=body, auth=(username, password))
    print(res.text)


if __name__ == "__main__":
    main()