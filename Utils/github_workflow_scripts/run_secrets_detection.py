#!/usr/bin/env python3

import argparse
import sys

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SECRETS_INSTANCE_URL = "https://content-gold.paloaltonetworks.com/instance/execute/GenericWebhook_Secrets"


def arguments_handler():
    """ Validates and parses script arguments.

     Returns:
        Namespace: Parsed arguments object.

     """
    parser = argparse.ArgumentParser(description='Run secrets detection.')
    parser.add_argument('-p', '--pr_number', help='The PR number to check if it includes secrets.')
    parser.add_argument('-b', '--branch_name', help='The branch name.')
    parser.add_argument('-u', '--username', help='The instance username.')
    parser.add_argument('-s', '--password', help='The instance password.')
    return parser.parse_args()


def trigger_generic_webhook(options):
    pr_number = options.pr_number
    branch_name = options.branch_name
    username = options.username
    password = options.password
    body = {
        "name": "GenericWebhook_Secrets",
        "raw_json": {"BranchName": branch_name, "PullRequestNumber": pr_number},
    }
    # post to Content Gold
    res = requests.post(SECRETS_INSTANCE_URL, json=body, auth=(username, password))

    if res.status_code != 200:
        print(
            f"Secrets detection playbook was failed. Post request to Content Gold has status code of {res.status_code}")
        sys.exit(1)

    res_json = res.json()
    if res_json and isinstance(res_json, list):
        res_json_response_data = res.json()[0]
        if res_json_response_data:
            investigation_id = res_json_response_data.get("id")
            print(investigation_id)
            return

    print("Secrets detection playbook has failed")
    sys.exit(1)


def main():
    options = arguments_handler()
    trigger_generic_webhook(options)


if __name__ == "__main__":
    main()
