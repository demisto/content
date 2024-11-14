#!/usr/bin/env python3

import argparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SECRETS_INSTANCE_URL_SUFFIX = "/instance/execute/GenericWebhook_Secrets"


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
    parser.add_argument('-gs', '--gold_server_url', help='The content gold instance url.')
    return parser.parse_args()


def trigger_generic_webhook(options):
    pr_number = options.pr_number
    branch_name = options.branch_name
    username = options.username
    password = options.password
    gold_server_url = options.gold_server_url
    secrets_instance_url = f"{gold_server_url}/instance/execute/GenericWebhook_Secrets"

    body = {
        "name": "GenericWebhook_Secrets",
        "raw_json": {"BranchName": branch_name, "PullRequestNumber": pr_number},
    }
    # post to Content Gold
    res = requests.post(secrets_instance_url, json=body, auth=(username, password))

    if res.status_code != 200:
        raise ConnectionError(
            f"Secrets detection playbook was failed. Post request to Content Gold has status code of {res.status_code}")

    res_json = res.json()
    if res_json and isinstance(res_json, list):
        res_json_response_data = res.json()[0]
        if res_json_response_data:
            investigation_id = res_json_response_data.get("id")
            print(investigation_id)
            return

    raise Exception("Secrets detection playbook has failed")


def main():
    options = arguments_handler()
    trigger_generic_webhook(options)


if __name__ == "__main__":
    main()
