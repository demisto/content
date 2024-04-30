import requests
import json
import sys
import argparse
import urllib3
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging

# Disable insecure warnings
urllib3.disable_warnings()


def options_handler():
    parser = argparse.ArgumentParser(description='Creates release branch for demisto-sdk.')

    parser.add_argument('-t', '--access_token', help='Github access token', required=True)
    parser.add_argument('-n', '--release_branch_name', help='The name of the release branch', required=True)
    parser.add_argument('-b', '--sdk_branch_name', help='From which branch in demisto-sdk we want to create the release',
                        required=False, default='master')

    options = parser.parse_args()
    return options


def main():
    install_logging("create_release_branch.log", logger=logging)
    options = options_handler()
    release_branch_name = options.release_branch_name
    access_token = options.access_token
    sdk_branch_name = options.sdk_branch_name

    logging.info(f"Preparing to create release branch {release_branch_name} from {sdk_branch_name}")

    # get the sha value from the branch
    url = f"https://api.github.com/repos/demisto/demisto-sdk/branches/{sdk_branch_name}"
    response = requests.request("GET", url)

    commit_sha = response.json().get('commit', {}).get('sha')
    if not commit_sha:
        logging.error(f'Failed to retrieve demisto-sdk {sdk_branch_name} branch')
        logging.error(response.text)
        sys.exit(1)

    # create the release branch
    url = "https://api.github.com/repos/demisto/demisto-sdk/git/refs"

    payload = json.dumps({
        "ref": f"refs/heads/{release_branch_name}",
        "sha": commit_sha
    })
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {access_token}'
    }

    response = requests.request("POST", url, headers=headers, data=payload, verify=False)
    if response.status_code != 201:
        logging.error('failed to create the release branch')
        logging.error(response.text)
        sys.exit(1)

    logging.success(f"The branch {release_branch_name} created successfully!")


if __name__ == "__main__":
    main()
