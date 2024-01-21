import requests
import json
import sys
import argparse
import urllib3
from create_release import get_changelog_text
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging

# Disable insecure warnings
urllib3.disable_warnings()


def options_handler():
    parser = argparse.ArgumentParser(description='Triggers update-demisto-sdk-version workflow')

    parser.add_argument('-t', '--access_token', help='Github access token', required=True)
    parser.add_argument('-b', '--release_branch_name', help='The name of the release branch', required=True)
    parser.add_argument('-r', '--reviewer', help='The reviewer of the pull request', required=True)

    options = parser.parse_args()
    return options


def main():
    install_logging("TriggerUpdateSDKWorkflow.log", logger=logging)

    options = options_handler()
    release_branch_name = options.release_branch_name
    access_token = options.access_token
    reviewer = options.reviewer

    inputs = {
        'reviewer': reviewer,
        # 'release_version': release_branch_name,
        'release_version': '1.25.0', #TODO: remove this line
        'release_changes': get_changelog_text(release_branch_name)
    }

    data = {
        'ref': 'master',
        'inputs': inputs
    }

    headers = {
      'Content-Type': 'application/vnd.github+json',
      'Authorization': f'Bearer {access_token}'
    }

    url = 'https://api.github.com/repos/demisto/content/actions/workflows/update-demisto-sdk-version.yml/dispatches'
    response = requests.request("POST", url, headers=headers, data=json.dumps(data), verify=False)
    if response.status_code != 204:
        logging.error('Failed to trigger update-demisto-sdk-version workflow')
        logging.error(response.text)
        sys.exit(1)

    logging.success('update-demisto-sdk-version workflow triggered successfully')


if __name__ == "__main__":
    main()
