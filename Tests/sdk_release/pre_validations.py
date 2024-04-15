import requests
import sys
import re
import argparse
import urllib3
import logging
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.gitlab_basic_slack_notifier import get_slack_user

# Disable insecure warnings
urllib3.disable_warnings()

# regex to validate that the version format is correct e.g: <2.1.3>
VERSION_FORMAT_REGEX = '\d{1,3}\.\d{1,3}\.\d{1,3}'

GITHUB_USER_URL = 'https://api.github.com/users/{username}'
GITHUB_BRANCH_URL = 'https://api.github.com/repos/demisto/demisto-sdk/branches/{branch_name}'


def options_handler():
    parser = argparse.ArgumentParser(description='Triggers update-demisto-sdk-version workflow')

    parser.add_argument('-t', '--github_token', help='Github access token', required=True)
    parser.add_argument('-gt', '--gitlab_token', help='Gitlab API token', required=True)
    parser.add_argument('-v', '--release_version', help='The release version', required=True)
    parser.add_argument('-r', '--reviewer', help='The reviewer of the pull request', required=True)
    parser.add_argument('-b', '--sdk_branch_name', help='From which branch in demisto-sdk we want to create the release',
                        required=True)
    options = parser.parse_args()
    return options


def main():
    install_logging('pre_validations.log')
    options = options_handler()
    github_token = options.github_token
    release_version = options.release_version
    gitlab_token = options.gitlab_token
    reviewer = options.reviewer
    sdk_branch_name = options.sdk_branch_name
    errors = []

    # validate version format
    if not re.match(VERSION_FORMAT_REGEX, release_version):
        errors.append(f'The SDK release version {release_version} is not according to the expected format.'
                      f' The format of version should be in x.y.z format, e.g: <2.1.3>')

    # validate if github user exists
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {github_token}'
    }
    url = GITHUB_USER_URL.format(username=reviewer)
    response = requests.request("GET", url, headers=headers, verify=False)
    if response.status_code != requests.codes.ok:
        errors.append(f'Failed to retrieve the user {reviewer} from github,\nerror: {response.text}')

    # validate if branch exists
    url = GITHUB_BRANCH_URL.format(branch_name=sdk_branch_name)
    response = requests.request("GET", url, verify=False)
    if response.status_code != requests.codes.ok:
        errors.append(f'Failed to retrieve the branch {sdk_branch_name} from demisto-sdk repo,\nerror: {response.text}')

    # validate if the user exists in name_mapping.json file
    try:
        get_slack_user(gitlab_token, reviewer)
    except Exception as e:
        errors.append(f'Failed to retrieve the user from name_mapping.json file,\nerror: {str(e)}')

    if errors:
        logging.error('\n'.join(errors))
        sys.exit(1)


if __name__ == "__main__":
    main()
