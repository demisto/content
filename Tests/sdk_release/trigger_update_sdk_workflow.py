import requests
import json
import sys
import os
import argparse
import urllib3
from create_release import get_changelog_text
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging

# Disable insecure warnings
urllib3.disable_warnings()

SLACK_CHANGELOG_FILE = 'CHANGELOG_SLACK.txt'

SLACK_RELEASE_MESSAGE = 'demisto-sdk `{}` has been released :party-github:\n' \
        ':alert: Please run in the terminal\n' \
        '`~/dev/demisto/demisto-sdk/demisto_sdk/scripts/update_demisto_sdk_version.sh ~/dev/demisto/content ~/dev/demisto/demisto-sdk`\n' \
        'Change log\n```\n{}\n```'


def options_handler():
    parser = argparse.ArgumentParser(description='Triggers update-demisto-sdk-version workflow')

    parser.add_argument('-t', '--access_token', help='Github access token', required=True)
    parser.add_argument('-b', '--release_branch_name', help='The name of the release branch', required=True)
    parser.add_argument('-r', '--reviewer', help='The reviewer of the pull request', required=True)
    parser.add_argument('--artifacts-folder', help='Artifacts folder to create the CHANGELOG_SLACK.txt file', required=True)
    parser.add_argument('-d', '--is_draft', help='Is draft pull request')
    options = parser.parse_args()
    return options


def main():
    install_logging("TriggerUpdateSDKWorkflow.log", logger=logging)

    options = options_handler()
    release_branch_name = options.release_branch_name
    access_token = options.access_token
    reviewer = options.reviewer
    artifacts_folder = options.artifacts_folder
    is_draft = options.is_draft

    if is_draft and is_draft.lower() in ("yes", "true", "y"):
        is_draft = True
        logging.info('preparing to trigger update-demisto-sdk-version workflow with draft pull request')
    else:
        is_draft = False
        logging.info('preparing to trigger update-demisto-sdk-version workflow')

    inputs = {
        'reviewer': reviewer,
        # 'release_version': release_branch_name,
        'release_version': '1.25.0',  # TODO: remove this line
        'release_changes': get_changelog_text(release_branch_name),
        'is_draft': is_draft
    }

    data = {
        # 'ref': 'master',
        'ref': 'sdk-release',  # TODO: remove this line
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

    changelog_text = get_changelog_text(release_branch_name, text_format='slack')

    changelog_text = SLACK_RELEASE_MESSAGE.format(release_branch_name, changelog_text)
    changelog_file = os.path.join(artifacts_folder, SLACK_CHANGELOG_FILE)

    with open(changelog_file, "w") as f:
        f.write(str(changelog_text))


if __name__ == "__main__":
    main()
