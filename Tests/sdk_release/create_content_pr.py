import requests
import json
import sys
import os
import argparse
import urllib3
import time
from create_release import get_changelog_text
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging

# Disable insecure warnings
urllib3.disable_warnings()

SLACK_CHANGELOG_FILE = 'CHANGELOG_SLACK.txt'
SLACK_MERGE_PRS_FILE = 'SLACK_MERGE_PRS_REQUEST.txt'
CONTENT_PR_NUMBER_FILE = 'CONTENT_PR.txt'
SDK_PR_NUMBER_FILE = 'SDK_PR.txt'

TIMEOUT = 60 * 60  # 1 hour

PRS_LIST_TEMPLATE = 'https://api.github.com/repos/demisto/{}/pulls?head=demisto:{}'
UPDATE_SDK_VERSION_WORKFLOW = 'https://api.github.com/repos/demisto/content/actions' \
                              '/workflows/update-demisto-sdk-version.yml/dispatches'

SLACK_MERGE_PRS_MESSAGE = 'Please merge the demisto-sdk and content pull requests:\n{}\n{}'
SLACK_RELEASE_MESSAGE = 'demisto-sdk `{}` has been released :party-github:\n' \
                        ':alert: Please run in the terminal\n' \
                        '`~/dev/demisto/demisto-sdk/demisto_sdk/scripts/update_demisto_sdk_version.sh ~/dev/' \
                        'demisto/content ~/dev/demisto/demisto-sdk`\nChange log\n```\n{}\n```'


def get_pr_from_branch(repository, branch, access_token):
    url = PRS_LIST_TEMPLATE.format(repository, branch)
    res = requests.get(url, headers={'Authorization': f'Bearer {access_token}'}, verify=False)
    if res.status_code != 200:
        logging.error(f'Failed to retrieve pull request from branch {branch}')
        logging.error(res.text)
        sys.exit(1)

    prs_list = res.json()
    if prs_list:
        return prs_list[0]
    return None


def options_handler():
    parser = argparse.ArgumentParser(description='Triggers update-demisto-sdk-version workflow')

    parser.add_argument('-t', '--access_token', help='Github access token', required=True)
    parser.add_argument('-b', '--release_branch_name', help='The name of the release branch', required=True)
    parser.add_argument('-r', '--reviewer', help='The reviewer of the pull request', required=True)
    parser.add_argument('--artifacts-folder', help='Artifacts folder to create the files', required=True)
    parser.add_argument('-d', '--is_draft', help='Is draft pull request')
    options = parser.parse_args()
    return options


def main():
    install_logging("CreateContentPR.log", logger=logging)

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

    # prepare the inputs for trigger update-demisto-sdk-version workflow
    inputs = {
        'reviewer': reviewer,
        'release_version': '1.25.3',
        'is_draft': is_draft,
        'release_changes': get_changelog_text(release_branch_name)
    }

    data = {
        # 'ref': 'master',
        'ref': 'sdk-release',
        'inputs': inputs
    }

    headers = {
        'Content-Type': 'application/vnd.github+json',
        'Authorization': f'Bearer {access_token}'
    }

    # trigger update-demisto-sdk-version workflow
    response = requests.request("POST", UPDATE_SDK_VERSION_WORKFLOW, headers=headers,
                                data=json.dumps(data), verify=False)
    if response.status_code != 204:
        logging.error('Failed to trigger update-demisto-sdk-version workflow')
        logging.error(response.text)
        sys.exit(1)

    logging.success('update-demisto-sdk-version workflow triggered successfully')

    logging.info('Waiting for content release pull request creation')

    # initialize timer
    start = time.time()
    elapsed: float = 0

    content_pr: dict = {}
    # wait to content pr to create
    while not content_pr and elapsed < TIMEOUT:
        content_pr = get_pr_from_branch('content', release_branch_name, access_token)

        if not content_pr:
            logging.info('content pull request not created yet')

        time.sleep(60)
        elapsed = time.time() - start

    if elapsed >= TIMEOUT:
        logging.error('Timeout reached while waiting for content pull requests creation')
        sys.exit(1)

    logging.success(f'content pull request created: {content_pr.get("html_url")}')

    # write the changelog text to SLACK_CHANGELOG_FILE
    changelog_text = get_changelog_text(release_branch_name, text_format='slack')
    changelog_text = SLACK_RELEASE_MESSAGE.format(release_branch_name, changelog_text)
    changelog_file = os.path.join(artifacts_folder, SLACK_CHANGELOG_FILE)
    with open(changelog_file, "w") as f:
        f.write(str(changelog_text))

    # write the sdk pr number to file
    sdk_pr = get_pr_from_branch('demisto-sdk', release_branch_name, access_token)
    sdk_pr_file = os.path.join(artifacts_folder, SDK_PR_NUMBER_FILE)
    with open(sdk_pr_file, "w") as f:
        f.write(str(sdk_pr.get("number")))

    # write the content pr number to file
    content_pr_file = os.path.join(artifacts_folder, CONTENT_PR_NUMBER_FILE)
    with open(content_pr_file, "w") as f:
        f.write(str(content_pr.get("number")))

    # write the SLACK_MERGE_PRS_FILE
    slack_message = SLACK_MERGE_PRS_MESSAGE.format(content_pr.get("html_url"), sdk_pr.get("html_url"))
    slack_merge_prs_file = os.path.join(artifacts_folder, SLACK_MERGE_PRS_FILE)
    with open(slack_merge_prs_file, "w") as f:
        f.write(str(slack_message))


if __name__ == "__main__":
    main()
