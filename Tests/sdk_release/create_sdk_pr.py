import time

import requests
import re
import sys
import argparse
import base64
import json
import urllib3
from pathlib import Path
from distutils.util import strtobool
from datetime import datetime
from create_release import get_changelog_text
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging

# Disable insecure warnings
urllib3.disable_warnings()

API_SUFFIX = 'https://api.github.com/repos/demisto/demisto-sdk'
SDK_WORKFLOW_SUFFIX = 'https://github.com/demisto/demisto-sdk/actions/runs/'
SLACK_PR_READY_FILE = 'SDK_PR_READY.txt'
SDK_PR_NUMBER_FILE = 'SDK_PR.txt'
SLACK_PR_READY_MESSAGE = "The demisto-sdk release PR is ready and waiting for review," \
                         " please approve it but don't merge it yet\n{sdk_pr}"
TIMEOUT = 60 * 60  # 1 hour


def options_handler():
    parser = argparse.ArgumentParser(description='Creates release pull request for demisto-sdk.')

    parser.add_argument('-t', '--access_token', help='Github access token', required=True)
    parser.add_argument('-b', '--release_branch_name', help='The name of the release branch', required=True)
    parser.add_argument('-ro', '--release_owner', help='Github username of the release owner', required=True)
    parser.add_argument('-d', '--is_draft', help='Is draft pull request', default='FALSE')
    parser.add_argument('--artifacts-folder', help='Artifacts folder to create the files', required=True)

    options = parser.parse_args()
    return options


def main():
    install_logging("create_sdk_pr.log", logger=logging)

    options = options_handler()
    access_token = options.access_token
    release_branch_name = options.release_branch_name
    is_draft = options.is_draft
    release_owner = options.release_owner
    artifacts_folder = options.artifacts_folder

    if is_draft and bool(strtobool(is_draft)):
        is_draft = True
        logging.info(f'Preparing to create draft Pull request to release branch {release_branch_name}')
    else:
        is_draft = False
        logging.info(f'Preparing to create Pull request to release branch {release_branch_name}')

    headers = {
        'Authorization': f'Bearer {access_token}',
        'accept': 'application/vnd.github+json'
    }

    # get pyproject.toml file sha
    url = f'{API_SUFFIX}/contents/pyproject.toml'
    response = requests.request('GET', url, params={'ref': release_branch_name}, verify=False)
    if response.status_code != requests.codes.ok:
        logging.error(f'Failed to get the pyproject.toml file from branch {release_branch_name}')
        logging.error(response.text)
        sys.exit(1)
    pyproject_sha = response.json().get('sha')

    # get pyproject.toml file content
    url = f'https://raw.githubusercontent.com/demisto/demisto-sdk/{release_branch_name}/pyproject.toml'
    response = requests.request('GET', url, verify=False)
    if response.status_code != requests.codes.ok:
        logging.error(f'Failed to get the pyproject.toml file content from branch {release_branch_name}')
        logging.error(response.text)
        sys.exit(1)
    pyproject_content = response.text

    # update pyproject.toml content with the release version
    file_text = re.sub(r'\nversion = \"(\d+\.\d+\.\d+)\"\n', f'\nversion = "{release_branch_name}"\n', pyproject_content)
    content = bytes(file_text, encoding='utf8')

    # commit pyproject.toml
    data = {
        'message': 'Commit poetry files',
        'content': base64.b64encode(content).decode("utf-8"),
        'branch': release_branch_name,
        'sha': pyproject_sha
    }

    url = f'{API_SUFFIX}/contents/pyproject.toml'
    response = requests.request('PUT', url, data=json.dumps(data), headers=headers, verify=False)
    if response.status_code != requests.codes.ok:
        logging.error('Failed to commit the pyproject.toml file')
        logging.error(response.text)
        sys.exit(1)

    # create the sdk release PR
    data = {
        'base': 'master',
        'head': release_branch_name,
        'title': f'Demisto-sdk release {release_branch_name}',
        'body': '',
        'draft': is_draft
    }
    url = f'{API_SUFFIX}/pulls'
    response = requests.request('POST', url, data=json.dumps(data), headers=headers, verify=False)
    if response.status_code != 201:
        logging.error(f'Failed to create pull request for branch {release_branch_name}')
        logging.error(response.text)
        sys.exit(1)

    pr_url = response.json().get('html_url')
    pr_number = response.json().get('number')
    logging.success(f'The SDK Pull request created successfully! {pr_url}')

    # write the sdk pr number to file
    sdk_pr_file = Path(artifacts_folder, SDK_PR_NUMBER_FILE)
    sdk_pr_file.write_text(str(pr_number))

    # write the SLACK_PR_READY_FILE
    slack_message = SLACK_PR_READY_MESSAGE.format(sdk_pr=pr_url)
    slack_message_file = Path(artifacts_folder, SLACK_PR_READY_FILE)
    slack_message_file.write_text(slack_message)

    # request review from the owner
    data = {'reviewers': [release_owner]}
    url = f'{API_SUFFIX}/pulls/{pr_number}/requested_reviewers'
    response = requests.request('POST', url, data=json.dumps(data), headers=headers, verify=False)
    if response.status_code != 201:
        logging.error(f'Failed to request review to pull request: {pr_url}')
        logging.error(response.text)

    logging.success(f'{release_owner} added as reviewer to the release pull request')

    # trigger SDK changelog workflow, The reference can be found here:
    # https://docs.github.com/en/rest/actions/workflows?apiVersion=2022-11-28#create-a-workflow-dispatch-event
    logging.info('Triggering SDK changelog workflow')
    inputs = {
        'branch_name': release_branch_name,
        'pr_number': str(pr_number),
        'pr_title': f'demisto-sdk release {release_branch_name}'
    }

    data = {
        'ref': release_branch_name,
        'inputs': inputs
    }
    url = f'{API_SUFFIX}/actions/workflows/sdk-release.yml/dispatches'
    response = requests.request('POST', url, data=json.dumps(data), headers=headers, verify=False)

    if response.status_code != requests.codes.no_content:
        logging.error('Failed to trigger SDK changelog workflow')
        logging.error(response.text)
        sys.exit(1)
    logging.info('SDK changelog workflow triggered, waiting for it to be finished')
    # there is no content in the response therefore we wait 10 seconds before checking
    # the workflows to find the workflow that triggered
    time.sleep(10)

    # get all the workflows for sdk-release.yml in the release branch
    url = f'{API_SUFFIX}/actions/workflows/sdk-release.yml/runs'
    response = requests.request('GET', url, params={'branch': release_branch_name}, headers=headers, verify=False)
    if response.status_code != requests.codes.ok:
        logging.error('Failed to retrieve SDK changelog workflow')
        logging.error(response.text)
        sys.exit(1)

    # to get the workflow id, we get from the response the latest workflow id
    workflow_runs = response.json().get('workflow_runs', [])
    workflow_id = max(
        workflow_runs,
        key=lambda x: datetime.strptime(x["created_at"], "%Y-%m-%dT%H:%M:%SZ"),
    ).get('id')

    logging.info(f'SDK changelog workflow triggered successfully: {SDK_WORKFLOW_SUFFIX}{workflow_id}')

    # initialize timer
    start = time.time()

    elapsed: float = 0
    url = f'{API_SUFFIX}/actions/runs/{workflow_id}/jobs'

    while elapsed < TIMEOUT:
        response = requests.request('GET', url, headers=headers, verify=False)
        if response.status_code != requests.codes.ok:
            logging.error('Failed to retrieve SDK changelog workflow status')
            logging.error(response.text)
            sys.exit(1)

        job_data = response.json().get('jobs', [])[0]
        status = job_data.get('status')
        if status == "completed":
            logging.info("SDK changelog workflow completed")
            break

        logging.info(f'waiting to SDK changelog workflow to finish, current status: {status}')
        time.sleep(10)
        elapsed = time.time() - start

        if elapsed >= TIMEOUT:
            logging.critical('Timeout reached while waiting for SDK changelog workflow to complete')
            sys.exit(1)

    if job_data.get('conclusion') != 'success':
        logging.error('Retrieve SDK changelog workflow Failed:')
        logging.error(job_data)
        sys.exit(1)

    logging.success('Retrieve SDK changelog workflow finished successfully')

    # update the release PR body
    data = {
        'body': get_changelog_text(release_branch_name),
    }
    url = f'{API_SUFFIX}/pulls/{pr_number}'
    response = requests.request('PATCH', url, data=json.dumps(data), headers=headers, verify=False)
    if response.status_code != requests.codes.ok:
        logging.error(f'Failed to update pull request: {pr_url}')
        logging.error(response.text)
        sys.exit(1)

    logging.success('SDK pull request updated successfully with the changelog')


if __name__ == "__main__":
    main()
