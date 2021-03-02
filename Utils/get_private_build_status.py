import os
import sys
import json
import time
import argparse
import requests
import logging
from urllib.parse import urljoin
from Tests.scripts.utils.log_util import install_logging
from Utils.trigger_private_build import GET_WORKFLOW_URL, PRIVATE_REPO_WORKFLOW_ID_FILE,\
                                        GET_WORKFLOWS_TIMEOUT_THRESHOLD, WORKFLOW_HTML_URL

# disable insecure warnings
requests.packages.urllib3.disable_warnings()


def get_workflow_status(bearer_token, workflow_id):
    workflow_url = urljoin(GET_WORKFLOW_URL, workflow_id)
    res = requests.get(workflow_url,
                       headers={'Authorization': bearer_token},
                       verify=False)
    if res.status_code != 200:
        logging.error(
            f'Failed to gets private repo workflow, request to {workflow_url} failed with error: {str(res.content)}')
        sys.exit(1)

    try:
        workflow = json.loads(res.content)
    except ValueError:
        logging.exception('Enable to parse private repo workflows response')
        sys.exit(1)

    return workflow.get('status')


def main():
    install_logging("GetPrivateBuildStatus.log")

    if not os.path.isfile(PRIVATE_REPO_WORKFLOW_ID_FILE):
        logging.info('Build private repo skipped')
        sys.exit(0)

    # gets workflow id from the file
    with open(PRIVATE_REPO_WORKFLOW_ID_FILE, 'r') as f:
        workflow_id = f.read()

    # get github_token parameter
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('--github-token', help='Github token')
    args = arg_parser.parse_args()
    bearer_token = f'Bearer {args.github_token}'

    # gets the workflow status
    status = get_workflow_status(bearer_token, workflow_id)

    # initialize timer
    start = time.time()
    time.process_time()
    elapsed = 0

    # polling the workflow status while is in progress
    while status in ['queued', 'in_progress'] and elapsed < GET_WORKFLOWS_TIMEOUT_THRESHOLD:
        logging.info(f'Workflow {workflow_id} status is {status}')
        time.sleep(10)
        status = get_workflow_status(bearer_token, workflow_id)
        elapsed = time.time() - start

    if elapsed > GET_WORKFLOWS_TIMEOUT_THRESHOLD:
        logging.error(f'Timeout reached while waiting for private content build to complete, build url:'
                      f' {WORKFLOW_HTML_URL}/{workflow_id}')
        sys.exit(1)

    logging.info(f'Workflow {workflow_id} status is {status}')
    if status != 'completed':
        logging.error(
            f'Private repo build failed,  build url: {WORKFLOW_HTML_URL}/{workflow_id}')
        sys.exit(1)

    logging.info('Build private repo finished successfully')
    sys.exit(0)


if __name__ == "__main__":
    main()
