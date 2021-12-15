import os
import sys
import json
import time
import argparse
from typing import Tuple

import requests
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging
from Utils.trigger_private_build import GET_WORKFLOW_URL, PRIVATE_REPO_WORKFLOW_ID_FILE, \
    GET_WORKFLOWS_TIMEOUT_THRESHOLD, WORKFLOW_HTML_URL

# disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


def get_workflow_status(github_token: str, workflow_id: str) -> Tuple[str, str, str]:
    """ Returns a set with the workflow job status, job conclusion and current step that running now in the job
        for the given workflow id.

    Args:
        github_token: Github bearer token.
        workflow_id: Github workflow id.

    Returns: (Workflow job status, Workflow job conclusion - only if the job completed otherwise its None,
              Current step that running now - only if the job is running otherwise its None )

    """

    # get the workflow run status
    workflow_url = GET_WORKFLOW_URL.format(workflow_id)
    res = requests.get(workflow_url,
                       headers={'Authorization': f'Bearer {github_token}'},
                       verify=False)
    if res.status_code != 200:
        logging.critical(
            f'Failed to gets private repo workflow, request to {workflow_url} failed with error: {str(res.content)}')
        sys.exit(1)

    # parse response
    try:
        workflow = json.loads(res.content)
    except ValueError:
        logging.exception('Enable to parse private repo workflows response')
        sys.exit(1)

    # get the workflow job from the response to know what step is in progress now
    jobs = workflow.get('jobs', [])

    if not jobs:
        logging.critical(f'Failed to gets private repo workflow jobs, build url: {WORKFLOW_HTML_URL}/{workflow_id}')
        sys.exit(1)

    curr_job = jobs[0]
    job_status = curr_job.get('status')
    job_conclusion = curr_job.get('conclusion')

    if job_status == 'completed':
        return 'completed', job_conclusion, ''

    # check for failure steps
    failure_steps = [step for step in jobs[0].get('steps') if step.get('conclusion') == 'failure']
    if failure_steps:
        return 'completed', 'failure', failure_steps[0].get('name')

    # if the job is still in progress - get the current step
    curr_step = next(step for step in jobs[0].get('steps') if step.get('status') == 'in_progress')

    return job_status, job_conclusion, curr_step.get('name')


def main():
    install_logging("GetPrivateBuildStatus.log", logger=logging)

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
    github_token = args.github_token

    # gets the workflow status
    status, conclusion, step = get_workflow_status(github_token, workflow_id)

    # initialize timer
    start = time.time()
    elapsed: float = 0

    # polling the workflow status while is in progress
    while status in ['queued', 'in_progress'] and elapsed < GET_WORKFLOWS_TIMEOUT_THRESHOLD:
        logging.info(f'Workflow {workflow_id} status is {status}, current step: {step}')
        time.sleep(60)
        status, conclusion, step = get_workflow_status(github_token, workflow_id)
        elapsed = time.time() - start

    if elapsed >= GET_WORKFLOWS_TIMEOUT_THRESHOLD:
        logging.critical(f'Timeout reached while waiting for private content build to complete, build url:'
                         f' {WORKFLOW_HTML_URL}/{workflow_id}')
        sys.exit(1)

    logging.info(f'Workflow {workflow_id} conclusion is {conclusion}')
    if conclusion != 'success':
        logging.critical(
            f'Private repo build failed,  build url: {WORKFLOW_HTML_URL}/{workflow_id}')
        sys.exit(1)

    logging.success('Build private repo finished successfully')
    sys.exit(0)


if __name__ == "__main__":
    main()
