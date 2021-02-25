import argparse
import requests
import logging
import sys
import json
import os
from urllib.parse import urljoin

GET_WORKFLOW_URL = 'https://api.github.com/repos/demisto/content-private/actions/runs/'


def get_workflow_status(bearer_token, workflow_id):
    workflow_url = urljoin(GET_WORKFLOW_URL,workflow_id)
    res = requests.request("GET",
                           workflow_url,
                           headers={'Authorization': bearer_token},
                           verify=False)
    if res.status_code != 200:
        logging.error(
            f'Failed to gets private repo workflow, request to {workflow_url} failed with error: {str(res.content)}')
        sys.exit(1)

    try:
        workflow = json.loads(res.content)
    except ValueError:
        logging.error('Enable to parse private repo workflows response')
        sys.exit(1)

    return workflow.get('status')


def main():
    workflow_id = ''
    with open("PRIVATE_REPO_WORKFLOW_ID.txt", "r") as f:
        workflow_id = f.read()
    print(workflow_id)
    # arg_parser = argparse.ArgumentParser()
    # arg_parser.add_argument('--github-token', help='Github token')
    # arg_parser.add_argument('--workflow-id', help='Workflow ID')
    # args = arg_parser.parse_args()
    #
    # bearer_token = 'Bearer ' + args.github_token
    # status = get_workflow_status(bearer_token, args.workflow_id)
    # if status in ['queued','in_progress']:
    #     status = get_workflow_status(bearer_token, args.workflow_id)


if __name__ == "__main__":
    main()
