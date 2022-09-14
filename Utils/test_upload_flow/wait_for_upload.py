import argparse
import json
from Tests.scripts.utils import logging_wrapper as logging
import sys
import time

import requests

GITLAB_CONTENT_PIPELINES_BASE_URL = 'http://code.pan.run/api/v4/projects/2596/pipelines/'
TIMEOUT = 60 * 60 * 2


def get_pipeline_status(pipeline_id, token):
    url = GITLAB_CONTENT_PIPELINES_BASE_URL + pipeline_id
    res = requests.get(url,
                       headers={'Authorization': f'Bearer {token}'},
                       verify=False)
    if res.status_code != 200:
        logging.error(f'Failed to get status of pipeline {pipeline_id}, request to '
                      f'{GITLAB_CONTENT_PIPELINES_BASE_URL} failed with error: {str(res.content)}')
        sys.exit(1)

    try:
        pipeline_info = json.loads(res.content)
        pipeline_status = pipeline_info['status']
    except Exception as e:
        logging.error(f'Unable to parse pipeline status response: {e}')
        sys.exit(1)

    return pipeline_status


def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('-g', '--gitlab-api-token', help='Github api token')
    arg_parser.add_argument('-p', '--pipeline-id', help='Pipeline id')

    args = arg_parser.parse_args()

    token = args.gitlab_api_token
    pipeline_id = args.pipeline_id

    status = get_pipeline_status(pipeline_id, token)

    # initialize timer
    start = time.time()
    elapsed: float = 0

    while status not in ['failed', 'success'] and elapsed < TIMEOUT:
        logging.info(f'Pipeline {pipeline_id} status is {status}')
        time.sleep(300)
        status = get_pipeline_status(pipeline_id, token)
        elapsed = time.time() - start

    if elapsed >= TIMEOUT:
        logging.critical(f'Timeout reached while waiting for upload to complete, pipeline number: {pipeline_id}')
        sys.exit(1)

    # We don't care if the status is success, since we are also checking failures of the upload
    logging.success(f'The upload flow with pipeline {pipeline_id} has finished.')


if __name__ == "__main__":
    main()
