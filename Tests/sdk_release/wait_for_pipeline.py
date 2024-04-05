import argparse
import json
from Tests.scripts.utils import logging_wrapper as logging
import sys
import time
import requests
import urllib3
from Tests.scripts.utils.log_util import install_logging
from Utils.github_workflow_scripts.utils import get_env_var

# Disable insecure warnings
urllib3.disable_warnings()

GITLAB_SERVER_URL = get_env_var('CI_SERVER_URL', 'https://gitlab.xdr.pan.local')  # disable-secrets-detection
TIMEOUT = 60 * 60 * 6  # 6 hours


def get_pipeline_status(pipeline_id, project_id, token):
    url = f'{GITLAB_SERVER_URL}/api/v4/projects/{project_id}/pipelines/{pipeline_id}/jobs'
    res = requests.get(url, headers={'Authorization': f'Bearer {token}'})
    if res.status_code != requests.codes.ok:
        logging.error(f'Failed to get status of pipeline {pipeline_id}')
        logging.error(res.text)
        return ''

    try:
        jobs_info = json.loads(res.content)
        pipeline_status = jobs_info[0].get('pipeline', {}).get('status')

    except Exception as e:
        logging.error(f'Unable to parse pipeline status response: {res.text}, error: {str(e)}')
        return ''

    return pipeline_status


def get_pipeline_info(pipeline_id, project_id, token):
    url = f'{GITLAB_SERVER_URL}/api/v4/projects/{project_id}/pipelines/{pipeline_id}'
    res = requests.get(url, headers={'Authorization': f'Bearer {token}'})
    if res.status_code != requests.codes.ok:
        logging.error(f'Failed to get status of pipeline {pipeline_id}')
        logging.error(res.text)
        sys.exit(1)

    try:
        pipeline_info = json.loads(res.content)
    except Exception as e:
        logging.error(f'Unable to parse pipeline status response: {res.text}, error: {str(e)}')
        sys.exit(1)

    return pipeline_info


def main():
    install_logging('wait_for_pipeline.log', logger=logging)

    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('-g', '--gitlab-api-token', help='Gitlab api token')
    arg_parser.add_argument('-p', '--pipeline-id', help='Pipeline id')
    arg_parser.add_argument('-pid', '--project-id', help='Project id')

    args = arg_parser.parse_args()

    token = args.gitlab_api_token
    pipeline_id = args.pipeline_id
    project_id = args.project_id

    pipeline_status = 'running'  # pipeline status when start to run

    # initialize timer
    start = time.time()
    elapsed: float = 0

    while elapsed < TIMEOUT:
        pipeline_status = get_pipeline_status(pipeline_id, project_id, token)
        logging.info(f'Pipeline {pipeline_id} status is {pipeline_status}')

        if pipeline_status in ['failed', 'success', 'canceled']:
            break

        time.sleep(300)  # 5 minutes
        elapsed = time.time() - start

        if elapsed >= TIMEOUT:
            logging.critical(f'Timeout reached while waiting for the pipeline to complete, pipeline number: {pipeline_id}')
            sys.exit(1)

    pipeline_url = get_pipeline_info(pipeline_id, project_id, token).get('web_url')

    if pipeline_status != 'success':
        logging.error(f'The pipeline status is {pipeline_status}. See pipeline here: {pipeline_url}')
        sys.exit(1)

    logging.success(f'The pipeline has finished. See pipeline here: {pipeline_url}')


if __name__ == "__main__":
    main()
