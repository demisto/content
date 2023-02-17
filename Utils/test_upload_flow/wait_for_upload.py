import argparse
import json
from Tests.scripts.utils import logging_wrapper as logging
import sys
import time
import requests
from Tests.scripts.utils.log_util import install_logging


GITLAB_CONTENT_PIPELINES_BASE_URL = 'http://code.pan.run/api/v4/projects/2596/pipelines/'  # disable-secrets-detection
TIMEOUT = 60 * 60 * 6  # 6 hours - TODO - Decrease after replacing id-set with graph


def get_pipeline_info(pipeline_id, token):
    url = GITLAB_CONTENT_PIPELINES_BASE_URL + pipeline_id
    res = requests.get(url, headers={'Authorization': f'Bearer {token}'})
    if res.status_code != 200:
        logging.error(f'Failed to get status of pipeline {pipeline_id}, request to '
                      f'{GITLAB_CONTENT_PIPELINES_BASE_URL} failed with error: {str(res.content)}')
        sys.exit(1)

    try:
        pipeline_info = json.loads(res.content)
    except Exception as e:
        logging.error(f'Unable to parse pipeline status response: {e}')
        sys.exit(1)

    return pipeline_info


def get_upload_job_status(pipeline_id, token):
    """
    We poll and check the pipelines status, where we only want to make sure the job 'upload packs to marketplace' has
    been reached. If not, this means some other job failed, and that the upload did not happen.
    """
    url = GITLAB_CONTENT_PIPELINES_BASE_URL + pipeline_id + '/jobs'
    res = requests.get(url, headers={'Authorization': f'Bearer {token}'})
    if res.status_code != 200:
        logging.error(f'Failed to get status of pipeline {pipeline_id}, request to '
                      f'{GITLAB_CONTENT_PIPELINES_BASE_URL} failed with error: {str(res.content)}')
        sys.exit(1)

    try:
        jobs_info = json.loads(res.content)
        pipeline_status = jobs_info[0].get('pipeline', {}).get('status')
        upload_job_status = get_job_status('upload-packs-to-marketplace', jobs_info)
    except Exception as e:
        logging.error(f'Unable to parse pipeline status response: {e}')
        sys.exit(1)

    return pipeline_status, upload_job_status


def get_job_status(job_name, pipelines_jobs_response):
    for job in pipelines_jobs_response:
        if job.get('name') == job_name:
            return job.get('status')


def main():
    install_logging('wait_for_upload.log', logger=logging)

    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('-g', '--gitlab-api-token', help='Github api token')
    arg_parser.add_argument('-p', '--pipeline-id', help='Pipeline id')

    args = arg_parser.parse_args()

    token = args.gitlab_api_token
    pipeline_id = args.pipeline_id

    pipeline_status, upload_job_status = get_upload_job_status(pipeline_id, token)

    # initialize timer
    start = time.time()
    elapsed: float = 0

    while pipeline_status not in ['failed', 'success', 'canceled'] and elapsed < TIMEOUT:
        logging.info(f'Pipeline {pipeline_id} status is {pipeline_status}')
        time.sleep(300)
        pipeline_status, upload_job_status = get_upload_job_status(pipeline_id, token)
        elapsed = time.time() - start

    if elapsed >= TIMEOUT:
        logging.critical(f'Timeout reached while waiting for upload to complete, pipeline number: {pipeline_id}')
        sys.exit(1)

    pipeline_url = get_pipeline_info(pipeline_id, token).get('web_url')

    if upload_job_status == 'skipped':
        logging.info(f'Failed to upload files to marketplace. See failed pipeline here: {pipeline_url}')
        sys.exit(1)

    logging.info(f'The upload has finished. See pipeline here: {pipeline_url}')


if __name__ == "__main__":
    main()
