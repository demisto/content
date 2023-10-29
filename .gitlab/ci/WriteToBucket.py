from google.cloud import storage
from Tests.scripts.utils import logging_wrapper as logging
from Tests.scripts.utils.log_util import install_logging
from google.cloud import storage  # noqa
import argparse
import dimutex

LOCKS_BUCKET = 'xsoar-ci-artifacts'
QUEUE_REPO = 'queue'
MACHINES_LOCKS_REPO = 'machines_locks'
JOB_STATUS_URL = 'https://code.pan.run/api/v4/projects/{}/jobs/{}'  # disable-secrets-detection
CONTENT_GITLAB_PROJECT_ID = '2596'


def options_handler() -> argparse.Namespace:
    """
    Returns: options parsed from input arguments.

    """
    parser = argparse.ArgumentParser(description='Utility for lock machines')
    parser.add_argument('--service-account', help='Path to gcloud service account.')
    # parser.add_argument('--gcs_locks_path', help='Path to lock repo.')
    # parser.add_argument('--ci_job_id', help='the job id.')
    # parser.add_argument('--test_machines', help='comma separated string contains all available machines.')
    # parser.add_argument('--gitlab_status_token', help='gitlab token to get the job status.')
    # parser.add_argument('--response_machine', help='file to update the chosen machine.')
    # parser.add_argument('--lock_machine_name', help='a machine name to lock the specific machine')
    # parser.add_argument('--number_machines_to_lock', help='the needed machines number.', type=int)

    options = parser.parse_args()
    return options


# def write_to_gcs_with_mutex(data, bucket_name, file_name):
#     client = storage.Client()
#     bucket = client.bucket(bucket_name)
    # blob = bucket.blob(file_name)

    # with mutex:
    #     with blob.open("w") as f:
    #         f.write(data)


if __name__ == "__main__":
    file_name = "PR number.txt"
    install_logging('lock_cloud_machines.log', logger=logging)
    logging.info('Starting to search for a CLOUD machine/s to lock')
    options = options_handler()
    storage_client = storage.Client.from_service_account_json(options.service_account)
    storage_bucket = storage_client.bucket(LOCKS_BUCKET)
    blob = storage_bucket.blob(file_name)

    # lock = dimutex.GCS(bucket=LOCKS_BUCKET, name='lock-name')
    # try:
    #     lock.acquire()
    # except dimutex.AlreadyAcquiredError:
    #     print('already acquired')

    file_already_exist = storage.Blob(bucket=storage_bucket, name=file_name).exists(storage_client)
    if not file_already_exist:
        try:
            blob.upload_from_string(data="nothing", if_generation_match=None)
            print("this is the first failure, trigger a slack message")
        except Exception:
            print("this is not the first failure, trigger a 'reply in thread' slack message")
    else:
        print("this is not the first failure, trigger a 'reply in thread' slack message")
    # lock.release()
