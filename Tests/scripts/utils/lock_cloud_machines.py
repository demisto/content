from Tests.scripts.utils import logging_wrapper as logging
from Tests.scripts.utils.log_util import install_logging
from time import sleep
import random
import requests
from google.cloud import storage
import argparse


QUEUE_REPO = 'queue'
MACHINES_LOCKS_REPO = 'machines_locks'


def options_handler():
    """
    Returns: options parsed from input arguments.

    """
    parser = argparse.ArgumentParser(description='Utility for lock machines')
    parser.add_argument('--service_account', help='Path to gcloud service account.')
    parser.add_argument('--gcs_locks_path', help='Path to lock repo.')
    parser.add_argument('--ci_job_id', help='the job id.')
    parser.add_argument('--test_machines_list', help='the name of the file with all the test machines .')
    parser.add_argument('--gitlab_status_token', help='gitlub token to get the job status.')
    parser.add_argument('--response_machine', help='file to update the chosen machine.')
    parser.add_argument('--lock_machine_name', help='a machine name to lock the specific machine')
    parser.add_argument('--number_machines_to_lock', help='the needed machines number.')

    options = parser.parse_args()
    return options


def get_queue_locks_details(storage_client: storage.Client, bucket_name: str, prefix: str):
    """
    get a list of all queue locks files.
    Args:
        storage_client(storage.Client): The GCP storage client.
        bucket_name(str): the bucket name.
        prefix(str): the prefix to search for specific files.

    Returns: list of dicts with the job-id and the time_created of the lock file.

    """
    blobs = storage_client.list_blobs(bucket_name)
    files = []
    found = False
    for blob in blobs:
        if blob.name.startswith(prefix):
            found = True
            files.append({'name': blob.name.strip(prefix), 'time_created': blob.time_created})
        elif found:
            break
    return files


def get_machines_locks_details(storage_client: storage.Client, bucket_name: str,
                               lock_repository_name: str, machines_lock_repo: str):
    """
    get a list of all machines locks files.
    Args:
        storage_client(storage.Client): The GCP storage client.
        bucket_name(str): the bucket name.
        lock_repository_name(str):  the lock_repository_name name.
        prefix(str): the prefix to search for specific files.

    Returns: list of dicts with the job-id and the time_created of the lock file.

    """
    blobs = storage_client.list_blobs(bucket_name)
    files = []
    found = False
    for blob in blobs:
        if blob.name.startswith(lock_repository_name):
            found = True
            if blob.name.startswith(f'{lock_repository_name}/{machines_lock_repo}'):
                lock_file_name = blob.name.split('/')[-1]
                if lock_file_name:
                    files.append({'machine_name': lock_file_name.split('-lock-')[0],
                                  'job_id': lock_file_name.split('-lock-')[1]})
        elif found:
            break
    return files


def check_job_status(token: str, job_id: str):
    """
    get the status of a job in gitlab.
    Args:
        token(str): the gitlab token.
        job_id(str):  the job id to check.
    Returns: the status of the job.

    """
    user_endpoint = f"https://code.pan.run/api/v4/projects/2596/jobs/{job_id}"  # disable-secrets-detection
    headers = {'PRIVATE-TOKEN': token}
    response = requests.get(user_endpoint, headers=headers)
    return response.json().get('status')


def remove_build_from_queue(storage_bucket: any, lock_repository_name: str, job_id: str):
    """deletes a lock queue file """
    file_path = f'{lock_repository_name}/{QUEUE_REPO}/{job_id}'
    blob = storage_bucket.blob(file_path)
    try:
        blob.delete()
    except Exception as err:
        logging.info(f'when we try to delete a build_from_queue = {file_path}, we get an error: {str(err)}')
        pass


def remove_machine_lock_file(storage_bucket: any, lock_repository_name: str, machine_name: str, job_id: str):
    """deletes a lock machine file """
    file_path = f'{lock_repository_name}/{machine_name}-lock-{job_id}'
    blob = storage_bucket.blob(file_path)
    try:
        blob.delete()
    except Exception as err:
        logging.info(f'when we try to delete a lock machine file = {file_path}, we get an error: {str(err)}')
        pass


def lock_machine(storage_bucket: any, lock_repository_name: str, machine_name: str, job_id: str):
    """create a lock machine file """
    blob = storage_bucket.blob(f'{lock_repository_name}/{MACHINES_LOCKS_REPO}/{machine_name}-lock-{job_id}')
    blob.upload_from_string('')


def adding_build_to_the_queue(storage_bucket: any, lock_repository_name: str, job_id: str):
    """create a lock machine file """
    blob = storage_bucket.blob(f'{lock_repository_name}/{QUEUE_REPO}/{job_id}')
    blob.upload_from_string('')


def get_my_place_in_the_queue(storage_client: storage.Client, gcs_locks_path: str, job_id: str):
    """
    get_my_place_in_the_queue
    Args:
        storage_client(storage.Client): The GCP storage client.
        gcs_locks_path(str): the lock repository name.
        job_id(str): the job id to check.

    Returns: the place in the queue.

    """
    logging.info('gets all builds in the queue')
    builds_in_queue = get_queue_locks_details(storage_client, 'xsoar-ci-artifacts', f'{gcs_locks_path}/{QUEUE_REPO}/')
    # sorting the files by time_created
    sorted_builds_in_queue = sorted(builds_in_queue, key=lambda d: d['time_created'], reverse=False)

    my_place_in_the_queue = next((index for (index, d) in enumerate(sorted_builds_in_queue) if d["name"] == job_id))
    previous_build_in_queue = ''
    if my_place_in_the_queue > 0:
        previous_build_in_queue = sorted_builds_in_queue[my_place_in_the_queue - 1].get('name')
    return my_place_in_the_queue, previous_build_in_queue


def try_to_lock_machine(storage_bucket: any, machine: str, machines_locks: list, gitlab_status_token: str,
                        gcs_locks_path: str, job_id: str) -> str:
    """
    try to lock machine for the job
    Args:
        storage_bucket(google.cloud.storage.bucket.Bucket): google storage bucket where lock machine is stored.
        machine(str): the machine to lock.
        machines_locks(srt): all the exiting lock files.
        gitlab_status_token(str): the gitlab token.
        gcs_locks_path(str): the lock repository name.
        job_id(str): the job id to check.

    Returns: the machine name if locked.

    """
    lock_machine_name = ''
    job_id_of_the_existing_lock = next((d['job_id'] for d in machines_locks if d["machine_name"] == machine), None)
    if job_id_of_the_existing_lock:
        logging.info(f'There is a lock file for job id: {job_id_of_the_existing_lock}')
        job_id_of_the_existing_lock_status = check_job_status(gitlab_status_token, job_id_of_the_existing_lock)
        logging.info(f'the status of job id: {job_id_of_the_existing_lock} is: {job_id_of_the_existing_lock_status}')
        if job_id_of_the_existing_lock_status != 'running':
            # machine found! removing the not relevant lock and create a now one
            remove_machine_lock_file(storage_bucket, gcs_locks_path, machine, job_id_of_the_existing_lock)
            lock_machine(storage_bucket, gcs_locks_path, machine, job_id)
            lock_machine_name = machine
    else:
        # machine found! create lock file
        logging.info('There is no a lock file')
        lock_machine(storage_bucket, gcs_locks_path, machine, job_id)
        lock_machine_name = machine
    return lock_machine_name


def main():
    install_logging('lock_cloud_machines.log', logger=logging)
    logging.info('Starting search a CLOUD machine to lock')
    options = options_handler()
    storage_client = storage.Client.from_service_account_json(options.service_account)
    storage_bucket = storage_client.bucket('xsoar-ci-artifacts')
    number_machines_to_lock = int(options.number_machines_to_lock)

    logging.info('adding job_id to the queue')
    adding_build_to_the_queue(storage_bucket, options.gcs_locks_path, options.ci_job_id)

    # running until the build is the first in queue
    first_in_the_queue = False
    while not first_in_the_queue:
        my_place_in_the_queue, previous_build = get_my_place_in_the_queue(storage_client, options.gcs_locks_path,
                                                                          options.ci_job_id)
        logging.info(f'my place in the queue is: {my_place_in_the_queue}')

        if my_place_in_the_queue == 0:
            first_in_the_queue = True
        else:
            # we check the status of the build that is ahead of me in the queue
            previous_build_status = check_job_status(options.gitlab_status_token, previous_build)
            if previous_build_status != 'running':
                # delete the lock file of the build because its not running
                remove_build_from_queue(storage_bucket, options.gcs_locks_path, previous_build)
            else:
                sleep(random.randint(8, 13))

    logging.info('Start searching for an empty machine')
    if options.lock_machine_name:
        logging.info('trying to lock the given machine: {options.lock_machine_name}')
        list_machines = [options.lock_machine_name]
    else:
        logging.info('gets all machines names')
        test_machines_list = storage_bucket.blob(f'{options.gcs_locks_path}/{options.test_machines_list}')
        list_machines = test_machines_list.download_as_string().decode("utf-8").split()
        random.shuffle(list_machines)

    logging.info(f'gets all machines lock files')
    machines_locks = get_machines_locks_details(storage_client, 'xsoar-ci-artifacts',
                                                options.gcs_locks_path, MACHINES_LOCKS_REPO)

    lock_machine_name = None
    while number_machines_to_lock > 0:
        for machine in list_machines:
            lock_machine_name = try_to_lock_machine(storage_bucket, machine, machines_locks,
                                                    options.gitlab_status_token, options.gcs_locks_path, options.ci_job_id)

            if lock_machine_name:
                number_machines_to_lock -= 1
                break

    # remove build from queue
    remove_build_from_queue(storage_bucket, options.gcs_locks_path, options.ci_job_id)

    f = open(options.response_machine, "w")
    f.write(f"export CLOUD_CHOSEN_MACHINE_ID={lock_machine_name}")
    f.close()


if __name__ == '__main__':
    main()
