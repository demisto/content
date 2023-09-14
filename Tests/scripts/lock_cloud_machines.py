import time
from typing import Any
from Tests.scripts.utils import logging_wrapper as logging
from Tests.scripts.utils.log_util import install_logging
from time import sleep
import random
import requests
from google.cloud import storage
import argparse

LOCKS_BUCKET = 'xsoar-ci-artifacts'
QUEUE_REPO = 'queue'
MACHINES_LOCKS_REPO = 'machines_locks'
JOB_STATUS_URL = 'https://code.pan.run/api/v4/projects/{}/jobs/{}'  # disable-secrets-detection
CONTENT_GITLAB_PROJECT_ID = '2596'


def options_handler():
    """
    Returns: options parsed from input arguments.

    """
    parser = argparse.ArgumentParser(description='Utility for lock machines')
    parser.add_argument('--service_account', help='Path to gcloud service account.')
    parser.add_argument('--gcs_locks_path', help='Path to lock repo.')
    parser.add_argument('--ci_job_id', help='the job id.')
    parser.add_argument('--test_machines', help='comma separated string contains all available machines.')
    parser.add_argument('--gitlab_status_token', help='gitlab token to get the job status.')
    parser.add_argument('--response_machine', help='file to update the chosen machine.')
    parser.add_argument('--lock_machine_name', help='a machine name to lock the specific machine')
    parser.add_argument('--number_machines_to_lock', help='the needed machines number.', type=int)

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
        machines_lock_repo(str): the machines_lock_repo name.

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


def check_job_status(token: str, job_id: str, num_of_retries: int = 5, interval: float = 30.0):
    """
    get the status of a job in gitlab.

    Args:
        token(str): the gitlab token.
        job_id(str): the job id to check.
        num_of_retries (int): num of retries to establish a connection to gitlab in case of a connection error.
        interval (float): the interval to wait before trying to establish a connection to gitlab each attempt.

    Returns: the status of the job.

    """
    user_endpoint = JOB_STATUS_URL.format(CONTENT_GITLAB_PROJECT_ID, job_id)
    headers = {'PRIVATE-TOKEN': token}

    for attempt_num in range(1, num_of_retries + 1):
        try:
            logging.debug(f'Try to get the status of job ID {job_id} in attempt number {attempt_num}')
            response = requests.get(user_endpoint, headers=headers)
            response_as_json = response.json()
            logging.debug(f'{user_endpoint=} raw response={response_as_json} for {job_id=}')
            return response_as_json.get('status')
        except requests.ConnectionError as error:
            logging.error(f'Got connection error: {error} in attempt number {attempt_num}')
            if attempt_num == num_of_retries:
                raise error
            else:
                logging.debug(f'sleeping for {interval} seconds to try to re-establish gitlab connection')
                time.sleep(interval)
    return None


def remove_file(storage_bucket: Any, file_path: str):
    """
    deletes a file from the bucket
    Args:
        storage_bucket(google.cloud.storage.bucket.Bucket): google storage bucket where lock machine is stored.
        file_path(str): the path of the file.
    """
    blob = storage_bucket.blob(file_path)
    try:
        blob.delete()
    except Exception as err:
        logging.debug(f'when we try to delete a build_from_queue = {file_path}, we get an error: {str(err)}')
        pass


def lock_machine(storage_bucket: Any, lock_repository_name: str, machine_name: str, job_id: str):
    """
    create a lock machine file
    Args:
        storage_bucket(google.cloud.storage.bucket.Bucket): google storage bucket where lock machine is stored.
        lock_repository_name(str) the lock repository name.
        machine_name: the machine to lock.
        job_id(str): the job id that locks.
    """
    blob = storage_bucket.blob(f'{lock_repository_name}/{MACHINES_LOCKS_REPO}/{machine_name}-lock-{job_id}')
    blob.upload_from_string('')


def adding_build_to_the_queue(storage_bucket: Any, lock_repository_name: str, job_id: str):
    """
    create a lock machine file
    Args:
        storage_bucket(google.cloud.storage.bucket.Bucket): google storage bucket where lock machine is stored.
        lock_repository_name(str): the lock repository name.
        job_id(str): the job id to be added to the queue.
    """
    blob = storage_bucket.blob(f'{lock_repository_name}/{QUEUE_REPO}/{job_id}')
    blob.upload_from_string('')


def get_my_place_in_the_queue(storage_client: storage.Client, gcs_locks_path: str, job_id: str):
    """
    get the place in the queue for job-id by the time-created of lock-file time-created.
    Args:
        storage_client(storage.Client): The GCP storage client.
        gcs_locks_path(str): the lock repository name.
        job_id(str): the job id to check.

    Returns: the place in the queue.

    """
    logging.debug('getting all builds in the queue')
    builds_in_queue = get_queue_locks_details(storage_client=storage_client, bucket_name=LOCKS_BUCKET,
                                              prefix=f'{gcs_locks_path}/{QUEUE_REPO}/')
    # sorting the files by time_created
    sorted_builds_in_queue = sorted(builds_in_queue, key=lambda d: d['time_created'], reverse=False)

    my_place_in_the_queue = next((index for (index, d) in enumerate(sorted_builds_in_queue) if d["name"] == job_id), None)
    if my_place_in_the_queue is None:
        raise Exception("Unable to find the queue lock file, probably a problem creating the file")
    previous_build_in_queue = ''
    if my_place_in_the_queue > 0:
        previous_build_in_queue = sorted_builds_in_queue[my_place_in_the_queue - 1].get('name')
    return my_place_in_the_queue, previous_build_in_queue


def try_to_lock_machine(storage_bucket: Any, machine: str, machines_locks: list, gitlab_status_token: str,
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

    if job_id_of_the_existing_lock:  # This means there might be a build using this machine
        logging.debug(f'There is a lock file for job id: {job_id_of_the_existing_lock}')
        job_id_of_the_existing_lock_status = check_job_status(gitlab_status_token, job_id_of_the_existing_lock)
        logging.debug(f'the status of job id: {job_id_of_the_existing_lock} is: {job_id_of_the_existing_lock_status}')
        if job_id_of_the_existing_lock_status != 'running':
            # The job holding the machine is not running anymore, it is safe to remove its lock from the machine.
            logging.info(f'Found job [{job_id_of_the_existing_lock}] status: '
                         f'{job_id_of_the_existing_lock_status} that\'s locking machine: {machine}. Deleting the lock.')
            remove_file(storage_bucket,
                        file_path=f'{gcs_locks_path}/{MACHINES_LOCKS_REPO}/{machine}-lock-{job_id_of_the_existing_lock}')
        else:
            return lock_machine_name
    else:
        # machine found! create lock file
        logging.debug('There is no existing lock file')
    logging.info(f'Locking machine {machine}')
    lock_machine(storage_bucket, gcs_locks_path, machine, job_id)
    lock_machine_name = machine
    return lock_machine_name


def get_and_lock_all_needed_machines(storage_client, storage_bucket, list_machines, gcs_locks_path,
                                     number_machines_to_lock, job_id, gitlab_status_token):
    """
    get the requested machines and locked them to the job-id.
    The function will wait (busy waiting) until it was able to successfully lock the requested number of machines.
    In between runs, it will sleep for a minute to allow other builds to finish.
    Args:
        storage_client(storage.Client): The GCP storage client.
        storage_bucket(google.cloud.storage.bucket.Bucket): google storage bucket where lock machine is stored.
        list_machines (list): all the exiting machines.
        gcs_locks_path(str): the lock repository name.
        number_machines_to_lock(int): the number of the requested machines.
        job_id(str): the job id to lock.
        gitlab_status_token(str): the gitlab token.

    Returns: the machine name if locked.
    """

    logging.debug('getting all machines lock files')
    machines_locks = get_machines_locks_details(storage_client, LOCKS_BUCKET,
                                                gcs_locks_path, MACHINES_LOCKS_REPO)

    lock_machine_list = []
    while number_machines_to_lock > 0:
        busy_machines = []
        for machine in list_machines:
            lock_machine_name = try_to_lock_machine(storage_bucket, machine, machines_locks,
                                                    gitlab_status_token, gcs_locks_path,
                                                    job_id)

            # We managed to lock a machine
            if lock_machine_name:
                lock_machine_list.append(lock_machine_name)
                number_machines_to_lock -= 1
                # If we don't need more machines to lock we end the loop
                if not number_machines_to_lock:
                    break

                # If the machine was busy we save it to try it again later
            else:
                busy_machines.append(machine)

        # Next round we will try and lock only the busy machines
        list_machines = busy_machines

        # we need more machines but all machines where busy in this round
        if number_machines_to_lock:
            logging.info(f'Missing {number_machines_to_lock} available machine/s in order to continue, sleeping for 1 minute')
            sleep(60)
    return lock_machine_list


def create_list_of_machines_to_run(storage_bucket, lock_machine_name, gcs_locks_path, test_machines,
                                   number_machines_to_lock):
    """
    get the list of the available machines (or one specific given machine for debugging).
    Args:
        storage_bucket(google.cloud.storage.bucket.Bucket): google storage bucket where lock machine is stored.
        lock_machine_name(str): the name of the file with the list of the test machines.
        test_machines(str): all the exiting machines.
        gcs_locks_path(str): the lock repository name.
        number_machines_to_lock(int): the number of the requested machines.

    Returns: the machines list.
    """
    if lock_machine_name:  # For debugging: We got a name of a specific machine to use.
        logging.info(f'trying to lock the given machine: {lock_machine_name}')
        list_machines = [lock_machine_name]
    else:
        logging.info('getting all machine names')  # We are looking for a free machine in all the available machines.
        list_machines = test_machines.split(',')
        random.shuffle(list_machines)

    if number_machines_to_lock > len(list_machines):
        logging.error(
            f'This build requested {number_machines_to_lock} but there are only {len(list_machines)} active machines')
        raise
    return list_machines


def wait_for_build_to_be_first_in_queue(storage_client, storage_bucket, gcs_locks_path, job_id, gitlab_status_token):
    """
    this function will wait (busy waiting) for the current build to be the first in the queue,
    in case he is not the first it will check if the build before it is alive and cancel it in case it is not,
    between runs it will sleep for a random amount of seconds.
    Args:
        storage_client(storage.Client): The GCP storage client.
        storage_bucket(google.cloud.storage.bucket.Bucket): google storage bucket where lock machine is stored.
        gcs_locks_path(str): the lock repository name.
        job_id(str): the job id to check.
        gitlab_status_token(str): the gitlab token.
    """
    first_in_the_queue = False
    sleep(random.randint(1, 3))
    while not first_in_the_queue:
        my_place_in_the_queue, previous_build = get_my_place_in_the_queue(storage_client, gcs_locks_path, job_id)
        logging.info(f'My place in the queue is: {my_place_in_the_queue}')

        if my_place_in_the_queue == 0:
            first_in_the_queue = True
        else:
            # we check the status of the build that is ahead of me in the queue
            previous_build_status = check_job_status(gitlab_status_token, previous_build)
            if previous_build_status != 'running':
                # delete the lock file of the build because its not running
                remove_file(storage_bucket, f'{gcs_locks_path}/{QUEUE_REPO}/{previous_build}')
            else:
                sleep(random.randint(8, 13))
    return first_in_the_queue


def main():
    install_logging('lock_cloud_machines.log', logger=logging)
    logging.info('Starting to search for a CLOUD machine/s to lock')
    options = options_handler()
    storage_client = storage.Client.from_service_account_json(options.service_account)
    storage_bucket = storage_client.bucket(LOCKS_BUCKET)

    logging.info(f'Adding job_id: {options.ci_job_id} to the queue')
    adding_build_to_the_queue(storage_bucket, options.gcs_locks_path, options.ci_job_id)

    # running until the build is the first in queue
    wait_for_build_to_be_first_in_queue(storage_client, storage_bucket, options.gcs_locks_path, options.ci_job_id,
                                        options.gitlab_status_token)

    logging.info('Starting to search for available machine')

    list_machines = create_list_of_machines_to_run(storage_bucket, options.lock_machine_name, options.gcs_locks_path,
                                                   options.test_machines, options.number_machines_to_lock)

    lock_machine_list = get_and_lock_all_needed_machines(storage_client, storage_bucket, list_machines,
                                                         options.gcs_locks_path, options.number_machines_to_lock,
                                                         options.ci_job_id, options.gitlab_status_token)

    # remove build from queue
    remove_file(storage_bucket, file_path=f'{options.gcs_locks_path}/{QUEUE_REPO}/{options.ci_job_id}')

    # the output need to be improved if we wont to support locking for multiply machines.
    with open(options.response_machine, "w") as f:
        f.write(f"export CLOUD_CHOSEN_MACHINE_ID={lock_machine_list[0]}")


if __name__ == '__main__':
    main()
