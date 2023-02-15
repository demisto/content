import random

import requests
from google.cloud import storage

import ast
import argparse
import os
import sys

import demisto_client
from Tests.configure_and_test_integration_instances import CloudBuild
from Tests.scripts.utils import logging_wrapper as logging
from Tests.scripts.utils.log_util import install_logging
from Tests.Marketplace.search_and_install_packs import install_packs
from time import sleep


def get_all_installed_packs(client: demisto_client):
    """

    Args:
        client (demisto_client): The client to connect to.

    Returns:
        list of installed python
    """
    try:
        logging.info("Attempting to fetch all installed packs.")
        response_data, status_code, _ = demisto_client.generic_request_func(client,
                                                                            path='/contentpacks/metadata/installed',
                                                                            method='GET',
                                                                            accept='application/json',
                                                                            _request_timeout=None)
        if 200 <= status_code < 300:
            installed_packs = ast.literal_eval(response_data)
            installed_packs_ids = [pack.get('id') for pack in installed_packs]
            logging.success('Successfully fetched all installed packs.')
            installed_packs_ids_str = ', '.join(installed_packs_ids)
            logging.debug(
                f'The following packs are currently installed from a previous build run:\n{installed_packs_ids_str}')
            if 'Base' in installed_packs_ids:
                installed_packs_ids.remove('Base')
            return installed_packs_ids
        else:
            result_object = ast.literal_eval(response_data)
            message = result_object.get('message', '')
            raise Exception(f'Failed to fetch installed packs - with status code {status_code}\n{message}')
    except Exception as e:
        logging.exception(f'The request to fetch installed packs has failed. Additional info: {str(e)}')
        return None


def uninstall_packs(client: demisto_client, pack_ids: list):
    """

    Args:
        client (demisto_client): The client to connect to.
        pack_ids: packs ids to uninstall

    Returns:
        True if uninstalling succeeded False otherwise.

    """
    body = {"IDs": pack_ids}
    try:
        logging.info("Attempting to uninstall all installed packs.")
        response_data, status_code, _ = demisto_client.generic_request_func(client,
                                                                            path='/contentpacks/installed/delete',
                                                                            method='POST',
                                                                            body=body,
                                                                            accept='application/json',
                                                                            _request_timeout=None)
    except Exception as e:
        logging.exception(f'The request to uninstall packs has failed. Additional info: {str(e)}')
        return False

    return True


def uninstall_all_packs(client: demisto_client, hostname):
    """ Lists all installed packs and uninstalling them.
    Args:
        client (demisto_client): The client to connect to.
        hostname (str): cloud hostname

    Returns (list, bool):
        A flag that indicates if the operation succeeded or not.
    """
    logging.info(f'Starting to search and uninstall packs in server: {hostname}')

    packs_to_uninstall: list = get_all_installed_packs(client)
    if packs_to_uninstall:
        return uninstall_packs(client, packs_to_uninstall)
    logging.debug('Skipping packs uninstallation - nothing to uninstall')
    return True


def reset_base_pack_version(client: demisto_client):
    """
    Resets base pack version to prod version.

    Args:
        client (demisto_client): The client to connect to.


    """
    host = client.api_client.configuration.host.replace('https://api-', 'https://')  # disable-secrets-detection
    try:
        # make the search request
        response_data, status_code, _ = demisto_client.generic_request_func(client,
                                                                            path='/contentpacks/marketplace/Base',
                                                                            method='GET',
                                                                            accept='application/json',
                                                                            _request_timeout=None)
        if 200 <= status_code < 300:
            result_object = ast.literal_eval(response_data)

            if result_object and result_object.get('currentVersion'):
                logging.debug('Found Base pack in bucket!')

                pack_data = {
                    'id': result_object.get('id'),
                    'version': result_object.get('currentVersion')
                }
                # install latest version of Base pack
                logging.info(f'updating base pack to version {result_object.get("currentVersion")}')
                return install_packs(client, host, [pack_data], False)

            else:
                raise Exception('Did not find Base pack')
        else:
            result_object = ast.literal_eval(response_data)
            msg = result_object.get('message', '')
            err_msg = f'Search request for base pack, failed with status code ' \
                      f'{status_code}\n{msg}'
            raise Exception(err_msg)
    except Exception:
        logging.exception('Search request Base pack has failed.')
        return False


def wait_for_uninstallation_to_complete(client: demisto_client, retries: int = 30):
    """
    Query if there are still installed packs, as it might take time to complete.
    Args:
        client (demisto_client): The client to connect to.
        retries: Max number of sleep priods.

    Returns: True if all packs were uninstalled successfully

    """
    retry = 0
    try:
        installed_packs = get_all_installed_packs(client)
        while len(installed_packs) > 1:
            if retry > retries:
                raise Exception('Waiting time for packs to be uninstalled has passed, there are still installed '
                                'packs. Aborting.')
            logging.info(f'The process of uninstalling all packs is not over! There are still {len(installed_packs)} '
                         f'packs installed. Sleeping for 10 seconds.')
            sleep(60)
            installed_packs = get_all_installed_packs(client)
            retry = retry + 1

    except Exception as e:
        logging.exception(f'Exception while waiting for the packs to be uninstalled. The error is {e}')
        return False
    return True


def options_handler():
    """

    Returns: options parsed from input arguments.

    """
    parser = argparse.ArgumentParser(description='Utility for instantiating and testing integration instances')
    parser.add_argument('--service_account', help='cloud machine to use, if it is cloud build.')
    parser.add_argument('--gcs_locks_path', help='Path to secret cloud server metadata file.')
    parser.add_argument('--ci_job_id', help='Path to the file with cloud Servers api keys.')
    parser.add_argument('--test_machines_list', help='Path to the file with cloud Servers api keys.')
    parser.add_argument('--gitlab_status_token', help='Path to the file with cloud Servers api keys.')

    options = parser.parse_args()
    return options


def get_files_in_gcp_folder(storage_client, bucket_name, prefix):
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


def get_machines_locks_details(storage_client, bucket_name, prefix):
    blobs = storage_client.list_blobs(bucket_name)
    files = []
    found = False
    for blob in blobs:
        if blob.name.startswith(prefix):
            found = True
            files.append({'machine_name': f'qa2-test-{(blob.name.strip(prefix)).strip("-")[0]}', 'job_id': (blob.name.strip(prefix)).strip("-")[3]})
        elif found:
            break
    return files


def check_job_status(options, job_id):
    user_endpoint = f"https://code.pan.run/api/v4/projects/2596/jobs/{job_id}"
    headers = {'PRIVATE-TOKEN': options.gitlab_status_token}
    response = requests.get(user_endpoint, headers=headers)
    return response.json().get('status')


def remove_build_from_queue(storage_bucket, lock_repo_name, job_id):
    blob = storage_bucket.blob(f'{lock_repo_name}/queue-ga-lock-{job_id}')
    try:
        blob.delete()
    except Exception as err:
        pass


def remove_machine_lock_file(storage_bucket, lock_repo_name, machine_name, job_id):
    blob = storage_bucket.blob(f'{lock_repo_name}/{machine_name}-lock-{job_id}')
    try:
        blob.delete()
    except Exception as err:
        pass


def lock_machine(storage_bucket, lock_repo_name, machine_name, job_id):
    blob = storage_bucket.blob(f'{lock_repo_name}/{machine_name}-lock-{job_id}')
    blob.upload_from_string('')


def main():
    install_logging('lock_cloud_machines.log', logger=logging)

    options = options_handler()
    logging.info(f'Starting search a CLOUD machine to lock')

    logging.info(f'adding job_id to the queue')
    storage_client = storage.Client.from_service_account_json(options.service_account)
    storage_bucket = storage_client.bucket('xsoar-ci-artifacts')
    lock_repo_name = f'{options.gcs_locks_path.split("/")[-1]}'
    blob = storage_bucket.blob(f'{lock_repo_name}/queue-ga-lock-{options.ci_job_id}')
    blob.upload_from_string('')

    logger = storage_bucket.blob(f'{lock_repo_name}/loger')
    logger.upload_from_string(f'get all builds in the queue')
    first_in_the_queue = False
    while not first_in_the_queue:
        builds_in_queue = (get_files_in_gcp_folder(storage_client, 'xsoar-ci-artifacts', f'{lock_repo_name}/queue-ga-lock-'))
        sorted_builds_in_queue = sorted(builds_in_queue, key=lambda d: d['time_created'], reverse=True)
        my_place_in_the_queue = next((index for (index, d) in enumerate(sorted_builds_in_queue) if d["name"] == options.ci_job_id), None)
        s = logger.download_as_string()
        logger.upload_from_string(f'{s}\nmy place in the queue is: {my_place_in_the_queue}')
        if my_place_in_the_queue == 0:
            first_in_the_queue = True
        else:
            previous_build = sorted_builds_in_queue[my_place_in_the_queue-1].get('name')
            previous_build_status = check_job_status(storage_client, previous_build)
            if previous_build_status != 'running':
                remove_build_from_queue(storage_bucket, lock_repo_name, previous_build)
            else:
                sleep(random.randint(8, 13))
    s = logger.download_as_string()
    logger.upload_from_string(f'{s}\nstart searching for an empty machine')
    test_machines_list = storage_bucket.blob(f'{lock_repo_name}/{options.test_machines_list}')
    list_machines = test_machines_list.download_as_string().decode("utf-8").split()
    s = logger.download_as_string()
    logger.upload_from_string(f'{s}\nlist_machines are: {list_machines}')
    machines_locks = (get_files_in_gcp_folder(storage_client, 'xsoar-ci-artifacts', f'{lock_repo_name}/qa2-test-'))
    s = logger.download_as_string()
    logger.upload_from_string(f'{s}\nmachines_locks are: {machines_locks}')
    lock_machine_name = None
    while not lock_machine_name:
        for machine in list_machines:
            job_id_of_the_existing_lock = next((d['job_id'] for d in machines_locks if d["machine_name"] == machine), None)
            if job_id_of_the_existing_lock:
                s = logger.download_as_string()
                logger.upload_from_string(f'{s}\nThere is a lock file for job id: {job_id_of_the_existing_lock}')
                job_id_of_the_existing_lock_status = check_job_status(storage_client, job_id_of_the_existing_lock)
                s = logger.download_as_string()
                logger.upload_from_string(f'{s}\nthe status of job id: {job_id_of_the_existing_lock} is: {job_id_of_the_existing_lock_status}')
                if job_id_of_the_existing_lock_status != 'running':
                    remove_machine_lock_file(storage_bucket, lock_repo_name, machine, job_id_of_the_existing_lock)
                    lock_machine(storage_bucket, lock_repo_name, machine, options.ci_job_id)
                    remove_build_from_queue(storage_bucket, lock_repo_name, options.ci_job_id)
                    lock_machine_name = machine
                    break
            else:
                s = logger.download_as_string()
                logger.upload_from_string(f'{s}\nThere is no a lock file')
                lock_machine(storage_bucket, lock_repo_name, machine, options.ci_job_id)
                remove_build_from_queue(storage_bucket, lock_repo_name, options.ci_job_id)
                lock_machine_name = machine
                break
    return lock_machine_name

if __name__ == '__main__':
    main()
