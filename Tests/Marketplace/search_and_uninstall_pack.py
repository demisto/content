import argparse
import ast
import json
import math
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from time import sleep
from typing import Any

import demisto_client

from Tests.Marketplace.common import generic_request_with_retries, wait_until_not_updating, ALREADY_IN_PROGRESS, \
    send_api_request_with_retries
from Tests.Marketplace.configure_and_install_packs import search_and_install_packs_and_their_dependencies
from Tests.configure_and_test_integration_instances import CloudBuild, get_custom_user_agent
from Tests.scripts.utils import logging_wrapper as logging
from Tests.scripts.utils.log_util import install_logging
from demisto_sdk.commands.common.tools import string_to_bool


TEST_DATA_PATTERN = '*_testdata.json'
DATASET_NOT_FOUND_ERROR_CODE = 599


def check_if_pack_still_installed(client: demisto_client,
                                  pack_id: str,
                                  attempts_count: int = 3,
                                  sleep_interval: int = 30,
                                  request_timeout: int = 300,
                                  ):
    """

    Args:
       client (demisto_client): The client to connect to.
       attempts_count (int): The number of attempts to install the packs.
       sleep_interval (int): The sleep interval, in seconds, between install attempts.
       pack_id: pack id to check id still installed on the machine.
       request_timeout (int): The timeout per call to the server.

    Returns:
        True if the pack is still installed, False otherwise.

    """
    def success_handler(response_data):
        installed_packs = ast.literal_eval(response_data)
        installed_packs_ids = [pack.get('id') for pack in installed_packs]
        return pack_id in installed_packs_ids, None

    return generic_request_with_retries(client=client,
                                        retries_message="Failed to get all installed packs.",
                                        exception_message="Failed to get installed packs.",
                                        prior_message=f"Checking if pack {pack_id} is still installed",
                                        path='/contentpacks/metadata/installed',
                                        method='GET',
                                        attempts_count=attempts_count,
                                        sleep_interval=sleep_interval,
                                        success_handler=success_handler,
                                        request_timeout=request_timeout,
                                        )


def get_all_installed_packs(client: demisto_client, non_removable_packs: list):
    """

    Args:
        non_removable_packs: list of packs that can't be uninstalled.
        client (demisto_client): The client to connect to.

    Returns:
        list of id's of the installed packs
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
            for pack in non_removable_packs:
                if pack in installed_packs_ids:
                    installed_packs_ids.remove(pack)
            return installed_packs_ids
        else:
            result_object = ast.literal_eval(response_data)
            message = result_object.get('message', '')
            raise Exception(f'Failed to fetch installed packs - with status code {status_code}\n{message}')
    except Exception as e:
        logging.exception(f'The request to fetch installed packs has failed. Additional info: {str(e)}')
        return None


def uninstall_all_packs_one_by_one(client: demisto_client, hostname, non_removable_packs: list):
    """ Lists all installed packs and uninstalling them.
    Args:
        client (demisto_client): The client to connect to.
        hostname (str): cloud hostname
        non_removable_packs: list of packs that can't be uninstalled.

    Returns (bool):
        A flag that indicates if the operation succeeded or not.
    """
    packs_to_uninstall = get_all_installed_packs(client, non_removable_packs)
    logging.info(f'Starting to search and uninstall packs in server: {hostname}, packs count to '
                 f'uninstall: {len(packs_to_uninstall)}')
    uninstalled_count = 0
    failed_to_uninstall = []
    start_time = datetime.utcnow()
    if packs_to_uninstall:
        for i, pack_to_uninstall in enumerate(packs_to_uninstall, 1):
            logging.info(f"{i}/{len(packs_to_uninstall)} - Attempting to uninstall a pack: {pack_to_uninstall}")
            successful_uninstall, _ = uninstall_pack(client, pack_to_uninstall)
            if successful_uninstall:
                uninstalled_count += 1
            else:
                failed_to_uninstall.append(pack_to_uninstall)
    end_time = datetime.utcnow()
    logging.info(f"Finished uninstalling - Succeeded: {uninstalled_count} out of {len(packs_to_uninstall)}, "
                 f"Took:{end_time - start_time}")
    if failed_to_uninstall:
        logging.error(f"Failed to uninstall: {','.join(failed_to_uninstall)}")
    return uninstalled_count == len(packs_to_uninstall)


def uninstall_pack(client: demisto_client,
                   pack_id: str,
                   attempts_count: int = 5,
                   sleep_interval: int = 60,
                   request_timeout: int = 300,
                   ):
    """

    Args:
        client (demisto_client): The client to connect to.
        pack_id: packs id to uninstall
        attempts_count (int): The number of attempts to install the packs.
        sleep_interval (int): The sleep interval, in seconds, between install attempts.
        request_timeout (int): The timeout per call to the server.
    Returns:
        Boolean - If the operation succeeded.

    """

    def success_handler(_):
        logging.success(f'Pack: {pack_id} was successfully uninstalled from the server')
        return True, None

    def should_try_handler():
        """

        Returns: true if we should try and uninstall the pack - the pack is still installed

        """
        still_installed, _ = check_if_pack_still_installed(client=client,
                                                           pack_id=pack_id)
        return still_installed

    def api_exception_handler(api_ex, _) -> Any:
        if ALREADY_IN_PROGRESS in api_ex.body and not wait_until_not_updating(client):
            raise Exception(
                "Failed to wait for the server to exit installation/updating status"
            ) from api_ex
        return None

    failure_massage = f'Failed to uninstall pack: {pack_id}'

    return generic_request_with_retries(client=client,
                                        retries_message=failure_massage,
                                        exception_message=failure_massage,
                                        prior_message=f'Uninstalling pack {pack_id}',
                                        path=f'/contentpacks/installed/{pack_id}',
                                        method='DELETE',
                                        attempts_count=attempts_count,
                                        sleep_interval=sleep_interval,
                                        should_try_handler=should_try_handler,
                                        success_handler=success_handler,
                                        api_exception_handler=api_exception_handler,
                                        request_timeout=request_timeout
                                        )


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


def uninstall_all_packs(client: demisto_client, hostname, non_removable_packs: list):
    """ Lists all installed packs and uninstalling them.
    Args:
        non_removable_packs: list of packs that can't be uninstalled.
        client (demisto_client): The client to connect to.
        hostname (str): cloud hostname

    Returns (list, bool):
        A flag that indicates if the operation succeeded or not.
    """
    logging.info(f'Starting to search and uninstall packs in server: {hostname}')

    packs_to_uninstall: list = get_all_installed_packs(client, non_removable_packs)
    if packs_to_uninstall:
        return uninstall_packs(client, packs_to_uninstall)
    logging.debug('Skipping packs uninstallation - nothing to uninstall')
    return True


def reset_core_pack_version(client: demisto_client, non_removable_packs: list):
    """
    Resets core pack version to prod version.

    Args:
        non_removable_packs: list of packs that can't be uninstalled.
        client (demisto_client): The client to connect to.


    """
    host = client.api_client.configuration.host.replace('https://api-', 'https://')  # disable-secrets-detection
    _, success = search_and_install_packs_and_their_dependencies(pack_ids=non_removable_packs,
                                                                 client=client,
                                                                 hostname=host,
                                                                 install_packs_in_batches=True,
                                                                 production_bucket=True)
    return success


def wait_for_uninstallation_to_complete(client: demisto_client, non_removable_packs: list):
    """
    Query if there are still installed packs, as it might take time to complete.
    Args:
        non_removable_packs: list of packs that can't be uninstalled.
        client (demisto_client): The client to connect to.

    Returns: True if all packs were uninstalled successfully

    """
    retry = 0
    sleep_duration = 150
    try:
        installed_packs = get_all_installed_packs(client, non_removable_packs)
        # Monitoring when uninstall packs don't work
        installed_packs_amount_history, failed_uninstall_attempt_count = len(installed_packs), 0
        # new calculation for num of retries
        retries = math.ceil(len(installed_packs) / 2)
        while len(installed_packs) > len(non_removable_packs):
            if retry > retries:
                raise Exception('Waiting time for packs to be uninstalled has passed, there are still installed '
                                'packs. Aborting.')
            if failed_uninstall_attempt_count >= 3:
                raise Exception(f'Uninstalling packs failed three times. {installed_packs=}')
            logging.info(f'The process of uninstalling all packs is not over! There are still {len(installed_packs)} '
                         f'packs installed. Sleeping for {sleep_duration} seconds.')
            sleep(sleep_duration)
            installed_packs = get_all_installed_packs(client, non_removable_packs)

            if len(installed_packs) == installed_packs_amount_history:
                # did not uninstall any pack
                failed_uninstall_attempt_count += 1
            else:  # uninstalled at least one pack
                installed_packs_amount_history = len(installed_packs)
                failed_uninstall_attempt_count = 0

            retry += 1

    except Exception as e:
        logging.exception(f'Exception while waiting for the packs to be uninstalled. The error is {e}')
        return False
    return True


def sync_marketplace(client: demisto_client,
                     attempts_count: int = 5,
                     sleep_interval: int = 60,
                     request_timeout: int = 120,
                     sleep_time_after_sync: int = 120,
                     hard: bool = True,
                     ) -> bool:
    """
    Send a request to sync marketplace.

    Args:
        client (demisto_client): The client to connect to.
        attempts_count (int): The number of attempts to install the packs.
        sleep_interval (int): The sleep interval, in seconds, between install attempts.
        request_timeout (int): The request timeout, in seconds.
        sleep_time_after_sync(int): The sleep interval, in seconds, after sync.
        hard(bool): Whether to perform a hard sync or not.
    Returns:
        Boolean - If the operation succeeded.

    """

    def api_exception_handler(api_ex, _) -> Any:
        if ALREADY_IN_PROGRESS in api_ex.body and not wait_until_not_updating(client):
            raise Exception(
                "Failed to wait for the server to exit installation/updating status"
            ) from api_ex
        return None

    success, _ = generic_request_with_retries(client=client,
                                              retries_message="Retrying to sync marketplace.",
                                              exception_message="Failed to sync marketplace.",
                                              prior_message=f"Sent request for sync marketplace, hard: {hard}",
                                              path=f'/contentpacks/marketplace/sync?hard={str(hard).lower()}',
                                              method='POST',
                                              attempts_count=attempts_count,
                                              sleep_interval=sleep_interval,
                                              request_timeout=request_timeout,
                                              api_exception_handler=api_exception_handler)
    if success:
        logging.success(f'Sent request for sync successfully, sleeping for {sleep_time_after_sync} seconds.')
        sleep(sleep_time_after_sync)
    return success


def delete_datasets(dataset_names, base_url, api_key, auth_id):
    """
    Return dataset names from testdata files.
    Args:
        dataset_names (set):dataset names to delete
        base_url (str): The base url of the machine.
        api_key (str): API key of the machine.
        auth_id (str): authentication parameter for the machine.
    Returns:
        Boolean - If the operation succeeded.
    """
    def should_try_handler(response) -> Any:
        if response is not None and response.status_code == DATASET_NOT_FOUND_ERROR_CODE:
            logging.info("Failed to delete dataset, probably it is not exist on the machine.")
            return False
        return True

    success = True
    for dataset in dataset_names:
        headers = {
            "x-xdr-auth-id": str(auth_id),
            "Authorization": api_key,
            "Content-Type": "application/json",
        }
        body = {'dataset_name': dataset}
        success &= send_api_request_with_retries(
            base_url=base_url,
            retries_message='Retrying to delete dataset',
            success_message=f'Successfully deleted dataset: "{dataset}".',
            exception_message=f'Failed to delete dataset: "{dataset}"',
            prior_message=f'Trying to delete dataset: "{dataset}"',
            endpoint='/public_api/v1/xql/delete_dataset',
            method='POST',
            headers=headers,
            accept='application/json',
            body=json.dumps(body),
            should_try_handler=should_try_handler,
        )
    return success


def get_datasets_to_delete(modeling_rules_file: str):
    """
    Given a path to a file containing a list of modeling rules paths,
    returns a list of their corresponding datasets that should be deleted.
    Args:
        modeling_rules_file (str): A path to a file holding the list of modeling rules collected for testing in this build.
    Returns:
        Set - datasets to delete.
    """
    datasets_to_delete = set()
    if Path(modeling_rules_file).is_file():
        with open(modeling_rules_file) as f:
            for modeling_rule_to_test in f.readlines():
                modeling_rule_path = Path(f'Packs/{modeling_rule_to_test.strip()}')
                test_data_matches = list(modeling_rule_path.glob(TEST_DATA_PATTERN))
                if test_data_matches:
                    modeling_rule_testdata_path = test_data_matches[0]
                    test_data = json.loads(modeling_rule_testdata_path.read_text())
                    for data in test_data.get('data', []):
                        dataset_name = data.get('dataset')
                        if dataset_name:
                            datasets_to_delete.add(dataset_name)
    return datasets_to_delete


def delete_datasets_by_testdata(base_url, api_key, auth_id, dataset_names):
    """
    Delete all datasets that the build will test in this job.

    Args:
        base_url (str): The base url of the cloud machine.
        api_key (str): API key of the machine.
        auth_id (str): authentication parameter for the machine.
        dataset_names (set): datasets to delete

    Returns:
        Boolean - If the operation succeeded.
    """
    logging.info("Starting to handle delete datasets from cloud instance.")
    logging.debug(f'Collected datasets to delete {dataset_names=}.')
    success = delete_datasets(dataset_names=dataset_names, base_url=base_url, api_key=api_key, auth_id=auth_id)
    return success


def options_handler() -> argparse.Namespace:
    """

    Returns: options parsed from input arguments.

    """
    parser = argparse.ArgumentParser(description='Utility for cleaning Cloud machines.')
    parser.add_argument('--cloud_machine', help='cloud machine to use, if it is cloud build.')
    parser.add_argument('--cloud_servers_path', help='Path to secret cloud server metadata file.')
    parser.add_argument('--cloud_servers_api_keys', help='Path to the file with cloud Servers api keys.')
    parser.add_argument('--non-removable-packs', help='List of packs that cant be removed.')
    parser.add_argument('--one-by-one', help='Uninstall pack one pack at a time.', action='store_true')
    parser.add_argument('--build-number', help='CI job number where the instances were created', required=True)
    parser.add_argument('--modeling_rules_to_test_files', help='List of modeling rules test data to check.', required=True)
    parser.add_argument('--reset-core-pack-version', help='Reset the core pack version.', type=string_to_bool)

    options = parser.parse_args()

    return options


def clean_machine(options: argparse.Namespace, cloud_machine: str) -> bool:
    api_key, _, base_url, xdr_auth_id = CloudBuild.get_cloud_configuration(cloud_machine,
                                                                           options.cloud_servers_path,
                                                                           options.cloud_servers_api_keys)

    client = demisto_client.configure(base_url=base_url,
                                      verify_ssl=False,
                                      api_key=api_key,
                                      auth_id=xdr_auth_id)
    client.api_client.user_agent = get_custom_user_agent(options.build_number)
    logging.debug(f'Setting user agent on client to: {client.api_client.user_agent}')

    # We are syncing marketplace since we are copying production bucket to build bucket and if packs were configured
    # in earlier builds they will appear in the bucket as it is cached.
    success = sync_marketplace(client=client)
    non_removable_packs = options.non_removable_packs.split(',')
    if options.reset_core_pack_version:
        success &= reset_core_pack_version(client, non_removable_packs)
    if success:
        if options.one_by_one:
            success = uninstall_all_packs_one_by_one(client, cloud_machine, non_removable_packs)
        else:
            success = uninstall_all_packs(client, cloud_machine, non_removable_packs) and \
                wait_for_uninstallation_to_complete(client, non_removable_packs)
    success &= sync_marketplace(client=client)
    success &= delete_datasets_by_testdata(base_url=base_url,
                                           api_key=api_key,
                                           auth_id=xdr_auth_id,
                                           dataset_names=get_datasets_to_delete(
                                               modeling_rules_file=options.modeling_rules_to_test_files)
                                           )
    return success


def main():
    install_logging('cleanup_cloud_instance.log', logger=logging)

    # In Cloud, We don't use demisto username
    os.environ.pop('DEMISTO_USERNAME', None)

    options = options_handler()
    logging.info(f'Starting cleanup for CLOUD servers:{options.cloud_machine}')
    cloud_machines: list[str] = list(filter(None, options.cloud_machine.split(',')))
    success = True
    with ThreadPoolExecutor(max_workers=len(cloud_machines), thread_name_prefix='clean-machine') as executor:
        futures = [
            executor.submit(clean_machine, options, cloud_machine)
            for cloud_machine in cloud_machines
        ]
        for future in as_completed(futures):
            try:
                success &= future.result()
            except Exception as ex:
                logging.exception(f'Failed to cleanup machine. Additional info: {str(ex)}')
                success = False

    if not success:
        logging.error('Failed to uninstall packs.')
        sys.exit(2)
    logging.info('Finished cleanup successfully.')


if __name__ == '__main__':
    main()
