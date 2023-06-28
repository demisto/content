import ast
import argparse
import math
import os
import sys

import demisto_client
from Tests.configure_and_test_integration_instances import CloudBuild
from Tests.scripts.utils import logging_wrapper as logging
from Tests.scripts.utils.log_util import install_logging
from Tests.Marketplace.configure_and_install_packs import search_and_install_packs_and_their_dependencies
from time import sleep


def get_all_installed_packs(client: demisto_client, unremovable_packs: list):
    """

    Args:
        unremovable_packs: list of packs that can't be uninstalled.
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
            for pack in unremovable_packs:
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


def uninstall_all_packs(client: demisto_client, hostname, unremovable_packs: list):
    """ Lists all installed packs and uninstalling them.
    Args:
        unremovable_packs: list of packs that can't be uninstalled.
        client (demisto_client): The client to connect to.
        hostname (str): cloud hostname

    Returns (list, bool):
        A flag that indicates if the operation succeeded or not.
    """
    logging.info(f'Starting to search and uninstall packs in server: {hostname}')

    packs_to_uninstall: list = get_all_installed_packs(client, unremovable_packs)
    if packs_to_uninstall:
        return uninstall_packs(client, packs_to_uninstall)
    logging.debug('Skipping packs uninstallation - nothing to uninstall')
    return True


def reset_core_pack_version(client: demisto_client, unremovable_packs: list):
    """
    Resets core pack version to prod version.

    Args:
        unremovable_packs: list of packs that can't be uninstalled.
        client (demisto_client): The client to connect to.


    """
    host = client.api_client.configuration.host.replace('https://api-', 'https://')  # disable-secrets-detection
    _, success = search_and_install_packs_and_their_dependencies(pack_ids=unremovable_packs,
                                                                 client=client,
                                                                 hostname=host,
                                                                 install_packs_one_by_one=True)
    return success


def wait_for_uninstallation_to_complete(client: demisto_client, unremovable_packs: list):
    """
    Query if there are still installed packs, as it might take time to complete.
    Args:
        unremovable_packs: list of packs that can't be uninstalled.
        client (demisto_client): The client to connect to.

    Returns: True if all packs were uninstalled successfully

    """
    retry = 0
    sleep_duration = 150
    try:
        installed_packs = get_all_installed_packs(client, unremovable_packs)
        # Monitoring when uninstall packs don't work
        installed_packs_amount_history, failed_uninstall_attempt_count = len(installed_packs), 0
        # new calculation for num of retries
        retries = math.ceil(len(installed_packs) / 2)
        while len(installed_packs) > len(unremovable_packs):
            if retry > retries:
                raise Exception('Waiting time for packs to be uninstalled has passed, there are still installed '
                                'packs. Aborting.')
            if failed_uninstall_attempt_count >= 3:
                raise Exception(f'Uninstalling packs failed three times. {installed_packs=}')
            logging.info(f'The process of uninstalling all packs is not over! There are still {len(installed_packs)} '
                         f'packs installed. Sleeping for {sleep_duration} seconds.')
            sleep(sleep_duration)
            installed_packs = get_all_installed_packs(client, unremovable_packs)

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


def sync_marketplace(client: demisto_client):
    """
    Syncs marketplace
    Args:
        client (demisto_client): The client to connect to.
    """
    try:
        _ = demisto_client.generic_request_func(client, path='/contentpacks/marketplace/sync', method='POST')
        logging.info('Synced marketplace successfully.')
    except Exception as e:
        logging.warning(f'Failed to sync marketplace. Error: {str(e)}')


def options_handler():
    """

    Returns: options parsed from input arguments.

    """
    parser = argparse.ArgumentParser(description='Utility for instantiating and testing integration instances')
    parser.add_argument('--cloud_machine', help='cloud machine to use, if it is cloud build.')
    parser.add_argument('--cloud_servers_path', help='Path to secret cloud server metadata file.')
    parser.add_argument('--cloud_servers_api_keys', help='Path to the file with cloud Servers api keys.')
    parser.add_argument('--unremovable_packs', help='List of packs that cant be removed.')

    options = parser.parse_args()

    return options


def main():
    install_logging('cleanup_cloud_instance.log', logger=logging)

    # in cloud we dont use demisto username
    os.environ.pop('DEMISTO_USERNAME', None)

    options = options_handler()
    host = options.cloud_machine
    logging.info(f'Starting cleanup for CLOUD server {host}')

    api_key, _, base_url, xdr_auth_id = CloudBuild.get_cloud_configuration(options.cloud_machine,
                                                                           options.cloud_servers_path,
                                                                           options.cloud_servers_api_keys)

    client = demisto_client.configure(base_url=base_url,
                                      verify_ssl=False,
                                      api_key=api_key,
                                      auth_id=xdr_auth_id)
    # We are syncing marketplace since we are copying production bucket to build bucket and if packs were configured
    # in earlier builds they will appear in the bucket as it is cached.
    sync_marketplace(client=client)
    unremovable_packs = options.unremovable_packs.split(',')
    success = reset_core_pack_version(client, unremovable_packs) and \
        uninstall_all_packs(client, host, unremovable_packs) and \
        wait_for_uninstallation_to_complete(client, unremovable_packs)
    sync_marketplace(client=client)
    if not success:
        sys.exit(2)
    logging.info('Uninstalling packs done.')


if __name__ == '__main__':
    main()
