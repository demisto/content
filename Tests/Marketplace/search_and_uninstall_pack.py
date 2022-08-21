import ast
import argparse
import os
import sys

import demisto_client
from Tests.configure_and_test_integration_instances import XSIAMBuild
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
        hostname (str): xsiam hostname

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
            sleep(10)
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
    parser.add_argument('--xsiam_machine', help='XSIAM machine to use, if it is XSIAM build.')
    parser.add_argument('--xsiam_servers_path', help='Path to secret xsiam server metadata file.')
    parser.add_argument('--xsiam_servers_api_keys', help='Path to the file with XSIAM Servers api keys.')

    options = parser.parse_args()

    return options


def main():
    install_logging('cleanup_xsiam_instance.log', logger=logging)

    # in xsiam we dont use demisto username
    os.environ.pop('DEMISTO_USERNAME', None)

    options = options_handler()
    host = options.xsiam_machine
    api_key, _, base_url, xdr_auth_id = XSIAMBuild.get_xsiam_configuration(options.xsiam_machine,
                                                                           options.xsiam_servers_path,
                                                                           options.xsiam_servers_api_keys)
    logging.info(f'Starting cleanup for XSIAM server {host}')

    client = demisto_client.configure(base_url=base_url,
                                      verify_ssl=False,
                                      api_key=api_key,
                                      auth_id=xdr_auth_id)

    success = reset_base_pack_version(client) and uninstall_all_packs(client,
                                                                      host) and wait_for_uninstallation_to_complete(
        client)
    if not success:
        sys.exit(2)
    logging.info('Uninstalling packs done.')


if __name__ == '__main__':
    main()
