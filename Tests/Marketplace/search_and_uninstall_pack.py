import ast
import json

import demisto_client
from threading import Thread, Lock
from demisto_sdk.commands.common.tools import run_threads_list
from Tests.scripts.utils import logging_wrapper as logging


def get_all_installed_packs(client: demisto_client):
    """

    Args:
        client (demisto_client): The client to connect to.

    Returns:
        list of installed python
    """
    try:
        response_data, status_code, _ = demisto_client.generic_request_func(client,
                                                                            path='/contentpacks/metadata/installed',
                                                                            method='GET',
                                                                            accept='application/json',
                                                                            _request_timeout=None)
        installed_packs_ids = []
        if 200 <= status_code < 300:
            installed_packs = ast.literal_eval(response_data)
            installed_packs_ids = [pack.get('id') for pack in installed_packs]
            logging.success('Successfully fetched all installed packs ')
            logging.debug(f'The following packs were are installed:\n{installed_packs_ids}')
        else:
            result_object = ast.literal_eval(response_data)
            message = result_object.get('message', '')
            raise Exception(f'Failed to fetch installed packs - with status code {status_code}\n{message}')
    except Exception as e:
        logging.exception(f'The request to fetch installed packs has failed. Additional info: {str(e)}')

    finally:
        if 'Base' in installed_packs_ids:
            installed_packs_ids.remove('Base')
        return installed_packs_ids


def uninstall_packs(client: demisto_client, pack_ids: list):
    body = {"IDs": pack_ids}
    try:
        response_data, status_code, _ = demisto_client.generic_request_func(client,
                                                                            path='/contentpacks/installed/delete',
                                                                            method='POST',
                                                                            body=body,
                                                                            accept='application/json',
                                                                            _request_timeout=None)
        if 200 <= status_code < 300:
            logging.success('Successfully uninstalled installed packs ')
        else:
            result_object = ast.literal_eval(response_data)
            message = result_object.get('message', '')
            raise Exception(f'Failed to uninstall packs - with status code {status_code}\n{message}')
    except Exception as e:
        logging.exception(f'The request to uninstall packs has failed. Additional info: {str(e)}')
        return False

    return True


def uninstall_all_packs(client: demisto_client):
    """ Lists all installed packs and uninstalling them.
    Args:
        client (demisto_client): The client to connect to.

    Returns (list, bool):
        A flag that indicates if the operation succeeded or not.
    """
    host = client.api_client.configuration.host

    logging.info(f'Starting to search and uinstall packs in server: {host}')

    packs_to_uninstall: list = get_all_installed_packs(client)
    return uninstall_packs(client, packs_to_uninstall)


def main():
    client = demisto_client.configure(base_url='http://localhost:8080',
                                      verify_ssl=False,
                                      api_key='ED7BDA68C3509E068A7C0AC96A445D38')
    uninstall_all_packs(client)


main()
