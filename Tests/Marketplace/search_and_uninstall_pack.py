import ast
import json
import argparse
import os
import sys

import demisto_client
from Tests.scripts.utils import logging_wrapper as logging
from Tests.scripts.utils.log_util import install_logging
from search_and_install_packs import install_packs


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

    logging.info(f'Starting to search and uninstall packs in server: {host}')

    packs_to_uninstall: list = get_all_installed_packs(client)
    return uninstall_packs(client, packs_to_uninstall)


def options_handler():
    """

    Returns: options parsed from input arguments.

    """
    parser = argparse.ArgumentParser(description='Utility for instantiating and testing integration instances')
    parser.add_argument('--xsiam_machine', help='XSIAM machine to use, if it is XSIAM build.')
    parser.add_argument('--xsiam_servers_path', help='Path to secret xsiam server metadata file.')

    # disable-secrets-detection-end
    options = parser.parse_args()

    return options


def get_json_file(path):
    """

    Args:
        path: path to retrieve file from.

    Returns: json object loaded from the path.

    """
    with open(path, 'r') as json_file:
        return json.loads(json_file.read())


def get_xsiam_configuration(xsiam_machine, xsiam_servers):
    """
        Parses conf params from servers list.
    """
    conf = xsiam_servers.get(xsiam_machine)
    return conf.get('api_key'), conf.get('base_url'), conf.get('x-xdr-auth-id')


def reset_base_pack_version(client: demisto_client):
    """
    Resets base pack version to prod version.

    Args:
        client (demisto_client): The client to connect to.


    """
    host = client.api_client.configuration.host
    try:
        # make the search request
        response_data, status_code, _ = demisto_client.generic_request_func(client,
                                                                            path=f'/contentpacks/marketplace/Base',
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
                    # 'version': '1.18.18'
                }
                # install latest version of Base pack
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
        logging.exception(f'Search request Base pack has failed.')


def main():
    install_logging('Install_Content_And_Configure_Integrations_On_Server.log', logger=logging)

    # in xsiam we dont use demisto username
    os.environ.pop('DEMISTO_USERNAME', None)

    options = options_handler()
    xsiam_servers = get_json_file(options.xsiam_servers_path)
    api_key, base_url, xdr_auth_id = get_xsiam_configuration(options.xsiam_machine, xsiam_servers)

    client = demisto_client.configure(base_url=base_url,
                                      verify_ssl=False,
                                      api_key=api_key,
                                      auth_id=xdr_auth_id)
    success = uninstall_all_packs(client) and reset_base_pack_version(client)

    if not success:
        sys.exit(2)


if __name__ == '__main__':
    main()
