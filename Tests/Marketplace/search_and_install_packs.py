from __future__ import print_function

import os
import ast
import json
import glob
import re
import sys
import demisto_client
from demisto_client.demisto_api.rest import ApiException
from threading import Thread, Lock
from demisto_sdk.commands.common.tools import print_color, LOG_COLORS, run_threads_list, print_error
from typing import List

from Tests.Marketplace.marketplace_services import PACKS_FULL_PATH, IGNORED_FILES
from Tests.test_content import ParallelPrintsManager

PACK_METADATA_FILE = 'pack_metadata.json'
SUCCESS_FLAG = True


def get_pack_display_name(pack_id: str) -> str:
    """
    Gets the display name of the pack from the pack ID.

    :param pack_id: ID of the pack.
    :return: Name found in the pack metadata, otherwise an empty string.
    """
    metadata_path = os.path.join(PACKS_FULL_PATH, pack_id, PACK_METADATA_FILE)
    if pack_id and os.path.isfile(metadata_path):
        with open(metadata_path, 'r') as json_file:
            pack_metadata = json.load(json_file)
        return pack_metadata.get('name')
    return ''


def create_dependencies_data_structure(response_data: dict, dependants_ids: list, dependencies_data: list,
                                       checked_packs: list):
    """ Recursively creates the packs' dependencies data structure for the installation requests
    (only required and uninstalled).

    Args:
        response_data (dict): The GET /search/dependencies response data.
        dependants_ids (list): A list of the dependant packs IDs.
        dependencies_data (list): The dependencies data structure to be created.
        checked_packs (list): Required dependants that were already found.
    """

    next_call_dependants_ids = []

    for dependency in response_data:
        dependants = dependency.get('dependants', {})
        for dependant in dependants.keys():
            is_required = dependants[dependant].get('level', '') == 'required'
            if dependant in dependants_ids and is_required and dependency.get('id') not in checked_packs:
                dependencies_data.append({
                    'id': dependency.get('id'),
                    'version': dependency.get('extras', {}).get('pack', {}).get('currentVersion')
                })
                next_call_dependants_ids.append(dependency.get('id'))
                checked_packs.append(dependency.get('id'))

    if next_call_dependants_ids:
        create_dependencies_data_structure(response_data, next_call_dependants_ids, dependencies_data, checked_packs)


def get_pack_dependencies(client: demisto_client, prints_manager: ParallelPrintsManager, pack_data: dict,
                          thread_index: int, lock: Lock):
    """ Get the pack's required dependencies.

    Args:
        client (demisto_client): The configured client to use.
        prints_manager (ParallelPrintsManager): A prints manager object.
        pack_data (dict): Contains the pack ID and version.
        thread_index (int): the thread index.
        lock (Lock): A lock object.
    Returns:
        (list) The pack's dependencies.
    """
    pack_id = pack_data['id']

    try:
        response_data, status_code, _ = demisto_client.generic_request_func(
            client,
            path='/contentpacks/marketplace/search/dependencies',
            method='POST',
            body=[pack_data],
            accept='application/json',
            _request_timeout=None
        )

        if 200 <= status_code < 300:
            dependencies_data = []
            dependants_ids = [pack_id]
            reseponse_data = ast.literal_eval(response_data).get('dependencies', [])
            create_dependencies_data_structure(reseponse_data, dependants_ids, dependencies_data, dependants_ids)
            dependencies_str = ', '.join([dep['id'] for dep in dependencies_data])
            if dependencies_data:
                message = 'Found the following dependencies for pack {}:\n{}\n'.format(pack_id, dependencies_str)
                prints_manager.add_print_job(message, print_color, thread_index, LOG_COLORS.GREEN)
                prints_manager.execute_thread_prints(thread_index)
            return dependencies_data
        if status_code == 400:
            err_msg = f"Unable to find dependencies for {pack_id}."
            prints_manager.add_print_job(err_msg, print_color, thread_index, LOG_COLORS.RED)
            prints_manager.execute_thread_prints(thread_index)
            return []
        else:
            result_object = ast.literal_eval(response_data)
            msg = result_object.get('message', '')
            err_msg = 'Failed to get pack {} dependencies - with status code {}\n{}\n'.format(pack_id, status_code, msg)
            raise Exception(err_msg)
    except Exception as e:
        err_msg = 'The request to get pack {} dependencies has failed. Reason:\n{}\n'.format(pack_id, str(e))
        prints_manager.add_print_job(err_msg, print_color, thread_index, LOG_COLORS.RED)
        prints_manager.execute_thread_prints(thread_index)

        lock.acquire()
        global SUCCESS_FLAG
        SUCCESS_FLAG = False
        lock.release()


def search_pack(client: demisto_client, prints_manager: ParallelPrintsManager, pack_display_name: str, pack_id: str,
                thread_index: int, lock: Lock) -> dict:
    """ Make a pack search request.

    Args:
        client (demisto_client): The configured client to use.
        prints_manager (ParallelPrintsManager): Print manager object.
        pack_display_name (string): The pack display name.
        pack_id (string): The pack ID.
        thread_index (int): the thread index.
        lock (Lock): A lock object.
    Returns:
        (dict): Returns the pack data if found, or empty dict otherwise.
    """

    try:
        # make the search request
        response_data, status_code, _ = demisto_client.generic_request_func(client,
                                                                            path=f'/contentpacks/marketplace/{pack_id}',
                                                                            method='GET',
                                                                            accept='application/json',
                                                                            _request_timeout=None)

        if 200 <= status_code < 300:
            result_object = ast.literal_eval(response_data)

            if result_object and result_object.get('currentVersion'):
                print_msg = f'Found pack "{pack_display_name}" by its ID "{pack_id}" in bucket!\n'
                prints_manager.add_print_job(print_msg, print_color, thread_index, LOG_COLORS.GREEN)
                prints_manager.execute_thread_prints(thread_index)

                pack_data = {
                    'id': result_object.get('id'),
                    'version': result_object.get('currentVersion')
                }
                return pack_data

            else:
                print_msg = f'Did not find pack "{pack_display_name}" by its ID "{pack_id}" in bucket.\n'
                prints_manager.add_print_job(print_msg, print_color, thread_index, LOG_COLORS.RED)
                prints_manager.execute_thread_prints(thread_index)
                raise Exception(print_msg)
        else:
            result_object = ast.literal_eval(response_data)
            msg = result_object.get('message', '')
            err_msg = f'Search request for pack "{pack_display_name}" with ID "{pack_id}", failed with status code ' \
                      f'{status_code}\n{msg}'
            raise Exception(err_msg)
    except Exception as e:
        err_msg = f'Search request for pack "{pack_display_name}" with ID "{pack_id}", failed. Reason:\n{str(e)}'
        prints_manager.add_print_job(err_msg, print_color, thread_index, LOG_COLORS.RED)

        lock.acquire()
        global SUCCESS_FLAG
        SUCCESS_FLAG = False
        lock.release()


def find_malformed_pack_id(error_message: str) -> List:
    """
    Find the pack ID from the installation error message.
    Args:
        error_message (str): The error message of the failed installation pack.

    Returns: Pack_id (str)

    """
    malformed_pack_pattern = re.compile(r'invalid version [0-9.]+ for pack with ID ([\w_-]+)')
    malformed_pack_id = malformed_pack_pattern.findall(str(error_message))
    if malformed_pack_id:
        return malformed_pack_id
    else:
        raise Exception(f'The request to install packs has failed. Reason: {str(error_message)}')


def install_nightly_packs(client: demisto_client, host: str, prints_manager: ParallelPrintsManager, thread_index: int,
                          packs_to_install: List, request_timeout: int = 999999):
    """
    Install content packs on nightly build.
    We will catch the exception if pack fails to install and send the request to install packs again without the
    corrupted pack.
    Args:
        client(demisto_client): The configured client to use.
        host (str): The server URL.
        prints_manager (ParallelPrintsManager): Print manager object.
        thread_index (int): the thread index.
        packs_to_install (list): A list of the packs to install.
        request_timeout (int): Timeout settings for the installation request.

    Returns:
        None: No data returned.
    """
    packs_to_install_str = ', '.join([pack['id'] for pack in packs_to_install])
    message = 'Installing the following packs in server {}:\n{}'.format(host, packs_to_install_str)
    prints_manager.add_print_job(message, print_color, thread_index, LOG_COLORS.GREEN, include_timestamp=True)
    prints_manager.execute_thread_prints(thread_index)
    # make the pack installation request
    all_packs_install_successfully = False
    request_data = {
        'packs': packs_to_install,
        'ignoreWarnings': True
    }
    while not all_packs_install_successfully:
        try:
            response_data, status_code, _ = demisto_client.generic_request_func(client,
                                                                                path='/contentpacks/marketplace/install',
                                                                                method='POST',
                                                                                body=request_data,
                                                                                accept='application/json',
                                                                                _request_timeout=request_timeout)

            if 200 <= status_code < 300:
                packs_data = [{'ID': pack.get('id'), 'CurrentVersion': pack.get('currentVersion')} for pack in
                              ast.literal_eval(response_data)]
                packs_message = f'The following packs were successfully installed:\n{packs_data}'
                prints_manager.add_print_job(packs_message, print_color, thread_index, LOG_COLORS.GREEN,
                                             include_timestamp=True)
            else:
                result_object = ast.literal_eval(response_data)
                message = result_object.get('message', '')
                err_msg = f'Failed to install packs - with status code {status_code}\n{message}\n'
                prints_manager.add_print_job(err_msg, print_error, thread_index, include_timestamp=True)
                raise Exception(err_msg)
            break

        except Exception as e:
            err_msg = f'The request to install packs has failed. Reason:\n{str(e)}\n'
            prints_manager.add_print_job(err_msg, print_error, thread_index, include_timestamp=True)
            all_packs_install_successfully = False
            malformed_pack_id = find_malformed_pack_id(str(e))
            if not malformed_pack_id:
                break
            # Remove the malformed pack from the pack to install list.
            packs = [pack for pack in packs_to_install if pack['id'] not in malformed_pack_id]
            request_data = {
                'packs': packs,
                'ignoreWarnings': True
            }

        finally:
            prints_manager.execute_thread_prints(thread_index)


def install_packs_from_artifacts(client: demisto_client, host: str, prints_manager: ParallelPrintsManager,
                                 thread_index: int, test_pack_path: str, pack_ids_to_install: List):
    """
    Installs all the packs located in the artifacts folder of the BitHub actions build. Please note:
    The server always returns a 200 status even if the pack was not installed.

    :param client: Demisto-py client to connect to the server.
    :param host: FQDN of the server.
    :param prints_manager: ParallelPrintsManager - Will be deprecated.
    :param thread_index: Integer indicating which thread the test is running on.
    :param test_pack_path: Path the the test pack directory.
    :param pack_ids_to_install: List of pack IDs to install.
    :return: None. Call to server waits until a successful response.
    """
    print(f"Test pack path is: {test_pack_path}")
    print(f"Pack IDs to install are: {pack_ids_to_install}")
    local_packs = glob.glob(f"{test_pack_path}/*.zip")
    for local_pack in local_packs:
        if any(pack_id in local_pack for pack_id in pack_ids_to_install):
            packs_install_msg = f'Installing the following pack: {local_pack}'
            prints_manager.add_print_job(packs_install_msg, print_color, thread_index,
                                         LOG_COLORS.GREEN,
                                         include_timestamp=True)
            upload_zipped_packs(client=client, host=host, prints_manager=prints_manager,
                                thread_index=thread_index, pack_path=local_pack)


def install_packs_private(client: demisto_client, host: str,
                          prints_manager: ParallelPrintsManager, thread_index: int,
                          pack_ids_to_install: List, test_pack_path: str):
    """ Make a packs installation request.

    Args:
        client (demisto_client): The configured client to use.
        host (str): The server URL.
        prints_manager (ParallelPrintsManager): Print manager object.
        thread_index (int): the thread index.
        pack_ids_to_install (list): List of Pack IDs to install.
        test_pack_path (str): Path where test packs are located.
    """
    install_packs_from_artifacts(client, host, prints_manager, thread_index,
                                 pack_ids_to_install=pack_ids_to_install,
                                 test_pack_path=test_pack_path)


def install_packs(client: demisto_client, host: str, prints_manager: ParallelPrintsManager,
                  thread_index: int, packs_to_install: list, request_timeout: int = 999999,
                  is_nightly: bool = False):
    """ Make a packs installation request.

    Args:
        client (demisto_client): The configured client to use.
        host (str): The server URL.
        prints_manager (ParallelPrintsManager): Print manager object.
        thread_index (int): the thread index.
        packs_to_install (list): A list of the packs to install.
        request_timeout (int): Timeout settings for the installation request.
        is_nightly (bool): Is the build nightly or not.
    """
    if is_nightly:
        install_nightly_packs(client, host, prints_manager, thread_index, packs_to_install)
        return
    request_data = {
        'packs': packs_to_install,
        'ignoreWarnings': True
    }

    packs_to_install_str = ', '.join([pack['id'] for pack in packs_to_install])
    message = 'Installing the following packs in server {}:\n{}'.format(host, packs_to_install_str)
    prints_manager.add_print_job(message, print_color, thread_index, LOG_COLORS.GREEN,
                                 include_timestamp=True)
    prints_manager.execute_thread_prints(thread_index)

    # make the pack installation request
    try:
        response_data, status_code, _ = demisto_client.generic_request_func(client,
                                                                            path='/contentpacks/marketplace/install',
                                                                            method='POST',
                                                                            body=request_data,
                                                                            accept='application/json',
                                                                            _request_timeout=request_timeout)

        if 200 <= status_code < 300:
            packs_data = [{'ID': pack.get('id'), 'CurrentVersion': pack.get('currentVersion')} for
                          pack in
                          ast.literal_eval(response_data)]
            packs_message = f'The following packs were successfully installed:\n{packs_data}'
            prints_manager.add_print_job(packs_message, print_color, thread_index, LOG_COLORS.GREEN,
                                         include_timestamp=True)
        else:
            result_object = ast.literal_eval(response_data)
            message = result_object.get('message', '')
            err_msg = f'Failed to install packs - with status code {status_code}\n{message}\n'
            prints_manager.add_print_job(err_msg, print_error, thread_index, include_timestamp=True)
            raise Exception(err_msg)
    except Exception as e:
        err_msg = f'The request to install packs has failed. Reason:\n{str(e)}\n'
        prints_manager.add_print_job(err_msg, print_error, thread_index, include_timestamp=True)

        global SUCCESS_FLAG
        SUCCESS_FLAG = False
    finally:
        prints_manager.execute_thread_prints(thread_index)


def search_pack_and_its_dependencies(client: demisto_client, prints_manager: ParallelPrintsManager,
                                     pack_id: str, packs_to_install: list, installation_request_body: list,
                                     thread_index: int, lock: Lock):
    """ Searches for the pack of the specified file path, as well as its dependencies,
        and updates the list of packs to be installed accordingly.

    Args:
        client (demisto_client): The configured client to use.
        prints_manager (ParallelPrintsManager): A prints manager object.
        pack_id (str): The id of the pack to be installed.
        packs_to_install (list) A list of the packs to be installed in this iteration.
        installation_request_body (list): A list of packs to be installed, in the request format.
        thread_index (int): the thread index.
        lock (Lock): A lock object.
    """
    pack_data = []
    if pack_id not in packs_to_install:
        pack_display_name = get_pack_display_name(pack_id)
        if pack_display_name:
            pack_data = search_pack(client, prints_manager, pack_display_name, pack_id, thread_index, lock)
        if pack_data is None:
            pack_data = {
                'id': pack_id,
                'version': '1.0.0'
            }

    if pack_data:
        dependencies = get_pack_dependencies(client, prints_manager, pack_data, thread_index, lock)

        current_packs_to_install = [pack_data]
        if dependencies:
            current_packs_to_install.extend(dependencies)

        lock.acquire()
        for pack in current_packs_to_install:
            if pack['id'] not in packs_to_install:
                packs_to_install.append(pack['id'])
                installation_request_body.append(pack)
        lock.release()


def add_pack_to_installation_request(pack_id: str, installation_request_body: List[dict]):
    """
    Adds a pack to the pack_ids variable which is given to the search_and_install_packs_and_their_dependencies
    function. The request must have the ID and Version.

    :param pack_id: Id of the pack to add.
    :param installation_request_body: The current pack_ids object to be modified.
    :return: Updated installation_request_body object.
    """
    metadata_path = os.path.join(PACKS_FULL_PATH, pack_id, PACK_METADATA_FILE)
    with open(metadata_path, 'r') as json_file:
        pack_metadata = json.load(json_file)
        version = pack_metadata.get('currentVersion')
        installation_request_body.append({
            'id': pack_id,
            'version': version
        })


def install_all_content_packs(client: demisto_client, host: str, prints_manager: ParallelPrintsManager,
                              thread_index: int = 0):
    """
    Iterates over the packs currently located in the Packs directory. Wrapper for install_packs.

    :param client: Demisto-py client to connect to the server.
    :param host: FQDN of the server.
    :param prints_manager: ParallelPrintsManager - Will be deprecated.
    :param thread_index: Integer indicating which thread the test is running on.
    :return: None. Prints the response from the server in the build.
    """
    all_packs = []

    for pack_id in os.listdir(PACKS_FULL_PATH):
        if pack_id not in IGNORED_FILES:
            add_pack_to_installation_request(pack_id, all_packs)
    install_packs(client, host, prints_manager, thread_index, all_packs, is_nightly=True)


def upload_zipped_packs(client: demisto_client, host: str, prints_manager: ParallelPrintsManager,
                        thread_index: int, pack_path: str):
    """ Install packs from zip file.

        Args:
            client (demisto_client): The configured client to use.
            host (str): The server URL.
            prints_manager (ParallelPrintsManager): Print manager object.
            thread_index (int): the index (for prints_manager).
            pack_path (str): path to pack zip.
        """
    header_params = {
        'Content-Type': 'multipart/form-data'
    }
    file_path = os.path.abspath(pack_path)
    files = {'file': file_path}

    message = 'Making "POST" request to server {} - to install all packs from file {}'.format(host, pack_path)
    prints_manager.add_print_job(message, print_color, thread_index, LOG_COLORS.GREEN)
    prints_manager.execute_thread_prints(thread_index)

    # make the pack installation request
    try:
        response_data, status_code, _ = client.api_client.call_api(resource_path='/contentpacks/installed/upload',
                                                                   method='POST',
                                                                   header_params=header_params, files=files)

        if 200 <= status_code < 300:
            message = 'All packs from {} were successfully installed!\n'.format(pack_path)
            prints_manager.add_print_job(message, print_color, thread_index, LOG_COLORS.GREEN)
            prints_manager.execute_thread_prints(thread_index)
        else:
            result_object = ast.literal_eval(response_data)
            message = result_object.get('message', '')
            err_msg = 'Failed to install packs - with status code {}\n{}\n'.format(status_code, message)
            raise Exception(err_msg)
    except Exception as e:
        if e.__class__ == ApiException:
            err_msg = 'The request to install packs has failed. Reason:\n{}\n'.format(str(e.body))
        else:
            err_msg = 'The request to install packs has failed. Reason:\n{}\n'.format(str(e))
        prints_manager.add_print_job(err_msg, print_color, thread_index, LOG_COLORS.GREEN)
        prints_manager.execute_thread_prints(thread_index)
        sys.exit(1)


def search_and_install_packs_and_their_dependencies_private(test_pack_path: str, pack_ids: list,
                                                            client: demisto_client,
                                                            prints_manager: ParallelPrintsManager,
                                                            thread_index: int = 0):
    """ Searches for the packs from the specified list, searches their dependencies, and then installs them.
    Args:
        test_pack_path (str): Path of where the test packs are located.
        pack_ids (list): A list of the pack ids to search and install.
        client (demisto_client): The client to connect to.
        prints_manager (ParallelPrintsManager): A prints manager object.
        thread_index (int): the thread index.

    Returns (list, bool):
        A list of the installed packs' ids, or an empty list if is_nightly == True.
        A flag that indicates if the operation succeeded or not.
    """
    host = client.api_client.configuration.host

    msg = f'Starting to search and install packs in server: {host}'
    prints_manager.add_print_job(msg, print_color, thread_index, LOG_COLORS.GREEN)
    prints_manager.execute_thread_prints(thread_index)

    install_packs_private(client, host, prints_manager, thread_index, pack_ids, test_pack_path)

    return SUCCESS_FLAG


def search_and_install_packs_and_their_dependencies(pack_ids: list, client: demisto_client,
                                                    prints_manager: ParallelPrintsManager,
                                                    thread_index: int = 0):
    """ Searches for the packs from the specified list, searches their dependencies, and then
    installs them.
    Args:
        pack_ids (list): A list of the pack ids to search and install.
        client (demisto_client): The client to connect to.
        prints_manager (ParallelPrintsManager): A prints manager object.
        thread_index (int): the thread index.

    Returns (list, bool):
        A list of the installed packs' ids, or an empty list if is_nightly == True.
        A flag that indicates if the operation succeeded or not.
    """
    host = client.api_client.configuration.host

    msg = f'Starting to search and install packs in server: {host}'
    prints_manager.add_print_job(msg, print_color, thread_index, LOG_COLORS.GREEN)
    prints_manager.execute_thread_prints(thread_index)

    packs_to_install = []  # we save all the packs we want to install, to avoid duplications
    installation_request_body = []  # the packs to install, in the request format

    threads_list = []
    lock = Lock()

    for pack_id in pack_ids:
        thread = Thread(target=search_pack_and_its_dependencies,
                        kwargs={'client': client,
                                'prints_manager': prints_manager,
                                'pack_id': pack_id,
                                'packs_to_install': packs_to_install,
                                'installation_request_body': installation_request_body,
                                'thread_index': thread_index,
                                'lock': lock})
        threads_list.append(thread)
    run_threads_list(threads_list)

    install_packs(client, host, prints_manager, thread_index, installation_request_body)

    return packs_to_install, SUCCESS_FLAG
