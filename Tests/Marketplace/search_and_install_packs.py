from __future__ import print_function

import os
import ast
import json
import demisto_client
from threading import Thread, Lock
from demisto_sdk.commands.common.tools import print_color, LOG_COLORS, run_threads_list, print_error
from Tests.Marketplace.marketplace_services import PACKS_FULL_PATH, IGNORED_FILES

PACK_METADATA_FILE = 'pack_metadata.json'
SUCCESS_FLAG = True


def get_pack_display_name(pack_id):
    metadata_path = os.path.join(PACKS_FULL_PATH, pack_id, PACK_METADATA_FILE)
    if pack_id and os.path.isfile(metadata_path):
        with open(metadata_path, 'r') as json_file:
            pack_metadata = json.load(json_file)
        return pack_metadata.get('name')
    return ''


def get_pack_data_from_results(search_results, pack_display_name):
    if not search_results:
        return {}
    for pack in search_results:
        if pack.get('name') == pack_display_name:
            return {
                'id': pack.get('id'),
                'version': pack.get('currentVersion')
            }
    return {}


def create_dependencies_data_structure(response_data, dependants_ids, dependencies_data, checked_packs):
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


def get_pack_dependencies(client, prints_manager, pack_data, thread_index, lock):
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


def search_pack(client, prints_manager, pack_display_name, thread_index, lock):
    """ Make a pack search request.

    Args:
        client (demisto_client): The configured client to use.
        prints_manager (ParallelPrintsManager): Print manager object.
        pack_display_name (string): The pack display name.
        thread_index (int): the thread index.
        lock (Lock): A lock object.
    Returns:
        (dict): Returns the pack data if found, or empty dict otherwise.
    """

    try:
        # make the search request
        response_data, status_code, _ = demisto_client.generic_request_func(client,
                                                                            path='/contentpacks/marketplace/search',
                                                                            method='POST',
                                                                            body={"packsQuery": pack_display_name},
                                                                            accept='application/json',
                                                                            _request_timeout=None)

        if 200 <= status_code < 300:
            result_object = ast.literal_eval(response_data)
            search_results = result_object.get('packs', [])
            pack_data = get_pack_data_from_results(search_results, pack_display_name)
            if pack_data:
                print_msg = 'Found pack {} in bucket!\n'.format(pack_display_name)
                prints_manager.add_print_job(print_msg, print_color, thread_index, LOG_COLORS.GREEN)
                prints_manager.execute_thread_prints(thread_index)
                return pack_data

            else:
                print_msg = 'Did not find pack {} in bucket.\n'.format(pack_display_name)
                prints_manager.add_print_job(print_msg, print_color, thread_index, LOG_COLORS.RED)
                prints_manager.execute_thread_prints(thread_index)
                raise Exception(print_msg)
        else:
            result_object = ast.literal_eval(response_data)
            msg = result_object.get('message', '')
            err_msg = 'Pack {} search request failed - with status code {}\n{}'.format(pack_display_name,
                                                                                       status_code, msg)
            raise Exception(err_msg)
    except Exception as e:
        err_msg = 'The request to search pack {} has failed. Reason:\n{}'.format(pack_display_name, str(e))
        prints_manager.add_print_job(err_msg, print_color, thread_index, LOG_COLORS.RED)

        lock.acquire()
        global SUCCESS_FLAG
        SUCCESS_FLAG = False
        lock.release()


def install_packs(client, host, prints_manager, thread_index, packs_to_install, request_timeout=9999999):
    """ Make a packs installation request.

    Args:
        client (demisto_client): The configured client to use.
        host (str): The server URL.
        prints_manager (ParallelPrintsManager): Print manager object.
        thread_index (int): the thread index.
        packs_to_install (list): A list of the packs to install.
        request_timeout (int): Timeout settings for the installation request.
    """

    request_data = {
        'packs': packs_to_install,
        'ignoreWarnings': True
    }

    packs_to_install_str = ', '.join([pack['id'] for pack in packs_to_install])
    message = 'Installing the following packs in server {}:\n{}'.format(host, packs_to_install_str)
    prints_manager.add_print_job(message, print_color, thread_index, LOG_COLORS.GREEN, include_timestamp=True)
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
            message = 'Packs were successfully installed!\n'
            prints_manager.add_print_job(message, print_color, thread_index, LOG_COLORS.GREEN, include_timestamp=True)
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


def search_pack_and_its_dependencies(client, prints_manager, pack_id, packs_to_install,
                                     installation_request_body, thread_index, lock):
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
            pack_data = search_pack(client, prints_manager, pack_display_name, thread_index, lock)

    if pack_data:
        dependencies = get_pack_dependencies(client, prints_manager, pack_data, thread_index, lock)

        current_packs_to_install = [pack_data]
        current_packs_to_install.extend(dependencies)

        lock.acquire()
        for pack in current_packs_to_install:
            if pack['id'] not in packs_to_install:
                packs_to_install.append(pack['id'])
                installation_request_body.append(pack)
        lock.release()


def add_pack_to_installation_request(pack_id, installation_request_body):
    metadata_path = os.path.join(PACKS_FULL_PATH, pack_id, PACK_METADATA_FILE)
    with open(metadata_path, 'r') as json_file:
        pack_metadata = json.load(json_file)
        version = pack_metadata.get('currentVersion')
        installation_request_body.append({
            'id': pack_id,
            'version': version
        })


def install_all_content_packs(client, host, prints_manager, thread_index=0):
    all_packs = []

    for pack_id in os.listdir(PACKS_FULL_PATH):
        if pack_id not in IGNORED_FILES and pack_id != 'Silverfort':  # todo: remove silverfort when fixed
            add_pack_to_installation_request(pack_id, all_packs)
    install_packs(client, host, prints_manager, thread_index, all_packs)


# todo: remove if not used
def upload_zipped_packs(client, host, prints_manager):
    """ Install packs from zip file.

        Args:
            client (demisto_client): The configured client to use.
            host (str): The server URL.
            prints_manager (ParallelPrintsManager): Print manager object.
        """
    header_params = {
        'Content-Type': 'multipart/form-data'
    }

    packs_zip_path = 'artifacts/zipped_packs.zip'
    file_path = os.path.abspath(packs_zip_path)
    files = {'file': file_path}

    message = 'Making "POST" request to server {} - to install all packs from file {}'.format(host, packs_zip_path)
    prints_manager.add_print_job(message, print_color, 0, LOG_COLORS.GREEN)
    prints_manager.execute_thread_prints(0)

    # make the pack installation request
    try:
        response_data, status_code, _ = client.api_client.call_api(resource_path='/contentpacks/installed/upload',
                                                                   method='POST',
                                                                   header_params=header_params, files=files)

        if 200 <= status_code < 300:
            message = 'All packs from {} were successfully installed!\n'.format(packs_zip_path)
            prints_manager.add_print_job(message, print_color, 0, LOG_COLORS.GREEN)
            prints_manager.execute_thread_prints(0)
        else:
            result_object = ast.literal_eval(response_data)
            message = result_object.get('message', '')
            err_msg = 'Failed to install packs - with status code {}\n{}\n'.format(status_code, message)
            raise Exception(err_msg)
    except Exception as e:
        err_msg = 'The request to install packs has failed. Reason:\n{}\n'.format(str(e))
        raise Exception(err_msg)


def search_and_install_packs_and_their_dependencies(pack_ids, client, prints_manager, thread_index=0):
    """ Searches for the packs from the specified list, searches their dependencies, and then installs them.
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

    msg = 'Starting to search and install packs in server: {}\n'.format(host)
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
