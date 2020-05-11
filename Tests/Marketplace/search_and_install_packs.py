from __future__ import print_function

import ast
import json
import demisto_client
from threading import Thread, Lock
from demisto_sdk.commands.common.tools import print_error, print_color, LOG_COLORS, run_threads_list


def get_pack_display_name(pack_id):
    if pack_id:
        with open('./Packs/{}/pack_metadata.json'.format(pack_id), 'r') as json_file:
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


def create_dependencies_data_structure(response_data, pack_id):
    """ Creates the pack's dependencies data structure for the installation requests (only required and uninstalled).

    Args:
        response_data (dict): The configured client to use.
        pack_id (str): The pack ID.

    Returns:
        (tuple): The dependencies data structure, and a string of the dependencies ids.
    """
    dependencies_data = []

    if response_data and response_data.get('dependencies'):
        for dependency in response_data.get('dependencies'):
            is_required = dependency.get('dependants', {}).get(pack_id, {}).get('level', '') == 'required'
            # empty currentVersion field implies the pack isn't installed yet
            if not dependency.get('currentVersion') and is_required:
                dependencies_data.append({
                    'id': dependency.get('id'),
                    'version': dependency.get('extras', {}).get('pack', {}).get('currentVersion')
                })

    dependencies_str = ', '.join(dependency['id'] for dependency in dependencies_data)

    return dependencies_data, dependencies_str


def get_pack_dependencies(client, prints_manager, pack_data):
    """ Get the pack's required dependencies.

    Args:
        client (demisto_client): The configured client to use.
        prints_manager (ParallelPrintsManager): A prints manager object.
        pack_data (dict): Contains the pack ID and version.

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
            accept='application/json'
        )

        if 200 <= status_code < 300:
            dependencies_data, dependencies_str = create_dependencies_data_structure(ast.literal_eval(response_data),
                                                                                     pack_id)
            if dependencies_data:
                message = 'Found the following dependencies for pack {}:\n{}'.format(pack_id, dependencies_str)
                prints_manager.add_print_job(message, print_color, 0, LOG_COLORS.GREEN)
                prints_manager.execute_thread_prints(0)
            return dependencies_data
        else:
            result_object = ast.literal_eval(response_data)
            msg = result_object.get('message', '')
            err_msg = 'Failed to get pack {} dependencies - with status code {}\n{}'.format(pack_id, status_code, msg)
            raise Exception(err_msg)
    except Exception as e:
        err_msg = 'The request to get pack {} dependencies has failed. Reason:\n{}'.format(pack_id, str(e))
        raise Exception(err_msg)


def search_pack(client, prints_manager, pack_display_name):
    """ Make a pack search request.

    Args:
        client (demisto_client): The configured client to use.
        prints_manager (ParallelPrintsManager): Print manager object.
        pack_display_name (string): The pack display name.

    Returns:
        (dict): Returns the pack data if found, or empty dict otherwise.
    """

    try:
        # make the search request
        response_data, status_code, _ = demisto_client.generic_request_func(client,
                                                                            path='/contentpacks/marketplace/search',
                                                                            method='POST',
                                                                            body={"packsQuery": pack_display_name},
                                                                            accept='application/json')

        if 200 <= status_code < 300:
            result_object = ast.literal_eval(response_data)
            search_results = result_object.get('packs', [])
            pack_data = get_pack_data_from_results(search_results, pack_display_name)
            if pack_data:
                print_msg = 'Found pack {} in bucket!\n'.format(pack_display_name)
                prints_manager.add_print_job(print_msg, print_color, 0, LOG_COLORS.GREEN)
                prints_manager.execute_thread_prints(0)
                return pack_data

            else:
                print_msg = 'Did not find pack {} in bucket.\n'.format(pack_display_name)
                prints_manager.add_print_job(print_msg, print_color, 0, LOG_COLORS.YELLOW)
                prints_manager.execute_thread_prints(0)
                return {}
        else:
            result_object = ast.literal_eval(response_data)
            msg = result_object.get('message', '')
            err_msg = 'Pack {} search request failed - with status code {}\n{}'.format(pack_display_name,
                                                                                       status_code, msg)
            raise Exception(err_msg)
    except Exception as e:
        err_msg = 'The request to search pack {} has failed. Reason:\n{}'.format(pack_display_name, str(e))
        raise Exception(err_msg)


def install_packs(client, packs_to_install):
    """ Make a packs installation request.

    Args:
        client (demisto_client): The configured client to use.
        packs_to_install (list): A list of the packs to install.
    """

    request_data = {
        'packs': packs_to_install,
        'ignoreWarnings': True
    }

    # make the pack installation request
    try:
        response_data, status_code, _ = demisto_client.generic_request_func(client,
                                                                            path='/contentpacks/marketplace/install',
                                                                            method='POST',
                                                                            body=request_data,
                                                                            accept='application/json')

        if not 200 <= status_code < 300:
            result_object = ast.literal_eval(response_data)
            message = result_object.get('message', '')
            err_msg = 'Failed to install packs - with status code {}\n{}'.format(status_code, message)
            raise Exception(err_msg)
    except Exception as e:
        err_msg = 'The request to install packs has failed. Reason:\n{}'.format(str(e))
        raise Exception(err_msg)


def search_pack_and_its_dependencies(client, prints_manager, pack_id, packs_to_install,
                                     installation_request_body, lock):
    """ Searches for the pack of the specified file path, as well as its dependencies,
        and updates the list of packs to be installed accordingly.

    Args:
        client (demisto_client): The configured client to use.
        prints_manager (ParallelPrintsManager): A prints manager object.
        pack_id (str): The id of the pack to be installed.
        packs_to_install (list): A list of packs to be installed.
        installation_request_body (list): A list of packs to be installed, in the request format.
        lock (Lock): A lock object.
    """
    pack_display_name = get_pack_display_name(pack_id)
    pack_data = search_pack(client, prints_manager, pack_display_name)

    if pack_data:
        dependencies = get_pack_dependencies(client, prints_manager, pack_data)

        current_packs_to_install = [pack_data]
        current_packs_to_install.extend(dependencies)

        lock.acquire()
        for pack in current_packs_to_install:
            if pack['id'] not in packs_to_install:
                packs_to_install.append(pack['id'])
                installation_request_body.append(pack)
        lock.release()


def search_and_install_packs_and_their_dependencies(pack_ids, client, prints_manager):
    """ Searches for the packs from the specified list, searches their dependencies, and then installs them.
    Args:
        pack_ids (list): A list of the pack ids to search and install.
        client (demisto_client): The client to connect to.
        prints_manager (ParallelPrintsManager): A prints manager object.

    Returns (list): A list of the installed packs' ids.
    """
    lock = Lock()
    threads_list = []

    packs_to_install = []  # we save here all the packs we want to install, to avoid duplications
    installation_request_body = []  # the packs to install, in the request format

    host = client.api_client.configuration.host
    msg = 'Starting to search and install packs in server: {}\n'.format(host)
    prints_manager.add_print_job(msg, print_color, 0, LOG_COLORS.GREEN)
    prints_manager.execute_thread_prints(0)

    for pack_id in pack_ids:
        thread = Thread(target=search_pack_and_its_dependencies,
                        kwargs={'client': client,
                                'prints_manager': prints_manager,
                                'pack_id': pack_id,
                                'packs_to_install': packs_to_install,
                                'installation_request_body': installation_request_body,
                                'lock': lock})
        threads_list.append(thread)
    run_threads_list(threads_list)

    install_packs(client, installation_request_body)

    packs_str = '\n'.join(packs_to_install)
    message = 'Successully installed the following packs in server {}:\n{}'.format(host, packs_str)
    prints_manager.add_print_job(message, print_color, 0, LOG_COLORS.GREEN)
    prints_manager.execute_thread_prints(0)

    return packs_to_install

