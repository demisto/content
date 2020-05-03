from __future__ import print_function

import ast
import json
import demisto_client
from threading import Thread
from demisto_sdk.commands.common.tools import print_error, print_color, LOG_COLORS, is_file_path_in_pack, \
    get_pack_name, run_threads_list


def get_pack_display_name(path):
    if is_file_path_in_pack(path):
        pack_id = get_pack_name(path)
        if pack_id:
            with open('./Packs/{}/pack_metadata.json'.format(pack_id), 'r') as json_file:
                pack_metadata = json.load(json_file)
            return pack_metadata.get('name')
    return ''


def get_pack_data_from_results(search_results, pack_display_name):
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
        response_data (dict): The configured client to use
        pack_id (str): The pack ID

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
        client (demisto_client): The configured client to use
        prints_manager (ParallelPrintsManager): Print manager object
        pack_data (dict): Contains the pack ID and version
    """
    pack_id = pack_data['id']
    host = client.api_client.configuration.host
    prints_manager.add_print_job('\nGetting pack {} dependencies from host {}...'.format(pack_id, host), print, 0)

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

        prints_manager.add_print_job('Found the following dependencies for pack {}:\n{}'.format(pack_id,
                                                                                                dependencies_str),
                                     print_color, 0, LOG_COLORS.GREEN)
        prints_manager.execute_thread_prints(0)
        return dependencies_data
    else:
        result_object = ast.literal_eval(response_data)
        message = result_object.get('message', '')
        err_msg = 'Failed to get pack {} dependencies - with status code {}\n{}'.format(pack_id, status_code, message)
        prints_manager.add_print_job(err_msg, print_error, 0)
        prints_manager.execute_thread_prints(0)
        return {}


def search_pack(client, prints_manager, pack_display_name):
    """ Make a pack search request.

    Args:
        client (demisto_client): The configured client to use
        prints_manager (ParallelPrintsManager): Print manager object
        pack_display_name (string): The pack display name

    Returns:
        (dict): Returns the pack data if found, or empty dict otherwise.
    """

    host = client.api_client.configuration.host
    print_msg = '\nMaking "POST" request to server - "{}" to search pack {}.'.format(host, pack_display_name)
    prints_manager.add_print_job(print_msg, print, 0)

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
            print_msg = '\nFound pack {} in bucket!'.format(pack_display_name)
            prints_manager.add_print_job(print_msg, print_color, 0, LOG_COLORS.GREEN)
            prints_manager.execute_thread_prints(0)
            return pack_data

        else:
            print_msg = 'Did not find pack {} in bucket.'.format(pack_display_name)
            prints_manager.add_print_job(print_msg, print_color, 0, LOG_COLORS.YELLOW)
            prints_manager.execute_thread_prints(0)
            return {}
    else:
        result_object = ast.literal_eval(response_data)
        msg = result_object.get('message', '')
        err_msg = 'Pack {} search request failed - with status code {}\n{}'.format(pack_display_name, status_code, msg)
        prints_manager.add_print_job(err_msg, print_error, 0)
        prints_manager.execute_thread_prints(0)
        return {}


def install_pack(client, prints_manager, pack_display_name, packs_to_install):
    """ Make a pack installation request.

    Args:
        client (demisto_client): The configured client to use
        prints_manager (ParallelPrintsManager): Print manager object
        pack_display_name (string): The pack display name
        packs_to_install (list): A list of the packs to install.
    """
    host = client.api_client.configuration.host
    prints_manager.add_print_job('\nMaking "POST" request to server - "{}" to install pack {}'
                                 ' and its dependencies.'.format(host, pack_display_name), print, 0)

    request_data = {
        'packs': packs_to_install,
        'ignoreWarnings': True
    }

    # make the pack installation request
    response_data, status_code, _ = demisto_client.generic_request_func(client,
                                                                        path='/contentpacks/marketplace/install',
                                                                        method='POST',
                                                                        body=request_data,
                                                                        accept='application/json')

    if 200 <= status_code < 300:
        prints_manager.add_print_job('Pack {} Successfully Installed!'.format(pack_display_name), print_color, 0,
                                     LOG_COLORS.GREEN)
        prints_manager.execute_thread_prints(0)
    else:
        result_object = ast.literal_eval(response_data)
        message = result_object.get('message', '')
        err_msg = 'Failed to install pack {} - with status code {}\n{}'.format(pack_display_name, status_code, message)
        prints_manager.add_print_job(err_msg, print_error, 0)
        prints_manager.execute_thread_prints(0)


def search_and_install_pack(client, prints_manager, int_path, installed_packs):
    pack_display_name = get_pack_display_name(int_path)
    pack_data = search_pack(client, prints_manager, pack_display_name)

    dependencies = get_pack_dependencies(client, prints_manager, pack_data)
    packs_to_install = [pack_data] + dependencies
    install_pack(client, prints_manager, pack_display_name, packs_to_install)
    installed_packs.update([pack['id'] for pack in packs_to_install])


def search_and_install_packs_and_their_dependencies(integrations_files, client, prints_manager):
    threads_list = []
    installed_packs = set()

    for int_path in integrations_files:
        thread = Thread(target=search_and_install_pack,
                        kwargs={'client': client,
                                'prints_manager': prints_manager,
                                'int_path': int_path,
                                'installed_packs': installed_packs})
        threads_list.append(thread)
    run_threads_list(threads_list)

    return installed_packs
