from __future__ import print_function

import ast
import json
import demisto_client
from time import sleep
from threading import Thread, Lock
from demisto_sdk.commands.common.tools import print_error, print_color, LOG_COLORS, is_file_path_in_pack, \
    get_pack_name, run_threads_list


def get_pack_id_by_path(path):
    if is_file_path_in_pack(path):
        return get_pack_name(path)
    return ''


def get_pack_metadata(pack_id):  # todo: remove if not used
    with open('./Packs/{}/pack_metadata.json'.format(pack_id), 'r') as json_file:
        pack_metadata = json.load(json_file)
    return pack_metadata


def get_pack_from_results(search_results, pack_id):
    for pack in search_results:
        if pack.get('id') == pack_id:
            return pack
    return {}


def search_pack(client, prints_manager, pack_id):  # todo: maybe change to pack_display_name
    """ Make a pack search request.

    Args:
        client (demisto_client): The configured client to use
        prints_manager (ParallelPrintsManager): Print manager object
        pack_id (string): The pack ID

    Returns:
        (dict): Returns the pack metadata if found, or empty dict otherwise.
    """

    host = client.api_client.configuration.host
    print_msg = '\nMaking "POST" request to server - "{}" to search pack {}.'.format(host, pack_id)
    prints_manager.add_print_job(print_msg, print, 0)

    # make the search request
    response_data, status_code, _ = demisto_client.generic_request_func(client,
                                                                        path='/contentpacks/marketplace/search',
                                                                        method='POST',
                                                                        body={"packsQuery": pack_id},
                                                                        accept='application/json')

    if 200 <= status_code < 300:
        result_object = ast.literal_eval(response_data)
        search_results = result_object.get('packs', [])
        pack_metadata = get_pack_from_results(search_results, pack_id)
        if pack_metadata:
            print_msg = '\nFound pack {} in bucket!'.format(pack_id)
            prints_manager.add_print_job(print_msg, print_color, 0, LOG_COLORS.GREEN)
            prints_manager.execute_thread_prints(0)
            return pack_metadata

        else:
            print_msg = 'Did not find pack {} in bucket.'.format(pack_id)
            prints_manager.add_print_job(print_msg, print_color, 0, LOG_COLORS.YELLOW)
            prints_manager.execute_thread_prints(0)
            return {}
    else:
        result_object = ast.literal_eval(response_data)
        msg = result_object.get('message', '')
        err_msg = 'Pack {} search request failed - with status code {}\n{}'.format(pack_id, status_code, msg)
        prints_manager.add_print_job(err_msg, print_error, 0)
        prints_manager.execute_thread_prints(0)
        return {}


def install_pack(client, prints_manager, pack_id, pack_version):
    """ Make a pack installation request.

    Args:
        client (demisto_client): The configured client to use
        prints_manager (ParallelPrintsManager): Print manager object
        pack_id (string): The pack ID
        pack_version (string): The current version of the pack
    """
    host = client.api_client.configuration.host
    prints_manager.add_print_job('\nMaking "POST" request to server - "{}" to install pack {}.'.format(host, pack_id),
                                 print, 0)

    data = [{
        "id": pack_id,
        "version": pack_version
    }]

    # make the pack installation request
    response_data, status_code, _ = demisto_client.generic_request_func(client,
                                                                        path='/contentpacks/marketplace/install',
                                                                        method='POST',
                                                                        body=data,
                                                                        accept='application/json')

    if 200 <= status_code < 300:
        prints_manager.add_print_job('Pack {} Successfully Installed!'.format(pack_id), print_color, 0,
                                     LOG_COLORS.GREEN)
        prints_manager.execute_thread_prints(0)
    else:
        result_object = ast.literal_eval(response_data)
        message = result_object.get('message', '')
        err_msg = 'Failed to install pack {} - with status code {}\n{}'.format(pack_id, status_code, message)
        prints_manager.add_print_job(err_msg, print_error, 0)
        prints_manager.execute_thread_prints(0)


def is_installation_in_progress(pack_id, packs_in_progress, lock):
    lock.acquire()
    if pack_id not in packs_in_progress:
        packs_in_progress.add(pack_id)
        lock.release()
        return False
    else:
        lock.release()
        return True


def search_and_install_pack(client, prints_manager, pack_id, packs_in_progress, packs_installed, lock):
    if not is_installation_in_progress(pack_id, packs_in_progress, lock):
        pack_metadata = search_pack(client, prints_manager, pack_id)

        # get dependencies, search & install them as well
        dependencies = pack_metadata.get('dependencies', {}).keys()
        threads_list = []
        for pack in dependencies:
            t = Thread(target=search_and_install_pack,
                       kwargs={'client': client,
                               'prints_manager': prints_manager,
                               'pack_id': pack,
                               'packs_in_progress': packs_in_progress,
                               'packs_installed': packs_installed,
                               'lock': lock})

            threads_list.append(t)

        run_threads_list(threads_list)

        pack_version = pack_metadata.get('currentVersion', '')
        install_pack(client, prints_manager, pack_id, pack_version)

        packs_installed.add(pack_id)

    else:
        while pack_id not in packs_installed:
            sleep(1)  # can't proceed to dependency before installed


def search_and_install_packs_and_their_dependencies(integrations_files, client, prints_manager):
    threads_list = []
    packs_in_progress = set()  # used to avoid double installation
    packs_installed = set()  # used to avoid double installation
    lock = Lock()

    packs = [get_pack_id_by_path(path) for path in integrations_files]  # todo: maybe change to pack display name

    message = '\nInstalling the following packs (and their dependencies):\n{}'.format(', '.join(packs))
    prints_manager.add_print_job(message, print, 0)

    for pack_id in packs:
        if pack_id:
            thread = Thread(target=search_and_install_pack,
                            kwargs={'client': client,
                                    'prints_manager': prints_manager,
                                    'pack_id': pack_id,
                                    'packs_in_progress': packs_in_progress,
                                    'packs_installed': packs_installed,
                                    'lock': lock})
            threads_list.append(thread)
    run_threads_list(threads_list)

    return packs_installed
