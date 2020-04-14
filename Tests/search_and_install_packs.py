from __future__ import print_function

import os
import ast
import demisto_client
from threading import Thread, Lock
from demisto_sdk.commands.common.tools import print_error, print_color, LOG_COLORS, is_file_path_in_pack, \
    get_pack_name, run_threads_list
from Tests.test_content import ParallelPrintsManager


def get_pack_id_by_path(path):
    if is_file_path_in_pack(path):
        return get_pack_name(path)
    return ''


def get_pack_from_results(search_results, pack_id):
    for pack in search_results:
        if pack.get('id') == pack_id:
            return pack
    return {}


def search_pack(client, prints_manager, thread_index, pack_id):
    """ Make a pack search request.

    Args:
        client (demisto_client): The configured client to use
        prints_manager (ParallelPrintsManager): Print manager object
        thread_index (int): The thread index
        pack_id (string): The pack ID

    Returns:
        (dict): Returns the pack metadata if found, or empty dict otherwise.
    """

    host = client.api_client.configuration.host
    prints_manager.add_print_job('\nMaking "POST" request to server - "{}" to search pack {}.'.format(host, pack_id),
                                 print, thread_index)

    # make the search request
    response_data, status_code, _ = demisto_client.generic_request_func(self=client,
                                                                        path='/contentpacks/marketplace/search',
                                                                        method='POST',
                                                                        body={"packsQuery": pack_id, "size": 3},
                                                                        accept='application/json')

    if 200 <= status_code < 300:
        result_object = ast.literal_eval(response_data)
        search_results = result_object.get('packs', [])
        pack_metadata = get_pack_from_results(search_results, pack_id)
        if pack_metadata:
            prints_manager.add_print_job('\nFound pack {} in bucket!'.format(pack_id),
                                         print_color, thread_index, LOG_COLORS.GREEN)
            prints_manager.execute_thread_prints(thread_index)
            return pack_metadata

        else:
            prints_manager.add_print_job('Did not find pack {} in bucket.'.format(pack_id), print_color, thread_index,
                                         LOG_COLORS.YELLOW)
            prints_manager.execute_thread_prints(thread_index)
            return {}
    else:
        result_object = ast.literal_eval(response_data)
        message = result_object.get('message', '')
        err_msg = 'Pack {} search request failed - with status code {}\n{}'.format(pack_id, status_code, message)
        prints_manager.add_print_job(err_msg, print_error, thread_index)
        prints_manager.execute_thread_prints(thread_index)
        return {}


def install_pack(client, prints_manager, thread_index, pack_id, pack_version):
    """ Make a pack installation request.

    Args:
        client (demisto_client): The configured client to use
        prints_manager (ParallelPrintsManager): Print manager object
        thread_index (int): The thread index
        pack_id (string): The pack ID
        pack_version (string): The current version of the pack
    """
    host = client.api_client.configuration.host
    prints_manager.add_print_job('\nMaking "POST" request to server - "{}" to install pack {}.'.format(host, pack_id),
                                 print, thread_index)

    data = [{
        "id": pack_id,
        "version": pack_version
    }]

    # make the pack installation request
    response_data, status_code, _ = demisto_client.generic_request_func(self=client,
                                                                        path='/contentpacks/marketplace/install',
                                                                        method='POST',
                                                                        body=data,
                                                                        accept='application/json')

    if 200 <= status_code < 300:
        prints_manager.add_print_job(f'Pack {pack_id} Successfully Installed!', print_color, thread_index,
                                     LOG_COLORS.GREEN)
        prints_manager.execute_thread_prints(thread_index)
    else:
        result_object = ast.literal_eval(response_data)
        message = result_object.get('message', '')
        err_msg = f'Failed to install pack {pack_id} - with status code {status_code}\n' + message
        prints_manager.add_print_job(err_msg, print_error, thread_index)
        prints_manager.execute_thread_prints(thread_index)
        os._exit(1)


def is_installation_in_progress(pack_id, packs_in_progress):
    # we use locks here to validate we don't install a pack twice
    in_progress = False

    lock = Lock()
    lock.acquire()

    if pack_id not in packs_in_progress:
        packs_in_progress.add(pack_id)
        in_progress = True

    lock.release()

    return in_progress


def search_and_install_pack(client, prints_manager, thread_index, pack_id, packs_in_progress):
    if is_installation_in_progress(pack_id, packs_in_progress):
        pack_metadata = search_pack(client, prints_manager, thread_index, pack_id)

        # get dependencies, search & install them as well
        dependencies = pack_metadata.get('dependencies', {}).keys()
        threads_list = []
        threads_prints_manager = ParallelPrintsManager(len(dependencies))
        for idx, pack in enumerate(dependencies):
            t = Thread(target=search_and_install_pack,
                       kwargs={'client': client,
                               'prints_manager': threads_prints_manager,
                               'thread_index': idx,
                               'pack_id': pack,
                               'packs_in_progress': packs_in_progress})

            threads_list.append(t)

        run_threads_list(threads_list)

        pack_version = pack_metadata.get('currentVersion', '')
        install_pack(client, prints_manager, thread_index, pack_id, pack_version)


def search_and_install_pack_and_its_dependencies(client, prints_manager, thread_index, path, packs_in_progress):
    pack_id = get_pack_id_by_path(path)
    if pack_id and pack_id != 'Legacy':
        search_and_install_pack(client, prints_manager, thread_index, pack_id, packs_in_progress)
    else:
        prints_manager.add_print_job('', print_error, thread_index)
        prints_manager.execute_thread_prints(thread_index)
        os._exit(1)
