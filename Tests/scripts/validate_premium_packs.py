import demisto_client
import argparse
import logging
import zipfile
import json
import ast
import sys
import os

from Tests.configure_and_test_integration_instances import Build, Server
from Tests.test_content import get_json_file, ParallelPrintsManager
from demisto_sdk.commands.common.tools import print_color, LOG_COLORS, print_error

INDEX_FILE_PATH = 'index.json'


def options_handler():
    parser = argparse.ArgumentParser(description='Utility for instantiating integration instances')
    parser.add_argument('--ami_env', help='The AMI environment for the current run. Options are '
                                          '"Demisto 6.0", "Demisto Marketplace". The server url is determined by the'
                                          ' AMI environment.', default="Demisto Marketplace")
    parser.add_argument('--index_path', help='The index.zip file path, generated on the cloud\n'
                                             ' In case only_check_index_file is set, specify path to index.json',
                        required=True)
    # parser.add_argument('--commit_hash', help='The commit hash of the current build', required=True)
    parser.add_argument('-s', '--secret', help='Path to secret conf file')
    parser.add_argument('--only_check_index_zip', help='Path to index.zip')
    parser.add_argument('--only_check_index_file', help='Path to index.json')

    options = parser.parse_args()
    if options.only_check_index_zip and options.only_check_index_file:
        logging.info('Options only_check_index_zip and only_check_index_file cannot be true together.')
        return None

    return options


def update_expectations_from_git(index_data):
    # TODO: implement
    return index_data


def unzip_index_and_return_index_file(index_zip_path):
    logging.info('Unzipping')
    with zipfile.ZipFile(index_zip_path, 'r') as zip_obj:
        extracted_path = zip_obj.extract(f"index/{INDEX_FILE_PATH}", path="./extracted-index")

    logging.info(f'extracted path is now: {extracted_path}')
    dir_list = os.listdir(f"./extracted-index/index")
    logging.info(f'dir {extracted_path} is now: \n {dir_list}')

    return f"./{extracted_path}"


def check_and_return_index_data(index_file_path):  # , commit_hash):
    with open(index_file_path, 'r') as index_file:
        index_data = json.load(index_file)

    logging.info(f"Found index data:\n {index_data} \n\n Checking...")
    # TODO: check commit hash with master
    # assert index_data["commit"] == commit_hash
    assert len(index_data["packs"]) != 0
    for pack in index_data["packs"]:
        assert pack["id"] != ""
        assert pack["price"] > 0
    return index_data


def get_paid_packs(client: demisto_client, prints_manager: ParallelPrintsManager, thread_index: int,
                   request_timeout: int = 999999):

    request_data = \
        {
            'page': 0,
            'size': 50,
            'sort':
                [{
                    'field': 'updated',
                    'asc': 0
                }],
            'general': ["generalFieldPaid"]
        }

    message = f'Getting premium packs from server {client.api_client.configuration.host}:\n'
    prints_manager.add_print_job(message, print_color, thread_index, LOG_COLORS.GREEN,
                                 include_timestamp=True)
    prints_manager.execute_thread_prints(thread_index)

    # make the pack installation request
    response_data, status_code, _ = demisto_client.generic_request_func(client,
                                                                        path='/contentpacks/marketplace/search',
                                                                        method='POST',
                                                                        body=request_data,
                                                                        accept='application/json',
                                                                        _request_timeout=request_timeout)

    if status_code == 200:
        response = json.load(response_data)
        packs_message = 'Got premium packs from server'
        prints_manager.add_print_job(packs_message, print_color, thread_index, LOG_COLORS.GREEN, include_timestamp=True)
        return response["packs"]
    result_object = ast.literal_eval(response_data)
    message = result_object.get('message', '')
    err_msg = f'Failed to retrieve premium packs - with status code {status_code}\n{message}\n'
    prints_manager.add_print_job(err_msg, print_error, thread_index, include_timestamp=True)
    return None


def verify_server_paid_packs_by_index(server_paid_packs, index_data):

    # Sorting both lists by id
    sorted_server_packs = sorted(server_paid_packs, key=lambda i: i['id'])
    sorted_index_packs = sorted(index_data, key=lambda i: i['id'])

    # Checking lists are the same.
    for (server_pack, index_pack) in zip(sorted_server_packs, sorted_index_packs):
        assert server_pack["id"] == index_pack["id"]
        assert server_pack["price"] == index_pack["price"]


def main():
    logging.info('Retrieving the index fle')
    options = options_handler()
    if not options.only_check_index_file:
        index_file_path = unzip_index_and_return_index_file(options.index_path)
    else:
        index_file_path = options.index_path

    index_data = check_and_return_index_data(index_file_path)  # options.commit_hash)
    update_expectations_from_git(index_data)

    if not (options.only_check_index_zip or options.only_check_index_file):

        # Get the host by the ami env
        hosts, _ = Build.get_servers(ami_env=options.ami_env)

        logging.info('Retrieving the credentials for Cortex XSOAR server')
        secret_conf_file = get_json_file(path=options.secret)
        username: str = secret_conf_file.get('username')
        password: str = secret_conf_file.get('userPassword')

        # Check the marketplace
        for host in hosts:
            server = Server(host=host, user_name=username, password=password)
            paid_packs = get_paid_packs(client=server.client)
            if paid_packs is not None:
                logging.info(f'Verifying premium packs in {host}')
                verify_server_paid_packs_by_index(paid_packs, index_data)
            else:
                sys.exit(1)


if __name__ == '__main__':
    main()
