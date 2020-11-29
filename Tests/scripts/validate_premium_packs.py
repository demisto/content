"""Validate premium packs.

Check index.json file inside the index.zip archive in the cloud.
Validate no missing ids are found and that all packs have a positive price.
Validate commit hash is in master's history.
Check the server configured on master.
Validate the pack id's in the index file are present on the server and the prices match.
"""
import demisto_client
import argparse
import logging
import zipfile
import json
import ast
import sys
import os

from Tests.configure_and_test_integration_instances import Build, Server
from Tests.scripts.utils.log_util import install_logging
from Tests.test_content import get_json_file

INDEX_FILE_PATH = 'index.json'


def options_handler():
    parser = argparse.ArgumentParser(description='Utility for instantiating integration instances')
    parser.add_argument('--ami_env', help='The AMI environment for the current run. Options are '
                                          '"Demisto 6.0", "Demisto Marketplace". The server url is determined by the'
                                          ' AMI environment.', default="Demisto Marketplace")
    parser.add_argument('--index_path', help='The index.zip file path, generated on the cloud\n'
                                             ' In case only_check_index_file is set, specify path to index.json',
                        required=True)
    parser.add_argument('--master_history', help='Path to a file that contains the master history commit hashes',
                        required=True)
    parser.add_argument('-s', '--secret', help='Path to secret conf file')

    options = parser.parse_args()

    return options


def log_message_if_statement(statement, error_message, success_message=None):
    """Log error message if statement is false, Log success otherwise

    Args:
        statement: The boolean statement to check.
        error_message: The error message to log if statement is false
        success_message: The success message to log if statement is true

    Returns: The statements boolean value.
    """
    if not statement:
        logging.error(error_message)
    elif success_message is not None:
        logging.success(success_message)
    return statement


def unzip_index_and_return_index_file(index_zip_path):
    """Unzip index.zip and return the extracted index.json path

    Args:
        index_zip_path: The path to the index.zip file.

    Returns: The extracted index.json path
    """
    logging.info('Unzipping')
    with zipfile.ZipFile(index_zip_path, 'r') as zip_obj:
        extracted_path = zip_obj.extract(member=f"index/{INDEX_FILE_PATH}", path="./extracted-index")

    logging.info(f'extracted path is now: {extracted_path}')

    return f"./{extracted_path}"


def check_and_return_index_data(index_file_path):
    """Check index.json file inside the index.zip archive in the cloud.

    Validate no missing ids are found and that all packs have a positive price.

    Args:
        index_file_path: The path to the index.json.

    Returns: Dict with the index data.

    """
    with open(index_file_path, 'r') as index_file:
        index_data = json.load(index_file)

    logging.info("Found index data in index file. Checking...")
    logging.debug(f"Index data is:\n {index_data}")

    packs_list_exists = log_message_if_statement(statement=(len(index_data["packs"]) != 0),
                                                 error_message="Found 0 packs in index file."
                                                               "\nAborting the rest of the check.")
    if not packs_list_exists:
        return False

    packs_are_valid = True
    for pack in index_data["packs"]:
        id_exists = log_message_if_statement(statement=(pack["id"] != ""),
                                             error_message="There is a missing pack id.")
        price_is_valid = log_message_if_statement(statement=(pack["price"] > 0),
                                                  error_message=f"The price on the pack {pack['id']} is 0 or less")
        if (not id_exists) or (not price_is_valid):
            packs_are_valid = False

    log_message_if_statement(statement=packs_are_valid,
                             error_message=f"The packs in the {index_file_path} file were found invalid.",
                             success_message=f"{index_file_path} file was found valid")
    return packs_are_valid, index_data


def get_paid_packs(client: demisto_client, request_timeout: int = 999999):
    """Get premium packs from client.

    Trigger an API request to demisto server.
    Request is identical to checking the premium box through the marketplace GUI.

    Args:
        client: The demisto client to the preform request on.
        request_timeout: Timeout of API request

    Returns:
        Dict of premium packs as found in the server.
        Return None if no premium packs were found.
    """
    request_data = \
        {
            'page': 0,
            'size': 50,
            'sort':
                [{
                    'field': 'updated',
                    'asc': False
                }],
            'general': ["generalFieldPaid"]
        }

    logging.info(f'Getting premium packs from server {client.api_client.configuration.host}:\n')

    # make the pack installation request
    response_data, status_code, _ = demisto_client.generic_request_func(client,
                                                                        path='/contentpacks/marketplace/search',
                                                                        method='POST',
                                                                        body=request_data,
                                                                        accept='application/json',
                                                                        _request_timeout=request_timeout)

    if status_code == 200:
        logging.debug(f'Got response data {response_data}')
        response = ast.literal_eval(response_data)
        logging.debug(f'Response dict is {response}')
        logging.info('Got premium packs from server.')
        return response["packs"]

    result_object = ast.literal_eval(response_data)
    message = result_object.get('message', '')
    logging.error(f'Failed to retrieve premium packs - with status code {status_code}\n{message}\n')
    return None


def verify_server_paid_packs_by_index(server_paid_packs, index_data_packs):
    """Compare two pack dictionaries and assert id's and prices are identical.

    Log errors if the lists differ.

    Args:
        server_paid_packs: Dictionary of packs to check.
        index_data_packs: Dictionary of packs to compare to.

    Return:
        True if all packs are identical, False otherwise.
    """
    # Sorting both lists by id
    sorted_server_packs = sorted(server_paid_packs, key=lambda pack: pack['id'])
    sorted_index_packs = sorted(index_data_packs, key=lambda pack: pack['id'])

    packs_identical = True
    # Checking lists are the same.
    for (server_pack, index_pack) in zip(sorted_server_packs, sorted_index_packs):
        ids_match = log_message_if_statement(statement=(server_pack["id"] == index_pack["id"]),
                                             error_message=f'server pack id {server_pack["id"]} '
                                                           f'does not match index pack id {index_pack["id"]}')
        if ids_match:
            prices_match = log_message_if_statement(statement=(server_pack["price"] == index_pack["price"]),
                                                    error_message=f'server pack price {server_pack["price"]} '
                                                                  f'for pack id {server_pack["id"]} '
                                                                  f'does not match the pack price '
                                                                  f'found in the index file {index_pack["price"]}',
                                                    success_message=f'Pack: {server_pack["id"]} is valid.')
            if not prices_match:
                packs_identical = False
        else:
            packs_identical = False

    return packs_identical


def check_commit_in_master_history(index_commit_hash, master_history_path):
    """Assert commit hash is in master history.

    Args:
        index_commit_hash: commit hash
        master_history_path: path to a file with all the master's commit hash history separated by \n

    Returns: True if commit hash is in master history, False otherwise.
    """

    with open(master_history_path, 'r') as master_history_file:
        master_history = master_history_file.read()
        master_commits = master_history.split('\n')

    return log_message_if_statement(statement=(index_commit_hash in master_commits),
                                    error_message=f'Commit hash {index_commit_hash} is not in master history',
                                    success_message="Commit hash in index file is valid.")


def main():
    install_logging('Validate Premium Packs.log')
    logging.info('Retrieving the index file')
    options = options_handler()
    index_file_path = unzip_index_and_return_index_file(options.index_path)

    # Validate index.json file
    index_is_valid, index_data = check_and_return_index_data(index_file_path)

    # Validate commit hash in master history
    commit_hash_is_valid = check_commit_in_master_history(index_data["commit"], options.master_history)

    if (not index_is_valid) or (not commit_hash_is_valid):
        logging.debug('Index content is invalid. Aborting.')
        os.remove(index_file_path)
        sys.exit(1)

    # Get the host by the ami env
    hosts, _ = Build.get_servers(ami_env=options.ami_env)

    logging.info('Retrieving the credentials for Cortex XSOAR server')
    secret_conf_file = get_json_file(path=options.secret)
    username: str = secret_conf_file.get('username')
    password: str = secret_conf_file.get('userPassword')

    # Check the marketplace in the first host
    host = hosts[0]
    server = Server(host=host, user_name=username, password=password)
    paid_packs = get_paid_packs(client=server.client)
    if paid_packs is not None:
        logging.info(f'Verifying premium packs in {host}')
        paid_packs_are_identical = verify_server_paid_packs_by_index(paid_packs, index_data["packs"])
        log_message_if_statement(statement=paid_packs_are_identical,
                                 error_message=f'Test failed on host: {host}.',
                                 success_message=f'All premium packs in host: {host} are valid')
        if not paid_packs_are_identical:
            os.remove(index_file_path)
            sys.exit(1)
    else:
        os.remove(index_file_path)
        logging.error(f'Missing premium packs in host: {host}')
        sys.exit(1)

    os.remove(index_file_path)


if __name__ == '__main__':
    main()
