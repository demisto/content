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

from Tests.Marketplace.marketplace_services import init_storage_client, GCPConfig, CONTENT_ROOT_PATH
from Tests.Marketplace.upload_packs import download_and_extract_index, get_content_git_client
from Tests.configure_and_test_integration_instances import Build, Server
from Tests.scripts.utils.log_util import install_logging
from Tests.test_content import get_json_file
from pprint import pformat

INDEX_FILE_PATH = 'index.json'
DEFAULT_PAGE_SIZE = 50


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
    parser.add_argument('-e', '--extract_path', help="Full path of folder to extract wanted packs", required=True)
    parser.add_argument('-pb', '--production_bucket_name', help="Production bucket name", required=True)
    parser.add_argument('-sa', '--service_account',
                        help=("Path to gcloud service account, is for circleCI usage. "
                              "For local development use your personal account and "
                              "authenticate using Google Cloud SDK by running: "
                              "`gcloud auth application-default login` and leave this parameter blank. "),
                        required=True)
    parser.add_argument('-s', '--secret', help='Path to secret conf file', required=True)

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


def check_index_data(index_data):
    """Check index.json file inside the index.zip archive in the cloud.

    Validate no missing ids are found and that all packs have a positive price.

    Args:
        index_data: The path to the index.json.

    Returns: Dict with the index data.

    """
    logging.info("Found index data in index file. Checking...")
    logging.debug(f"Index data is:\n {pformat(index_data)}")

    packs_list_exists = log_message_if_statement(statement=(len(index_data.get("packs", [])) != 0),
                                                 error_message="Found 0 packs in index file."
                                                               "\nAborting the rest of the check.")
    if not packs_list_exists:
        return False

    packs_are_valid = True
    for pack in index_data["packs"]:
        pack_is_good = verify_pack(pack)
        if not pack_is_good:
            packs_are_valid = False

    return packs_are_valid


def verify_pack(pack):
    """

    Args:
        pack:

    Returns:

    """
    id_exists = log_message_if_statement(statement=(pack.get("id", "") != ""),
                                         error_message="There is a missing pack id.",
                                         success_message=f"Found pack with a valid id: {pack['id']}.")
    price_is_valid = log_message_if_statement(statement=(pack.get("price", -1) > 0),
                                              error_message=f"The price on the pack {pack['id']} is 0 or less.",
                                              success_message=f"The price on the pack {pack['id']} is valid.")
    return all(id_exists, price_is_valid)


def get_paid_packs_page(client: demisto_client, page: int = 0, size: int = DEFAULT_PAGE_SIZE, request_timeout: int = 999999):
    """Get premium packs from client.

    Trigger an API request to demisto server.
    Request is identical to checking the premium box through the marketplace GUI.

    Args:
        client: The demisto client to the preform request on.
        page:
        size:
        request_timeout: Timeout of API request

    Returns:
        Dict of premium packs as found in the server.
        Return None if no premium packs were found.
    """
    request_data = \
        {
            'page': page,
            'size': size,
            'sort':
                [{
                    'field': 'updated',
                    'asc': False
                }],
            'general': ["generalFieldPaid"]
        }

    logging.info(f'Getting premium packs from server {client.api_client.configuration.host}:')

    # make the pack installation request
    response_data, status_code, _ = demisto_client.generic_request_func(client,
                                                                        path='/contentpacks/marketplace/search',
                                                                        method='POST',
                                                                        body=request_data,
                                                                        accept='application/json',
                                                                        _request_timeout=request_timeout)

    if status_code == 200:
        logging.debug(f'Got response data {pformat(response_data)}')
        response = ast.literal_eval(response_data)
        logging.info('Got premium packs from server.')
        return response["packs"], response["total"]

    result_object = ast.literal_eval(response_data)
    message = result_object.get('message', '')
    logging.error(f'Failed to retrieve premium packs - with status code {status_code}\n{message}\n')
    return None


def get_premium_packs(client: demisto_client, request_timeout: int = 999999):
    """

    Args:
        client:
        request_timeout:

    Returns:

    """
    server_packs, total = get_paid_packs_page(client=client,
                                              page=0,
                                              size=DEFAULT_PAGE_SIZE,
                                              request_timeout=request_timeout)
    if total <= DEFAULT_PAGE_SIZE:
        return server_packs
    if total % DEFAULT_PAGE_SIZE == 0:
        pages_until_all = int(total / DEFAULT_PAGE_SIZE)
    else:
        pages_until_all = int(total / DEFAULT_PAGE_SIZE) + 1

    for page in range(1, pages_until_all + 1):
        next_server_packs, _ = get_paid_packs_page(client=client,
                                                   page=page,
                                                   size=DEFAULT_PAGE_SIZE,
                                                   request_timeout=request_timeout)
        server_packs.update(next_server_packs)
    return server_packs


def verify_pack_in_list(pack, pack_list, pack_list_name="pack list"):
    """Verify pack is in the pack list with same id and price.

    Args:
        pack: (Dict) pack containing an id and a price.
        pack_list: (List[Dict]) list of packs containing id and a price.
        pack_list_name: Name of the list for better logs.

    Returns: True if pack is in list, False otherwise.
    """
    for pack_from_list in pack_list:
        if pack["id"] == pack_from_list["id"]:
            price_matches = log_message_if_statement(statement=(pack["price"] == pack_from_list["price"]),
                                                     error_message=f'Price in pack {pack["id"]} does not match the'
                                                                   f' price in the list. '
                                                                   f'{pack["price"]} != {pack_from_list["price"]}',
                                                     success_message=f'Pack {pack["id"]} is valid.')
            return price_matches

    logging.error(f'Pack {pack["id"]} is not in {pack_list_name}')
    return False


def verify_server_paid_packs_by_index(server_paid_packs, index_data_packs):
    """Compare two pack dictionaries and assert id's and prices are identical.

    Log errors if the lists differ.

    Args:
        server_paid_packs: Dictionary of packs to check.
        index_data_packs: Dictionary of packs to compare to.

    Return:
        True if all packs are identical, False otherwise.
    """

    logging.info('Verifying all premium server packs are in the index.json')
    missing_server_packs = []
    for server_pack in server_paid_packs:
        server_pack_in_index = verify_pack_in_list(server_pack, index_data_packs, "index packs")
        if not server_pack_in_index:
            missing_server_packs.append(server_pack)

    all_server_packs_in_index = log_message_if_statement(statement=(len(missing_server_packs) == 0),
                                                         error_message=f'The following premium server packs were'
                                                                       f' not found exactly the same as in the index'
                                                                       f' packs:\n{pformat(missing_server_packs)}')

    logging.info('Verifying all premium index packs are in the server')
    missing_index_packs = []
    for index_pack in index_data_packs:
        index_pack_in_server = verify_pack_in_list(index_pack, server_paid_packs, "premium server packs")
        if not index_pack_in_server:
            missing_index_packs.append(index_pack)

    all_index_packs_in_server = log_message_if_statement(statement=(len(missing_index_packs) == 0),
                                                         error_message=f'The following index packs were'
                                                                       f' not found exactly the same as in the server'
                                                                       f' packs:\n{pformat(missing_index_packs)}')

    return all(all_index_packs_in_server, all_server_packs_in_index)


def get_hexsha(commit):
    return commit.hexsha


def check_commit_in_master_history(index_commit_hash):
    """Assert commit hash is in master history.

    Args:
        index_commit_hash: commit hash

    Returns: True if commit hash is in master history, False otherwise.
    """
    content_repo = get_content_git_client(CONTENT_ROOT_PATH)
    master_commits = list(map(get_hexsha, list(content_repo.iter_commits("master"))))

    return log_message_if_statement(statement=(index_commit_hash in master_commits),
                                    error_message=f'Commit hash {index_commit_hash} is not in master history',
                                    success_message="Commit hash in index file is valid.")


def get_and_validate_index_json(service_account, production_bucket_name, extract_path):
    """

    Args:
        service_account:
        production_bucket_name:
        extract_path:
        master_history:

    Returns:

    """
    logging.info('Downloading and extracting index.zip from the cloud')
    storage_client = init_storage_client(service_account)
    production_bucket = storage_client.bucket(production_bucket_name)
    index_folder_path, build_index_blob, build_index_generation = \
        download_and_extract_index(production_bucket, extract_path)

    logging.info('Retrieving the index file')
    index_file_path = os.path.join(index_folder_path, f'{GCPConfig.INDEX_NAME}.json')
    with open(index_file_path, 'r') as index_file:
        index_data = json.load(index_file)

    # Validate index.json file
    index_is_valid = check_index_data(index_data)
    log_message_if_statement(statement=index_is_valid,
                             error_message=f"The packs in the {index_file_path} file were found invalid.",
                             success_message=f"{index_file_path} file was found valid")

    # Validate commit hash in master history
    commit_hash_is_valid = check_commit_in_master_history(index_data.get("commit", ""))
    return all(index_is_valid, commit_hash_is_valid), index_data


def extract_credentials_from_secret(secret_path):
    """

    Args:
        secret_path:

    Returns:

    """
    logging.info('Retrieving the credentials for Cortex XSOAR server')
    secret_conf_file = get_json_file(path=secret_path)
    username: str = secret_conf_file.get('username')
    password: str = secret_conf_file.get('userPassword')
    return username, password


def main():
    install_logging('Validate Premium Packs.log')
    options = options_handler()

    index_is_valid, index_data = get_and_validate_index_json(service_account=options.service_account,
                                                             production_bucket_name=options.production_bucket_name,
                                                             extract_path=options.extract_path)
    if not index_is_valid:
        logging.critical('Index content is invalid. Aborting.')
        sys.exit(1)

    # Get the first host by the ami env
    hosts, _ = Build.get_servers(ami_env=options.ami_env)
    host = hosts[0]
    username, password = extract_credentials_from_secret(options.secret)
    server = Server(host=host, user_name=username, password=password)

    # Verify premium packs in the server
    paid_packs = get_premium_packs(client=server.client)
    if paid_packs is not None:
        logging.info(f'Verifying premium packs in {server.host}')
        paid_packs_are_identical = verify_server_paid_packs_by_index(paid_packs, index_data["packs"])
        log_message_if_statement(statement=paid_packs_are_identical,
                                 error_message=f'Test failed on host: {server.host}.',
                                 success_message=f'All premium packs in host: {server.host} are valid')
        if not paid_packs_are_identical:
            sys.exit(1)
    else:
        logging.critical(f'Missing all premium packs in host: {server.host}')
        sys.exit(1)


if __name__ == '__main__':
    main()
