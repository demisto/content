"""Validate premium packs.

Check the server configured on master.
Validate the pack id's in the index file are present on the server and the prices match.
"""
import demisto_client
import argparse
import logging
import ast
import sys
import os

from Tests.scripts.validate_index import log_message_if_statement, get_index_json_data
from Tests.configure_and_test_integration_instances import Build, Server
from Tests.Marketplace.marketplace_services import load_json, GCPConfig
from Tests.scripts.utils.log_util import install_logging
from pprint import pformat

DEFAULT_PAGE_SIZE = 50


def options_handler():
    parser = argparse.ArgumentParser(description='Test for validating premium packs on servers.')
    parser.add_argument('-a', '--ami_env',
                        help='The AMI environment for the current run. Options are '
                             '"Demisto 6.0", "Server Master". The server url is determined by the'
                             ' AMI environment.', default='Server Master')
    parser.add_argument('-e', '--extract_path',
                        help=f'Full path of folder to extract the {GCPConfig.INDEX_NAME}.zip to',
                        required=True)
    parser.add_argument('-pb', '--production_bucket_name', help='Production bucket name', required=True)
    parser.add_argument('-sa', '--service_account', help='Path to gcloud service account', required=True)
    parser.add_argument('-s', '--secret', help='Path to secret conf file', required=True)

    options = parser.parse_args()
    return options


def get_paid_packs_page(client: demisto_client,
                        page: int = 0,
                        size: int = DEFAULT_PAGE_SIZE,
                        request_timeout: int = 999999) -> (dict, int):
    """Get premium packs from client.

    Trigger an API request to demisto server.
    Request is identical to checking the premium box through the marketplace GUI.

    Args:
        client: The demisto client to the preform request on.
        page: Page number of the request.
        size: Number of packs to bring each time.
        request_timeout: Timeout of API request

    Returns:
        (Dict: premium packs as found in the server, int: Total premium packs that exist)
        (None, 0) if no premium packs were found.
    """
    request_data = {
        'page': page,
        'size': size,
        'sort': [{
            'field': 'updated',
            'asc': False
        }],
        'general': ["generalFieldPaid"]
    }

    logging.info(f"Getting premium packs from server {client.api_client.configuration.host}:")

    try:
        # make the pack installation request
        response_data, status_code, _ = demisto_client.generic_request_func(client,
                                                                            path='/contentpacks/marketplace/search',
                                                                            method='POST',
                                                                            body=request_data,
                                                                            accept='application/json',
                                                                            _request_timeout=request_timeout)
    except Exception as exception:
        logging.error(f"Error trying to communicate with demisto server: {exception}")
        return None, 0

    logging.debug(f"Got response data {pformat(response_data)}")
    response = ast.literal_eval(response_data)
    if status_code == 200:
        logging.info("Got premium packs from server.")
        return response["packs"], response["total"]

    message = response.get('message', '')
    logging.error(f"Failed to retrieve premium packs - with status code {status_code}\n{message}\n")
    return None, 0


def get_premium_packs(client: demisto_client, request_timeout: int = 999999) -> dict:
    """Get premium packs from client.

    Handle the pagination.

    Args:
        client: The demisto client to the preform request on.
        request_timeout: Timeout of each API request

    Returns:
        Dict of premium packs as found in the server.
        Return None if no premium packs were found.
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

    for page in range(1, pages_until_all):
        next_server_packs, _ = get_paid_packs_page(client=client,
                                                   page=page,
                                                   size=DEFAULT_PAGE_SIZE,
                                                   request_timeout=request_timeout)
        server_packs.update(next_server_packs)
    return server_packs


def verify_pack_in_list(pack: dict, pack_list: list, pack_list_name: str = "pack list") -> bool:
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


def verify_outer_contains_inner(inner_packs: list, outer_packs: list, inner_packs_name: str,
                                outer_packs_name: str) -> bool:
    """Verify inner_packs are all inside outer_packs.

    Args:
        inner_packs: List of packs to verify.
        outer_packs: List of packs to verify from.
        inner_packs_name: Name of inner packs for better logging.
        outer_packs_name: Name of outer packs for better logging.

    Returns: True if all inner_packs are inside, false otherwise.
    """
    missing_packs = []
    for inner_pack in inner_packs:
        pack_inside = verify_pack_in_list(inner_pack, outer_packs, outer_packs_name)
        if not pack_inside:
            missing_packs.append({"id": inner_pack["id"], "price": inner_pack["price"]})

    return log_message_if_statement(statement=(len(missing_packs) == 0),
                                    error_message=f"The following {inner_packs_name} were"
                                    f" not found exactly the same as in the {outer_packs_name}:"
                                    f" \n{pformat(missing_packs)}")


def verify_server_paid_packs_by_index(server_paid_packs: list, index_data_packs: list) -> bool:
    """Compare two pack dictionaries and assert id's and prices are identical.

    Log errors if the lists differ.

    Args:
        server_paid_packs: Dictionary of packs to check.
        index_data_packs: Dictionary of packs to compare to.

    Return:
        True if all packs are identical, False otherwise.
    """

    logging.info("Verifying all premium server packs are in the index.json")
    all_server_packs_in_index = verify_outer_contains_inner(inner_packs=server_paid_packs,
                                                            outer_packs=index_data_packs,
                                                            inner_packs_name="premium server packs",
                                                            outer_packs_name="index packs")

    logging.info("Verifying all premium index packs are in the server")
    all_index_packs_in_server = verify_outer_contains_inner(inner_packs=index_data_packs,
                                                            outer_packs=server_paid_packs,
                                                            inner_packs_name="index packs",
                                                            outer_packs_name="premium server packs")

    return all([all_index_packs_in_server, all_server_packs_in_index])


def extract_credentials_from_secret(secret_path: str) -> (str, str):
    """Extract Credentials from secret file.

    Args:
        secret_path: The path to the secret file.

    Returns: (username, password) found in the secret file.
    """
    logging.info("Retrieving the credentials for Cortex XSOAR server")
    secret_conf_file = load_json(file_path=secret_path)
    username: str = secret_conf_file.get("username")
    password: str = secret_conf_file.get("userPassword")
    return username, password


def main():
    install_logging("Validate Premium Packs.log")
    options = options_handler()
    exit_code = 0

    index_data, index_path = get_index_json_data(service_account=options.service_account,
                                                 production_bucket_name=options.production_bucket_name,
                                                 extract_path=options.extract_path)

    # Get the first host by the ami env
    hosts, _ = Build.get_servers(ami_env=options.ami_env)
    host = hosts[0]
    username, password = extract_credentials_from_secret(options.secret)
    server = Server(host=host, user_name=username, password=password)

    # Verify premium packs in the server
    paid_packs = get_premium_packs(client=server.client)
    if paid_packs:
        logging.info(f"Verifying premium packs in {server.host}")
        paid_packs_are_identical = verify_server_paid_packs_by_index(paid_packs, index_data["packs"])
        log_message_if_statement(statement=paid_packs_are_identical,
                                 error_message=f"Test failed on host: {server.host}.",
                                 success_message=f"All premium packs in host: {server.host} are valid")
        if not paid_packs_are_identical:
            exit_code = 1
    else:
        logging.critical(f"Missing all premium packs in host: {server.host}")
        exit_code = 1

    # Deleting GCS PATH before exit
    if os.path.exists(options.service_account):
        os.remove(options.service_account)
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
