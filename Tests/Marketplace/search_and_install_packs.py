<<<<<<< HEAD
=======

>>>>>>> 5896217e5bc2e4aeea327a288d416e647bda2af2
import contextlib
from functools import lru_cache
import glob
import json
import os
<<<<<<< HEAD
import time
=======
>>>>>>> 5896217e5bc2e4aeea327a288d416e647bda2af2
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Lock
<<<<<<< HEAD
=======
from time import sleep
from typing import List
>>>>>>> 5896217e5bc2e4aeea327a288d416e647bda2af2

import demisto_client
from demisto_client.demisto_api.rest import ApiException
from demisto_sdk.commands.common import tools
from demisto_sdk.commands.content_graph.common import PACK_METADATA_FILENAME
from google.cloud.storage import Bucket
from packaging.version import Version
from urllib3.exceptions import HTTPWarning, HTTPError

from Tests.Marketplace.marketplace_constants import (IGNORED_FILES,
                                                     PACKS_FOLDER,
                                                     PACKS_FULL_PATH,
                                                     GCPConfig, Metadata)
from Tests.Marketplace.marketplace_services import (Pack, init_storage_client,
                                                    load_json)
from Tests.Marketplace.upload_packs import download_and_extract_index
from Tests.scripts.utils import logging_wrapper as logging

PACK_PATH_VERSION_REGEX = re.compile(fr'^{GCPConfig.PRODUCTION_STORAGE_BASE_PATH}/[A-Za-z0-9-_.]+/(\d+\.\d+\.\d+)/[A-Za-z0-9-_.]'
                                     r'+\.zip$')
SUCCESS_FLAG = True
WLM_TASK_FAILED_ERROR_CODE = 101704


<<<<<<< HEAD
def is_pack_deprecated(pack_id: str, check_locally: bool = True, pack_api_data: dict | None = None) -> bool:
    """
    Check whether a pack is deprecated or not.
    Can be checked locally (pack_metadata.json), or using Marketplace API response data.

    Args:
        pack_id (str): ID of the pack to check.
        check_locally (bool): Whether to check locally (pack_metadata file) or not (will use Marketplace API data instead).
        pack_api_data (dict): Marketplace API data to use if 'check_locally' is False.
            Needs to be the API data of a specific pack item (and not the complete response with a list of packs).

    Returns:
        bool: True if the pack is deprecated, False otherwise
    """
    if check_locally:
        pack_metadata_path = Path(PACKS_FOLDER) / pack_id / PACK_METADATA_FILENAME

        if not pack_metadata_path.is_file():
            return True

        return tools.get_pack_metadata(str(pack_metadata_path)).get('hidden', False)

    else:
        if pack_api_data:
            return pack_api_data['extras']['pack']['deprecated']

        else:
            raise ValueError("'If not checking locally, 'pack_api_data' parameter must be provided.'")
=======
def is_pack_deprecated(pack_path: str) -> bool:
    """Checks whether the pack is deprecated.
    Tests are not being collected for deprecated packs and the pack is not installed in the build process.
    Args:
        pack_path (str): The pack path
    Returns:
        True if the pack is deprecated, False otherwise
    """
    pack_metadata_path = Path(pack_path) / PACK_METADATA_FILENAME
    if not pack_metadata_path.is_file():
        return True
    return tools.get_pack_metadata(str(pack_metadata_path)).get('hidden', False)
>>>>>>> 5896217e5bc2e4aeea327a288d416e647bda2af2


def get_pack_id_from_error_with_gcp_path(error: str) -> str:
    """
<<<<<<< HEAD
    Gets the id of the pack from the pack's path in GCP that is mentioned in the error msg.

=======
        Gets the id of the pack from the pack's path in GCP that is mentioned in the error msg.
>>>>>>> 5896217e5bc2e4aeea327a288d416e647bda2af2
    Args:
        error: path of pack in GCP.

    Returns:
<<<<<<< HEAD
        str: The id of given pack.
=======
        The id of given pack.
>>>>>>> 5896217e5bc2e4aeea327a288d416e647bda2af2
    """
    return error.split('/packs/')[1].split('.zip')[0].split('/')[0]


<<<<<<< HEAD
=======
def get_pack_display_name(pack_id: str) -> str:
    """
    Gets the display name of the pack from the pack ID.

    :param pack_id: ID of the pack.
    :return: Name found in the pack metadata, otherwise an empty string.
    """
    metadata_path = os.path.join(PACKS_FULL_PATH, pack_id, PACK_METADATA_FILENAME)
    if pack_id and os.path.isfile(metadata_path):
        with open(metadata_path, 'r') as json_file:
            pack_metadata = json.load(json_file)
        return pack_metadata.get('name')
    return ''


>>>>>>> 5896217e5bc2e4aeea327a288d416e647bda2af2
@lru_cache
def is_pack_hidden(pack_id: str) -> bool:
    """
    Check if the given pack is deprecated.

    :param pack_id: ID of the pack.
    :return: True if the pack is deprecated, i.e. has 'hidden: true' field, False otherwise.
    """
    metadata_path = os.path.join(PACKS_FULL_PATH, pack_id, PACK_METADATA_FILENAME)
    if pack_id and os.path.isfile(metadata_path):
<<<<<<< HEAD
        with open(metadata_path) as json_file:
=======
        with open(metadata_path, 'r') as json_file:
>>>>>>> 5896217e5bc2e4aeea327a288d416e647bda2af2
            pack_metadata = json.load(json_file)
            return pack_metadata.get('hidden', False)
    else:
        logging.warning(f'Could not open metadata file of pack {pack_id}')
    return False


<<<<<<< HEAD
def create_dependencies_data_structure(response_data: dict, dependants_ids: list, dependencies_data: list, checked_packs: list):
    """
    Recursively create packs' dependencies data structure for installation requests (only required and uninstalled).

    Args:
        response_data (dict): Dependencies data from the '/search/dependencies' endpoint response.
=======
def create_dependencies_data_structure(response_data: dict, dependants_ids: list, dependencies_data: list,
                                       checked_packs: list):
    """ Recursively creates the packs' dependencies data structure for the installation requests
    (only required and uninstalled).

    Args:
        response_data (dict): The GET /search/dependencies response data.
>>>>>>> 5896217e5bc2e4aeea327a288d416e647bda2af2
        dependants_ids (list): A list of the dependant packs IDs.
        dependencies_data (list): The dependencies data structure to be created.
        checked_packs (list): Required dependants that were already found.
    """
<<<<<<< HEAD
=======

>>>>>>> 5896217e5bc2e4aeea327a288d416e647bda2af2
    next_call_dependants_ids = []

    for dependency in response_data:
        dependants = dependency.get('dependants', {})
<<<<<<< HEAD
        for dependant in dependants:
            is_required = dependants[dependant].get('level', '') == 'required'
            if dependant in dependants_ids and is_required and dependency['id'] not in checked_packs:
                dependencies_data.append(dependency)
                next_call_dependants_ids.append(dependency['id'])
                checked_packs.append(dependency['id'])
=======
        for dependant in dependants.keys():
            is_required = dependants[dependant].get('level', '') == 'required'
            if dependant in dependants_ids and is_required and dependency.get('id') not in checked_packs:
                dependencies_data.append({
                    'id': dependency.get('id'),
                    'version': dependency.get('extras', {}).get('pack', {}).get('currentVersion')
                })
                next_call_dependants_ids.append(dependency.get('id'))
                checked_packs.append(dependency.get('id'))
>>>>>>> 5896217e5bc2e4aeea327a288d416e647bda2af2

    if next_call_dependants_ids:
        create_dependencies_data_structure(response_data, next_call_dependants_ids, dependencies_data, checked_packs)


<<<<<<< HEAD
def get_pack_dependencies(client: demisto_client, pack_id: str, lock: Lock) -> dict | None:
    """
    Get pack's required dependencies.

    Args:
        client (demisto_client): The configured client to use.
        pack_id (str): ID of the pack to get dependencies for.
        lock (Lock): A lock object.

    Returns:
        dict | None: API response data for the /search/dependencies endpoint. None if the request failed.
    """
    global SUCCESS_FLAG

    api_endpoint = "/contentpacks/marketplace/search/dependencies"
    body = [{"id": pack_id}]  # Not specifying a "version" key will result in the latest version of the pack being fetched.

    logging.debug(f"Fetching dependencies for pack '{pack_id}'.\n"
                  f"Sending POST request to {api_endpoint} with body: {json.dumps(body)}")

    try:
        response_data, _, _ = demisto_client.generic_request_func(
            client,
            path=api_endpoint,
            method='POST',
            body=body,
            accept='application/json',
            _request_timeout=None,
            response_type='object',
        )

        logging.debug(f"Succeeded to fetch dependencies for pack '{pack_id}'.\nResponse: '{json.dumps(response_data)}'")
        return response_data

    except ApiException as ex:
        with lock:
            SUCCESS_FLAG = False
        logging.exception(f"API request to fetch dependencies of pack '{pack_id}' has failed.\n"
                          f"Response code '{ex.status}'\nResponse: '{ex.body}'\nResponse Headers: '{ex.headers}'")

    except Exception as ex:
        with lock:
            SUCCESS_FLAG = False
        logging.exception(f"API call to fetch dependencies of '{pack_id}' has failed.\nError: {ex}.")

    return None


def find_malformed_pack_id(body: str) -> list:
=======
def get_pack_dependencies(client: demisto_client, pack_data: dict, lock: Lock):
    """ Get the pack's required dependencies.

    Args:
        client (demisto_client): The configured client to use.
        pack_data (dict): Contains the pack ID and version.
        lock (Lock): A lock object.
    Returns:
        (list) The pack's dependencies.
    """
    global SUCCESS_FLAG
    pack_id = pack_data['id']
    logging.debug(f'Getting dependencies for pack {pack_id}')
    try:
        response_data, status_code, _ = demisto_client.generic_request_func(
            client,
            path='/contentpacks/marketplace/search/dependencies',
            method='POST',
            body=[pack_data],
            accept='application/json',
            _request_timeout=None,
            response_type='object'
        )
        if 200 <= status_code < 300:
            dependencies_data: list = []
            dependants_ids = [pack_id]
            response_data = response_data.get('dependencies', [])
            create_dependencies_data_structure(response_data, dependants_ids, dependencies_data, dependants_ids)
            if dependencies_data:
                dependencies_str = ', '.join([dep['id'] for dep in dependencies_data])
                logging.debug(f'Found the following dependencies for pack {pack_id}: {dependencies_str}')
            return dependencies_data
        if status_code == 400:
            logging.error(f'Unable to find dependencies for {pack_id}.')
            return []
        msg = response_data.get('message', '')
        raise Exception(f'status code {status_code}\n{msg}\n')
    except ApiException as api_ex:
        with lock:
            SUCCESS_FLAG = False
        logging.exception(f"The request to get pack {pack_id} dependencies has failed, Got {api_ex.status} from server, "
                          f"message:{api_ex.body}, headers:{api_ex.headers}")
    except Exception as ex:
        with lock:
            SUCCESS_FLAG = False
        logging.exception(f"The request to get pack {pack_id} dependencies has failed. {ex}.")


def search_pack(client: demisto_client,
                pack_display_name: str,
                pack_id: str,
                lock: Lock) -> dict:
    """ Make a pack search request.

    Args:
        client (demisto_client): The configured client to use.
        pack_display_name (string): The pack display name.
        pack_id (string): The pack ID.
        lock (Lock): A lock object.
    Returns:
        (dict): Returns the pack data if found, or empty dict otherwise.
    """

    try:
        response_data, status_code, _ = demisto_client.generic_request_func(client,
                                                                            path=f'/contentpacks/marketplace/{pack_id}',
                                                                            method='GET',
                                                                            accept='application/json',
                                                                            _request_timeout=None,
                                                                            response_type='object')
        if 200 <= status_code < 300:
            if response_data and response_data.get('currentVersion'):
                logging.debug(f'Found pack "{pack_display_name}" by its ID "{pack_id}" in bucket!')
                return {
                    'id': response_data.get('id'),
                    'version': response_data.get('currentVersion'),
                }
            else:
                raise Exception(f'Did not find pack "{pack_display_name}" by its ID "{pack_id}" in bucket.')
        else:
            err_msg = f'Search request for pack "{pack_display_name}" with ID "{pack_id}", failed with status code ' \
                      f'{status_code}\n{response_data.get("message", "")}'
            raise Exception(err_msg)

    except ApiException as ex:
        logging.exception(f'API Exception trying to search pack "{pack_display_name}" with ID "{pack_id}".'
                          f' Exception: {ex.status}, {ex.body}')
    except Exception as ex:
        logging.exception(f'Search request for pack "{pack_display_name}" with ID "{pack_id}", failed. '
                          f'Exception: {str(ex)}')

    lock.acquire()
    global SUCCESS_FLAG
    SUCCESS_FLAG = False
    lock.release()
    return {}


def find_malformed_pack_id(body: str) -> List:
>>>>>>> 5896217e5bc2e4aeea327a288d416e647bda2af2
    """
    Find the pack ID from the installation error message in the case the error is that the pack is not found or
    in case that the error is that the pack's version is invalid.
    Args:
        body (str): The response message of the failed installation pack.

    Returns: list of malformed ids (list)

    """
    malformed_ids = []
    if body:
        with contextlib.suppress(json.JSONDecodeError):
            response_info = json.loads(body)
            if error_info := response_info.get('error'):
                errors_info = [error_info]
            else:
                # the errors are returned as a list of error
                errors_info = response_info.get('errors', [])
            malformed_pack_pattern = re.compile(r'invalid version [0-9.]+ for pack with ID ([\w_-]+)')
            for error in errors_info:
                if 'pack id: ' in error:
                    malformed_ids.extend(error.split('pack id: ')[1].replace(']', '').replace('[', '').replace(
                        ' ', '').split(','))
                else:
                    malformed_pack_id = malformed_pack_pattern.findall(str(error))
                    if malformed_pack_id and error:
                        malformed_ids.extend(malformed_pack_id)
    return malformed_ids


def handle_malformed_pack_ids(malformed_pack_ids, packs_to_install):
    """
    Handles the case where the malformed id failed the installation, but it was not a part of the initial installation.
    This is in order to prevent an infinite loop for this such edge case.
    Args:
        malformed_pack_ids: the ids found from the error msg
        packs_to_install: list of packs that was already installed that caused the failure.

    Returns:
        raises an error.
    """
    for malformed_pack_id in malformed_pack_ids:
        if malformed_pack_id not in {pack['id'] for pack in packs_to_install}:
            raise Exception(f'The pack {malformed_pack_id} has failed to install even '
                            f'though it was not in the installation list')


<<<<<<< HEAD
def install_packs_from_artifacts(client: demisto_client, host: str, test_pack_path: str, pack_ids_to_install: list):
=======
def install_packs_from_artifacts(client: demisto_client, host: str, test_pack_path: str, pack_ids_to_install: List):
>>>>>>> 5896217e5bc2e4aeea327a288d416e647bda2af2
    """
    Installs all the packs located in the artifacts folder of the BitHub actions build. Please note:
    The server always returns a 200 status even if the pack was not installed.

    :param client: Demisto-py client to connect to the server.
    :param host: FQDN of the server.
    :param test_pack_path: Path to the test pack directory.
    :param pack_ids_to_install: List of pack IDs to install.
    :return: None. Call to server waits until a successful response.
    """
    logging.info(f"Test pack path is: {test_pack_path}")
    logging.info(f"Pack IDs to install are: {pack_ids_to_install}")

    local_packs = glob.glob(f"{test_pack_path}/*.zip")

    for local_pack in local_packs:
        if any(pack_id in local_pack for pack_id in pack_ids_to_install):
            logging.info(f'Installing the following pack: {local_pack}')
            upload_zipped_packs(client=client, host=host, pack_path=local_pack)


def install_packs_private(client: demisto_client,
                          host: str,
<<<<<<< HEAD
                          pack_ids_to_install: list,
=======
                          pack_ids_to_install: List,
>>>>>>> 5896217e5bc2e4aeea327a288d416e647bda2af2
                          test_pack_path: str):
    """ Make a packs installation request.

    Args:
        client (demisto_client): The configured client to use.
        host (str): The server URL.
        pack_ids_to_install (list): List of Pack IDs to install.
        test_pack_path (str): Path where test packs are located.
    """
    install_packs_from_artifacts(client,
                                 host,
                                 pack_ids_to_install=pack_ids_to_install,
                                 test_pack_path=test_pack_path)


def get_error_ids(body: str) -> set[str]:
    with contextlib.suppress(json.JSONDecodeError):
        response_info = json.loads(body)
        return {error["id"] for error in response_info.get("errors", [])}
    return set()


def install_packs(client: demisto_client,
                  host: str,
                  packs_to_install: list,
                  request_timeout: int = 3600,
                  attempts_count: int = 5,
                  sleep_interval: int = 60,
                  ):
    """ Make a packs installation request.
       If a pack fails to install due to malformed pack, this function catches the corrupted pack and call another
       request to install packs again, this time without the corrupted pack.
       If a pack fails to install due to timeout when sending a request to GCP,
       request to install all packs again once more.

    Args:
        client (demisto_client): The configured client to use.
        host (str): The server URL.
        packs_to_install (list): A list of the packs to install.
        request_timeout (int): Timeout setting, in seconds, for the installation request.
        attempts_count (int): The number of attempts to install the packs.
        sleep_interval (int): The sleep interval, in seconds, between install attempts.
    """
    global SUCCESS_FLAG
    if not packs_to_install:
        logging.info("There are no packs to install on servers. Consolidating installation as success")
        return SUCCESS_FLAG
    try:
        for attempt in range(attempts_count - 1, -1, -1):
            try:
                logging.info(f"Installing packs {', '.join([p.get('id') for p in packs_to_install])} on server {host}. "
                             f"Attempt: {attempts_count - attempt}/{attempts_count}")
                response, status_code, headers = demisto_client.generic_request_func(client,
                                                                                     path='/contentpacks/marketplace/install',
                                                                                     method='POST',
                                                                                     body={'packs': packs_to_install,
                                                                                           'ignoreWarnings': True},
                                                                                     accept='application/json',
                                                                                     _request_timeout=request_timeout,
                                                                                     response_type='object')

                if 200 <= status_code < 300 and status_code != 204:
                    packs_data = [{'ID': pack.get('id'), 'CurrentVersion': pack.get('currentVersion')} for pack in response]
                    logging.success(f'Packs were successfully installed on server {host}')
                    logging.debug(f'The packs that were successfully installed on server {host}:\n{packs_data}')
                    break

                if not attempt:
                    raise Exception(f"Got bad status code: {status_code}, headers: {headers}")

                logging.warning(f"Got bad status code: {status_code} from the server, headers:{headers}")

            except ApiException as ex:
                if malformed_ids := find_malformed_pack_id(ex.body):
                    handle_malformed_pack_ids(malformed_ids, packs_to_install)
                    if not attempt:
                        raise Exception(f"malformed packs: {malformed_ids}") from ex

                    # We've more attempts, retrying without tho malformed packs.
                    SUCCESS_FLAG = False
                    logging.error(f"Unable to install malformed packs: {malformed_ids}, retrying without them.")
                    packs_to_install = [pack for pack in packs_to_install if pack['id'] not in malformed_ids]

                if (error_ids := get_error_ids(ex.body)) and WLM_TASK_FAILED_ERROR_CODE in error_ids:
                    # If we got this error code, it means that the modeling rules are not valid, exiting install flow.
                    raise Exception(f"Got [{WLM_TASK_FAILED_ERROR_CODE}] error code - Modeling rules and Dataset validations "
                                    f"failed. Please look at GCP logs to understand why it failed.") from ex

                if not attempt:  # exhausted all attempts, understand what happened and exit.
                    if 'timeout awaiting response' in ex.body:
                        if '/packs/' in ex.body:
                            pack_id = get_pack_id_from_error_with_gcp_path(ex.body)
                            raise Exception(f"timeout awaiting response headers while trying to install pack {pack_id}") from ex

                        raise Exception("timeout awaiting response headers while trying to install, "
                                        "couldn't determine pack id.") from ex

                    if 'Item not found' in ex.body:
                        raise Exception(f'Item not found error, headers:{ex.headers}.') from ex

                    # Unknown exception reason, re-raise.
                    raise Exception(f"Got {ex.status} from server, message:{ex.body}, headers:{ex.headers}") from ex
            except (HTTPError, HTTPWarning) as http_ex:
                if not attempt:
                    raise Exception("Failed to perform http request to the server") from http_ex

            # There are more attempts available, sleep and retry.
<<<<<<< HEAD
            logging.debug(f"Failed to install packs: {packs_to_install}, sleeping for {sleep_interval} seconds.")
            time.sleep(sleep_interval)
=======
            logging.debug(f"failed to install packs: {packs_to_install}, sleeping for {sleep_interval} seconds.")
            sleep(sleep_interval)
>>>>>>> 5896217e5bc2e4aeea327a288d416e647bda2af2
    except Exception as e:
        logging.exception(f'The request to install packs: {packs_to_install} has failed. Additional info: {str(e)}')
        SUCCESS_FLAG = False

    finally:
        return SUCCESS_FLAG


def search_pack_and_its_dependencies(client: demisto_client,
                                     pack_id: str,
                                     packs_to_install: list,
                                     installation_request_body: list,
                                     lock: Lock,
<<<<<<< HEAD
                                     collected_dependencies: list,
                                     is_post_update: bool,
                                     multithreading: bool = True,
                                     batch_packs_install_request_body: list | None = None,
                                     ):
    """
    Searches for the pack of the specified file path, as well as its dependencies,
    and updates the list of packs to be installed accordingly.
    Deprecated packs don't have their tests collected, and are not installed in the build process.
=======
                                     packs_in_the_list_to_install: list,
                                     one_pack_and_its_dependencies_in_batch: bool = False,
                                     batch_packs_install_request_body: list = None,
                                     ):
    """ Searches for the pack of the specified file path, as well as its dependencies,
        and updates the list of packs to be installed accordingly.
>>>>>>> 5896217e5bc2e4aeea327a288d416e647bda2af2

    Args:
        client (demisto_client): The configured client to use.
        pack_id (str): The id of the pack to be installed.
        packs_to_install (list) A list of the packs to be installed in this iteration.
        installation_request_body (list): A list of packs to be installed, in the request format.
        lock (Lock): A lock object.
<<<<<<< HEAD
        collected_dependencies (list): list of packs that are already in the list to install
        is_post_update (bool): Whether the installation is done in post-update or not (pre-update otherwise).
        multithreading (bool): Whether to install packs in parallel or not.
            If false - install all packs in one batch.
        batch_packs_install_request_body (list | None, None): A list of pack batches (lists) to use in installation requests.
            Each list contain one pack and its dependencies.
    """
    # Note:
    # On pre-update, we use current prod data, so packs to install should not be deprecated, and should exist on the Marketplace.
    # If they are not for some reason - the API call will fail with a 400 status "item not found" error.

    # On post-update, we want to check for deprecation status locally before making the API call,
    # because if the pack has been deprecated, the test upload flow won't upload the pack to the bucket,
    # and the Marketplace API call for the pack will fail.
    if is_post_update:
        if is_pack_deprecated(pack_id=pack_id, check_locally=True):
            logging.warning(f"Pack '{pack_id}' is deprecated (hidden) and will not be installed.")
            return

    api_data = get_pack_dependencies(client, pack_id, lock)

    if not api_data:
        return  # If an error response was returned, error information has already been logged on 'get_pack_dependencies'.

    pack_api_data = api_data['packs'][0]

    current_packs_to_install = [pack_api_data]
    dependencies_data: list[dict] = []

    create_dependencies_data_structure(response_data=api_data.get('dependencies', []),
                                       dependants_ids=[pack_id],
                                       dependencies_data=dependencies_data,
                                       checked_packs=[pack_id])

    if dependencies_data:
        dependencies_ids = [dependency['id'] for dependency in dependencies_data]
        logging.debug(f"Found dependencies for '{pack_id}': {dependencies_ids}")

        for dependency in dependencies_data:
            dependency_id = dependency['id']
            # If running on pre-update, we check for deprecation using API data.
            # if running on post-update, we check for deprecation locally on the branch.
            is_deprecated = is_pack_deprecated(pack_id=dependency_id, check_locally=is_post_update, pack_api_data=dependency)

            if is_deprecated:
                logging.critical(f"Pack '{pack_id}' depends on pack '{dependency_id}' which is a deprecated pack.")
                global SUCCESS_FLAG
                SUCCESS_FLAG = False

            else:
                current_packs_to_install.append(dependency)

    lock.acquire()

    if not multithreading:
        if batch_packs_install_request_body is None:
            batch_packs_install_request_body = []
        if pack_and_its_dependencies := {
            p['id']: p
            for p in current_packs_to_install
            if p['id'] not in collected_dependencies
        }:
            collected_dependencies += pack_and_its_dependencies
            pack_and_its_dependencies_as_list = [
                get_pack_installation_request_data(pack_id=pack['id'], pack_version=pack['extras']['pack']['currentVersion'])
                for pack in list(pack_and_its_dependencies.values())
            ]
            packs_to_install.extend([pack['id'] for pack in pack_and_its_dependencies_as_list])
            batch_packs_install_request_body.append(pack_and_its_dependencies_as_list)

    else:  # multithreading
        for pack in current_packs_to_install:
            if pack['id'] not in packs_to_install:
                packs_to_install.append(pack['id'])
                installation_request_body.append(
                    get_pack_installation_request_data(pack_id=pack['id'],
                                                       pack_version=pack['extras']['pack']['currentVersion']))

    lock.release()


def get_latest_version_from_bucket(pack_id: str, production_bucket: Bucket) -> str:
    """
    Retrieves the latest version of pack in the bucket
=======
        packs_in_the_list_to_install (list): list of packs that are already in the list to install
        one_pack_and_its_dependencies_in_batch(bool): Whether to install packs in small batches.
            If false - install all packs in one batch.
        batch_packs_install_request_body (list): A list of lists packs to be installed, in the request format.
            Each list contain one pack and its dependencies.

    """
    pack_data = {}
    if pack_id not in packs_to_install:
        pack_display_name = get_pack_display_name(pack_id)
        if pack_display_name:
            pack_data = search_pack(client, pack_display_name, pack_id, lock)
        if pack_data is None:
            pack_data = {
                'id': pack_id,
                'version': '1.0.0'
            }

    if pack_data:
        dependencies = get_pack_dependencies(client, pack_data, lock)

        current_packs_to_install = [pack_data]
        if dependencies:
            # Check that the dependencies don't include a deprecated pack:
            for dependency in dependencies:
                pack_path = os.path.join(PACKS_FOLDER, dependency.get('id'))
                if is_pack_deprecated(pack_path):
                    logging.critical(f'Pack {pack_id} depends on pack {dependency.get("id")} which is a deprecated '
                                     f'pack.')
                    global SUCCESS_FLAG
                    SUCCESS_FLAG = False
                else:
                    current_packs_to_install.append(dependency)

        lock.acquire()
        if one_pack_and_its_dependencies_in_batch:
            pack_and_its_dependencies = \
                {p['id']: p for p in current_packs_to_install if p['id'] not in packs_in_the_list_to_install}
            if pack_and_its_dependencies:
                packs_in_the_list_to_install += pack_and_its_dependencies
                batch_packs_install_request_body.append(list(pack_and_its_dependencies.values()))  # type:ignore[union-attr]
        else:
            for pack in current_packs_to_install:
                if pack['id'] not in packs_to_install:
                    packs_to_install.append(pack['id'])
                    installation_request_body.append(pack)
        lock.release()


def get_latest_version_from_bucket(pack_id: str, production_bucket: Bucket) -> str:
    """ Retrieves the latest version of pack in the bucket
>>>>>>> 5896217e5bc2e4aeea327a288d416e647bda2af2

    Args:
        pack_id (str): The pack id to retrieve the latest version
        production_bucket (Bucket): The GCS production bucket

<<<<<<< HEAD
    Returns:
        The latest version of the pack as it is in the production bucket
=======
    Returns: The latest version of the pack as it is in the production bucket

>>>>>>> 5896217e5bc2e4aeea327a288d416e647bda2af2
    """
    pack_bucket_path = os.path.join(GCPConfig.PRODUCTION_STORAGE_BASE_PATH, pack_id)
    logging.debug(f'Trying to get latest version for pack {pack_id} from bucket path {pack_bucket_path}')
    # Adding the '/' in the end of the prefix to search for the exact pack id
    pack_versions_paths = [f.name for f in production_bucket.list_blobs(prefix=f'{pack_bucket_path}/') if
                           f.name.endswith('.zip')]

    pack_versions = []
    for path in pack_versions_paths:
        versions = PACK_PATH_VERSION_REGEX.findall(path)
        if not versions:
            continue
        pack_versions.append(Version(versions[0]))

    logging.debug(f'Found the following zips for {pack_id} pack: {pack_versions}')
    if pack_versions:
        return str(max(pack_versions))
    logging.error(f'Could not find any versions for pack {pack_id} in bucket path {pack_bucket_path}')
    return ''


def get_pack_installation_request_data(pack_id: str, pack_version: str):
    """
    Returns the installation request data of a given pack and its version. The request must have the ID and Version.

    :param pack_id: ID of the pack to add.
    :param pack_version: Version of the pack to add.
    :return: The request data part of the pack
    """
    return {
        'id': pack_id,
        'version': pack_version
    }


def install_all_content_packs_for_nightly(client: demisto_client, host: str, service_account: str):
    """ Iterates over the packs currently located in the Packs directory. Wrapper for install_packs.
    Retrieving the latest version of each pack from the production bucket.

    :param client: Demisto-py client to connect to the server.
    :param host: FQDN of the server.
    :param service_account: The full path to the service account json.
    :return: None. Prints the response from the server in the build.
    """
    all_packs = []

    # Initiate the GCS client and get the production bucket
    storage_client = init_storage_client(service_account)
    production_bucket = storage_client.bucket(GCPConfig.PRODUCTION_BUCKET)
    logging.debug(f"Installing all content packs for nightly flow in server {host}")

    # Add deprecated packs to IGNORED_FILES list:
    for pack_id in os.listdir(PACKS_FULL_PATH):
        if is_pack_hidden(pack_id):
            logging.debug(f'Skipping installation of hidden pack "{pack_id}"')
            IGNORED_FILES.append(pack_id)

    for pack_id in os.listdir(PACKS_FULL_PATH):
        if pack_id not in IGNORED_FILES:
            pack_version = get_latest_version_from_bucket(pack_id, production_bucket)
            if pack_version:
                all_packs.append(get_pack_installation_request_data(pack_id, pack_version))
    install_packs(client, host, all_packs)


def install_all_content_packs_from_build_bucket(client: demisto_client, host: str, server_version: str,
                                                bucket_packs_root_path: str, service_account: str,
                                                extract_destination_path: str):
    """ Iterates over the packs currently located in the Build bucket. Wrapper for install_packs.
    Retrieving the metadata of the latest version of each pack from the index.zip of the build bucket.

    :param client: Demisto-py client to connect to the server.
    :param host: FQDN of the server.
    :param server_version: The version of the server the packs are installed on.
    :param bucket_packs_root_path: The prefix to the root of packs in the bucket
    :param service_account: Google Service Account
    :param extract_destination_path: the full path of extract folder for the index.
    :return: None. Prints the response from the server in the build.
    """
    all_packs = []
    logging.debug(f"Installing all content packs in server {host} from packs path {bucket_packs_root_path}")

    storage_client = init_storage_client(service_account)
    build_bucket = storage_client.bucket(GCPConfig.CI_BUILD_BUCKET)
    index_folder_path, _, _ = download_and_extract_index(build_bucket, extract_destination_path, bucket_packs_root_path)

    for pack_id in os.listdir(index_folder_path):
        if Path(os.path.join(index_folder_path, pack_id)).is_dir():
            metadata_path = os.path.join(index_folder_path, pack_id, Pack.METADATA)
            pack_metadata = load_json(metadata_path)
            if 'partnerId' in pack_metadata:  # not installing private packs
                continue
            pack_version = pack_metadata.get(Metadata.CURRENT_VERSION, Metadata.SERVER_DEFAULT_MIN_VERSION)
            server_min_version = pack_metadata.get(Metadata.SERVER_MIN_VERSION, Metadata.SERVER_DEFAULT_MIN_VERSION)
            hidden = pack_metadata.get(Metadata.HIDDEN, False)
            # Check if the server version is greater than the minimum server version required for this pack or if the
            # pack is hidden (deprecated):
<<<<<<< HEAD
            if ('Master' in server_version or Version(server_version) >= Version(server_min_version)) and not hidden:
=======
            if ('Master' in server_version or Version(server_version) >= Version(server_min_version)) and \
                    not hidden:
>>>>>>> 5896217e5bc2e4aeea327a288d416e647bda2af2
                logging.debug(f"Appending pack id {pack_id}")
                all_packs.append(get_pack_installation_request_data(pack_id, pack_version))
            else:
                reason = 'Is hidden' if hidden else f'min server version is {server_min_version}'
                logging.debug(f'Pack: {pack_id} with version: {pack_version} will not be installed on {host}. '
                              f'Pack {reason}.')
    return install_packs(client, host, all_packs)


def upload_zipped_packs(client: demisto_client,
                        host: str,
                        pack_path: str):
<<<<<<< HEAD
    """
    Install packs from zip file.

    Args:
        client (demisto_client): The configured client to use.
        host (str): The server URL.
        pack_path (str): path to pack zip.
    """
=======
    """ Install packs from zip file.

        Args:
            client (demisto_client): The configured client to use.
            host (str): The server URL.
            pack_path (str): path to pack zip.
        """
>>>>>>> 5896217e5bc2e4aeea327a288d416e647bda2af2
    header_params = {
        'Content-Type': 'multipart/form-data'
    }
    auth_settings = ['api_key', 'csrf_token', 'x-xdr-auth-id']
    file_path = str(Path(pack_path).resolve())
    files = {'file': file_path}

    logging.info(f'Making "POST" request to server {host} - to install all packs from file {pack_path}')

    # make the pack installation request
    try:
        response_data, status_code, _ = client.api_client.call_api(resource_path='/contentpacks/installed/upload',
                                                                   method='POST',
                                                                   auth_settings=auth_settings,
                                                                   header_params=header_params, files=files,
                                                                   response_type='object')

        if 200 <= status_code < 300:
            logging.info(f'All packs from file {pack_path} were successfully installed on server {host}')
        else:
            message = response_data.get('message', '')
            raise Exception(f'Failed to install packs - with status code {status_code}\n{message}')
    except Exception:
        logging.exception('The request to install packs has failed.')
        sys.exit(1)


def search_and_install_packs_and_their_dependencies_private(test_pack_path: str,
                                                            pack_ids: list,
                                                            client: demisto_client):
    """ Searches for the packs from the specified list, searches their dependencies, and then installs them.
    Args:
        test_pack_path (str): Path of where the test packs are located.
        pack_ids (list): A list of the pack ids to search and install.
        client (demisto_client): The client to connect to.

    Returns (list, bool):
        A list of the installed packs' ids, or an empty list if is_nightly == True.
        A flag that indicates if the operation succeeded or not.
    """
    host = client.api_client.configuration.host

    logging.info(f'Starting to search and install packs in server: {host}')

    install_packs_private(client, host, pack_ids, test_pack_path)

    return SUCCESS_FLAG


def search_and_install_packs_and_their_dependencies(pack_ids: list,
                                                    client: demisto_client, hostname: str | None = None,
<<<<<<< HEAD
                                                    multithreading: bool = True,
                                                    is_post_update: bool = False):
    """
    Searches for the packs from the specified list, searches their dependencies, and then
    installs them.

=======
                                                    install_packs_one_by_one=False):
    """ Searches for the packs from the specified list, searches their dependencies, and then
    installs them.
>>>>>>> 5896217e5bc2e4aeea327a288d416e647bda2af2
    Args:
        pack_ids (list): A list of the pack ids to search and install.
        client (demisto_client): The client to connect to.
        hostname (str): Hostname of instance. Using for logs.
<<<<<<< HEAD
        multithreading (bool): Whether to use multithreading to install packs in parallel.
            If multithreading is used, installation requests will be sent in batches of each pack and its dependencies.
        is_post_update (bool): Whether the installation is in post update mode. Defaults to False.
=======
        install_packs_one_by_one(bool): Whether to install packs in small batches.
            If false - install all packs in one batch.

>>>>>>> 5896217e5bc2e4aeea327a288d416e647bda2af2
    Returns (list, bool):
        A list of the installed packs' ids, or an empty list if is_nightly == True.
        A flag that indicates if the operation succeeded or not.
    """
    host = hostname or client.api_client.configuration.host

    logging.info(f'Starting to search and install packs in server: {host}')

<<<<<<< HEAD
    packs_to_install: list = []  # Packs we want to install, to avoid duplications
    installation_request_body: list = []  # Packs to install, in the request format
    batch_packs_install_request_body: list = []  # List of lists of packs to install if not using multithreading .
    # Each list contain one pack and its dependencies.
    collected_dependencies: list = []  # List of packs that are already in the list to install.

    lock = Lock()

    kwargs = {
        'client': client,
        'packs_to_install': packs_to_install,
        'installation_request_body': installation_request_body,
        'lock': lock,
        'collected_dependencies': collected_dependencies,
        'is_post_update': is_post_update,
        'multithreading': multithreading,
        'batch_packs_install_request_body': batch_packs_install_request_body,
    }

    if is_post_update:
        logging.info("Detected post-update run mode. "
                     "Pack deprecation status will be determined using local pack metadata.")

    else:
        logging.info("Detected pre-update run mode. "
                     "Pack deprecation status will be determined using Marketplace API.")

    if not multithreading:
        for pack_id in pack_ids:
            search_pack_and_its_dependencies(pack_id=pack_id, **kwargs)

    else:
        with ThreadPoolExecutor(max_workers=130) as pool:
            for pack_id in pack_ids:
                pool.submit(search_pack_and_its_dependencies, pack_id=pack_id, **kwargs)
=======
    packs_to_install: list = []  # we save all the packs we want to install, to avoid duplications
    installation_request_body: list = []  # the packs to install, in the request format
    batch_packs_install_request_body: list = []    # list of lists of packs to install if install packs one by one.
    # Each list contain one pack and its dependencies.
    packs_in_the_list_to_install: list = []    # list of packs that are already in the list to install.

    lock = Lock()

    if install_packs_one_by_one:
        for pack_id in pack_ids:
            if is_pack_hidden(pack_id):
                logging.debug(f'pack {pack_id} is hidden, skipping installation and not searching for dependencies')
                continue
            search_pack_and_its_dependencies(
                client, pack_id, packs_to_install, installation_request_body, lock,
                packs_in_the_list_to_install, install_packs_one_by_one,
                batch_packs_install_request_body)
    else:
        with ThreadPoolExecutor(max_workers=130) as pool:
            for pack_id in pack_ids:
                if is_pack_hidden(pack_id):
                    logging.debug(f'pack {pack_id} is hidden, skipping installation and not searching for dependencies')
                    continue
                pool.submit(search_pack_and_its_dependencies,
                            client, pack_id, packs_to_install, installation_request_body, lock,
                            packs_in_the_list_to_install, install_packs_one_by_one,
                            batch_packs_install_request_body)
>>>>>>> 5896217e5bc2e4aeea327a288d416e647bda2af2
        batch_packs_install_request_body = [installation_request_body]

    for packs_to_install_body in batch_packs_install_request_body:
        install_packs(client, host, packs_to_install_body)

    return packs_to_install, SUCCESS_FLAG
