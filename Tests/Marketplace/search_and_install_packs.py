
import base64
import contextlib
import glob
import json
import os
import re
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from pathlib import Path
from threading import Lock
from typing import Any

import demisto_client
from demisto_sdk.commands.common import tools
from demisto_sdk.commands.common.logger import logger
from demisto_sdk.commands.content_graph.common import PACK_METADATA_FILENAME
from google.cloud.storage import Bucket  # noqa
from packaging.version import Version
from requests import Session

from Tests.Marketplace.common import ALREADY_IN_PROGRESS
from Tests.Marketplace.common import wait_until_not_updating, generic_request_with_retries
from Tests.Marketplace.marketplace_constants import (PACKS_FOLDER,
                                                     GCPConfig, Metadata)
from Tests.Marketplace.marketplace_services import (Pack, init_storage_client,
                                                    load_json)
from Tests.Marketplace.upload_packs import download_and_extract_index
from Tests.scripts.utils import logging_wrapper as logging

PACK_PATH_VERSION_REGEX = re.compile(fr'^{GCPConfig.PRODUCTION_STORAGE_BASE_PATH}/[A-Za-z0-9-_.]+/(\d+\.\d+\.\d+)/[A-Za-z0-9-_.]'  # noqa: E501
                                     r'+\.zip$')
WLM_TASK_FAILED_ERROR_CODE = 101704

GITLAB_SESSION = Session()
CONTENT_PROJECT_ID = os.getenv('CI_PROJECT_ID', '2596')  # the default is the id of the content repo in code.pan.run
PACKS_DIR = "Packs"
PACK_METADATA_FILE = Pack.PACK_METADATA
GITLAB_PACK_METADATA_URL = f'{{gitlab_url}}/api/v4/projects/{CONTENT_PROJECT_ID}/repository/files/{PACKS_DIR}%2F{{pack_id}}%2F{PACK_METADATA_FILE}'  # noqa: E501

BATCH_SIZE = 10


@lru_cache
def get_env_var(var_name: str) -> str:
    """
    Get an environment variable.
    This method adds a cache layer to the 'os.getenv' method, and raises an error if the variable is not set.

    Args:
        var_name (str): Name of the environment variable to get.

    Returns:
        str: Value of the environment variable.
    """
    var_value = os.getenv(var_name)
    if not var_value:
        raise ValueError(f"Environment variable '{var_name}' is not set.")

    return var_value


@lru_cache(maxsize=128)
def fetch_pack_metadata_from_gitlab(pack_id: str, commit_hash: str) -> dict:
    """
    Fetch pack metadata from master (a commit hash of the master branch when the build was triggered) using GitLab's API.

    Args:
        pack_id (str): ID of the pack to fetch metadata for (name of Pack's folder).
        commit_hash (str): A commit hash to fetch the metadata file from.

    Returns:
        dict: A dictionary containing pack's metadata.
    """
    api_url = GITLAB_PACK_METADATA_URL.format(gitlab_url=get_env_var('CI_SERVER_URL'), pack_id=pack_id)
    logging.debug(f"Fetching 'pack_metadata.json' file from GitLab for pack '{pack_id}'...")
    response = GITLAB_SESSION.get(api_url,
                                  headers={'PRIVATE-TOKEN': get_env_var('GITLAB_API_READ_TOKEN')},
                                  params={'ref': commit_hash})

    if response.status_code != 200:
        logging.error(f"Failed to fetch pack metadata from GitLab for pack '{pack_id}'.\n"
                      f"Response code: {response.status_code}\nResponse body: {response.text}")
        response.raise_for_status()

    file_data_b64 = response.json()['content']
    file_data = base64.b64decode(file_data_b64).decode('utf-8')

    return json.loads(file_data)


def is_pack_deprecated(pack_id: str, production_bucket: bool = True,
                       commit_hash: str | None = None, pack_api_data: dict | None = None) -> bool:
    """
    Check whether a pack is deprecated or not.
    If an error is encountered, and status can't be checked properly,
    the deprecation status will be set to a default value of False.

    Note:
        If 'production_bucket' is True, one of 'master_commit_hash' or 'pack_api_data' must be provided
        in order to determine whether the pack is deprecated or not.
        'commit_hash' is used to fetch pack's metadata from a specific commit hash (ex: production bucket's last commit)
        'pack_api_data' is the API data of a specific pack item (and not the complete response with a list of packs).

    Args:
        pack_id (str): ID of the pack to check.
        production_bucket (bool): Whether we want to check deprecation status on production bucket.
            Otherwise, deprecation status will be determined by checking the local 'pack_metadata.json' file.
        commit_hash (str, optional): Commit hash branch to use if 'production_bucket' is False.
            If 'pack_api_data' is not provided, will be used for fetching 'pack_metadata.json' file from GitLab.
        pack_api_data (dict | None, optional): Marketplace API data to use if 'production_bucket' is False.
            Needs to be the API data of a specific pack item (and not the complete response with a list of packs).

    Returns:
        bool: True if the pack is deprecated, False otherwise
    """
    if production_bucket:
        if pack_api_data:
            try:
                return pack_api_data['extras']['pack'].get('deprecated', False)

            except Exception as ex:
                logging.error(f"Failed to parse API response data for '{pack_id}'.\n"
                              f"API Data: {pack_api_data}\nError: {ex}")

        elif commit_hash:
            try:
                return fetch_pack_metadata_from_gitlab(pack_id=pack_id, commit_hash=commit_hash).get('hidden', False)

            except Exception as ex:
                logging.error(f"Failed to fetch pack metadata from GitLab for pack '{pack_id}'.\nError: {ex}")

        else:
            raise ValueError("Either 'master_commit_hash' or 'pack_api_data' must be provided.")

    else:  # Check locally
        pack_metadata_path = Path(PACKS_FOLDER) / pack_id / PACK_METADATA_FILENAME

        if pack_metadata_path.is_file():
            try:
                return tools.get_pack_metadata(str(pack_metadata_path)).get('hidden', False)

            except Exception as ex:
                logging.error(f"Failed to open file '{pack_metadata_path}'.\nError: {ex}")

        else:
            logging.warning(f"File '{pack_metadata_path}' could not be found, or isn't a file.")

    # If we got here, it means that nothing was returned and an error was encountered
    logging.warning(f"Deprecation status of '{pack_id}' could not be determined, "
                    "and has been set to a default value of 'False'.\n"
                    "Note that this might result in potential errors if it is deprecated.")
    return False


def get_pack_id_from_error_with_gcp_path(error: str) -> str:
    """
    Gets the id of the pack from the pack's path in GCP that is mentioned in the error msg.

    Args:
        error: path of pack in GCP.

    Returns:
        str: The id of given pack.
    """
    return error.split('/packs/')[1].split('.zip')[0].split('/')[0]


def create_dependencies_data_structure(response_data: dict, dependants_ids: list,
                                       dependencies_data: list, checked_packs: list):
    """
    Recursively create packs' dependencies data structure for installation requests (only required and uninstalled).

    Args:
        response_data (dict): Dependencies data from the '/search/dependencies' endpoint response.
        dependants_ids (list): A list of the dependant packs IDs.
        dependencies_data (list): The dependencies data structure to be created.
        checked_packs (list): Required dependants that were already found.
    """
    next_call_dependants_ids = []

    for dependency in response_data:
        dependants = dependency.get('dependants', {})

        for dependant in dependants:
            is_required = dependants[dependant].get('level', '') == 'required'

            if all((dependant in dependants_ids, is_required, dependency['id'] not in checked_packs)):
                dependencies_data.append(dependency)
                next_call_dependants_ids.append(dependency['id'])
                checked_packs.append(dependency['id'])

    if next_call_dependants_ids:
        create_dependencies_data_structure(response_data, next_call_dependants_ids, dependencies_data, checked_packs)


def get_pack_dependencies(client: demisto_client,
                          pack_id: str,
                          attempts_count: int = 5,
                          sleep_interval: int = 60,
                          request_timeout: int = 900,
                          ) -> dict | None:
    """
    Get pack's required dependencies.

    Args:
        client (demisto_client): The configured client to use.
        pack_id (str): ID of the pack to get dependencies for.
        attempts_count (int): The number of attempts to install the packs.
        sleep_interval (int): The sleep interval, in seconds, between request retry attempts.
        request_timeout (int): The timeout per call to the server.

    Returns:
        dict | None: API response data for the /search/dependencies endpoint. None if the request failed.
    """
    api_endpoint = "/contentpacks/marketplace/search/dependencies"
    body = [{"id": pack_id}]  # Not specifying a "version" key will return the latest version of the pack.

    def success_handler(response):
        logging.success(f"Succeeded to fetch dependencies for pack '{pack_id}'")
        return True, response

    failure_massage = f"Failed to fetch dependencies for pack: {pack_id}"
    retries_message = f"Retrying to fetch dependencies for pack: {pack_id}"
    prior_message = f"Fetching dependencies information for pack: {pack_id} using Marketplace API"

    _, data = generic_request_with_retries(client=client,
                                           retries_message=retries_message,
                                           exception_message=failure_massage,
                                           prior_message=prior_message,
                                           path=api_endpoint,
                                           method='POST',
                                           response_type='object',
                                           body=body,
                                           request_timeout=request_timeout,
                                           attempts_count=attempts_count,
                                           sleep_interval=sleep_interval,
                                           success_handler=success_handler)
    return data


def find_malformed_pack_id(body: str) -> list:
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


def install_packs_from_artifacts(client: demisto_client,
                                 host: str,
                                 test_pack_path: str,
                                 pack_ids_to_install: list) -> bool:
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
    return True


def install_packs_private(client: demisto_client,
                          host: str,
                          pack_ids_to_install: list,
                          test_pack_path: str) -> bool:
    """ Make a packs installation request.

    Args:
        client (demisto_client): The configured client to use.
        host (str): The server URL.
        pack_ids_to_install (list): List of Pack IDs to install.
        test_pack_path (str): Path where test packs are located.
    """
    return install_packs_from_artifacts(client,
                                        host,
                                        pack_ids_to_install=pack_ids_to_install,
                                        test_pack_path=test_pack_path)


def get_error_ids(body: str) -> dict[int, str]:
    with contextlib.suppress(json.JSONDecodeError):
        response_info = json.loads(body)
        return {error["id"]: error.get("detail", "") for error in response_info.get("errors", []) if "id" in error}
    return {}


def install_packs(client: demisto_client,
                  host: str,
                  packs_to_install: list,
                  attempts_count: int = 5,
                  sleep_interval: int = 60,
                  request_timeout: int = 600,
                  ) -> tuple[bool, list]:
    """ Make a packs installation request.
       If a pack fails to install due to malformed pack, this function catches the corrupted pack and call another
       request to install packs again, this time without the corrupted pack.
       If a pack fails to install due to timeout when sending a request to GCP,
       request to install all packs again once more.

    Args:
        client (demisto_client): The configured client to use.
        host (str): The server URL.
        packs_to_install (list): A list of the packs to install.
        attempts_count (int): The number of attempts to install the packs.
        sleep_interval (int): The sleep interval, in seconds, between install attempts.
        request_timeout (int): The timeout per call to the server.
    Returns:
        bool: True if the operation succeeded and False otherwise and a list of packs that were installed.
    """
    if not packs_to_install:
        logging.info("There are no packs to install on servers. Consolidating installation as success")
        return True, []

    success = True
    body = {
        'packs': packs_to_install,
        'ignoreWarnings': True
    }

    def success_handler(response_data_packs):
        packs_data = [
            {
                'ID': response_data_pack.get('id'),
                'CurrentVersion': response_data_pack.get('currentVersion')
            } for response_data_pack in response_data_packs]
        logging.success(f'Packs were successfully installed on server {host}')

        return success, packs_data

    def api_exception_handler(ex, attempt_left) -> Any:
        nonlocal packs_to_install, success, body
        if ALREADY_IN_PROGRESS in ex.body:
            wait_succeeded = wait_until_not_updating(client)
            if not wait_succeeded:
                raise Exception(
                    "Failed to wait for the server to exit installation/updating status"
                ) from ex
        if malformed_ids := find_malformed_pack_id(ex.body):
            handle_malformed_pack_ids(malformed_ids, packs_to_install)
            if not attempt_left:
                raise Exception(f"malformed packs: {malformed_ids}") from ex

            # We've more attempts, retrying without tho malformed packs.
            logging.error(f"Unable to install malformed packs: {malformed_ids}, retrying without them.")
            packs_to_install = [
                pack_to_install for pack_to_install in packs_to_install if pack_to_install['id'] not in malformed_ids
            ]
            body = {
                'packs': packs_to_install,
                'ignoreWarnings': True
            }
            return body

        error_ids = get_error_ids(ex.body)
        if WLM_TASK_FAILED_ERROR_CODE in error_ids:
            if "polling request failed for task ID" in error_ids[WLM_TASK_FAILED_ERROR_CODE].lower():
                logging.error(f"Got {WLM_TASK_FAILED_ERROR_CODE} error code - polling request failed for task ID, "
                              f"retrying.")
            else:
                # If we got this error code, it means that the modeling rules are not valid, exiting install flow.
                raise Exception(f"Got [{WLM_TASK_FAILED_ERROR_CODE}] error code - Modeling rules and Dataset validations "
                                f"failed. Please look at GCP logs to understand why it failed.") from ex

        if not attempt_left:  # exhausted all attempts, understand what happened and exit.
            if 'timeout awaiting response' in ex.body:
                if '/packs/' in ex.body:
                    pack_id = get_pack_id_from_error_with_gcp_path(ex.body)
                    raise Exception(f"timeout awaiting response headers while trying to install pack {pack_id}") from ex

                raise Exception("timeout awaiting response headers while trying to install, "
                                "couldn't determine pack id.") from ex

            if 'Item not found' in ex.body:
                raise Exception(f'Item not found error, headers:{ex.headers}.') from ex
        return body

    def should_try_handler():
        nonlocal packs_to_install
        logging.info(f"Retrying to install packs on server {host}:")
        for pack in packs_to_install:
            logger.info(f"\tID:{pack['id']} Version:{pack['version']}")
        return True

    retries_message = f"Retrying to install packs on server {host}"
    exception_massage = f"Failed to install packs on server {host}"
    prior_message = f"Installing packs on server {host}."
    logging.info(f"Installing packs on server {host}:")
    for pack in packs_to_install:
        logger.info(f"\tID:{pack['id']} Version:{pack['version']}")

    return generic_request_with_retries(client=client,
                                        retries_message=retries_message,
                                        exception_message=exception_massage,
                                        prior_message=prior_message,
                                        path='/contentpacks/marketplace/install',
                                        body=body,
                                        response_type='object',
                                        method='POST',
                                        attempts_count=attempts_count,
                                        sleep_interval=sleep_interval,
                                        success_handler=success_handler,
                                        api_exception_handler=api_exception_handler,
                                        should_try_handler=should_try_handler,
                                        request_timeout=request_timeout,
                                        )


def search_pack_and_its_dependencies(client: demisto_client,
                                     pack_id: str,
                                     packs_to_install: list,
                                     installation_request_body: list,
                                     lock: Lock,
                                     collected_dependencies: list,
                                     production_bucket: bool,
                                     commit_hash: str,
                                     multithreading: bool = True,
                                     list_packs_and_its_dependency_install_request_body: list | None = None,
                                     ) -> bool:
    """
    Update 'packs_to_install' (a pointer to a list that's reused and updated by the function on every iteration)
    with 'pack_id' and its dependencies, if 'pack_id' is not deprecated.
    The way deprecation status is determined depends on the 'production_bucket' flag.

    If 'production_bucket' is True, deprecation status is determined by checking the 'pack_metadata.json' file
    in the commit hash that was used for the last upload. If it's False, the deprecation status is checking the
    'pack_metadata.json' file locally (with changes applied on the branch).

    Args:
        client (demisto_client): The configured client to use.
        pack_id (str): The id of the pack to be installed.
        packs_to_install (list) A list of the packs to be installed in this iteration.
        installation_request_body (list): A list of packs to be installed, in the request format.
        lock (Lock): A lock object.
        collected_dependencies (list): list of packs that are already in the list to install
        production_bucket (bool): Whether pack deprecation status  is determined using production bucket.
        commit_hash (str): Commit hash to use for checking pack's deprecations status if GitLab's API is used.
            If 'pack_api_data' is not provided, will be used for fetching 'pack_metadata.json' file from GitLab.
        multithreading (bool): Whether to install packs in parallel or not.
            If false - install all packs in one batch.
        list_packs_and_its_dependency_install_request_body (list | None, None): A list of pack batches (lists)
            to use in installation requests. Each list contain one pack and its dependencies.
    # Returns: True if we succeeded to get the dependencies, False otherwise.
    """
    if is_pack_deprecated(pack_id=pack_id, production_bucket=production_bucket, commit_hash=commit_hash):
        logging.warning(f"Pack '{pack_id}' is deprecated (hidden) and will not be installed.")
        return True

    api_data = get_pack_dependencies(client=client, pack_id=pack_id)

    if not api_data:
        return False

    dependencies_data: list[dict] = []

    try:
        pack_api_data = api_data['packs'][0]
        current_packs_to_install = [pack_api_data]

        create_dependencies_data_structure(response_data=api_data.get('dependencies', []),
                                           dependants_ids=[pack_id],
                                           dependencies_data=dependencies_data,
                                           checked_packs=[pack_id])

    except Exception as ex:
        logging.error(f"Error: {ex}\n\nStack trace:\n{traceback.format_exc()}")
        return False

    if dependencies_data:
        dependencies_ids = [dependency['id'] for dependency in dependencies_data]
        logging.debug(f"Found dependencies for '{pack_id}': {dependencies_ids}")

        for dependency in dependencies_data:
            dependency_id = dependency['id']
            is_deprecated = is_pack_deprecated(pack_id=dependency_id,
                                               production_bucket=production_bucket, pack_api_data=dependency)

            if is_deprecated:
                logging.critical(f"Pack '{pack_id}' depends on pack '{dependency_id}' which is a deprecated pack.")
                return False
            current_packs_to_install.append(dependency)

    with lock:
        if not multithreading:
            if list_packs_and_its_dependency_install_request_body is None:
                list_packs_and_its_dependency_install_request_body = []
            if pack_and_its_dependencies := {
                p['id']: p
                for p in current_packs_to_install
                if p['id'] not in collected_dependencies
            }:
                collected_dependencies += pack_and_its_dependencies
                pack_and_its_dependencies_as_list = [
                    get_pack_installation_request_data(pack_id=pack['id'],
                                                       pack_version=pack['extras']['pack']['currentVersion'])
                    for pack in list(pack_and_its_dependencies.values())
                ]
                packs_to_install.extend([pack['id'] for pack in pack_and_its_dependencies_as_list])
                list_packs_and_its_dependency_install_request_body.append(pack_and_its_dependencies_as_list)
                logging.info(
                    f"list_packs_and_its_dependency_install_request_body: {list_packs_and_its_dependency_install_request_body} ")
        else:  # multithreading
            for pack in current_packs_to_install:
                if pack['id'] not in packs_to_install:
                    packs_to_install.append(pack['id'])
                    installation_request_body.append(
                        get_pack_installation_request_data(pack_id=pack['id'],
                                                           pack_version=pack['extras']['pack']['currentVersion']))
    return True


def get_latest_version_from_bucket(pack_id: str, production_bucket: Bucket) -> str:
    """
    Retrieves the latest version of pack in the bucket

    Args:
        pack_id (str): The pack id to retrieve the latest version
        production_bucket (Bucket): The GCS production bucket

    Returns:
        The latest version of the pack as it is in the production bucket
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


def install_all_content_packs_for_nightly(
    client: demisto_client, host: str, service_account: str, pack_ids_to_install: list[str]
) -> bool:
    """ Iterates over the packs currently located in the Packs directory. Wrapper for install_packs.
    Retrieving the latest version of each pack from the production bucket.

    :param client: Demisto-py client to connect to the server.
    :param host: FQDN of the server.
    :param service_account: The full path to the service account json.
    :param pack_ids_to_install: List of pack IDs to install specifically to XSOAR marketplace.
    :return: Boolean value indicating whether the installation was successful or not.
    """
    all_packs = []

    # Initiate the GCS client and get the production bucket
    storage_client = init_storage_client(service_account)
    production_bucket = storage_client.bucket(GCPConfig.PRODUCTION_BUCKET)
    logging.debug(f"Installing all content packs for nightly flow in server {host}")

    for pack_id in pack_ids_to_install:
        if pack_version := get_latest_version_from_bucket(pack_id, production_bucket):
            logging.debug(f'Found the {pack_version=} for {pack_id=}')
            all_packs.append(get_pack_installation_request_data(pack_id, pack_version))
    success, _ = install_packs(client, host, all_packs)
    return success


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
            if ('Master' in server_version or Version(server_version) >= Version(server_min_version)) and not hidden:
                logging.debug(f"Appending pack id {pack_id}")
                all_packs.append(get_pack_installation_request_data(pack_id, pack_version))
            else:
                reason = 'Is hidden' if hidden else f'min server version is {server_min_version}'
                logging.debug(f'Pack: {pack_id} with version: {pack_version} will not be installed on {host}. '
                              f'Pack {reason}.')
    return install_packs(client, host, all_packs)


def upload_zipped_packs(client: demisto_client,
                        host: str,
                        pack_path: str) -> bool:
    """
    Install packs from zip file.

    Args:
        client (demisto_client): The configured client to use.
        host (str): The server URL.
        pack_path (str): path to pack zip.
    Returns:
        bool: True if the operation succeeded and False otherwise.
    """
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
    except Exception:  # noqa
        logging.exception('The request to install packs has failed.')
        return False
    return True


def search_and_install_packs_and_their_dependencies_private(test_pack_path: str,
                                                            pack_ids: list,
                                                            client: demisto_client) -> bool:
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

    return install_packs_private(client, host, pack_ids, test_pack_path)


def search_and_install_packs_and_their_dependencies(pack_ids: list,
                                                    client: demisto_client, hostname: str | None = None,
                                                    multithreading: bool = True,
                                                    production_bucket: bool = True):
    """
    Searches for the packs from the specified list, searches their dependencies, and then
    installs them.

    Args:
        pack_ids (list): A list of the pack ids to search and install.
        client (demisto_client): The client to connect to.
        hostname (str): Hostname of instance. Using for logs.
        multithreading (bool): Whether to use multithreading to install packs in parallel.
            If multithreading is used, installation requests will be sent in batches of each pack and its dependencies.
        production_bucket (bool): Whether the installation is in post update mode. Defaults to False.
    Returns (list, bool):
        A list of the installed packs' ids, or an empty list if is_nightly == True.
        A flag that indicates if the operation succeeded or not.
    """
    host = hostname or client.api_client.configuration.host

    logging.info(f'Starting search for packs to install on: {host}')

    packs_to_install: list = []  # Packs we want to install, to avoid duplications
    installation_request_body: list = []  # Packs to install, in the request format
    list_packs_and_its_dependency_install_request_body: list = []  # List of lists of packs to install if not using multithreading
    # Each list contain one pack and its dependencies.
    collected_dependencies: list = []  # List of packs that are already in the list to install.
    master_commit_hash = get_env_var("LAST_UPLOAD_COMMIT")

    lock = Lock()

    kwargs = {
        'client': client,
        'packs_to_install': packs_to_install,
        'installation_request_body': installation_request_body,
        'lock': lock,
        'collected_dependencies': collected_dependencies,
        'production_bucket': production_bucket,
        'multithreading': multithreading,
        'list_packs_and_its_dependency_install_request_body': list_packs_and_its_dependency_install_request_body,
        'commit_hash': master_commit_hash,
    }

    success = True
    if not multithreading:
        pack_ids = sorted(pack_ids, key=lambda x: (x == "DeveloperTools", x == "Base"))
        logging.info(f"pack_ids = {pack_ids}")
        for pack_id in pack_ids:
            success &= search_pack_and_its_dependencies(pack_id=pack_id, **kwargs)

        batch_packs_install_request_body = create_batches(list_packs_and_its_dependency_install_request_body)

    else:
        with ThreadPoolExecutor(max_workers=50) as pool:
            futures = [
                pool.submit(
                    search_pack_and_its_dependencies, pack_id=pack_id, **kwargs
                )
                for pack_id in pack_ids
            ]
            for future in as_completed(futures):
                try:
                    success &= future.result()
                except Exception:  # noqa E722
                    logging.exception(
                        f"An exception occurred while searching for dependencies of pack '{pack_ids[futures.index(future)]}'"
                    )
                    success = False
        batch_packs_install_request_body = [installation_request_body]

    for packs_to_install_body in batch_packs_install_request_body:
        pack_success, _ = install_packs(client, host, packs_to_install_body)
        success &= pack_success

    return packs_to_install, success


def create_batches(list_of_packs_and_its_dependency: list):
    """
    Create a list of packs batches to install

    Args:
        list_of_packs_and_its_dependency (list): A list containing lists
            where each item is another list of a pack and its dependencies.
        A list of pack batches (lists) to use in installation requests in size less than BATCH_SIZE
    """

    batch: list = []
    list_of_batches: list = []
    for packs_to_install_body in list_of_packs_and_its_dependency:
        if len(batch) + len(packs_to_install_body) < BATCH_SIZE:
            batch.extend(packs_to_install_body)
        else:
            if batch:
                list_of_batches.append(batch)
            batch = packs_to_install_body
    list_of_batches.append(batch)

    return list_of_batches
