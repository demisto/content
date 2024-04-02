import base64
import contextlib
from datetime import datetime
import glob
import itertools
import json
import os
import re
from functools import lru_cache
from pathlib import Path
from tempfile import mkdtemp
from typing import Any
import networkx as nx
from networkx import DiGraph

from demisto_client.demisto_api.api.default_api import DefaultApi as DemistoClient
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
from Tests.Marketplace.upload_packs import download_and_extract_index, extract_packs_artifacts
from Tests.scripts.utils import logging_wrapper as logging

from demisto_sdk.commands.test_content.ParallelLoggingManager import ARTIFACTS_PATH

from Tests.test_content import get_server_numeric_version

PACK_PATH_VERSION_REGEX = re.compile(fr'^{GCPConfig.PRODUCTION_STORAGE_BASE_PATH}/[A-Za-z0-9-_.]+/(\d+\.\d+\.\d+)/[A-Za-z0-9-_.]'  # noqa: E501
                                     r'+\.zip$')
WLM_TASK_FAILED_ERROR_CODE = 101704

GITLAB_SESSION = Session()
CONTENT_PROJECT_ID = os.getenv('CI_PROJECT_ID', '1061')
ARTIFACTS_FOLDER_SERVER_TYPE = os.getenv('ARTIFACTS_FOLDER_SERVER_TYPE')
PACKS_DIR = "Packs"
PACK_METADATA_FILE = Pack.PACK_METADATA
GITLAB_PACK_METADATA_URL = f'{{gitlab_url}}/api/v4/projects/{CONTENT_PROJECT_ID}/repository/files/{PACKS_DIR}%2F{{pack_id}}%2F{PACK_METADATA_FILE}'  # noqa: E501

BATCH_SIZE = 10
PAGE_SIZE_DEFAULT = 50
CYCLE_SEPARATOR = "<->"


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

    Args:
        pack_id (str): ID of the pack to check.
        production_bucket (bool): Whether we want to check deprecation status on production bucket.
            Otherwise, deprecation status will be determined by checking the local 'pack_metadata.json' file.
        commit_hash (str, optional): Commit hash branch to use if 'production_bucket' is False.
            If 'pack_api_data' is not provided, will be used for fetching 'pack_metadata.json' file from GitLab.
        pack_api_data (dict | None, optional): Marketplace API data to use if 'production_bucket' is False.

    Returns:
        bool: True if the pack is deprecated, False otherwise
    """
    if production_bucket:
        if pack_api_data:
            try:
                return pack_api_data["deprecated"]

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


def install_packs_from_artifacts(client: DemistoClient,
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


def install_packs_private(client: DemistoClient,
                          host: str,
                          pack_ids_to_install: list,
                          test_pack_path: str) -> bool:
    """ Make a packs installation request.

    Args:
        client (DemistoClient): The configured client to use.
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


def install_packs(client: DemistoClient,
                  host: str,
                  packs_to_install: list,
                  attempts_count: int = 5,
                  sleep_interval: int = 60,
                  request_timeout: int = 900,
                  ) -> tuple[bool, list]:
    """ Make a packs installation request.
       If a pack fails to install due to malformed pack, this function catches the corrupted pack and call another
       request to install packs again, this time without the corrupted pack.
       If a pack fails to install due to timeout when sending a request to GCP,
       request to install all packs again once more.

    Args:
        client (DemistoClient): The configured client to use.
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
    client: DemistoClient, host: str, service_account: str, pack_ids_to_install: list[str]
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


def install_all_content_packs_from_build_bucket(client: DemistoClient, host: str, server_version: str,
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


def upload_zipped_packs(client: DemistoClient,
                        host: str,
                        pack_path: str) -> bool:
    """
    Install packs from zip file.

    Args:
        client (DemistoClient): The configured client to use.
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
                                                            client: DemistoClient) -> bool:
    """ Searches for the packs from the specified list, searches their dependencies, and then installs them.
    Args:
        test_pack_path (str): Path of where the test packs are located.
        pack_ids (list): A list of the pack ids to search and install.
        client (DemistoClient): The client to connect to.

    Returns (list, bool):
        A list of the installed packs' ids, or an empty list if is_nightly == True.
        A flag that indicates if the operation succeeded or not.
    """
    host = client.api_client.configuration.host

    logging.info(f'Starting to search and install packs in server: {host}')

    return install_packs_private(client, host, pack_ids, test_pack_path)


def get_json_file(path):
    with open(path) as json_file:
        return json.loads(json_file.read())


def get_packs_with_higher_min_version(packs_names: set[str],
                                      server_numeric_version: str,
                                      extract_content_packs_path: str) -> set[str]:
    """
    Return a set of packs that have higher min version than the server version.

    Args:
        packs_names (Set[str]): A set of packs to install.
        server_numeric_version (str): The server version.
        extract_content_packs_path (str): Path to a temporary folder with extracted content packs metadata.

    Returns:
        (Set[str]): The set of the packs names that supposed to be not installed because
                    their min version is greater than the server version.
    """
    packs_with_higher_version = set()
    for pack_name in packs_names:
        pack_metadata = get_json_file(f"{extract_content_packs_path}/{pack_name}/metadata.json")
        server_min_version = pack_metadata.get(Metadata.SERVER_MIN_VERSION,
                                               pack_metadata.get('server_min_version', Metadata.SERVER_DEFAULT_MIN_VERSION))

        if 'Master' not in server_numeric_version and Version(server_numeric_version) < Version(server_min_version):
            packs_with_higher_version.add(pack_name)
            logging.info(f"Skipping to install pack '{pack_name}' since the min version {server_min_version}, that is "
                         f"higher than server version {server_numeric_version}")

    return packs_with_higher_version


def create_graph(
    all_packs_dependencies: dict,
) -> DiGraph:
    """Creates a NetworkX directed graph representing the dependencies between packs.

    Iterates over the provided dictionary containing all packs dependencies and adds
    directed edges to the graph from each dependent pack to the pack it depends on.
    Edges are only added for mandatory dependencies.

    Args:
        all_packs_dependencies (dict): Dictionary containing pack IDs as keys and their
                                       dependencies as the values.

    Returns:
        DiGraph: NetworkX directed graph with edges representing dependencies
                 between packs.
    """
    graph_dependencies = nx.DiGraph()
    for pack_id in all_packs_dependencies:
        graph_dependencies.add_node(pack_id)
        pack_dependencies = all_packs_dependencies[pack_id]["dependencies"]
        for dependence in pack_dependencies:
            if pack_dependencies[dependence]["mandatory"]:
                graph_dependencies.add_edge(dependence, pack_id)
    return graph_dependencies


def merge_cycles(graph: DiGraph) -> DiGraph:
    """Merges nodes that are part of cycles in the directed graph into a single node.

    Args:
        graph (DiGraph): The directed graph to find and merge cycles in.

    Returns:
        tuple[dict[str, str], DiGraph]: A tuple with:
            - A dict mapping the original node names to the merged node name
            - The modified graph with cycles merged
    Note:
        The function returns the graph for visibility, even though the original graph changes.
    """
    logging.debug(
        f"Found the following cycles in the graph: {list(nx.simple_cycles(graph))}"
    )
    while cycle := next(nx.simple_cycles(graph), None):
        merged_node_name = CYCLE_SEPARATOR.join(cycle)
        for node_1, node_2 in list(graph.edges()):
            if node_1 in cycle:
                graph.add_edge(merged_node_name, node_2)
            elif node_2 in cycle:
                graph.add_edge(node_1, merged_node_name)
        for node in cycle:
            graph.remove_node(node)

    return graph


def split_cycles(list_of_nodes: list[str]) -> list[list[str]]:
    """Splits nodes that are merged cycles into individual nodes.

    Args:
        list_of_nodes (list[str]): A list of node names,
        where some of which are merged nodes with CYCLE_SEPARATOR.

    Returns:
        list[list[str]]: List of lists, that each list contains a single node,
        or several nodes that were merged.
    """
    return [node.split(CYCLE_SEPARATOR) for node in list_of_nodes]


def get_all_content_packs_dependencies(client: DemistoClient) -> dict[str, dict]:
    """Gets all content packs dependencies from the Marketplace API.

    Iterates over all pages of pack results from the Marketplace /search API.
    Extracts the "dependencies" field from each pack and collects them into a
    mapping of pack ID to dependencies dict.

    Args:
        client: Demisto API client instance

    Returns:
        dict[str, dict]: Mapping of pack ID to dependencies dict with fields:
                         "currentVersion", "dependencies", "deprecated"
    """
    all_packs_dependencies = {}
    for i in itertools.count():
        response = get_one_page_of_packs_dependencies(client, i)
        packs = response["packs"]
        logging.debug(f"Fetched dependencies of page {i} with {len(packs)} packs")
        for pack in packs:
            all_packs_dependencies[pack["id"]] = {
                "currentVersion": pack["currentVersion"],
                "dependencies": pack["dependencies"],
                "deprecated": pack["deprecated"],
            }
        if len(packs) < PAGE_SIZE_DEFAULT:
            all_packs_len = len(all_packs_dependencies)
            total = response["total"]
            if total > all_packs_len:
                logging.critical(
                    f"Marketplace API returned less than the total packs. Collected: {all_packs_len}, Total: {total}"
                )
            break
    return all_packs_dependencies


def get_one_page_of_packs_dependencies(
    client: DemistoClient,
    page: int,
    attempts_count: int = 5,
    sleep_interval: int = 60,
    request_timeout: int = 900,
):
    """
    Fetches one page of pack dependencies from the Marketplace API.

    Args:
        client: The Demisto API client object
        page: The page number to retrieve
        attempts_count: Number of retries upon failure
        sleep_interval: Time to sleep between retries
        request_timeout: Request timeout period

    Returns:
        The JSON response containing the packs dependencies for the given page
    """
    api_endpoint = "/contentpacks/marketplace/search"
    body = {
        "page": page,
        "size": PAGE_SIZE_DEFAULT,
        "sort": [
            {"field": "searchRank", "asc": False},
            {"field": "updated", "acs": False},
        ]
    }

    def success_handler(response):
        logging.success(f"Succeeded to fetch dependencies of page {page}")
        return True, response

    failure_massage = f"Failed to fetch dependencies of page: {page}"
    retries_message = f"Retrying to fetch dependencies of page: {page}"
    prior_message = (
        f"Fetching dependencies information of page {page} using Marketplace API"
    )

    _, data = generic_request_with_retries(
        client=client,
        retries_message=retries_message,
        exception_message=failure_massage,
        prior_message=prior_message,
        path=api_endpoint,
        method="POST",
        response_type="object",
        body=body,
        request_timeout=request_timeout,
        attempts_count=attempts_count,
        sleep_interval=sleep_interval,
        success_handler=success_handler,
    )
    return data


def search_for_deprecated_dependencies(
    pack_id: str,
    dependencies_for_pack_id: set,
    production_bucket: bool,
    all_packs_dependencies_data: dict,
):
    """
    Checks if the given pack ID has any deprecated dependencies.

    Args:
        pack_id (str): The ID of the pack to check.
        dependencies_for_pack_id (set): The set of dependency pack IDs for the pack.
        production_bucket (bool): Whether production bucket is used.
        all_packs_dependencies_data (dict): Mapping of pack ID to pack metadata.

    Returns:
        bool: False if no deprecated dependencies were found, True otherwise.
    """
    for dependency_pack in dependencies_for_pack_id:
        is_deprecated = is_pack_deprecated(
            pack_id=dependency_pack,
            production_bucket=production_bucket,
            pack_api_data=all_packs_dependencies_data[dependency_pack],
        )
        if is_deprecated:
            logging.critical(
                f"Pack '{pack_id}' depends on pack '{dependency_pack}' which is a deprecated pack.\n"
                "The pack and its dependencies will not be installed"
            )
            return False
    return True


def filter_packs_by_min_server_version(packs_id: set[str], server_version: str, extract_content_packs_path: str):
    """Filters a set of pack IDs to only those compatible with the given server version

    Args:
        packs_id (set[str]): Set of pack IDs to filter
        server_version (str): Server version to check pack compatibility against
        extract_content_packs_path (str): Path to a temporary folder with extracted content packs metadata

    Returns:
        set[str]: Set of pack IDs that are compatible with the provided server version
    """
    packs_with_higher_server_version = get_packs_with_higher_min_version(
        packs_names=packs_id,
        server_numeric_version=server_version,
        extract_content_packs_path=extract_content_packs_path
    )
    return packs_id - packs_with_higher_server_version


def create_packs_artifacts():
    """Creates artifacts for content packs.
    Extracts the content packs zip file into a temporary directory.

    Returns:
        str: Path to the extracted content packs directory.
    """
    extract_content_packs_path = mkdtemp()
    packs_artifacts_path = f'{ARTIFACTS_FOLDER_SERVER_TYPE}/content_packs.zip'
    extract_packs_artifacts(packs_artifacts_path, extract_content_packs_path)
    return extract_content_packs_path


def get_packs_and_dependencies_to_install(
    pack_ids: list,
    graph_dependencies: DiGraph,
    production_bucket: bool,
    all_packs_dependencies_data: dict,
    client: DemistoClient,
) -> tuple[bool, set]:
    """
    Fetches all dependencies for the given list of pack IDs and returns the packs and dependencies that should be installed.

    Args:
        pack_ids (list): List of pack IDs to get dependencies for
        graph_dependencies (DiGraph): Dependency graph
        production_bucket (bool): Whether the production bucket is used
        all_packs_dependencies_data (dict): Data about all packs and dependencies

    Returns:
        no_deprecated_dependencies (bool): Whether any deprecated dependencies were found
        all_packs_and_dependencies_to_install (set): Set containing all packs and dependencies that should be installed
    """
    no_deprecated_dependencies = True
    all_packs_and_dependencies_to_install: set[str] = set()
    server_numeric_version = get_server_numeric_version(client)
    extract_content_packs_path = create_packs_artifacts()

    for pack_id in pack_ids:
        dependencies_for_pack_id = nx.ancestors(graph_dependencies, pack_id)

        if dependencies_for_pack_id:
            logging.debug(
                f"Found dependencies for '{pack_id}': {dependencies_for_pack_id}"
            )
            dependencies_for_pack_id = filter_packs_by_min_server_version(
                dependencies_for_pack_id, server_numeric_version, extract_content_packs_path
            )
            no_deprecated_dependency = search_for_deprecated_dependencies(
                pack_id,
                dependencies_for_pack_id,
                production_bucket,
                all_packs_dependencies_data,
            )
            if no_deprecated_dependency:
                all_packs_and_dependencies_to_install.update(
                    dependencies_for_pack_id | {pack_id}
                )
            else:
                no_deprecated_dependencies = False
        else:
            all_packs_and_dependencies_to_install.add(pack_id)
            logging.debug(f"No dependencies found for '{pack_id}'")

    return no_deprecated_dependencies, all_packs_and_dependencies_to_install


def create_install_request_body(
    packs_to_install: list[list[str]],
    all_packs_dependencies_data: dict[str, dict],
) -> list[list[dict]]:
    """Creates the request body for installing packs.
    An inner list will contain several IDs if they are circularly dependent on each other.

    Args:
        packs_to_install: List of lists of pack IDs to install
        all_packs_dependencies_data: Dict containing dependencies data for all packs

    Returns:
        list: Request body with installation data for the packs
    """
    request_body = []
    for pack_ids in packs_to_install:
        request_body.append(
            [
                get_pack_installation_request_data(
                    pack, all_packs_dependencies_data[pack]["currentVersion"]
                )
                for pack in pack_ids
            ]
        )

    return request_body


def filter_deprecated_packs(
    pack_ids: list[str], production_bucket: bool, commit_hash: str
) -> list[str]:
    """Filters out deprecated packs from the pack_ids list.

    Checks if each pack ID in pack_ids is deprecated by calling is_pack_deprecated.
    If a pack is deprecated, logs a warning and does not include it in the returned list.

    Args:
        pack_ids: List of pack IDs to filter.
        production_bucket: Whether the installation is for production or not.
        commit_hash: The git commit hash to check against.
    Returns:
        List of pack IDs with deprecated packs filtered out.
    """
    filtered_packs_id = []
    for pack_id in pack_ids:
        if is_pack_deprecated(
            pack_id=pack_id,
            production_bucket=production_bucket,
            commit_hash=commit_hash,
        ):
            logging.warning(
                f"Pack '{pack_id}' is deprecated (hidden) and will not be installed."
            )
        else:
            filtered_packs_id.append(pack_id)

    return filtered_packs_id


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


def save_graph_data_file_log(graph: DiGraph, file_name: str) -> None:
    """Saves a graph visualization as a .dot file to the logs directory.

    Args:
        graph (DiGraph): The networkx DiGraph to save.
        file_name (str): The name to use for the saved .dot file.

    Returns:
        None: Returns nothing.

    Note:
        The saved json file can be read back into a graph object using networkx:
        ```
        with open(file_path) as f:
            graph_data = json.loads(f.read())

        graph_dependencies = nx.DiGraph()
        graph_dependencies.add_edges_from(graph_data["edges"])
        graph_dependencies.add_nodes_from(graph_data["nodes"])
        ```
    """
    file_name = f"{datetime.utcnow().strftime('%H:%M:%S')}_{file_name}.json"
    log_file_path = Path(ARTIFACTS_PATH) / 'logs' / file_name

    graph_data = {"nodes": list(graph.nodes()), "edges": list(graph.edges())}
    with open(log_file_path, 'w') as f:
        f.write(json.dumps(graph_data))

    logging.debug(f"Saving graph data to {log_file_path}")


def search_and_install_packs_and_their_dependencies(
    pack_ids: list,
    client: DemistoClient,
    hostname: str | None = None,
    install_packs_in_batches: bool = False,
    production_bucket: bool = True,
):
    """
    Searches for the packs from the specified list, searches their dependencies, and then
    installs them.

    Args:
        pack_ids (list): A list of the pack ids to search and install.
        client (DemistoClient): The client to connect to.
        hostname (str): Hostname of instance. Using for logs.
        multithreading (bool): Whether to use multithreading to install packs in parallel.
            If multithreading is used, installation requests will be sent in batches of each pack and its dependencies.
        production_bucket (bool): Whether the installation is in post update mode. Default is True.
    Returns (list, bool):
        A list of the installed packs IDs.
        A flag that indicates if the operation succeeded or not.

    Flow of the function:
        1. Filter out deprecated packs from the given pack IDs.
        2. Get all packs dependency data using the Demisto client.
        3. Create a dependency graph (for all the content) using the all_packs_dependencies_data.
        4. Get list of all packs and their dependencies to install from the graph.
        5. Create subgraph of packs to install and their dependencies.
        6. Merge packs with circular dependencies into single, to make DAG graph.
        7. Get a sorted list of packs to install based on the DAG graph, using topological sort.
        8. Create the request body to install packs by calling create_install_request_body.
        9. Create batches of packs to install if install_packs_in_batches is True.
        10. Install packs using the Demisto client.
    """
    host = hostname or client.api_client.configuration.host

    logging.info(f"Starting search for packs to install on: {host}")

    master_commit_hash = get_env_var("LAST_UPLOAD_COMMIT")

    success = True

    pack_ids = filter_deprecated_packs(pack_ids, production_bucket, master_commit_hash)
    if not pack_ids:
        logging.info(f"No packs to install on: {host}")
        return [], success

    all_packs_dependencies_data = get_all_content_packs_dependencies(client)

    graph_dependencies = create_graph(all_packs_dependencies_data)
    save_graph_data_file_log(graph_dependencies, "graph_dependencies_all_content")

    no_deprecated_dependencies, all_packs_and_dependencies_to_install = get_packs_and_dependencies_to_install(
        pack_ids,
        graph_dependencies,
        production_bucket,
        all_packs_dependencies_data,
        client,
    )
    success &= no_deprecated_dependencies

    # Create subgraph only with the packs that will be installed
    graph_dependencies_for_installed_packs = nx.subgraph(
        graph_dependencies, all_packs_and_dependencies_to_install
    ).copy()
    save_graph_data_file_log(graph_dependencies_for_installed_packs, "graph_dependencies_for_installed_packs")

    merged_graph_dependencies = merge_cycles(graph_dependencies_for_installed_packs)
    save_graph_data_file_log(merged_graph_dependencies, "merged_graph_dependencies")

    logging.debug(
        f"Get the following topological sort: {list(nx.topological_generations(merged_graph_dependencies))}"
    )
    sorted_packs_to_install = split_cycles(
        list(nx.topological_sort(merged_graph_dependencies))
    )

    packs_to_install_request_body = create_install_request_body(
        sorted_packs_to_install,
        all_packs_dependencies_data,
    )
    logging.debug(f"{packs_to_install_request_body=}")

    if install_packs_in_batches:
        batch_packs_install_request_body = create_batches(packs_to_install_request_body)
    else:
        batch_packs_install_request_body = [
            list(itertools.chain.from_iterable(packs_to_install_request_body))
        ]

    for packs_to_install_body in batch_packs_install_request_body:
        pack_success, _ = install_packs(client, host, packs_to_install_body)
        success &= pack_success

    return sorted_packs_to_install, success
