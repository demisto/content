from __future__ import print_function

import os
import ast
import json
import glob
import re
import sys
from concurrent.futures import ThreadPoolExecutor

import demisto_client
from threading import Lock
from demisto_client.demisto_api.rest import ApiException

from google.cloud.storage import Bucket
from packaging.version import Version
from typing import List

from Tests.Marketplace.marketplace_services import init_storage_client, Pack, load_json
from Tests.Marketplace.upload_packs import download_and_extract_index
from Tests.Marketplace.marketplace_constants import GCPConfig, PACKS_FULL_PATH, IGNORED_FILES, PACKS_FOLDER, Metadata
from Tests.scripts.utils.content_packs_util import is_pack_deprecated
from Tests.scripts.utils import logging_wrapper as logging

PACK_METADATA_FILE = 'pack_metadata.json'
PACK_PATH_VERSION_REGEX = re.compile(fr'^{GCPConfig.PRODUCTION_STORAGE_BASE_PATH}/[A-Za-z0-9-_.]+/(\d+\.\d+\.\d+)/[A-Za-z0-9-_.]'
                                     r'+\.zip$')
SUCCESS_FLAG = True


def get_pack_id_from_error_with_gcp_path(error: str) -> str:
    """
        Gets the id of the pack from the pack's path in GCP that is mentioned in the error msg.
    Args:
        error: path of pack in GCP.

    Returns:
        The id of given pack.
    """
    return error.split('/packs/')[1].split('.zip')[0].split('/')[0]


def get_pack_display_name(pack_id: str) -> str:
    """
    Gets the display name of the pack from the pack ID.

    :param pack_id: ID of the pack.
    :return: Name found in the pack metadata, otherwise an empty string.
    """
    metadata_path = os.path.join(PACKS_FULL_PATH, pack_id, PACK_METADATA_FILE)
    if pack_id and os.path.isfile(metadata_path):
        with open(metadata_path, 'r') as json_file:
            pack_metadata = json.load(json_file)
        return pack_metadata.get('name')
    return ''


def is_pack_hidden(pack_id: str) -> bool:
    """
    Check if the given pack is deprecated.

    :param pack_id: ID of the pack.
    :return: True if the pack is deprecated, i.e. has 'hidden: true' field, False otherwise.
    """
    metadata_path = os.path.join(PACKS_FULL_PATH, pack_id, PACK_METADATA_FILE)
    if pack_id and os.path.isfile(metadata_path):
        with open(metadata_path, 'r') as json_file:
            pack_metadata = json.load(json_file)
            return pack_metadata.get('hidden', False)
    else:
        logging.warning(f'Could not open metadata file of pack {pack_id}')
    return False


def create_dependencies_data_structure(response_data: dict, dependants_ids: list, dependencies_data: list,
                                       checked_packs: list):
    """ Recursively creates the packs' dependencies data structure for the installation requests
    (only required and uninstalled).

    Args:
        response_data (dict): The GET /search/dependencies response data.
        dependants_ids (list): A list of the dependant packs IDs.
        dependencies_data (list): The dependencies data structure to be created.
        checked_packs (list): Required dependants that were already found.
    """

    next_call_dependants_ids = []

    for dependency in response_data:
        dependants = dependency.get('dependants', {})
        for dependant in dependants.keys():
            is_required = dependants[dependant].get('level', '') == 'required'
            if dependant in dependants_ids and is_required and dependency.get('id') not in checked_packs:
                dependencies_data.append({
                    'id': dependency.get('id'),
                    'version': dependency.get('extras', {}).get('pack', {}).get('currentVersion')
                })
                next_call_dependants_ids.append(dependency.get('id'))
                checked_packs.append(dependency.get('id'))

    if next_call_dependants_ids:
        create_dependencies_data_structure(response_data, next_call_dependants_ids, dependencies_data, checked_packs)


def get_pack_dependencies(client: demisto_client, pack_data: dict, lock: Lock):
    """ Get the pack's required dependencies.

    Args:
        client (demisto_client): The configured client to use.
        pack_data (dict): Contains the pack ID and version.
        lock (Lock): A lock object.
    Returns:
        (list) The pack's dependencies.
    """
    pack_id = pack_data['id']
    logging.debug(f'Getting dependencies for pack {pack_id}')
    try:
        response_data, status_code, _ = demisto_client.generic_request_func(
            client,
            path='/contentpacks/marketplace/search/dependencies',
            method='POST',
            body=[pack_data],
            accept='application/json',
            _request_timeout=None
        )

        if 200 <= status_code < 300:
            dependencies_data: list = []
            dependants_ids = [pack_id]
            reseponse_data = ast.literal_eval(response_data).get('dependencies', [])
            create_dependencies_data_structure(reseponse_data, dependants_ids, dependencies_data, dependants_ids)
            dependencies_str = ', '.join([dep['id'] for dep in dependencies_data])
            if dependencies_data:
                logging.debug(f'Found the following dependencies for pack {pack_id}: {dependencies_str}')
            return dependencies_data
        if status_code == 400:
            logging.error(f'Unable to find dependencies for {pack_id}.')
            return []
        else:
            result_object = ast.literal_eval(response_data)
            msg = result_object.get('message', '')
            raise Exception(f'Failed to get pack {pack_id} dependencies - with status code {status_code}\n{msg}\n')
    except Exception:
        logging.exception(f'The request to get pack {pack_id} dependencies has failed.')

        lock.acquire()
        global SUCCESS_FLAG
        SUCCESS_FLAG = False
        lock.release()


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
        # make the search request
        response_data, status_code, _ = demisto_client.generic_request_func(client,
                                                                            path=f'/contentpacks/marketplace/{pack_id}',
                                                                            method='GET',
                                                                            accept='application/json',
                                                                            _request_timeout=None)

        if 200 <= status_code < 300:
            result_object = ast.literal_eval(response_data)

            if result_object and result_object.get('currentVersion'):
                logging.debug(f'Found pack "{pack_display_name}" by its ID "{pack_id}" in bucket!')

                pack_data = {
                    'id': result_object.get('id'),
                    'version': result_object.get('currentVersion')
                }
                return pack_data

            else:
                raise Exception(f'Did not find pack "{pack_display_name}" by its ID "{pack_id}" in bucket.')
        else:
            result_object = ast.literal_eval(response_data)
            msg = result_object.get('message', '')
            err_msg = f'Search request for pack "{pack_display_name}" with ID "{pack_id}", failed with status code ' \
                      f'{status_code}\n{msg}'
            raise Exception(err_msg)
    except Exception:
        logging.exception(f'Search request for pack "{pack_display_name}" with ID "{pack_id}", failed.')

        lock.acquire()
        global SUCCESS_FLAG
        SUCCESS_FLAG = False
        lock.release()
        return {}


def find_malformed_pack_id(body: str) -> List:
    """
    Find the pack ID from the installation error message in the case the error is that the pack is not found or
    in case that the error is that the pack's version is invalid.
    Args:
        body (str): The response message of the failed installation pack.

    Returns: list of malformed ids (list)

    """
    malformed_ids = []
    if body:
        response_info = json.loads(body)
        if error_info := response_info.get('error'):
            errors_info = [error_info]
        else:
            # the error is returned as a list of error
            errors_info = response_info.get('errors', [])
        for error in errors_info:
            if 'pack id: ' in error:
                malformed_ids.extend(error.split('pack id: ')[1].replace(']', '').replace('[', '').replace(
                    ' ', '').split(','))
            else:
                malformed_pack_pattern = re.compile(r'invalid version [0-9.]+ for pack with ID ([\w_-]+)')
                malformed_pack_id = malformed_pack_pattern.findall(str(error))
                if malformed_pack_id and error:
                    malformed_ids.extend(malformed_pack_id)
    return malformed_ids


def handle_malformed_pack_ids(malformed_pack_ids, packs_to_install):
    """
    Handles the case where the malformed id failed the installation but it was not a part of the initial installaion.
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


def install_packs_from_artifacts(client: demisto_client, host: str, test_pack_path: str, pack_ids_to_install: List):
    """
    Installs all the packs located in the artifacts folder of the BitHub actions build. Please note:
    The server always returns a 200 status even if the pack was not installed.

    :param client: Demisto-py client to connect to the server.
    :param host: FQDN of the server.
    :param test_pack_path: Path the the test pack directory.
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
                          pack_ids_to_install: List,
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


def install_packs(client: demisto_client,
                  host: str,
                  packs_to_install: list,
                  request_timeout: int = 999999,
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
        request_timeout (int): Timeout settings for the installation request.
    """

    class GCPTimeOutException(ApiException):
        def __init__(self, error):
            if '/packs/' in error:
                self.pack_id = get_pack_id_from_error_with_gcp_path(error)
            super().__init__()

    class MalformedPackException(ApiException):
        def __init__(self, pack_ids):
            self.malformed_ids = pack_ids
            super().__init__()

    class GeneralItemNotFoundError(ApiException):
        def __init__(self, error_msg):
            self.error_msg = error_msg
            super().__init__()

    def call_install_packs_request(packs):
        try:
            logging.debug(f'Installing the following packs on server {host}:\n{[pack["id"] for pack in packs]}')
            response_data, status_code, _ = demisto_client.generic_request_func(client,
                                                                                path='/contentpacks/marketplace/install',
                                                                                method='POST',
                                                                                body={'packs': packs,
                                                                                      'ignoreWarnings': True},
                                                                                accept='application/json',
                                                                                _request_timeout=request_timeout)

            if status_code in range(200, 300) and status_code != 204:
                packs_data = [{'ID': pack.get('id'), 'CurrentVersion': pack.get('currentVersion')} for pack in
                              ast.literal_eval(response_data)]
                logging.success(f'Packs were successfully installed on server {host}')
                logging.debug(f'The packs that were successfully installed on server {host}:\n{packs_data}')

        except ApiException as ex:
            if 'timeout awaiting response' in ex.body:
                raise GCPTimeOutException(ex.body)
            if malformed_ids := find_malformed_pack_id(ex.body):
                raise MalformedPackException(malformed_ids)
            if 'Item not found' in ex.body:
                raise GeneralItemNotFoundError(ex.body)
            raise ex

    try:
        logging.info(f'Installing packs on server {host}')
        try:
            call_install_packs_request(packs_to_install)

        except MalformedPackException as e:
            # if this is malformed pack error, remove malformed packs and retry until success
            handle_malformed_pack_ids(e.malformed_ids, packs_to_install)
            logging.warning(f'The request to install packs on server {host} has failed, retrying without packs '
                            f'{e.malformed_ids}')
            return install_packs(client, host, [pack for pack in packs_to_install if pack['id'] not in e.malformed_ids],
                                 request_timeout)

        except GCPTimeOutException as e:
            # if this is a gcp timeout, try only once more
            logging.warning(f'The request to install packs on server {host} has failed due to timeout awaiting response'
                            f' headers while trying to install pack {e.pack_id}, trying again for one more time')
            call_install_packs_request(packs_to_install)

        except GeneralItemNotFoundError as e:
            logging.warning(f'The request to install all packs on server {host} has failed due to an item not found '
                            f'error, with the message: {e.error_msg}.\n trying again for one more time')
            call_install_packs_request(packs_to_install)

    except Exception as e:
        logging.exception(f'The request to install packs has failed. Additional info: {str(e)}')
        global SUCCESS_FLAG
        SUCCESS_FLAG = False

    finally:
        return SUCCESS_FLAG


def search_pack_and_its_dependencies(client: demisto_client,
                                     pack_id: str,
                                     packs_to_install: list,
                                     installation_request_body: list,
                                     lock: Lock):
    """ Searches for the pack of the specified file path, as well as its dependencies,
        and updates the list of packs to be installed accordingly.

    Args:
        client (demisto_client): The configured client to use.
        pack_id (str): The id of the pack to be installed.
        packs_to_install (list) A list of the packs to be installed in this iteration.
        installation_request_body (list): A list of packs to be installed, in the request format.
        lock (Lock): A lock object.
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
                    current_packs_to_install.extend(dependencies)

        lock.acquire()
        for pack in current_packs_to_install:
            if pack['id'] not in packs_to_install:
                packs_to_install.append(pack['id'])
                installation_request_body.append(pack)
        lock.release()


def get_latest_version_from_bucket(pack_id: str, production_bucket: Bucket) -> str:
    """ Retrieves the latest version of pack in the bucket

    Args:
        pack_id (str): The pack id to retrieve the latest version
        production_bucket (Bucket): The GCS production bucket

    Returns: The latest version of the pack as it is in the production bucket

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
        pack_latest_version = str(max(pack_versions))
        return pack_latest_version
    else:
        logging.error(f'Could not find any versions for pack {pack_id} in bucket path {pack_bucket_path}')
        return ''


def get_pack_installation_request_data(pack_id: str, pack_version: str):
    """
    Returns the installation request data of a given pack and its version. The request must have the ID and Version.

    :param pack_id: Id of the pack to add.
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
        if os.path.isdir(os.path.join(index_folder_path, pack_id)):
            metadata_path = os.path.join(index_folder_path, pack_id, Pack.METADATA)
            pack_metadata = load_json(metadata_path)
            if 'partnerId' in pack_metadata:  # not installing private packs
                continue
            pack_version = pack_metadata.get(Metadata.CURRENT_VERSION, Metadata.SERVER_DEFAULT_MIN_VERSION)
            server_min_version = pack_metadata.get(Metadata.SERVER_MIN_VERSION, Metadata.SERVER_DEFAULT_MIN_VERSION)
            hidden = pack_metadata.get(Metadata.HIDDEN, False)
            # Check if the server version is greater than the minimum server version required for this pack or if the
            # pack is hidden (deprecated):
            if ('Master' in server_version or Version(server_version) >= Version(server_min_version)) and \
                    not hidden:
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
    """ Install packs from zip file.

        Args:
            client (demisto_client): The configured client to use.
            host (str): The server URL.
            pack_path (str): path to pack zip.
        """
    header_params = {
        'Content-Type': 'multipart/form-data'
    }
    auth_settings = ['api_key', 'csrf_token', 'x-xdr-auth-id']
    file_path = os.path.abspath(pack_path)
    files = {'file': file_path}

    logging.info(f'Making "POST" request to server {host} - to install all packs from file {pack_path}')

    # make the pack installation request
    try:
        response_data, status_code, _ = client.api_client.call_api(resource_path='/contentpacks/installed/upload',
                                                                   method='POST',
                                                                   auth_settings=auth_settings,
                                                                   header_params=header_params, files=files)

        if 200 <= status_code < 300:
            logging.info(f'All packs from file {pack_path} were successfully installed on server {host}')
        else:
            result_object = ast.literal_eval(response_data)
            message = result_object.get('message', '')
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
                                                    client: demisto_client, hostname: str = ''):
    """ Searches for the packs from the specified list, searches their dependencies, and then
    installs them.
    Args:
        pack_ids (list): A list of the pack ids to search and install.
        client (demisto_client): The client to connect to.
        hostname (str): Hostname of instance. Using for logs.

    Returns (list, bool):
        A list of the installed packs' ids, or an empty list if is_nightly == True.
        A flag that indicates if the operation succeeded or not.
    """
    host = hostname if hostname else client.api_client.configuration.host

    logging.info(f'Starting to search and install packs in server: {host}')

    packs_to_install: list = []  # we save all the packs we want to install, to avoid duplications
    installation_request_body: list = []  # the packs to install, in the request format

    lock = Lock()

    with ThreadPoolExecutor(max_workers=130) as pool:
        for pack_id in pack_ids:
            pool.submit(search_pack_and_its_dependencies,
                        client, pack_id, packs_to_install, installation_request_body, lock)

    install_packs(client, host, installation_request_body)

    return packs_to_install, SUCCESS_FLAG
