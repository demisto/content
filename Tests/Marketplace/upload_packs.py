import json
import os
import sys
import argparse
import shutil
import uuid
import prettytable
import glob
import requests
from datetime import datetime
from google.cloud.storage import Bucket
from pathlib import Path

from zipfile import ZipFile
from typing import Any, Tuple, Union, Optional

from requests import Response

from Tests.Marketplace.marketplace_services import init_storage_client, Pack, \
    load_json, get_content_git_client, get_recent_commits_data, store_successful_and_failed_packs_in_ci_artifacts, \
    json_write
from Tests.Marketplace.marketplace_statistics import StatisticsHandler
from Tests.Marketplace.marketplace_constants import PackStatus, Metadata, GCPConfig, BucketUploadFlow, \
    CONTENT_ROOT_PATH, PACKS_FOLDER, PACKS_FULL_PATH, IGNORED_FILES, IGNORED_PATHS, LANDING_PAGE_SECTIONS_PATH
from demisto_sdk.commands.common.tools import run_command, str2bool

from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging
import traceback


def get_packs_names(target_packs: str, previous_commit_hash: str = "HEAD^") -> set:
    """Detects and returns packs names to upload.

    In case that `Modified` is passed in target_packs input, checks the git difference between two commits,
    current and previous and greps only ones with prefix Packs/.
    By default this function will receive `All` as target_packs and will return all packs names from content repo.

    Args:
        target_packs (str): csv packs names or `All` for all available packs in content
                            or `Modified` for only modified packs (currently not in use).
        previous_commit_hash (str): the previous commit to diff with.

    Returns:
        set: unique collection of packs names to upload.

    """
    if target_packs.lower() == "all":
        if os.path.exists(PACKS_FULL_PATH):
            all_packs = {p for p in os.listdir(PACKS_FULL_PATH) if p not in IGNORED_FILES}
            logging.info(f"Number of selected packs to upload is: {len(all_packs)}")
            # return all available packs names
            return all_packs
        else:
            logging.error(f"Folder {PACKS_FOLDER} was not found at the following path: {PACKS_FULL_PATH}")
            sys.exit(1)
    elif target_packs.lower() == "modified":
        cmd = f"git diff --name-only HEAD..{previous_commit_hash} | grep 'Packs/'"
        modified_packs_path = run_command(cmd).splitlines()
        modified_packs = {p.split('/')[1] for p in modified_packs_path if p not in IGNORED_PATHS}
        logging.info(f"Number of modified packs is: {len(modified_packs)}")
        # return only modified packs between two commits
        return modified_packs
    elif target_packs and isinstance(target_packs, str):
        modified_packs = {p.strip() for p in target_packs.split(',') if p not in IGNORED_FILES}
        logging.info(f"Number of selected packs to upload is: {len(modified_packs)}")
        # return only packs from csv list
        return modified_packs
    else:
        logging.critical("Not correct usage of flag -p. Please check help section of upload packs script.")
        sys.exit(1)


def extract_packs_artifacts(packs_artifacts_path: str, extract_destination_path: str):
    """Extracts all packs from content pack artifact zip.

    Args:
        packs_artifacts_path (str): full path to content artifacts zip file.
        extract_destination_path (str): full path to directory where to extract the packs.

    """
    with ZipFile(packs_artifacts_path) as packs_artifacts:
        packs_artifacts.extractall(extract_destination_path)
    logging.info("Finished extracting packs artifacts")


def download_and_extract_index(storage_bucket: Any, extract_destination_path: str, storage_base_path: str) \
        -> Tuple[str, Any, int]:
    """Downloads and extracts index zip from cloud storage.

    Args:
        storage_bucket (google.cloud.storage.bucket.Bucket): google storage bucket where index.zip is stored.
        extract_destination_path (str): the full path of extract folder.
        storage_base_path (str): the source path of the index in the target bucket.
    Returns:
        str: extracted index folder full path.
        Blob: google cloud storage object that represents index.zip blob.
        str: downloaded index generation.

    """
    if storage_bucket.name == GCPConfig.PRODUCTION_PRIVATE_BUCKET:
        index_storage_path = os.path.join(GCPConfig.PRIVATE_BASE_PATH, f"{GCPConfig.INDEX_NAME}.zip")
    else:
        index_storage_path = os.path.join(storage_base_path, f"{GCPConfig.INDEX_NAME}.zip")
    download_index_path = os.path.join(extract_destination_path, f"{GCPConfig.INDEX_NAME}.zip")

    index_blob = storage_bucket.blob(index_storage_path)
    index_folder_path = os.path.join(extract_destination_path, GCPConfig.INDEX_NAME)
    index_generation = 0  # Setting to 0 makes the operation succeed only if there are no live versions of the blob

    if not os.path.exists(extract_destination_path):
        os.mkdir(extract_destination_path)

    if not index_blob.exists():
        os.mkdir(index_folder_path)
        logging.error(f"{storage_bucket.name} index blob does not exists")
        return index_folder_path, index_blob, index_generation

    index_blob.reload()
    index_generation = index_blob.generation

    index_blob.download_to_filename(download_index_path, if_generation_match=index_generation)

    if os.path.exists(download_index_path):
        with ZipFile(download_index_path, 'r') as index_zip:
            index_zip.extractall(extract_destination_path)

        if not os.path.exists(index_folder_path):
            logging.critical(f"Failed creating {GCPConfig.INDEX_NAME} folder with extracted data.")
            sys.exit(1)

        os.remove(download_index_path)
        logging.success(f"Finished downloading and extracting {GCPConfig.INDEX_NAME} file to "
                        f"{extract_destination_path}")

        return index_folder_path, index_blob, index_generation
    else:
        logging.critical(f"Failed to download {GCPConfig.INDEX_NAME}.zip file from cloud storage.")
        sys.exit(1)


def update_index_folder(index_folder_path: str, pack_name: str, pack_path: str, pack_version: str = '',
                        hidden_pack: bool = False) -> bool:
    """
    Copies pack folder into index folder.

    Args:
        index_folder_path (str): full path to index folder.
        pack_name (str): pack folder name to copy.
        pack_path (str): pack folder full path.
        pack_version (str): pack latest version.
        hidden_pack (bool): whether pack is hidden/internal or regular pack.

    Returns:
        bool: whether the operation succeeded.
    """
    task_status = False

    try:
        index_folder_subdirectories = [d for d in os.listdir(index_folder_path) if
                                       os.path.isdir(os.path.join(index_folder_path, d))]
        index_pack_path = os.path.join(index_folder_path, pack_name)
        metadata_files_in_index = glob.glob(f"{index_pack_path}/metadata-*.json")
        new_metadata_path = os.path.join(index_pack_path, f"metadata-{pack_version}.json")

        if pack_version:
            # Update the latest metadata
            if new_metadata_path in metadata_files_in_index:
                metadata_files_in_index.remove(new_metadata_path)

        # Remove old files but keep metadata files
        if pack_name in index_folder_subdirectories:
            for d in os.scandir(index_pack_path):
                if d.path not in metadata_files_in_index:
                    os.remove(d.path)

        # skipping index update in case hidden is set to True
        if hidden_pack:
            if os.path.exists(index_pack_path):
                shutil.rmtree(index_pack_path)  # remove pack folder inside index in case that it exists
            logging.warning(f"Skipping updating {pack_name} pack files to index")
            task_status = True
            return True

        # Copy new files and add metadata for latest version
        for d in os.scandir(pack_path):
            if not os.path.exists(index_pack_path):
                os.mkdir(index_pack_path)
                logging.info(f"Created {pack_name} pack folder in {GCPConfig.INDEX_NAME}")

            shutil.copy(d.path, index_pack_path)
            if pack_version and Pack.METADATA == d.name:
                shutil.copy(d.path, new_metadata_path)

        task_status = True
    except Exception:
        logging.exception(f"Failed in updating index folder for {pack_name} pack.")
    finally:
        return task_status


def clean_non_existing_packs(index_folder_path: str, private_packs: list, storage_bucket: Any,
                             storage_base_path: str) -> bool:
    """ Detects packs that are not part of content repo or from private packs bucket.

    In case such packs were detected, problematic pack is deleted from index and from content/packs/{target_pack} path.

    Args:
        index_folder_path (str): full path to downloaded index folder.
        private_packs (list): priced packs from private bucket.
        storage_bucket (google.cloud.storage.bucket.Bucket): google storage bucket where index.zip is stored.
        storage_base_path (str): the source path of the packs in the target bucket.

    Returns:
        bool: whether cleanup was skipped or not.
    """
    if ('CI' not in os.environ) or (
            os.environ.get('CI_COMMIT_BRANCH') != 'master' and storage_bucket.name == GCPConfig.PRODUCTION_BUCKET) or (
            os.environ.get('CI_COMMIT_BRANCH') == 'master' and storage_bucket.name not in
            (GCPConfig.PRODUCTION_BUCKET, GCPConfig.CI_BUILD_BUCKET)):
        logging.info("Skipping cleanup of packs in gcs.")  # skipping execution of cleanup in gcs bucket
        return True

    public_packs_names = {p for p in os.listdir(PACKS_FULL_PATH) if p not in IGNORED_FILES}
    private_packs_names = {p.get('id', '') for p in private_packs}
    valid_packs_names = public_packs_names.union(private_packs_names)
    # search for invalid packs folder inside index
    invalid_packs_names = {(entry.name, entry.path) for entry in os.scandir(index_folder_path) if
                           entry.name not in valid_packs_names and entry.is_dir()}

    if invalid_packs_names:
        try:
            logging.warning(f"Detected {len(invalid_packs_names)} non existing pack inside index, starting cleanup.")

            for invalid_pack in invalid_packs_names:
                invalid_pack_name = invalid_pack[0]
                invalid_pack_path = invalid_pack[1]
                # remove pack from index
                shutil.rmtree(invalid_pack_path)
                logging.warning(f"Deleted {invalid_pack_name} pack from {GCPConfig.INDEX_NAME} folder")
                # important to add trailing slash at the end of path in order to avoid packs with same prefix
                invalid_pack_gcs_path = os.path.join(storage_base_path, invalid_pack_name, "")  # by design

                for invalid_blob in [b for b in storage_bucket.list_blobs(prefix=invalid_pack_gcs_path)]:
                    logging.warning(f"Deleted invalid {invalid_pack_name} pack under url {invalid_blob.public_url}")
                    invalid_blob.delete()  # delete invalid pack in gcs
        except Exception:
            logging.exception("Failed to cleanup non existing packs.")

    else:
        logging.info(f"No invalid packs detected inside {GCPConfig.INDEX_NAME} folder")

    return False


def upload_index_to_storage(index_folder_path: str, extract_destination_path: str, index_blob: Any,
                            build_number: str, private_packs: list, current_commit_hash: str,
                            index_generation: int, is_private: bool = False, force_upload: bool = False,
                            previous_commit_hash: str = None, landing_page_sections: dict = None,
                            artifacts_dir: Optional[str] = None,
                            storage_bucket: Optional[Bucket] = None,
                            ):
    """
    Upload updated index zip to cloud storage.

    :param index_folder_path: index folder full path.
    :param extract_destination_path: extract folder full path.
    :param index_blob: google cloud storage object that represents index.zip blob.
    :param build_number: CI build number, used as an index revision.
    :param private_packs: List of private packs and their price.
    :param current_commit_hash: last commit hash of head.
    :param index_generation: downloaded index generation.
    :param is_private: Indicates if upload is private.
    :param force_upload: Indicates if force upload or not.
    :param previous_commit_hash: The previous commit hash to diff with.
    :param landing_page_sections: landingPage sections.
    :param artifacts_dir: The CI artifacts directory to upload the index.json to.
    :param storage_bucket: The storage bucket object
    :returns None.

    """
    if force_upload:
        # If we force upload we don't want to update the commit in the index.json file,
        # this is to be able to identify all changed packs in the next upload
        commit = previous_commit_hash
        logging.info('Force upload flow - Index commit hash should not be changed')
    else:
        # Otherwise, update the index with the current commit hash (the commit of the upload)
        commit = current_commit_hash
        logging.info('Updating production index commit hash to master last commit hash')

    if not landing_page_sections:
        landing_page_sections = load_json(LANDING_PAGE_SECTIONS_PATH)

    logging.debug(f'commit hash is: {commit}')
    index_json_path = os.path.join(index_folder_path, f'{GCPConfig.INDEX_NAME}.json')
    logging.info(f'index json path: {index_json_path}')
    logging.info(f'Private packs are: {private_packs}')
    with open(index_json_path, "w+") as index_file:
        index = {
            'revision': build_number,
            'modified': datetime.utcnow().strftime(Metadata.DATE_FORMAT),
            'packs': private_packs,
            'commit': commit,
            'landingPage': {'sections': landing_page_sections.get('sections', [])}  # type: ignore[union-attr]
        }
        json.dump(index, index_file, indent=4)

    index_zip_name = os.path.basename(index_folder_path)
    index_zip_path = shutil.make_archive(base_name=index_folder_path, format="zip",
                                         root_dir=extract_destination_path, base_dir=index_zip_name)
    try:
        logging.info(f'index zip path: {index_zip_path}')
        index_blob.reload()
        current_index_generation = index_blob.generation
        index_blob.cache_control = "no-cache,max-age=0"  # disabling caching for index blob

        if is_private or current_index_generation == index_generation:
            # we upload both index.json and the index.zip to allow usage of index.json without having to unzip
            index_blob.upload_from_filename(index_zip_path)
            logging.success(f"Finished uploading {GCPConfig.INDEX_NAME}.zip to storage.")
        else:
            logging.critical(f"Failed in uploading {GCPConfig.INDEX_NAME}, mismatch in index file generation.")
            logging.critical(f"Downloaded index generation: {index_generation}")
            logging.critical(f"Current index generation: {current_index_generation}")
            sys.exit(0)
    except Exception:
        logging.exception(f"Failed in uploading {GCPConfig.INDEX_NAME}.")
        sys.exit(1)
    finally:
        if artifacts_dir:
            # Store index.json in CircleCI artifacts
            shutil.copyfile(
                os.path.join(index_folder_path, f'{GCPConfig.INDEX_NAME}.json'),
                os.path.join(artifacts_dir, f'{GCPConfig.INDEX_NAME}.json'),
            )
        shutil.rmtree(index_folder_path)


def create_corepacks_config(storage_bucket: Any, build_number: str, index_folder_path: str,
                            artifacts_dir: str, storage_base_path: str, marketplace: str):
    """Create corepacks.json file and stores it in the artifacts dir. This files contains all of the server's core packs, under
    the key corepacks, and specifies which core packs should be upgraded upon XSOAR upgrade, under the key upgradeCorePacks.


     Args:
        storage_bucket (google.cloud.storage.bucket.Bucket): gcs bucket where core packs config is uploaded.
        build_number (str): circleCI build number.
        index_folder_path (str): The index folder path.
        artifacts_dir (str): The CI artifacts directory to upload the corepacks.json to.
        storage_base_path (str): the source path of the core packs in the target bucket.
        marketplace (str): the marketplace type of the bucket. possible options: xsoar, marketplace_v2

    """
    marketplace_core_packs = GCPConfig.get_core_packs(marketplace)
    core_packs_public_urls = []
    found_core_packs = set()
    for pack in os.scandir(index_folder_path):
        if pack.is_dir() and pack.name in marketplace_core_packs:
            pack_metadata_path = os.path.join(index_folder_path, pack.name, Pack.METADATA)

            if not os.path.exists(pack_metadata_path):
                logging.critical(f"{pack.name} pack {Pack.METADATA} is missing in {GCPConfig.INDEX_NAME}")
                sys.exit(1)

            with open(pack_metadata_path, 'r') as metadata_file:
                metadata = json.load(metadata_file)

            pack_current_version = metadata.get('currentVersion', Pack.PACK_INITIAL_VERSION)
            core_pack_relative_path = os.path.join(storage_base_path, pack.name,
                                                   pack_current_version, f"{pack.name}.zip")
            core_pack_public_url = os.path.join(GCPConfig.GCS_PUBLIC_URL, storage_bucket.name, core_pack_relative_path)

            if not storage_bucket.blob(core_pack_relative_path).exists():
                logging.critical(f"{pack.name} pack does not exist under {core_pack_relative_path} path")
                sys.exit(1)

            core_packs_public_urls.append(core_pack_public_url)
            found_core_packs.add(pack.name)

    if len(found_core_packs) != len(marketplace_core_packs):
        missing_core_packs = set(marketplace_core_packs) ^ found_core_packs
        logging.critical(f"Number of defined core packs are: {len(marketplace_core_packs)}")
        logging.critical(f"Actual number of found core packs are: {len(found_core_packs)}")
        logging.critical(f"Missing core packs are: {missing_core_packs}")
        sys.exit(1)

    corepacks_json_path = os.path.join(artifacts_dir, GCPConfig.CORE_PACK_FILE_NAME)
    core_packs_data = {
        'corePacks': core_packs_public_urls,
        'upgradeCorePacks': GCPConfig.get_core_packs_to_upgrade(marketplace),
        'buildNumber': build_number
    }
    json_write(corepacks_json_path, core_packs_data)
    logging.success(f"Finished copying {GCPConfig.CORE_PACK_FILE_NAME} to artifacts.")


def _build_summary_table(packs_input_list: list, include_pack_status: bool = False) -> Any:
    """Build summary table from pack list

    Args:
        packs_input_list (list): list of Packs
        include_pack_status (bool): whether pack includes status

    Returns:
        PrettyTable: table with upload result of packs.

    """
    table_fields = ["Index", "Pack ID", "Pack Display Name", "Latest Version", "Aggregated Pack Versions"]
    if include_pack_status:
        table_fields.append("Status")
    table = prettytable.PrettyTable()
    table.field_names = table_fields

    for index, pack in enumerate(packs_input_list, start=1):
        pack_status_message = PackStatus[pack.status].value
        row = [index, pack.name, pack.display_name, pack.latest_version,
               pack.aggregation_str if pack.aggregated and pack.aggregation_str else "False"]
        if include_pack_status:
            row.append(pack_status_message)
        table.add_row(row)

    return table


def build_summary_table_md(packs_input_list: list, include_pack_status: bool = False) -> str:
    """Build markdown summary table from pack list

    Args:
        packs_input_list (list): list of Packs
        include_pack_status (bool): whether pack includes status

    Returns:
        Markdown table: table with upload result of packs.

    """
    table_fields = ["Index", "Pack ID", "Pack Display Name", "Latest Version", "Status"] if include_pack_status \
        else ["Index", "Pack ID", "Pack Display Name", "Latest Version"]

    table = ['|', '|']

    for key in table_fields:
        table[0] = f'{table[0]} {key} |'
        table[1] = f'{table[1]} :- |'

    for index, pack in enumerate(packs_input_list):
        pack_status_message = PackStatus[pack.status].value if include_pack_status else ''

        row = [index, pack.name, pack.display_name, pack.latest_version, pack_status_message] if include_pack_status \
            else [index, pack.name, pack.display_name, pack.latest_version]

        row_hr = '|'
        for _value in row:
            row_hr = f'{row_hr} {_value}|'
        table.append(row_hr)

    return '\n'.join(table)


def add_private_content_to_index(private_index_path: str, extract_destination_path: str, index_folder_path: str,
                                 pack_names: set) -> Tuple[Union[list, list], list]:
    """ Adds a list of priced packs data-structures to the public index.json file.
    This step should not be skipped even if there are no new or updated private packs.

    Args:
        private_index_path: path to where the private index is located.
        extract_destination_path (str): full path to extract directory.
        index_folder_path (str): downloaded index folder directory path.
        pack_names (set): collection of pack names.

    Returns:
        list: priced packs from private bucket.

    """

    private_packs = []
    updated_private_packs = []

    try:
        private_packs = get_private_packs(private_index_path, pack_names,
                                          extract_destination_path)
        updated_private_packs = get_updated_private_packs(private_packs, index_folder_path)
        add_private_packs_to_index(index_folder_path, private_index_path)

    except Exception as e:
        logging.exception(f"Could not add private packs to the index. Additional Info: {str(e)}")

    finally:
        logging.info("Finished updating index with priced packs")
        shutil.rmtree(os.path.dirname(private_index_path), ignore_errors=True)
        return private_packs, updated_private_packs


def get_updated_private_packs(private_packs, index_folder_path):
    """ Checks for updated private packs by compering contentCommitHash between public index json and private pack
    metadata files.

    Args:
        private_packs (list): List of dicts containing pack metadata information.
        index_folder_path (str): The public index folder path.

    Returns:
        updated_private_packs (list) : a list of all private packs id's that were updated.

    """
    updated_private_packs = []

    public_index_file_path = os.path.join(index_folder_path, f"{GCPConfig.INDEX_NAME}.json")
    public_index_json = load_json(public_index_file_path)
    private_packs_from_public_index = public_index_json.get("packs", {})

    for pack in private_packs:
        private_pack_id = pack.get('id')
        private_commit_hash_from_metadata = pack.get('contentCommitHash', "")
        private_commit_hash_from_content_repo = ""
        for public_pack in private_packs_from_public_index:
            if public_pack.get('id') == private_pack_id:
                private_commit_hash_from_content_repo = public_pack.get('contentCommitHash', "")

        private_pack_was_updated = private_commit_hash_from_metadata != private_commit_hash_from_content_repo
        if private_pack_was_updated:
            updated_private_packs.append(private_pack_id)

    logging.debug(f"Updated private packs are: {updated_private_packs}")
    return updated_private_packs


def get_private_packs(private_index_path: str, pack_names: set = None,
                      extract_destination_path: str = '') -> list:
    """
    Gets a list of private packs.

    :param private_index_path: Path to where the private index is located.
    :param pack_names: Collection of pack names.
    :param extract_destination_path: Path to where the files should be extracted to.
    :return: List of dicts containing pack metadata information.
    """
    logging.info(f'getting all private packs. private_index_path: {private_index_path}')
    try:
        metadata_files = glob.glob(f"{private_index_path}/**/metadata.json")
    except Exception:
        logging.exception(f'Could not find metadata files in {private_index_path}.')
        return []

    if not metadata_files:
        logging.warning(f'No metadata files found in [{private_index_path}]')

    private_packs = []
    pack_names = pack_names or set()
    logging.info(f'all metadata files found: {metadata_files}')
    for metadata_file_path in metadata_files:
        try:
            with open(metadata_file_path, "r") as metadata_file:
                metadata = json.load(metadata_file)
            pack_id = metadata.get('id')
            is_changed_private_pack = pack_id in pack_names
            if is_changed_private_pack:  # Should take metadata from artifacts.
                with open(os.path.join(extract_destination_path, pack_id, "pack_metadata.json"),
                          "r") as metadata_file:
                    metadata = json.load(metadata_file)
            if metadata:
                private_packs.append({
                    'id': metadata.get('id') if not is_changed_private_pack else metadata.get('name'),
                    'price': metadata.get('price'),
                    'vendorId': metadata.get('vendorId', ""),
                    'partnerId': metadata.get('partnerId', ""),
                    'partnerName': metadata.get('partnerName', ""),
                    'contentCommitHash': metadata.get('contentCommitHash', "")
                })
        except ValueError:
            logging.exception(f'Invalid JSON in the metadata file [{metadata_file_path}].')

    return private_packs


def add_private_packs_to_index(index_folder_path: str, private_index_path: str):
    """ Add the private packs to the index folder.

    Args:
        index_folder_path: The index folder path.
        private_index_path: The path for the index of the private packs.

    """
    for d in os.scandir(private_index_path):
        if os.path.isdir(d.path):
            update_index_folder(index_folder_path, d.name, d.path)


def is_private_packs_updated(public_index_json, private_index_path):
    """ Checks whether there were changes in private packs from the last upload.
    The check compares the `content commit hash` field in the public index with the value stored in the private index.
    If there is at least one private pack that has been updated/released, the upload should be performed and not
    skipped.

    Args:
        public_index_json (dict) : The public index.json file.
        private_index_path (str): Path to where the private index.zip is located.

    Returns:
        is_private_packs_updated (bool): True if there is at least one private pack that was updated/released,
         False otherwise (i.e there are no private packs that have been updated/released).

    """
    logging.debug("Checking if there are updated private packs")

    private_index_file_path = os.path.join(private_index_path, f"{GCPConfig.INDEX_NAME}.json")
    private_index_json = load_json(private_index_file_path)
    private_packs_from_private_index = private_index_json.get("packs")
    private_packs_from_public_index = public_index_json.get("packs")

    if len(private_packs_from_private_index) != len(private_packs_from_public_index):
        # private pack was added or deleted
        logging.debug("There is at least one private pack that was added/deleted, upload should not be skipped.")
        return True

    id_to_commit_hash_from_public_index = {private_pack.get("id"): private_pack.get("contentCommitHash", "") for
                                           private_pack in private_packs_from_public_index}

    for private_pack in private_packs_from_private_index:
        pack_id = private_pack.get("id")
        content_commit_hash = private_pack.get("contentCommitHash", "")
        if id_to_commit_hash_from_public_index.get(pack_id) != content_commit_hash:
            logging.debug("There is at least one private pack that was updated, upload should not be skipped.")
            return True

    logging.debug("No private packs were changed")
    return False


def check_if_index_is_updated(index_folder_path: str, content_repo: Any, current_commit_hash: str,
                              previous_commit_hash: str, storage_bucket: Any,
                              is_private_content_updated: bool = False):
    """ Checks stored at index.json commit hash and compares it to current commit hash. In case no packs folders were
    added/modified/deleted, all other steps are not performed.

    Args:
        index_folder_path (str): index folder full path.
        content_repo (git.repo.base.Repo): content repo object.
        current_commit_hash (str): last commit hash of head.
        previous_commit_hash (str): the previous commit to diff with
        storage_bucket: public storage bucket.
        is_private_content_updated (bool): True if private content updated, False otherwise.

    """
    skipping_build_task_message = "Skipping Upload Packs To Marketplace Storage Step."

    try:
        if storage_bucket.name not in (GCPConfig.CI_BUILD_BUCKET, GCPConfig.PRODUCTION_BUCKET):
            logging.info("Skipping index update check in non production/build bucket")
            return

        if is_private_content_updated:
            logging.debug("Skipping index update as Private Content has updated.")
            return

        if not os.path.exists(os.path.join(index_folder_path, f"{GCPConfig.INDEX_NAME}.json")):
            # will happen only in init bucket run
            logging.warning(f"{GCPConfig.INDEX_NAME}.json not found in {GCPConfig.INDEX_NAME} folder")
            return

        with open(os.path.join(index_folder_path, f"{GCPConfig.INDEX_NAME}.json")) as index_file:
            index_json = json.load(index_file)

        index_commit_hash = index_json.get('commit', previous_commit_hash)

        try:
            index_commit = content_repo.commit(index_commit_hash)
        except Exception:
            # not updated build will receive this exception because it is missing more updated commit
            logging.exception(f"Index is already updated. {skipping_build_task_message}")
            sys.exit()

        current_commit = content_repo.commit(current_commit_hash)

        if current_commit.committed_datetime <= index_commit.committed_datetime:
            logging.warning(
                f"Current commit {current_commit.hexsha} committed time: {current_commit.committed_datetime}")
            logging.warning(f"Index commit {index_commit.hexsha} committed time: {index_commit.committed_datetime}")
            logging.warning("Index is already updated.")
            logging.warning(skipping_build_task_message)
            sys.exit()

        for changed_file in current_commit.diff(index_commit):
            if changed_file.a_path.startswith(PACKS_FOLDER):
                logging.info(
                    f"Found changed packs between index commit {index_commit.hexsha} and {current_commit.hexsha}")
                break
        else:
            logging.warning(f"No changes found between index commit {index_commit.hexsha} and {current_commit.hexsha}")
            logging.warning(skipping_build_task_message)
            sys.exit()
    except Exception:
        logging.exception("Failed in checking status of index")
        sys.exit(1)


def print_packs_summary(successful_packs: list, skipped_packs: list, failed_packs: list,
                        fail_build: bool = True):
    """Prints summary of packs uploaded to gcs.

    Args:
        successful_packs (list): list of packs that were successfully uploaded.
        skipped_packs (list): list of packs that were skipped during upload.
        failed_packs (list): list of packs that were failed during upload.
        fail_build (bool): indicates whether to fail the build upon failing pack to upload or not

    """
    logging.info(
        f"""\n
------------------------------------------ Packs Upload Summary ------------------------------------------
Total number of packs: {len(successful_packs + skipped_packs + failed_packs)}
----------------------------------------------------------------------------------------------------------""")

    if successful_packs:
        successful_packs_table = _build_summary_table(successful_packs)
        logging.success(f"Number of successful uploaded packs: {len(successful_packs)}")
        logging.success(f"Uploaded packs:\n{successful_packs_table}")
        with open('pack_list.txt', 'w') as f:
            f.write(successful_packs_table.get_string())
    if skipped_packs:
        skipped_packs_table = _build_summary_table(skipped_packs, include_pack_status=True)
        logging.warning(f"Number of skipped packs: {len(skipped_packs)}")
        logging.warning(f"Skipped packs:\n{skipped_packs_table}")
    if failed_packs:
        failed_packs_table = _build_summary_table(failed_packs, include_pack_status=True)
        logging.critical(f"Number of failed packs: {len(failed_packs)}")
        logging.critical(f"Failed packs:\n{failed_packs_table}")
        if fail_build:
            # We don't want the bucket upload flow to fail in Prepare Content step if a pack has failed to upload.
            sys.exit(1)

    # for external pull requests -  when there is no failed packs, add the build summary to the pull request
    branch_name = os.environ.get('CI_COMMIT_BRANCH')
    if branch_name and branch_name.startswith('pull/'):
        successful_packs_table = build_summary_table_md(successful_packs)

        build_num = os.environ['CI_BUILD_ID']

        bucket_path = f'https://console.cloud.google.com/storage/browser/' \
                      f'marketplace-ci-build/content/builds/{branch_name}/{build_num}'

        pr_comment = f'Number of successful uploaded packs: {len(successful_packs)}\n' \
                     f'Uploaded packs:\n{successful_packs_table}\n\n' \
                     f'Browse to the build bucket with this address:\n{bucket_path}'

        add_pr_comment(pr_comment)


def add_pr_comment(comment: str):
    """Add comment to the pull request.

    Args:
        comment (string): The comment text.

    """
    token = os.environ['CONTENT_GITHUB_TOKEN']
    branch_name = os.environ['CI_COMMIT_BRANCH']
    sha1 = os.environ['CI_COMMIT_SHA']

    query = f'?q={sha1}+repo:demisto/content+is:pr+is:open+head:{branch_name}+is:open'
    url = 'https://api.github.com/search/issues'
    headers = {'Authorization': 'Bearer ' + token}
    try:
        res = requests.get(url + query, headers=headers, verify=False)
        res_json = handle_github_response(res)
        if res_json and res_json.get('total_count', 0) == 1:
            issue_url = res_json['items'][0].get('comments_url') if res_json.get('items', []) else None
            if issue_url:
                res = requests.post(issue_url, json={'body': comment}, headers=headers, verify=False)
                handle_github_response(res)
        else:
            logging.warning(
                f'Add pull request comment failed: There is more then one open pull request for branch {branch_name}.')
    except Exception:
        logging.exception('Add pull request comment failed.')


def handle_github_response(response: Response) -> dict:
    """
    Handles the response from the GitHub server after making a request.
    :param response: Response from the server.
    :return: The returned response.
    """
    res_dict = response.json()
    if not res_dict.get('ok'):
        logging.warning(f'Add pull request comment failed: {res_dict.get("message")}')
    return res_dict


def get_packs_summary(packs_list):
    """ Returns the packs list divided into 3 lists by their status

    Args:
        packs_list (list): The full packs list

    Returns: 3 lists of packs - successful_packs, skipped_packs & failed_packs

    """
    skipped_status_codes = {
        PackStatus.PACK_ALREADY_EXISTS.name,
        PackStatus.PACK_IS_NOT_UPDATED_IN_RUNNING_BUILD.name,
        PackStatus.NOT_RELEVANT_FOR_MARKETPLACE.name,
    }

    successful_packs = []
    skipped_packs = []
    failed_packs = []
    for pack in packs_list:
        if pack.status == PackStatus.SUCCESS.name:
            successful_packs.append(pack)
        elif pack.status in skipped_status_codes:
            skipped_packs.append(pack)
        else:
            failed_packs.append(pack)

    return successful_packs, skipped_packs, failed_packs


def handle_private_content(public_index_folder_path, private_bucket_name, extract_destination_path, storage_client,
                           public_pack_names, storage_base_path: str) -> Tuple[bool, list, list]:
    """
    1. Add private packs to public index.json.
    2. Checks if there are private packs that were added/deleted/updated.

    Args:
        public_index_folder_path: extracted public index folder full path.
        private_bucket_name: Private storage bucket name
        extract_destination_path: full path to extract directory.
        storage_client : initialized google cloud storage client.
        public_pack_names : unique collection of public packs names to upload.
        storage_base_path (str): the source path in the target bucket.

    Returns:
        is_private_content_updated (bool): True if there is at least one private pack that was updated/released.
        False otherwise (i.e there are no private packs that have been updated/released).
        private_packs (list) : priced packs from private bucket.
        updated_private_packs_ids (list): all private packs id's that were updated.
    """
    if private_bucket_name:
        private_storage_bucket = storage_client.bucket(private_bucket_name)
        private_index_path, _, _ = download_and_extract_index(
            private_storage_bucket, os.path.join(extract_destination_path, "private"), storage_base_path
        )

        public_index_json_file_path = os.path.join(public_index_folder_path, f"{GCPConfig.INDEX_NAME}.json")
        public_index_json = load_json(public_index_json_file_path)

        if public_index_json:
            are_private_packs_updated = is_private_packs_updated(public_index_json, private_index_path)
            private_packs, updated_private_packs_ids = add_private_content_to_index(
                private_index_path, extract_destination_path, public_index_folder_path, public_pack_names
            )
            return are_private_packs_updated, private_packs, updated_private_packs_ids
        else:
            logging.error(f"Public {GCPConfig.INDEX_NAME}.json was found empty.")
            sys.exit(1)
    else:
        return False, [], []


def get_images_data(packs_list: list):
    """ Returns a data structure of all packs that an integration/author image of them was uploaded

    Args:
        packs_list (list): The list of all packs

    Returns:
        The images data structure
    """
    images_data = {}

    for pack in packs_list:
        pack_image_data: dict = {pack.name: {}}
        if pack.uploaded_author_image:
            pack_image_data[pack.name][BucketUploadFlow.AUTHOR] = True
        if pack.uploaded_integration_images:
            pack_image_data[pack.name][BucketUploadFlow.INTEGRATIONS] = pack.uploaded_integration_images
        if pack_image_data[pack.name]:
            images_data.update(pack_image_data)

    return images_data


def map_pack_dependencies_graph(pack_name, first_level_graph, full_dep_graph):
    """ Travel the mandatory dependencies to collect all dependencies under each pack name

    Args:
        pack_name (str): Name of the pack to look dependencies for.
        first_level_graph (dict): Graph of the first level dependencies.
        full_dep_graph (dict): Graph of all level mandatory dependencies (lazily loaded).

    Returns:
        (dict): Full dependencies graph
    """
    if pack_name not in full_dep_graph:
        pack_deps = set()
        if pack_name != "Base":
            # Base is always missing from the dependencies graph, but all are dependent on it
            pack_deps.add("Base")
        full_dep_graph[pack_name] = pack_deps
        deps = first_level_graph.get(pack_name, {}).get('dependencies')
        if not deps:
            return full_dep_graph
        for dep_name, dep_val in deps.items():
            # add 1st level mandatory dependencies
            if dep_val.get('mandatory'):
                pack_deps.add(dep_name)
                # add 2nd+ level mandatory dependencies
                map_pack_dependencies_graph(dep_name, first_level_graph, full_dep_graph)
                for inner_dep_name in full_dep_graph[dep_name]:
                    pack_deps.add(inner_dep_name)
    return full_dep_graph


def prepare_and_zip_pack(pack, signature_key, delete_test_playbooks=True):
    """
    Prepares the pack before zip, and then zips it.
    Args:
        pack (Pack): Pack to be zipped.
        signature_key (str): Base64 encoded string used to sign the pack.
        delete_test_playbooks (bool): Whether to delete test playbooks folder.
    Returns:
        (bool): Whether the zip was successful
    """
    task_status = pack.load_user_metadata()
    if not task_status:
        pack.status = PackStatus.FAILED_LOADING_USER_METADATA.value
        pack.cleanup()
        return False
    task_status = pack.collect_content_items()
    if not task_status:
        pack.status = PackStatus.FAILED_COLLECT_ITEMS.name
        pack.cleanup()
        return False
    task_status = pack.remove_unwanted_files(delete_test_playbooks)
    if not task_status:
        pack.status = PackStatus.FAILED_REMOVING_PACK_SKIPPED_FOLDERS
        pack.cleanup()
        return False
    task_status = pack.sign_pack(signature_key)
    if not task_status:
        pack.status = PackStatus.FAILED_SIGNING_PACKS.name
        pack.cleanup()
        return False
    task_status, _ = pack.zip_pack()
    if not task_status:
        pack.status = PackStatus.FAILED_ZIPPING_PACK_ARTIFACTS.name
        pack.cleanup()
        return False
    return True


def get_all_packs(packs_dict, extract_destination_path, id_set_path, marketplace):
    """
    Collect all packs from the id_set that are not packs_dict
    """
    if not id_set_path or not os.path.isfile(id_set_path):
        return packs_dict
    packs_dict = dict(packs_dict)
    with open(id_set_path) as f:
        id_set_packs = json.load(f).get('Packs', [])
    for pack_name in id_set_packs.keys():
        if pack_name not in packs_dict:
            pack = Pack(pack_name, os.path.join(extract_destination_path, pack_name), marketplace)
            packs_dict[pack_name] = pack
    return packs_dict


def upload_packs_with_dependencies_zip(extract_destination_path, packs_dependencies_mapping, signature_key,
                                       storage_bucket, storage_base_path, id_set_path, packs_list, marketplace):
    """
    Uploads packs with mandatory dependencies zip for all packs
    """
    logging.info("Starting to collect pack with dependencies zips")
    packs_dict = {pack.name: pack for pack in packs_list}
    packs_dict = get_all_packs(packs_dict, extract_destination_path, id_set_path, marketplace)
    full_deps_graph: dict = {}
    try:
        for pack in packs_dict.values():
            logging.info(f"Collecting dependencies of {pack.name}")
            pack_with_dep_path = os.path.join(pack.path, "with_dependencies")
            zip_with_deps_path = os.path.join(pack.path, pack.name + "_with_dependencies.zip")
            upload_path = os.path.join(storage_base_path, pack.name, pack.name + "_with_dependencies.zip")
            Path(pack_with_dep_path).mkdir(parents=True, exist_ok=True)
            full_deps_graph = map_pack_dependencies_graph(pack.name, packs_dependencies_mapping, full_deps_graph)
            if pack.name not in full_deps_graph:
                logging.error(f"Skipping dependencies collection for {pack.name}. missing from full_deps_graph")
                continue
            pack_deps = full_deps_graph[pack.name]
            if not (pack.zip_path and os.path.isfile(pack.zip_path)):
                if not prepare_and_zip_pack(pack, signature_key):
                    logging.warning(f"Skipping dependencies collection for {pack.name}. Failed zipping")
                    continue
            shutil.copy(pack.zip_path, os.path.join(pack_with_dep_path, pack.name + ".zip"))
            for dep_name in pack_deps:
                if dep_name not in packs_dict:
                    dep_pack = Pack(dep_name, os.path.join(extract_destination_path, dep_name), marketplace)
                    packs_dict[dep_name] = dep_pack
                else:
                    dep_pack = packs_dict[dep_name]
                if not (dep_pack.zip_path and os.path.isfile(dep_pack.zip_path)):
                    if not prepare_and_zip_pack(dep_pack, signature_key):
                        logging.error(f"Skipping dependency {pack.name}. Failed zipping")
                        continue
                shutil.copy(dep_pack.zip_path, os.path.join(pack_with_dep_path, dep_name + '.zip'))
            logging.info(f"Zipping {pack.name} with dependencies")
            Pack.zip_folder_items(
                pack_with_dep_path,
                pack_with_dep_path,
                zip_with_deps_path
            )
            shutil.rmtree(pack_with_dep_path)
            logging.info(f"Uploading {pack.name} with dependencies")
            task_status, _, _ = pack.upload_to_storage(
                zip_pack_path=zip_with_deps_path,
                latest_version='',
                storage_bucket=storage_bucket,
                override_pack=True,
                storage_base_path=storage_base_path,
                upload_path=upload_path
            )
            logging.info(f"{pack.name} with dependencies was{' not' if not task_status else ''} uploaded successfully")
            if not task_status:
                pack.status = PackStatus.FAILED_UPLOADING_PACK.name
                pack.cleanup()
    except Exception as e:
        logging.error(traceback.format_exc())
        logging.error(f"Failed uploading packs with dependencies: {e}")


def option_handler():
    """Validates and parses script arguments.

    Returns:
        Namespace: Parsed arguments object.

    """
    parser = argparse.ArgumentParser(description="Store packs in cloud storage.")
    # disable-secrets-detection-start
    parser.add_argument('-pa', '--packs_artifacts_path', help="The full path of packs artifacts", required=True)
    parser.add_argument('-idp', '--id_set_path', help="The full path of id_set.json", required=False)
    parser.add_argument('-e', '--extract_path', help="Full path of folder to extract wanted packs", required=True)
    parser.add_argument('-b', '--bucket_name', help="Storage bucket name", required=True)
    parser.add_argument('-s', '--service_account',
                        help=("Path to gcloud service account, is for circleCI usage. "
                              "For local development use your personal account and "
                              "authenticate using Google Cloud SDK by running: "
                              "`gcloud auth application-default login` and leave this parameter blank. "
                              "For more information go to: "
                              "https://googleapis.dev/python/google-api-core/latest/auth.html"),
                        required=False)
    parser.add_argument('-d', '--pack_dependencies', help="Full path to pack dependencies json file.", required=False)
    parser.add_argument('-p', '--pack_names',
                        help=("Target packs to upload to gcs. Optional values are: `All`, "
                              "`Modified` or csv list of packs "
                              "Default is set to `All`"),
                        required=False, default="All")
    parser.add_argument('-n', '--ci_build_number',
                        help="CircleCi build number (will be used as hash revision at index file)", required=False)
    parser.add_argument('-o', '--override_all_packs', help="Override all existing packs in cloud storage",
                        type=str2bool, default=False, required=True)
    parser.add_argument('-k', '--key_string', help="Base64 encoded signature key used for signing packs.",
                        required=False)
    parser.add_argument('-sb', '--storage_base_path', help="Storage base path of the directory to upload to.",
                        required=False)
    parser.add_argument('-rt', '--remove_test_playbooks', type=str2bool,
                        help='Should remove test playbooks from content packs or not.', default=True)
    parser.add_argument('-bu', '--bucket_upload', help='is bucket upload build?', type=str2bool, required=True)
    parser.add_argument('-pb', '--private_bucket_name', help="Private storage bucket name", required=False)
    parser.add_argument('-c', '--ci_branch', help="CI branch of current build", required=True)
    parser.add_argument('-f', '--force_upload', help="is force upload build?", type=str2bool, required=True)
    parser.add_argument('-dz', '--create_dependencies_zip', help="Upload packs with dependencies zip", type=str2bool,
                        required=False, default='false')
    parser.add_argument('-mp', '--marketplace', help="marketplace version", default='xsoar')
    # disable-secrets-detection-end
    return parser.parse_args()


def main():
    install_logging('Prepare_Content_Packs_For_Testing.log', logger=logging)
    option = option_handler()
    packs_artifacts_path = option.packs_artifacts_path
    id_set_path = option.id_set_path
    extract_destination_path = option.extract_path
    storage_bucket_name = option.bucket_name
    service_account = option.service_account
    target_packs = option.pack_names if option.pack_names else ""
    build_number = option.ci_build_number if option.ci_build_number else str(uuid.uuid4())
    override_all_packs = option.override_all_packs
    signature_key = option.key_string
    packs_dependencies_mapping = load_json(option.pack_dependencies) if option.pack_dependencies else {}
    storage_base_path = option.storage_base_path
    remove_test_playbooks = option.remove_test_playbooks
    is_bucket_upload_flow = option.bucket_upload
    private_bucket_name = option.private_bucket_name
    ci_branch = option.ci_branch
    force_upload = option.force_upload
    marketplace = option.marketplace
    is_create_dependencies_zip = option.create_dependencies_zip

    # google cloud storage client initialized
    storage_client = init_storage_client(service_account)
    storage_bucket = storage_client.bucket(storage_bucket_name)

    # Relevant when triggering test upload flow
    if storage_bucket_name:
        GCPConfig.PRODUCTION_BUCKET = storage_bucket_name

    # download and extract index from public bucket
    index_folder_path, index_blob, index_generation = download_and_extract_index(storage_bucket,
                                                                                 extract_destination_path,
                                                                                 storage_base_path)

    # content repo client initialized
    content_repo = get_content_git_client(CONTENT_ROOT_PATH)
    current_commit_hash, previous_commit_hash = get_recent_commits_data(content_repo, index_folder_path,
                                                                        is_bucket_upload_flow, ci_branch)

    # detect packs to upload
    pack_names = get_packs_names(target_packs, previous_commit_hash)
    extract_packs_artifacts(packs_artifacts_path, extract_destination_path)
    packs_list = [Pack(pack_name, os.path.join(extract_destination_path, pack_name), marketplace) for pack_name in pack_names
                  if os.path.exists(os.path.join(extract_destination_path, pack_name))]
    diff_files_list = content_repo.commit(current_commit_hash).diff(content_repo.commit(previous_commit_hash))

    # taking care of private packs
    is_private_content_updated, private_packs, updated_private_packs_ids = handle_private_content(
        index_folder_path, private_bucket_name, extract_destination_path, storage_client, pack_names, storage_base_path
    )

    if not option.override_all_packs:
        check_if_index_is_updated(index_folder_path, content_repo, current_commit_hash, previous_commit_hash,
                                  storage_bucket, is_private_content_updated)

    # initiate the statistics handler for marketplace packs
    statistics_handler = StatisticsHandler(service_account, index_folder_path)

    # clean index and gcs from non existing or invalid packs
    clean_non_existing_packs(index_folder_path, private_packs, storage_bucket, storage_base_path)

    # Packages that depend on new packs that are not in the previous index.json
    packs_missing_dependencies = []

    # starting iteration over packs
    for pack in packs_list:
        if not pack.should_upload_to_marketplace:
            logging.warning(f"Skipping {pack.name} pack as it is not supported in the current marketplace.")
            pack.status = PackStatus.NOT_RELEVANT_FOR_MARKETPLACE.name
            pack.cleanup()
            continue
        task_status = pack.upload_integration_images(storage_bucket, storage_base_path, diff_files_list, True)
        if not task_status:
            pack.status = PackStatus.FAILED_IMAGES_UPLOAD.name
            pack.cleanup()
            continue

        task_status = pack.upload_author_image(storage_bucket, storage_base_path, diff_files_list, True)

        if not task_status:
            pack.status = PackStatus.FAILED_AUTHOR_IMAGE_UPLOAD.name
            pack.cleanup()
            continue

        if not prepare_and_zip_pack(pack, signature_key, remove_test_playbooks):
            continue

        task_status, modified_rn_files_paths, pack_was_modified = pack.detect_modified(
            content_repo, index_folder_path, current_commit_hash, previous_commit_hash)

        if not task_status:
            pack.status = PackStatus.FAILED_DETECTING_MODIFIED_FILES.name
            pack.cleanup()
            continue

        task_status, is_missing_dependencies = pack.format_metadata(index_folder_path,
                                                                    packs_dependencies_mapping, build_number,
                                                                    current_commit_hash, pack_was_modified,
                                                                    statistics_handler, pack_names)

        if is_missing_dependencies:
            # If the pack is dependent on a new pack
            # (which is not yet in the index.zip as it might not have been iterated yet)
            # we will note that it is missing dependencies.
            # And finally after updating all the packages in index.zip - i.e. the new pack exists now.
            # We will go over the pack again to add what was missing.
            # See issue #37290
            packs_missing_dependencies.append(pack)

        if not task_status:
            pack.status = PackStatus.FAILED_METADATA_PARSING.name
            pack.cleanup()
            continue

        task_status, not_updated_build = pack.prepare_release_notes(index_folder_path, build_number, pack_was_modified,
                                                                    modified_rn_files_paths)
        if not task_status:
            pack.status = PackStatus.FAILED_RELEASE_NOTES.name
            pack.cleanup()
            continue

        if not_updated_build:
            pack.status = PackStatus.PACK_IS_NOT_UPDATED_IN_RUNNING_BUILD.name
            pack.cleanup()
            continue

        task_status, skipped_upload, _ = pack.upload_to_storage(pack.zip_path, pack.latest_version, storage_bucket,
                                                                override_all_packs or pack_was_modified,
                                                                storage_base_path)

        if not task_status:
            pack.status = PackStatus.FAILED_UPLOADING_PACK.name
            pack.cleanup()
            continue

        task_status, exists_in_index = pack.check_if_exists_in_index(index_folder_path)
        if not task_status:
            pack.status = PackStatus.FAILED_SEARCHING_PACK_IN_INDEX.name
            pack.cleanup()
            continue

        task_status = pack.prepare_for_index_upload()
        if not task_status:
            pack.status = PackStatus.FAILED_PREPARING_INDEX_FOLDER.name
            pack.cleanup()
            continue

        task_status = update_index_folder(index_folder_path=index_folder_path, pack_name=pack.name, pack_path=pack.path,
                                          pack_version=pack.latest_version, hidden_pack=pack.hidden)
        if not task_status:
            pack.status = PackStatus.FAILED_UPDATING_INDEX_FOLDER.name
            pack.cleanup()
            continue

        # in case that pack already exist at cloud storage path and in index, don't show that the pack was changed
        if skipped_upload and exists_in_index and pack not in packs_missing_dependencies:
            pack.status = PackStatus.PACK_ALREADY_EXISTS.name
            pack.cleanup()
            continue

        pack.status = PackStatus.SUCCESS.name

    logging.info(f"packs_missing_dependencies: {packs_missing_dependencies}")

    # Going over all packs that were marked as missing dependencies,
    # updating them with the new data for the new packs that were added to the index.zip
    for pack in packs_missing_dependencies:
        task_status, _ = pack.format_metadata(index_folder_path, packs_dependencies_mapping,
                                              build_number, current_commit_hash, False, statistics_handler,
                                              pack_names, format_dependencies_only=True)

        if not task_status:
            pack.status = PackStatus.FAILED_METADATA_REFORMATING.name
            pack.cleanup()
            continue

        task_status = update_index_folder(index_folder_path=index_folder_path, pack_name=pack.name, pack_path=pack.path,
                                          pack_version=pack.latest_version, hidden_pack=pack.hidden)
        if not task_status:
            pack.status = PackStatus.FAILED_UPDATING_INDEX_FOLDER.name
            pack.cleanup()
            continue

        pack.status = PackStatus.SUCCESS.name

    # upload core packs json to bucket
    create_corepacks_config(storage_bucket, build_number, index_folder_path,
                            os.path.dirname(packs_artifacts_path), storage_base_path, marketplace)

    # finished iteration over content packs
    upload_index_to_storage(index_folder_path=index_folder_path, extract_destination_path=extract_destination_path,
                            index_blob=index_blob, build_number=build_number, private_packs=private_packs,
                            current_commit_hash=current_commit_hash, index_generation=index_generation,
                            force_upload=force_upload, previous_commit_hash=previous_commit_hash,
                            landing_page_sections=statistics_handler.landing_page_sections,
                            artifacts_dir=os.path.dirname(packs_artifacts_path),
                            storage_bucket=storage_bucket,
                            )

    # get the lists of packs divided by their status
    successful_packs, skipped_packs, failed_packs = get_packs_summary(packs_list)

    # Store successful and failed packs list in CircleCI artifacts - to be used in Upload Packs To Marketplace job
    packs_results_file_path = os.path.join(os.path.dirname(packs_artifacts_path), BucketUploadFlow.PACKS_RESULTS_FILE)
    store_successful_and_failed_packs_in_ci_artifacts(
        packs_results_file_path, BucketUploadFlow.PREPARE_CONTENT_FOR_TESTING, successful_packs, failed_packs,
        updated_private_packs_ids, images_data=get_images_data(packs_list)
    )

    # summary of packs status
    print_packs_summary(successful_packs, skipped_packs, failed_packs, not is_bucket_upload_flow)

    if is_create_dependencies_zip:
        # handle packs with dependencies zip
        upload_packs_with_dependencies_zip(extract_destination_path, packs_dependencies_mapping, signature_key,
                                           storage_bucket, storage_base_path, id_set_path, packs_list, marketplace)


if __name__ == '__main__':
    main()
