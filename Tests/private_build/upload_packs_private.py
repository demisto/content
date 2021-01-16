import json
import os
import argparse
import shutil
import uuid
import glob
import logging
from typing import Any, Tuple, Union
from Tests.Marketplace.marketplace_services import init_storage_client, init_bigquery_client, Pack, PackStatus, \
    GCPConfig, CONTENT_ROOT_PATH, get_packs_statistics_dataframe, load_json, get_content_git_client, \
    get_recent_commits_data
from Tests.Marketplace.upload_packs import get_packs_names, extract_packs_artifacts, download_and_extract_index,\
    update_index_folder, clean_non_existing_packs, upload_index_to_storage, upload_core_packs_config,\
    upload_id_set, check_if_index_is_updated, print_packs_summary, get_packs_summary
from demisto_sdk.commands.common.tools import str2bool

from Tests.scripts.utils.log_util import install_logging


def is_pack_paid_or_premium(path_to_pack_metadata_in_index: str) -> bool:
    """
    Determines if a pack is a paid or premium pack.

    :param path_to_pack_metadata_in_index: The path to the pack_metadata.json in the index for the
    tested pack.
    :return: Boolean response if pack is paid or premium.
    """
    with open(path_to_pack_metadata_in_index, 'r') as pack_metadata_file:
        pack_metadata = json.load(pack_metadata_file)

    is_pack_paid = 'price' in pack_metadata and pack_metadata['price'] > 0
    is_pack_premium = 'premium' in pack_metadata and pack_metadata['premium']
    return is_pack_paid or is_pack_premium


def delete_public_packs_from_index(index_folder_path: str):
    """
    Removes all packs which are not private from the index.

    :param index_folder_path: Path to the index folder.
    :return: None
    """
    packs_in_index = [pack_dir.name for pack_dir in os.scandir(index_folder_path) if pack_dir.is_dir()]
    for pack_name in packs_in_index:
        path_to_pack = os.path.join(index_folder_path, pack_name)
        path_to_pack_metadata = os.path.join(path_to_pack, 'metadata.json')
        if not is_pack_paid_or_premium(path_to_pack_metadata):
            shutil.rmtree(path_to_pack, ignore_errors=True)


def update_private_index(private_index_path: str, unified_index_path: str):
    """
    Updates the private index by copying the unified index to the private index.

    :param private_index_path: Path to the private index.
    :param unified_index_path: Path to the unified index.
    :return:
    """
    private_packs_names = [d for d in os.listdir(private_index_path) if
                           os.path.isdir(os.path.join(private_index_path, d))]

    for private_pack_name in private_packs_names:
        path_to_pack_on_private_index = os.path.join(unified_index_path, private_pack_name)
        path_to_pack_on_unified_index = os.path.join(unified_index_path, private_pack_name)
        shutil.copy(path_to_pack_on_unified_index, path_to_pack_on_private_index)


def get_private_packs(private_index_path: str, pack_names: set = set(),
                      extract_destination_path: str = '') -> list:
    """
    Gets a list of private packs.

    :param private_index_path: Path to where the private index is located.
    :param pack_names: Collection of pack names.
    :param extract_destination_path: Path to where the files should be extracted to.
    :return: List of dicts containing pack metadata information.
    """
    try:
        metadata_files = glob.glob(f"{private_index_path}/**/metadata.json")
    except Exception:
        logging.exception(f'Could not find metadata files in {private_index_path}.')
        return []

    if not metadata_files:
        logging.warning(f'No metadata files found in [{private_index_path}]')

    private_packs = []
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
                    'vendorId': metadata.get('vendorId'),
                    'vendorName': metadata.get('vendorName'),
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


def update_index_with_priced_packs(private_storage_bucket: Any, extract_destination_path: str,
                                   index_folder_path: str, pack_names: set, is_private_build: bool) \
        -> Tuple[Union[list, list], str, Any]:
    """ Updates index with priced packs and returns list of priced packs data.

    Args:
        private_storage_bucket (google.cloud.storage.bucket.Bucket): google storage private bucket.
        extract_destination_path (str): full path to extract directory.
        index_folder_path (str): downloaded index folder directory path.
        pack_names (set): Collection of pack names.
        is_private_build (bool): Indicates if the build is private.

    Returns:
        list: priced packs from private bucket.

    """
    private_index_path = ""
    private_packs = []

    try:
        (private_index_path, private_index_blob, _) = \
            download_and_extract_index(private_storage_bucket,
                                       os.path.join(extract_destination_path,
                                                    'private'))
        logging.info("get_private_packs")
        private_packs = get_private_packs(private_index_path, pack_names,
                                          extract_destination_path)
        logging.info("add_private_packs_to_index")
        add_private_packs_to_index(index_folder_path, private_index_path)
        logging.info("Finished updating index with priced packs")
    except Exception:
        logging.exception('Could not add private packs to the index.')
    finally:
        shutil.rmtree(os.path.dirname(private_index_path), ignore_errors=True)
        return private_packs, private_index_path, private_index_blob


def should_upload_core_packs(storage_bucket_name: str) -> bool:
    """
    Indicates if the core packs should be updated.
    :param storage_bucket_name: Name of the storage bucket. Typically either marketplace-dist, or
                                marketplace-private-dist.
    :return: Boolean indicating if the core packs need to be updated.
    """
    is_private_storage_bucket = (storage_bucket_name != GCPConfig.PRODUCTION_PRIVATE_BUCKET)
    is_private_ci_bucket = (storage_bucket_name != GCPConfig.CI_PRIVATE_BUCKET)
    return not (is_private_storage_bucket or is_private_ci_bucket)


def create_and_upload_marketplace_pack(upload_config: Any, pack: Any, storage_bucket: Any, index_folder_path: str,
                                       packs_dependencies_mapping: dict, private_bucket_name: str,
                                       private_storage_bucket: bool = None,
                                       content_repo: bool = None, current_commit_hash: str = '',
                                       remote_previous_commit_hash: str = '', packs_statistic_df: Any = None)\
        -> Any:
    """
    The main logic flow for the create and upload process. Acts as a decision tree while consistently
    checking the status of the progress being made.

    :param upload_config: Configuration for the script as handled by the Option Handler.
    :param pack: Pack object.
    :param storage_bucket: Bucket the changes are being uploaded to.
    :param index_folder_path: Path to the index folder.
    :param packs_dependencies_mapping: Used by format_metadata to add dependencies to the metadata file.
    :param private_storage_bucket: Bucket where the private packs are uploaded.
    :param content_repo: The main content repository. demisto/content
    :param current_commit_hash: Current commit hash for the run. Used in the pack metadata file.
    :param remote_previous_commit_hash: Previous commit hash. Used for comparison.
    :param packs_statistic_df: Dataframe object containing current pack analytics.
    :return: Updated pack.status value.
    """
    build_number = upload_config.ci_build_number
    remove_test_playbooks = upload_config.remove_test_playbooks
    signature_key = upload_config.key_string
    extract_destination_path = upload_config.extract_path
    override_all_packs = upload_config.override_all_packs
    enc_key = upload_config.encryption_key
    is_private_build = upload_config.is_private
    packs_artifacts_dir = upload_config.artifacts_path
    private_artifacts_dir = upload_config.private_artifacts

    task_status, user_metadata = pack.load_user_metadata()
    if not task_status:
        pack.status = PackStatus.FAILED_LOADING_USER_METADATA.name
        pack.cleanup()
        return

    task_status, pack_content_items = pack.collect_content_items()
    if not task_status:
        pack.status = PackStatus.FAILED_COLLECT_ITEMS.name
        pack.cleanup()
        return

    task_status, integration_images = pack.upload_integration_images(storage_bucket)
    if not task_status:
        pack.status = PackStatus.FAILED_IMAGES_UPLOAD.name
        pack.cleanup()
        return

    task_status, author_image = pack.upload_author_image(storage_bucket)
    if not task_status:
        pack.status = PackStatus.FAILED_AUTHOR_IMAGE_UPLOAD.name
        pack.cleanup()
        return

    task_status = pack.format_metadata(user_metadata=user_metadata, pack_content_items=pack_content_items,
                                       integration_images=integration_images, author_image=author_image,
                                       index_folder_path=index_folder_path,
                                       packs_dependencies_mapping=packs_dependencies_mapping,
                                       build_number=build_number, commit_hash=current_commit_hash,
                                       packs_statistic_df=packs_statistic_df)

    if not task_status:
        pack.status = PackStatus.FAILED_METADATA_PARSING.name
        pack.cleanup()
        return

    task_status, not_updated_build = pack.prepare_release_notes(index_folder_path, build_number)
    if not task_status:
        pack.status = PackStatus.FAILED_RELEASE_NOTES.name
        pack.cleanup()
        return

    if not_updated_build:
        pack.status = PackStatus.PACK_IS_NOT_UPDATED_IN_RUNNING_BUILD.name
        pack.cleanup()
        return

    task_status = pack.remove_unwanted_files(remove_test_playbooks)
    if not task_status:
        pack.status = PackStatus.FAILED_REMOVING_PACK_SKIPPED_FOLDERS
        pack.cleanup()
        return

    task_status = pack.sign_pack(signature_key)
    if not task_status:
        pack.status = PackStatus.FAILED_SIGNING_PACKS.name
        pack.cleanup()
        return

    task_status, zip_pack_path = pack.zip_pack(extract_destination_path, pack._pack_name, enc_key, private_artifacts_dir)

    if not task_status:
        pack.status = PackStatus.FAILED_ZIPPING_PACK_ARTIFACTS.name
        pack.cleanup()
        return

    if not is_private_build:
        task_status, pack_was_modified = pack.detect_modified(content_repo, index_folder_path, current_commit_hash,
                                                              remote_previous_commit_hash)
        if not task_status:
            pack.status = PackStatus.FAILED_DETECTING_MODIFIED_FILES.name
            pack.cleanup()
            return
    else:
        pack_was_modified = False

    task_status = pack.is_pack_encrypted(zip_pack_path, enc_key)
    if not task_status:
        pack.status = PackStatus.FAILED_DECRYPT_PACK.name
        pack.cleanup()
        return

    bucket_for_uploading = private_storage_bucket if private_storage_bucket else storage_bucket
    (task_status, skipped_pack_uploading, full_pack_path) = \
        pack.upload_to_storage(zip_pack_path, pack.latest_version,
                               bucket_for_uploading, override_all_packs
                               or pack_was_modified, pack_artifacts_path=packs_artifacts_dir,
                               private_content=True)
    if full_pack_path is not None:
        bucket_path = f'https://console.cloud.google.com/storage/browser/{private_bucket_name}/'
        bucket_url = bucket_path + full_pack_path
    else:
        bucket_url = 'Pack was not uploaded.'
    pack.bucket_url = bucket_url

    if not task_status:
        pack.status = PackStatus.FAILED_UPLOADING_PACK.name
        pack.cleanup()
        return

    task_status, exists_in_index = pack.check_if_exists_in_index(index_folder_path)
    if not task_status:
        pack.status = PackStatus.FAILED_SEARCHING_PACK_IN_INDEX.name
        pack.cleanup()
        return

    # in case that pack already exist at cloud storage path and in index, skipped further steps
    if skipped_pack_uploading and exists_in_index:
        pack.status = PackStatus.PACK_ALREADY_EXISTS.name
        pack.cleanup()
        return

    task_status = pack.prepare_for_index_upload()
    if not task_status:
        pack.status = PackStatus.FAILED_PREPARING_INDEX_FOLDER.name
        pack.cleanup()
        return

    task_status = update_index_folder(index_folder_path=index_folder_path, pack_name=pack.name,
                                      pack_path=pack.path, pack_version=pack.latest_version,
                                      hidden_pack=pack.hidden)
    if not task_status:
        pack.status = PackStatus.FAILED_UPDATING_INDEX_FOLDER.name
        pack.cleanup()
        return

    pack.status = PackStatus.SUCCESS.name


def option_handler():
    """Validates and parses script arguments.

    Returns:
        Namespace: Parsed arguments object.

    """
    parser = argparse.ArgumentParser(description="Store packs in cloud storage.")
    # disable-secrets-detection-start
    parser.add_argument('-a', '--artifacts_path', help="The full path of packs artifacts", required=True)
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
    parser.add_argument('-i', '--id_set_path', help="The full path of id_set.json", required=False)
    parser.add_argument('-d', '--pack_dependencies', help="Full path to pack dependencies json file.", required=False)
    parser.add_argument('-p', '--pack_names',
                        help=("Target packs to upload to gcs. Optional values are: `All`, "
                              "`Modified` or csv list of packs "
                              "Default is set to `All`"),
                        required=False, default="All")
    parser.add_argument('-n', '--ci_build_number',
                        help="CircleCi build number (will be used as hash revision at index file)", required=False,
                        default=str(uuid.uuid4()))
    parser.add_argument('-bn', '--branch_name', help="Name of the branch CI is being ran on.", default='unknown')
    parser.add_argument('-o', '--override_all_packs', help="Override all existing packs in cloud storage",
                        default=False, action='store_true', required=False)
    parser.add_argument('-k', '--key_string', help="Base64 encoded signature key used for signing packs.",
                        required=False)
    parser.add_argument('-pb', '--private_bucket_name', help="Private storage bucket name", required=False)
    parser.add_argument('-sb', '--storage_base_path', help="Storage base path of the directory to upload to.",
                        required=False)
    parser.add_argument('-rt', '--remove_test_playbooks', type=str2bool,
                        help='Should remove test playbooks from content packs or not.', default=True)
    parser.add_argument('-ek', '--encryption_key', type=str,
                        help='The encryption key for the pack, if it should be encrypted.', default='')
    parser.add_argument('-pr', '--is_private', type=str2bool,
                        help='The encryption key for the pack, if it should be encrypted.', default=False)
    parser.add_argument('-pa', '--private_artifacts', type=str,
                        help='The name of the pack in which the private artifacts should be saved',
                        default='private_artifacts')
    # disable-secrets-detection-end
    return parser.parse_args()


def prepare_test_directories(pack_artifacts_path):
    """
    :param pack_artifacts_path: Path the the artifacts packs directory.
    Ensures the artifacts directory is present for the private build
    :return: None
    """

    packs_dir = '/home/runner/work/content-private/content-private/content/artifacts/packs'
    zip_path = '/home/runner/work/content-private/content-private/content/temp-dir'
    if not os.path.exists(packs_dir):
        logging.info("Packs dir not found. Creating.")
        os.mkdir(packs_dir)
    if not os.path.exists(zip_path):
        logging.info("Temp dir not found. Creating.")
        os.mkdir(zip_path)


def main():
    install_logging('upload_packs_private.log')
    upload_config = option_handler()
    packs_artifacts_path = upload_config.artifacts_path
    extract_destination_path = upload_config.extract_path
    storage_bucket_name = upload_config.bucket_name
    private_bucket_name = upload_config.private_bucket_name
    service_account = upload_config.service_account
    target_packs = upload_config.pack_names
    build_number = upload_config.ci_build_number
    id_set_path = upload_config.id_set_path
    packs_dependencies_mapping = load_json(upload_config.pack_dependencies) if upload_config.pack_dependencies else {}
    storage_base_path = upload_config.storage_base_path
    is_private_build = upload_config.is_private

    print(f"Packs artifact path is: {packs_artifacts_path}")

    prepare_test_directories(packs_artifacts_path)

    # google cloud storage client initialized
    storage_client = init_storage_client(service_account)
    storage_bucket = storage_client.bucket(storage_bucket_name)
    private_storage_bucket = storage_client.bucket(private_bucket_name)
    default_storage_bucket = private_storage_bucket if is_private_build else storage_bucket

    # download and extract index from public bucket
    index_folder_path, index_blob, index_generation = download_and_extract_index(storage_bucket,
                                                                                 extract_destination_path)

    # content repo client initialized
    if not is_private_build:
        content_repo = get_content_git_client(CONTENT_ROOT_PATH)
        current_commit_hash, remote_previous_commit_hash = get_recent_commits_data(content_repo, index_folder_path,
                                                                                   is_bucket_upload_flow=False,
                                                                                   is_private_build=True)
    else:
        current_commit_hash, remote_previous_commit_hash = "", ""
        content_repo = None

    if storage_base_path:
        GCPConfig.STORAGE_BASE_PATH = storage_base_path

    # detect packs to upload
    pack_names = get_packs_names(target_packs)
    extract_packs_artifacts(packs_artifacts_path, extract_destination_path)
    packs_list = [Pack(pack_name, os.path.join(extract_destination_path, pack_name)) for pack_name in pack_names
                  if os.path.exists(os.path.join(extract_destination_path, pack_name))]

    if not is_private_build:
        check_if_index_is_updated(index_folder_path, content_repo, current_commit_hash, remote_previous_commit_hash,
                                  storage_bucket)

    if private_bucket_name:  # Add private packs to the index
        private_packs, private_index_path, private_index_blob = update_index_with_priced_packs(private_storage_bucket,
                                                                                               extract_destination_path,
                                                                                               index_folder_path,
                                                                                               pack_names,
                                                                                               is_private_build)
    else:  # skipping private packs
        logging.info("Skipping index update of priced packs")
        private_packs = []

    # google cloud bigquery client initialized
    packs_statistic_df = None
    if not is_private_build:
        bq_client = init_bigquery_client(service_account)
        packs_statistic_df = get_packs_statistics_dataframe(bq_client)

    # clean index and gcs from non existing or invalid packs
    clean_non_existing_packs(index_folder_path, private_packs, default_storage_bucket)
    # starting iteration over packs
    for pack in packs_list:
        create_and_upload_marketplace_pack(upload_config, pack, storage_bucket, index_folder_path,
                                           packs_dependencies_mapping, private_bucket_name,
                                           private_storage_bucket=private_storage_bucket, content_repo=content_repo,
                                           current_commit_hash=current_commit_hash,
                                           remote_previous_commit_hash=remote_previous_commit_hash,
                                           packs_statistic_df=packs_statistic_df)
    # upload core packs json to bucket

    if should_upload_core_packs(storage_bucket_name):
        upload_core_packs_config(default_storage_bucket, build_number, index_folder_path)
    # finished iteration over content packs
    if is_private_build:
        delete_public_packs_from_index(index_folder_path)
        upload_index_to_storage(index_folder_path, extract_destination_path, private_index_blob, build_number,
                                private_packs,
                                current_commit_hash, index_generation, is_private_build)

    else:
        upload_index_to_storage(index_folder_path, extract_destination_path, index_blob, build_number, private_packs,
                                current_commit_hash, index_generation)

    # upload id_set.json to bucket
    upload_id_set(default_storage_bucket, id_set_path)

    # get the lists of packs divided by their status
    successful_packs, skipped_packs, failed_packs = get_packs_summary(packs_list)

    # summary of packs status
    print_packs_summary(successful_packs, skipped_packs, failed_packs)


if __name__ == '__main__':
    main()
