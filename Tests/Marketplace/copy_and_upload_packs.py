import json
import os
import sys
import argparse
import shutil
import logging
import re
from zipfile import ZipFile
from google.cloud.storage import Blob, Bucket

from Tests.scripts.utils.log_util import install_logging
from Tests.Marketplace.marketplace_services import init_storage_client, Pack, PackStatus, GCPConfig, PACKS_FULL_PATH, \
    IGNORED_FILES, PACKS_FOLDER, BucketUploadFlow, load_json, store_successful_and_failed_packs_in_ci_artifacts, \
    get_successful_and_failed_packs
from Tests.Marketplace.upload_packs import extract_packs_artifacts, print_packs_summary, get_packs_summary

LATEST_ZIP_REGEX = re.compile(fr'^{GCPConfig.GCS_PUBLIC_URL}/[\w./-]+/content/packs/([A-Za-z0-9-_.]+/\d+\.\d+\.\d+/'
                              r'[A-Za-z0-9-_.]+\.zip$)')


def get_pack_names(target_packs: str) -> set:
    """
    Retrieves the paths of all relevant packs (that aren't ignored)

    Args:
        target_packs (str): csv packs names or `All` for all available packs in content.

    Returns: The list of paths of the packs

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
    elif target_packs and isinstance(target_packs, str):
        modified_packs = {p.strip() for p in target_packs.split(',') if p not in IGNORED_FILES}
        logging.info(f"Number of selected packs to upload is: {len(modified_packs)}")
        # return only packs from csv list
        return modified_packs
    else:
        logging.error("Not correct usage of flag -p. Please check help section of upload packs script.")
        sys.exit(1)


def copy_index(index_folder_path: str, build_index_blob: Blob, build_index_generation: str, production_bucket: Bucket,
               build_bucket: Bucket):
    """ Copies the build bucket index to the production bucket index path.

    Args:
        index_folder_path (str): index folder full path.
        build_index_blob (Blob): google cloud storage object that represents build index.zip blob.
        build_index_generation (str): downloaded build index generation.
        production_bucket (google.cloud.storage.bucket.Bucket): gcs bucket where index is copied to.
        build_bucket (google.cloud.storage.bucket.Bucket): gcs bucket where index is copied from.

    """
    try:
        build_index_blob.reload()
        build_current_index_generation = build_index_blob.generation

        # disabling caching for prod index blob
        prod_index_storage_path = os.path.join(GCPConfig.STORAGE_BASE_PATH, f"{GCPConfig.INDEX_NAME}.zip")
        prod_index_blob = production_bucket.blob(prod_index_storage_path)
        prod_index_blob.cache_control = "no-cache,max-age=0"

        if build_current_index_generation == build_index_generation:
            copied_index = build_bucket.copy_blob(
                blob=build_index_blob, destination_bucket=production_bucket, new_name=prod_index_storage_path
            )
            if copied_index.exists():
                logging.success(f"Finished uploading {GCPConfig.INDEX_NAME}.zip to storage.")
            else:
                logging.error("Failed copying index from, build index blob does not exists.")
                sys.exit(1)
        else:
            logging.error(f"Failed in uploading {GCPConfig.INDEX_NAME}, mismatch in index file generation")
            logging.error(f"Downloaded build index generation: {build_index_generation}")
            logging.error(f"Current build index generation: {build_current_index_generation}")
            sys.exit(1)
    except Exception as e:
        logging.exception(f"Failed copying {GCPConfig.INDEX_NAME}. Additional Info: {str(e)}")
        sys.exit(1)
    finally:
        shutil.rmtree(index_folder_path)


def upload_core_packs_config(production_bucket: Bucket, build_number: str, extract_destination_path: str,
                             build_bucket: Bucket):
    """Uploads corepacks.json file configuration to bucket. Corepacks file includes core packs for server installation.

     Args:
        production_bucket (google.cloud.storage.bucket.Bucket): gcs bucket where core packs config is uploaded.
        build_number (str): CircleCI build number.
        extract_destination_path (str): Full path of folder to extract the corepacks file
        build_bucket (google.cloud.storage.bucket.Bucket): gcs bucket where core packs config is downloaded from.

    """
    # download the corepacks.json stored in the build bucket to temp dir
    build_corepacks_file_path = os.path.join(GCPConfig.BUILD_BASE_PATH, GCPConfig.CORE_PACK_FILE_NAME)
    build_corepacks_blob = build_bucket.blob(build_corepacks_file_path)

    if not build_corepacks_blob.exists():
        logging.critical(f"{GCPConfig.CORE_PACK_FILE_NAME} is missing in {build_bucket.name} bucket, exiting...")
        sys.exit(1)

    temp_corepacks_file_path = os.path.join(extract_destination_path, GCPConfig.CORE_PACK_FILE_NAME)
    build_corepacks_blob.download_to_filename(temp_corepacks_file_path)
    corepacks_file = load_json(temp_corepacks_file_path)

    # change the storage paths to the prod bucket
    corepacks_list = corepacks_file.get('corePacks', [])
    try:
        corepacks_list = [os.path.join(GCPConfig.GCS_PUBLIC_URL, production_bucket.name, GCPConfig.STORAGE_BASE_PATH,
                                       LATEST_ZIP_REGEX.findall(corepack_path)[0]) for corepack_path in corepacks_list]
    except IndexError:
        corepacks_list_str = '\n'.join(corepacks_list)
        logging.exception(f"GCS paths in build bucket corepacks.json file are not of format: "
                          f"{GCPConfig.GCS_PUBLIC_URL}/<BUCKET_NAME>/.../content/packs/...\n"
                          f"List of build bucket corepacks paths:\n{corepacks_list_str}")
        sys.exit(1)

    # construct core pack data with public gcs urls
    core_packs_data = {
        'corePacks': corepacks_list,
        'buildNumber': build_number
    }

    # upload core pack json file to gcs
    prod_corepacks_file_path = os.path.join(GCPConfig.STORAGE_BASE_PATH, GCPConfig.CORE_PACK_FILE_NAME)
    prod_corepacks_blob = production_bucket.blob(prod_corepacks_file_path)
    prod_corepacks_blob.upload_from_string(json.dumps(core_packs_data, indent=4))

    logging.success(f"Finished uploading {GCPConfig.CORE_PACK_FILE_NAME} to storage.")


def download_and_extract_index(build_bucket: Bucket, extract_destination_path: str):
    """Downloads and extracts production and build indexes zip from cloud storage.

    Args:
        build_bucket (google.cloud.storage.bucket.Bucket): google storage bucket where build index.zip is stored.
        extract_destination_path (str): the full path of extract folder.
    Returns:
        str: extracted build index folder full path.
        Blob: google cloud storage object that represents prod index.zip blob.
        Blob: google cloud storage object that represents build index.zip blob.
        str: downloaded prod index generation.
        str: downloaded build index generation.

    """
    build_index_storage_path = os.path.join(GCPConfig.BUILD_BASE_PATH, f"{GCPConfig.INDEX_NAME}.zip")
    download_build_index_path = os.path.join(extract_destination_path, f"{GCPConfig.INDEX_NAME}.zip")

    build_index_blob = build_bucket.blob(build_index_storage_path)
    build_index_folder_path = os.path.join(extract_destination_path, GCPConfig.INDEX_NAME)

    if not os.path.exists(extract_destination_path):
        os.mkdir(extract_destination_path)

    if not build_index_blob.exists():
        logging.error(f"No build index was found in path: {build_index_storage_path}")
        sys.exit(1)

    build_index_blob.reload()
    build_index_generation = build_index_blob.generation
    build_index_blob.download_to_filename(download_build_index_path, if_generation_match=build_index_generation)

    if os.path.exists(download_build_index_path):
        with ZipFile(download_build_index_path, 'r') as index_zip:
            index_zip.extractall(extract_destination_path)

        if not os.path.exists(build_index_folder_path):
            logging.error(f"Failed creating build {GCPConfig.INDEX_NAME} folder with extracted data.")
            sys.exit(1)

        os.remove(download_build_index_path)
        logging.success(f"Finished downloading and extracting build {GCPConfig.INDEX_NAME} file to "
                        f"{extract_destination_path}")

        return build_index_folder_path, build_index_blob, build_index_generation
    else:
        logging.error(f"Failed to download build {GCPConfig.INDEX_NAME}.zip file from cloud storage.")
        sys.exit(1)


def copy_id_set(production_bucket: Bucket, build_bucket: Bucket):
    """ Copies the id_set.json artifact from the build bucket to the production bucket.

    Args:
        production_bucket (google.cloud.storage.bucket.Bucket): gcs bucket where id_set is copied to.
        build_bucket (google.cloud.storage.bucket.Bucket): gcs bucket where id_set is copied from.
    """

    build_id_set_path = os.path.join(os.path.dirname(GCPConfig.BUILD_BASE_PATH), 'id_set.json')
    build_id_set_blob = build_bucket.blob(build_id_set_path)

    if not build_id_set_blob.exists():
        logging.error(f"id_set.json file does not exists in build bucket in path: {build_id_set_path}")
        sys.exit(1)

    prod_id_set_path = os.path.join(os.path.dirname(GCPConfig.STORAGE_BASE_PATH), 'id_set.json')
    try:
        copied_blob = build_bucket.copy_blob(
            blob=build_id_set_blob, destination_bucket=production_bucket, new_name=prod_id_set_path
        )
        if not copied_blob.exists():
            logging.error(f"Failed to upload id_set.json to {prod_id_set_path}")
            sys.exit(1)
        else:
            logging.success("Finished uploading id_set.json to storage.")
    except Exception as e:
        logging.exception(f"Failed copying ID Set. Additional Info: {str(e)}")
        sys.exit(1)


def verify_copy(successful_packs: list, pc_successful_packs_dict: dict):
    """ Verify that all uploaded packs from Prepare were copied & verify that no packs were mistakenly copied

    Args:
        successful_packs: The packs that were copied successfully
        pc_successful_packs_dict: The pack that were uploaded successfully in Prepare Content

    """
    pc_successful_packs_names = {*pc_successful_packs_dict}
    successful_packs_names = {pack.name for pack in successful_packs}
    not_uploaded = [pack for pack in pc_successful_packs_names if pack not in successful_packs_names]
    mistakenly_uploaded = [pack for pack in successful_packs_names if pack not in pc_successful_packs_names]
    error_str = "Mismatch in Prepare Content successful packs and Upload successful packs\n"
    error_str += f"Packs not copied: {', '.join(not_uploaded)}\n" if not_uploaded else ""
    error_str += f"Packs mistakenly copied: {', '.join(mistakenly_uploaded)}\n" if mistakenly_uploaded else ""
    assert not not_uploaded and not mistakenly_uploaded, error_str


def check_if_need_to_upload(pc_successful_packs_dict: dict, pc_failed_packs_dict: dict):
    """ If the two dicts are empty then no upload was done in Prepare Content step, so we need to skip uploading

    Args:
        pc_successful_packs_dict: The successful packs dict
        pc_failed_packs_dict: The failed packs dict

    """
    if not pc_successful_packs_dict and not pc_failed_packs_dict:
        logging.warning("Production bucket is updated with origin/master.")
        logging.warning("Skipping Upload To Marketplace Storage Step.")
        sys.exit(0)


def options_handler():
    """ Validates and parses script arguments.

    Returns:
        Namespace: Parsed arguments object.

    """
    parser = argparse.ArgumentParser(description="Store packs in cloud storage.")
    # disable-secrets-detection-start
    parser.add_argument('-a', '--artifacts_path', help="The full path of packs artifacts", required=True)
    parser.add_argument('-e', '--extract_path', help="Full path of folder to extract wanted packs", required=True)
    parser.add_argument('-pb', '--production_bucket_name', help="Production bucket name", required=True)
    parser.add_argument('-bb', '--build_bucket_name', help="CircleCI Build bucket name", required=True)
    parser.add_argument('-s', '--service_account',
                        help=("Path to gcloud service account, is for circleCI usage. "
                              "For local development use your personal account and "
                              "authenticate using Google Cloud SDK by running: "
                              "`gcloud auth application-default login` and leave this parameter blank. "
                              "For more information go to: "
                              "https://googleapis.dev/python/google-api-core/latest/auth.html"),
                        required=False)
    parser.add_argument('-p', '--pack_names',
                        help=("Target packs to upload to gcs. Optional values are: `All`"
                              " or csv list of packs "
                              "Default is set to `All`"),
                        required=False, default="All")
    parser.add_argument('-n', '--ci_build_number',
                        help="CircleCi build number (will be used as hash revision at index file)", required=True)
    parser.add_argument('-c', '--circle_branch',
                        help="CircleCi branch of current build", required=True)
    parser.add_argument('-pbp', '--production_base_path', help="Production base path of the directory to upload to.",
                        required=False)
    # disable-secrets-detection-end
    return parser.parse_args()


def main():
    install_logging('Copy_and_Upload_Packs.log')
    options = options_handler()
    packs_artifacts_path = options.artifacts_path
    extract_destination_path = options.extract_path
    production_bucket_name = options.production_bucket_name
    build_bucket_name = options.build_bucket_name
    service_account = options.service_account
    build_number = options.ci_build_number
    circle_branch = options.circle_branch
    production_base_path = options.production_base_path
    target_packs = options.pack_names

    # Google cloud storage client initialized
    storage_client = init_storage_client(service_account)
    production_bucket = storage_client.bucket(production_bucket_name)
    build_bucket = storage_client.bucket(build_bucket_name)

    # Initialize build and prod base paths
    build_bucket_path = os.path.join(GCPConfig.BUILD_PATH_PREFIX, circle_branch, build_number)
    GCPConfig.BUILD_BASE_PATH = os.path.join(build_bucket_path, GCPConfig.STORAGE_BASE_PATH)
    if production_base_path:
        GCPConfig.STORAGE_BASE_PATH = production_base_path

    # Download and extract build index from build and prod buckets
    build_index_folder_path, build_index_blob, build_index_generation = \
        download_and_extract_index(build_bucket, extract_destination_path)

    # Get the successful and failed packs file from Prepare Content step in Create Instances job if there are
    packs_results_file_path = os.path.join(os.path.dirname(packs_artifacts_path), BucketUploadFlow.PACKS_RESULTS_FILE)
    pc_successful_packs_dict, pc_failed_packs_dict = get_successful_and_failed_packs(
        packs_results_file_path, BucketUploadFlow.PREPARE_CONTENT_FOR_TESTING
    )
    logging.debug(f"Successful packs from Prepare Content: {pc_successful_packs_dict}")
    logging.debug(f"Failed packs from Prepare Content: {pc_failed_packs_dict}")

    # Check if needs to upload or not
    check_if_need_to_upload(pc_successful_packs_dict, pc_failed_packs_dict)

    # Detect packs to upload
    pack_names = get_pack_names(target_packs)
    extract_packs_artifacts(packs_artifacts_path, extract_destination_path)
    packs_list = [Pack(pack_name, os.path.join(extract_destination_path, pack_name)) for pack_name in pack_names
                  if os.path.exists(os.path.join(extract_destination_path, pack_name))]

    # Starting iteration over packs
    for pack in packs_list:
        # Indicates whether a pack has failed to upload on Prepare Content step
        task_status, pack_status = pack.is_failed_to_upload(pc_failed_packs_dict)
        if task_status:
            pack.status = pack_status
            pack.cleanup()
            continue

        task_status, user_metadata = pack.load_user_metadata()
        if not task_status:
            pack.status = PackStatus.FAILED_LOADING_USER_METADATA.name
            pack.cleanup()
            continue

        task_status, _ = pack.upload_integration_images(production_bucket)
        if not task_status:
            pack.status = PackStatus.FAILED_IMAGES_UPLOAD.name
            pack.cleanup()
            continue

        task_status, _ = pack.upload_author_image(production_bucket)
        if not task_status:
            pack.status = PackStatus.FAILED_AUTHOR_IMAGE_UPLOAD.name
            pack.cleanup()
            continue

        task_status = pack.remove_unwanted_files()
        if not task_status:
            pack.status = PackStatus.FAILED_REMOVING_PACK_SKIPPED_FOLDERS
            pack.cleanup()
            continue

        # Create a local copy of the pack's index changelog
        task_status = pack.create_local_changelog(build_index_folder_path)
        if not task_status:
            pack.status = PackStatus.FAILED_RELEASE_NOTES.name
            pack.cleanup()
            continue

        task_status, skipped_pack_uploading = pack.copy_and_upload_to_storage(production_bucket, build_bucket,
                                                                              pack.latest_version,
                                                                              pc_successful_packs_dict)
        if skipped_pack_uploading:
            pack.status = PackStatus.PACK_ALREADY_EXISTS.name
            pack.cleanup()
            continue

        if not task_status:
            pack.status = PackStatus.FAILED_UPLOADING_PACK.name
            pack.cleanup()
            continue

        pack.status = PackStatus.SUCCESS.name

    # upload core packs json to bucket
    upload_core_packs_config(production_bucket, build_number, extract_destination_path, build_bucket)

    # finished iteration over content packs
    copy_index(build_index_folder_path, build_index_blob, build_index_generation, production_bucket,
               build_bucket)

    # upload id_set.json to bucket
    copy_id_set(production_bucket, build_bucket)

    # get the lists of packs divided by their status
    successful_packs, skipped_packs, failed_packs = get_packs_summary(packs_list)

    # Store successful and failed packs list in CircleCI artifacts
    store_successful_and_failed_packs_in_ci_artifacts(
        packs_results_file_path, BucketUploadFlow.UPLOAD_PACKS_TO_MARKETPLACE_STORAGE, successful_packs, failed_packs
    )

    # verify that the successful from Prepare content and are the ones that were copied
    verify_copy(successful_packs, pc_successful_packs_dict)

    # summary of packs status
    print_packs_summary(successful_packs, skipped_packs, failed_packs)


if __name__ == '__main__':
    main()
