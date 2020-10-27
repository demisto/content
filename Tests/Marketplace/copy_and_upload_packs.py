import json
import os
import sys
import argparse
import shutil
import logging
from zipfile import ZipFile
from datetime import datetime

from Tests.scripts.utils.log_util import install_logging
from Tests.Marketplace.marketplace_services import init_storage_client, Pack, PackStatus, GCPConfig, PACKS_FULL_PATH, \
    IGNORED_FILES, Metadata
from Tests.Marketplace.upload_packs import extract_packs_artifacts, print_packs_summary, upload_id_set, load_json


def get_pack_names():
    """
    Retrieves the paths of all relevant packs (that aren't ignored)

    Returns: The list of paths of the packs

    """
    all_packs: set = set()
    if os.path.exists(PACKS_FULL_PATH):
        all_packs = {p for p in os.listdir(PACKS_FULL_PATH) if p not in IGNORED_FILES}
        logging.info(f"Number of selected packs to upload is: {len(all_packs)}")
    return all_packs


def upload_index_to_storage(index_folder_path, extract_destination_path, build_index_blob, prod_index_blob,
                            build_index_generation, prod_index_generation):
    """Upload updated index zip to cloud storage.

    Args:
        index_folder_path (str): index folder full path.
        extract_destination_path (str): extract folder full path.
        build_index_blob (Blob): google cloud storage object that represents build index.zip blob.
        prod_index_blob (Blob): google cloud storage object that represents prod index.zip blob.
        build_index_generation (str): downloaded build index generation.
        prod_index_generation (str): downloaded prod index generation.

    """
    temp_index_path = os.path.join(index_folder_path, f"{GCPConfig.INDEX_NAME}.json")
    index = load_json(temp_index_path)
    index['modified'] = datetime.utcnow().strftime(Metadata.DATE_FORMAT)
    with open(temp_index_path, "w+") as index_file:
        json.dump(index, index_file, indent=4)

    index_zip_name = os.path.basename(index_folder_path)
    index_zip_path = shutil.make_archive(base_name=index_folder_path, format="zip",
                                         root_dir=extract_destination_path, base_dir=index_zip_name)
    try:
        build_index_blob.reload()
        build_current_index_generation = build_index_blob.generation
        prod_index_blob.reload()
        prod_current_index_generation = prod_index_blob.generation

        prod_index_blob.cache_control = "no-cache,max-age=0"  # disabling caching for index blob

        if build_current_index_generation == build_index_generation and \
                prod_current_index_generation == prod_index_generation:
            prod_index_blob.upload_from_filename(index_zip_path)
            logging.success(f"Finished uploading {GCPConfig.INDEX_NAME}.zip to storage.")
        else:
            logging.error(f"Failed in uploading {GCPConfig.INDEX_NAME}, mismatch in index file generation")
            logging.error(f"Downloaded build index generation: {build_index_generation}")
            logging.error(f"Current build index generation: {build_current_index_generation}")
            logging.error(f"Downloaded prod index generation: {prod_index_generation}")
            logging.error(f"Current prod index generation: {prod_current_index_generation}")
            sys.exit(1)
    except Exception:
        logging.exception(f"Failed in uploading {GCPConfig.INDEX_NAME}")
        sys.exit(1)
    finally:
        shutil.rmtree(index_folder_path)


def upload_core_packs_config(production_bucket, build_number, extract_destination_path, build_bucket):
    """Uploads corepacks.json file configuration to bucket. Corepacks file includes core packs for server installation.

     Args:
        production_bucket (google.cloud.storage.bucket.Bucket): gcs bucket where core packs config is uploaded.
        build_number (str): CircleCI build number.
        extract_destination_path (str): Full path of folder to extract the corepacks file
        build_bucket (google.cloud.storage.bucket.Bucket): gcs bucket where core packs config is downloaded from.

    """
    # download the corepacks.json stored in the build bucket to temp dir
    build_corepacks_file_path = os.path.join(GCPConfig.BUILD_BASE_PATH, GCPConfig.CORE_PACK_FILE_NAME)
    temp_corepacks_file_path = os.path.join(extract_destination_path, GCPConfig.CORE_PACK_FILE_NAME)
    build_corepacks_blob = build_bucket.blob(build_corepacks_file_path)

    if not build_corepacks_blob.exists():
        logging.critical(f"{GCPConfig.CORE_PACK_FILE_NAME} is missing in {build_bucket.name} bucket, exiting...")
        sys.exit(1)

    build_corepacks_blob.download_to_filename(temp_corepacks_file_path)
    corepacks_file = load_json(temp_corepacks_file_path)

    # change the storage paths to the prod bucket
    corepacks_list = corepacks_file.get('corePacks', [])
    corepacks_list = [os.path.join(GCPConfig.GCS_PUBLIC_URL, production_bucket.name, GCPConfig.STORAGE_BASE_PATH,
                                   corepack_path.split('content/packs/')[1]) for corepack_path in corepacks_list]

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


def is_valid_pack(extract_destination_path, pack_name, production_bucket, build_bucket):
    """ Indicates whether a pack should be in the loop of uploads or not

    Args:
        extract_destination_path (str): Full path of folder to extract wanted packs
        pack_name (str): The pack name
        production_bucket (google.cloud.storage.bucket.Bucket): The production bucket
        build_bucket (google.cloud.storage.bucket.Bucket): The build bucket

    Returns:
        bool: True if the pack should be considered to upload or False otherwise

    """
    is_in_artifacts = os.path.exists(os.path.join(extract_destination_path, pack_name))
    prod_pack_names = [f.name for f in production_bucket.list_blobs(prefix=GCPConfig.STORAGE_BASE_PATH)]
    build_pack_names = [f.name for f in build_bucket.list_blobs(prefix=GCPConfig.BUILD_BASE_PATH)]
    # if pack is in prod bucket and not in build bucket it should be deleted because upload packs
    # on prepare content step in create instances job has deleted it
    is_in_prod_but_not_in_build = pack_name in prod_pack_names and pack_name not in build_pack_names
    return is_in_artifacts and not is_in_prod_but_not_in_build


def download_and_extract_index(production_bucket, build_bucket, extract_destination_path):
    """Downloads and extracts production and build indexes zip from cloud storage.

    Args:
        production_bucket (google.cloud.storage.bucket.Bucket): google storage bucket where prod index.zip is stored.
        build_bucket (google.cloud.storage.bucket.Bucket): google storage bucket where build index.zip is stored.
        extract_destination_path (str): the full path of extract folder.
    Returns:
        str: extracted build index folder full path.
        Blob: google cloud storage object that represents prod index.zip blob.
        Blob: google cloud storage object that represents build index.zip blob.
        str: downloaded prod index generation.
        str: downloaded build index generation.

    """
    prod_index_storage_path = os.path.join(GCPConfig.STORAGE_BASE_PATH, f"{GCPConfig.INDEX_NAME}.zip")
    build_index_storage_path = os.path.join(GCPConfig.BUILD_BASE_PATH, f"{GCPConfig.INDEX_NAME}.zip")
    download_build_index_path = os.path.join(extract_destination_path, f"{GCPConfig.INDEX_NAME}.zip")

    build_index_blob = build_bucket.blob(build_index_storage_path)
    prod_index_blob = production_bucket.blob(prod_index_storage_path)
    build_index_folder_path = os.path.join(extract_destination_path, GCPConfig.INDEX_NAME)
    # TODO: understand if we need this or no
    build_index_generation = 0  # Setting to 0 makes the operation succeed only if there are no live versions of blob

    if not os.path.exists(extract_destination_path):
        os.mkdir(extract_destination_path)

    if not build_index_blob.exists():
        logging.critical(f"No build index was found in path: {build_index_storage_path}")
        sys.exit(1)

    if not prod_index_blob.exists():
        logging.critical(f"No prod index was found in path: {prod_index_storage_path}")
        sys.exit(1)

    build_index_blob.reload()
    build_index_generation = build_index_blob.generation
    build_index_blob.download_to_filename(download_build_index_path, if_generation_match=build_index_generation)

    prod_index_blob.reload()
    prod_index_generation = prod_index_blob.generation

    if os.path.exists(download_build_index_path):
        with ZipFile(download_build_index_path, 'r') as index_zip:
            index_zip.extractall(extract_destination_path)

        if not os.path.exists(build_index_folder_path):
            logging.critical(f"Failed creating build {GCPConfig.INDEX_NAME} folder with extracted data.")
            sys.exit(1)

        os.remove(download_build_index_path)
        logging.info(f"Finished downloading and extracting build {GCPConfig.INDEX_NAME} file to "
                     f"{extract_destination_path}")

        return build_index_folder_path, prod_index_blob, build_index_blob, prod_index_generation, build_index_generation
    else:
        logging.critical(f"Failed to download build {GCPConfig.INDEX_NAME}.zip file from cloud storage.")
        sys.exit(1)


def options_handler():
    """Validates and parses script arguments.

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
    parser.add_argument('-i', '--id_set_path', help="The full path of id_set.json", required=False)
    parser.add_argument('-n', '--ci_build_number',
                        help="CircleCi build number (will be used as hash revision at index file)", required=True)
    parser.add_argument('-c', '--circle_branch',
                        help="CircleCi branch of current build", required=True)
    parser.add_argument('-o', '--override_all_packs', help="Override all existing packs in cloud storage",
                        default=False, action='store_true', required=False)
    parser.add_argument('-pbp', '--production_base_path', help="Production base path of the directory to upload to.",
                        required=False)
    # disable-secrets-detection-end
    return parser.parse_args()


def main():
    install_logging('Prepare Content Packs For Testing.log')
    options = options_handler()
    packs_artifacts_path = options.artifacts_path
    extract_destination_path = options.extract_path
    production_bucket_name = options.production_bucket_name
    build_bucket_name = options.build_bucket_name
    service_account = options.service_account
    build_number = options.ci_build_number
    circle_branch = options.circle_branch
    override_all_packs = options.override_all_packs
    id_set_path = options.id_set_path
    production_base_path = options.production_base_path

    # google cloud storage client initialized
    storage_client = init_storage_client(service_account)
    production_bucket = storage_client.bucket(production_bucket_name)
    build_bucket = storage_client.bucket(build_bucket_name)

    # initialize base paths
    if production_base_path:
        GCPConfig.STORAGE_BASE_PATH = production_base_path
    build_bucket_path = f'{GCPConfig.BUILD_BASE_PATH}/{circle_branch}/{build_number}/'
    GCPConfig.BUILD_BASE_PATH = f'{build_bucket_path}/{GCPConfig.STORAGE_BASE_PATH}'

    # TODO: for prepare content step, think what to do if a pack was failing to upload
    # TODO: for upload packs step, think what to do if a pack was failing to upload
    # TODO: what if no commit was found, for example: there was a squash of several master commits?
    # TODO: refactor prepare content step to be the same as upload step
    # TODO: refactor force upload

    # download and extract build and prod index from build and prod buckets
    build_index_folder_path, prod_index_blob, build_index_blob, prod_index_generation, build_index_generation = \
        download_and_extract_index(production_bucket, build_bucket, extract_destination_path)

    # detect packs to upload
    pack_names = get_pack_names()
    extract_packs_artifacts(packs_artifacts_path, extract_destination_path)
    packs_list = [Pack(pack_name, os.path.join(extract_destination_path, pack_name)) for pack_name in pack_names
                  if is_valid_pack(extract_destination_path, pack_name, production_bucket, build_bucket)]

    # starting iteration over packs
    for pack in packs_list:
        task_status = pack.copy_and_upload_integration_images(production_bucket, build_bucket)
        if not task_status:
            pack.status = PackStatus.FAILED_IMAGES_UPLOAD.name
            pack.cleanup()
            continue

        task_status = pack.copy_and_upload_author_image(production_bucket, build_bucket)
        if not task_status:
            pack.status = PackStatus.FAILED_AUTHOR_IMAGE_UPLOAD.name
            pack.cleanup()
            continue

        task_status, skipped_pack_uploading = pack.copy_and_upload_to_storage(production_bucket, build_bucket,
                                                                              override_all_packs)
        if skipped_pack_uploading:
            pack.status = PackStatus.PACK_ALREADY_EXISTS.name

        if not task_status:
            pack.status = PackStatus.FAILED_UPLOADING_PACK.name
            pack.cleanup()
            continue

        pack.status = PackStatus.SUCCESS.name

    # upload core packs json to bucket
    upload_core_packs_config(production_bucket, build_number, extract_destination_path, build_bucket)

    # finished iteration over content packs
    upload_index_to_storage(build_index_folder_path, extract_destination_path, build_index_blob, prod_index_blob,
                            build_index_generation, prod_index_generation)

    # upload id_set.json to bucket
    upload_id_set(production_bucket, id_set_path)

    # summary of packs status
    print_packs_summary(packs_list, comment_on_pr=False, include_bucket_url=False)


if __name__ == '__main__':
    main()
