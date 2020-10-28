import json
import os
import sys
import argparse
import shutil
import uuid
import prettytable
import glob
import git
import requests
from datetime import datetime
from zipfile import ZipFile
import logging

from Tests.scripts.utils.log_util import install_logging
from Tests.Marketplace.marketplace_services import init_storage_client, Pack, PackStatus, \
    GCPConfig, PACKS_FULL_PATH, IGNORED_FILES, PACKS_FOLDER, IGNORED_PATHS, Metadata, CONTENT_ROOT_PATH
from Tests.Marketplace.upload_packs import download_and_extract_index, extract_packs_artifacts, update_index_folder, \
    add_pr_comment, upload_id_set
from demisto_sdk.commands.common.tools import run_command, str2bool


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


def upload_index_to_storage(index_folder_path, extract_destination_path, index_blob, build_number, private_packs,
                            current_commit_hash, index_generation):
    """Upload updated index zip to cloud storage.

    Args:
        index_folder_path (str): index folder full path.
        extract_destination_path (str): extract folder full path.
        index_blob (Blob): google cloud storage object that represents index.zip blob.
        build_number (str): circleCI build number, used as an index revision.
        private_packs (list): List of private packs and their price.
        current_commit_hash (str): last commit hash of head.
        index_generation (str): downloaded index generation.

    """
    with open(os.path.join(index_folder_path, f"{GCPConfig.INDEX_NAME}.json"), "w+") as index_file:
        index = {
            'revision': build_number,
            'modified': datetime.utcnow().strftime(Metadata.DATE_FORMAT),
            'packs': private_packs,
            'commit': current_commit_hash
        }
        json.dump(index, index_file, indent=4)

    index_zip_name = os.path.basename(index_folder_path)
    index_zip_path = shutil.make_archive(base_name=index_folder_path, format="zip",
                                         root_dir=extract_destination_path, base_dir=index_zip_name)
    try:
        index_blob.reload()
        current_index_generation = index_blob.generation
        index_blob.cache_control = "no-cache,max-age=0"  # disabling caching for index blob

        if current_index_generation == index_generation:
            index_blob.upload_from_filename(index_zip_path)
            logging.success(f"Finished uploading {GCPConfig.INDEX_NAME}.zip to storage.")
        else:
            logging.error(f"Failed in uploading {GCPConfig.INDEX_NAME}, mismatch in index file generation")
            logging.error(f"Downloaded index generation: {index_generation}")
            logging.error(f"Current index generation: {current_index_generation}")
            sys.exit(0)
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


def _build_summary_table(packs_input_list, include_pack_status=False):
    """Build summary table from pack list

    Args:
        packs_input_list (list): list of Packs

    Returns:
        PrettyTable: table with upload result of packs.

    """
    table_fields = ["Index", "Pack ID", "Pack Display Name", "Latest Version", "Status",
                    "Pack Bucket URL"] if include_pack_status \
        else ["Index", "Pack ID", "Pack Display Name", "Latest Version", "Pack Bucket URL"]
    table = prettytable.PrettyTable()
    table.field_names = table_fields

    for index, pack in enumerate(packs_input_list, start=1):
        pack_status_message = PackStatus[pack.status].value
        row = [index, pack.name, pack.display_name, pack.latest_version, pack_status_message,
               pack.bucket_url] if include_pack_status \
            else [index, pack.name, pack.display_name, pack.latest_version, pack.bucket_url]
        table.add_row(row)

    return table


def build_summary_table_md(packs_input_list, include_pack_status=False):
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


def load_json(file_path):
    """ Reads and loads json file.

    Args:
        file_path (str): full path to json file.

    Returns:
        dict: loaded json file.

    """
    with open(file_path, 'r') as json_file:
        result = json.load(json_file)

    return result


def print_packs_summary(packs_list):
    """Prints summary of packs uploaded to gcs.

    Args:
        packs_list (list): list of initialized packs.

    """
    successful_packs = [pack for pack in packs_list if pack.status == PackStatus.SUCCESS.name]
    skipped_packs = [pack for pack in packs_list if
                     pack.status == PackStatus.PACK_ALREADY_EXISTS.name
                     or pack.status == PackStatus.PACK_IS_NOT_UPDATED_IN_RUNNING_BUILD.name
                     or pack.status == PackStatus.FAILED_DETECTING_MODIFIED_FILES.name]
    failed_packs = [pack for pack in packs_list if pack not in successful_packs and pack not in skipped_packs]

    logging.info(
        f"""\n
------------------------------------------ Packs Upload Summary ------------------------------------------
Total number of packs: {len(packs_list)}
----------------------------------------------------------------------------------------------------------""")

    if successful_packs:
        successful_packs_table = _build_summary_table(successful_packs)
        logging.success(f"Number of successful uploaded packs: {len(successful_packs)}")
        logging.success(f"Uploaded packs:\n{successful_packs_table}")
    if skipped_packs:
        skipped_packs_table = _build_summary_table(skipped_packs)
        logging.warning(f"Number of skipped packs: {len(skipped_packs)}")
        logging.warning(f"Skipped packs:\n{skipped_packs_table}")
    if failed_packs:
        failed_packs_table = _build_summary_table(failed_packs, include_pack_status=True)
        logging.critical(f"Number of failed packs: {len(failed_packs)}")
        logging.critical(f"Failed packs:\n{failed_packs_table}")
        sys.exit(1)

    # for external pull requests -  when there is no failed packs, add the build summary to the pull request
    branch_name = os.environ['CIRCLE_BRANCH']
    if branch_name.startswith('pull/'):
        successful_packs_table = build_summary_table_md(successful_packs)

        build_num = os.environ['CIRCLE_BUILD_NUM']

        bucket_path = f'https://console.cloud.google.com/storage/browser/' \
                      f'marketplace-ci-build/content/builds/{branch_name}/{build_num}'

        pr_comment = f'Number of successful uploaded packs: {len(successful_packs)}\n' \
                     f'Uploaded packs:\n{successful_packs_table}\n\n' \
                     f'Browse to the build bucket with this address:\n{bucket_path}'

        add_pr_comment(pr_comment)


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
    return is_in_artifacts and is_in_prod_but_not_in_build


def options_handler():
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
                        help="CircleCi build number (will be used as hash revision at index file)", required=True)
    parser.add_argument('-c', '--circle_branch',
                        help="CircleCi branch of current build", required=True)
    parser.add_argument('-o', '--override_all_packs', help="Override all existing packs in cloud storage",
                        default=False, action='store_true', required=False)
    parser.add_argument('-k', '--key_string', help="Base64 encoded signature key used for signing packs.",
                        required=False)
    parser.add_argument('-pb', '--private_bucket_name', help="Private storage bucket name", required=False)
    parser.add_argument('-sb', '--storage_base_path', help="Storage base path of the directory to upload to.",
                        required=False)
    parser.add_argument('-rt', '--remove_test_playbooks', type=str2bool,
                        help='Should remove test playbooks from content packs or not.', default=True)
    # disable-secrets-detection-end
    return parser.parse_args()


def main():
    install_logging('Prepare Content Packs For Testing.log')
    options = options_handler()
    packs_artifacts_path = options.artifacts_path
    extract_destination_path = options.extract_path
    production_bucket_name = options.production_bucket_name
    build_bucket_name = options.build_bucket_name
    private_bucket_name = options.private_bucket_name
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

    # download and extract index from public bucket
    index_folder_path, index_blob, index_generation = download_and_extract_index(production_bucket,
                                                                                 extract_destination_path)
    # detect packs to upload
    pack_names = get_pack_names()
    extract_packs_artifacts(packs_artifacts_path, extract_destination_path)
    packs_list = [Pack(pack_name, os.path.join(extract_destination_path, pack_name)) for pack_name in pack_names
                  if is_valid_pack(extract_destination_path, pack_name, production_bucket, build_bucket)]

    # TODO: check that new/modified packs are in the artifacts (sdk)

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
    upload_core_packs_config(production_bucket, build_number, index_folder_path, extract_destination_path, build_bucket)

    # finished iteration over content packs
    upload_index_to_storage(index_folder_path, extract_destination_path, index_blob, build_number, private_packs,
                            current_commit_hash, index_generation)

    # upload id_set.json to bucket
    upload_id_set(production_bucket, id_set_path)

    # summary of packs status
    print_packs_summary(packs_list)


if __name__ == '__main__':
    main()
