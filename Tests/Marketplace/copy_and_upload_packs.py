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


def get_packs_names():
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


def upload_core_packs_config(storage_bucket, build_number, index_folder_path):
    """Uploads corepacks.json file configuration to bucket. Corepacks file includes core packs for server installation.

     Args:
        storage_bucket (google.cloud.storage.bucket.Bucket): gcs bucket where core packs config is uploaded.
        build_number (str): circleCI build number.
        index_folder_path (str): The index folder path.

    """
    core_packs_public_urls = []
    found_core_packs = set()

    for pack in os.scandir(index_folder_path):
        if pack.is_dir() and pack.name in GCPConfig.CORE_PACKS_LIST:
            pack_metadata_path = os.path.join(index_folder_path, pack.name, Pack.METADATA)

            if not os.path.exists(pack_metadata_path):
                logging.critical(f"{pack.name} pack {Pack.METADATA} is missing in {GCPConfig.INDEX_NAME}")
                sys.exit(1)

            with open(pack_metadata_path, 'r') as metadata_file:
                metadata = json.load(metadata_file)

            pack_current_version = metadata.get('currentVersion', Pack.PACK_INITIAL_VERSION)
            core_pack_relative_path = os.path.join(GCPConfig.STORAGE_BASE_PATH, pack.name,
                                                   pack_current_version, f"{pack.name}.zip")
            core_pack_public_url = os.path.join(GCPConfig.GCS_PUBLIC_URL, storage_bucket.name, core_pack_relative_path)

            if not storage_bucket.blob(core_pack_relative_path).exists():
                logging.critical(f"{pack.name} pack does not exist under {core_pack_relative_path} path")
                sys.exit(1)

            core_packs_public_urls.append(core_pack_public_url)
            found_core_packs.add(pack.name)

    if len(found_core_packs) != len(GCPConfig.CORE_PACKS_LIST):
        missing_core_packs = set(GCPConfig.CORE_PACKS_LIST) ^ found_core_packs
        logging.error(f"Number of defined core packs are: {len(GCPConfig.CORE_PACKS_LIST)}")
        logging.error(f"Actual number of found core packs are: {len(found_core_packs)}")
        logging.critical(f"Missing core packs are: {missing_core_packs}")
        sys.exit(1)

    # construct core pack data with public gcs urls
    core_packs_data = {
        'corePacks': core_packs_public_urls,
        'buildNumber': build_number
    }
    # TODO: download from ci-build-bucket, refactor and upload to prod-bucket
    # upload core pack json file to gcs
    core_packs_config_path = os.path.join(GCPConfig.STORAGE_BASE_PATH, GCPConfig.CORE_PACK_FILE_NAME)
    blob = storage_bucket.blob(core_packs_config_path)
    blob.upload_from_string(json.dumps(core_packs_data, indent=4))

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
                        help="CircleCi build number (will be used as hash revision at index file)", required=False)
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
    option = option_handler()
    packs_artifacts_path = option.artifacts_path
    extract_destination_path = option.extract_path
    storage_bucket_name = option.bucket_name
    private_bucket_name = option.private_bucket_name
    service_account = option.service_account
    target_packs = option.pack_names if option.pack_names else ""
    build_number = option.ci_build_number if option.ci_build_number else str(uuid.uuid4())
    override_all_packs = option.override_all_packs
    signature_key = option.key_string
    id_set_path = option.id_set_path
    packs_dependencies_mapping = load_json(option.pack_dependencies) if option.pack_dependencies else {}
    storage_base_path = option.storage_base_path
    remove_test_playbooks = option.remove_test_playbooks

    # google cloud storage client initialized
    storage_client = init_storage_client(service_account)
    storage_bucket = storage_client.bucket(storage_bucket_name)

    if storage_base_path:
        GCPConfig.STORAGE_BASE_PATH = storage_base_path

    # TODO: for prepare content step, think what to do if a pack was failing to upload
    # TODO: for upload packs step, think what to do if a pack was failing to upload
    # TODO: what if no commit was found, for example: there was a squash of several master commits?

    # download and extract index from public bucket
    index_folder_path, index_blob, index_generation = download_and_extract_index(storage_bucket,
                                                                                 extract_destination_path)

    # detect packs to upload
    # TODO: think why need to get pack names from content repo and not from artifacts
    pack_names = get_packs_names()
    extract_packs_artifacts(packs_artifacts_path, extract_destination_path)
    packs_list = [Pack(pack_name, os.path.join(extract_destination_path, pack_name)) for pack_name in pack_names
                  if os.path.exists(os.path.join(extract_destination_path, pack_name))]

    # TODO: check each pack not in ci-build-bucket but on prod-bucket
    # TODO: check that new/modified packs are in the artifacts (sdk)

    # starting iteration over packs
    for pack in packs_list:
        task_status, integration_images = pack.upload_integration_images(storage_bucket)
        if not task_status:
            pack.status = PackStatus.FAILED_IMAGES_UPLOAD.name
            pack.cleanup()
            continue

        task_status, author_image = pack.upload_author_image(storage_bucket)
        if not task_status:
            pack.status = PackStatus.FAILED_AUTHOR_IMAGE_UPLOAD.name
            pack.cleanup()
            continue

        task_status, zip_pack_path = pack.zip_pack()
        # TODO: here need to download pack from bucket
        if not task_status:
            pack.status = PackStatus.FAILED_ZIPPING_PACK_ARTIFACTS.name
            pack.cleanup()
            continue

        (task_status, skipped_pack_uploading, full_pack_path) = \
            pack.upload_to_storage(zip_pack_path, pack.latest_version,
                                   storage_bucket, override_all_packs)
        if full_pack_path is not None:
            branch_name = os.environ['CIRCLE_BRANCH']
            build_num = os.environ['CIRCLE_BUILD_NUM']
            bucket_path = f'https://console.cloud.google.com/storage/browser/' \
                          f'marketplace-ci-build/{branch_name}/{build_num}'
            bucket_url = bucket_path.join(full_pack_path)
        else:
            bucket_url = 'Pack was not uploaded.'
        if not task_status:
            pack.status = PackStatus.FAILED_UPLOADING_PACK.name
            pack.bucket_url = bucket_url
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
    upload_core_packs_config(storage_bucket, build_number, index_folder_path)

    # finished iteration over content packs
    upload_index_to_storage(index_folder_path, extract_destination_path, index_blob, build_number, private_packs,
                            current_commit_hash, index_generation)

    # upload id_set.json to bucket
    upload_id_set(storage_bucket, id_set_path)

    # summary of packs status
    print_packs_summary(packs_list)


if __name__ == '__main__':
    main()
