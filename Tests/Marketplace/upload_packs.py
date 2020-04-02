import json
import os
import sys
import argparse
import warnings
import shutil
import uuid
import prettytable
import google.auth
from google.cloud import storage
from datetime import datetime
from zipfile import ZipFile
from Tests.Marketplace.marketplace_services import Pack, PackStatus
from Tests.test_utils import run_command, print_error, print_warning, print_color, LOG_COLORS

# global constants
CONTENT_PACKS_FOLDER = "Packs"  # name of base packs folder inside content repo
IGNORED_FILES = ['__init__.py', 'ApiModules']  # files to ignore inside Packs folder
IGNORED_PATHS = [os.path.join(CONTENT_PACKS_FOLDER, p) for p in IGNORED_FILES]
CONTENT_ROOT_PATH = os.path.abspath(os.path.join(__file__, '../../..'))  # full path to content root repo
PACKS_FULL_PATH = os.path.join(CONTENT_ROOT_PATH, CONTENT_PACKS_FOLDER)  # full path to Packs folder in content repo
INTEGRATIONS_FOLDER = "Integrations"  # integrations folder name inside pack


def get_modified_packs(specific_packs=""):
    """Detects and returns modified or new packs names.

    Checks the git difference between two commits, current and previous and greps only ones with prefix Packs/.
    After content repo will move only for Packs structure, the grep pipe can be removed.
    In case of local dev mode, the function will receive comma separated list of target packs.

    Args:
        specific_packs (str): comma separated packs names or `All` for all available packs in content.

    Returns:
        set: unique collection of modified/new packs names.

    """
    if specific_packs.lower() == "all":
        if os.path.exists(PACKS_FULL_PATH):
            all_packs = {p for p in os.listdir(PACKS_FULL_PATH) if p not in IGNORED_FILES}
            print(f"Number of selected packs is: {len(all_packs)}")
            return all_packs
        else:
            print(f"Folder {CONTENT_PACKS_FOLDER} was not found at the following path: {PACKS_FULL_PATH}")
            sys.exit(1)

    elif specific_packs:
        modified_packs = {p.strip() for p in specific_packs.split(',')}
        print(f"Number of selected packs is: {len(modified_packs)}")
        return modified_packs
    else:
        cmd = f"git diff --name-only HEAD..HEAD^ | grep 'Packs/'"
        modified_packs_path = run_command(cmd, use_shell=True).splitlines()
        modified_packs = {p.split('/')[1] for p in modified_packs_path if p not in IGNORED_PATHS}
        print(f"Number of modified packs is: {len(modified_packs)}")

        return modified_packs


def extract_packs_artifacts(packs_artifacts_path, extract_destination_path):
    """Extracts all packs from content pack artifact zip.

    Args:
        packs_artifacts_path (str): full path to content artifacts zip file.
        extract_destination_path (str): full path to directory where to extract the packs.

    """
    with ZipFile(packs_artifacts_path) as packs_artifacts:
        packs_artifacts.extractall(extract_destination_path)
    print("Finished extracting packs artifacts")


def init_storage_client(service_account=None):
    """Initialize google cloud storage client.

    In case of local dev usage the client will be initialized with user default credentials.
    Otherwise, client will be initialized from service account json that is stored in CirlceCI.

    Args:
        service_account (str): full path to service account json.

    Return:
        storage.Client: initialized google cloud storage client.
    """
    if service_account:
        storage_client = storage.Client.from_service_account_json(service_account)
        print("Created gcp service account")

        return storage_client
    else:
        # in case of local dev use, ignored the warning of non use of service account.
        warnings.filterwarnings("ignore", message=google.auth._default._CLOUD_SDK_CREDENTIALS_WARNING)
        credentials, project = google.auth.default()
        storage_client = storage.Client(credentials=credentials, project=project)
        print("Created gcp private account")

        return storage_client


def download_and_extract_index(storage_bucket, extract_destination_path):
    """Downloads and extracts index zip from cloud storage.

    Args:
        storage_bucket (google.cloud.storage.bucket.Bucket): google storage bucket where index.zip is stored.
        extract_destination_path (str): the full path of extract folder.

    Returns:
        str: extracted index folder full path.
        Blob: google cloud storage object that represents index.zip blob.

    """
    index_storage_path = os.path.join(STORAGE_BASE_PATH, f"{Pack.INDEX_NAME}.zip")
    download_index_path = os.path.join(extract_destination_path, f"{Pack.INDEX_NAME}.zip")

    index_blob = storage_bucket.blob(index_storage_path)
    index_folder_path = os.path.join(extract_destination_path, Pack.INDEX_NAME)

    if not index_blob.exists():
        os.mkdir(index_folder_path)
        return index_folder_path, index_blob

    index_blob.cache_control = "no-cache"  # index zip should never be cached in the memory, should be updated version
    index_blob.reload()
    index_blob.download_to_filename(download_index_path)

    if os.path.exists(download_index_path):
        with ZipFile(download_index_path, 'r') as index_zip:
            index_zip.extractall(extract_destination_path)

        if not os.path.exists(index_folder_path):
            print_error(f"Failed creating {Pack.INDEX_NAME} folder with extracted data.")
            sys.exit(1)

        os.remove(download_index_path)
        print(f"Finished downloading and extracting {Pack.INDEX_NAME} file to {extract_destination_path}")

        return index_folder_path, index_blob
    else:
        print_error(f"Failed to download {Pack.INDEX_NAME}.zip file from cloud storage.")
        sys.exit(1)


def update_index_folder(index_folder_path, pack_name, pack_path):
    """Copies pack folder into index folder.

    Args:
        index_folder_path (str): full path to index folder.
        pack_name (str): pack folder name to copy.
        pack_path (str): pack folder full path.

    Returns:
        bool: whether the operation succeeded.
    """
    task_status = False

    try:
        index_folder_subdirectories = [d for d in os.listdir(index_folder_path) if
                                       os.path.isdir(os.path.join(index_folder_path, d))]
        index_pack_path = os.path.join(index_folder_path, pack_name)

        if pack_name in index_folder_subdirectories:
            shutil.rmtree(index_pack_path)
        shutil.copytree(pack_path, index_pack_path)
        task_status = True
    except Exception as e:
        print_error(f"Failed in updating index folder for {pack_name} pack\n. Additional info: {e}")
    finally:
        return task_status


def upload_index_to_storage(index_folder_path, extract_destination_path, index_blob, build_number):
    """Upload updated index zip to cloud storage.

    Args:
        index_folder_path (str): index folder full path.
        extract_destination_path (str): extract folder full path.
        index_blob (Blob): google cloud storage object that represents index.zip blob.
        build_number (str): circleCI build number, used as an index revision.

    """
    with open(os.path.join(index_folder_path, f"{Pack.INDEX_NAME}.json"), "w+") as index_file:
        index = {
            'description': 'Master index for Demisto Content Packages',
            'baseUrl': 'https://marketplace.demisto.ninja/content/packs',  # disable-secrets-detection
            'revision': build_number,
            'modified': datetime.utcnow().strftime(Pack.DATE_FORMAT),
            'landingPage': {
                'sections': [
                    'Trending',
                    'Recommended by Demisto',
                    'New',
                    'Getting Started'
                ]
            }
        }
        json.dump(index, index_file, indent=4)

    index_zip_name = os.path.basename(index_folder_path)
    index_zip_path = shutil.make_archive(base_name=index_folder_path, format="zip",
                                         root_dir=extract_destination_path, base_dir=index_zip_name)

    index_blob.cache_control = "no-cache"  # disabling caching for index blob
    if index_blob.exists():
        index_blob.reload()

    index_blob.upload_from_filename(index_zip_path)
    shutil.rmtree(index_folder_path)
    print_color(f"Finished uploading {Pack.INDEX_NAME}.zip to storage.", LOG_COLORS.GREEN)


def _build_summary_table(packs_input_list):
    """Build summary table from pack list

    Args:
        packs_input_list (list): list of Packs

    Returns:
        PrettyTable: table with upload result of packs.

    """
    table_fields = ["Index", "Pack Name", "Version", "Status"]
    table = prettytable.PrettyTable()
    table.field_names = table_fields

    for index, pack in enumerate(packs_input_list, start=1):
        pack_status_message = PackStatus[pack.status].value
        row = [index, pack.name, pack.latest_version, pack_status_message]
        table.add_row(row)

    return table


def print_packs_summary(packs_list):
    """Prints summary of packs uploaded to gcs.

    Args:
        packs_list (list): list of initialized packs.

    """
    successful_packs = [pack for pack in packs_list if pack.status == PackStatus.SUCCESS.name]
    skipped_packs = [pack for pack in packs_list if pack.status == PackStatus.PACK_ALREADY_EXISTS.name]
    failed_packs = [pack for pack in packs_list if pack not in successful_packs and pack not in skipped_packs]

    print("\n")
    print("--------------------------------------- Packs Upload Summary ---------------------------------------")
    print(f"Total number of packs: {len(packs_list)}")

    if successful_packs:
        print_color(f"Number of successful uploaded packs: {len(successful_packs)}", LOG_COLORS.GREEN)
        successful_packs_table = _build_summary_table(successful_packs)
        print_color(successful_packs_table, LOG_COLORS.GREEN)
    if skipped_packs:
        print_warning(f"Number of skipped packs: {len(skipped_packs)}")
        skipped_packs_table = _build_summary_table(skipped_packs)
        print_warning(skipped_packs_table)
    if failed_packs:
        print_error(f"Number of failed packs: {len(failed_packs)}")
        failed_packs_table = _build_summary_table(failed_packs)
        print_error(failed_packs_table)


def option_handler():
    """Validates and parses script arguments.

    Returns:
        Namespace: Parsed arguments object.

    """
    parser = argparse.ArgumentParser(description="Store packs in cloud storage.")
    # disable-secrets-detection-start
    parser.add_argument('-a', '--artifacts_path', help="The full path of packs artifacts", required=True)
    parser.add_argument('-e', '--extract_path', help="Full path of folder to extract wanted packs", required=True)
    parser.add_argument('-s', '--service_account',
                        help=("Path to gcloud service account, is for circleCI usage. "
                              "For local development use your personal account and "
                              "authenticate using Google Cloud SDK by running: "
                              "`gcloud auth application-default login` and leave this parameter blank. "
                              "For more information go to: "
                              "https://googleapis.dev/python/google-api-core/latest/auth.html"),
                        required=False)
    parser.add_argument('-p', '--pack_names',
                        help=("Comma separated list of target pack names. "
                              "Define `All` in order to store all available packs."),
                        required=False, default="")
    parser.add_argument('-b', '--bucket_name', help="Storage bucket name", required=True)
    parser.add_argument('-n', '--ci_build_number',
                        help="CircleCi build number (will be used as hash revision at index file)", required=False)
    parser.add_argument('-o', '--override_pack', help="Override existing packs in cloud storage", default=False,
                        action='store_true', required=False)
    parser.add_argument('-k', '--key_string', help="Base64 encoded signature key used for signing packs.",
                        required=False)
    # disable-secrets-detection-end
    return parser.parse_args()


def main():
    option = option_handler()
    packs_artifacts_path = option.artifacts_path
    extract_destination_path = option.extract_path
    storage_bucket_name = option.bucket_name
    service_account = option.service_account
    specific_packs = option.pack_names
    build_number = option.ci_build_number if option.ci_build_number else str(uuid.uuid4())
    override_pack = option.override_pack
    signature_key = option.key_string

    # detect new or modified packs
    modified_packs = get_modified_packs(specific_packs)
    extract_packs_artifacts(packs_artifacts_path, extract_destination_path)
    packs_list = [Pack(pack_name, os.path.join(extract_destination_path, pack_name)) for pack_name in modified_packs
                  if os.path.exists(os.path.join(extract_destination_path, pack_name))]

    # google cloud storage client initialized
    storage_client = init_storage_client(service_account)
    storage_bucket = storage_client.bucket(storage_bucket_name)
    index_folder_path, index_blob = download_and_extract_index(storage_bucket, extract_destination_path)
    index_was_updated = False  # indicates whether one or more index folders were updated

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

        task_status, pack_content_items = pack.collect_content_items()
        if not task_status:
            pack.status = PackStatus.FAILED_COLLECT_ITEMS.name
            pack.cleanup()
            continue

        task_status = pack.format_metadata(pack_content_items, integration_images, author_image,
                                           index_folder_path)
        if not task_status:
            pack.status = PackStatus.FAILED_METADATA_PARSING.name
            pack.cleanup()
            continue

        # todo finish implementation of release notes
        # pack.parse_release_notes()

        task_status = pack.remove_unwanted_files()
        if not task_status:
            pack.status = PackStatus.FAILED_REMOVING_PACK_SKIPPED_FOLDERS
            pack.cleanup()
            continue

        task_status = pack.sign_pack(signature_key)
        if not task_status:
            pack.status = PackStatus.FAILED_SIGNING_PACKS.name
            pack.cleanup()
            continue

        task_status, zip_pack_path = pack.zip_pack()
        if not task_status:
            pack.status = PackStatus.FAILED_ZIPPING_PACK_ARTIFACTS.name
            pack.cleanup()
            continue

        task_status, skipped_pack_uploading = pack.upload_to_storage(zip_pack_path, pack.latest_version, storage_bucket,
                                                                     override_pack)
        if not task_status:
            pack.status = PackStatus.FAILED_UPLOADING_PACK.name
            pack.cleanup()
            continue

        # in case that pack already exist at cloud storage path, skipped further steps
        if skipped_pack_uploading:
            pack.status = PackStatus.PACK_ALREADY_EXISTS.name
            pack.cleanup()
            continue

        task_status = pack.prepare_for_index_upload()
        if not task_status:
            pack.status = PackStatus.FAILED_PREPARING_INDEX_FOLDER.name
            pack.cleanup()
            continue

        task_status = update_index_folder(index_folder_path=index_folder_path, pack_name=pack.name, pack_path=pack.path)
        if not task_status:
            pack.status = PackStatus.FAILED_UPDATING_INDEX_FOLDER.name
            pack.cleanup()
            continue

        # detected index update
        index_was_updated = True
        pack.status = PackStatus.SUCCESS.name

    # finished iteration over content packs
    if index_was_updated:
        upload_index_to_storage(index_folder_path, extract_destination_path, index_blob, build_number)
    else:
        print_warning(f"Skipping uploading index.zip to storage.")

    # summary of packs status
    print_packs_summary(packs_list)


if __name__ == '__main__':
    main()
