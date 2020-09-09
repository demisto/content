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
from Tests.Marketplace.marketplace_services import init_storage_client, init_bigquery_client, Pack, PackStatus, \
    GCPConfig, PACKS_FULL_PATH, IGNORED_FILES, PACKS_FOLDER, IGNORED_PATHS, Metadata, CONTENT_ROOT_PATH, \
    get_packs_statistics_dataframe
from demisto_sdk.commands.common.tools import run_command, print_error, print_warning, print_color, LOG_COLORS, str2bool


def get_packs_names(target_packs):
    """Detects and returns packs names to upload.

    In case that `Modified` is passed in target_packs input, checks the git difference between two commits,
    current and previous and greps only ones with prefix Packs/.
    By default this function will receive `All` as target_packs and will return all packs names from content repo.

    Args:
        target_packs (str): csv packs names or `All` for all available packs in content
                            or `Modified` for only modified packs (currently not in use).

    Returns:
        set: unique collection of packs names to upload.

    """
    if target_packs.lower() == "all":
        if os.path.exists(PACKS_FULL_PATH):
            all_packs = {p for p in os.listdir(PACKS_FULL_PATH) if p not in IGNORED_FILES}
            print(f"Number of selected packs to upload is: {len(all_packs)}")
            # return all available packs names
            return all_packs
        else:
            print_error((f"Folder {PACKS_FOLDER} was not found "
                         f"at the following path: {PACKS_FULL_PATH}"))
            sys.exit(1)
    elif target_packs.lower() == "modified":
        cmd = "git diff --name-only HEAD..HEAD^ | grep 'Packs/'"
        modified_packs_path = run_command(cmd).splitlines()
        modified_packs = {p.split('/')[1] for p in modified_packs_path if p not in IGNORED_PATHS}
        print(f"Number of modified packs is: {len(modified_packs)}")
        # return only modified packs between two commits
        return modified_packs
    elif target_packs and isinstance(target_packs, str):
        modified_packs = {p.strip() for p in target_packs.split(',') if p not in IGNORED_FILES}
        print(f"Number of selected packs to upload is: {len(modified_packs)}")
        # return only packs from csv list
        return modified_packs
    else:
        print_error("Not correct usage of flag -p. Please check help section of upload packs script.")
        sys.exit(1)


def extract_packs_artifacts(packs_artifacts_path, extract_destination_path):
    """Extracts all packs from content pack artifact zip.

    Args:
        packs_artifacts_path (str): full path to content artifacts zip file.
        extract_destination_path (str): full path to directory where to extract the packs.

    """
    with ZipFile(packs_artifacts_path) as packs_artifacts:
        packs_artifacts.extractall(extract_destination_path)
    print("Finished extracting packs artifacts")


def download_and_extract_index(storage_bucket, extract_destination_path):
    """Downloads and extracts index zip from cloud storage.

    Args:
        storage_bucket (google.cloud.storage.bucket.Bucket): google storage bucket where index.zip is stored.
        extract_destination_path (str): the full path of extract folder.
    Returns:
        str: extracted index folder full path.
        Blob: google cloud storage object that represents index.zip blob.
        str: downloaded index generation.

    """
    index_storage_path = os.path.join(GCPConfig.STORAGE_BASE_PATH, f"{GCPConfig.INDEX_NAME}.zip")
    download_index_path = os.path.join(extract_destination_path, f"{GCPConfig.INDEX_NAME}.zip")

    index_blob = storage_bucket.blob(index_storage_path)
    index_folder_path = os.path.join(extract_destination_path, GCPConfig.INDEX_NAME)
    index_generation = 0  # Setting to 0 makes the operation succeed only if there are no live versions of the blob

    if not os.path.exists(extract_destination_path):
        os.mkdir(extract_destination_path)

    if not index_blob.exists():
        os.mkdir(index_folder_path)
        return index_folder_path, index_blob, index_generation

    index_blob.reload()
    index_generation = index_blob.generation
    index_blob.download_to_filename(download_index_path, if_generation_match=index_generation)

    if os.path.exists(download_index_path):
        with ZipFile(download_index_path, 'r') as index_zip:
            index_zip.extractall(extract_destination_path)

        if not os.path.exists(index_folder_path):
            print_error(f"Failed creating {GCPConfig.INDEX_NAME} folder with extracted data.")
            sys.exit(1)

        os.remove(download_index_path)
        print(f"Finished downloading and extracting {GCPConfig.INDEX_NAME} file to {extract_destination_path}")

        return index_folder_path, index_blob, index_generation
    else:
        print_error(f"Failed to download {GCPConfig.INDEX_NAME}.zip file from cloud storage.")
        sys.exit(1)


def update_index_folder(index_folder_path, pack_name, pack_path, pack_version='', hidden_pack=False):
    """Copies pack folder into index folder.

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
            print_warning(f"Skipping updating {pack_name} pack files to index")
            task_status = True
            return

        # Copy new files and add metadata for latest version
        for d in os.scandir(pack_path):
            if not os.path.exists(index_pack_path):
                os.mkdir(index_pack_path)
                print(f"Created {pack_name} pack folder in {GCPConfig.INDEX_NAME}")

            shutil.copy(d.path, index_pack_path)
            if pack_version and Pack.METADATA == d.name:
                shutil.copy(d.path, new_metadata_path)

        task_status = True
    except Exception as e:
        print_error(f"Failed in updating index folder for {pack_name} pack\n. Additional info: {e}")
    finally:
        return task_status


def clean_non_existing_packs(index_folder_path, private_packs, storage_bucket):
    """ Detects packs that are not part of content repo or from private packs bucket.

    In case such packs were detected, problematic pack is deleted from index and from content/packs/{target_pack} path.

    Args:
        index_folder_path (str): full path to downloaded index folder.
        private_packs (list): priced packs from private bucket.
        storage_bucket (google.cloud.storage.bucket.Bucket): google storage bucket where index.zip is stored.

    Returns:
        bool: whether cleanup was skipped or not.
    """
    if ('CI' not in os.environ) or (
            os.environ.get('CIRCLE_BRANCH') != 'master' and storage_bucket.name == GCPConfig.PRODUCTION_BUCKET) or (
            os.environ.get('CIRCLE_BRANCH') == 'master' and storage_bucket.name != GCPConfig.PRODUCTION_BUCKET):
        print("Skipping cleanup of packs in gcs.")  # skipping execution of cleanup in gcs bucket
        return True

    public_packs_names = {p for p in os.listdir(PACKS_FULL_PATH) if p not in IGNORED_FILES}
    private_packs_names = {p.get('id', '') for p in private_packs}
    valid_packs_names = public_packs_names.union(private_packs_names)
    # search for invalid packs folder inside index
    invalid_packs_names = {(entry.name, entry.path) for entry in os.scandir(index_folder_path) if
                           entry.name not in valid_packs_names and entry.is_dir()}

    if invalid_packs_names:
        try:
            print_warning(f"Detected {len(invalid_packs_names)} non existing pack inside index, starting cleanup.")

            for invalid_pack in invalid_packs_names:
                invalid_pack_name = invalid_pack[0]
                invalid_pack_path = invalid_pack[1]
                # remove pack from index
                shutil.rmtree(invalid_pack_path)
                print_warning(f"Deleted {invalid_pack_name} pack from {GCPConfig.INDEX_NAME} folder")
                # important to add trailing slash at the end of path in order to avoid packs with same prefix
                invalid_pack_gcs_path = os.path.join(GCPConfig.STORAGE_BASE_PATH, invalid_pack_name, "")  # by design

                for invalid_blob in [b for b in storage_bucket.list_blobs(prefix=invalid_pack_gcs_path)]:
                    print_warning(f"Deleted invalid {invalid_pack_name} pack under url {invalid_blob.public_url}")
                    invalid_blob.delete()  # delete invalid pack in gcs
        except Exception as e:
            print_error(f"Failed to cleanup non existing packs. Additional info:\n {e}")

    else:
        print(f"No invalid packs detected inside {GCPConfig.INDEX_NAME} folder")

    return False


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
            print_color(f"Finished uploading {GCPConfig.INDEX_NAME}.zip to storage.", LOG_COLORS.GREEN)
        else:
            print_error(f"Failed in uploading {GCPConfig.INDEX_NAME}, mismatch in index file generation")
            print_error(f"Downloaded index generation: {index_generation}")
            print_error(f"Current index generation: {current_index_generation}")
            sys.exit(0)
    except Exception as e:
        print_error(f"Failed in uploading {GCPConfig.INDEX_NAME}, additional info: {e}\n")
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
                print_error(f"{pack.name} pack {Pack.METADATA} is missing in {GCPConfig.INDEX_NAME}")
                sys.exit(1)

            with open(pack_metadata_path, 'r') as metadata_file:
                metadata = json.load(metadata_file)

            pack_current_version = metadata.get('currentVersion', Pack.PACK_INITIAL_VERSION)
            core_pack_relative_path = os.path.join(GCPConfig.STORAGE_BASE_PATH, pack.name,
                                                   pack_current_version, f"{pack.name}.zip")
            core_pack_public_url = os.path.join(GCPConfig.GCS_PUBLIC_URL, storage_bucket.name, core_pack_relative_path)

            if not storage_bucket.blob(core_pack_relative_path).exists():
                print_error(f"{pack.name} pack does not exist under {core_pack_relative_path} path")
                sys.exit(1)

            core_packs_public_urls.append(core_pack_public_url)
            found_core_packs.add(pack.name)

    if len(found_core_packs) != len(GCPConfig.CORE_PACKS_LIST):
        missing_core_packs = set(GCPConfig.CORE_PACKS_LIST) ^ found_core_packs
        print_error(f"Number of defined core packs are: {len(GCPConfig.CORE_PACKS_LIST)}")
        print_error(f"Actual number of found core packs are: {len(found_core_packs)}")
        print_error(f"Missing core packs are: {missing_core_packs}")
        sys.exit(1)

    # construct core pack data with public gcs urls
    core_packs_data = {
        'corePacks': core_packs_public_urls,
        'buildNumber': build_number
    }
    # upload core pack json file to gcs
    core_packs_config_path = os.path.join(GCPConfig.STORAGE_BASE_PATH, GCPConfig.CORE_PACK_FILE_NAME)
    blob = storage_bucket.blob(core_packs_config_path)
    blob.upload_from_string(json.dumps(core_packs_data, indent=4))

    print_color(f"Finished uploading {GCPConfig.CORE_PACK_FILE_NAME} to storage.", LOG_COLORS.GREEN)


def upload_id_set(storage_bucket, id_set_local_path=None):
    """
    Uploads the id_set.json artifact to the bucket.

    Args:
        storage_bucket (google.cloud.storage.bucket.Bucket): gcs bucket where core packs config is uploaded.
        id_set_local_path: path to the id_set.json file
    """
    if not id_set_local_path:
        print("Skipping upload of id set to gcs.")
        return

    id_set_gcs_path = os.path.join(GCPConfig.STORAGE_CONTENT_PATH, 'id_set.json')
    blob = storage_bucket.blob(id_set_gcs_path)

    with open(id_set_local_path, mode='r') as f:
        blob.upload_from_file(f)
    print_color("Finished uploading id_set.json to storage.", LOG_COLORS.GREEN)


def get_private_packs(private_index_path):
    """ Get the list of ID and price of the private packs.

    Args:
        private_index_path: The path for the index of the private packs.

    Returns:
        private_packs: A list of ID and price of the private packs.
    """
    try:
        metadata_files = glob.glob(f"{private_index_path}/**/metadata.json")
    except Exception as e:
        print_warning(f'Could not find metadata files in {private_index_path}: {str(e)}')
        return []

    if not metadata_files:
        print_warning(f'No metadata files found in [{private_index_path}]')

    private_packs = []
    for metadata_file_path in metadata_files:
        try:
            with open(metadata_file_path, "r") as metadata_file:
                metadata = json.load(metadata_file)
            if metadata:
                private_packs.append({
                    'id': metadata.get('id'),
                    'price': metadata.get('price')
                })
        except ValueError as e:
            print_error(f'Invalid JSON in the metadata file [{metadata_file_path}]: {str(e)}')

    return private_packs


def add_private_packs_to_index(index_folder_path, private_index_path):
    """ Add the private packs to the index folder.

    Args:
        index_folder_path: The index folder path.
        private_index_path: The path for the index of the private packs.

    """
    for d in os.scandir(private_index_path):
        if os.path.isdir(d.path):
            update_index_folder(index_folder_path, d.name, d.path)


def update_index_with_priced_packs(private_storage_bucket, extract_destination_path, index_folder_path):
    """ Updates index with priced packs and returns list of priced packs data.

    Args:
        private_storage_bucket (google.cloud.storage.bucket.Bucket): google storage private bucket.
        extract_destination_path (str): full path to extract directory.
        index_folder_path (str): downloaded index folder directory path.

    Returns:
        list: priced packs from private bucket.

    """
    private_index_path = ""
    private_packs = []

    try:
        private_index_path, _, _ = download_and_extract_index(private_storage_bucket,
                                                              os.path.join(extract_destination_path, 'private'))
        private_packs = get_private_packs(private_index_path)
        add_private_packs_to_index(index_folder_path, private_index_path)
        print("Finished updating index with priced packs")
    except Exception as e:
        print_error(f'Could not add private packs to the index: {str(e)}')
    finally:
        if private_index_path:
            shutil.rmtree(os.path.dirname(private_index_path), ignore_errors=True)
        return private_packs


def _build_summary_table(packs_input_list, include_pack_status=False):
    """Build summary table from pack list

    Args:
        packs_input_list (list): list of Packs

    Returns:
        PrettyTable: table with upload result of packs.

    """
    table_fields = ["Index", "Pack ID", "Pack Display Name", "Latest Version", "Status"] if include_pack_status \
        else ["Index", "Pack ID", "Pack Display Name", "Latest Version"]
    table = prettytable.PrettyTable()
    table.field_names = table_fields

    for index, pack in enumerate(packs_input_list, start=1):
        pack_status_message = PackStatus[pack.status].value
        row = [index, pack.name, pack.display_name, pack.latest_version, pack_status_message] if include_pack_status \
            else [index, pack.name, pack.display_name, pack.latest_version]
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


def get_content_git_client(content_repo_path):
    """ Initializes content repo client.

    Args:
        content_repo_path (str): content repo full path

    Returns:
        git.repo.base.Repo: content repo object.

    """
    return git.Repo(content_repo_path)


def get_recent_commits_data(content_repo):
    """ Returns recent commits hashes (of head and remote master)

    Args:
        content_repo (git.repo.base.Repo): content repo object.

    Returns:
        str: last commit hash of head.
        str: previous commit of origin/master (origin/master~1)
    """
    return content_repo.head.commit.hexsha, content_repo.commit('origin/master~1').hexsha


def check_if_index_is_updated(index_folder_path, content_repo, current_commit_hash, remote_previous_commit_hash,
                              storage_bucket):
    """ Checks stored at index.json commit hash and compares it to current commit hash. In case no packs folders were
    added/modified/deleted, all other steps are not performed.

    Args:
        index_folder_path (str): index folder full path.
        content_repo (git.repo.base.Repo): content repo object.
        current_commit_hash (str): last commit hash of head.
        remote_previous_commit_hash (str): previous commit of origin/master (origin/master~1)
        storage_bucket: public storage bucket.

    """
    skipping_build_task_message = "Skipping Upload Packs To Marketplace Storage Step."

    try:
        if storage_bucket.name != GCPConfig.PRODUCTION_BUCKET:
            print("Skipping index update check in non production bucket")
            return

        if not os.path.exists(os.path.join(index_folder_path, f"{GCPConfig.INDEX_NAME}.json")):
            # will happen only in init bucket run
            print_warning(f"{GCPConfig.INDEX_NAME}.json not found in {GCPConfig.INDEX_NAME} folder")
            return

        with open(os.path.join(index_folder_path, f"{GCPConfig.INDEX_NAME}.json")) as index_file:
            index_json = json.load(index_file)

        index_commit_hash = index_json.get('commit', remote_previous_commit_hash)

        try:
            index_commit = content_repo.commit(index_commit_hash)
        except Exception as e:
            # not updated build will receive this exception because it is missing more updated commit
            print_warning(f"Index is already updated. Additional info:\n {e}")
            print_warning(skipping_build_task_message)
            sys.exit()

        current_commit = content_repo.commit(current_commit_hash)

        if current_commit.committed_datetime <= index_commit.committed_datetime:
            print_warning(f"Current commit {current_commit.hexsha} committed time: {current_commit.committed_datetime}")
            print_warning(f"Index commit {index_commit.hexsha} committed time: {index_commit.committed_datetime}")
            print_warning("Index is already updated.")
            print_warning(skipping_build_task_message)
            sys.exit()

        for changed_file in current_commit.diff(index_commit):
            if changed_file.a_path.startswith(PACKS_FOLDER):
                print(f"Found changed packs between index commit {index_commit.hexsha} and {current_commit.hexsha}")
                break
        else:
            print_warning(f"No changes found between index commit {index_commit.hexsha} and {current_commit.hexsha}")
            print_warning(skipping_build_task_message)
            sys.exit()
    except Exception as e:
        print_error(f"Failed in checking status of index. Additional info:\n {e}")
        sys.exit(1)


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

    print("\n")
    print("------------------------------------------ Packs Upload Summary ------------------------------------------")
    print(f"Total number of packs: {len(packs_list)}")
    print("----------------------------------------------------------------------------------------------------------")

    if successful_packs:
        print_color(f"Number of successful uploaded packs: {len(successful_packs)}", LOG_COLORS.GREEN)
        print_color("Uploaded packs:\n", LOG_COLORS.GREEN)
        successful_packs_table = _build_summary_table(successful_packs)
        print_color(successful_packs_table, LOG_COLORS.GREEN)
    if skipped_packs:
        print_warning(f"Number of skipped packs: {len(skipped_packs)}")
        print_warning("Skipped packs:\n")
        skipped_packs_table = _build_summary_table(skipped_packs)
        print_warning(skipped_packs_table)
    if failed_packs:
        print_error(f"Number of failed packs: {len(failed_packs)}")
        print_error("Failed packs:\n")
        failed_packs_table = _build_summary_table(failed_packs, include_pack_status=True)
        print_error(failed_packs_table)
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


def add_pr_comment(comment):
    """Add comment to the pull request.

    Args:
        comment (string): The comment text.

    """
    token = os.environ['CONTENT_GITHUB_TOKEN']
    branch_name = os.environ['CIRCLE_BRANCH']
    sha1 = os.environ['CIRCLE_SHA1']

    query = f'?q={sha1}+repo:demisto/content+is:pr+is:open+head:{branch_name}+is:open'
    url = 'https://api.github.com/search/issues'
    headers = {'Authorization': 'Bearer ' + token}
    try:
        res = requests.get(url + query, headers=headers, verify=False)
        res = handle_github_response(res)
        if res and res.get('total_count', 0) == 1:
            issue_url = res['items'][0].get('comments_url') if res.get('items', []) else None
            if issue_url:
                res = requests.post(issue_url, json={'body': comment}, headers=headers, verify=False)
                handle_github_response(res)
        else:
            print_warning('Add pull request comment failed: There is more then one open pull request for branch {}.'
                          .format(branch_name))
    except Exception as e:
        print_warning('Add pull request comment failed: {}'.format(e))


def handle_github_response(response):
    res_dict = response.json()
    if not res_dict.get('ok'):
        print_warning('Add pull request comment failed: {}'.
                      format(res_dict.get('message')))
    return res_dict


def main():
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

    # content repo client initialized
    content_repo = get_content_git_client(CONTENT_ROOT_PATH)
    current_commit_hash, remote_previous_commit_hash = get_recent_commits_data(content_repo)

    if storage_base_path:
        GCPConfig.STORAGE_BASE_PATH = storage_base_path

    # detect packs to upload
    pack_names = get_packs_names(target_packs)
    extract_packs_artifacts(packs_artifacts_path, extract_destination_path)
    packs_list = [Pack(pack_name, os.path.join(extract_destination_path, pack_name)) for pack_name in pack_names
                  if os.path.exists(os.path.join(extract_destination_path, pack_name))]

    # download and extract index from public bucket
    index_folder_path, index_blob, index_generation = download_and_extract_index(storage_bucket,
                                                                                 extract_destination_path)

    if not option.override_all_packs:
        check_if_index_is_updated(index_folder_path, content_repo, current_commit_hash, remote_previous_commit_hash,
                                  storage_bucket)

    # google cloud bigquery client initialized
    bq_client = init_bigquery_client(service_account)
    packs_statistic_df = get_packs_statistics_dataframe(bq_client)

    if private_bucket_name:  # Add private packs to the index
        private_storage_bucket = storage_client.bucket(private_bucket_name)
        private_packs = update_index_with_priced_packs(private_storage_bucket, extract_destination_path,
                                                       index_folder_path)
    else:  # skipping private packs
        print("Skipping index update of priced packs")
        private_packs = []

    # clean index and gcs from non existing or invalid packs
    clean_non_existing_packs(index_folder_path, private_packs, storage_bucket)

    # starting iteration over packs
    for pack in packs_list:
        task_status, user_metadata = pack.load_user_metadata()
        if not task_status:
            pack.status = PackStatus.FAILED_LOADING_USER_METADATA.value
            pack.cleanup()
            continue

        task_status, pack_content_items = pack.collect_content_items()
        if not task_status:
            pack.status = PackStatus.FAILED_COLLECT_ITEMS.name
            pack.cleanup()
            continue

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

        task_status = pack.format_metadata(user_metadata=user_metadata, pack_content_items=pack_content_items,
                                           integration_images=integration_images, author_image=author_image,
                                           index_folder_path=index_folder_path,
                                           packs_dependencies_mapping=packs_dependencies_mapping,
                                           build_number=build_number, commit_hash=current_commit_hash,
                                           packs_statistic_df=packs_statistic_df)
        if not task_status:
            pack.status = PackStatus.FAILED_METADATA_PARSING.name
            pack.cleanup()
            continue

        task_status, not_updated_build = pack.prepare_release_notes(index_folder_path, build_number)
        if not task_status:
            pack.status = PackStatus.FAILED_RELEASE_NOTES.name
            pack.cleanup()
            continue

        if not_updated_build:
            pack.status = PackStatus.PACK_IS_NOT_UPDATED_IN_RUNNING_BUILD.name
            pack.cleanup()
            continue

        task_status = pack.remove_unwanted_files(remove_test_playbooks)
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

        task_status, pack_was_modified = pack.detect_modified(content_repo, index_folder_path, current_commit_hash,
                                                              remote_previous_commit_hash)
        if not task_status:
            pack.status = PackStatus.FAILED_DETECTING_MODIFIED_FILES.name
            pack.cleanup()
            continue

        task_status, skipped_pack_uploading = pack.upload_to_storage(zip_pack_path, pack.latest_version, storage_bucket,
                                                                     override_all_packs or pack_was_modified)
        if not task_status:
            pack.status = PackStatus.FAILED_UPLOADING_PACK.name
            pack.cleanup()
            continue

        task_status, exists_in_index = pack.check_if_exists_in_index(index_folder_path)
        if not task_status:
            pack.status = PackStatus.FAILED_SEARCHING_PACK_IN_INDEX.name
            pack.cleanup()
            continue

        # in case that pack already exist at cloud storage path and in index, skipped further steps
        if skipped_pack_uploading and exists_in_index:
            pack.status = PackStatus.PACK_ALREADY_EXISTS.name
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
