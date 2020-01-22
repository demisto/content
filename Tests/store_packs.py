import json
import os
import sys
import argparse
import shutil
import uuid
import google.auth
from google.cloud import storage
from distutils.util import strtobool
from datetime import datetime
from zipfile import ZipFile, ZIP_DEFLATED
from Tests.test_utils import run_command, print_error, collect_pack_script_tags, collect_content_items_data

STORAGE_BASE_PATH = "content/packs"

DIR_NAME_TO_CONTENT_TYPE = {
    "Scripts": "Automations",
    "IncidentFields": "Incident Fields",
    "Playbooks": "Playbooks",
    "Integrations": "Integrations",
    "IncidentTypes": "Incident Types",
    "Layouts": "Incident Layouts",
    "Reports": "Reports",
    "Dashboards": "Dashboards"
}


class Pack:
    PACK_INITIAL_VERSION = "1.0.0"
    DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
    CHANGELOG = "changelog.json"
    README = "README.md"
    METADATA = "metadata.json"
    INDEX_JSON = "index.json"
    EXCLUDE_DIRECTORIES = ["TestPlaybooks"]

    def __init__(self, pack_name, pack_path, storage_bucket):
        self._pack_name = pack_name
        self._pack_path = pack_path
        self._storage_bucket = storage_bucket

    @property
    def name(self):
        return self._pack_name

    @property
    def path(self):
        return self._pack_path

    @property
    def latest_version(self):
        return self._get_latest_version()

    def _get_latest_version(self):
        if Pack.CHANGELOG not in os.listdir(self._pack_path):
            return self.PACK_INITIAL_VERSION

        changelog_path = os.path.join(self._pack_path, Pack.CHANGELOG)

        with open(changelog_path, "r") as changelog:
            changelog_json = json.load(changelog)

            pack_versions = list(changelog_json.keys())
            pack_versions.sort(key=lambda str_version: [int(v) for v in str_version.split(".")],
                               reverse=True)

            return pack_versions[0]

    def _parse_pack_metadata(self, user_metadata):
        pack_metadata = {}
        # todo add id to metadata
        pack_metadata['id'] = self._pack_name
        pack_metadata['displayName'] = user_metadata.get('name', '')
        pack_metadata['description'] = user_metadata.get('description', '')
        pack_metadata['updated'] = datetime.utcnow().strftime(Pack.DATE_FORMAT)
        pack_metadata['support'] = user_metadata.get('support', '')
        pack_metadata['beta'] = bool(strtobool(user_metadata.get('beta')))
        pack_metadata['deprecated'] = bool(strtobool(user_metadata.get('deprecated')))
        pack_metadata['certification'] = user_metadata.get('certification', '')
        pack_metadata['serverMinVersion'] = user_metadata.get('serverMinVersion', '')
        pack_metadata['serverLicense'] = user_metadata.get('serverLicense', '')
        pack_metadata['currentVersion'] = user_metadata.get('currentVersion', '')

        pack_metadata['supportDetails'] = {}
        pack_metadata['supportDetails']['author'] = user_metadata.get('author', '')
        support_url = user_metadata.get('url')

        if support_url:
            pack_metadata['supportDetails']['url'] = support_url
        support_email = user_metadata.get('email')

        if support_email:
            pack_metadata['supportDetails']['email'] = support_email

        # pack_metadata['general'] = user_metadata.get('general', [])
        pack_metadata['tags'] = collect_pack_script_tags(self._pack_path)
        pack_metadata['categories'] = user_metadata.get('categories', [])
        content_items_data = {DIR_NAME_TO_CONTENT_TYPE[k]: v for (k, v) in
                              collect_content_items_data(self._pack_path).items() if k in DIR_NAME_TO_CONTENT_TYPE}
        pack_metadata['contentItems'] = content_items_data
        pack_metadata["contentItemTypes"] = list(content_items_data.keys())
        # todo collect all integrations display name
        # pack_metadata["integrations"] = collect_integration_display_names(self._pack_path)
        pack_metadata["useCases"] = user_metadata.get('useCases', [])
        pack_metadata["keywords"] = user_metadata.get('keywords', [])
        # pack_metadata["dependencies"] = {}  # TODO: build dependencies tree

        return pack_metadata

    def zip_pack(self):
        zip_pack_path = f"{self._pack_path}.zip"

        with ZipFile(zip_pack_path, 'w', ZIP_DEFLATED) as pack_zip:
            for root, dirs, files in os.walk(self._pack_path, topdown=True):
                dirs[:] = [d for d in dirs if d not in Pack.EXCLUDE_DIRECTORIES]

                for f in files:
                    full_file_path = os.path.join(root, f)
                    relative_file_path = os.path.relpath(full_file_path, self._pack_path)
                    pack_zip.write(filename=full_file_path, arcname=relative_file_path)

        return zip_pack_path

    def upload_to_storage(self, zip_pack_path, latest_version):
        version_pack_path = os.path.join(STORAGE_BASE_PATH, self._pack_name, latest_version)
        existing_files = [f.name for f in self._storage_bucket.list_blobs(prefix=version_pack_path)]

        if len(existing_files) > 0:
            print_error(f"The following packs already exist at storage: {', '.join(existing_files)}")
            print_error(f"Skipping step of uploading {self._pack_name}.zip to storage.")
            sys.exit(1)

        pack_full_path = f"{version_pack_path}/{self._pack_name}.zip"
        blob = self._storage_bucket.blob(pack_full_path)

        with open(zip_pack_path, "rb") as pack_zip:
            blob.upload_from_file(pack_zip)
            os.remove(zip_pack_path)

        print(f"Uploaded {self._pack_name} pack to {pack_full_path} path.")

    def format_metadata(self):
        if Pack.METADATA not in os.listdir(self._pack_path):
            print_error(f"{self._pack_name} pack is missing {Pack.METADATA} file.")
            sys.exit(1)

        metadata_path = os.path.join(self._pack_path, Pack.METADATA)

        with open(metadata_path, "r+") as metadata_file:
            user_metadata = json.load(metadata_file)
            formatted_metadata = self._parse_pack_metadata(user_metadata)
            metadata_file.seek(0)
            json.dump(formatted_metadata, metadata_file, indent=4)

    def prepare_for_index_upload(self):
        files_to_leave = [Pack.METADATA, Pack.CHANGELOG, Pack.README]

        for file_or_folder in os.listdir(self._pack_path):
            files_or_folder_path = os.path.join(self._pack_path, file_or_folder)

            if file_or_folder in files_to_leave:
                continue

            if os.path.isdir(files_or_folder_path):
                shutil.rmtree(files_or_folder_path)
            else:
                os.remove(files_or_folder_path)

    def cleanup(self):
        if os.path.exists(self._pack_path):
            shutil.rmtree(self._pack_path)


def get_modified_packs(is_circle=False, specific_pack=None):
    if not is_circle:
        return {specific_pack}

    cmd = f"git diff --name-only HEAD..HEAD^ | grep 'Packs/'"
    modified_packs_path = run_command(cmd, use_shell=True).splitlines()
    modified_packs = {p.split('/')[1] for p in modified_packs_path}
    print(f"Number of modified packs is: {len(modified_packs)}")

    return modified_packs


def extract_modified_packs(modified_packs, packs_artifacts_path, extract_destination_path):
    with ZipFile(packs_artifacts_path) as packs_artifacts:
        for pack in packs_artifacts.namelist():
            for modified_pack in modified_packs:

                if pack.startswith(f"{modified_pack}/"):
                    packs_artifacts.extract(pack, extract_destination_path)
                    print(f"Extracted {pack} to path: {extract_destination_path}")


def init_storage_client(is_circle=False, service_account_key_file=None):
    if is_circle and not service_account_key_file:
        print_error("Missing path to service account json key file.")
        sys.exit(1)

    if is_circle:
        return storage.Client.from_service_account_json(service_account_key_file)
    else:
        credentials, project = google.auth.default()
        return storage.Client(credentials=credentials, project=project)


def download_and_extract_index(storage_bucket, extract_destination_path, index_file_name="index"):
    index_storage_path = os.path.join(STORAGE_BASE_PATH, f"{index_file_name}.zip")
    download_index_path = os.path.join(extract_destination_path, f"{index_file_name}.zip")

    index_blob = storage_bucket.blob(index_storage_path)
    index_blob.download_to_filename(download_index_path)

    if os.path.exists(download_index_path):
        with ZipFile(download_index_path, 'r') as index_zip:
            index_zip.extractall(extract_destination_path)

        if index_file_name not in os.listdir(extract_destination_path):
            print_error(f"Extracted index folder name does not match: {index_file_name}")
            sys.exit(1)

        os.remove(download_index_path)

        return os.path.join(extract_destination_path, index_file_name), index_blob
    else:
        print_error(f"Failed to download {index_file_name} file from cloud storage.")
        sys.exit(1)


def update_index_folder(index_folder_path, pack_name, pack_path):
    index_folder_subdirectories = [d for d in os.listdir(index_folder_path) if
                                   os.path.isdir(os.path.join(index_folder_path, d))]
    index_pack_path = os.path.join(index_folder_path, pack_name)

    if pack_name in index_folder_subdirectories:
        shutil.rmtree(index_pack_path)
    shutil.copytree(pack_path, index_pack_path)


def upload_index_to_storage(index_folder_path, extract_destination_path, index_blob, build_number):
    index_zip_name = os.path.basename(index_folder_path)

    if Pack.INDEX_JSON not in os.listdir(index_folder_path):
        # todo create new index.json in case index doesn't exist
        # todo remove exit statement when creation code implemented
        sys.exit()

    with open(os.path.join(index_folder_path, Pack.INDEX_JSON), "r+") as index_file:
        index = json.load(index_file)
        index['revision'] = build_number
        index['modified'] = datetime.utcnow().strftime(Pack.DATE_FORMAT)
        index_file.seek(0)
        json.dump(index, index_file, indent=4)
        index_file.truncate()

    index_zip_path = shutil.make_archive(os.path.join(extract_destination_path, index_zip_name), format="zip",
                                         root_dir=index_folder_path)

    index_blob.upload_from_filename(index_zip_path)
    os.remove(index_zip_path)
    shutil.rmtree(index_folder_path)


def option_handler():
    parser = argparse.ArgumentParser(description="Store packs in cloud storage.")
    parser.add_argument('-a', '--artifactsPath', help="The full path of packs artifacts", required=True)
    parser.add_argument('-e', '--extractPath', help="Full path of folder to extract wanted packs", required=True)
    parser.add_argument('-c', '--circleCi', help="Whether run script locally or in circleCi", default=False)
    parser.add_argument('-p', '--packName', help="Use only in local mode, the target pack name to store.",
                        required=False, default="")
    parser.add_argument('-b', '--bucketName', help="Storage bucket name", required=True)
    parser.add_argument('-n', '--ciBuildNumber',
                        help="CircleCi build number (will be used as hash revision at index file)", required=False)

    return parser.parse_args()


def main():
    option = option_handler()
    packs_artifacts_path = option.artifactsPath
    extract_destination_path = option.extractPath
    storage_bucket_name = option.bucketName
    is_circle = option.circleCi
    specific_pack = option.packName
    build_number = option.ciBuildNumber if option.ciBuildNumber else str(uuid.uuid4())

    storage_client = init_storage_client(is_circle)
    storage_bucket = storage_client.get_bucket(storage_bucket_name)

    modified_packs = get_modified_packs(is_circle, specific_pack)
    extract_modified_packs(modified_packs, packs_artifacts_path, extract_destination_path)
    packs_list = [Pack(pack_name, os.path.join(extract_destination_path, pack_name), storage_bucket)
                  for pack_name in modified_packs]

    index_folder_path, index_blob = download_and_extract_index(storage_bucket, extract_destination_path)

    for pack in packs_list:
        pack.format_metadata()
        zip_pack_path = pack.zip_pack()
        pack.upload_to_storage(zip_pack_path, pack.latest_version)
        pack.prepare_for_index_upload()
        update_index_folder(index_folder_path=index_folder_path, pack_name=pack.name, pack_path=pack.path)
        pack.cleanup()

    # todo need permissions to override index.zip in the bucket
    upload_index_to_storage(index_folder_path, extract_destination_path, index_blob, build_number)


if __name__ == '__main__':
    main()
