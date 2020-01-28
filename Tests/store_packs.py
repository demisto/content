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
from Tests.test_utils import run_command, print_error, collect_content_items_data

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
    CHANGELOG_JSON = "changelog.json"
    CHANGELOG_MD = "changelog.md"
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
        if Pack.CHANGELOG_JSON not in os.listdir(self._pack_path):
            return self.PACK_INITIAL_VERSION

        changelog_path = os.path.join(self._pack_path, Pack.CHANGELOG_JSON)

        with open(changelog_path, "r") as changelog:
            changelog_json = json.load(changelog)

            pack_versions = list(changelog_json.keys())
            pack_versions.sort(key=lambda str_version: [int(v) for v in str_version.split(".")],
                               reverse=True)

            return pack_versions[0]

    def _parse_pack_metadata(self, user_metadata):
        pack_metadata = {}
        pack_metadata['id'] = self._pack_name
        pack_metadata['name'] = user_metadata.get('displayName', '')
        pack_metadata['description'] = user_metadata.get('description', '')
        pack_metadata['created'] = user_metadata.get('created', '')
        pack_metadata['updated'] = datetime.utcnow().strftime(Pack.DATE_FORMAT)
        pack_metadata['support'] = user_metadata.get('support', '')
        is_beta = user_metadata.get('beta', False)
        pack_metadata['beta'] = bool(strtobool(is_beta)) if isinstance(is_beta, str) else is_beta
        pack_metadata['certification'] = user_metadata.get('certification', '')
        is_deprecated = user_metadata.get('deprecated', False)
        pack_metadata['deprecated'] = bool(strtobool(is_beta)) if isinstance(is_deprecated, str) else is_deprecated
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
        pack_metadata['tags'] = user_metadata.get('tags', [])
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
            # todo important, for now print warning and don't fail the build on it
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

    def parse_release_notes(self):
        if Pack.CHANGELOG_MD not in os.listdir(self._pack_path):
            print_error(f"The pack {self._pack_name} is missing {Pack.CHANGELOG_MD} file.")
            sys.exit(1)

        changelog_md_path = os.path.join(self._pack_path, Pack.CHANGELOG_MD)

        with open(changelog_md_path, 'r') as release_notes_file:
            release_notes = release_notes_file.read
            # todo implement release notes logic and create changelog.json
            pass

    def prepare_for_index_upload(self):
        files_to_leave = [Pack.METADATA, Pack.CHANGELOG_JSON, Pack.README]

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


def get_modified_packs(specific_packs=None):
    if specific_packs:
        return [p.strip() for p in specific_packs.split(',')]

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


def init_storage_client(service_account=None):
    if service_account:
        return storage.Client.from_service_account_json(service_account)
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
    with open(os.path.join(index_folder_path, Pack.INDEX_JSON), "w+") as index_file:
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
    index_zip_path = shutil.make_archive(os.path.join(extract_destination_path, index_zip_name), format="zip",
                                         root_dir=index_folder_path)

    index_blob.upload_from_filename(index_zip_path)
    os.remove(index_zip_path)
    shutil.rmtree(index_folder_path)


def option_handler():
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
                        help="Comma separated list of target pack names. Is used only in local dev mode.",
                        required=False, default="")
    parser.add_argument('-b', '--bucket_name', help="Storage bucket name", required=True)
    parser.add_argument('-n', '--ci_build_number',
                        help="CircleCi build number (will be used as hash revision at index file)", required=False)
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

    storage_client = init_storage_client(service_account)
    storage_bucket = storage_client.get_bucket(storage_bucket_name)

    modified_packs = get_modified_packs(specific_packs)
    extract_modified_packs(modified_packs, packs_artifacts_path, extract_destination_path)
    packs_list = [Pack(pack_name, os.path.join(extract_destination_path, pack_name), storage_bucket)
                  for pack_name in modified_packs]

    index_folder_path, index_blob = download_and_extract_index(storage_bucket, extract_destination_path)

    for pack in packs_list:
        pack.format_metadata()
        # todo finish implementation of release notes
        # pack.parse_release_notes()
        zip_pack_path = pack.zip_pack()
        pack.upload_to_storage(zip_pack_path, pack.latest_version)
        pack.prepare_for_index_upload()
        update_index_folder(index_folder_path=index_folder_path, pack_name=pack.name, pack_path=pack.path)
        pack.cleanup()

    upload_index_to_storage(index_folder_path, extract_destination_path, index_blob, build_number)


if __name__ == '__main__':
    main()
