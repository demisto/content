import json
import os
import sys
import argparse

from os import path
from zipfile import ZipFile, ZIP_DEFLATED
from Tests.test_utils import run_command, print_error
from google.cloud import storage
import google.auth


def option_handler():
    parser = argparse.ArgumentParser(description="Store packs in cloud storage.")
    parser.add_argument('-a', '--artifactsPath', help="The full path of packs artifacts", required=True)
    parser.add_argument('-e', '--extractPath', help="Full path of folder to extract wanted packs", required=True)
    parser.add_argument('-c', '--circleCi', help="Whether run script locally or in circleCi", default=False)
    parser.add_argument('-p', '--packName', help="Use only in local mode, the target pack name to store.",
                        required=False, default="")
    parser.add_argument('-b', '--bucketName', help="Storage bucket name", required=True)

    return parser.parse_args()


class PackStorage:
    CHANGELOG = "changelog.json"
    PACK_INITIAL_VERSION = "1.0.0"

    def __init__(self, pack_name, pack_path, storage_bucket):
        self.pack_name = pack_name
        self.pack_path = pack_path
        self.storage_bucket = storage_bucket

    @property
    def latest_version(self):
        return self._get_latest_version()

    def _get_latest_version(self):
        if self.CHANGELOG not in os.listdir(self.pack_path):
            return self.PACK_INITIAL_VERSION

        changelog_path = path.join(self.pack_path, self.CHANGELOG)

        with open(changelog_path, "r") as changelog:
            changelog_json = json.load(changelog)

            pack_versions = list(changelog_json.keys())
            pack_versions.sort(key=lambda str_version: [int(v) for v in str_version.split(".")],
                               reverse=True)

            return pack_versions[0]

    def zip_pack(self):
        zip_pack_path = f"{self.pack_path}.zip"

        with ZipFile(zip_pack_path, 'w', ZIP_DEFLATED) as pack_zip:
            for root, dirs, files in os.walk(self.pack_path):
                for f in files:
                    full_file_path = path.join(root, f)
                    relative_file_path = path.relpath(full_file_path, self.pack_path)
                    pack_zip.write(filename=full_file_path, arcname=relative_file_path)

        return zip_pack_path

    def store_pack(self, zip_pack_path, latest_version):
        version_pack_path = f"content/packs/{self.pack_name}/{latest_version}"
        existing_files = [f.name for f in self.storage_bucket.list_blobs(prefix=version_pack_path)]

        if len(existing_files) > 0:
            print_error(f"The following packs already exist at storage: {', '.join(existing_files)}")
            print_error(f"Skipping step of uploading {self.pack_name}.zip to storage.")
            sys.exit(1)

        pack_full_path = f"{version_pack_path}/{self.pack_name}.zip"
        blob = self.storage_bucket.blob(pack_full_path)

        with open(zip_pack_path, "rb") as pack_zip:
            blob.upload_from_file(pack_zip)

        print(f"Uploaded {self.pack_name} pack to {pack_full_path} path.")


def get_modified_packs(is_circle=False, specific_pack=None):
    if not is_circle:
        return [specific_pack]

    cmd = f"git diff --name-only HEAD..HEAD^ | grep 'Packs/'"
    modified_packs_path = run_command(cmd, use_shell=True).splitlines()
    modified_packs = [p.split('/')[1] for p in modified_packs_path]
    print(f"Number of modified packs is: {len(modified_packs)}")

    return modified_packs


def extract_modified_packs(modified_packs, packs_artifacts_path, extract_destination_path):
    with ZipFile(packs_artifacts_path) as packs_artifacts:
        for pack in packs_artifacts.namelist():
            for modified_pack in modified_packs:

                if pack.startswith(f"{modified_pack}/"):
                    packs_artifacts.extract(pack, extract_destination_path)

    print(f"Extracted {', '.join(modified_packs)} packs to path: {extract_destination_path}")


def init_storage_client(is_circle=False, service_account_key_file=None):
    if is_circle and not service_account_key_file:
        print_error("Missing path to service account json key file.")
        sys.exit(1)

    if is_circle:
        return storage.Client.from_service_account_json(service_account_key_file)
    else:
        credentials, project = google.auth.default()
        return storage.Client(credentials=credentials, project=project)


def main():
    option = option_handler()
    packs_artifacts_path = option.artifactsPath
    extract_destination_path = option.extractPath
    storage_bucket_name = option.bucketName
    is_circle = option.circleCi
    specific_pack = option.packName

    storage_client = init_storage_client(is_circle)
    storage_bucket = storage_client.get_bucket(storage_bucket_name)

    modified_packs = get_modified_packs(is_circle, specific_pack)
    extract_modified_packs(modified_packs, packs_artifacts_path, extract_destination_path)
    pack_storage_list = [PackStorage(pack_name, path.join(extract_destination_path, pack_name), storage_bucket)
                         for pack_name in modified_packs]

    for pack_storage in pack_storage_list:
        latest_version = pack_storage.latest_version
        zip_pack_path = pack_storage.zip_pack()
        pack_storage.store_pack(zip_pack_path, latest_version)


if __name__ == '__main__':
    main()
