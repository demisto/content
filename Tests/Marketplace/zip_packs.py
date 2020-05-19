import argparse
import os
import shutil
from google.cloud import storage
from datetime import datetime
from zipfile import ZipFile
from Tests.Marketplace.marketplace_services import Pack, PackStatus, GCPConfig, PACKS_FULL_PATH, IGNORED_FILES, \
    PACKS_FOLDER, IGNORED_PATHS, Metadata

from Tests.Marketplace.upload_packs import init_storage_client, extract_packs_artifacts
from demisto_sdk.commands.common.tools import print_error


def option_handler():
    """Validates and parses script arguments.

    Returns:
        Namespace: Parsed arguments object.

    """
    parser = argparse.ArgumentParser(description="Zip packs from a GCP bucket.")
    # disable-secrets-detection-start
    parser.add_argument('-a', '--artifacts_path', help="The full path of packs artifacts", required=True)
    parser.add_argument('-p', '--path', help="Full path of folder to extract wanted packs", required=True)
    parser.add_argument('-b', '--bucket_name', help="Storage bucket name", required=True)
    parser.add_argument('-s', '--service_account',
                        help=("Path to gcloud service account, is for circleCI usage. "
                              "For local development use your personal account and "
                              "authenticate using Google Cloud SDK by running: "
                              "`gcloud auth application-default login` and leave this parameter blank. "
                              "For more information go to: "
                              "https://googleapis.dev/python/google-api-core/latest/auth.html"),
                        required=False)

    return parser.parse_args()


def zip_packs(storage_bucket, packs_artifacts_path, destination_path):
    extract_packs_artifacts(packs_artifacts_path, destination_path)
    zipped_packs = []
    for pack in os.scandir(destination_path):
        pack_path = os.path.join(GCPConfig.STORAGE_BASE_PATH, pack.name)
        blobs = list(storage_bucket.list_blobs(prefix=pack_path))
        if blobs:
            for blob in blobs:
                print(blob.name)
            blob = blobs[0]
            download_path = os.path.join(destination_path, f"{pack.name}.zip")
            zipped_packs.append({pack.name: download_path})
            print(f'Downloading pack: {pack.name}')
            blob.cache_control = "no-cache"  # index zip should never be cached in the memory, should be updated version
            blob.reload()
            blob.download_to_filename(download_path)

    print(f'Zipping packs.')
    zf = ZipFile(os.path.join(destination_path, 'Packs.zip'), mode='w')
    try:
        for zip_pack in zipped_packs:
            for name, path in zip_pack.items():
                print(f'Zipping {path}')
                zf.write(path, f"{name}.zip")
    except Exception as e:
        print_error(f'Failed to zip packs: {e}')
    finally:
        zf.close()

    files_to_remove = [file_.path for file_ in os.scandir(destination_path) if file_.name != 'Packs.zip']
    for file_ in files_to_remove:
        if os.path.isdir(file_):
            shutil.rmtree(file_)
        else:
            os.remove(file_)


def main():
    option = option_handler()
    packs_artifacts_path = option.artifacts_path
    storage_bucket_name = option.bucket_name
    extract_destination_path = option.path
    service_account = option.service_account

    # google cloud storage client initialized
    storage_client = init_storage_client(service_account)
    storage_bucket = storage_client.bucket(storage_bucket_name)

    zip_packs(storage_bucket, packs_artifacts_path, extract_destination_path)


if __name__ == '__main__':
    main()
