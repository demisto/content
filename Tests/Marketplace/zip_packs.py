import argparse
import os
import shutil
from zipfile import ZipFile
from Tests.Marketplace.marketplace_services import init_storage_client,\
    CORE_PACKS, GCPConfig, IGNORED_FILES, PACKS_FULL_PATH, Pack

from demisto_sdk.commands.common.tools import print_error, print_success, LooseVersion

ARTIFACT_NAME = 'zipped_packs.zip'
ARTIFACT_PATH = '/home/circleci/project/artifacts'


def option_handler():
    """Validates and parses script arguments.

    Returns:
        Namespace: Parsed arguments object.

    """
    parser = argparse.ArgumentParser(description="Zip packs from a GCP bucket.")
    # disable-secrets-detection-start
    parser.add_argument('-a', '--artifacts_path', help="Path of the CircleCI artifacts to save the zip file in",
                        required=False)
    parser.add_argument('-z', '--zip_path', help="Full path of folder to zip packs in", required=True)
    parser.add_argument('-b', '--bucket_name', help="Storage bucket name", required=True)
    parser.add_argument('-br', '--branch_name', help="Name of the branch", required=False)
    parser.add_argument('-n', '--circle_build', help="Number of the circle build", required=False)
    parser.add_argument('-s', '--service_account',
                        help=("Path to gcloud service account, is for circleCI usage. "
                              "For local development use your personal account and "
                              "authenticate using Google Cloud SDK by running: "
                              "`gcloud auth application-default login` and leave this parameter blank. "
                              "For more information go to: "
                              "https://googleapis.dev/python/google-api-core/latest/auth.html"),
                        required=False)

    return parser.parse_args()


def zip_packs(packs, destination_path):
    """
    Zips packs to a provided path.
    Args:
        packs: The packs to zip
        destination_path: The destination path to zip the packs in.

    Returns:
        success: Whether the operation succeeded.
    """

    success = True
    zf = ZipFile(os.path.join(destination_path, ARTIFACT_NAME), mode='w')
    try:
        for zip_pack in packs:
            for name, path in zip_pack.items():
                print(f'Zipping {path}')
                zf.write(path, f"{name}.zip")
    except Exception as e:
        print_error(f'Failed adding packs to the zip file: {e}')
        success = False
    finally:
        zf.close()

    return success


def download_packs_from_gcp(storage_bucket, destination_path, circle_build, branch_name):
    """
    Iterates over the Packs directory in the content repository and downloads each pack (if found) from a GCP bucket.
    Args:
        storage_bucket: The GCP bucket to download from.
        destination_path: The path to download the packs to.
        branch_name: The branch name of the build.
        circle_build: The number of the circle ci build.

    Returns:
        zipped_packs: A list of the downloaded packs paths and their corresponding pack names.
    """
    zipped_packs = []
    for pack_dir in os.scandir(PACKS_FULL_PATH):  # Get all the pack names
        if pack_dir.name in IGNORED_FILES + CORE_PACKS:
            continue
        pack = Pack(pack_dir.name, pack_dir.path)
        # Search for the pack in the bucket
        pack_prefix = os.path.join(GCPConfig.STORAGE_BASE_PATH, branch_name, circle_build, pack.name,
                                   pack.latest_version)
        blobs = list(storage_bucket.list_blobs(prefix=pack_prefix))
        if blobs:
            blob = get_pack_zip_from_blob(blobs)
            download_path = os.path.join(destination_path, f"{pack.name}.zip")
            zipped_packs.append({pack.name: download_path})
            print(f'Downloading pack from GCP: {pack.name}')
            blob.download_to_filename(download_path)

    return zipped_packs


def cleanup(destination_path):
    """
    Cleans up the destination path directory by removing everything except the packs zip.
    Args:
        destination_path: The destination path.
    """
    files_to_remove = [file_.path for file_ in os.scandir(destination_path) if file_.name != ARTIFACT_NAME]
    for file_ in files_to_remove:
        if os.path.isdir(file_):
            shutil.rmtree(file_)
        else:
            os.remove(file_)


def get_pack_zip_from_blob(blobs):
    """
    Returns the zip pack from a list of blobs in a pack.
    Args:
        blobs: The zip blob of a specific pack.

    Returns:
        blob: The zip blob of the pack.
    """
    blobs = [b for b in blobs if b.name.endswith('.zip')]
    blob = blobs[0]

    return blob


def main():
    option = option_handler()
    storage_bucket_name = option.bucket_name
    zip_path = option.zip_path
    artifacts_path = option.artifacts_path
    service_account = option.service_account
    circle_build = option.circle_build
    branch_name = option.branch_name

    # google cloud storage client initialized
    storage_client = init_storage_client(service_account)
    storage_bucket = storage_client.bucket(storage_bucket_name)

    if not circle_build or not branch_name:
        # Ignore build properties
        circle_build = ''
        branch_name = ''

    zipped_packs = []
    success = True
    try:
        zipped_packs = download_packs_from_gcp(storage_bucket, zip_path, circle_build, branch_name)
    except Exception as e:
        print_error(f'Failed downloading packs: {e}')
        success = False

    if zipped_packs:
        success = zip_packs(zipped_packs, zip_path)

    if success:
        print_success('Successfully zipped packs.')
    else:
        print_error('Failed zipping packs.')

    cleanup(zip_path)

    if artifacts_path:
        # Save in the artifacts
        shutil.copy(os.path.join(zip_path, ARTIFACT_NAME), os.path.join(artifacts_path, ARTIFACT_NAME))


if __name__ == '__main__':
    main()
