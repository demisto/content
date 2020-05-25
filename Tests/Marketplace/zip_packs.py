import argparse
import os
from concurrent.futures import ThreadPoolExecutor
import shutil
from zipfile import ZipFile
from Tests.Marketplace.marketplace_services import init_storage_client, GCPConfig, IGNORED_FILES, PACKS_FULL_PATH

from demisto_sdk.commands.common.tools import print_error, print_success, print_warning, LooseVersion

ARTIFACT_NAME = 'zipped_packs.zip'
MAX_THREADS = 4
BUILD_GCP_PATH = 'content/builds'


def option_handler():
    """Validates and parses script arguments.

    Returns:
        Namespace: Parsed arguments object.

    """
    parser = argparse.ArgumentParser(description="Zip packs from a GCP bucket.")
    # disable-secrets-detection-start
    parser.add_argument('-a', '--artifacts_path', help="Path of the CircleCI artifacts to save the zip file in",
                        required=False)
    parser.add_argument('-gp', '--gcp_path', help="Path of the content packs in the GCP bucket",
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
    """

    with ZipFile(os.path.join(destination_path, ARTIFACT_NAME), mode='w') as zf:
        for zip_pack in packs:
            for name, path in zip_pack.items():
                print(f'Adding {name} to the zip file')
                zf.write(path, f"{name}.zip")


def download_packs_from_gcp(storage_bucket, gcp_path, destination_path, circle_build, branch_name):
    """
    Iterates over the Packs directory in the content repository and downloads each pack (if found) from a GCP bucket
    in parallel.
    Args:
        storage_bucket: The GCP bucket to download from.
        gcp_path: The path of the packs in the GCP bucket.
        destination_path: The path to download the packs to.
        branch_name: The branch name of the build.
        circle_build: The number of the circle ci build.

    Returns:
        zipped_packs: A list of the downloaded packs paths and their corresponding pack names.
    """
    zipped_packs = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        for pack in os.scandir(PACKS_FULL_PATH):  # Get all the pack names
            if pack.name in IGNORED_FILES:
                continue
            # Search for the pack in the bucket
            pack_prefix = os.path.join(gcp_path, branch_name, circle_build, pack.name)
            blobs = list(storage_bucket.list_blobs(prefix=pack_prefix))
            if blobs:
                blob = get_latest_pack_zip_from_blob(pack.name, blobs)
                if not blob:
                    print_warning(f'Failed to get the zip of the pack {pack.name} from GCP')
                    continue
                download_path = os.path.join(destination_path, f"{pack.name}.zip")
                zipped_packs.append({pack.name: download_path})
                print(f'Downloading pack from GCP: {pack.name}')
                executor_submit(executor, download_path, blob)
            else:
                print_warning(f'Did not find a pack to download with the prefix: {pack_prefix}')

    return zipped_packs


def executor_submit(executor, download_path, blob):
    executor.submit(blob.download_to_filename, download_path)


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


def get_latest_pack_zip_from_blob(pack, blobs):
    """
    Returns the latest zip of a pack from a list of blobs.
    Args:
        pack: The pack name
        blobs: The blob list

    Returns:
        blob: The zip blob of the pack with the latest version.
    """
    blob = None
    blobs = [b for b in blobs if os.path.splitext(os.path.basename(b.name))[0] == pack and b.name.endswith('.zip')]
    if blobs:
        blobs = sorted(blobs, key=lambda b: LooseVersion(os.path.basename(os.path.dirname(b.name))), reverse=True)
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
    gcp_path = option.gcp_path

    # google cloud storage client initialized
    storage_client = init_storage_client(service_account)
    storage_bucket = storage_client.bucket(storage_bucket_name)

    if not circle_build or not branch_name:
        # Ignore build properties
        circle_build = ''
        branch_name = ''

    if not gcp_path:
        gcp_path = BUILD_GCP_PATH

    zipped_packs = []
    success = True
    try:
        zipped_packs = download_packs_from_gcp(storage_bucket, gcp_path, zip_path, circle_build, branch_name)
    except Exception as e:
        print_error(f'Failed downloading packs: {e}')
        success = False

    if zipped_packs:
        try:
            zip_packs(zipped_packs, zip_path)
        except Exception as e:
            print_error(f'Failed zipping packs: {e}')
            success = False

        if success:
            print_success('Successfully zipped packs.')
        else:
            print_error('Failed zipping packs.')

        cleanup(zip_path)

        if artifacts_path:
            # Save in the artifacts
            shutil.copy(os.path.join(zip_path, ARTIFACT_NAME), os.path.join(artifacts_path, ARTIFACT_NAME))
    else:
        print_warning('Did not find any packs to zip.')


if __name__ == '__main__':
    main()
