import argparse
import json
import os
from concurrent.futures import ThreadPoolExecutor
import shutil
import sys
import logging
from time import sleep
from zipfile import ZipFile
from Tests.Marketplace.marketplace_services import init_storage_client, IGNORED_FILES, PACKS_FULL_PATH
from Tests.scripts.utils.log_util import install_logging
from demisto_sdk.commands.common.tools import LooseVersion, str2bool

ARTIFACT_NAME = 'content_marketplace_packs.zip'
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
    parser.add_argument('-pvt', '--private', type=str2bool, help='Indicates if the tools is running '
                                                                 'on a private build.',
                        required=False, default=False)
    parser.add_argument('-rt', '--remove_test_playbooks', type=str2bool,
                        help='Whether to remove test playbooks from content packs or not.', default=True)

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
                logging.info(f'Adding {name} to the zip file')
                zf.write(path, f'{name}.zip')


def remove_test_playbooks_if_exist(zips_path, packs):
    """
    If a pack has test playbooks, the function extracts the pack, removes the test playbooks and zips the pack again.
    Args:
        zips_path: The path where the pack zips are.
        packs: The packs name and path.
    """
    for zip_pack in packs:
        for name, path in zip_pack.items():
            remove = False
            with ZipFile(path, mode='r') as pack_zip:
                zip_contents = pack_zip.namelist()
                dir_names = [os.path.basename(os.path.dirname(content)) for content in zip_contents]
                if 'TestPlaybooks' in dir_names:
                    remove = True
                    logging.info(f'Removing TestPlaybooks from the pack {name}')
                    new_path = os.path.join(zips_path, name)
                    os.mkdir(new_path)
                    pack_zip.extractall(path=new_path,
                                        members=(member for member in zip_contents if 'TestPlaybooks' not in member))
                    remove_test_playbooks_from_signatures(new_path, zip_contents)
            if remove:
                # Remove the current pack zip
                os.remove(path)
                shutil.make_archive(new_path, 'zip', new_path)


def remove_test_playbooks_from_signatures(path, filenames):
    """
    Remove the test playbook entries from the signatures file
    Args:
        path: The path of the pack
        filenames: The names of the files in the pack

    """
    signature_file_path = os.path.join(path, 'signatures.sf')
    test_playbooks = [file_ for file_ in filenames if 'TestPlaybooks' in file_]
    if os.path.isfile(signature_file_path):
        with open(signature_file_path, 'r') as signature_file:
            signature = json.load(signature_file)
            for test_playbook in test_playbooks:
                del signature[test_playbook]
        with open(signature_file_path, 'w') as signature_file:
            json.dump(signature, signature_file)
    else:
        logging.warning(f'Could not find signatures in the pack {os.path.basename(os.path.dirname(path))}')


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

            if gcp_path == BUILD_GCP_PATH:
                pack_prefix = os.path.join(gcp_path, branch_name, circle_build, 'content', 'packs', pack.name)
            else:
                pack_prefix = os.path.join(gcp_path, branch_name, circle_build, pack.name)

            if not branch_name or not circle_build:
                pack_prefix = pack_prefix.replace('/builds/content', '')

            # Search for the pack in the bucket
            blobs = list(storage_bucket.list_blobs(prefix=pack_prefix))
            if blobs:
                blob = get_latest_pack_zip_from_blob(pack.name, blobs)
                if not blob:
                    logging.warning(f'Failed to get the zip of the pack {pack.name} from GCP')
                    continue
                download_path = os.path.join(destination_path, f"{pack.name}.zip")
                zipped_packs.append({pack.name: download_path})
                logging.info(f'Downloading pack from GCP: {pack.name}')
                executor_submit(executor, download_path, blob)
                sleep(1)
                if os.path.exists('/home/runner/work/content-private/content-private/content/artifacts/'):
                    logging.info(f"Copying pack from {download_path} to /home/runner/work/content-private/"
                                 f"content-private/content/artifacts/packs/{pack.name}.zip")
                    shutil.copy(download_path,
                                f'/home/runner/work/content-private/content-private/content/artifacts/'
                                f'packs/{pack.name}.zip')
            else:
                logging.warning(f'Did not find a pack to download with the prefix: {pack_prefix}')

    if not zipped_packs:
        logging.critical('Did not find any pack to download from GCP.')
        sys.exit(1)
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
    install_logging('Zip_Content_Packs_From_GCS.log')
    option = option_handler()
    storage_bucket_name = option.bucket_name
    zip_path = option.zip_path
    artifacts_path = option.artifacts_path
    service_account = option.service_account
    circle_build = option.circle_build
    branch_name = option.branch_name
    gcp_path = option.gcp_path
    remove_test_playbooks = option.remove_test_playbooks
    private_build = option.private
    if private_build:
        packs_dir = '/home/runner/work/content-private/content-private/content/artifacts/packs'
        zip_path = '/home/runner/work/content-private/content-private/content/temp-dir'
        if not os.path.exists(packs_dir):
            logging.debug("Packs dir not found. Creating.")
            os.mkdir(packs_dir)
        if not os.path.exists(zip_path):
            logging.debug("Temp dir not found. Creating.")
            os.mkdir(zip_path)
        artifacts_path = '/home/runner/work/content-private/content-private/content/artifacts'

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
    except Exception:
        logging.exception('Failed downloading packs')
        success = False

    if remove_test_playbooks:
        try:
            remove_test_playbooks_if_exist(zip_path, zipped_packs)
        except Exception:
            logging.exception('Failed removing test playbooks from packs')
            success = False

    if zipped_packs and success:
        try:
            zip_packs(zipped_packs, zip_path)
        except Exception:
            logging.exception('Failed zipping packs')
            success = False

        if success:
            logging.info('Successfully zipped packs.')
            if artifacts_path:
                # Save in the artifacts
                shutil.copy(os.path.join(zip_path, ARTIFACT_NAME), os.path.join(artifacts_path, ARTIFACT_NAME))
        else:
            logging.critical('Failed zipping packs.')
            sys.exit(1)
    else:
        logging.warning('Did not find any packs to zip.')

    cleanup(zip_path)


if __name__ == '__main__':
    main()
