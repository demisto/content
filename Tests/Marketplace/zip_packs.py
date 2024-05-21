import argparse
import json
import os
import shutil
import sys
import logging
from packaging.version import Version
from zipfile import ZipFile
from Tests.Marketplace.marketplace_constants import IGNORED_FILES, PACKS_FULL_PATH
from Tests.scripts.utils.log_util import install_logging
from demisto_sdk.commands.common.tools import str2bool, get_files_in_dir
from pathlib import Path

ARTIFACT_NAME = 'content_marketplace_packs.zip'


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

    return parser.parse_args()


def zip_packs(zipped_packs, destination_path):
    """
    Zips packs to a provided path.
    Args:
        zipped_packs: A dictionary containing pack name as key and it's latest zip path as value
        destination_path: The destination path to zip the packs in.
    """
    with ZipFile(os.path.join(destination_path, ARTIFACT_NAME), mode='w') as zf:
        for key, value in zipped_packs.items():
            logging.info(f'Adding {key} to the zip file')
            zf.write(value, f'{key}.zip')


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
                    pack_path = os.path.join(zips_path, name)
                    pack_zip.extractall(path=pack_path,
                                        members=(member for member in zip_contents if 'TestPlaybooks' not in member))
                    remove_test_playbooks_from_signatures(pack_path, zip_contents)
            if remove:
                # Remove the current pack zip
                os.remove(path)
                shutil.make_archive(pack_path, 'zip', pack_path)


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


def get_zipped_packs_names(zip_path):
    """
    Creates a list of dictionaries containing a pack name as key and the latest zip file path of the pack as value.
    Args:
        zip_path: path containing all the packs copied from the storage bucket
    Returns:
        A dictionary containing each pack name and it's zip path.
        {'Slack': 'content/packs/slack/1.3.19/slack.zip', 'qualys': 'content/packs/qualys/2.0/qualys.zip'}
    """
    zipped_packs = {}
    zip_path = os.path.join(zip_path, 'packs')  # directory of the packs

    dir_entries = os.listdir(zip_path)
    packs_list = [pack.name for pack in os.scandir(PACKS_FULL_PATH)]  # list of all packs from repo

    for entry in dir_entries:
        entry_path = os.path.join(zip_path, entry)
        if entry not in IGNORED_FILES and entry in packs_list and os.path.isdir(entry_path):
            # This is a pack directory, should keep only most recent release zip
            pack_files = get_files_in_dir(entry_path, ['zip'])
            latest_zip = get_latest_pack_zip_from_pack_files(entry, pack_files)
            if not latest_zip:
                logging.warning(f'Failed to get the zip of the pack {entry} from GCP')
                continue
            logging.info(f"Found latest zip of {entry}, which is {latest_zip}")
            zipped_packs[Path(latest_zip).stem] = latest_zip

    if not zipped_packs:
        raise Exception('No zip files were found')
    return zipped_packs


def copy_zipped_packs_to_artifacts(zipped_packs, artifacts_path):
    """
    Copies zip files if needed
    Args:
        zipped_packs: A dictionary containing pack name as key and it's latest zip path as value
        artifacts_path: Path of the artifacts folder
    """
    if os.path.exists(artifacts_path):
        for key, value in zipped_packs.items():
            logging.info(f"Copying pack from {value} to {artifacts_path}/packs/{key}.zip")
            shutil.copy(value, f'{artifacts_path}/packs/{key}.zip')


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


def get_latest_pack_zip_from_pack_files(pack, pack_files):
    """
    Returns the latest zip of a pack from a list of blobs.
    Args:
        pack: The pack name
        pack_files: A list of string which are paths of the pack's files
    Returns:
        latest_zip_path: The zip path of the pack with the latest version.
    """
    latest_zip_path = None
    latest_zip_version = None
    for current_file_path in pack_files:
        current_pack_name = os.path.splitext(os.path.basename(current_file_path))[0]
        if current_pack_name == pack and current_file_path.endswith('.zip'):
            current_pack_zip_version = Version(os.path.basename(os.path.dirname(current_file_path)))
            if not latest_zip_version or latest_zip_version < current_pack_zip_version:
                latest_zip_version = current_pack_zip_version
                latest_zip_path = current_file_path

    return latest_zip_path


def main():
    install_logging('Zip_Content_Packs_From_GCS.log')
    option = option_handler()
    zip_path = option.zip_path
    artifacts_path = option.artifacts_path
    private_build = option.private

    zipped_packs = {}
    success = True
    try:
        zipped_packs = get_zipped_packs_names(zip_path)
    except Exception as e:
        logging.exception(f'Failed to get zipped packs names, {e}')
        success = False

    if private_build:
        try:
            copy_zipped_packs_to_artifacts(zipped_packs, artifacts_path)
        except Exception as e:
            logging.exception(f'Failed to copy to artifacts, {e}')
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
    else:
        logging.warning('Failed to perform zip content packs from GCS step.')

    cleanup(zip_path)

    if not success:
        sys.exit(1)


if __name__ == '__main__':
    main()
