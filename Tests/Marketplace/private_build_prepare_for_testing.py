import argparse
import os
from Tests.Marketplace.marketplace_services import GCPConfig, init_storage_client, Pack
from Tests.private_build.upload_packs_private import extract_packs_artifacts
from demisto_sdk.commands.common.tools import str2bool

from Tests.scripts.utils.log_util import install_logging


def option_handler():
    """Validates and parses script arguments.

    Returns:
        Namespace: Parsed arguments object.

    """
    parser = argparse.ArgumentParser(description="Store packs in cloud storage.")
    # disable-secrets-detection-start
    parser.add_argument('-p', '--pack_name', help="Name of the private pack to upload.", required=True)
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

    parser.add_argument('-i', '--id_set_path', help="The full path of id_set.json", required=False)
    parser.add_argument('-d', '--pack_dependencies', help="Full path to pack dependencies json file.", required=False)

    parser.add_argument('-n', '--ci_build_number',
                        help="CircleCi build number (will be used as hash revision at index file)", required=True)
    parser.add_argument('-o', '--override_all_packs', help="Override all existing packs in cloud storage",
                        default=False, action='store_true', required=False)
    parser.add_argument('-k', '--key_string', help="Base64 encoded signature key used for signing packs.",
                        required=False)
    parser.add_argument('-sb', '--storage_base_path', help="Storage base path of the directory to upload to.",
                        required=False)
    parser.add_argument('-rt', '--remove_test_playbooks', type=str2bool,
                        help='Should remove test playbooks from content packs or not.', default=True)
    parser.add_argument('-enc', '--encrypt_pack', type=str2bool,
                        help='Should encrypt pack or not.', default=False)
    parser.add_argument('-ek', '--encryption_key', type=str,
                        help='The encryption key for the pack, if it should be encrypted.', default='')

    # disable-secrets-detection-end
    return parser.parse_args()


def upload_premium_pack_to_private_testing_bucket(premium_pack, private_testing_repo_client, extract_destination_path):
    _, zip_pack_path = premium_pack.zip_pack(extract_destination_path, premium_pack._pack_name, False, '')
    premium_pack.upload_to_storage(zip_pack_path, premium_pack.latest_version, private_testing_repo_client, True, True)


def main():
    install_logging('Prepare_Content_Packs_For_Testing.log')
    packs_dir = '/home/runner/work/content-private/content-private/content/artifacts/packs'
    temp_dir = '/home/runner/work/content-private/content-private/content/temp-dir'
    if not os.path.exists(packs_dir):
        os.mkdir(packs_dir)
    if not os.path.exists(temp_dir):
        os.mkdir(temp_dir)
    upload_config = option_handler()
    path_to_artifacts = upload_config.artifacts_path
    extract_destination_path = upload_config.extract_path
    service_account = upload_config.service_account
    pack_name = upload_config.pack_names
    storage_base_path = upload_config.storage_base_path

    if storage_base_path:
        GCPConfig.STORAGE_BASE_PATH = storage_base_path

    storage_client = init_storage_client(service_account)
    private_testing_bucket_client = storage_client.bucket(GCPConfig.CI_PRIVATE_BUCKET)

    extract_packs_artifacts(path_to_artifacts, extract_destination_path)
    path_to_pack = os.path.join(extract_destination_path, pack_name)
    premium_pack = Pack(pack_name, path_to_pack)

    upload_premium_pack_to_private_testing_bucket(premium_pack, pack_name, private_testing_bucket_client)
