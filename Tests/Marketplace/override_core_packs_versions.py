import os
import argparse
import uuid
import json

from Tests.Marketplace.marketplace_services import json_write, get_content_git_client
from Tests.Marketplace.marketplace_constants import GCPConfig, CONTENT_ROOT_PATH, COREPACKS_OVERRIDE_FILE_PATH
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging


def should_override_locked_corepacks_file(marketplace: str, last_upload_commit: str):
    """
        Checks if the corepacks_override.json file in the repo should be used to override an existing corepacks file.
        The override file should be used if the following conditions are met:
        1. The current version of the corepacks_override.json is different from the last version in master.
        2. The current marketplace appears as should be overriden in the corepacks_override.json.

        Args
            marketplace (str): the marketplace type of the bucket. possible options: xsoar, xsoar_saas, marketplace_v2 or xpanse
            last_upload_commit(str): Last upload commit.

        Returns True if a file should be updated and False otherwise.
        """

    content_repo = get_content_git_client(CONTENT_ROOT_PATH)
    commit = content_repo.commit(last_upload_commit)

    # Access the file as a blob from the last commit
    last_commit_blob = commit.tree / COREPACKS_OVERRIDE_FILE_PATH

    # Get the content of the last commit blob
    last_commit_content = json.loads(last_commit_blob.data_stream.read())

    # Get the current file content
    current_override_content = GCPConfig.corepacks_override_contents

    # If the files are different and the current marketplace is in the override file we override
    if current_override_content != last_commit_content and marketplace in current_override_content:
        updated_corepacks_content = current_override_content.get(marketplace).get('updated_corepacks_content')
        if updated_corepacks_content:
            logging.info('current marketplace contains updated core packs content, overriding.')
            return True
    return False


def override_locked_corepacks_file(build_number: str, artifacts_dir: str, marketplace: str = 'xsoar'):
    """
    Override an existing corepacks-X.X.X.json file, where X.X.X is the server version that was specified in the
    corepacks_override.json file.
    Additionally, update the file version in the versions-metadata.json file, and the corepacks file with the
    current build number.

    Args:
         build_number (str): The build number to use in the corepacks file, if it should be overriden.
         artifacts_dir (str): The CI artifacts directory to upload the corepacks file to.
         marketplace (str)
    """
    # Get the updated content of the corepacks file:
    override_corepacks_server_version = GCPConfig.corepacks_override_contents.get('server_version')
    corepacks_file_new_content = GCPConfig.corepacks_override_contents.get(marketplace, {}).get('updated_corepacks_content')

    # Update the build number to the current build number:
    corepacks_file_new_content['buildNumber'] = build_number

    # Upload the updated corepacks file to the given artifacts' folder:
    override_corepacks_file_name = f'corepacks-{override_corepacks_server_version}.json'
    logging.debug(f'Overriding {override_corepacks_file_name} with the following content:\n {corepacks_file_new_content}')
    corepacks_json_path = os.path.join(artifacts_dir, override_corepacks_file_name)
    json_write(corepacks_json_path, corepacks_file_new_content)
    logging.success(f"Finished copying overriden {override_corepacks_file_name} to artifacts.")


def upload_server_versions_metadata(artifacts_dir: str):
    """
    Upload the versions-metadata.json to the build artifacts folder.

    Args:
        artifacts_dir (str): The CI artifacts directory to upload the versions-metadata.json file to.
    """
    versions_metadata_path = os.path.join(artifacts_dir, GCPConfig.VERSIONS_METADATA_FILE)
    json_write(versions_metadata_path, GCPConfig.versions_metadata_contents)
    logging.success(f"Finished copying {GCPConfig.VERSIONS_METADATA_FILE} to artifacts to {artifacts_dir}.")


def option_handler():
    """Validates and parses script arguments.

    Returns:
        Namespace: Parsed arguments object.

    """
    parser = argparse.ArgumentParser(description="Store packs in cloud storage.")
    # disable-secrets-detection-start
    parser.add_argument('-pa', '--packs_artifacts_path', help="The full path of packs artifacts", required=True)
    parser.add_argument('-n', '--ci_build_number',
                        help="CircleCi build number (will be used as hash revision at index file)", required=False)
    parser.add_argument('-mp', '--marketplace', help="marketplace version", default='xsoar')
    parser.add_argument('-uc', '--upload_commit', help="Last upload commit", required=True)

    # disable-secrets-detection-end
    return parser.parse_args()


def main():
    install_logging('override_core_packs.log', logger=logging)
    options = option_handler()
    packs_artifacts_path = options.packs_artifacts_path
    marketplace = options.marketplace
    build_number = options.ci_build_number if options.ci_build_number else str(uuid.uuid4())
    last_upload_commit = options.upload_commit

    # override a locked core packs file (used for hot-fixes)
    if should_override_locked_corepacks_file(marketplace=marketplace, last_upload_commit=last_upload_commit):
        logging.debug('Using the corepacks_override.json file to update an existing corepacks file.')
        override_locked_corepacks_file(build_number=build_number,
                                       artifacts_dir=packs_artifacts_path,
                                       marketplace=marketplace)
    else:
        logging.debug('Skipping overriding an existing corepacks file.')

    # upload server versions metadata to bucket
    upload_server_versions_metadata(packs_artifacts_path)


if __name__ == '__main__':
    main()
