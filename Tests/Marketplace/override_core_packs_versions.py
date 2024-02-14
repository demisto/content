import os
import argparse
import uuid


from Tests.Marketplace.marketplace_services import json_write
from Tests.Marketplace.marketplace_constants import GCPConfig
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging




def should_override_locked_corepacks_file(marketplace: str = 'xsoar'):
    """
    Checks if the corepacks_override.json file in the repo should be used to override an existing corepacks file.
    The override file should be used if the following conditions are met:
    1. The versions-metadata.json file contains a server version that matches the server version specified in the
        override file.
    2. The file version of the server version in the corepacks_override.json file is greater than the matching file
        version in the versions-metadata.json file.
    3. The marketplace to which the upload is taking place matches the marketplace specified in the override file.

    Args
        marketplace (str): the marketplace type of the bucket. possible options: xsoar, marketplace_v2 or xpanse

    Returns True if a file should be updated and False otherwise.
    """
    override_corepacks_server_version = GCPConfig.corepacks_override_contents.get('server_version')
        
    override_marketplaces = list(GCPConfig.corepacks_override_contents.get('updated_corepacks_content', {}).keys())

    override_corepacks_file_version = GCPConfig.corepacks_override_contents.get('updated_corepacks_content').get('file_version')
    current_corepacks_file_version = GCPConfig.core_packs_file_versions.get(override_corepacks_server_version, {}).get('file_version').get(marketplace)
    if not current_corepacks_file_version:
        logging.debug(f'Could not find a matching file version for server version {override_corepacks_server_version} in '
                      f'{GCPConfig.VERSIONS_METADATA_FILE} file. Skipping upload of {GCPConfig.COREPACKS_OVERRIDE_FILE}...')
        return False

    if int(override_corepacks_file_version) <= int(current_corepacks_file_version):
        logging.debug(
            f'Corepacks file version: {override_corepacks_file_version} of server version {override_corepacks_server_version} in '
            f'{GCPConfig.COREPACKS_OVERRIDE_FILE} is not greater than the version in {GCPConfig.VERSIONS_METADATA_FILE}: '
            f'{current_corepacks_file_version}. Skipping upload of {GCPConfig.COREPACKS_OVERRIDE_FILE}...')
        return False

    if override_marketplaces and marketplace not in override_marketplaces:
        logging.debug(f'Current marketplace {marketplace} is not selected in the {GCPConfig.VERSIONS_METADATA_FILE} '
                      f'file. Skipping upload of {GCPConfig.COREPACKS_OVERRIDE_FILE}...')
        return False

    return True


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
    corepacks_file_new_content = GCPConfig.corepacks_override_contents.get('updated_corepacks_content').get(marketplace, {})

    # Update the build number to the current build number:
    corepacks_file_new_content['buildNumber'] = build_number

    # Upload the updated corepacks file to the given artifacts folder:
    override_corepacks_file_name = f'corepacks-{override_corepacks_server_version}.json'
    logging.debug(f'Overriding {override_corepacks_file_name} with the following content:\n {corepacks_file_new_content}')
    corepacks_json_path = os.path.join(artifacts_dir, override_corepacks_file_name)
    json_write(corepacks_json_path, corepacks_file_new_content)
    logging.success(f"Finished copying overriden {override_corepacks_file_name} to artifacts.")

    # Update the file version of the matching corepacks version in the versions-metadata.json file
    override_corepacks_file_version = GCPConfig.corepacks_override_contents.get('file_version')
    logging.debug(f'Bumping file version of server version {override_corepacks_server_version} in versions-metadata.json from'
                  f'{GCPConfig.versions_metadata_contents["version_map"][override_corepacks_server_version]["file_version"]} to'
                  f'{override_corepacks_file_version}')
    GCPConfig.versions_metadata_contents['version_map'][override_corepacks_server_version]['file_version'][marketplace] = \
        override_corepacks_file_version

def upload_server_versions_metadata(artifacts_dir: str):
    """
    Upload the versions-metadata.json to the build artifacts folder.

    Args:
        artifacts_dir (str): The CI artifacts directory to upload the versions-metadata.json file to.
    """
    versions_metadata_path = os.path.join(artifacts_dir, GCPConfig.VERSIONS_METADATA_FILE)
    json_write(versions_metadata_path, GCPConfig.versions_metadata_contents)
    logging.success(f"Finished copying {GCPConfig.VERSIONS_METADATA_FILE} to artifacts.")
 
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
    
    # disable-secrets-detection-end
    return parser.parse_args()

   
def main():
    install_logging('override_core_packs.log', logger=logging)
    logging.info("here")
    options = option_handler()
    packs_artifacts_path = options.packs_artifacts_path
    marketplace = options.marketplace
    build_number = options.ci_build_number if options.ci_build_number else str(uuid.uuid4())
    
    # override a locked core packs file (used for hot-fixes)
    if should_override_locked_corepacks_file(marketplace=marketplace):
        logging.debug('Using the corepacks_override.json file to update an existing corepacks file.')
        override_locked_corepacks_file(build_number=build_number,
                                       artifacts_dir=os.path.dirname(packs_artifacts_path),
                                       marketplace=marketplace)
    else:
        logging.debug('Skipping overriding an existing corepacks file.')
    
    # upload server versions metadata to bucket
    upload_server_versions_metadata(os.path.dirname(packs_artifacts_path))


if __name__ == '__main__':
    main()