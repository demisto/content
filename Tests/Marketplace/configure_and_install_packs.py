import argparse
import sys
import traceback

from demisto_sdk.commands.common.tools import get_json
from Tests.configure_and_test_integration_instances import MARKET_PLACE_CONFIGURATION, \
    XSOARBuild, XSOARServer, CloudBuild, CloudServer, Build, get_packs_with_higher_min_version
from Tests.Marketplace.search_and_install_packs import search_and_install_packs_and_their_dependencies
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging
from Tests.Marketplace.marketplace_constants import GCPConfig, XSIAM_MP, XSOAR_MP


def options_handler():
    # disable-secrets-detection-start
    parser = argparse.ArgumentParser(description='Utility for instantiating integration instances')
    parser.add_argument('--ami_env', help='The AMI environment for the current run. Options are '
                                          '"Server 6.5, "Server 6.6", "Server 6.8", "Server Master", "XSIAM Master"'
                                          'The server url is determined by the AMI environment.',
                        default="Server Master")
    parser.add_argument('-s', '--secret', help='Path to secret conf file')
    parser.add_argument('--branch', help='GitHub branch name', required=True)
    parser.add_argument('--build_number', help='CI job number where the instances were created', required=True)
    parser.add_argument('--service_account', help="Path to gcloud service account", required=True)
    parser.add_argument('-e', '--extract_path', help=f'Full path of folder to extract the {GCPConfig.INDEX_NAME}.zip '
                                                     f'to', required=True)
    parser.add_argument('--cloud_machine', help='cloud machine to use, if it is cloud build.')
    parser.add_argument('--cloud_servers_path', help='Path to the secret cloud server metadata file.')
    parser.add_argument('-pl', '--pack_ids_to_install', help='Path to the packs to install file.')
    parser.add_argument('--cloud_servers_api_keys', help='Path to the file with cloud Servers api keys.')
    options = parser.parse_args()
    # disable-secrets-detection-end

    return options


def install_packs_from_content_packs_to_install_path(servers, pack_ids, marketplace_tag_name, hostname=''):
    """
    Install pack_ids from "$ARTIFACTS_FOLDER/content_packs_to_install.txt" file, and packs dependencies.
    This method is called during the post-update phase of the build (with branch changed applied).

    Args:
        pack_ids: the pack IDs to install.
        servers: XSIAM or XSOAR Servers to install packs on it.
    """
    use_multithreading = marketplace_tag_name != XSIAM_MP

    for server in servers:
        logging.info(f'Starting to install all content packs in {hostname if hostname else server.internal_ip}')
        _, success = search_and_install_packs_and_their_dependencies(pack_ids=pack_ids,
                                                                     client=server.client,
                                                                     hostname=hostname,
                                                                     multithreading=use_multithreading,
                                                                     production_bucket=False)
        if not success:
            raise Exception('Failed to search and install packs and their dependencies.')


def xsoar_configure_and_install_flow(options, branch_name: str, build_number: str):
    """
    Args:
        options: script arguments.
        branch_name(str): name of the current branch.
        build_number(str): number of the current build flow
    """
    # Get the host by the ami env
    server_to_port_mapping, server_version = XSOARBuild.get_servers(ami_env=options.ami_env)

    logging.info('Retrieving the credentials for Cortex XSOAR server')
    secret_conf_file = get_json(file_path=options.secret)
    username: str = secret_conf_file.get('username')
    password: str = secret_conf_file.get('userPassword')

    servers = []
    # Configure the Servers
    for server_url in server_to_port_mapping:
        server = XSOARServer(internal_ip=server_url, user_name=username, password=password, build_number=build_number)
        logging.info(f'Adding Marketplace configuration to {server_url}')
        error_msg: str = 'Failed to set marketplace configuration.'
        server.add_server_configuration(config_dict=MARKET_PLACE_CONFIGURATION, error_msg=error_msg)
        XSOARBuild.set_marketplace_url(servers=[server], branch_name=branch_name, ci_build_number=build_number)
        servers.append(server)

    content_path = Build.content_path or ''
    if not content_path:
        raise Exception('Could not find content path')

    # Create a list of all packs that should be installed
    packs_to_install = set(Build.fetch_pack_ids_to_install(options.pack_ids_to_install))
    logging.info(f'Packs to install before filtering by minServerVersion: {packs_to_install}')

    # Get packs with 'minServerVersion' that's higher than server's version
    packs_with_higher_server_version = get_packs_with_higher_min_version(
        packs_names=packs_to_install,
        server_numeric_version=server_version
    )
    logging.info(f'Packs with minServerVersion that is higher than server version: {packs_with_higher_server_version}')

    # Remove packs that 'minServerVersion' that's higher than server's version.
    pack_ids_with_valid_min_server_version = packs_to_install - packs_with_higher_server_version
    logging.info(f'Installing content packs: {pack_ids_with_valid_min_server_version}')

    for b in batch(list(pack_ids_with_valid_min_server_version), batch_size=20):
        logging.info(f'installing packs in batch: {b}')
        install_packs_from_content_packs_to_install_path(servers=servers,
                                                         pack_ids=b,
                                                         marketplace_tag_name=XSOAR_MP)
    logging.success(
        f'Finished content packs: {pack_ids_with_valid_min_server_version} in {[server.internal_ip for server in servers]}'
    )


def batch(iterable, batch_size=1):
    """Gets an iterable and yields slices of it.

    Args:
        iterable (list): list or other iterable object.
        batch_size (int): the size of batches to fetch

    Return:
        (list): Iterable slices of given
    """
    current_batch = iterable[:batch_size]
    not_batched = iterable[batch_size:]
    while current_batch:
        yield current_batch
        current_batch = not_batched[:batch_size]
        not_batched = not_batched[batch_size:]


def xsiam_configure_and_install_flow(options, branch_name: str, build_number: str):
    """
    Args:
        options: script arguments.
        branch_name(str): name of the current branch.
        build_number(str): number of the current build flow
    """
    logging.info('Retrieving the credentials for Cortex XSIAM server')
    cloud_machine = options.cloud_machine
    api_key, server_numeric_version, base_url, xdr_auth_id = CloudBuild.get_cloud_configuration(
        cloud_machine,
        options.cloud_servers_path,
        options.cloud_servers_api_keys)
    # Configure the Server
    server = CloudServer(api_key, server_numeric_version, base_url, xdr_auth_id, cloud_machine, build_number)
    CloudBuild.set_marketplace_url(servers=[server], branch_name=branch_name, ci_build_number=build_number)

    # extract pack_ids from the content_packs_to_install.txt
    pack_ids = Build.fetch_pack_ids_to_install(options.pack_ids_to_install)
    # Acquire the server's host and install new uploaded content packs
    install_packs_from_content_packs_to_install_path(servers=[server], pack_ids=pack_ids, hostname=server.name,
                                                     marketplace_tag_name=XSIAM_MP)
    logging.success(f'Finished installing all content packs in {cloud_machine}')


def main():
    try:
        install_logging('Install_Packs.log', logger=logging)
        options = options_handler()
        branch_name: str = options.branch
        build_number: str = options.build_number

        if options.ami_env == "XSIAM":
            xsiam_configure_and_install_flow(options, branch_name, build_number)
        else:
            xsoar_configure_and_install_flow(options, branch_name, build_number)

    except Exception as e:
        logging.error(f'Failed to configure and install packs: {e}')
        logging.error(traceback.format_exc())
        sys.exit(1)


if __name__ == '__main__':
    main()
