import argparse
import sys
import traceback

from demisto_sdk.commands.common.tools import get_json, str2bool
from Tests.configure_and_test_integration_instances import MARKET_PLACE_CONFIGURATION, \
    XSOARBuild, XSOARServer, XSIAMBuild, XSIAMServer, Build, get_packs_with_higher_min_version
from Tests.Marketplace.search_and_install_packs import install_all_content_packs_from_build_bucket, \
    search_and_install_packs_and_their_dependencies
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging
from Tests.Marketplace.marketplace_constants import GCPConfig


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
    parser.add_argument('--xsiam_machine', help='XSIAM machine to use, if it is XSIAM build.')
    parser.add_argument('--xsiam_servers_path', help='Path to the secret xsiam server metadata file.')
    parser.add_argument('-pl', '--pack_ids_to_install', help='Path to the packs to install file.')
    parser.add_argument('-o', '--override_all_packs', help="Override all existing packs in cloud storage",
                        type=str2bool, default=False, required=True)
    parser.add_argument('--xsiam_servers_api_keys', help='Path to the file with XSIAM Servers api keys.')
    options = parser.parse_args()
    # disable-secrets-detection-end

    return options


def install_packs_from_content_packs_to_install_path(servers, pack_ids, hostname=''):
    """
    Install pack_ids from "$ARTIFACTS_FOLDER/content_packs_to_install.txt" file, and packs dependencies.

    Args:
        hostname:
        pack_ids: the pack IDs to install.
        servers: XSIAM or XSOAR Servers to install packs on it.
    """
    for server in servers:
        logging.info(f'Starting to install all content packs in {hostname if hostname else server.internal_ip}')
        _, success = search_and_install_packs_and_their_dependencies(pack_ids, server.client, hostname)
        if not success:
            raise Exception('Failed to search and install packs and their dependencies.')


def xsoar_configure_and_install_all_packs(options, branch_name: str, build_number: str):
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

    # Configure the Servers
    for server_url, port in server_to_port_mapping.items():
        server = XSOARServer(internal_ip=server_url, port=port, user_name=username, password=password)
        logging.info(f'Adding Marketplace configuration to {server_url}')
        error_msg: str = 'Failed to set marketplace configuration.'
        server.add_server_configuration(config_dict=MARKET_PLACE_CONFIGURATION, error_msg=error_msg)
        XSOARBuild.set_marketplace_url(servers=[server], branch_name=branch_name, ci_build_number=build_number)

        # Acquire the server's host and install all content packs (one threaded execution)
        logging.info(f'Starting to install all content packs in {server_url}')
        server_host: str = server.client.api_client.configuration.host
        success_flag = install_all_content_packs_from_build_bucket(
            client=server.client, host=server_host, server_version=server_version,
            bucket_packs_root_path=GCPConfig.BUILD_BUCKET_PACKS_ROOT_PATH.format(branch=branch_name,
                                                                                 build=build_number,
                                                                                 marketplace='xsoar'),
            service_account=options.service_account, extract_destination_path=options.extract_path
        )
        if success_flag:
            logging.success(f'Finished installing all content packs in {server_url}')
        else:
            logging.error('Failed to install all packs.')
            sys.exit(1)


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
    for server_url, port in server_to_port_mapping.items():
        server = XSOARServer(internal_ip=server_url, port=port, user_name=username, password=password)
        logging.info(f'Adding Marketplace configuration to {server_url}')
        error_msg: str = 'Failed to set marketplace configuration.'
        server.add_server_configuration(config_dict=MARKET_PLACE_CONFIGURATION, error_msg=error_msg)
        XSOARBuild.set_marketplace_url(servers=[server], branch_name=branch_name, ci_build_number=build_number)
        servers.append(server)

    content_path = Build.content_path or ''
    if not content_path:
        raise Exception('Could not find content path')

    # all packs that should be installed
    packs_to_install = set(Build.fetch_pack_ids_to_install(options.pack_ids_to_install))
    logging.info(f'packs to install before filtering by minServerVersion {packs_to_install}')

    # get packs that their minServerVersion is higher than the server version
    packs_with_higher_server_version = get_packs_with_higher_min_version(
        packs_names=packs_to_install,
        content_path=content_path,
        server_numeric_version=server_version
    )
    logging.info(f'packs with minServerVersion that is higher than server version {packs_with_higher_server_version}')

    # remove all the packs that that their minServerVersion is higher than the server version.
    pack_ids_with_valid_min_server_version = packs_to_install - packs_with_higher_server_version
    logging.info(f'starting to install content packs {pack_ids_with_valid_min_server_version}')

    install_packs_from_content_packs_to_install_path(servers, list(pack_ids_with_valid_min_server_version))
    logging.success(
        f'Finished installing all content packs {pack_ids_with_valid_min_server_version} '
        f'in {[server.internal_ip for server in servers]}'
    )


def xsiam_configure_and_install_flow(options, branch_name: str, build_number: str):
    """
    Args:
        options: script arguments.
        branch_name(str): name of the current branch.
        build_number(str): number of the current build flow
    """
    logging.info('Retrieving the credentials for Cortex XSIAM server')
    xsiam_machine = options.xsiam_machine
    api_key, server_numeric_version, base_url, xdr_auth_id = XSIAMBuild.get_xsiam_configuration(
        xsiam_machine,
        options.xsiam_servers_path,
        options.xsiam_servers_api_keys)
    # Configure the Server
    server = XSIAMServer(api_key, server_numeric_version, base_url, xdr_auth_id, xsiam_machine)
    XSIAMBuild.set_marketplace_url(servers=[server], branch_name=branch_name, ci_build_number=build_number)

    # extract pack_ids from the content_packs_to_install.txt
    pack_ids = Build.fetch_pack_ids_to_install(options.pack_ids_to_install)
    # Acquire the server's host and install new uploaded content packs
    install_packs_from_content_packs_to_install_path([server], pack_ids, server.name)
    logging.success(f'Finished installing all content packs in {xsiam_machine}')


def main():
    try:
        install_logging('Install_Packs.log', logger=logging)
        options = options_handler()
        branch_name: str = options.branch
        build_number: str = options.build_number

        if options.ami_env in ["XSIAM Master"]:
            xsiam_configure_and_install_flow(options, branch_name, build_number)
        elif options.override_all_packs:
            xsoar_configure_and_install_all_packs(options, branch_name, build_number)
        else:
            xsoar_configure_and_install_flow(options, branch_name, build_number)

    except Exception as e:
        logging.error(f'Failed to configure and install packs: {e}')
        logging.error(traceback.format_exc())
        sys.exit(1)


if __name__ == '__main__':
    main()
