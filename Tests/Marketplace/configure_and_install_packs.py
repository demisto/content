import argparse
import sys

from demisto_sdk.commands.common.tools import get_json

from Tests.configure_and_test_integration_instances import MARKET_PLACE_CONFIGURATION, \
    XSOARBuild, XSOARServer, XSIAMBuild, get_json_file, XSIAMServer
from Tests.Marketplace.search_and_install_packs import install_all_content_packs_from_build_bucket, \
    search_and_install_packs_and_their_dependencies
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging
from Tests.Marketplace.marketplace_constants import GCPConfig


def options_handler():
    # disable-secrets-detection-start
    parser = argparse.ArgumentParser(description='Utility for instantiating integration instances')
    parser.add_argument('--ami_env', help='The AMI environment for the current run. Options are '
                                          '"Server 6.1", "Server 6.2", "Server Master", "XSIAM Master"'
                                          'The server url is determined by the AMI environment.',
                        default="Server Master")
    parser.add_argument('-s', '--secret', help='Path to secret conf file')
    parser.add_argument('--branch', help='GitHub branch name', required=True)
    parser.add_argument('--build_number', help='CI job number where the instances were created', required=True)
    parser.add_argument('--service_account', help="Path to gcloud service account", required=True)
    parser.add_argument('-e', '--extract_path', help=f'Full path of folder to extract the {GCPConfig.INDEX_NAME}.zip '
                                                     f'to', required=True)
    parser.add_argument('--xsiam_machine', help='XSIAM machine to use, if it is XSIAM build.')
    parser.add_argument('--xsiam_servers_path', help='Path to secret xsiam server metadata file.')

    options = parser.parse_args()
    # disable-secrets-detection-end

    return options


def install_packs(servers):
    """
    Install pack_ids from "$ARTIFACTS_FOLDER/pack_results.json" file, and packs dependencies.
    Args:
        servers: XSIAM or XSOAR Servers to install packs on it.

    Returns:
        installed_content_packs_successfully: Whether packs installed successfully
    """
    # todo: get pack ids from packs_results.json
    pack_ids = []
    installed_content_packs_successfully = True
    for server in servers:
        try:
            hostname = server.name
            _, flag = search_and_install_packs_and_their_dependencies(pack_ids, server.client, hostname)
            if not flag:
                raise Exception('Failed to search and install packs.')
        except Exception:
            logging.exception('Failed to search and install packs')
            installed_content_packs_successfully = False

    return installed_content_packs_successfully


def xsoar_configure_and_install_flow(options, branch_name: str, build_number: str):
    """
    Args:
        options:
        branch_name:
        build_number:
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


def xsiam_configure_and_install_flow(options, branch_name: str, build_number: str):
    """
    Args:
        options:
        branch_name:
        build_number:
    """
    logging.info('Retrieving the credentials for Cortex XSIAM server')
    xsiam_machine = options.xsiam_machine
    xsiam_servers = get_json_file(options.xsiam_servers_path)
    api_key, server_numeric_version, base_url, xdr_auth_id = XSIAMBuild.get_xsiam_configuration(xsiam_machine,
                                                                                                xsiam_servers)
    # Configure the Server
    server = XSIAMServer(api_key, server_numeric_version, base_url, xdr_auth_id, xsiam_machine)
    XSIAMBuild.set_marketplace_url(servers=[server], branch_name=branch_name, ci_build_number=build_number)

    # Acquire the server's host and install new uploaded content packs
    logging.info(f'Starting to install all content packs in {xsiam_machine}')
    success_flag = install_packs([server])
    if success_flag:
        logging.success(f'Finished installing all content packs in {xsiam_machine}')
    else:
        logging.error('Failed to install all packs.')
        sys.exit(1)


def main():
    install_logging('Install_Packs.log', logger=logging)
    options = options_handler()
    branch_name: str = options.branch
    build_number: str = options.build_number

    if options.ami_env in ["XSIAM Master"]:
        xsiam_configure_and_install_flow(options, branch_name, build_number)
    else:
        xsoar_configure_and_install_flow(options, branch_name, build_number)


if __name__ == '__main__':
    main()
