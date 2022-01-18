import argparse
import sys

from demisto_sdk.commands.common.tools import get_json

from Tests.configure_and_test_integration_instances import set_marketplace_url, MARKET_PLACE_CONFIGURATION, \
    Build, Server
from Tests.Marketplace.search_and_install_packs import install_all_content_packs_from_build_bucket
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging
from Tests.Marketplace.marketplace_constants import GCPConfig


def options_handler():
    # disable-secrets-detection-start
    parser = argparse.ArgumentParser(description='Utility for instantiating integration instances')
    parser.add_argument('--ami_env', help='The AMI environment for the current run. Options are '
                                          '"Server 6.0", "Server Master". The server url is determined by the'
                                          ' AMI environment.', default="Server Master")
    parser.add_argument('-s', '--secret', help='Path to secret conf file')
    parser.add_argument('--branch', help='GitHub branch name', required=True)
    parser.add_argument('--build_number', help='CI job number where the instances were created', required=True)
    parser.add_argument('--service_account', help="Path to gcloud service account", required=True)
    parser.add_argument('-e', '--extract_path', help=f'Full path of folder to extract the {GCPConfig.INDEX_NAME}.zip '
                                                     f'to', required=True)

    options = parser.parse_args()
    # disable-secrets-detection-end

    return options


def main():
    install_logging('Install_Packs.log', logger=logging)
    options = options_handler()

    # Get the host by the ami env
    server_to_port_mapping, server_version = Build.get_servers(ami_env=options.ami_env)

    logging.info('Retrieving the credentials for Cortex XSOAR server')
    secret_conf_file = get_json(file_path=options.secret)
    username: str = secret_conf_file.get('username')
    password: str = secret_conf_file.get('userPassword')
    branch_name: str = options.branch
    build_number: str = options.build_number

    # Configure the Servers
    for server_url, port in server_to_port_mapping.items():
        server = Server(internal_ip=server_url, port=port, user_name=username, password=password)
        logging.info(f'Adding Marketplace configuration to {server_url}')
        error_msg: str = 'Failed to set marketplace configuration.'
        server.add_server_configuration(config_dict=MARKET_PLACE_CONFIGURATION, error_msg=error_msg)
        set_marketplace_url(servers=[server], branch_name=branch_name, ci_build_number=build_number)

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


if __name__ == '__main__':
    main()
