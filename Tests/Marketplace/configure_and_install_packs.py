import argparse
from Tests.configure_and_test_integration_instances import set_marketplace_url, MARKET_PLACE_CONFIGURATION, \
    Build, Server
from Tests.test_content import get_json_file, ParallelPrintsManager
from Tests.Marketplace.search_and_install_packs import install_all_content_packs
from demisto_sdk.commands.common.tools import print_color, LOG_COLORS


def options_handler():
    parser = argparse.ArgumentParser(description='Utility for instantiating integration instances')
    parser.add_argument('--ami_env', help='The AMI environment for the current run. Options are '
                                          '"Demisto 6.0", "Demisto Marketplace". The server url is determined by the'
                                          ' AMI environment.', default="Demisto Marketplace")
    parser.add_argument('-s', '--secret', help='Path to secret conf file')
    parser.add_argument('--branch', help='GitHub branch name', required=True)
    parser.add_argument('--build_number', help='CI job number where the instances were created', required=True)

    options = parser.parse_args()

    return options


def main():
    options = options_handler()

    # Get the host by the ami env
    hosts, _ = Build.get_servers(ami_env=options.ami_env)

    print_color('Retrieving the credentials for Cortex XSOAR server', LOG_COLORS.NATIVE)
    secret_conf_file = get_json_file(path=options.secret)
    username: str = secret_conf_file.get('username')
    password: str = secret_conf_file.get('userPassword')

    # Configure the Servers
    for host in hosts:
        server = Server(host=host, user_name=username, password=password)
        print_color(f'Adding Marketplace configuration to {host}', LOG_COLORS.NATIVE)
        error_msg: str = 'Failed to set marketplace configuration.'
        server.add_server_configuration(config_dict=MARKET_PLACE_CONFIGURATION, error_msg=error_msg)
        set_marketplace_url(servers=[server], branch_name=options.branch, ci_build_number=options.build_number)

        # Acquire the server's host and install all content packs (one threaded execution)
        print_color(f'Starting to install all content packs in {host}', LOG_COLORS.NATIVE)
        server_host: str = server.client.api_client.configuration.host
        install_all_content_packs(client=server.client, host=server_host, prints_manager=ParallelPrintsManager(1))
        print_color(f'Finished installing all content packs in {host}', LOG_COLORS.NATIVE)


if __name__ == '__main__':
    main()

# TODO: add logging
