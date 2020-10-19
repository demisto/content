import argparse
from Tests.configure_and_test_integration_instances import Server, set_marketplace_url, MARKET_PLACE_CONFIGURATION,\
    Build, get_json_file
from Tests.test_content import ParallelPrintsManager
from Tests.Marketplace.search_and_install_packs import install_all_content_packs
from demisto_sdk.commands.common.tools import print_color, LOG_COLORS


def options_handler():
    parser = argparse.ArgumentParser(description='Utility for instantiating and testing integration instances')
    parser.add_argument('-u', '--user', help='The username for the login', required=True)
    parser.add_argument('-p', '--password', help='The password for the login', required=True)
    parser.add_argument('--ami_env', help='The AMI environment for the current run. Options are '
                                          '"Server Master", "Demisto GA", "Demisto one before GA", "Demisto two before '
                                          'GA". The server url is determined by the AMI environment.')
    parser.add_argument('-s', '--secret', help='Path to secret conf file')
    parser.add_argument('--branch', help='GitHub branch name', required=True)
    parser.add_argument('--build-number', help='CI job number where the instances were created', required=True)

    options = parser.parse_args()

    return options


def main():
    options = options_handler()

    # Get the host by the ami env
    hosts, _ = Build.get_servers(ami_env=options.ami_env)

    print_color('Retrieving the credentials for Cortex XSOAR server', LOG_COLORS.GREEN)
    secret_conf_file = get_json_file(path=options.secret)
    username: str = options.user if options.user else secret_conf_file.get('username')
    password: str = options.password if options.password else secret_conf_file.get('userPassword')

    # Configure the Server
    host = hosts[0]
    server: Server = Server(host=host, user_name=username, password=password)
    error_msg: str = 'Failed to set marketplace configuration.'
    print_color(f'Adding Marketplace configuration to {host}', LOG_COLORS.GREEN)
    server.add_server_configuration(config_dict=MARKET_PLACE_CONFIGURATION, error_msg=error_msg)
    set_marketplace_url(servers=[server], branch_name=options.branch, ci_build_number=options.build_number)

    # Acquire the server's host and install all content packs (one threaded execution)
    print_color(f'Starting to install all content packs in {host}', LOG_COLORS.GREEN)
    server_host: str = server.client.api_client.configuration.host
    install_all_content_packs(client=server.client, host=server_host, prints_manager=ParallelPrintsManager(1))
    print_color(f'Finished installing all content packs in {host}', LOG_COLORS.GREEN)


if __name__ == '__main__':
    main()
