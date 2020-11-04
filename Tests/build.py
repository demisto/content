import os
from Tests.configure_and_test_integration_instances import Running
from Tests.server import Server
from Tests.test_content import get_server_numeric_version, get_json_file


class Build:
    # START CHANGE ON LOCAL RUN #
    content_path = '{}/project'.format(os.getenv('HOME'))
    test_pack_target = '{}/project/Tests'.format(os.getenv('HOME'))
    key_file_path = 'Use in case of running with non local server'
    run_environment = Running.CIRCLECI_RUN
    env_results_path = './env_results.json'
    DEFAULT_SERVER_VERSION = '99.99.98'

    #  END CHANGE ON LOCAL RUN  #

    def __init__(self, options):
        self.git_sha1 = options.git_sha1
        self.branch_name = options.branch
        self.ci_build_number = options.build_number
        self.is_nightly = options.is_nightly
        self.ami_env = options.ami_env
        self.servers, self.server_numeric_version = self.get_servers(options.ami_env)
        self.secret_conf = get_json_file(options.secret)
        self.username = options.user if options.user else self.secret_conf.get('username')
        self.password = options.password if options.password else self.secret_conf.get('userPassword')
        self.servers = [Server(server_url, self.username, self.password) for server_url in self.servers]
        self.is_private = options.is_private
        conf = get_json_file(options.conf)
        self.tests = conf['tests']
        self.skipped_integrations_conf = conf['skipped_integrations']

    @staticmethod
    def get_servers(ami_env):
        env_conf = Build.get_env_conf()
        servers = Build.determine_servers_urls(env_conf, ami_env)
        if Build.run_environment == Running.CIRCLECI_RUN:
            server_numeric_version = get_server_numeric_version(ami_env)
        else:
            server_numeric_version = Build.DEFAULT_SERVER_VERSION
        return servers, server_numeric_version

    @staticmethod
    def get_env_conf():
        if Build.run_environment == Running.CIRCLECI_RUN:
            return get_json_file(Build.env_results_path)

        elif Build.run_environment == Running.WITH_LOCAL_SERVER:
            # START CHANGE ON LOCAL RUN #
            return [{
                "InstanceDNS": "http://localhost:8080",
                "Role": "Demisto Marketplace"  # e.g. 'Demisto Marketplace'
            }]
        elif Build.run_environment == Running.WITH_OTHER_SERVER:
            return [{
                "InstanceDNS": "DNS NANE",  # without http prefix
                "Role": "DEMISTO EVN"  # e.g. 'Demisto Marketplace'
            }]
        #  END CHANGE ON LOCAL RUN  #

    @staticmethod
    def determine_servers_urls(env_results, ami_env):
        """
        Arguments:
            env_results: (dict)
                env_results.json in server
            ami_env: (str)
                The amazon machine image environment whose IP we should connect to.

        Returns:
            (lst): The server url list to connect to
        """

        instances_dns = [env.get('InstanceDNS') for env in env_results if ami_env in env.get('Role', '')]

        server_urls = []
        for dns in instances_dns:
            server_url = dns if not dns or dns.startswith('http') else f'https://{dns}'
            server_urls.append(server_url)
        return server_urls
