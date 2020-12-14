from __future__ import print_function

import argparse
import os
import uuid
import json
import ast
import subprocess
import sys
import zipfile
from datetime import datetime
from enum import IntEnum
from pprint import pformat
from time import sleep
from threading import Thread
from distutils.version import LooseVersion
import logging
from typing import List

from Tests.mock_server import MITMProxy, run_with_mock, RESULT
from Tests.scripts.utils.log_util import install_logging

from paramiko.client import SSHClient, AutoAddPolicy
import demisto_client
from ruamel import yaml
from demisto_sdk.commands.common.tools import run_threads_list, run_command, get_yaml,\
    str2bool, format_version, find_type
from demisto_sdk.commands.common.constants import FileType
from Tests.test_integration import __get_integration_config, __test_integration_instance, disable_all_integrations
from Tests.test_content import extract_filtered_tests, get_server_numeric_version
from Tests.update_content_data import update_content
from Tests.Marketplace.search_and_install_packs import search_and_install_packs_and_their_dependencies, \
    install_all_content_packs, upload_zipped_packs, install_all_content_packs_for_nightly
from Tests.tools import update_server_configuration
from demisto_sdk.commands.validate.validate_manager import ValidateManager

MARKET_PLACE_MACHINES = ('master',)
SKIPPED_PACKS = ['NonSupported', 'ApiModules']
DOCKER_HARDENING_CONFIGURATION = {
    'docker.cpu.limit': '1.0',
    'docker.run.internal.asuser': 'true',
    'limit.docker.cpu': 'true',
    'python.pass.extra.keys': '--memory=1g##--memory-swap=-1##--pids-limit=256##--ulimit=nofile=1024:8192'
}
MARKET_PLACE_CONFIGURATION = {
    'content.pack.verify': 'false',
    'marketplace.initial.sync.delay': '0',
    'content.pack.ignore.missing.warnings.contentpack': 'true'
}
ID_SET_PATH = './Tests/id_set.json'


class Running(IntEnum):
    CIRCLECI_RUN = 0
    WITH_OTHER_SERVER = 1
    WITH_LOCAL_SERVER = 2


class SimpleSSH(SSHClient):
    logging.getLogger("paramiko").setLevel(logging.WARNING)

    def __init__(self, host, user='ec2-user', port=22, key_file_path='~/.ssh/id_rsa'):
        self.run_environment = Build.run_environment
        if self.run_environment in [Running.CIRCLECI_RUN, Running.WITH_OTHER_SERVER]:
            super().__init__()
            self.load_system_host_keys()
            self.set_missing_host_key_policy(AutoAddPolicy())
            if self.run_environment == Running.CIRCLECI_RUN:
                self.connect(hostname=host, username=user, timeout=60.0)
            elif self.run_environment == Running.WITH_OTHER_SERVER:
                if key_file_path.startswith('~'):
                    key_file_path = key_file_path.replace('~', os.getenv('HOME'), 1)
                    self.connect(hostname=host, port=port, username=user, key_filename=key_file_path, timeout=60.0)

    def exec_command(self, command, *_other):
        if self.run_environment in [Running.CIRCLECI_RUN, Running.WITH_OTHER_SERVER]:
            _, _stdout, _stderr = super(SimpleSSH, self).exec_command(command)
            return _stdout.read(), _stderr.read()
        else:
            return run_command(command, is_silenced=False), None


class Server:

    def __init__(self, host, user_name, password):
        self.__ssh_client = None
        self.__client = None
        self.host = host
        self.user_name = user_name
        self.password = password

    def __str__(self):
        return self.host

    @property
    def client(self):
        if self.__client is None:
            self.__client = self.reconnect_client()

        return self.__client

    def reconnect_client(self):
        self.__client = demisto_client.configure(self.host, verify_ssl=False, username=self.user_name,
                                                 password=self.password)
        return self.__client

    def add_server_configuration(self, config_dict, error_msg, restart=False):
        update_server_configuration(self.client, config_dict, error_msg)

        if restart:
            self.exec_command('sudo systemctl restart demisto')

    def exec_command(self, command):
        if self.__ssh_client is None:
            self.__init_ssh()
        self.__ssh_client.exec_command(command)

    def __init_ssh(self):
        self.__ssh_client = SimpleSSH(host=self.host.replace('https://', '').replace('http://', ''),
                                      key_file_path=Build.key_file_path, user='ec2-user')


def get_id_set(id_set_path) -> dict:
    """
    Used to collect the ID set so it can be passed to the Build class on init.

    :return: ID set as a dict if it exists.
    """
    if os.path.isfile(id_set_path):
        return get_json_file(id_set_path)


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
        self._proxy = None
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
        self.unmockable_integrations = conf['unmockable_integrations']
        id_set_path = options.id_set_path if options.id_set_path else ID_SET_PATH
        self.id_set = get_id_set(id_set_path)
        self.test_pack_path = options.test_pack_path if options.test_pack_path else None
        self.tests_to_run = self.fetch_tests_list(options.tests_to_run)
        self.content_root = options.content_root
        self.pack_ids_to_install = self.fetch_pack_ids_to_install(options.pack_ids_to_install)
        self.service_account = options.service_account

    @property
    def proxy(self):
        if not self._proxy:
            self._proxy = MITMProxy(self.servers[0].host.replace('https://', ''), logging_module=logging)
            self._proxy.configure_proxy_in_demisto(proxy=self._proxy.ami.docker_ip + ':' + self._proxy.PROXY_PORT,
                                                   username=self.username, password=self.password,
                                                   server=self.servers[0].host)
        return self._proxy

    @staticmethod
    def fetch_tests_list(tests_to_run_path: str):
        """
        Fetches the test list from the filter.

        :param tests_to_run_path: Path to location of test filter.
        :return: List of tests if there are any, otherwise empty list.
        """
        tests_to_run = []
        with open(tests_to_run_path, "r") as filter_file:
            tests_from_file = filter_file.readlines()
            for test_from_file in tests_from_file:
                test_clean = test_from_file.rstrip()
                tests_to_run.append(test_clean)
        return tests_to_run

    @staticmethod
    def fetch_pack_ids_to_install(packs_to_install_path: str):
        """
        Fetches the test list from the filter.

        :param packs_to_install_path: Path to location of pack IDs to install file.
        :return: List of Pack IDs if there are any, otherwise empty list.
        """
        tests_to_run = []
        with open(packs_to_install_path, "r") as filter_file:
            tests_from_file = filter_file.readlines()
            for test_from_file in tests_from_file:
                test_clean = test_from_file.rstrip()
                tests_to_run.append(test_clean)
        return tests_to_run

    @staticmethod
    def get_servers(ami_env):
        env_conf = get_env_conf()
        servers = determine_servers_urls(env_conf, ami_env)
        if Build.run_environment == Running.CIRCLECI_RUN:
            server_numeric_version = get_server_numeric_version(ami_env)
        else:
            server_numeric_version = Build.DEFAULT_SERVER_VERSION
        return servers, server_numeric_version


def options_handler():
    parser = argparse.ArgumentParser(description='Utility for instantiating and testing integration instances')
    parser.add_argument('-u', '--user', help='The username for the login', required=True)
    parser.add_argument('-p', '--password', help='The password for the login', required=True)
    parser.add_argument('--ami_env', help='The AMI environment for the current run. Options are '
                                          '"Server Master", "Server 5.0". '
                                          'The server url is determined by the AMI environment.')
    parser.add_argument('-g', '--git_sha1', help='commit sha1 to compare changes with')
    parser.add_argument('-c', '--conf', help='Path to conf file', required=True)
    parser.add_argument('-s', '--secret', help='Path to secret conf file')
    parser.add_argument('-n', '--is-nightly', type=str2bool, help='Is nightly build')
    parser.add_argument('-pr', '--is_private', type=str2bool, help='Is private build')
    parser.add_argument('--branch', help='GitHub branch name', required=True)
    parser.add_argument('--build-number', help='CI job number where the instances were created', required=True)
    parser.add_argument('--test_pack_path', help='Path to where the test pack will be saved.',
                        default='/home/runner/work/content-private/content-private/content/artifacts/packs')
    parser.add_argument('--content_root', help='Path to the content root.',
                        default='/home/runner/work/content-private/content-private/content')
    parser.add_argument('--id_set_path', help='Path to the ID set.')
    parser.add_argument('-l', '--tests_to_run', help='Path to the Test Filter.',
                        default='./Tests/filter_file.txt')
    parser.add_argument('-pl', '--pack_ids_to_install', help='Path to the packs to install file.',
                        default='./Tests/content_packs_to_install.txt')
    # disable-secrets-detection-start
    parser.add_argument('-sa', '--service_account',
                        help=("Path to gcloud service account, is for circleCI usage. "
                              "For local development use your personal account and "
                              "authenticate using Google Cloud SDK by running: "
                              "`gcloud auth application-default login` and leave this parameter blank. "
                              "For more information go to: "
                              "https://googleapis.dev/python/google-api-core/latest/auth.html"),
                        required=False)
    # disable-secrets-detection-end
    options = parser.parse_args()

    return options


def check_test_version_compatible_with_server(test, server_version):
    """
    Checks if a given test is compatible wis the given server version.
    Arguments:
        test: (dict)
            Test playbook object from content conf.json. May contain the following fields: "playbookID",
            "integrations", "instance_names", "timeout", "nightly", "fromversion", "toversion.
        server_version: (int)
            The server numerical version.
    Returns:
        (bool) True if test is compatible with server version or False otherwise.
    """
    test_from_version = format_version(test.get('fromversion', '0.0.0'))
    test_to_version = format_version(test.get('toversion', '99.99.99'))
    server_version = format_version(server_version)

    if not (LooseVersion(test_from_version) <= LooseVersion(server_version) <= LooseVersion(test_to_version)):
        playbook_id = test.get('playbookID')
        logging.debug(
            f'Test Playbook: {playbook_id} was ignored in the content installation test due to version mismatch '
            f'(test versions: {test_from_version}-{test_to_version}, server version: {server_version})')
        return False
    return True


def filter_tests_with_incompatible_version(tests, server_version):
    """
    Filter all tests with incompatible version to the given server.
    Arguments:
        tests: (list)
            List of test objects.
        server_version: (int)
            The server numerical version.
    Returns:
        (lst): List of filtered tests (compatible version)
    """

    filtered_tests = [test for test in tests if
                      check_test_version_compatible_with_server(test, server_version)]
    return filtered_tests


def configure_integration_instance(integration, client, placeholders_map):
    """
    Configure an instance for an integration

    Arguments:
        integration: (dict)
            Integration object whose params key-values are set
        client: (demisto_client)
            The client to connect to
        placeholders_map: (dict)
             Dict that holds the real values to be replaced for each placeholder.

    Returns:
        (dict): Configured integration instance
    """
    integration_name = integration.get('name')
    logging.info(f'Configuring instance for integration "{integration_name}"')
    integration_instance_name = integration.get('instance_name', '')
    integration_params = change_placeholders_to_values(placeholders_map, integration.get('params'))
    is_byoi = integration.get('byoi', True)
    validate_test = integration.get('validate_test', True)

    integration_configuration = __get_integration_config(client, integration_name)
    if not integration_configuration:
        return None

    # In the integration configuration in content-test-conf conf.json, the test_validate flag was set to false
    if not validate_test:
        logging.debug(f'Skipping configuration for integration: {integration_name} (it has test_validate set to false)')
        return None
    module_instance = set_integration_instance_parameters(integration_configuration, integration_params,
                                                          integration_instance_name, is_byoi, client)
    return module_instance


def filepath_to_integration_name(integration_file_path):
    """Load an integration file and return the integration name.

    Args:
        integration_file_path (str): The path to an integration yml file.

    Returns:
        (str): The name of the integration.
    """
    integration_yaml = get_yaml(integration_file_path)
    integration_name = integration_yaml.get('name')
    return integration_name


def get_integration_names_from_files(integration_files_list):
    integration_names_list = [filepath_to_integration_name(path) for path in integration_files_list]
    return [name for name in integration_names_list if name]  # remove empty values


def get_new_and_modified_integration_files(branch_name):
    """Return 2 lists - list of new integrations and list of modified integrations since the first commit of the branch.

    Args:
        branch_name: The branch name against which we will run the 'git diff' command.

    Returns:
        (tuple): Returns a tuple of two lists, the file paths of the new integrations and modified integrations.
    """
    # get changed yaml files (filter only added and modified files)
    file_validator = ValidateManager()
    file_validator.branch_name = branch_name
    modified_files, added_files, _, _, _ = file_validator.get_modified_and_added_files('...', 'origin/master')

    new_integration_files = [
        file_path for file_path in added_files if
        find_type(file_path) in [FileType.INTEGRATION, FileType.BETA_INTEGRATION]
    ]

    modified_integration_files = [
        file_path for file_path in modified_files if
        isinstance(file_path, str) and find_type(file_path) in [FileType.INTEGRATION, FileType.BETA_INTEGRATION]
    ]
    return new_integration_files, modified_integration_files


def is_content_update_in_progress(client):
    """Make request to check if content is updating.

    Args:
        client (demisto_client): The configured client to use.

    Returns:
        (str): Returns the request response data which is 'true' if updating and 'false' if not.
    """
    host = client.api_client.configuration.host
    logging.debug(f'Making "Get" request to server - "{host}" to check if content is installing.')

    # make request to check if content is updating
    response_data, status_code, _ = demisto_client.generic_request_func(self=client, path='/content/updating',
                                                                        method='GET', accept='application/json')

    if status_code >= 300 or status_code < 200:
        result_object = ast.literal_eval(response_data)
        message = result_object.get('message', '')
        logging.error(f"Failed to check if content is installing - with status code {status_code}\n{message}")
        return 'request unsuccessful'

    return response_data


def get_content_version_details(client, ami_name):
    """Make request for details about the content installed on the demisto instance.

    Args:
        client (demisto_client): The configured client to use.
        ami_name (string): the role name of the machine

    Returns:
        (tuple): The release version and asset ID of the content installed on the demisto instance.
    """
    host = client.api_client.configuration.host
    logging.info(f'Making "POST" request to server - "{host}" to check installed content.')

    # make request to installed content details
    uri = '/content/installedlegacy' if ami_name in MARKET_PLACE_MACHINES else '/content/installed'
    response_data, status_code, _ = demisto_client.generic_request_func(self=client, path=uri,
                                                                        method='POST')

    try:
        result_object = ast.literal_eval(response_data)
        logging.debug(f'Response was {response_data}')
    except ValueError:
        logging.exception('failed to parse response from demisto.')
        return '', 0

    if status_code >= 300 or status_code < 200:
        message = result_object.get('message', '')
        logging.error(f'Failed to check if installed content details - with status code {status_code}\n{message}')
    return result_object.get('release', ''), result_object.get('assetId', 0)


def change_placeholders_to_values(placeholders_map, config_item):
    """Replaces placeholders in the object to their real values

    Args:
        placeholders_map: (dict)
             Dict that holds the real values to be replaced for each placeholder.
        config_item: (json object)
            Integration configuration object.

    Returns:
        dict. json object with the real configuration.
    """
    item_as_string = json.dumps(config_item)
    for key, value in placeholders_map.items():
        item_as_string = item_as_string.replace(key, str(value))
    return json.loads(item_as_string)


def set_integration_params(integrations, secret_params, instance_names, placeholders_map, logging_module=logging):
    """
    For each integration object, fill in the parameter values needed to configure an instance from
    the secret_params taken from our secret configuration file. Because there may be a number of
    configurations for a single integration (if there are values provided in our secret conf for
    multiple different instances of the same integration) then selects the parameter values for the
    configuration of the instance whose instance is in 'instance_names' (will take the last one listed
    in 'secret_params'). Note that this function does not explicitly return the modified 'integrations'
    object but rather it modifies the 'integrations' object since it is passed by reference and not by
    value, so the 'integrations' object that was passed to this function will have been changed once
    this function has completed execution and gone out of scope.

    Arguments:
        integrations: (list of dicts)
            List of integration objects whose 'params' attribute will be populated in this function.
        secret_params: (list of dicts)
            List of secret configuration values for all of our integrations (as well as specific
            instances of said integrations).
        instance_names: (list)
            The names of particular instances of an integration to use the secret_params of as the
            configuration values.
        placeholders_map: (dict)
             Dict that holds the real values to be replaced for each placeholder.
        logging_module (Union[ParallelLoggingManager,logging]): The logging module to use

    Returns:
        (bool): True if integrations params were filled with secret configuration values, otherwise false
    """
    for integration in integrations:
        integration_params = [change_placeholders_to_values(placeholders_map, item) for item
                              in secret_params if item['name'] == integration['name']]

        if integration_params:
            matched_integration_params = integration_params[0]
            # if there are more than one integration params, it means that there are configuration
            # values in our secret conf for multiple instances of the given integration and now we
            # need to match the configuration values to the proper instance as specified in the
            # 'instance_names' list argument
            if len(integration_params) != 1:
                found_matching_instance = False
                for item in integration_params:
                    if item.get('instance_name', 'Not Found') in instance_names:
                        matched_integration_params = item
                        found_matching_instance = True

                if not found_matching_instance:
                    optional_instance_names = [optional_integration.get('instance_name', 'None')
                                               for optional_integration in integration_params]
                    failed_match_instance_msg = 'There are {} instances of {}, please select one of them by using' \
                                                ' the instance_name argument in conf.json. The options are:\n{}'
                    logging_module.error(failed_match_instance_msg.format(len(integration_params),
                                                                          integration['name'],
                                                                          '\n'.join(optional_instance_names)))
                    return False

            integration['params'] = matched_integration_params.get('params', {})
            integration['byoi'] = matched_integration_params.get('byoi', True)
            integration['instance_name'] = matched_integration_params.get('instance_name', integration['name'])
            integration['validate_test'] = matched_integration_params.get('validate_test', True)

    return True


def set_module_params(param_conf, integration_params):
    """Configure a parameter object for use in a module instance.

    Each integration parameter is actually an object with many fields that together describe it. E.g. a given
    parameter will have all of the following fields - "name", "display", "value", "hasvalue", "defaultValue",
    etc. This function fills the "value" field for a parameter configuration object and returns it for use in
    a module instance.

    Args:
        param_conf (dict): The parameter configuration object.
        integration_params (dict): The values to use for an integration's parameters to configure an instance.

    Returns:
        (dict): The configured parameter object
    """
    if param_conf['display'] in integration_params or param_conf['name'] in integration_params:
        # param defined in conf
        key = param_conf['display'] if param_conf['display'] in integration_params else param_conf['name']
        if key == 'credentials':
            credentials = integration_params[key]
            param_value = {
                'credential': '',
                'identifier': credentials['identifier'],
                'password': credentials['password'],
                'passwordChanged': False
            }
        else:
            param_value = integration_params[key]

        param_conf['value'] = param_value
        param_conf['hasvalue'] = True
    elif param_conf['defaultValue']:
        # if the parameter doesn't have a value provided in the integration's configuration values
        # but does have a default value then assign it to the parameter for the module instance
        param_conf['value'] = param_conf['defaultValue']
    return param_conf


def __set_server_keys(client, integration_params, integration_name):
    """Adds server configuration keys using the demisto_client.

    Args:
        client (demisto_client): The configured client to use.
        integration_params (dict): The values to use for an integration's parameters to configure an instance.
        integration_name (str): The name of the integration which the server configurations keys are related to.

    """
    if 'server_keys' not in integration_params:
        return

    logging.info(f'Setting server keys for integration: {integration_name}')

    data = {
        'data': {},
        'version': -1
    }

    for key, value in integration_params.get('server_keys').items():
        data['data'][key] = value

    response_data, status_code, _ = demisto_client.generic_request_func(self=client, path='/system/config',
                                                                        method='POST', body=data)

    try:
        result_object = ast.literal_eval(response_data)
    except ValueError:
        logging.exception(f'failed to parse response from demisto. response is {response_data}')
        return

    if status_code >= 300 or status_code < 200:
        message = result_object.get('message', '')
        logging.error(f'Failed to set server keys, status_code: {status_code}, message: {message}')


def set_integration_instance_parameters(integration_configuration,
                                        integration_params,
                                        integration_instance_name,
                                        is_byoi,
                                        client):
    """Set integration module values for integration instance creation

    The integration_configuration and integration_params should match, in that
    they are for the same integration

    Arguments:
        integration_configuration: (dict)
            dictionary of the integration configuration parameters/keys that need
            filling to instantiate an instance of a given integration
        integration_params: (dict)
            values for a given integration taken from the configuration file in
            which the secret values are stored to configure instances of various
            integrations
        integration_instance_name: (str)
            The name of the integration instance being configured if there is one
            provided in the conf.json
        is_byoi: (bool)
            If the integration is byoi or not
        client: (demisto_client)
            The client to connect to

    Returns:
        (dict): The configured module instance to send to the Demisto server for
        instantiation.
    """
    module_configuration = integration_configuration.get('configuration', {})
    if not module_configuration:
        module_configuration = []

    if 'integrationInstanceName' in integration_params:
        instance_name = integration_params['integrationInstanceName']
    else:
        instance_name = '{}_test_{}'.format(integration_instance_name.replace(' ', '_'), str(uuid.uuid4()))

    # define module instance
    module_instance = {
        'brand': integration_configuration['name'],
        'category': integration_configuration['category'],
        'configuration': integration_configuration,
        'data': [],
        'enabled': "true",
        'engine': '',
        'id': '',
        'isIntegrationScript': is_byoi,
        'name': instance_name,
        'passwordProtected': False,
        'version': 0
    }

    # set server keys
    __set_server_keys(client, integration_params, integration_configuration['name'])

    # set module params
    for param_conf in module_configuration:
        configured_param = set_module_params(param_conf, integration_params)
        module_instance['data'].append(configured_param)

    return module_instance


def group_integrations(integrations, skipped_integrations_conf, new_integrations_names, modified_integrations_names):
    """
    Filter integrations into their respective lists - new, modified or unchanged. if it's on the skip list, then
    skip if random tests were chosen then we may be configuring integrations that are neither new or modified.

    Args:
        integrations (list): The integrations to categorize.
        skipped_integrations_conf (dict): Integrations that are on the skip list.
        new_integrations_names (list): The names of new integrations.
        modified_integrations_names (list): The names of modified integrations.

    Returns:
        (tuple): Lists of integrations objects as well as an Integration-to-Status dictionary useful for logs.
    """
    new_integrations = []
    modified_integrations = []
    unchanged_integrations = []
    integration_to_status = {}
    for integration in integrations:
        integration_name = integration.get('name', '')
        if integration_name in skipped_integrations_conf.keys():
            continue

        if integration_name in new_integrations_names:
            new_integrations.append(integration)
        elif integration_name in modified_integrations_names:
            modified_integrations.append(integration)
            integration_to_status[integration_name] = 'Modified Integration'
        else:
            unchanged_integrations.append(integration)
            integration_to_status[integration_name] = 'Unchanged Integration'
    return new_integrations, modified_integrations, unchanged_integrations, integration_to_status


def get_integrations_for_test(test, skipped_integrations_conf):
    """Return a list of integration objects that are necessary for a test (excluding integrations on the skip list).

    Args:
        test (dict): Test dictionary from the conf.json file containing the playbookID, integrations and
            instance names.
        skipped_integrations_conf (dict): Skipped integrations dictionary with integration names as keys and
            the skip reason as values.

    Returns:
        (list): List of integration objects to configure.
    """
    integrations_conf = test.get('integrations', [])

    if not isinstance(integrations_conf, list):
        integrations_conf = [integrations_conf]

    integrations = [
        {'name': integration, 'params': {}} for
        integration in integrations_conf if integration not in skipped_integrations_conf
    ]
    return integrations


def update_content_on_demisto_instance(client, server, ami_name):
    """Try to update the content

    Args:
        client (demisto_client): The configured client to use.
        server (str): The server url to pass to Tests/update_content_data.py
    """
    content_zip_path = 'artifacts/all_content.zip'
    update_content(content_zip_path, server=server, client=client)

    # Check if content update has finished installing
    sleep_interval = 20
    updating_content = is_content_update_in_progress(client)
    while updating_content.lower() == 'true':
        sleep(sleep_interval)
        updating_content = is_content_update_in_progress(client)

    if updating_content.lower() == 'request unsuccessful':
        # since the request to check if content update installation finished didn't work, can't use that mechanism
        # to check and just try sleeping for 30 seconds instead to allow for content update installation to complete
        logging.debug('Request to install content was unsuccessful, sleeping for 30 seconds and retrying')
        sleep(30)
    else:
        # check that the content installation updated
        # verify the asset id matches the circleci build number / asset_id in the content-descriptor.json
        release, asset_id = get_content_version_details(client, ami_name)
        with open('content-descriptor.json', 'r') as cd_file:
            cd_json = json.loads(cd_file.read())
            cd_release = cd_json.get('release')
            cd_asset_id = cd_json.get('assetId')
        if release == cd_release and asset_id == cd_asset_id:
            logging.success(f'Content Update Successfully Installed on server {server}.')
        else:
            logging.error(
                f'Content Update to version: {release} was Unsuccessful:\nAttempted to install content with release '
                f'"{cd_release}" and assetId "{cd_asset_id}" but release "{release}" and assetId "{asset_id}" '
                f'were retrieved from the instance post installation.')
            if ami_name not in MARKET_PLACE_MACHINES:
                os._exit(1)


def report_tests_status(preupdate_fails, postupdate_fails, preupdate_success, postupdate_success,
                        new_integrations_names):
    """Prints errors and/or warnings if there are any and returns whether whether testing was successful or not.

    Args:
        preupdate_fails (set): List of tuples of integrations that failed the "Test" button prior to content
            being updated on the demisto instance where each tuple is comprised of the integration name and the
            name of the instance that was configured for that integration which failed.
        postupdate_fails (set): List of tuples of integrations that failed the "Test" button after content was
            updated on the demisto instance where each tuple is comprised of the integration name and the name
            of the instance that was configured for that integration which failed.
        preupdate_success (set): List of tuples of integrations that succeeded the "Test" button prior to content
            being updated on the demisto instance where each tuple is comprised of the integration name and the
            name of the instance that was configured for that integration which failed.
        postupdate_success (set): List of tuples of integrations that succeeded the "Test" button after content was
            updated on the demisto instance where each tuple is comprised of the integration name and the name
            of the instance that was configured for that integration which failed.
        new_integrations_names (list): List of the names of integrations that are new since the last official
            content release and that will only be present on the demisto instance after the content update is
            performed.

    Returns:
        (bool): False if there were integration instances that succeeded prior to the content update and then
            failed after content was updated, otherwise True.
    """
    testing_status = True

    # a "Test" can be either successful both before and after content update(succeeded_pre_and_post variable),
    # fail on one of them(mismatched_statuses variable), or on both(failed_pre_and_post variable)
    succeeded_pre_and_post = preupdate_success.intersection(postupdate_success)
    if succeeded_pre_and_post:
        succeeded_pre_and_post_string = "\n".join(
            [f'Integration: "{integration_of_instance}", Instance: "{instance_name}"' for
             instance_name, integration_of_instance in succeeded_pre_and_post])
        logging.success(
            'Integration instances that had ("Test" Button) succeeded both before and after the content update:\n'
            f'{succeeded_pre_and_post_string}')

    failed_pre_and_post = preupdate_fails.intersection(postupdate_fails)
    mismatched_statuses = postupdate_fails - preupdate_fails
    failed_only_after_update = []
    failed_but_is_new = []
    for instance_name, integration_of_instance in mismatched_statuses:
        if integration_of_instance in new_integrations_names:
            failed_but_is_new.append((instance_name, integration_of_instance))
        else:
            failed_only_after_update.append((instance_name, integration_of_instance))

    # warnings but won't fail the build step
    if failed_but_is_new:
        failed_but_is_new_string = "\n".join(
            [f'Integration: "{integration_of_instance}", Instance: "{instance_name}"'
             for instance_name, integration_of_instance in failed_but_is_new])
        logging.warning(f'New Integrations ("Test" Button) Failures:\n{failed_but_is_new_string}')
    if failed_pre_and_post:
        failed_pre_and_post_string = "\n".join(
            [f'Integration: "{integration_of_instance}", Instance: "{instance_name}"'
             for instance_name, integration_of_instance in failed_pre_and_post])
        logging.warning(f'Integration instances that had ("Test" Button) failures '
                        f'both before and after the content update:\n{pformat(failed_pre_and_post_string)}')

    # fail the step if there are instances that only failed after content was updated
    if failed_only_after_update:
        failed_only_after_update_string = "\n".join(
            [f'Integration: "{integration_of_instance}", Instance: "{instance_name}"' for
             instance_name, integration_of_instance in failed_only_after_update])
        testing_status = False
        logging.critical('Integration instances that had ("Test" Button) failures only after content was updated:\n'
                         f'{pformat(failed_only_after_update_string)}.\n'
                         f'This indicates that your updates introduced breaking changes to the integration.')

    return testing_status


def get_env_conf():
    if Build.run_environment == Running.CIRCLECI_RUN:
        return get_json_file(Build.env_results_path)

    elif Build.run_environment == Running.WITH_LOCAL_SERVER:
        # START CHANGE ON LOCAL RUN #
        return [{
            "InstanceDNS": "http://localhost:8080",
            "Role": "Server Master"  # e.g. 'Server Master'
        }]
    elif Build.run_environment == Running.WITH_OTHER_SERVER:
        return [{
            "InstanceDNS": "DNS NANE",  # without http prefix
            "Role": "DEMISTO EVN"  # e.g. 'Server Master'
        }]
    #  END CHANGE ON LOCAL RUN  #


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


def get_json_file(path):
    with open(path, 'r') as json_file:
        return json.loads(json_file.read())


def configure_servers_and_restart(build):
    if LooseVersion(build.server_numeric_version) >= LooseVersion('5.5.0'):
        configurations = DOCKER_HARDENING_CONFIGURATION
        configure_types = ['docker hardening']
        if LooseVersion(build.server_numeric_version) >= LooseVersion('6.0.0'):
            configure_types.append('marketplace')
            configurations.update(MARKET_PLACE_CONFIGURATION)

        error_msg = 'failed to set {} configurations'.format(' and '.join(configure_types))
        manual_restart = Build.run_environment == Running.WITH_LOCAL_SERVER
        for server in build.servers:
            server.add_server_configuration(configurations, error_msg=error_msg, restart=not manual_restart)

        if manual_restart:
            input('restart your server and then press enter.')
        else:
            logging.info('Done restarting servers. Sleeping for 1 minute')
            sleep(60)


def restart_server(server):
    try:
        logging.info('Restarting servers to apply server config ...')

        # copy from .demisto_bashrc stop_server && start_server
        command = 'sudo systemctl restart demisto'
        SimpleSSH(host=server.replace('https://', '').replace('http://', ''), key_file_path=Build.key_file_path,
                  user='ec2-user').exec_command(command)
    except Exception:
        logging.exception('New SSH restart demisto failed')
        restart_server_legacy(server)


def restart_server_legacy(server):
    try:
        ssh_string = 'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {}@{} ' \
                     '"sudo systemctl restart demisto"'
        subprocess.check_output(
            ssh_string.format('ec2-user', server.replace('https://', '')), shell=True)
    except subprocess.CalledProcessError:
        logging.exception('Legacy SSH restart demisto failed')


def get_tests(build: Build) -> List[str]:
    """
    Selects the tests from that should be run in this execution and filters those that cannot run in this server version
    Args:
        build: Build object

    Returns:
        Test configurations from conf.json that should be run in this execution
    """
    server_numeric_version: str = build.server_numeric_version
    tests: dict = build.tests
    if Build.run_environment == Running.CIRCLECI_RUN:
        filtered_tests = extract_filtered_tests()
        if build.is_nightly:
            # skip test button testing
            logging.debug('Not running instance tests in nightly flow')
            tests_for_iteration = []
        elif filtered_tests:
            tests_for_iteration = [test for test in tests if test.get('playbookID', '') in filtered_tests]
        else:
            tests_for_iteration = tests

        tests_for_iteration = filter_tests_with_incompatible_version(tests_for_iteration, server_numeric_version)
        return tests_for_iteration
    else:
        # START CHANGE ON LOCAL RUN #
        return [
            {
                "playbookID": "Docker Hardening Test",
                "fromversion": "5.0.0"
            },
            {
                "integrations": "SplunkPy",
                "playbookID": "SplunkPy-Test-V2",
                "memory_threshold": 500,
                "instance_names": "use_default_handler"
            }
        ]
        #  END CHANGE ON LOCAL RUN  #


def get_changed_integrations(build: Build) -> tuple:
    """
    Return 2 lists - list of new integrations and list of modified integrations since the commit of the git_sha1.

    Args:
        build: the build object
    Returns:
        list of new integrations and list of modified integrations
    """
    new_integrations_files, modified_integrations_files = get_new_and_modified_integration_files(
        build.branch_name) if not build.is_private else ([], [])
    new_integrations_names, modified_integrations_names = [], []

    if new_integrations_files:
        new_integrations_names = get_integration_names_from_files(new_integrations_files)
        logging.debug(f'New Integrations Since Last Release:\n{new_integrations_names}')

    if modified_integrations_files:
        modified_integrations_names = get_integration_names_from_files(modified_integrations_files)
        logging.debug(f'Updated Integrations Since Last Release:\n{modified_integrations_names}')
    return new_integrations_names, modified_integrations_names


def get_pack_ids_to_install():
    if Build.run_environment == Running.CIRCLECI_RUN:
        with open('./Tests/content_packs_to_install.txt', 'r') as packs_stream:
            pack_ids = packs_stream.readlines()
            return [pack_id.rstrip('\n') for pack_id in pack_ids]
    else:
        # START CHANGE ON LOCAL RUN #
        return [
            'SplunkPy'
        ]
        #  END CHANGE ON LOCAL RUN  #


def nightly_install_packs(build, install_method=install_all_content_packs, pack_path=None, service_account=None):
    threads_list = []

    # For each server url we install pack/ packs
    for thread_index, server in enumerate(build.servers):
        kwargs = {'client': server.client, 'host': server.host}
        if service_account:
            kwargs['service_account'] = service_account
        if pack_path:
            kwargs['pack_path'] = pack_path
        threads_list.append(Thread(target=install_method, kwargs=kwargs))
    run_threads_list(threads_list)


def install_nightly_pack(build):
    nightly_install_packs(build, install_method=install_all_content_packs_for_nightly,
                          service_account=build.service_account)
    create_nightly_test_pack()
    nightly_install_packs(build, install_method=upload_zipped_packs,
                          pack_path=f'{Build.test_pack_target}/test_pack.zip')

    logging.info('Sleeping for 45 seconds while installing nightly packs')
    sleep(45)


def install_packs(build, pack_ids=None):
    pack_ids = get_pack_ids_to_install() if pack_ids is None else pack_ids
    installed_content_packs_successfully = True
    for server in build.servers:
        try:
            _, flag = search_and_install_packs_and_their_dependencies(pack_ids, server.client)
            if not flag:
                raise Exception('Failed to search and install packs.')
        except Exception:
            logging.exception('Failed to search and install packs')
            installed_content_packs_successfully = False

    return installed_content_packs_successfully


def configure_server_instances(build: Build, tests_for_iteration, all_new_integrations, modified_integrations):
    modified_module_instances = []
    new_module_instances = []
    testing_client = build.servers[0].client
    for test in tests_for_iteration:
        integrations = get_integrations_for_test(test, build.skipped_integrations_conf)

        playbook_id = test.get('playbookID')

        new_integrations, modified_integrations, unchanged_integrations, integration_to_status = group_integrations(
            integrations, build.skipped_integrations_conf, all_new_integrations, modified_integrations
        )
        integration_to_status_string = '\n\t\t\t\t\t\t'.join(
            [f'"{key}" - {val}' for key, val in integration_to_status.items()])
        if integration_to_status_string:
            logging.info(f'All Integrations for test "{playbook_id}":\n\t\t\t\t\t\t{integration_to_status_string}')
        else:
            logging.info(f'No Integrations for test "{playbook_id}"')
        instance_names_conf = test.get('instance_names', [])
        if not isinstance(instance_names_conf, list):
            instance_names_conf = [instance_names_conf]

        integrations_to_configure = modified_integrations[:]
        integrations_to_configure.extend(unchanged_integrations)
        placeholders_map = {'%%SERVER_HOST%%': build.servers[0]}
        new_ints_params_set = set_integration_params(new_integrations, build.secret_conf['integrations'],
                                                     instance_names_conf,
                                                     placeholders_map)
        ints_to_configure_params_set = set_integration_params(integrations_to_configure,
                                                              build.secret_conf['integrations'],
                                                              instance_names_conf, placeholders_map)
        if not new_ints_params_set:
            logging.error(f'failed setting parameters for integrations: {new_integrations}')
        if not ints_to_configure_params_set:
            logging.error(f'failed setting parameters for integrations: {integrations_to_configure}')
        if not (new_ints_params_set and ints_to_configure_params_set):
            continue

        modified_module_instances_for_test, new_module_instances_for_test = configure_modified_and_new_integrations(
            build,
            integrations_to_configure,
            new_integrations,
            testing_client)

        modified_module_instances.extend(modified_module_instances_for_test)
        new_module_instances.extend(new_module_instances_for_test)
    return modified_module_instances, new_module_instances


def configure_modified_and_new_integrations(build: Build,
                                            modified_integrations_to_configure: list,
                                            new_integrations_to_configure: list,
                                            demisto_client: demisto_client) -> tuple:
    """
    Configures old and new integrations in the server configured in the demisto_client.
    Args:
        build: The build object
        modified_integrations_to_configure: Integrations to configure that are already exists
        new_integrations_to_configure: Integrations to configure that were created in this build
        demisto_client: A demisto client

    Returns:
        A tuple with two lists:
        1. List of configured instances of modified integrations
        2. List of configured instances of new integrations
    """
    modified_modules_instances = []
    new_modules_instances = []
    for integration in modified_integrations_to_configure:
        placeholders_map = {'%%SERVER_HOST%%': build.servers[0]}
        module_instance = configure_integration_instance(integration, demisto_client, placeholders_map)
        if module_instance:
            modified_modules_instances.append(module_instance)
    for integration in new_integrations_to_configure:
        placeholders_map = {'%%SERVER_HOST%%': build.servers[0]}
        module_instance = configure_integration_instance(integration, demisto_client, placeholders_map)
        if module_instance:
            new_modules_instances.append(module_instance)
    return modified_modules_instances, new_modules_instances


def instance_testing(build: Build, all_module_instances, pre_update):
    update_status = 'Pre' if pre_update else 'Post'
    failed_tests = set()
    successful_tests = set()
    # Test all module instances (of modified + unchanged integrations) pre-updating content
    if all_module_instances:
        # only print start message if there are instances to configure
        logging.info(f'Start of Instance Testing ("Test" button) ({update_status}-update)')
    else:
        logging.info(f'No integrations to configure for the chosen tests. ({update_status}-update)')
    for instance in all_module_instances:
        integration_of_instance = instance.get('brand', '')
        instance_name = instance.get('name', '')
        testing_client = build.servers[0].reconnect_client()
        # If there is a failure, __test_integration_instance will print it
        if integration_of_instance not in build.unmockable_integrations:
            has_mock_file = build.proxy.has_mock_file(integration_of_instance)
            success = False
            if has_mock_file:
                with run_with_mock(build.proxy, integration_of_instance) as result_holder:
                    success, _ = __test_integration_instance(testing_client, instance)
                    result_holder[RESULT] = success
            if not success:
                with run_with_mock(build.proxy, integration_of_instance, record=True) as result_holder:
                    success, _ = __test_integration_instance(testing_client, instance)
                    result_holder[RESULT] = success
        else:
            success, _ = __test_integration_instance(testing_client, instance)
        if not success:
            failed_tests.add((instance_name, integration_of_instance))
        else:
            successful_tests.add((instance_name, integration_of_instance))

    return successful_tests, failed_tests


def update_content_till_v6(build: Build):
    threads_list = []
    # For each server url we install content
    for thread_index, server in enumerate(build.servers):
        t = Thread(target=update_content_on_demisto_instance,
                   kwargs={'client': server.client, 'server': server.host, 'ami_name': build.ami_env})
        threads_list.append(t)

    run_threads_list(threads_list)


def disable_instances(build: Build):
    for server in build.servers:
        disable_all_integrations(server.client)


def create_nightly_test_pack():
    test_pack_zip(Build.content_path, Build.test_pack_target)


def test_files(content_path):
    packs_root = f'{content_path}/Packs'
    packs = filter(lambda x: x.is_dir(), os.scandir(packs_root))
    for pack_dir in packs:
        if pack_dir in SKIPPED_PACKS:
            continue
        playbooks_root = f'{pack_dir.path}/TestPlaybooks'
        if os.path.isdir(playbooks_root):
            for playbook_path, playbook in get_test_playbooks_in_dir(playbooks_root):
                yield playbook_path, playbook
            if os.path.isdir(f'{playbooks_root}/NonCircleTests'):
                for playbook_path, playbook in get_test_playbooks_in_dir(f'{playbooks_root}/NonCircleTests'):
                    yield playbook_path, playbook


def get_test_playbooks_in_dir(path):
    playbooks = filter(lambda x: x.is_file(), os.scandir(path))
    for playbook in playbooks:
        yield playbook.path, playbook


def test_pack_metadata():
    now = datetime.now().isoformat().split('.')[0]
    now = f'{now}Z'
    metadata = {
        "name": "nightly test",
        "id": str(uuid.uuid4()),
        "description": "nightly test pack (all test playbooks and scripts).",
        "created": now,
        "updated": now,
        "legacy": True,
        "support": "Cortex XSOAR",
        "supportDetails": {},
        "author": "Cortex XSOAR",
        "authorImage": "",
        "certification": "certified",
        "price": 0,
        "serverMinVersion": "6.0.0",
        "serverLicense": "",
        "currentVersion": "1.0.0",
        "general": [],
        "tags": [],
        "categories": [
            "Forensics & Malware Analysis"
        ],
        "contentItems": {},
        "integrations": [],
        "useCases": [],
        "keywords": [],
        "dependencies": {}
    }
    return json.dumps(metadata, indent=4)


def test_pack_zip(content_path, target):
    with zipfile.ZipFile(f'{target}/test_pack.zip', 'w', zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr('test_pack/metadata.json', test_pack_metadata())
        for test_path, test in test_files(content_path):
            if not test_path.endswith('.yml'):
                continue
            test = test.name
            with open(test_path, 'r') as test_file:
                if not (test.startswith('playbook-') or test.startswith('script-')):
                    test_type = find_type(_dict=yaml.safe_load(test_file), file_type='yml').value
                    test_file.seek(0)
                    test_target = f'test_pack/TestPlaybooks/{test_type}-{test}'
                else:
                    test_target = f'test_pack/TestPlaybooks/{test}'
                zip_file.writestr(test_target, test_file.read())


def get_non_added_packs_ids(build: Build):
    """

    :param build: the build object
    :return: all non added packs i.e. unchanged packs (dependencies) and modified packs
    """
    compare_against = 'origin/master{}'.format('' if not build.branch_name == 'master' else '~1')
    added_files = run_command(f'git diff --name-only --diff-filter=A '
                              f'{compare_against}..refs/heads/{build.branch_name} -- Packs/*/pack_metadata.json')
    added_files = filter(lambda x: x, added_files.split('\n'))
    added_pack_ids = map(lambda x: x.split('/')[1], added_files)
    return set(get_pack_ids_to_install()) - set(added_pack_ids)


def set_marketplace_url(servers, branch_name, ci_build_number):
    url_suffix = f'{branch_name}/{ci_build_number}'
    config_path = 'marketplace.bootstrap.bypass.url'
    config = {config_path: f'https://storage.googleapis.com/marketplace-ci-build/content/builds/{url_suffix}'}
    for server in servers:
        server.add_server_configuration(config, 'failed to configure marketplace custom url ', True)
    logging.success('Updated marketplace url and restarted servers')
    logging.info('sleeping for 60 seconds')
    sleep(60)


def test_integrations_post_update(build: Build, new_module_instances: list, modified_module_instances: list) -> tuple:
    """
    Runs 'test-module on all integrations for post-update check
    Args:
        build: A build object
        new_module_instances: A list containing new integrations instances to run test-module on
        modified_module_instances: A list containing old (existing) integrations instances to run test-module on

    Returns:
        * A list of integration names that have failed the 'test-module' execution post update
        * A list of integration names that have succeeded the 'test-module' execution post update
    """
    modified_module_instances.extend(new_module_instances)
    successful_tests_post, failed_tests_post = instance_testing(build, modified_module_instances, pre_update=False)
    return successful_tests_post, failed_tests_post


def update_content_on_servers(build: Build) -> bool:
    """
    Updates content on the build's server according to the server version
    Args:
        build: Build object

    Returns:
        A boolean that indicates whether the content installation was successful.
        If the server version is lower then 5.9.9 will return the 'installed_content_packs_successfully' parameter as is
        If the server version is higher or equal to 6.0 - will return True if the packs installation was successful
        both before that update and after the update.
    """
    installed_content_packs_successfully = True
    if LooseVersion(build.server_numeric_version) < LooseVersion('6.0.0'):
        update_content_till_v6(build)
    elif not build.is_nightly:
        set_marketplace_url(build.servers, build.branch_name, build.ci_build_number)
        installed_content_packs_successfully = install_packs(build)
    return installed_content_packs_successfully


def configure_and_test_integrations_pre_update(build: Build, new_integrations, modified_integrations) -> tuple:
    """
    Configures integration instances that exist in the current version and for each integration runs 'test-module'.
    Args:
        build: Build object
        new_integrations: A list containing new integrations names
        modified_integrations: A list containing modified integrations names

    Returns:
        A tuple consists of:
        * A list of modified module instances configured
        * A list of new module instances configured
        * A list of integrations that have failed the 'test-module' command execution
        * A list of integrations that have succeeded the 'test-module' command execution
        * A list of new integrations names
    """
    tests_for_iteration = get_tests(build)
    modified_module_instances, new_module_instances = configure_server_instances(build,
                                                                                 tests_for_iteration,
                                                                                 new_integrations,
                                                                                 modified_integrations)
    successful_tests_pre, failed_tests_pre = instance_testing(build, modified_module_instances, pre_update=True)
    return modified_module_instances, new_module_instances, failed_tests_pre, successful_tests_pre


def install_packs_pre_update(build: Build) -> bool:
    """
    Install packs on server according to server version
    Args:
        build: A build object

    Returns:
        A boolean that indicates whether the installation was successful or not
    """
    installed_content_packs_successfully = False
    if LooseVersion(build.server_numeric_version) >= LooseVersion('6.0.0'):
        if build.is_nightly:
            install_nightly_pack(build)
            installed_content_packs_successfully = True
        else:
            if not build.is_private:
                pack_ids = get_non_added_packs_ids(build)
                installed_content_packs_successfully = install_packs(build, pack_ids=pack_ids)
    else:
        installed_content_packs_successfully = True
    return installed_content_packs_successfully


def main():
    install_logging('Install Content And Configure Integrations On Server.log')
    build = Build(options_handler())

    configure_servers_and_restart(build)
    disable_instances(build)
    installed_content_packs_successfully = install_packs_pre_update(build)

    new_integrations, modified_integrations = get_changed_integrations(build)

    pre_update_configuration_results = configure_and_test_integrations_pre_update(build,
                                                                                  new_integrations,
                                                                                  modified_integrations)
    modified_module_instances, new_module_instances, failed_tests_pre, successful_tests_pre = pre_update_configuration_results
    installed_content_packs_successfully = update_content_on_servers(build) and installed_content_packs_successfully

    successful_tests_post, failed_tests_post = test_integrations_post_update(build,
                                                                             new_module_instances,
                                                                             modified_module_instances)

    success = report_tests_status(failed_tests_pre, failed_tests_post, successful_tests_pre, successful_tests_post,
                                  new_integrations)
    if not success or not installed_content_packs_successfully:
        sys.exit(2)


if __name__ == '__main__':
    main()
