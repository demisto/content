from __future__ import print_function

import argparse
import logging
import os
import uuid
import json
import ast
import subprocess
import sys
import zipfile
from datetime import datetime
from enum import IntEnum
from time import sleep
from threading import Thread
from distutils.version import LooseVersion

from demisto_sdk.commands.validate.validate_manager import ValidateManager
from paramiko.client import SSHClient, AutoAddPolicy
import demisto_client
from ruamel import yaml

from demisto_sdk.commands.common.tools import print_error, print_warning, print_color, LOG_COLORS, run_threads_list, \
    run_command, get_yaml, str2bool, format_version, find_type
from demisto_sdk.commands.common.constants import RUN_ALL_TESTS_FORMAT, FileType
from Tests.test_integration import __get_integration_config, __test_integration_instance, \
    __disable_integrations_instances
from Tests.test_content import extract_filtered_tests, ParallelPrintsManager, \
    get_server_numeric_version
from Tests.update_content_data import update_content
from Tests.Marketplace.search_and_install_packs import search_and_install_packs_and_their_dependencies, \
    install_all_content_packs, upload_zipped_packs

from Tests.tools import update_server_configuration

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


def get_id_set() -> dict:
    """
    Used to collect the ID set so it can be passed to the Build class on init.

    :return: ID set as a dict if it exists.
    """
    if os.path.isfile(ID_SET_PATH):
        return get_json_file(ID_SET_PATH)


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
        self.id_set = get_id_set()

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
                                          '"Server Master", "Demisto GA", "Demisto one before GA", "Demisto two before '
                                          'GA". The server url is determined by the AMI environment.')
    parser.add_argument('-g', '--git_sha1', help='commit sha1 to compare changes with')
    parser.add_argument('-c', '--conf', help='Path to conf file', required=True)
    parser.add_argument('-s', '--secret', help='Path to secret conf file')
    parser.add_argument('-n', '--is-nightly', type=str2bool, help='Is nightly build')
    parser.add_argument('-pr', '--is_private', type=str2bool, help='Is private build')
    parser.add_argument('--branch', help='GitHub branch name', required=True)
    parser.add_argument('--build-number', help='CI job number where the instances were created', required=True)

    options = parser.parse_args()

    return options


def check_test_version_compatible_with_server(test, server_version, prints_manager):
    """
    Checks if a given test is compatible wis the given server version.
    Arguments:
        test: (dict)
            Test playbook object from content conf.json. May contain the following fields: "playbookID",
            "integrations", "instance_names", "timeout", "nightly", "fromversion", "toversion.
        server_version: (int)
            The server numerical version.
        prints_manager: (ParallelPrintsManager)
            Print manager object.
    Returns:
        (bool) True if test is compatible with server version or False otherwise.
    """
    test_from_version = format_version(test.get('fromversion', '0.0.0'))
    test_to_version = format_version(test.get('toversion', '99.99.99'))
    server_version = format_version(server_version)

    if not (LooseVersion(test_from_version) <= LooseVersion(server_version) <= LooseVersion(test_to_version)):
        warning_message = 'Test Playbook: {} was ignored in the content installation test due to version mismatch ' \
                          '(test versions: {}-{}, server version: {})'.format(test.get('playbookID'),
                                                                              test_from_version,
                                                                              test_to_version,
                                                                              server_version)
        prints_manager.add_print_job(warning_message, print_warning, 0)
        return False
    return True


def filter_tests_with_incompatible_version(tests, server_version, prints_manager):
    """
    Filter all tests with incompatible version to the given server.
    Arguments:
        tests: (list)
            List of test objects.
        server_version: (int)
            The server numerical version.
        prints_manager: (ParallelPrintsManager)
            Print manager object.

    Returns:
        (lst): List of filtered tests (compatible version)
    """

    filtered_tests = [test for test in tests if
                      check_test_version_compatible_with_server(test, server_version, prints_manager)]
    prints_manager.execute_thread_prints(0)
    return filtered_tests


def configure_integration_instance(integration, client, prints_manager, placeholders_map):
    """
    Configure an instance for an integration

    Arguments:
        integration: (dict)
            Integration object whose params key-values are set
        client: (demisto_client)
            The client to connect to
        prints_manager: (ParallelPrintsManager)
            Print manager object
        placeholders_map: (dict)
             Dict that holds the real values to be replaced for each placeholder.

    Returns:
        (dict): Configured integration instance
    """
    integration_name = integration.get('name')
    prints_manager.add_print_job('Configuring instance for integration "{}"\n'.format(integration_name),
                                 print_color, 0, LOG_COLORS.GREEN)
    prints_manager.execute_thread_prints(0)
    integration_instance_name = integration.get('instance_name', '')
    integration_params = change_placeholders_to_values(placeholders_map, integration.get('params'))
    is_byoi = integration.get('byoi', True)
    validate_test = integration.get('validate_test', True)

    integration_configuration = __get_integration_config(client, integration_name, prints_manager)
    prints_manager.execute_thread_prints(0)
    if not integration_configuration:
        return None

    # In the integration configuration in content-test-conf conf.json, the test_validate flag was set to false
    if not validate_test:
        skipping_configuration_message = \
            "Skipping configuration for integration: {} (it has test_validate set to false)".format(integration_name)
        prints_manager.add_print_job(skipping_configuration_message, print_warning, 0)
        prints_manager.execute_thread_prints(0)
        return None
    module_instance = set_integration_instance_parameters(integration_configuration, integration_params,
                                                          integration_instance_name, is_byoi, client, prints_manager)
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


def get_new_and_modified_integration_files(build):
    """Return 2 lists - list of new integrations and list of modified integrations since the commit of the git_sha1.

    Args:
        git_sha1 (str): The git sha of the commit against which we will run the 'git diff' command.

    Returns:
        (tuple): Returns a tuple of two lists, the file paths of the new integrations and modified integrations.
    """
    # get changed yaml files (filter only added and modified files)
    file_validator = ValidateManager()
    file_validator.branch_name = build.branch_name
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


def is_content_update_in_progress(client, prints_manager, thread_index):
    """Make request to check if content is updating.

    Args:
        client (demisto_client): The configured client to use.
        prints_manager (ParallelPrintsManager): Print manager object
        thread_index (int): The thread index

    Returns:
        (str): Returns the request response data which is 'true' if updating and 'false' if not.
    """
    host = client.api_client.configuration.host
    prints_manager.add_print_job(
        '\nMaking "Get" request to server - "{}" to check if content is installing.'.format(host), print,
        thread_index)

    # make request to check if content is updating
    response_data, status_code, _ = demisto_client.generic_request_func(self=client, path='/content/updating',
                                                                        method='GET', accept='application/json')

    if status_code >= 300 or status_code < 200:
        result_object = ast.literal_eval(response_data)
        message = result_object.get('message', '')
        msg = "Failed to check if content is installing - with status code " + str(status_code) + '\n' + message
        prints_manager.add_print_job(msg, print_error, thread_index)
        return 'request unsuccessful'

    return response_data


def get_content_version_details(client, ami_name, prints_manager, thread_index):
    """Make request for details about the content installed on the demisto instance.

    Args:
        client (demisto_client): The configured client to use.
        ami_name (string): the role name of the machine
        prints_manager (ParallelPrintsManager): Print manager object
        thread_index (int): The thread index

    Returns:
        (tuple): The release version and asset ID of the content installed on the demisto instance.
    """
    host = client.api_client.configuration.host
    installed_content_message = '\nMaking "POST" request to server - "{}" to check installed content.'.format(host)
    prints_manager.add_print_job(installed_content_message, print_color, thread_index, LOG_COLORS.GREEN)

    # make request to installed content details
    uri = '/content/installedlegacy' if ami_name in MARKET_PLACE_MACHINES else '/content/installed'
    response_data, status_code, _ = demisto_client.generic_request_func(self=client, path=uri,
                                                                        method='POST')

    try:
        result_object = ast.literal_eval(response_data)
    except ValueError as err:
        print_error('failed to parse response from demisto. response is {}.\nError:\n{}'.format(response_data, err))
        return '', 0

    if status_code >= 300 or status_code < 200:
        message = result_object.get('message', '')
        msg = "Failed to check if installed content details - with status code " + str(status_code) + '\n' + message
        print_error(msg)
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


def set_integration_params(integrations, secret_params, instance_names, placeholders_map):
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
                    print_error(failed_match_instance_msg.format(len(integration_params),
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


def __set_server_keys(client, prints_manager, integration_params, integration_name):
    """Adds server configuration keys using the demisto_client.

    Args:
        client (demisto_client): The configured client to use.
        prints_manager (ParallelPrintsManager): Print manager object.
        integration_params (dict): The values to use for an integration's parameters to configure an instance.
        integration_name (str): The name of the integration which the server configurations keys are related to.

    """
    if 'server_keys' not in integration_params:
        return

    prints_manager.add_print_job(f'Setting server keys for integration: {integration_name}',
                                 print_color, 0, LOG_COLORS.GREEN)

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
    except ValueError as err:
        print_error(
            'failed to parse response from demisto. response is {}.\nError:\n{}'.format(response_data, err))
        return

    if status_code >= 300 or status_code < 200:
        message = result_object.get('message', '')
        msg = "Failed to set server keys " + str(status_code) + '\n' + message
        print_error(msg)


def set_integration_instance_parameters(integration_configuration, integration_params, integration_instance_name,
                                        is_byoi, client, prints_manager):
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
        prints_manager: (ParallelPrintsManager)
            Print manager object

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
    __set_server_keys(client, prints_manager, integration_params, integration_configuration['name'])

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


def update_content_on_demisto_instance(client, server, ami_name, prints_manager, thread_index):
    """Try to update the content

    Args:
        client (demisto_client): The configured client to use.
        server (str): The server url to pass to Tests/update_content_data.py
        prints_manager (ParallelPrintsManager): Print manager object
        thread_index (int): The thread index
    """
    content_zip_path = 'artifacts/all_content.zip'
    update_content(content_zip_path, server=server, client=client)

    # Check if content update has finished installing
    sleep_interval = 20
    updating_content = is_content_update_in_progress(client, prints_manager, thread_index)
    while updating_content.lower() == 'true':
        sleep(sleep_interval)
        updating_content = is_content_update_in_progress(client, prints_manager, thread_index)

    if updating_content.lower() == 'request unsuccessful':
        # since the request to check if content update installation finished didn't work, can't use that mechanism
        # to check and just try sleeping for 30 seconds instead to allow for content update installation to complete
        sleep(30)
    else:
        # check that the content installation updated
        # verify the asset id matches the circleci build number / asset_id in the content-descriptor.json
        release, asset_id = get_content_version_details(client, ami_name, prints_manager, thread_index)
        with open('content-descriptor.json', 'r') as cd_file:
            cd_json = json.loads(cd_file.read())
            cd_release = cd_json.get('release')
            cd_asset_id = cd_json.get('assetId')
        if release == cd_release and asset_id == cd_asset_id:
            prints_manager.add_print_job('Content Update Successfully Installed!', print_color, thread_index,
                                         LOG_COLORS.GREEN)
        else:
            err_details = 'Attempted to install content with release "{}" and assetId '.format(cd_release)
            err_details += '"{}" but release "{}" and assetId "{}" were '.format(cd_asset_id, release, asset_id)
            err_details += 'retrieved from the instance post installation.'
            prints_manager.add_print_job(
                'Content Update to version: {} was Unsuccessful:\n{}'.format(release, err_details),
                print_error, thread_index)
            prints_manager.execute_thread_prints(thread_index)

            if ami_name not in MARKET_PLACE_MACHINES:
                os._exit(1)


def report_tests_status(preupdate_fails, postupdate_fails, preupdate_success, postupdate_success,
                        new_integrations_names, prints_manager):
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
        prints_manager: (ParallelPrintsManager)
            Print manager object

    Returns:
        (bool): False if there were integration instances that succeeded prior to the content update and then
            failed after content was updated, otherwise True.
    """
    testing_status = True

    # a "Test" can be either successful both before and after content update(succeeded_pre_and_post variable),
    # fail on one of them(mismatched_statuses variable), or on both(failed_pre_and_post variable)
    succeeded_pre_and_post = preupdate_success.intersection(postupdate_success)
    if succeeded_pre_and_post:
        succeeded_message = '\nIntegration instances that had ("Test" Button) succeeded' \
                            ' both before and after the content update'
        prints_manager.add_print_job(succeeded_message, print_color, 0, LOG_COLORS.GREEN)
        for instance_name, integration_of_instance in succeeded_pre_and_post:
            prints_manager.add_print_job(
                'Integration: "{}", Instance: "{}"'.format(integration_of_instance, instance_name),
                print_color, 0, LOG_COLORS.GREEN)

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
        prints_manager.add_print_job('New Integrations ("Test" Button) Failures', print_warning, 0)
        for instance_name, integration_of_instance in failed_but_is_new:
            prints_manager.add_print_job(
                'Integration: "{}", Instance: "{}"'.format(integration_of_instance, instance_name), print_warning, 0)
    if failed_pre_and_post:
        failure_category = '\nIntegration instances that had ("Test" Button) failures' \
                           ' both before and after the content update'
        prints_manager.add_print_job(failure_category, print_warning, 0)
        for instance_name, integration_of_instance in failed_pre_and_post:
            prints_manager.add_print_job(
                'Integration: "{}", Instance: "{}"'.format(integration_of_instance, instance_name), print_warning, 0)

    # fail the step if there are instances that only failed after content was updated
    if failed_only_after_update:
        testing_status = False
        failure_category = '\nIntegration instances that had ("Test" Button) failures' \
                           ' only after content was updated. This indicates that your' \
                           ' updates introduced breaking changes to the integration.'
        prints_manager.add_print_job(failure_category, print_error, 0)
        for instance_name, integration_of_instance in failed_only_after_update:
            prints_manager.add_print_job(
                'Integration: "{}", Instance: "{}"'.format(integration_of_instance, instance_name), print_error, 0)

    prints_manager.execute_thread_prints(0)

    return testing_status


def set_marketplace_gcp_bucket_for_build(client, prints_manager, branch_name, ci_build_number, is_nightly, is_private):
    """Sets custom marketplace GCP bucket based on branch name and build number

    Args:
        client (demisto_client): The configured client to use.
        prints_manager (ParallelPrintsManager): Print manager object
        branch_name (str): GitHub branch name
        ci_build_number (str): CI build number

    Returns:
        response_data: The response data
        status_code: The response status code
    """
    host = client.api_client.configuration.host
    installed_content_message = \
        '\nMaking "POST" request to server - "{}" to set GCP bucket server configuration.'.format(host)
    prints_manager.add_print_job(installed_content_message, print_color, 0, LOG_COLORS.GREEN)

    # make request to update server configs
    # disable-secrets-detection-start
    server_configuration = {
        'content.pack.verify': 'false',
        'marketplace.initial.sync.delay': '0',
        'content.pack.ignore.missing.warnings.contentpack': 'true'
    }
    if is_private:
        server_configuration['marketplace.bootstrap.bypass.url'] = 'https://storage.googleapis.com/marketplace-ci-build'
        server_configuration['marketplace.gcp.path'] = 'content/builds/{}/{}/content/packs'.format(branch_name,
                                                                                                   ci_build_number)
        server_configuration['jobs.marketplacepacks.schedule'] = '1m'
        server_configuration[
            'marketplace.premium.gateway.service.url'] = 'https://xsoar-premium-content-team-gateway.demisto.works'
    elif not is_nightly:
        server_configuration['marketplace.bootstrap.bypass.url'] = \
            'https://storage.googleapis.com/marketplace-ci-build/content/builds/{}/{}'.format(
                branch_name, ci_build_number)
    error_msg = "Failed to set GCP bucket server config - with status code "
    # disable-secrets-detection-end
    return update_server_configuration(client, server_configuration, error_msg)


def set_docker_hardening_for_build(client, prints_manager):
    """Sets docker hardening configuration

    Args:
        client (demisto_client): The configured client to use.
        prints_manager (ParallelPrintsManager): Print manager object

    Returns:
        response_data: The response data
        status_code: The response status code
    """
    host = client.api_client.configuration.host
    installed_content_message = \
        '\nMaking "POST" request to server - "{}" to set docker hardening server configuration.'.format(host)
    prints_manager.add_print_job(installed_content_message, print_color, 0, LOG_COLORS.GREEN)

    # make request to update server configs
    server_configuration = {
        'docker.cpu.limit': '1.0',
        'docker.run.internal.asuser': 'true',
        'limit.docker.cpu': 'true',
        'python.pass.extra.keys': '--memory=1g##--memory-swap=-1##--pids-limit=256##--ulimit=nofile=1024:8192'
    }
    error_msg = "Failed to set docker hardening server config - with status code "

    return update_server_configuration(client, server_configuration, error_msg)


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


def configure_servers_and_restart(build, prints_manager):
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
            prints_manager.add_print_job('Done restarting servers.\nSleeping for 1 minute...', print_warning, 0)
            prints_manager.execute_thread_prints(0)
            sleep(60)


def restart_server(server):
    try:
        print('Restarting servers to apply server config ...')

        # copy from .demisto_bashrc stop_server && start_server
        command = 'sudo systemctl restart demisto'
        SimpleSSH(host=server.replace('https://', '').replace('http://', ''), key_file_path=Build.key_file_path,
                  user='ec2-user').exec_command(command)
    except Exception as error:
        print_error(f'New SSH restart demisto failed with error: {str(error)}')
        print(error.__traceback__)
        restart_server_legacy(server)


def restart_server_legacy(server):
    try:
        ssh_string = 'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {}@{} ' \
                     '"sudo systemctl restart demisto"'
        subprocess.check_output(
            ssh_string.format('ec2-user', server.replace('https://', '')), shell=True)
    except subprocess.CalledProcessError as exc:
        print(exc.output)


def get_tests(server_numeric_version, prints_manager, tests):
    if Build.run_environment == Running.CIRCLECI_RUN:
        filtered_tests, filter_configured, run_all_tests = extract_filtered_tests()
        if run_all_tests:
            # skip test button testing
            skipped_instance_test_message = 'Not running instance tests when {} is turned on'.format(
                RUN_ALL_TESTS_FORMAT)
            prints_manager.add_print_job(skipped_instance_test_message, print_warning, 0)
            tests_for_iteration = []
        elif filter_configured and filtered_tests:
            tests_for_iteration = [test for test in tests if test.get('playbookID', '') in filtered_tests]
        else:
            tests_for_iteration = tests

        tests_for_iteration = filter_tests_with_incompatible_version(tests_for_iteration, server_numeric_version,
                                                                     prints_manager)
        prints_manager.execute_thread_prints(0)

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


def get_changed_integrations(build, prints_manager):
    new_integrations_files, modified_integrations_files = get_new_and_modified_integration_files(
        build) if not build.is_private else ([], [])
    new_integrations_names, modified_integrations_names = [], []

    if new_integrations_files:
        new_integrations_names = get_integration_names_from_files(new_integrations_files)
        new_integrations_names_message = \
            'New Integrations Since Last Release:\n{}\n'.format('\n'.join(new_integrations_names))
        prints_manager.add_print_job(new_integrations_names_message, print_warning, 0)

    if modified_integrations_files:
        modified_integrations_names = get_integration_names_from_files(modified_integrations_files)
        modified_integrations_names_message = \
            'Updated Integrations Since Last Release:\n{}\n'.format('\n'.join(modified_integrations_names))
        prints_manager.add_print_job(modified_integrations_names_message, print_warning, 0)
    prints_manager.execute_thread_prints(0)
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


def nightly_install_packs(build, threads_print_manager, install_method=install_all_content_packs, pack_path=None):
    threads_list = []

    # For each server url we install pack/ packs
    for thread_index, server in enumerate(build.servers):
        kwargs = {'client': server.client, 'host': server.host,
                  'prints_manager': threads_print_manager,
                  'thread_index': thread_index}
        if pack_path:
            kwargs['pack_path'] = pack_path
        threads_list.append(Thread(target=install_method, kwargs=kwargs))
    run_threads_list(threads_list)


def install_nightly_pack(build, prints_manager):
    threads_print_manager = ParallelPrintsManager(len(build.servers))
    nightly_install_packs(build, threads_print_manager, install_method=install_all_content_packs)
    create_nightly_test_pack()
    nightly_install_packs(build, threads_print_manager, install_method=upload_zipped_packs,
                          pack_path=f'{Build.test_pack_target}/test_pack.zip')

    prints_manager.add_print_job('Sleeping for 45 seconds...', print_warning, 0, include_timestamp=True)
    prints_manager.execute_thread_prints(0)
    sleep(45)


def install_packs(build, prints_manager, pack_ids=None):
    pack_ids = get_pack_ids_to_install() if pack_ids is None else pack_ids
    installed_content_packs_successfully = True
    for server in build.servers:
        try:
            _, flag = search_and_install_packs_and_their_dependencies(pack_ids, server.client,
                                                                      prints_manager)
            if not flag:
                raise Exception('Failed to search and install packs.')
        except Exception as exc:
            prints_manager.add_print_job(str(exc), print_error, 0)
            prints_manager.execute_thread_prints(0)
            installed_content_packs_successfully = False

    return installed_content_packs_successfully


def configure_server_instances(build: Build, tests_for_iteration, all_new_integrations, modified_integrations,
                               prints_manager):
    all_module_instances = []
    brand_new_integrations = []
    testing_client = build.servers[0].client
    for test in tests_for_iteration:
        integrations = get_integrations_for_test(test, build.skipped_integrations_conf)

        integrations_names = [i.get('name') for i in integrations]
        prints_manager.add_print_job('All Integrations for test "{}":'.format(test.get('playbookID')), print_warning, 0)
        prints_manager.add_print_job(integrations_names, print_warning, 0)

        new_integrations, modified_integrations, unchanged_integrations, integration_to_status = group_integrations(
            integrations, build.skipped_integrations_conf, all_new_integrations, modified_integrations
        )

        instance_names_conf = test.get('instance_names', [])
        if not isinstance(instance_names_conf, list):
            instance_names_conf = [instance_names_conf]

        integrations_names = [i.get('name') for i in integrations]
        prints_manager.add_print_job('All Integrations for test "{}":'.format(test.get('playbookID')), print_warning, 0)
        prints_manager.add_print_job(integrations_names, print_warning, 0)

        integrations_msg = '\n'.join(['"{}" - {}'.format(key, val) for key, val in integration_to_status.items()])
        prints_manager.add_print_job('{}\n'.format(integrations_msg), print_warning, 0)

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
            prints_manager.add_print_job(
                'failed setting parameters for integrations "{}"'.format('\n'.join(new_integrations)), print_error, 0)
        if not ints_to_configure_params_set:
            prints_manager.add_print_job(
                'failed setting parameters for integrations\n "{}"'.format(integrations_to_configure), print_error, 0)
        if not (new_ints_params_set and ints_to_configure_params_set):
            continue
        prints_manager.execute_thread_prints(0)

        module_instances = []
        for integration in integrations_to_configure:
            placeholders_map = {'%%SERVER_HOST%%': build.servers[0]}
            module_instance = configure_integration_instance(integration, testing_client, prints_manager,
                                                             placeholders_map)
            if module_instance:
                module_instances.append(module_instance)

        all_module_instances.extend(module_instances)
        for integration in new_integrations:
            placeholders_map = {'%%SERVER_HOST%%': build.servers[0]}
            module_instance = configure_integration_instance(integration, testing_client, prints_manager,
                                                             placeholders_map)
            if module_instance:
                module_instances.append(module_instance)

        brand_new_integrations.extend(module_instances)
    return all_module_instances, brand_new_integrations


def instance_testing(build: Build, all_module_instances, prints_manager, pre_update):
    update_status = 'Pre' if pre_update else 'Post'
    failed_tests = set()
    successful_tests = set()
    # Test all module instances (of modified + unchanged integrations) pre-updating content
    if all_module_instances:
        # only print start message if there are instances to configure
        prints_manager.add_print_job(f'Start of Instance Testing ("Test" button) ({update_status}-update)',
                                     print_warning, 0)
    else:
        prints_manager.add_print_job(f'No integrations to configure for the chosen tests. ({update_status}-update)',
                                     print_warning, 0)
    prints_manager.execute_thread_prints(0)

    testing_client = build.servers[0].client
    for instance in all_module_instances:
        integration_of_instance = instance.get('brand', '')
        instance_name = instance.get('name', '')
        msg = 'Testing ("Test" button) for instance "{}" of integration "{}".'.format(instance_name,
                                                                                      integration_of_instance)
        prints_manager.add_print_job(msg, print_color, 0, LOG_COLORS.GREEN)
        prints_manager.execute_thread_prints(0)
        # If there is a failure, __test_integration_instance will print it
        success, _ = __test_integration_instance(testing_client, instance, prints_manager)
        prints_manager.execute_thread_prints(0)
        if not success:
            failed_tests.add((instance_name, integration_of_instance))
        else:
            successful_tests.add((instance_name, integration_of_instance))

    return successful_tests, failed_tests


def update_content_till_v6(build: Build):
    threads_list = []
    threads_prints_manager = ParallelPrintsManager(len(build.servers))
    # For each server url we install content
    for thread_index, server in enumerate(build.servers):
        t = Thread(target=update_content_on_demisto_instance,
                   kwargs={'client': server.client, 'server': server.host, 'ami_name': build.ami_env,
                           'prints_manager': threads_prints_manager,
                           'thread_index': thread_index})
        threads_list.append(t)

    run_threads_list(threads_list)


def disable_instances(build: Build, all_module_instances, prints_manager):
    __disable_integrations_instances(build.servers[0].client, all_module_instances, prints_manager)
    prints_manager.execute_thread_prints(0)


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
        yield os.path.join(path, playbook), playbook


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
    sleep(60)


def main():
    build = Build(options_handler())

    prints_manager = ParallelPrintsManager(1)

    configure_servers_and_restart(build, prints_manager)
    installed_content_packs_successfully = False

    if LooseVersion(build.server_numeric_version) >= LooseVersion('6.0.0'):
        if build.is_nightly:
            install_nightly_pack(build, prints_manager)
            installed_content_packs_successfully = True
        else:
            if not build.is_private:
                pack_ids = get_non_added_packs_ids(build)
                installed_content_packs_successfully = install_packs(build, prints_manager, pack_ids=pack_ids)
    else:
        installed_content_packs_successfully = True

    tests_for_iteration = get_tests(build.server_numeric_version, prints_manager, build.tests)
    new_integrations, modified_integrations = get_changed_integrations(build, prints_manager)
    all_module_instances, brand_new_integrations = \
        configure_server_instances(build, tests_for_iteration, new_integrations, modified_integrations, prints_manager)
    successful_tests_pre, failed_tests_pre = instance_testing(build, all_module_instances, prints_manager,
                                                              pre_update=True)
    if LooseVersion(build.server_numeric_version) < LooseVersion('6.0.0'):
        update_content_till_v6(build)
    elif not build.is_nightly:
        set_marketplace_url(build.servers, build.branch_name, build.ci_build_number)
        installed_content_packs_successfully = install_packs(build,
                                                             prints_manager) and installed_content_packs_successfully

    all_module_instances.extend(brand_new_integrations)
    successful_tests_post, failed_tests_post = instance_testing(build, all_module_instances, prints_manager,
                                                                pre_update=False)
    disable_instances(build, all_module_instances, prints_manager)

    success = report_tests_status(failed_tests_pre, failed_tests_post, successful_tests_pre, successful_tests_post,
                                  new_integrations, prints_manager)
    if not success or not installed_content_packs_successfully:
        sys.exit(2)


if __name__ == '__main__':
    main()
