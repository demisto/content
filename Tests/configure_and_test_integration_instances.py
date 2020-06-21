from __future__ import print_function

import argparse
import os
import uuid
import json
import ast
import subprocess
import sys
from time import sleep
from threading import Thread
from distutils.version import LooseVersion
import demisto_client

from demisto_sdk.commands.common.tools import print_error, print_warning, print_color, LOG_COLORS, run_threads_list, \
    run_command, get_last_release_version, checked_type, get_yaml, str2bool, server_version_compare
from demisto_sdk.commands.validate.file_validator import FilesValidator
from demisto_sdk.commands.common.constants import YML_INTEGRATION_REGEXES, RUN_ALL_TESTS_FORMAT

from Tests.test_integration import __get_integration_config, __test_integration_instance, \
    __disable_integrations_instances
from Tests.test_content import load_conf_files, extract_filtered_tests, ParallelPrintsManager, \
    get_server_numeric_version
from Tests.update_content_data import update_content
from Tests.Marketplace.search_and_install_packs import search_and_install_packs_and_their_dependencies

MARKET_PLACE_MACHINES = ('master',)


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
    parser.add_argument('--branch', help='GitHub branch name', required=True)
    parser.add_argument('--build-number', help='CI build number', required=True)

    options = parser.parse_args()

    return options


def determine_servers_urls(ami_env):
    """
    Use the "env_results.json" file and -env argument passed to the script to determine
    the demisto server url to connect to.
    In case there are several machines (nightly - parallel) several urls will be returned.

    Arguments:
        ami_env: (str)
            The amazon machine image environment whose IP we should connect to.

    Returns:
        (lst): The server url list to connect to
    """

    with open('./env_results.json', 'r') as json_file:
        env_results = json.load(json_file)

    instances_dns = [env.get('InstanceDNS') for env in env_results if ami_env in env.get('Role', '')]

    server_urls = []
    for dns in instances_dns:
        server_url = dns if not dns or dns.startswith('http') else f'https://{dns}'
        server_urls.append(server_url)
    return server_urls


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
    test_from_version = test.get('fromversion', '0.0.0')
    test_to_version = test.get('toversion', '99.99.99')
    if (server_version_compare(test_from_version, server_version) > 0
            or server_version_compare(test_to_version, server_version) < 0):
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


def get_new_and_modified_integration_files(git_sha1):
    """Return 2 lists - list of new integrations and list of modified integrations since the commit of the git_sha1.

    Args:
        git_sha1 (str): The git sha of the commit against which we will run the 'git diff' command.

    Returns:
        (tuple): Returns a tuple of two lists, the file paths of the new integrations and modified integrations.
    """
    # get changed yaml files (filter only added and modified files)
    tag = get_last_release_version()
    file_validator = FilesValidator()
    change_log = run_command('git diff --name-status {}'.format(git_sha1))
    modified_files, added_files, _, _ = file_validator.get_modified_files(change_log, tag)
    all_integration_regexes = YML_INTEGRATION_REGEXES

    new_integration_files = [
        file_path for file_path in added_files if checked_type(file_path, all_integration_regexes)
    ]

    modified_integration_files = [
        file_path for file_path in modified_files if
        isinstance(file_path, str) and checked_type(file_path, all_integration_regexes)
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
        item_as_string = item_as_string.replace(key, value)
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
        (dict): The configured paramter object
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
    mismatched_statuses = preupdate_fails.symmetric_difference(postupdate_fails)
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

    return testing_status


def set_marketplace_gcp_bucket_for_build(client, prints_manager, branch_name, ci_build_number):
    """Sets custom marketplace GCP bucket based on branch name and build number

    Args:
        client (demisto_client): The configured client to use.
        prints_manager (ParallelPrintsManager): Print manager object
        branch_name (str): GitHub branch name
        ci_build_number (str): CI build number

    Returns:
        None
    """
    host = client.api_client.configuration.host
    installed_content_message = \
        '\nMaking "POST" request to server - "{}" to set GCP bucket server configuration.'.format(host)
    prints_manager.add_print_job(installed_content_message, print_color, 0, LOG_COLORS.GREEN)

    # make request to update server configs
    data = {
        'data': {
            'content.pack.verify': 'false',
            'marketplace.initial.sync.delay': '0',
            'content.pack.ignore.missing.warnings.contentpack': 'true',
            'marketplace.bootstrap.bypass.url':
                'https://storage.googleapis.com/marketplace-ci-build/content/builds/{}/{}'.format(
                    branch_name, ci_build_number
                )
        },
        'version': -1
    }
    response_data, status_code, _ = demisto_client.generic_request_func(self=client, path='/system/config',
                                                                        method='POST', body=data)

    try:
        result_object = ast.literal_eval(response_data)
    except ValueError as err:
        print_error('failed to parse response from demisto. response is {}.\nError:\n{}'.format(response_data, err))
        return

    if status_code >= 300 or status_code < 200:
        message = result_object.get('message', '')
        msg = "Failed to set GCP bucket server config - with status code " + str(status_code) + '\n' + message
        print_error(msg)


def get_pack_ids_to_install():
    with open('./Tests/content_packs_to_install.txt', 'r') as packs_stream:
        pack_ids = packs_stream.readlines()
        return [pack_id.rstrip('\n') for pack_id in pack_ids]


def main():
    options = options_handler()
    username = options.user
    password = options.password
    ami_env = options.ami_env
    git_sha1 = options.git_sha1
    conf_path = options.conf
    secret_conf_path = options.secret
    branch_name = options.branch
    ci_build_number = options.build_number

    servers = determine_servers_urls(ami_env)
    server_numeric_version = get_server_numeric_version(ami_env)

    prints_manager = ParallelPrintsManager(1)

    conf, secret_conf = load_conf_files(conf_path, secret_conf_path)
    secret_params = secret_conf.get('integrations', []) if secret_conf else []

    username = secret_conf.get('username') if not username else username
    password = secret_conf.get('userPassword') if not password else password

    if LooseVersion(server_numeric_version) >= LooseVersion('6.0.0'):
        for server in servers:
            client = demisto_client.configure(base_url=server, username=username, password=password,
                                              verify_ssl=False)
            set_marketplace_gcp_bucket_for_build(client, prints_manager, branch_name, ci_build_number)
            print('Restarting servers to apply GCS server config ...')
            ssh_string = 'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {}@{} ' \
                         '"sudo systemctl restart demisto"'
            try:
                subprocess.check_output(
                    ssh_string.format('ec2-user', server.replace('https://', '')), shell=True)
            except subprocess.CalledProcessError as exc:
                print(exc.output)
        print('Done restarting servers.')

    tests = conf['tests']
    skipped_integrations_conf = conf['skipped_integrations']
    all_module_instances = []

    filtered_tests, filter_configured, run_all_tests = extract_filtered_tests(is_nightly=options.is_nightly)
    tests_for_iteration = tests
    if run_all_tests:
        # skip test button testing
        skipped_instance_test_message = 'Not running instance tests when {} is turned on'.format(RUN_ALL_TESTS_FORMAT)
        prints_manager.add_print_job(skipped_instance_test_message, print_warning, 0)
        tests_for_iteration = []
    elif filter_configured and filtered_tests:
        tests_for_iteration = [test for test in tests if test.get('playbookID', '') in filtered_tests]

    tests_for_iteration = filter_tests_with_incompatible_version(tests_for_iteration, server_numeric_version,
                                                                 prints_manager)
    prints_manager.execute_thread_prints(0)

    # get a list of brand new integrations that way we filter them out to only configure instances
    # after updating content
    new_integrations_files, modified_integrations_files = get_new_and_modified_integration_files(git_sha1)
    new_integrations_names, modified_integrations_names = [], []

    installed_content_packs_successfully = True

    if LooseVersion(server_numeric_version) >= LooseVersion('6.0.0'):
        # sleep for one minute before starting to search and install packs to ensure bucket is ready
        prints_manager.add_print_job('Sleeping for 1 minute...', print_warning, 0)
        prints_manager.execute_thread_prints(0)
        sleep(60)

        pack_ids = get_pack_ids_to_install()
        # install content packs in every server
        for server_url in servers:
            try:
                client = demisto_client.configure(base_url=server_url, username=username, password=password,
                                                  verify_ssl=False)
                search_and_install_packs_and_their_dependencies(pack_ids, client, prints_manager, options.is_nightly)
            except Exception as exc:
                prints_manager.add_print_job(str(exc), print_error, 0)
                prints_manager.execute_thread_prints(0)
                installed_content_packs_successfully = False

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
    # Each test is a dictionary from Tests/conf.json which may contain the following fields
    # "playbookID", "integrations", "instance_names", "timeout", "nightly", "fromversion", "toversion"
    # Note that only the "playbookID" field is required with all of the others being optional.
    # Most tests have an "integrations" field listing the integration used for that playbook
    # and sometimes an "instance_names" field which is used when there are multiple instances
    # of an integration that we want to configure with different configuration values. Look at
    # [conf.json](../conf.json) for examples
    brand_new_integrations = []

    for test in tests_for_iteration:
        testing_client = demisto_client.configure(base_url=servers[0], username=username, password=password,
                                                  verify_ssl=False)
        integrations = get_integrations_for_test(test, skipped_integrations_conf)
        instance_names_conf = test.get('instance_names', [])
        if not isinstance(instance_names_conf, list):
            instance_names_conf = [instance_names_conf]

        integrations_names = [i.get('name') for i in integrations]
        prints_manager.add_print_job('All Integrations for test "{}":'.format(test.get('playbookID')), print_warning, 0)
        prints_manager.add_print_job(integrations_names, print_warning, 0)

        new_integrations, modified_integrations, unchanged_integrations, integration_to_status = group_integrations(
            integrations, skipped_integrations_conf, new_integrations_names, modified_integrations_names
        )

        integrations_msg = '\n'.join(['"{}" - {}'.format(key, val) for key, val in integration_to_status.items()])
        prints_manager.add_print_job('{}\n'.format(integrations_msg), print_warning, 0)

        integrations_to_configure = modified_integrations[:]
        integrations_to_configure.extend(unchanged_integrations)

        # set params for new integrations and [modified + unchanged] integrations, then add the new ones
        # to brand_new_integrations list for later use
        placeholders_map = {'%%SERVER_HOST%%': servers[0]}
        new_ints_params_set = set_integration_params(new_integrations, secret_params, instance_names_conf,
                                                     placeholders_map)
        ints_to_configure_params_set = set_integration_params(integrations_to_configure, secret_params,
                                                              instance_names_conf, placeholders_map)
        if not new_ints_params_set:
            prints_manager.add_print_job(
                'failed setting parameters for integrations "{}"'.format('\n'.join(new_integrations)), print_error, 0)
        if not ints_to_configure_params_set:
            prints_manager.add_print_job(
                'failed setting parameters for integrations "{}"'.format('\n'.join(integrations_to_configure)),
                print_error, 0)
        if not (new_ints_params_set and ints_to_configure_params_set):
            continue
        prints_manager.execute_thread_prints(0)

        brand_new_integrations.extend(new_integrations)

        module_instances = []
        for integration in integrations_to_configure:
            placeholders_map = {'%%SERVER_HOST%%': servers[0]}
            module_instance = configure_integration_instance(integration, testing_client, prints_manager,
                                                             placeholders_map)
            if module_instance:
                module_instances.append(module_instance)

        all_module_instances.extend(module_instances)

    preupdate_fails = set()
    postupdate_fails = set()
    preupdate_success = set()
    postupdate_success = set()

    # Test all module instances (of modified + unchanged integrations) pre-updating content
    if all_module_instances:
        # only print start message if there are instances to configure
        prints_manager.add_print_job('Start of Instance Testing ("Test" button) prior to Content Update:',
                                     print_warning, 0)
    else:
        prints_manager.add_print_job('No integrations to configure for the chosen tests. (Pre-update)',
                                     print_warning, 0)
    prints_manager.execute_thread_prints(0)

    for instance in all_module_instances:
        testing_client = demisto_client.configure(base_url=servers[0], username=username, password=password,
                                                  verify_ssl=False)
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
            preupdate_fails.add((instance_name, integration_of_instance))
        else:
            preupdate_success.add((instance_name, integration_of_instance))

    if LooseVersion(server_numeric_version) < LooseVersion('6.0.0'):
        threads_list = []
        threads_prints_manager = ParallelPrintsManager(len(servers))
        # For each server url we install content
        for thread_index, server_url in enumerate(servers):
            client = demisto_client.configure(base_url=server_url, username=username,
                                              password=password, verify_ssl=False)
            t = Thread(target=update_content_on_demisto_instance,
                       kwargs={'client': client, 'server': server_url, 'ami_name': ami_env,
                               'prints_manager': threads_prints_manager,
                               'thread_index': thread_index})
            threads_list.append(t)

        run_threads_list(threads_list)

    # configure instances for new integrations
    new_integration_module_instances = []
    for integration in brand_new_integrations:
        placeholders_map = {'%%SERVER_HOST%%': servers[0]}
        new_integration_module_instance = configure_integration_instance(integration, testing_client, prints_manager,
                                                                         placeholders_map)
        if new_integration_module_instance:
            new_integration_module_instances.append(new_integration_module_instance)

    all_module_instances.extend(new_integration_module_instances)

    # After content upload has completed - test ("Test" button) integration instances
    # Test all module instances (of pre-existing AND new integrations) post-updating content
    if all_module_instances:
        # only print start message if there are instances to configure
        prints_manager.add_print_job('Start of Instance Testing ("Test" button) after the Content Update:',
                                     print_warning, 0)
    else:
        prints_manager.add_print_job('No integrations to configure for the chosen tests. (Post-update)',
                                     print_warning, 0)
    prints_manager.execute_thread_prints(0)

    for instance in all_module_instances:
        integration_of_instance = instance.get('brand', '')
        instance_name = instance.get('name', '')
        msg = 'Testing ("Test" button) for instance "{}" of integration "{}" .'.format(instance_name,
                                                                                       integration_of_instance)
        prints_manager.add_print_job(msg, print_color, 0, LOG_COLORS.GREEN)
        prints_manager.execute_thread_prints(0)
        # If there is a failure, __test_integration_instance will print it
        success, _ = __test_integration_instance(testing_client, instance, prints_manager)
        prints_manager.execute_thread_prints(0)
        if not success:
            postupdate_fails.add((instance_name, integration_of_instance))
        else:
            postupdate_success.add((instance_name, integration_of_instance))
    # reinitialize all clients since their authorization has probably expired by now
    for server_url in servers:
        client = demisto_client.configure(base_url=server_url, username=username, password=password, verify_ssl=False)
        __disable_integrations_instances(client, all_module_instances, prints_manager)
    prints_manager.execute_thread_prints(0)

    success = report_tests_status(preupdate_fails, postupdate_fails, preupdate_success, postupdate_success,
                                  new_integrations_names, prints_manager)
    prints_manager.execute_thread_prints(0)
    if not success or not installed_content_packs_successfully:
        sys.exit(2)


if __name__ == '__main__':
    main()
