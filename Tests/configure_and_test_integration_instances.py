import argparse
import uuid
import json
import ast
import sys
import demisto_client
from time import sleep

from Tests.test_integration import __get_integration_config, __test_integration_instance
from Tests.test_integration import __disable_integrations_instances
from Tests.test_utils import print_error, print_warning, print_color, LOG_COLORS
from Tests.test_content import load_conf_files, extract_filtered_tests
from Tests.test_utils import run_command, get_last_release_version, checked_type, get_yaml
from Tests.scripts.validate_files import FilesValidator
from Tests.scripts.constants import YML_INTEGRATION_REGEXES, INTEGRATION_REGEX
from Tests.scripts.constants import PACKS_INTEGRATION_REGEX, BETA_INTEGRATION_REGEX


def options_handler():
    parser = argparse.ArgumentParser(description='Utility for instantiating and testing integration instances')
    parser.add_argument('-u', '--user', help='The username for the login', required=True)
    parser.add_argument('-p', '--password', help='The password for the login', required=True)
    parser.add_argument('--ami_env', help='The AMI environment for the current run. Options are '
                        '"Server Master", "Demisto GA", "Demisto one before GA", "Demisto two before GA". '
                        'The server url is determined by the AMI environment.')
    parser.add_argument('-g', '--git_sha1', help='commit sha1 to compare changes with')
    parser.add_argument('-c', '--conf', help='Path to conf file', required=True)
    parser.add_argument('-s', '--secret', help='Path to secret conf file')

    options = parser.parse_args()

    return options


def determine_server_url(ami_env):
    '''
    Use the "env_results.json" file and -env argument passed to the script to determine
    the demisto server url to connect to

    Arguments:
        ami_env: (str)
            The amazon machine image environment whose IP we should connect to.

    Returns:
        (str): The server url to connect to
    '''
    instance_dns = ''
    with open('./env_results.json', 'r') as json_file:
        env_results = json.load(json_file)
        env_to_instance_dns = {env.get('Role'): env.get('InstanceDNS') for env in env_results}
        instance_dns = env_to_instance_dns.get(ami_env)
    server_url = instance_dns if instance_dns.startswith('http') else ('https://{}'.format(instance_dns) if
                                                                       instance_dns else '')
    return server_url


def configure_integration_instance(integration, client):
    '''Configure an instance for an integration

    Arguments:
        integration: (dict)
            Integration object whose params key-values are set
        client: (demisto_client)
            The client to connect to

    Returns:
        (dict): Configured integration instance
    '''
    integration_name = integration.get('name')
    print('Configuring instance for integration "{}"\n'.format(integration_name))
    integration_instance_name = integration.get('instance_name', '')
    integration_params = integration.get('params')
    is_byoi = integration.get('byoi', True)

    integration_configuration = __get_integration_config(client, integration_name)
    module_instance = set_integration_instance_parameters(integration_configuration, integration_params,
                                                          integration_instance_name, is_byoi)
    return module_instance


def filepath_to_integration_name(integration_file_path):
    '''Load an integration file and return the integration name.

    Args:
        integration_file_path (str): The path to an integration yml file.

    Returns:
        (str): The name of the integration.
    '''
    integration_yaml = get_yaml(integration_file_path)
    integration_name = integration_yaml.get('name')
    return integration_name


def get_new_and_modified_integrations(git_sha1):
    '''Return 2 lists - list of new integrations and list of modified integrations since the commit of the git_sha1.

    Args:
        git_sha1 (str): The git sha of the commit against which we will run the 'git diff' command.

    Returns:
        (tuple): Returns a tuple of two lists, the names of the new integrations, and the names of
            modified integrations.
    '''
    # get changed yaml files (filter only added and modified files)
    tag = get_last_release_version()
    file_validator = FilesValidator()
    change_log = run_command('git diff --name-status {}'.format(git_sha1))
    modified_files, added_files, removed_files, old_format_files = file_validator.get_modified_files(change_log, tag)
    all_integration_regexes = YML_INTEGRATION_REGEXES
    all_integration_regexes.extend([INTEGRATION_REGEX, PACKS_INTEGRATION_REGEX, BETA_INTEGRATION_REGEX])
    added_integration_files = [
        file_path for file_path in added_files if checked_type(file_path, all_integration_regexes)
    ]
    modified_integration_files = [
        file_path for file_path in modified_files if
        isinstance(file_path, str) and checked_type(file_path, all_integration_regexes)
    ]

    new_integrations_names = [
        filepath_to_integration_name(file_path) for
        file_path in added_integration_files if filepath_to_integration_name(file_path)
    ]
    modified_integrations_names = [
        filepath_to_integration_name(file_path) for
        file_path in modified_integration_files if filepath_to_integration_name(file_path)
    ]
    return new_integrations_names, modified_integrations_names


def is_content_update_in_progress(client):
    '''Make request to check if content is updating.

    Args:
        client (demisto_client): The configured client to use.

    Returns:
        (str): Returns the request response data which is 'true' if updating and 'false' if not.
    '''
    host = client.api_client.configuration.host
    print('\nMaking "Get" request to server - "{}" to check if content is installing.'.format(host))

    # make request to check if content is updating
    response_data, status_code, _ = demisto_client.generic_request_func(self=client, path='/content/updating',
                                                                        method='GET', accept='application/json')

    if status_code >= 300 or status_code < 200:
        result_object = ast.literal_eval(response_data)
        message = result_object.get('message', '')
        msg = "Failed to check if content is installing - with status code " + str(status_code) + '\n' + message
        print_error(msg)
        return 'request unsuccessful'
    else:
        return response_data


def get_content_version_details(client):
    '''Make request for details about the content installed on the demisto instance.

    Args:
        client (demisto_client): The configured client to use.

    Returns:
        (tuple): The release version and asset ID of the content installed on the demisto instance.
    '''
    host = client.api_client.configuration.host
    print('\nMaking "POST" request to server - "{}" to check installed content.'.format(host))

    # make request to installed content details
    response_data, status_code, _ = demisto_client.generic_request_func(self=client, path='/content/installed',
                                                                        method='POST')

    result_object = ast.literal_eval(response_data)
    if status_code >= 300 or status_code < 200:
        message = result_object.get('message', '')
        msg = "Failed to check if installed content details - with status code " + str(status_code) + '\n' + message
        print_error(msg)
    return result_object.get('release', ''), result_object.get('assetId', 0)


def set_integration_params(integrations, secret_params, instance_names):
    '''
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

    Returns:
        (bool): True if integrations params were filled with secret configuration values, otherwise false
    '''
    for integration in integrations:
        integration_params = [item for item in secret_params if item['name'] == integration['name']]

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

    return True


def set_module_params(param_conf, integration_params):
    '''Configure a parameter object for use in a module instance.

    Each integration parameter is actually an object with many fields that together describe it. E.g. a given
    parameter will have all of the following fields - "name", "display", "value", "hasvalue", "defaultValue",
    etc. This function fills the "value" field for a parameter configuration object and returns it for use in
    a module instance.

    Args:
        param_conf (dict): The parameter configuration object.
        integration_params (dict): The values to use for an integration's parameters to configure an instance.

    Returns:
        (dict): The configured paramter object
    '''
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


def set_integration_instance_parameters(integration_configuration, integration_params, integration_instance_name,
                                        is_byoi):
    '''Set integration module values for integration instance creation

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

    Returns:
        (dict): The configured module instance to send to the Demisto server for
        instantiation.
    '''
    module_configuration = integration_configuration.get('configuration', {})
    if not module_configuration:
        module_configuration = []

    instance_name = '{}_test_{}'.format(integration_instance_name.replace(' ', '_'),
                                        str(uuid.uuid4()))
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

    # set module params
    for param_conf in module_configuration:
        configured_param = set_module_params(param_conf, integration_params)
        module_instance['data'].append(configured_param)

    return module_instance


def group_integrations(integrations, skipped_integrations_conf, new_integrations_names, modified_integrations_names):
    '''
    Filter integrations into their respective lists - new, modified or unchanged. if it's on the skip list, then
    skip if random tests were chosen then we may be configuring integrations that are neither new or modified.

    Args:
        integrations (list): The integrations to categorize.
        skipped_integrations_conf (dict): Integrations that are on the skip list.
        new_integrations_names (list): The names of new integrations.
        modified_integrations_names (list): The names of modified integrations.

    Returns:
        (tuple): Lists of integrations objects as well as an Integration-to-Status dictionary useful for logs.
    '''
    new_integrations = []
    modified_integrations = []
    unchanged_integrations = []
    integration_to_status = {}
    for integration in integrations:
        integration_name = integration.get('name', '')
        if integration_name in skipped_integrations_conf.keys():
            continue
        elif integration_name in new_integrations_names:
            new_integrations.append(integration)
        elif integration_name in modified_integrations_names:
            modified_integrations.append(integration)
            integration_to_status[integration_name] = 'Modified Integration'
        else:
            unchanged_integrations.append(integration)
            integration_to_status[integration_name] = 'Unchanged Integration'
    return new_integrations, modified_integrations, unchanged_integrations, integration_to_status


def get_integrations_for_test(test, skipped_integrations_conf):
    '''Return a list of integration objects that are necessary for a test (excluding integrations on the skip list).

    Args:
        test (dict): Test dictionary from the conf.json file containing the playbookID, integrations and
            instance names.
        skipped_integrations_conf (dict): Skipped integrations dictionary with integration names as keys and
            the skip reason as values.

    Returns:
        (list): List of integration objects to configure.
    '''
    integrations_conf = test.get('integrations', [])

    if not isinstance(integrations_conf, list):
        integrations_conf = [integrations_conf]

    integrations = [
        {'name': integration, 'params': {}} for
        integration in integrations_conf if integration not in skipped_integrations_conf
    ]
    return integrations


def update_content_on_demisto_instance(client, username, password, server):
    '''Try to update the content

    Args:
        client (demisto_client): The configured client to use.
        username (str): The username to pass to Tests/update_content_data.py
        password (str): The password to pass to Tests/update_content_data.py
        server (str): The server url to pass to Tests/update_content_data.py
    '''
    content_zip_path = 'artifacts/all_content.zip'
    cmd_str = 'python Tests/update_content_data.py -u {} -p {} -s {} --content_zip {}'.format(username, password,
                                                                                              server, content_zip_path)
    run_command(cmd_str, is_silenced=False)

    # Check if content update has finished installing
    sleep_interval = 20
    updating_content = is_content_update_in_progress(client)
    while updating_content.lower() == 'true':
        sleep(sleep_interval)
        updating_content = is_content_update_in_progress(client)

    if updating_content.lower() == 'request unsuccessful':
        # since the request to check if content update installation finished didn't work, can't use that mechanism
        # to check and just try sleeping for 30 seconds instead to allow for content update installation to complete
        sleep(30)
    else:
        # check that the content installation updated
        # verify the asset id matches the circleci build number / asset_id in the content-descriptor.json
        release, asset_id = get_content_version_details(client)
        with open('content-descriptor.json', 'r') as cd_file:
            cd_json = json.loads(cd_file.read())
            cd_release = cd_json.get('release')
            cd_asset_id = cd_json.get('assetId')
        if release == cd_release and asset_id == cd_asset_id:
            print_color('Content Update Successfully Installed!', color=LOG_COLORS.GREEN)
        else:
            err_details = 'Attempted to install content with release "{}" and assetId '.format(cd_release)
            err_details += '"{}" but release "{}" and assetId "{}" were '.format(cd_asset_id, release, asset_id)
            err_details += 'retrieved from the instance post installation.'
            print_error('Content Update was Unsuccessful:\n{}'.format(err_details))
            sys.exit(1)


def report_tests_status(preupdate_fails, postupdate_fails, new_integrations_names):
    '''Prints errors and/or warnings if there are any and returns whether whether testing was successful or not.

    Args:
        preupdate_fails (list): List of tuples of integrations that failed the "Test" button prior to content
            being updated on the demisto instance where each tuple is comprised of the integration name and the
            name of the instance that was configured for that integration which failed.
        postupdate_fails (list): List of tuples of integrations that failed the "Test" button after content was
            updated on the demisto instance where each tuple is comprised of the integration name and the name
            of the instance that was configured for that integration which failed.
        new_integrations_names (list): List of the names of integrations that are new since the last official
            content release and that will only be present on the demisto instance after the content update is
            performed.

    Returns:
        (bool): False if there were integration instances that succeeded prior to the content update and then
            failed after content was updated, otherwise True.
    '''
    testing_status = True
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
        print_warning('New Integrations ("Test" Button) Failures')
        for instance_name, integration_of_instance in failed_but_is_new:
            print_warning('Integration: "{}", Instance: "{}"'.format(integration_of_instance, instance_name))
    if failed_pre_and_post:
        failure_category = '\nIntegration instances that had ("Test" Button) failures' \
                           ' both before and after the content update'
        print_warning(failure_category)
        for instance_name, integration_of_instance in failed_pre_and_post:
            print_warning('Integration: "{}", Instance: "{}"'.format(integration_of_instance, instance_name))

    # fail the step if there are instances that only failed after content was updated
    if failed_only_after_update:
        testing_status = False
        failure_category = '\nIntegration instances that had ("Test" Button) failures' \
                           ' only after content was updated. This indicates that your' \
                           'updates introduced breaking changes to the integration.'
        print_error(failure_category)
        for instance_name, integration_of_instance in failed_only_after_update:
            print_error('Integration: "{}", Instance: "{}"'.format(integration_of_instance, instance_name))

    return testing_status


def main():
    options = options_handler()
    username = options.user
    password = options.password
    ami_env = options.ami_env
    git_sha1 = options.git_sha1
    server = determine_server_url(ami_env)
    conf_path = options.conf
    secret_conf_path = options.secret

    conf, secret_conf = load_conf_files(conf_path, secret_conf_path)
    secret_params = secret_conf.get('integrations', []) if secret_conf else []

    username = secret_conf.get('username') if not username else username
    password = secret_conf.get('userPassword') if not password else password

    client = demisto_client.configure(base_url=server, username=username, password=password, verify_ssl=False)

    tests = conf['tests']
    skipped_integrations_conf = conf['skipped_integrations']
    all_module_instances = []

    filtered_tests, filter_configured, run_all_tests = extract_filtered_tests()
    tests_for_iteration = tests
    if run_all_tests:
        # Use all tests for testing, leave 'tests_for_iteration' as is
        pass
    elif filter_configured and filtered_tests:
        tests_for_iteration = [test for test in tests if test.get('playbookID', '') in filtered_tests]

    # get a list of brand new integrations that way we filter them out to only configure instances
    # after updating content
    new_integrations_names, modified_integrations_names = get_new_and_modified_integrations(git_sha1)
    if new_integrations_names:
        print_warning('New Integrations Since Last Release:\n{}\n'.format('\n'.join(new_integrations_names)))
    if modified_integrations_names:
        print_warning('Updated Integrations Since Last Release:\n{}\n'.format('\n'.join(modified_integrations_names)))

    # Each test is a dictionary from Tests/conf.json which may contain the following fields
    # "playbookID", "integrations", "instance_names", "timeout", "nightly", "fromversion", "toversion"
    # Note that only the "playbookID" field is required with all of the others being optional.
    # Most tests have an "integrations" field listing the integration used for that playbook
    # and sometimes an "instance_names" field which is used when there are multiple instances
    # of an integration that we want to configure with different configuration values. Look at
    # [conf.json](../conf.json) for examples
    brand_new_integrations = []
    for test in tests_for_iteration:
        integrations = get_integrations_for_test(test, skipped_integrations_conf)
        instance_names_conf = test.get('instance_names', [])
        if not isinstance(instance_names_conf, list):
            instance_names_conf = [instance_names_conf]

        integrations_names = [i.get('name') for i in integrations]
        print_warning('All Integrations for test "{}":'.format(test.get('playbookID')))
        print_warning(integrations_names)

        new_integrations, modified_integrations, unchanged_integrations, integration_to_status = group_integrations(
            integrations, skipped_integrations_conf, new_integrations_names, modified_integrations_names
        )

        integrations_msg = '\n'.join(['"{}" - {}'.format(key, val) for key, val in integration_to_status.items()])
        print_warning('{}\n'.format(integrations_msg))

        integrations_to_configure = modified_integrations[:]
        integrations_to_configure.extend(unchanged_integrations)

        # set params for new integrations and [modified + unchanged] integrations, then add the new ones
        # to brand_new_integrations list for later use
        new_ints_params_set = set_integration_params(new_integrations, secret_params, instance_names_conf)
        ints_to_configure_params_set = set_integration_params(integrations_to_configure, secret_params,
                                                              instance_names_conf)
        if not new_ints_params_set:
            print_error('failed setting parameters for integrations "{}"'.format('\n'.join(new_integrations)))
        if not ints_to_configure_params_set:
            print_error('failed setting parameters for integrations "{}"'.format('\n'.join(integrations_to_configure)))
        if not (new_ints_params_set and ints_to_configure_params_set):
            continue

        brand_new_integrations.extend(new_integrations)

        module_instances = []
        for integration in integrations_to_configure:
            module_instances.append(configure_integration_instance(integration, client))
        all_module_instances.extend(module_instances)

    preupdate_fails = set()
    postupdate_fails = set()

    # Test all module instances (of modified + unchanged integrations) pre-updating content
    if all_module_instances:
        # only print start message if there are instances to configure
        print_warning('Start of Instance Testing ("Test" button) prior to Content Update:')
    else:
        print_warning('No integrations to configure for the chosen tests. (Pre-update)')
    for instance in all_module_instances:
        integration_of_instance = instance.get('brand', '')
        instance_name = instance.get('name', '')
        msg = 'Testing ("Test" button) for instance "{}" of integration "{}".'.format(instance_name,
                                                                                      integration_of_instance)
        print(msg)
        # If there is a failure, __test_integration_instance will print it
        success = __test_integration_instance(client, instance)
        if not success:
            preupdate_fails.add((instance_name, integration_of_instance))

    update_content_on_demisto_instance(client, username, password, server)

    # configure instances for new integrations
    new_integration_module_instances = []
    for integration in brand_new_integrations:
        new_integration_module_instances.append(configure_integration_instance(integration, client))
    all_module_instances.extend(new_integration_module_instances)

    # After content upload has completed - test ("Test" button) integration instances
    # Test all module instances (of pre-existing AND new integrations) post-updating content
    if all_module_instances:
        print_warning('Start of Instance Testing ("Test" button) after the Content Update:')
    else:
        print_warning('No integrations to configure for the chosen tests. (Post-update)')
    for instance in all_module_instances:
        integration_of_instance = instance.get('brand', '')
        instance_name = instance.get('name', '')
        msg = 'Testing ("Test" button) for instance "{}" of integration "{}" .'.format(instance_name,
                                                                                       integration_of_instance)
        print(msg)
        # If there is a failure, __test_integration_instance will print it
        success = __test_integration_instance(client, instance)
        if not success:
            postupdate_fails.add((instance_name, integration_of_instance))

    # reinitiate the client since its authorization has probably expired by now
    client = demisto_client.configure(base_url=server, username=username, password=password, verify_ssl=False)
    __disable_integrations_instances(client, all_module_instances)

    success = report_tests_status(preupdate_fails, postupdate_fails, new_integrations_names)
    if not success:
        sys.exit(1)


if __name__ == '__main__':
    main()
