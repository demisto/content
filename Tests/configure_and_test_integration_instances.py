import argparse
import uuid
import json
import ast
import demisto_client
from Tests.test_integration import __get_integration_config, __test_integration_instance
from Tests.test_integration import __disable_integrations_instances
from Tests.test_utils import print_error, print_warning, print_color, LOG_COLORS
from Tests.test_content import load_conf_files, collect_integrations, extract_filtered_tests
from Tests.test_utils import run_command, get_last_release_version, checked_type, get_yaml
from Tests.scripts.validate_files import FilesValidator
from Tests.scripts.constants import YML_INTEGRATION_REGEXES, INTEGRATION_REGEX
from Tests.scripts.constants import PACKS_INTEGRATION_REGEX, BETA_INTEGRATION_REGEX
from time import sleep


def options_handler():
    parser = argparse.ArgumentParser(description='Utility for instantiating and testing integration instances')
    parser.add_argument('-u', '--user', help='The username for the login', required=True)
    parser.add_argument('-p', '--password', help='The password for the login', required=True)
    parser.add_argument('-env', '--ami_env', help='The AMI environment for the current run. Options are '
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


def get_new_and_modified_integrations(git_sha1):
    '''Return 2 lists - list of new integrations and list of modified integrations since the commit of the git_sha1'''
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
    modded_integration_files = [
        file_path for file_path in modified_files if checked_type(file_path, all_integration_regexes)
    ]

    new_integrations_names = []
    for integration_file_path in added_integration_files:
        integration_yaml = get_yaml(integration_file_path)
        integration_name = integration_yaml.get('name')
        if integration_name:
            new_integrations_names.append(integration_name)
    modded_integrations_names = []
    for integration_file_path in modded_integration_files:
        integration_yaml = get_yaml(integration_file_path)
        integration_name = integration_yaml.get('name')
        if integration_name:
            modded_integrations_names.append(integration_name)
    return new_integrations_names, modded_integrations_names


def is_content_updating(server, username, password):
    '''Configure Demisto Client and make request to check if content is updating'''
    # Configure Demisto Client
    c = demisto_client.configure(base_url=server, username=username, password=password, verify_ssl=False)

    msg = '\nMaking "Get" request to server - "{}" to check if content is installing.'.format(server)
    print(msg)

    # make request to check if content is updating
    response_data, status_code, _ = demisto_client.generic_request_func(self=c, path='/content/updating',
                                                                        method='GET', accept='application/json')

    if status_code >= 300 or status_code < 200:
        result_object = ast.literal_eval(response_data)
        message = result_object.get('message', '')
        msg = "Failed to check if content is installing - with status code " + str(status_code) + '\n' + message
        print_error(msg)
        return 'request unsuccessful'
    else:
        return response_data


def get_content_installation(client):
    '''Make request for details about the content installed on the demisto instance'''
    msg = '\nMaking "POST" request to server - "{}" to check installed content.'.format(client.configuration.host)
    print(msg)

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
        module_instance['data'].append(param_conf)

    return module_instance


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
    nightly_integrations = conf['nightly_integrations']
    skipped_integrations_conf = conf['skipped_integrations']

    skipped_integration = set([])
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
        integrations_conf = test.get('integrations', [])
        instance_names_conf = test.get('instance_names', [])

        if not isinstance(integrations_conf, list):
            integrations_conf = [integrations_conf]
        if not isinstance(instance_names_conf, list):
            instance_names_conf = [instance_names_conf]

        _, integrations, _ = collect_integrations(integrations_conf, skipped_integration,
                                                  skipped_integrations_conf, nightly_integrations)

        integrations_names = [i.get('name') for i in integrations]
        print_warning('All Integrations for test "{}":'.format(test.get('playbookID')))
        print_warning(integrations_names)

        new_integrations = []
        modified_integrations = []
        unchanged_integrations = []
        integration_to_status = {}

        # filter integrations into their respective lists - new, modified or unchanged. if it's on the skip list, then
        # skip if random tests were chosen then we may be configuring integrations that are neither new or modified.
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

        integrations_msg = '\n'.join(['"{}" - {}'.format(key, val) for key, val in integration_to_status.items()])
        print_warning('{}\n'.format(integrations_msg))

        integrations_to_configure = modified_integrations[:]
        integrations_to_configure.extend(unchanged_integrations)

        # set params for new integrations and [modified + unchanged] integrations, then add the new ones
        # to brand_new_integrations list for later use
        ni_params_set = set_integration_params(new_integrations, secret_params, instance_names_conf)
        ti_params_set = set_integration_params(integrations_to_configure, secret_params, instance_names_conf)
        if not ni_params_set:
            print_error('failed setting parameters for integrations "{}"'.format('\n'.join(new_integrations)))
        if not ti_params_set:
            print_error('failed setting parameters for integrations "{}"'.format('\n'.join(integrations_to_configure)))
        if not (ni_params_set and ti_params_set):
            continue

        brand_new_integrations.extend(new_integrations)

        module_instances = []
        for integration in integrations_to_configure:
            module_instances.append(configure_integration_instance(integration, client))
        all_module_instances.extend(module_instances)

    # Test all module instances (of modified + unchanged integrations) pre-updating content
    print_warning('Start of Instance Testing ("Test" button) prior to Content Update:')
    for instance in all_module_instances:
        integration_of_instance = instance.get('brand', '')
        instance_name = instance.get('name', '')
        msg = 'Testing ("Test" button) for instance "{}" of integration "{}".'.format(instance_name,
                                                                                      integration_of_instance)
        print(msg)
        # If there is a failure, __test_integration_instance will print it
        __test_integration_instance(client, instance)

    # TODO: need to add support for content packs
    # Upload content_new.zip + content_test.zip as all_content.zip to demisto server (aka upload new content)
    content_zip_path = 'all_content.zip'
    cmd_str = 'python Tests/update_content_data.py -u {} -p {} -s {} -up {}'.format(username, password, server,
                                                                                    content_zip_path)
    run_command(cmd_str, is_silenced=False)

    # Check if content update has finished installing
    sleep_interval = 1
    updating_content = is_content_updating(server, username, password)
    while updating_content.lower() == 'true':
        sleep(sleep_interval)
        updating_content = is_content_updating(server, username, password)

    if updating_content.lower() == 'request unsuccessful':
        # since the request to check if content update installation finished didn't work, can't use that mechanism
        # to check and just try sleeping for 30 seconds instead to allow for content update installation to complete
        sleep(30)
    else:
        # check that the content installation updated
        # verify the asset id matches the circleci build number / asset_id in the content-descriptor.json
        release, asset_id = get_content_installation(client)
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

    # configure instances for new integrations
    new_integration_module_instances = []
    for integration in brand_new_integrations:
        new_integration_module_instances.append(configure_integration_instance(integration, client))
    all_module_instances.extend(new_integration_module_instances)

    # After content upload has completed - test ("Test" button) integration instances
    # Test all module instances (of pre-existing AND new integrations) post-updating content
    print_warning('Start of Instance Testing ("Test" button) after the Content Update:')
    for instance in all_module_instances:
        integration_of_instance = instance.get('brand', '')
        instance_name = instance.get('name', '')
        msg = 'Testing ("Test" button) for instance "{}" of integration "{}" .'.format(instance_name,
                                                                                       integration_of_instance)
        print(msg)
        # If there is a failure, __test_integration_instance will print it
        __test_integration_instance(client, instance)

    __disable_integrations_instances(client, all_module_instances)


if __name__ == '__main__':
    main()
