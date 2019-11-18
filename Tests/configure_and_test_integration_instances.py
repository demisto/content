import argparse
import uuid
import demisto_client
from Tests.test_integration import configure_proxy_unsecure, __enable_integrations_instances
from Tests.test_integration import __delete_integrations_instances, __disable_integrations_instances
from Tests.test_integration import __get_integration_configuration, __test_integration_instance
from Tests.test_utils import print_error
from Tests.test_content import load_conf_files, collect_integrations, extract_filtered_tests
from Tests.test_utils import run_command


def options_handler():
    parser = argparse.ArgumentParser(description='Utility for instantiating and testing integration instances')
    parser.add_argument('-u', '--user', help='The username for the login', required=True)
    parser.add_argument('-p', '--password', help='The password for the login', required=True)
    parser.add_argument('-s', '--server', help='The server URL to connect to')
    parser.add_argument('-c', '--conf', help='Path to conf file', required=True)
    parser.add_argument('-e', '--secret', help='Path to secret conf file')

    options = parser.parse_args()

    return options


def set_integration_params(integrations, secret_params, instance_names):
    for integration in integrations:
        integration_params = [item for item in secret_params if item['name'] == integration['name']]

        if integration_params:
            matched_integration_params = integration_params[0]
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


def set_integration_instance_parameters(integration_configuration, integration_params, integration_instance_name, is_byoi):
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
    module_configuration = integration_configuration['configuration']
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
            # param is required - take default value
            param_conf['value'] = param_conf['defaultValue']
        module_instance['data'].append(param_conf)

    return module_instance


def main():
    options = options_handler()
    username = options.user
    password = options.password
    server = options.server
    conf_path = options.conf
    secret_conf_path = options.secret

    conf, secret_conf = load_conf_files(conf_path, secret_conf_path)
    secret_params = secret_conf['integrations'] if secret_conf else []

    username = secret_conf.get('username')
    password = secret_conf.get('userPassword')

    client = demisto_client.configure(base_url=server, username=username, password=password, verify_ssl=False)

    tests = conf['tests']
    nightly_integrations = conf['nightly_integrations']
    skipped_integrations_conf = conf['skipped_integrations']
    unmockable_integrations = conf['unmockable_integrations']

    skipped_integration = set([])
    all_module_instances = []

    filtered_tests, filter_configured, run_all_tests = extract_filtered_tests()
    tests_for_iteration = tests
    if run_all_tests:
        # Use all tests for testing, leave 'tests_for_iteration' as is
        pass
    elif filter_configured and filtered_tests:
        tests_for_iteration = [test for test in tests if test.get('playbookID', '') in filtered_tests]

    # Each test is a dictionary from Tests/conf.json which may contain the following fields
    # "playbookID", "integrations", "instance_names", "timeout", "nightly", "fromversion", "toversion"
    # Note that only the "playbookID" field is required with all of the others being optional.
    # Most tests have an "integrations" field listing the integration used for that playbook
    # and sometimes an "instance_names" field which is used when there are multiple instances
    # of an integration that we want to configure with different configuration values. Look at
    # [conf.json](../conf.json) for examples
    for test in tests_for_iteration:
        integrations_conf = test.get('integrations', [])
        instance_names_conf = test.get('instance_names', [])

        if not isinstance(instance_names_conf, list):
            instance_names_conf = [instance_names_conf, ]

        has_skipped_integration, integrations, is_nightly_integration = collect_integrations(integrations_conf, skipped_integration, skipped_integrations_conf, nightly_integrations)
        are_params_set = set_integration_params(integrations, secret_params, instance_names_conf)
        if not are_params_set:
            print_error('failed setting parameters for integrations "{}"'.format('\n'.join(integrations)))
            continue
        module_instances = []
        for integration in integrations:
            integration_name = integration.get('name', None)
            if integration_name in skipped_integrations_conf.keys():
                continue
            integration_instance_name = integration.get('instance_name', '')
            integration_params = integration.get('params', None)
            is_byoi = integration.get('byoi', True)

            integration_configuration = __get_integration_configuration(client, integration_name)
            module_instance = set_integration_instance_parameters(integration_configuration, integration_params, integration_instance_name, is_byoi)
            module_instances.append(module_instance)
        all_module_instances.extend(module_instances)

    # Test all module instances pre-updating content
    failure_messages = []
    for instance in all_module_instances:
        success = __test_integration_instance(client, instance)
        if not success:
            integration_of_instance = instance.get('brand', '')
            instance_name = instance.get('name', '')
            fail_msg = 'Instance "{}" of integration "{}" test ("Test" button) failed.'.format(instance_name, integration_of_instance)
            failure_messages.append(fail_msg)
    # Print out any ("Test" button) failures
    if failure_messages:
        print_error('Instance "Test" button failures prior to Content Update:')
        for failure_msg in failure_messages:
            print_error(failure_msg)

    # Upload current build's content_new.zip to demisto server (aka upload new content)
    content_zip_path = '.content_new.zip'
    cmd_str = 'python update_content_data.py -u {} -p {} -s {} -up {}'.format(username, password, server, content_zip_path)
    run_command(cmd_str, is_silenced=False)

    # After content upload has completed - test ("Test" button) integration instances
    # Test all module instances post-updating content
    failure_messages = []
    for instance in all_module_instances:
        success = __test_integration_instance(client, instance)
        if not success:
            integration_of_instance = instance.get('brand', '')
            instance_name = instance.get('name', '')
            fail_msg = 'Instance "{}" of integration "{}" test ("Test" button) failed.'.format(instance_name, integration_of_instance)
            failure_messages.append(fail_msg)
    # Print out any ("Test" button) failures
    if failure_messages:
        print_error('Instance "Test" button failures after the Content Update:')
        for failure_msg in failure_messages:
            print_error(failure_msg)

    __disable_integrations_instances(client, all_module_instances)
    __delete_integrations_instances(client, all_module_instances)


if __name__ == '__main__':
    main()
