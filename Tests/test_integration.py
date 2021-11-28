from __future__ import print_function

import ast
import logging
import time
import urllib.parse
import uuid
from pprint import pformat

import demisto_client
import requests.exceptions
import urllib3
from demisto_client.demisto_api.rest import ApiException

# Disable insecure warnings
from demisto_sdk.commands.test_content.tools import update_server_configuration

urllib3.disable_warnings()

# ----- Constants ----- #
DEFAULT_TIMEOUT = 60
DEFAULT_INTERVAL = 20
ENTRY_TYPE_ERROR = 4


# ----- Functions ----- #

# get integration configuration
def __get_integration_config(client, integration_name, logging_module=logging):
    body = {
        'page': 0, 'size': 100, 'query': 'name:' + integration_name
    }
    try:
        res_raw = demisto_client.generic_request_func(self=client, path='/settings/integration/search',
                                                      method='POST', body=body)
    except ApiException:
        logging_module.exception(f'failed to get integration {integration_name} configuration')
        return None

    res = ast.literal_eval(res_raw[0])
    TIMEOUT = 180
    SLEEP_INTERVAL = 5
    total_sleep = 0
    while 'configurations' not in res:
        if total_sleep == TIMEOUT:
            logging_module.error(f"Timeout - failed to get integration {integration_name} configuration. Error: {res}")
            return None

        time.sleep(SLEEP_INTERVAL)
        total_sleep += SLEEP_INTERVAL

    all_configurations = res['configurations']
    match_configurations = [x for x in all_configurations if x['name'] == integration_name]

    if not match_configurations or len(match_configurations) == 0:
        logging_module.error('integration was not found')
        return None

    return match_configurations[0]


# __test_integration_instance
def __test_integration_instance(client, module_instance, logging_module=logging):
    connection_retries = 3
    response_code = 0
    integration_of_instance = module_instance.get('brand', '')
    instance_name = module_instance.get('name', '')
    logging_module.info(
        f'Running "test-module" for instance "{instance_name}" of integration "{integration_of_instance}".')
    for i in range(connection_retries):
        try:
            response_data, response_code, _ = demisto_client.generic_request_func(self=client, method='POST',
                                                                                  path='/settings/integration/test',
                                                                                  body=module_instance,
                                                                                  _request_timeout=120)
            break
        except ApiException:
            logging_module.exception(
                'Failed to test integration instance, error trying to communicate with demisto server')
            return False, None
        except urllib3.exceptions.ReadTimeoutError:
            logging_module.warning(f"Could not connect. Trying to connect for the {i + 1} time")

    if int(response_code) != 200:
        logging_module.error(f'Integration-instance test ("Test" button) failed. Bad status code: {response_code}')
        return False, None

    result_object = ast.literal_eval(response_data)
    success, failure_message = bool(result_object.get('success')), result_object.get('message')
    if not success:
        server_url = client.api_client.configuration.host
        test_failed_msg = f'Test integration failed - server: {server_url}.'
        test_failed_msg += f'\nFailure message: {failure_message}' if failure_message else ' No failure message.'
        logging_module.error(test_failed_msg)
    return success, failure_message


def __set_server_keys(client, logging_manager, integration_params, integration_name):
    """Adds server configuration keys using the demisto_client.

    Args:
        client (demisto_client): The configured client to use.
        logging_manager (ParallelLoggingManager): logging manager object.
        integration_params (dict): The values to use for an integration's parameters to configure an instance.
        integration_name (str): The name of the integration which the server configurations keys are related to.

    """
    if 'server_keys' not in integration_params:
        return

    logging_manager.debug(f'Setting server keys for integration: {integration_name}')

    data: dict = {
        'data': {},
        'version': -1
    }

    for key, value in integration_params.get('server_keys').items():
        data['data'][key] = value

    update_server_configuration(
        client=client,
        server_configuration=integration_params.get('server_keys'),
        error_msg='Failed to set server keys',
        logging_manager=logging_manager
    )


def __delete_integration_instance_if_determined_by_name(client, instance_name, logging_manager):
    """Deletes integration instance by it's name.

    Args:
        client (demisto_client): The configured client to use.
        instance_name (str): The name of the instance to delete.
        logging_manager (ParallelLoggingManager): logging manager object.

    Notes:
        This function is needed when the name of the instance is pre-defined in the tests configuration, and the test
        itself depends on the instance to be called as the `instance name`.
        In case we need to configure another instance with the same name, the client will throw an error, so we
        will call this function first, to delete the instance with this name.

    """
    try:
        int_resp = demisto_client.generic_request_func(self=client, method='POST',
                                                       path='/settings/integration/search',
                                                       body={'size': 1000})
        int_instances = ast.literal_eval(int_resp[0])
    except ApiException:
        logging_manager.exception(
            'Failed to delete integrations instance, error trying to communicate with demisto server')
        return
    if int(int_resp[1]) != 200:
        logging_manager.error(f'Get integration instance failed with status code: {int_resp[1]}')
        return
    if 'instances' not in int_instances:
        logging_manager.info('No integrations instances found to delete')
        return

    for instance in int_instances['instances']:
        if instance.get('name') == instance_name:
            logging_manager.info(f'Deleting integration instance {instance_name} since it is defined by name')
            __delete_integration_instance(client, instance.get('id'), logging_manager)


# return instance name if succeed, None otherwise
def __create_integration_instance(server, username, password, integration_name, integration_instance_name,
                                  integration_params, is_byoi, logging_manager=logging, validate_test=True):
    # get configuration config (used for later rest api
    integration_conf_client = demisto_client.configure(base_url=server, username=username, password=password,
                                                       verify_ssl=False)
    configuration = __get_integration_config(integration_conf_client, integration_name, logging_manager)
    if not configuration:
        return None, 'No configuration'

    module_configuration = configuration['configuration']
    if not module_configuration:
        module_configuration = []

    if 'integrationInstanceName' in integration_params:
        instance_name = integration_params['integrationInstanceName']
        __delete_integration_instance_if_determined_by_name(integration_conf_client, instance_name, logging_manager)
    else:
        instance_name = f'{integration_instance_name.replace(" ", "_")}_test_{uuid.uuid4()}'

    logging_manager.info(
        f'Configuring instance for {integration_name} (instance name: {instance_name}, validate "Test": {validate_test})'
    )
    # define module instance
    module_instance = {
        'brand': configuration['name'],
        'category': configuration['category'],
        'configuration': configuration,
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
    __set_server_keys(integration_conf_client, logging_manager, integration_params, configuration['name'])

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
    try:
        res = demisto_client.generic_request_func(self=integration_conf_client, method='PUT',
                                                  path='/settings/integration',
                                                  body=module_instance)
    except ApiException:
        error_message = f'Error trying to create instance for integration: {integration_name}'
        logging_manager.exception(error_message)
        return None, error_message

    if res[1] != 200:
        error_message = f'create instance failed with status code  {res[1]}'
        logging_manager.error(error_message)
        logging_manager.error(pformat(res[0]))
        return None, error_message

    integration_config = ast.literal_eval(res[0])
    module_instance['id'] = integration_config['id']

    # test integration
    refreshed_client = demisto_client.configure(base_url=server, username=username, password=password, verify_ssl=False)
    if validate_test:
        test_succeed, failure_message = __test_integration_instance(refreshed_client, module_instance, logging_manager)
    else:
        logging_manager.debug(
            f"Skipping test validation for integration: {integration_name} (it has test_validate set to false)"
        )
        test_succeed = True

    if not test_succeed:
        __disable_integrations_instances(refreshed_client, [module_instance], logging_manager)
        return None, failure_message

    return module_instance, ''


def __disable_integrations_instances(client, module_instances, logging_module=logging):
    for configured_instance in module_instances:
        # tested with POSTMAN, this is the minimum required fields for the request.
        module_instance = {
            key: configured_instance[key] for key in ['id', 'brand', 'name', 'data', 'isIntegrationScript', ]
        }
        module_instance['enable'] = "false"
        module_instance['version'] = -1
        logging.debug(f'Disabling integration {module_instance.get("name")}')
        try:
            res = demisto_client.generic_request_func(self=client, method='PUT',
                                                      path='/settings/integration',
                                                      body=module_instance)
        except ApiException:
            logging_module.exception('Failed to disable integration instance')
            return

        if res[1] != 200:
            logging_module.error(f'disable instance failed, Error: {pformat(res)}')


# return True if delete-integration-instance succeeded, False otherwise
def __delete_integration_instance(client, instance_id, logging_manager=logging):
    try:
        res = demisto_client.generic_request_func(self=client, method='DELETE',
                                                  path='/settings/integration/' + urllib.parse.quote(
                                                      instance_id))
    except ApiException:
        logging_manager.exception('Failed to delete integration instance, error trying to communicate with demisto.')
        return False
    if int(res[1]) != 200:
        logging_manager.error(f'delete integration instance failed\nStatus code {res[1]}')
        logging_manager.error(pformat(res))
        return False
    return True


# delete all integration instances, return True if all succeed delete all
def __delete_integrations_instances(client, module_instances, logging_manager=logging):
    succeed = True
    for module_instance in module_instances:
        succeed = __delete_integration_instance(client, module_instance['id'], logging_manager) and succeed
    return succeed


def disable_all_integrations(dem_client, logging_manager=logging):
    """
    Disable all enabled integrations. Should be called at start of test loop to start out clean

    Arguments:
        client -- demisto py client
    """
    try:
        body = {'size': 1000}
        int_resp = demisto_client.generic_request_func(self=dem_client, method='POST',
                                                       path='/settings/integration/search',
                                                       body=body)
        int_instances = ast.literal_eval(int_resp[0])
    except requests.exceptions.RequestException:
        logging_manager.exception('Failed to disable all integrations, error trying to communicate with demisto server')
        return
    if int(int_resp[1]) != 200:
        logging_manager.error(f'Get all integration instances failed with status code: {int_resp[1]}')
        return
    if 'instances' not in int_instances:
        logging_manager.info("No integrations instances found to disable all")
        return
    to_disable = []
    for instance in int_instances['instances']:
        if instance.get('enabled') == 'true' and instance.get("isIntegrationScript"):
            logging_manager.debug(
                f'Adding to disable list. Name: {instance.get("name")}. Brand: {instance.get("brand")}')
            to_disable.append(instance)
    if len(to_disable) > 0:
        __disable_integrations_instances(dem_client, to_disable, logging_manager)
