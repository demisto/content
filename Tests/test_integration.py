from __future__ import print_function
import copy
import time
from pprint import pformat
import uuid
import ast
import urllib
import urllib3
import requests.exceptions
from demisto_client.demisto_api.rest import ApiException
import demisto_client
import json

from demisto_sdk.commands.common.tools import print_error, print_warning, print_color, LOG_COLORS, Docker
from demisto_sdk.commands.common.constants import PB_Status

# Disable insecure warnings
urllib3.disable_warnings()

# ----- Constants ----- #
DEFAULT_TIMEOUT = 60
DEFAULT_INTERVAL = 20
ENTRY_TYPE_ERROR = 4


# ----- Functions ----- #

# get integration configuration
def __get_integration_config(client, integration_name, prints_manager, thread_index=0):
    body = {
        'page': 0, 'size': 100, 'query': 'name:' + integration_name
    }
    try:
        res_raw = demisto_client.generic_request_func(self=client, path='/settings/integration/search',
                                                      method='POST', body=body)
    except ApiException as conn_error:
        prints_manager.add_print_job(conn_error, print, thread_index)
        return None

    res = ast.literal_eval(res_raw[0])
    TIMEOUT = 180
    SLEEP_INTERVAL = 5
    total_sleep = 0
    while 'configurations' not in res:
        if total_sleep == TIMEOUT:
            error_message = "Timeout - failed to get integration {} configuration. Error: {}".format(integration_name,
                                                                                                     res)
            prints_manager.add_print_job(error_message, print_error, thread_index)
            return None

        time.sleep(SLEEP_INTERVAL)
        total_sleep += SLEEP_INTERVAL

    all_configurations = res['configurations']
    match_configurations = [x for x in all_configurations if x['name'] == integration_name]

    if not match_configurations or len(match_configurations) == 0:
        prints_manager.add_print_job('integration was not found', print_error, thread_index)
        return None

    return match_configurations[0]


# __test_integration_instance
def __test_integration_instance(client, module_instance, prints_manager, thread_index=0):
    connection_retries = 3
    response_code = 0
    prints_manager.add_print_job("trying to connect.", print_warning, thread_index)
    for i in range(connection_retries):
        try:
            response_data, response_code, _ = demisto_client.generic_request_func(self=client, method='POST',
                                                                                  path='/settings/integration/test',
                                                                                  body=module_instance,
                                                                                  _request_timeout=120)
            break
        except ApiException as conn_err:
            error_msg = 'Failed to test integration instance, error trying to communicate with demisto ' \
                        'server: {} '.format(conn_err)
            prints_manager.add_print_job(error_msg, print_error, thread_index)
            return False, None
        except urllib3.exceptions.ReadTimeoutError:
            warning_msg = "Could not connect. Trying to connect for the {} time".format(i + 1)
            prints_manager.add_print_job(warning_msg, print_warning, thread_index)

    if int(response_code) != 200:
        test_failed_msg = 'Integration-instance test ("Test" button) failed.\nBad status code: ' + str(
            response_code)
        prints_manager.add_print_job(test_failed_msg, print_error, thread_index)
        return False, None

    result_object = ast.literal_eval(response_data)
    success, failure_message = bool(result_object.get('success')), result_object.get('message')
    if not success:
        if failure_message:
            test_failed_msg = 'Test integration failed.\nFailure message: {}'.format(failure_message)
            prints_manager.add_print_job(test_failed_msg, print_error, thread_index)
        else:
            test_failed_msg = 'Test integration failed\nNo failure message.'
            prints_manager.add_print_job(test_failed_msg, print_error, thread_index)
    return success, failure_message


# return instance name if succeed, None otherwise
def __create_integration_instance(client, integration_name, integration_instance_name,
                                  integration_params, is_byoi, prints_manager, validate_test=True, thread_index=0):
    start_message = 'Configuring instance for {} (instance name: {}, ' \
                    'validate "Test": {})'.format(integration_name, integration_instance_name, validate_test)
    prints_manager.add_print_job(start_message, print, thread_index)

    # get configuration config (used for later rest api
    configuration = __get_integration_config(client, integration_name, prints_manager,
                                             thread_index=thread_index)
    if not configuration:
        return None, 'No configuration', None

    module_configuration = configuration['configuration']
    if not module_configuration:
        module_configuration = []

    instance_name = '{}_test_{}'.format(integration_instance_name.replace(' ', '_'),
                                        str(uuid.uuid4()))
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
        res = demisto_client.generic_request_func(self=client, method='PUT',
                                                  path='/settings/integration',
                                                  body=module_instance)
    except ApiException as conn_err:
        error_message = 'Error trying to create instance for integration: {0}:\n {1}'.format(
            integration_name, conn_err
        )
        prints_manager.add_print_job(error_message, print_error, thread_index)
        return None, error_message, None

    if res[1] != 200:
        error_message = 'create instance failed with status code ' + str(res[1])
        prints_manager.add_print_job(error_message, print_error, thread_index)
        prints_manager.add_print_job(pformat(res[0]), print_error, thread_index)
        return None, error_message, None

    integration_config = ast.literal_eval(res[0])
    module_instance['id'] = integration_config['id']

    # test integration
    if validate_test:
        test_succeed, failure_message = __test_integration_instance(client, module_instance, prints_manager,
                                                                    thread_index=thread_index)
    else:
        print_warning(
            "Skipping test validation for integration: {} (it has test_validate set to false)".format(integration_name)
        )
        test_succeed = True

    if not test_succeed:
        __disable_integrations_instances(client, [module_instance], prints_manager, thread_index=thread_index)
        return None, failure_message, None

    docker_image = Docker.get_integration_image(integration_config)

    return module_instance, '', docker_image


def __disable_integrations_instances(client, module_instances, prints_manager, thread_index=0):
    for configured_instance in module_instances:
        # tested with POSTMAN, this is the minimum required fields for the request.
        module_instance = {
            key: configured_instance[key] for key in ['id', 'brand', 'name', 'data', 'isIntegrationScript', ]
        }
        module_instance['enable'] = "false"
        module_instance['version'] = -1

        try:
            res = demisto_client.generic_request_func(self=client, method='PUT',
                                                      path='/settings/integration',
                                                      body=module_instance)
        except ApiException as conn_err:
            error_message = 'Failed to disable integration instance, error trying to communicate with demisto ' \
                            'server: {} '.format(conn_err)
            prints_manager.add_print_job(error_message, print_error, thread_index)
            return

        if res[1] != 200:
            error_message = 'disable instance failed with status code ' + str(res[1])
            prints_manager.add_print_job(error_message, print_error, thread_index)
            prints_manager.add_print_job(pformat(res), print_error, thread_index)


def __enable_integrations_instances(client, module_instances):
    for configured_instance in module_instances:
        # tested with POSTMAN, this is the minimum required fields for the request.
        module_instance = {
            key: configured_instance[key] for key in ['id', 'brand', 'name', 'data', 'isIntegrationScript', ]
        }
        module_instance['enable'] = "true"
        module_instance['version'] = -1

        try:
            res = demisto_client.generic_request_func(self=client, method='PUT',
                                                      path='/settings/integration',
                                                      body=module_instance)
        except ApiException as conn_err:
            print_error(
                'Failed to enable integration instance, error trying to communicate with demisto '
                'server: {} '.format(conn_err)
            )

        if res[1] != 200:
            print_error('Enabling instance failed with status code ' + str(res[1]) + '\n' + pformat(res))


# create incident with given name & playbook, and then fetch & return the incident
def __create_incident_with_playbook(client, name, playbook_id, integrations, prints_manager, thread_index=0):
    # create incident
    create_incident_request = demisto_client.demisto_api.CreateIncidentRequest()
    create_incident_request.create_investigation = True
    create_incident_request.playbook_id = playbook_id
    create_incident_request.name = name

    try:
        response = client.create_incident(create_incident_request=create_incident_request)
    except ApiException as err:
        prints_manager.add_print_job(str(err), print_error, thread_index)

    try:
        inc_id = response.id
    except:  # noqa: E722
        inc_id = 'incCreateErr'
    # inc_id = response_json.get('id', 'incCreateErr')
    if inc_id == 'incCreateErr':
        integration_names = [integration['name'] for integration in integrations if
                             'name' in integration]
        error_message = 'Failed to create incident for integration names: {} and playbookID: {}.' \
                        'Possible reasons are:\nMismatch between playbookID in conf.json and ' \
                        'the id of the real playbook you were trying to use,' \
                        'or schema problems in the TestPlaybook.'.format(str(integration_names), playbook_id)
        prints_manager.add_print_job(error_message, print_error, thread_index)
        return False, -1

    # get incident
    search_filter = demisto_client.demisto_api.SearchIncidentsData()
    inc_filter = demisto_client.demisto_api.IncidentFilter()
    inc_filter.query = 'id:' + str(inc_id)
    # inc_filter.query
    search_filter.filter = inc_filter

    try:
        incidents = client.search_incidents(filter=search_filter)
    except ApiException as err:
        prints_manager.add_print_job(err, print, thread_index)
        incidents = {'total': 0}

    # poll the incidents queue for a max time of 120 seconds
    timeout = time.time() + 120
    while incidents['total'] != 1:
        try:
            incidents = client.search_incidents(filter=search_filter)
        except ApiException as err:
            prints_manager.add_print_job(err, print, thread_index)
        if time.time() > timeout:
            error_message = 'Got timeout for searching incident with id {}, ' \
                            'got {} incidents in the search'.format(inc_id, incidents['total'])
            prints_manager.add_print_job(error_message, print_error, thread_index)
            return False, -1

        time.sleep(1)

    return incidents['data'][0], inc_id


# returns current investigation playbook state - 'inprogress'/'failed'/'completed'
def __get_investigation_playbook_state(client, inv_id, prints_manager, thread_index=0):
    try:
        investigation_playbook_raw = demisto_client.generic_request_func(self=client, method='GET',
                                                                         path='/inv-playbook/' + inv_id)
        investigation_playbook = ast.literal_eval(investigation_playbook_raw[0])
    except requests.exceptions.RequestException as conn_err:
        error_message = 'Failed to get investigation playbook state, error trying to communicate with demisto ' \
                        'server: {} '.format(conn_err)
        prints_manager.add_print_job(error_message, print_error, thread_index)
        return PB_Status.FAILED

    try:
        state = investigation_playbook['state']
        return state
    except:  # noqa: E722
        return PB_Status.NOT_SUPPORTED_VERSION


# return True if delete-incident succeeded, False otherwise
def __delete_incident(client, incident, prints_manager, thread_index=0):
    try:
        body = {
            'ids': [incident['id']],
            'filter': {},
            'all': False
        }
        res = demisto_client.generic_request_func(self=client, method='POST',
                                                  path='/incident/batchDelete', body=body)
    except requests.exceptions.RequestException as conn_err:
        error_message = 'Failed to delete incident, error trying to communicate with demisto server: {} ' \
                        ''.format(conn_err)
        prints_manager.add_print_job(error_message, print_error, thread_index)
        return False

    if int(res[1]) != 200:
        error_message = 'delete incident failed\nStatus code' + str(res[1])
        prints_manager.add_print_job(error_message, print_error, thread_index)
        prints_manager.add_print_job(pformat(res), print_error, thread_index)
        return False

    return True


# return True if delete-integration-instance succeeded, False otherwise
def __delete_integration_instance(client, instance_id, prints_manager, thread_index=0):
    try:
        res = demisto_client.generic_request_func(self=client, method='DELETE',
                                                  path='/settings/integration/' + urllib.quote(
                                                      instance_id))
    except requests.exceptions.RequestException as conn_err:
        error_message = 'Failed to delete integration instance, error trying to communicate with demisto ' \
                        'server: {} '.format(conn_err)
        prints_manager.add_print_job(error_message, print_error, thread_index)
        return False
    if int(res[1]) != 200:
        error_message = 'delete integration instance failed\nStatus code' + str(res[1])
        prints_manager.add_print_job(error_message, print_error, thread_index)
        prints_manager.add_print_job(pformat(res), print_error, thread_index)
        return False
    return True


# delete all integration instances, return True if all succeed delete all
def __delete_integrations_instances(client, module_instances, prints_manager, thread_index=0):
    succeed = True
    for module_instance in module_instances:
        succeed = __delete_integration_instance(client, module_instance['id'], thread_index=thread_index,
                                                prints_manager=prints_manager) and succeed
    return succeed


def __print_investigation_error(client, playbook_id, investigation_id, prints_manager, color=LOG_COLORS.RED,
                                thread_index=0):
    try:
        empty_json = {"pageSize": 1000}
        res = demisto_client.generic_request_func(self=client, method='POST',
                                                  path='/investigation/' + urllib.quote(
                                                      investigation_id), body=empty_json)
    except requests.exceptions.RequestException as conn_err:
        error_message = 'Failed to print investigation error, error trying to communicate with demisto ' \
                        'server: {} '.format(conn_err)
        prints_manager.add_print_job(error_message, print_error, thread_index)
    if res and int(res[1]) == 200:
        resp_json = ast.literal_eval(res[0])
        entries = resp_json['entries']
        prints_manager.add_print_job('Playbook ' + playbook_id + ' has failed:', print_color, thread_index,
                                     message_color=color)
        for entry in entries:
            if entry['type'] == ENTRY_TYPE_ERROR and entry['parentContent']:
                prints_manager.add_print_job('- Task ID: ' + entry['taskId'].encode('utf-8'), print_color, thread_index,
                                             message_color=color)
                prints_manager.add_print_job('  Command: ' + entry['parentContent'].encode('utf-8'), print_color,
                                             thread_index, message_color=color)
                body_contents_str = '  Body:\n' + entry['contents'].encode('utf-8') + '\n'
                prints_manager.add_print_job(body_contents_str, print_color,
                                             thread_index, message_color=color)


# Configure integrations to work with mock
def configure_proxy_unsecure(integration_params):
    """Copies the integration parameters dictionary.
        Set proxy and insecure integration parameters to true.

    Args:
        integration_params: dict of the integration parameters.
    """
    integration_params_copy = copy.deepcopy(integration_params)
    for param in ('proxy', 'useProxy', 'insecure', 'unsecure'):
        integration_params[param] = True

    return integration_params_copy


# 1. create integrations instances
# 2. create incident with playbook
# 3. wait for playbook to finish run
# 4. if test pass - delete incident & instance
# return playbook status
def test_integration(client, server_url, integrations, playbook_id, prints_manager, options=None, is_mock_run=False,
                     thread_index=0):
    options = options if options is not None else {}
    # create integrations instances
    module_instances = []
    test_docker_images = set()

    with open("./Tests/conf.json", 'r') as conf_file:
        docker_thresholds = json.load(conf_file).get('docker_thresholds', {}).get('images', {})

    for integration in integrations:
        integration_name = integration.get('name', None)
        integration_instance_name = integration.get('instance_name', '')
        integration_params = integration.get('params', None)
        is_byoi = integration.get('byoi', True)
        validate_test = integration.get('validate_test', True)

        if is_mock_run:
            configure_proxy_unsecure(integration_params)

        module_instance, failure_message, docker_image = __create_integration_instance(client, integration_name,
                                                                                       integration_instance_name,
                                                                                       integration_params,
                                                                                       is_byoi, prints_manager,
                                                                                       validate_test=validate_test,
                                                                                       thread_index=thread_index)
        if module_instance is None:
            failure_message = failure_message if failure_message else 'No failure message could be found'
            msg = 'Failed to create instance: {}'.format(failure_message)
            prints_manager.add_print_job(msg, print_error, thread_index)  # disable-secrets-detection
            __delete_integrations_instances(client, module_instances, prints_manager, thread_index=thread_index)
            return False, -1

        module_instances.append(module_instance)
        if docker_image:
            test_docker_images.update(docker_image)

        prints_manager.add_print_job('Create integration {} succeed'.format(integration_name), print, thread_index)

    # create incident with playbook
    incident, inc_id = __create_incident_with_playbook(client, 'inc_{}'.format(playbook_id, ),
                                                       playbook_id, integrations, prints_manager,
                                                       thread_index=thread_index)

    if not incident:
        return False, -1

    investigation_id = incident['investigationId']
    if investigation_id is None or len(investigation_id) == 0:
        incident_id_not_found_msg = 'Failed to get investigation id of incident:' + incident
        prints_manager.add_print_job(incident_id_not_found_msg, print_error, thread_index)  # disable-secrets-detection
        return False, -1

    prints_manager.add_print_job('Investigation URL: {}/#/WorkPlan/{}'.format(server_url, investigation_id), print,
                                 thread_index)

    timeout_amount = options['timeout'] if 'timeout' in options else DEFAULT_TIMEOUT
    timeout = time.time() + timeout_amount

    i = 1
    # wait for playbook to finish run
    while True:
        # give playbook time to run
        time.sleep(1)

        # fetch status
        playbook_state = __get_investigation_playbook_state(client, investigation_id, prints_manager,
                                                            thread_index=thread_index)

        if playbook_state in (PB_Status.COMPLETED, PB_Status.NOT_SUPPORTED_VERSION):
            break
        if playbook_state == PB_Status.FAILED:
            if is_mock_run:
                prints_manager.add_print_job(playbook_id + ' failed with error/s', print_warning, thread_index)
                __print_investigation_error(client, playbook_id, investigation_id, prints_manager,
                                            LOG_COLORS.YELLOW, thread_index=thread_index)
            else:
                prints_manager.add_print_job(playbook_id + ' failed with error/s', print_error, thread_index)
                __print_investigation_error(client, playbook_id, investigation_id, prints_manager,
                                            thread_index=thread_index)
            break
        if time.time() > timeout:
            prints_manager.add_print_job(playbook_id + ' failed on timeout', print_error, thread_index)
            break

        if i % DEFAULT_INTERVAL == 0:
            loop_number_message = 'loop no. {}, playbook state is {}'.format(
                i / DEFAULT_INTERVAL, playbook_state)
            prints_manager.add_print_job(loop_number_message, print, thread_index)
        i = i + 1

    __disable_integrations_instances(client, module_instances, prints_manager, thread_index=thread_index)

    if test_docker_images:
        memory_threshold = options.get('memory_threshold', Docker.DEFAULT_CONTAINER_MEMORY_USAGE)
        pids_threshold = options.get('pid_threshold', Docker.DEFAULT_CONTAINER_PIDS_USAGE)
        error_message = Docker.check_resource_usage(server_url=server_url,
                                                    docker_images=test_docker_images,
                                                    def_memory_threshold=memory_threshold,
                                                    def_pid_threshold=pids_threshold,
                                                    docker_thresholds=docker_thresholds)

        if error_message:
            prints_manager.add_print_job(error_message, print_error, thread_index)
            return PB_Status.FAILED_DOCKER_TEST, inc_id
    else:
        prints_manager.add_print_job("Skipping docker container memory resource check for test {}".format(playbook_id),
                                     print_warning, thread_index)

    test_pass = playbook_state in (PB_Status.COMPLETED, PB_Status.NOT_SUPPORTED_VERSION)
    if test_pass:
        # delete incident
        __delete_incident(client, incident, prints_manager, thread_index=thread_index)

        # delete integration instance
        __delete_integrations_instances(client, module_instances, prints_manager, thread_index=thread_index)

    return playbook_state, inc_id


def disable_all_integrations(demisto_api_key, server, prints_manager, thread_index=0):
    """
    Disable all enabled integrations. Should be called at start of test loop to start out clean

    Arguments:
        client -- demisto py client
    """
    client = demisto_client.configure(base_url=server, api_key=demisto_api_key, verify_ssl=False)
    try:
        body = {'size': 1000}
        int_resp = demisto_client.generic_request_func(self=client, method='POST',
                                                       path='/settings/integration/search',
                                                       body=body)
        int_instances = ast.literal_eval(int_resp[0])
    except requests.exceptions.RequestException as conn_err:
        error_message = 'Failed to disable all integrations, error trying to communicate with demisto server: ' \
                        '{} '.format(conn_err)
        prints_manager.add_print_job(error_message, print_error, thread_index)
        return
    if int(int_resp[1]) != 200:
        error_message = 'Get all integration instances failed with status code: {}'.format(int_resp[1])
        prints_manager.add_print_job(error_message, print_error, thread_index)
        return
    if 'instances' not in int_instances:
        prints_manager.add_print_job("No integrations instances found to disable all", print, thread_index)
        return
    to_disable = []
    for instance in int_instances['instances']:
        if instance.get('enabled') == 'true' and instance.get("isIntegrationScript"):
            add_to_disable_message = "Adding to disable list. Name: {}. Brand: {}".format(instance.get("name"),
                                                                                          instance.get("brand"))
            prints_manager.add_print_job(add_to_disable_message, print, thread_index)
            to_disable.append(instance)
    if len(to_disable) > 0:
        __disable_integrations_instances(client, to_disable, prints_manager, thread_index=thread_index)
