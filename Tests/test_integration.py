import time
from pprint import pformat
import uuid
import urllib
from test_utils import print_error

# ----- Constants ----- #
DEFAULT_TIMEOUT = 60
DEFAULT_INTERVAL = 20
ENTRY_TYPE_ERROR = 4

INC_CREATION_ERR = 'Failed to create incident. Possible reasons are:\nMismatch between playbookID in conf.json and ' \
                   'the id of the real playbook you were trying to use, or schema problems in the TestPlaybook.'


class PB_Status:
    COMPLETED = 'completed'
    FAILED = 'failed'
    IN_PROGRESS = 'inprogress'


# ----- Functions ----- #


# get integration configuration
def __get_integration_config(client, integration_name):
    res = client.req('POST', '/settings/integration/search', {
        'page': 0, 'size': 100, 'query': 'name:' + integration_name
    })

    res = res.json()
    all_configurations = res['configurations']
    match_configurations = [x for x in all_configurations if x['name'] == integration_name]

    if not match_configurations or len(match_configurations) == 0:
        print_error('integration was not found')
        return None

    return match_configurations[0]


# __test_integration_instance
def __test_integration_instance(client, module_instance):
    res = client.req('POST', '/settings/integration/test', module_instance)
    if res.status_code != 200:
        print_error('Integration-instance test ("Test" button) failed.\nBad status code: ' + str(res.status_code))
        return False

    result_object = res.json()
    success = result_object['success']
    if not success:
        print_error('Test integration failed.\n Failure message: ' + result_object['message'])
        return False

    return True


# return instance name if succeed, None otherwise
def __create_integration_instance(client, integration_name, integration_params, is_byoi):
    print('Configuring instance for {}'.format(integration_name))
    # get configuration config (used for later rest api
    configuration = __get_integration_config(client, integration_name)
    if not configuration:
        return None

    module_configuration = configuration['configuration']
    if not module_configuration:
        module_configuration = []

    instance_name = integration_name + '_test' + str(uuid.uuid4())
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
    res = client.req('PUT', '/settings/integration', module_instance)

    if res.status_code != 200:
        print_error('create instance failed with status code ' + str(res.status_code))
        print_error(pformat(res.json()))
        return None

    integration_config = res.json()
    module_instance['id'] = integration_config['id']

    # test integration
    test_succeed = __test_integration_instance(client, module_instance)

    if not test_succeed:
        __disable_integrations_instances(client, [module_instance])
        return None

    return module_instance


def __disable_integrations_instances(client, module_instances):
    for configured_instance in module_instances:
        module_instance = {
            key: configured_instance[key] for key in ['id', 'brand', 'name', 'data', 'isIntegrationScript', ]
        }
        module_instance['enable'] = "false"
        module_instance['version'] = -1

        res = client.req('PUT', '/settings/integration', module_instance)

        if res.status_code != 200:
            print_error('disable instance failed with status code ' + str(res.status_code))
            print_error(pformat(res.json()))


# create incident with given name & playbook, and then fetch & return the incident
def __create_incident_with_playbook(client, name, playbook_id):
    # create incident
    kwargs = {'createInvestigation': True, 'playbookId': playbook_id}
    response_json = {}
    try:
        r = client.CreateIncident(name, None, None, None, None, None, None, **kwargs)
        response_json = r.json()
    except RuntimeError as err:
        print_error(str(err))

    inc_id = response_json.get('id', 'incCreateErr')
    if inc_id == 'incCreateErr':
        print_error(INC_CREATION_ERR)
        return False, -1

    # get incident
    incidents = client.SearchIncidents(0, 50, 'id:' + inc_id)

    # poll the incidents queue for a max time of 25 seconds
    timeout = time.time() + 25
    while incidents['total'] != 1:
        incidents = client.SearchIncidents(0, 50, 'id:' + inc_id)
        if time.time() > timeout:
            print_error('Got timeout for searching incident with id {}, '
                        'got {} incidents in the search'.format(inc_id, incidents['total']))
            return False, -1

        time.sleep(1)

    return incidents['data'][0], inc_id


# returns current investigation playbook state - 'inprogress'/'failed'/'completed'
def __get_investigation_playbook_state(client, inv_id):
    res = client.req('GET', '/inv-playbook/' + inv_id, {})
    investigation_playbook = res.json()

    return investigation_playbook['state']


# return True if delete-incident succeeded, False otherwise
def __delete_incident(client, incident):
    res = client.req('POST', '/incident/batchDelete', {
        'ids': [incident['id']],
        'filter': {},
        'all': False
    })

    if res.status_code != 200:
        print_error('delete incident failed\nStatus code' + str(res.status_code))
        print_error(pformat(res.json()))
        return False

    return True


# return True if delete-integration-instance succeeded, False otherwise
def __delete_integration_instance(client, instance_id):
    res = client.req('DELETE', '/settings/integration/' + urllib.quote(instance_id), {})
    if res.status_code != 200:
        print_error('delete integration instance failed\nStatus code' + str(res.status_code))
        print_error(pformat(res.json()))
        return False
    return True


# delete all integration instances, return True if all succeed delete all
def __delete_integrations_instances(client, module_instances):
    succeed = True
    for module_instance in module_instances:
        succeed = __delete_integration_instance(client, module_instance['id']) and succeed
    return succeed


def __print_investigation_error(client, playbook_id, investigation_id):
    res = client.req('POST', '/investigation/' + urllib.quote(investigation_id), {})
    if res.status_code == 200:
        entries = res.json()['entries']
        print_error('Playbook ' + playbook_id + ' has failed:')
        for entry in entries:
            if entry['type'] == ENTRY_TYPE_ERROR:
                if entry['parentContent']:
                    print_error('\t- Command: ' + str(entry['parentContent']))
                print_error('\t- Body: ' + str(entry['contents']))


# 1. create integrations instances
# 2. create incident with playbook
# 3. wait for playbook to finish run
# 4. if test pass - delete incident & instance
# return True if playbook completed successfully
def test_integration(client, integrations, playbook_id, options=None):
    options = options if options is not None else {}
    # create integrations instances
    module_instances = []
    for integration in integrations:
        integration_name = integration.get('name', None)
        integration_params = integration.get('params', None)
        is_byoi = integration.get('byoi', True)

        module_instance = __create_integration_instance(client, integration_name, integration_params, is_byoi)
        if module_instance is None:
            print_error('Failed to create instance')
            __delete_integrations_instances(client, module_instances)
            return False, -1

        module_instances.append(module_instance)
        print('Create integration %s succeed' % (integration_name, ))

    # create incident with playbook
    incident, inc_id = __create_incident_with_playbook(client, 'inc_%s' % (playbook_id, ), playbook_id)

    if not incident:
        return False, -1

    investigation_id = incident['investigationId']
    if investigation_id is None or len(investigation_id) == 0:
        print_error('Failed to get investigation id of incident:' + incident)
        return False, -1

    timeout_amount = options['timeout'] if 'timeout' in options else DEFAULT_TIMEOUT
    timeout = time.time() + timeout_amount

    i = 1
    # wait for playbook to finish run
    while True:
        # give playbook time to run
        time.sleep(1)

        # fetch status
        playbook_state = __get_investigation_playbook_state(client, investigation_id)

        if playbook_state == PB_Status.COMPLETED:
            break
        if playbook_state == PB_Status.FAILED:
            print_error(playbook_id + ' failed with error/s')
            __print_investigation_error(client, playbook_id, investigation_id)
            break
        if time.time() > timeout:
            print_error(playbook_id + ' failed on timeout')
            break

        if i % DEFAULT_INTERVAL == 0:
            print 'loop no.' + str(i / DEFAULT_INTERVAL) + ', playbook state is ' + playbook_state
        i = i + 1

    __disable_integrations_instances(client, module_instances)

    test_pass = playbook_state == PB_Status.COMPLETED
    if test_pass:
        # delete incident
        __delete_incident(client, incident)

        # delete integration instance
        __delete_integrations_instances(client, module_instances)

    return test_pass, inc_id
