import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''
from datetime import datetime

import dateparser

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


def results_return(command, data):
    if command == 'GetVersion':
        results = CommandResults(
            outputs_prefix='CiscoAMP.' + str(command),
            outputs_key_field='',
            outputs={'version': data['version']}
        )
    elif 'data' in data and data['data']:
        results = CommandResults(
            outputs_prefix='CiscoAMP.' + str(command),
            outputs_key_field='',
            outputs=data['data']
        )
    else:
        results = CommandResults(
            outputs_prefix='CiscoAMP.' + str(command),
            outputs_key_field='',
            outputs={'data': 'no results'}
        )
    return_results(results)


def test_module(client):
    result = client._http_request('GET', '/version/')
    if result:
        return 'ok'
    else:
        return f'Test failed: {result}'


def create_incident_from_log(log):
    occurred = log['date']
    keys = log.keys()
    labels = []
    for key in keys:
        labels.append({'type': key, 'value': str(log[key])})
        try:
            formatted_description = f'Cisco AMP Incident - {log["detection"]}'
        except KeyError:
            formatted_description = 'Cisco AMP Incident'
    return {
        'name': formatted_description,
        'labels': labels,
        'rawJSON': json.dumps(log),
        'occurred': occurred
    }


def form_incindents(logs):
    listofincidents = []
    for item in logs:
        listofincidents.append(create_incident_from_log(item))
    return listofincidents


def fetch_incidents(client):
    parameters = {}
    timefrom = dateparser.parse(demisto.params().get('fetch_time')).strftime('%Y-%m-%dT%H:%M:%S')
    orginaloffset = int(demisto.params().get('fetch_time_offset'))
    if orginaloffset < 10 and orginaloffset >= 0:
        offset = f'+0{orginaloffset}:00'
    else:
        offset = f'+{orginaloffset}:00'
    timefrom += offset
    eventtype = demisto.params().get('fetch_event_type')
    last_run = demisto.getLastRun()
    if last_run and 'start_time' in last_run:
        start_time = last_run.get('start_time')
    else:
        start_time = timefrom
    end_time = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
    end_time += offset
    parameters['start_date'] = start_time
    if eventtype:
        parameters['event_type[]'] = eventtype.split(',')
    results = client._http_request('GET', 'events', params=parameters)
    if 'data' in results and results['metadata']['results']['total'] > 0:
        demisto.setLastRun({'start_time': end_time})
        demisto.incidents(form_incindents(results['data']))
    else:
        demisto.setLastRun({'start_time': end_time})
        demisto.incidents([])


def main():
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')

    # get the service API url
    base_url = urljoin(demisto.params()['server'], '/v1/')

    verify_certificate = not demisto.params().get('insecure', False)

    proxy = demisto.params().get('proxy', False)

    headers = {'Accept': 'application/json', 'content-type': 'application/json'}

    demisto.info(f'Command being called is {demisto.command()}')
    try:
        client = BaseClient(
            base_url=base_url,
            verify=verify_certificate,
            auth=(username, password),
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)
        elif demisto.command() == 'fetch-incidents':
            fetch_incidents(client)
        elif demisto.command() == 'amp_get_computers':
            parameters = {'group_guid[]': demisto.args().get('group_guid'),
                          'internal_ip': demisto.args().get('internal_ip'),
                          'hostname[]': demisto.args().get('hostname'),
                          'external_ip': demisto.args().get('external_ip'),
                          'limit': demisto.args().get('limit')}
            results_return('GetComputers', client._http_request('GET', 'computers/', params=parameters))
        elif demisto.command() == 'amp_get_computer_by_connector':
            connector_guid = demisto.args().get('connector_guid')
            results_return('GetComputerByConnector', client._http_request('GET', f'computers/{connector_guid}'))
        elif demisto.command() == 'amp_get_computer_trajectory':
            connector_guid = demisto.args().get('connector_guid')
            parameters = {'q': demisto.args().get('q'),
                          'limit': demisto.args().get('limit')}
            results_return('GetComputerByTrajectory', client._http_request(
                'GET', f'computers/{connector_guid}/trajectory', params=parameters))
        elif demisto.command() == 'amp_move_computer':
            connector_guid = demisto.args().get('connector_guid')
            jsonparameters = {'group_guid': demisto.args().get('group_guid')}
            jsonparameters = remove_empty_elements(jsonparameters)
            results_return('MoveComputer', client._http_request('PATCH', f'computers/{connector_guid}', json_data=jsonparameters))
        elif demisto.command() == 'amp_get_computer_activity':
            parameters = {'q': demisto.args().get('q'),
                          'offset': demisto.args().get('offset'),
                          'limit': demisto.args().get('limit')}
            results_return('GetComputerActivity', client._http_request('GET', 'computers/activity', params=parameters))
        elif demisto.command() == 'amp_get_user_activity':
            parameters = {'q': demisto.args().get('q'),
                          'limit': demisto.args().get('limit'),
                          'offset': demisto.args().get('offset')}
            results_return('GetUserActivity', client._http_request('GET', 'computers/user_activity', params=parameters))
        elif demisto.command() == 'amp_get_user_trajectory':
            connector_guid = demisto.args().get('connector_guid')
            parameters = {'q': demisto.args().get('q'),
                          'limit': demisto.args().get('limit')}
            results_return('GetUserByTrajectory', client._http_request(
                'GET', f'computers/{connector_guid}/user_trajectory', params=parameters))
        elif demisto.command() == 'amp_delete_computer':
            connector_guid = demisto.args().get('connector_guid')
            results_return('DeleteComputer', client._http_request('DELETE', f'computers/{connector_guid}'))
        elif demisto.command() == 'amp_get_computers_isolation':
            connector_guid = demisto.args().get('connector_guid')
            results_return('GetComputerIsolation', client._http_request('GET', f'computers/{connector_guid}/isolation'))
        elif demisto.command() == 'amp_get_computers_isolation_feature_availability':
            connector_guid = demisto.args().get('connector_guid')
            results_return('ComputerIsolationFeature', client._http_request('OPTIONS', f'computers/{connector_guid}/isolation'))
        elif demisto.command() == 'amp_put_computers_isolation':
            connector_guid = demisto.args().get('connector_guid')
            results_return('PutComputerIsolation', client._http_request('PUT', f'computers/{connector_guid}/isolation'))
        elif demisto.command() == 'amp_delete_computers_isolation':
            connector_guid = demisto.args().get('connector_guid')
            results_return('DeleteComputerIsolation', client._http_request(
                'DELETE', f'computers/{connector_guid}/isolation', params=parameters))
        elif demisto.command() == 'amp_get_events':
            parameters = {'group_guid[]': demisto.args().get('group_guid'),
                          'detection_sha256': demisto.args().get('detection_sha256'),
                          'application_sha256': demisto.args().get('application_sha256'),
                          'connector_guid[]': demisto.args().get('connector_guid'),
                          'start_date': demisto.args().get('start_date'),
                          'offset': demisto.args().get('offset'),
                          'event_type[]': demisto.args().get('event_type').split(','),
                          'limit': demisto.args().get('limit')}
            results_return('GetEvents', client._http_request('GET', 'events', params=parameters))
        elif demisto.command() == 'amp_get_event_types':
            results_return('GetEventTypes', client._http_request('GET', 'event_types'))
        elif demisto.command() == 'amp_get_application_blocking':
            parameters = {'name[]': demisto.args().get('name'),
                          'offset': demisto.args().get('offset'),
                          'limit': demisto.args().get('limit')}
            results_return('GetApplicationBlocking', client._http_request(
                'GET', 'file_lists/application_blocking', params=parameters))
        elif demisto.command() == 'amp_get_file_list_by_guid':
            file_list_guid = demisto.args().get('file_list_guid')
            results_return('GetFileList', client._http_request('GET', f'file_lists/{file_list_guid}'))
        elif demisto.command() == 'amp_get_simple_custom_detections':
            parameters = {'name[]': demisto.args().get('name'),
                          'offset': demisto.args().get('offset'),
                          'limit': demisto.args().get('limit')}
            results_return('GetSimpleCustomDetections', client._http_request(
                'GET', 'file_lists/simple_custom_detections', params=parameters))
        elif demisto.command() == 'amp_get_file_list_files':
            file_list_guid = demisto.args().get('file_list_guid')
            parameters = {'offset': demisto.args().get('offset'),
                          'limit': demisto.args().get('limit')}
            results_return('GetFileListFiles', client._http_request(
                'GET', f'file_lists/{file_list_guid}/files', params=parameters))
        elif demisto.command() == 'amp_get_file_list_files_by_sha':
            file_list_guid = demisto.args().get('file_list_guid')
            sha256 = demisto.args().get('sha256')
            results_return('GetFileListFilesBySHA256', client._http_request('GET', f'file_lists/{file_list_guid}/files/{sha256}'))
        elif demisto.command() == 'amp_set_file_list_files_by_sha':
            file_list_guid = demisto.args().get('file_list_guid')
            sha256 = demisto.args().get('sha256')
            jsonparameters = {'description': demisto.args().get('description')}
            jsonparameters = remove_empty_elements(jsonparameters)
            results_return('SetFileList', client._http_request(
                'POST', f'file_lists/{file_list_guid}/files/{sha256}', json_data=jsonparameters))
        elif demisto.command() == 'amp_delete_file_list_files_by_sha':
            file_list_guid = demisto.args().get('file_list_guid')
            sha256 = demisto.args().get('sha256')
            results_return('DeleteFileList', client._http_request('DELETE', f'file_lists/{file_list_guid}/files/{sha256}'))
        elif demisto.command() == 'amp_get_groups':
            parameters = {'name': demisto.args().get('name'),
                          'limit': demisto.args().get('limit')}
            results_return('GetGroups', client._http_request('GET', 'groups/', params=parameters))
        elif demisto.command() == 'amp_get_group':
            group_guid = demisto.args().get('group_guid')
            results_return('GetGroup', client._http_request('GET', f'groups/{group_guid}'))
        elif demisto.command() == 'amp_set_group_policy':
            group_guid = demisto.args().get('group_guid')
            jsonparameters = {'linux_policy_guid': demisto.args().get('linux_policy_guid'),
                              'android_policy_guid': demisto.args().get('android_policy_guid'),
                              'mac_policy_guid': demisto.args().get('mac_policy_guid'),
                              'windows_policy_guid': demisto.args().get('windows_policy_guid')}
            jsonparameters = remove_empty_elements(jsonparameters)
            results_return('SetGroupPolicy', client._http_request('PATCH', f'groups/{group_guid}', json_data=jsonparameters))
        elif demisto.command() == 'amp_get_policies':
            parameters = {'name[]': demisto.args().get('name'),
                          'offset': demisto.args().get('offset'),
                          'product[]': demisto.args().get('product'),
                          'limit': demisto.args().get('limit')}
            results_return('GetPolicies', client._http_request('GET', 'policies/', params=parameters))
        elif demisto.command() == 'amp_get_policy':
            policy_guid = demisto.args().get('policy_guid')
            results_return('GetPolicy', client._http_request('GET', f'policies/{policy_guid}'))
        elif demisto.command() == 'amp_get_version':
            results_return('GetVersion', client._http_request('GET', 'version'))
        elif demisto.command() == 'amp_set_group_child_policy':
            child_guid = demisto.args().get('child_guid')
            jsonparameters = {'parent_group_guid': demisto.args().get('parent_group_guid')}
            jsonparameters = remove_empty_elements(jsonparameters)
            results_return('SetGroupChild', client._http_request(
                'PATCH', f'groups/{child_guid}/parent', json_data=jsonparameters))
        elif demisto.command() == 'amp_create_group':
            jsonparameters = {'name': demisto.args().get('name'),
                              'description': demisto.args().get('description')}
            jsonparameters = remove_empty_elements(jsonparameters)
            results_return('CreateGroup', client._http_request('POST', 'groups', json_data=jsonparameters))
        elif demisto.command() == 'amp_delete_group':
            group_guid = demisto.args().get('group_guid')
            results_return('DeleteGroup', client._http_request('DELETE', f'groups/{group_guid}'))
        elif demisto.command() == 'amp_get_indicators':
            parameters = {'offset': demisto.args().get('offset'),
                          'limit': demisto.args().get('limit')}
            results_return('Indicators', client._http_request('GET', 'indicators/', params=parameters))
        elif demisto.command() == 'amp_get_indicator':
            indicator_guid = demisto.args().get('indicator_guid')
            results_return('Indicator', client._http_request('GET', f'indicators/{indicator_guid}'))
        elif demisto.command() == 'amp_get_app_trajectory':
            parameters = {'ios_bid': demisto.args().get('ios_bid')}
            results_return('Indicator', client._http_request('GET', 'app_trajectory/queries', params=parameters))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
