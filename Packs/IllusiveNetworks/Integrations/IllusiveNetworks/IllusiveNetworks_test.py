from IllusiveNetworks import Client, is_deceptive_user_command, is_deceptive_server_command, \
    delete_deceptive_users_command, delete_deceptive_servers_command, run_forensics_on_demand_command, \
    get_asm_host_insight_command, get_asm_cj_insight_command, get_deceptive_users_command, \
    get_deceptive_servers_command, get_forensics_timeline_command, assign_host_to_policy_command, \
    remove_host_from_policy_command, add_deceptive_users_command, add_deceptive_servers_command, \
    get_incidents_command, get_event_incident_id_command, fetch_incidents, get_incident_events_command, \
    get_forensics_analyzers_command, get_forensics_triggering_process_info_command, get_forensics_artifacts_command

from CommonServerPython import parse_date_range
from freezegun import freeze_time


DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.000Z'


def test_is_deceptive_user_command_returns_true(requests_mock):
    mock_response = {'result': 'true'}
    requests_mock.get('https://server/api/v1/deceptive-entities/user?userName=myUser', json=mock_response)

    client = Client(base_url='https://server', verify=False)
    args = {
        'username': 'myUser'
    }
    _, outputs, _ = is_deceptive_user_command(client, args)

    assert outputs['Illusive.IsDeceptive(val.Username == obj.Username)']['Username'] == args['username']
    assert outputs['Illusive.IsDeceptive(val.Username == obj.Username)']['IsDeceptiveUser'] is True


def test_is_deceptive_user_command_returns_false(requests_mock):
    requests_mock.get('https://server/api/v1/deceptive-entities/user?userName=myUser', text='')

    client = Client(base_url='https://server', verify=False)
    args = {
        'username': 'myUser'
    }
    _, outputs, _ = is_deceptive_user_command(client, args)

    assert outputs['Illusive.IsDeceptive(val.Username == obj.Username)']['Username'] == args['username']
    assert outputs['Illusive.IsDeceptive(val.Username == obj.Username)']['IsDeceptiveUser'] is False


def test_is_deceptive_server_command_returns_true(requests_mock):
    mock_response = {'result': 'true'}
    requests_mock.get('https://server/api/v1/deceptive-entities/server?hostName=myHost', json=mock_response)

    client = Client(base_url='https://server', verify=False)
    args = {
        'hostname': 'myHost'
    }
    _, outputs, _ = is_deceptive_server_command(client, args)

    assert outputs['Illusive.IsDeceptive(val.Hostname == obj.Hostname)']['Hostname'] == args['hostname']
    assert outputs['Illusive.IsDeceptive(val.Hostname == obj.Hostname)']['IsDeceptiveServer'] is True


def test_is_deceptive_server_command_returns_false(requests_mock):
    requests_mock.get('https://server/api/v1/deceptive-entities/server?hostName=myHost', text='')

    client = Client(base_url='https://server', verify=False)
    args = {
        'hostname': 'myHost'
    }
    _, outputs, _ = is_deceptive_server_command(client, args)

    assert outputs['Illusive.IsDeceptive(val.Hostname == obj.Hostname)']['Hostname'] == args['hostname']
    assert outputs['Illusive.IsDeceptive(val.Hostname == obj.Hostname)']['IsDeceptiveServer'] is False


def test_delete_deceptive_users_command(requests_mock):
    mock_response = {'result': 'False'}
    requests_mock.delete('https://server/api/v1/deceptive-entities/users?deceptive_users=user1&deceptive_users=user2',
                         json=mock_response)

    client = Client(base_url='https://server', verify=False)

    args = {
        'deceptive_users': ['user1', 'user2']
    }
    _, outputs, _ = delete_deceptive_users_command(client, args)

    assert outputs == {}


def test_delete_deceptive_servers_command(requests_mock):
    mock_response = {'result': 'False'}
    requests_mock.delete('https://server/api/v1/deceptive-entities/servers?deceptive_hosts=server1', json=mock_response)

    client = Client(base_url='https://server', verify=False)

    args = {
        'deceptive_hosts': ['server1']
    }
    _, outputs, _ = delete_deceptive_servers_command(client, args)

    assert outputs == {}


def test_run_forensics_on_demand_command(requests_mock):
    mock_response = {'EventId': '1234'}
    requests_mock.post('https://server/api/v1/event/create-external-event?hostNameOrIp=myIp', json=mock_response)

    client = Client(base_url='https://server', verify=False)
    args = {
        'fqdn_or_ip': "myIp"
    }
    _, outputs, _ = run_forensics_on_demand_command(client, args)

    assert outputs == {'Illusive.Event(val.eventId == obj.eventId)': {'EventId': '1234'}}


def test_get_event_incident_id_command(requests_mock):
    mock_response = {'EventId': '1234', 'IncidentId': '1'}
    requests_mock.get('https://server/api/v1/incidents/id?event_id=1234', json=mock_response)

    client = Client(base_url='https://server', verify=False)

    args = {
        'event_id': "1234"
    }
    _, outputs, _ = get_event_incident_id_command(client, args)

    assert outputs == {'Illusive.Event(val.eventId == obj.eventId)':
                       [{'eventId': 1234, 'incidentId': {'EventId': '1234', 'IncidentId': '1'},
                        'status': 'Done'}]}


def test_get_asm_host_insight_command(requests_mock):
    mock_response = {'hostname': 'aaa', 'domainName': 'bbb', 'ipAddresses': '1.1.1.1'}
    requests_mock.get('https://server/api/v1/attack-surface/machine-insights?hostNameOrIp=myIp',
                      json=mock_response, status_code=202)

    client = Client(base_url='https://server', verify=False)

    args = {
        'hostnameOrIp': "myIp"
    }
    _, outputs, _ = get_asm_host_insight_command(client, args)

    assert outputs == {'Illusive.AttackSurfaceInsightsHost(val.ipAddresses == obj.ipAddresses)':
                       {'hostname': 'aaa', 'domainName': 'bbb', 'ipAddresses': '1.1.1.1'}}


def test_get_asm_cj_insight_command(requests_mock):
    mock_response = {'data': [], 'hostname': 'bbb', 'machineTagAndSubTags': {'tag': 'tag', 'subTag': 'sub'}}
    requests_mock.get('https://server/api/v1/crownjewels/insights', json=mock_response, status_code=202)

    client = Client(base_url='https://server', verify=False)

    args = {
    }
    _, outputs, _ = get_asm_cj_insight_command(client, args)

    assert outputs == {'Illusive.AttackSurfaceInsightsCrownJewel(val.hostname == obj.hostname)':
                       {'data': [], 'hostname': 'bbb', 'machineTagAndSubTags': {'tag': 'tag', 'subTag': 'sub'}}}


def test_get_deceptive_users_command(requests_mock):
    mock_response = {'data': [], 'hostname': 'bbb', 'machineTagAndSubTags': {'tag': 'tag', 'subTag': 'sub'}}
    requests_mock.get('https://server/api/v1/deceptive-entities/users?deceptive_user_type=ALL', json=mock_response)

    client = Client(base_url='https://server', verify=False)
    args = {
    }
    _, outputs, _ = get_deceptive_users_command(client, args)

    assert outputs == {'Illusive.DeceptiveUser(val.userName == obj.userName)':
                       {'data': [], 'hostname': 'bbb', 'machineTagAndSubTags': {'tag': 'tag', 'subTag': 'sub'}}}


def test_get_deceptive_servers_command(requests_mock):
    mock_response = {'data': [], 'hostname': 'bbb', 'machineTagAndSubTags': {'tag': 'tag', 'subTag': 'sub'}}
    requests_mock.get('https://server/api/v1/deceptive-entities/servers?deceptive_server_type=SUGGESTED',
                      json=mock_response)

    client = Client(base_url='https://server', verify=False)
    args = {
        'type': "SUGGESTED",
    }
    _, outputs, _ = get_deceptive_servers_command(client, args)

    assert outputs == {'Illusive.DeceptiveServer(val.host == obj.host)':
                       {'data': [], 'hostname': 'bbb', 'machineTagAndSubTags': {'tag': 'tag', 'subTag': 'sub'}}}


@freeze_time("2024-04-10T11:00:00")
def test_get_forensics_timeline_command(requests_mock):
    mock_response = [{'IncidentId': "aaa", 'Status': 'Done', 'details': {'date': 'aaa'}}]
    client = Client(base_url='https://server', verify=False)
    start_date = "1 month"
    end_date = "3 days"
    args = {
        'incident_id': "3",
        'start_date': start_date,
        'end_date': end_date
    }
    start_date_parsed, _ = parse_date_range(start_date, date_format=DATE_FORMAT, utc=True)
    end_date_parsed, _ = parse_date_range(end_date, date_format=DATE_FORMAT, utc=True)
    url = f'https://server/api/v1/forensics/timeline?incident_id=3&end_date={end_date_parsed}&start_date={start_date_parsed}'\

    requests_mock.get(url, json=mock_response)
    _, outputs, _ = get_forensics_timeline_command(client, args)

    assert outputs == {'Illusive.Forensics(val.IncidentId == obj.IncidentId)':
                       {'IncidentId': '3', 'Status': 'Done', 'Evidence':
                        [{'IncidentId': 'aaa', 'Status': 'Done', 'details': {'date': 'aaa'}, 'date': 'aaa'}]}}


def test_remove_host_from_policy_command(requests_mock):
    mock_response = {'result': 'True'}
    requests_mock.post('https://server/api/v1/policy/domain_hosts/remove_assignment', json=mock_response)

    client = Client(base_url='https://server', verify=False)
    args = {
        'hosts': ['aaa@domain.com']
    }
    _, outputs, _ = remove_host_from_policy_command(client, args)

    assert outputs == {'Illusive.DeceptionPolicy.isAssigned(val.hosts == obj.hosts)':
                       [{'isAssigned': False, 'hosts': 'aaa@domain.com', 'policy_name': ''}]}


def test_assign_host_to_policy_command(requests_mock):
    mock_response = {'result': 'True'}
    requests_mock.post('https://server/api/v1/policy/domain_hosts/assign?policy_name=myPolicy', json=mock_response)

    client = Client(base_url='https://server', verify=False)
    args = {
        'policy_name': "myPolicy",
        'hosts': ['aaa@domain.com']
    }

    _, outputs, _ = assign_host_to_policy_command(client, args)

    assert outputs == {'Illusive.DeceptionPolicy.isAssigned(val.hosts == obj.hosts)':
                       [{'isAssigned': True, 'hosts': 'aaa@domain.com', 'policy_name': 'myPolicy'}]}


def test_add_deceptive_users_command(requests_mock):
    mock_response = {'id': 'aaa'}
    requests_mock.post('https://server/api/v1/deceptive-entities/users', json=mock_response)

    client = Client(base_url='https://server', verify=False)
    user_name = "aaa"
    domain_name = "illusive.com"
    args = {
        'password': "aaa",
        'username': user_name,
        'domain_name': domain_name,
        'policy_names': ["myPolicy"]
    }

    _, outputs, _ = add_deceptive_users_command(client, args)

    assert outputs == {'Illusive.DeceptiveUser(val.userName == obj.userName)':
                       {'userName': 'aaa', 'domainName': 'illusive.com', 'policyNames': ['myPolicy'], 'password': 'aaa'}}


def test_add_deceptive_servers_command(requests_mock):
    mock_response = {'id': 'aaa'}
    requests_mock.post('https://server/api/v1/deceptive-entities/servers', json=mock_response)

    client = Client(base_url='https://server', verify=False)
    user_name = 'aaa.illusive.com'
    args = {
        'service_types': ["FTP", "SSH"],
        'host': user_name
    }

    _, outputs, _ = add_deceptive_servers_command(client, args)

    assert outputs == {'Illusive.DeceptiveServer(val.host == obj.host)':
                       {'host': 'aaa.illusive.com', 'serviceTypes': ['FTP', 'SSH'], 'policyNames': "All Policies"}}


def test_get_incident_command(requests_mock):
    mock_response = {'deceptionFamilies': [], 'incidentId': '1234', 'hasForensics': True, 'incidentTypes': 'MACHINE'}
    requests_mock.get('https://server/api/v2/incidents/incident?incident_id=13', json=mock_response)

    client = Client(base_url='https://server', verify=False)
    args = {
        'incident_id': "13",
        'start_date': "3 days"
    }
    _, outputs, _ = get_incidents_command(client, args)

    assert outputs == {'Illusive.Incident(val.incidentId == obj.incidentId)':
                       {'deceptionFamilies': [], 'incidentId': '1234', 'hasForensics': True, 'incidentTypes': 'MACHINE'}}


def test_get_incidents_command(requests_mock):
    mock_response = [{'deceptionFamilies': [], 'incidentId': '1234', 'hasForensics': True, 'incidentTypes': 'MACHINE'},
                     {'deceptionFamilies': [], 'incidentId': '4321', 'hasForensics': False, 'incidentTypes': 'MACHINE'}]
    requests_mock.get('https://server/api/v1/incidents?limit=10&offset=0', json=mock_response)

    client = Client(base_url='https://server', verify=False)
    args = {
    }
    _, outputs, _ = get_incidents_command(client, args)

    assert outputs == {'Illusive.Incident(val.incidentId == obj.incidentId)': [
                      {'deceptionFamilies': [], 'incidentId': '1234', 'hasForensics': True, 'incidentTypes': 'MACHINE'},
                      {'deceptionFamilies': [], 'incidentId': '4321', 'hasForensics': False, 'incidentTypes': 'MACHINE'}
    ]}


def test_fetch_incidents(requests_mock):
    client = Client(base_url='https://server', verify=False)
    mock_response = [{'deceptionFamilies': [], 'incidentId': '1234', 'hasForensics': True,
                      'incidentTypes': 'MACHINE', 'incidentTimeUTC': '2020-04-21T15:39:32.954Z'},
                     {'deceptionFamilies': [], 'incidentId': '4321', 'hasForensics': False,
                     'incidentTypes': 'MACHINE', 'incidentTimeUTC': '2020-04-21T14:53:54.234Z'}]
    first_fetch_time = "7 days"
    requests_mock.get('https://server/api/v1/incidents?limit=10&offset=0&start_date=2018-10-24T14:13:20+00:000Z',
                      json=mock_response)
    nextcheck, incidents = fetch_incidents(client, {'last_run': "2018-10-24T14:13:20+00:000Z"}, first_fetch_time, None)

    assert str(nextcheck['last_run']) == '2020-04-21T15:39:32.954Z'
    assert isinstance(incidents, list)
    assert isinstance(incidents[0]['name'], str)


def test_fetch_incidents_first_fetch(requests_mock):
    client = Client(base_url='https://server', verify=False)
    mock_response = []
    first_fetch_time = "7 days"
    last_fetch, _ = parse_date_range(first_fetch_time, date_format=DATE_FORMAT, utc=True)
    requests_mock.get(f'https://server/api/v1/incidents?limit=10&offset=0&start_date={last_fetch}',
                      json=mock_response)
    nextcheck, incidents = fetch_incidents(client, {'last_run': None}, first_fetch_time, None)

    assert str(nextcheck['last_run']) == last_fetch
    assert isinstance(incidents, list)
    assert len(incidents) == 0


def test_get_incident_events_command(requests_mock):
    mock_response = [{'eventId': '11', 'eventTimeUTC': '1234', 'hasForensics': True},
                     {'eventId': '22', 'eventTimeUTC': '1234', 'hasForensics': True}]
    requests_mock.get('https://server/api/v1/incidents/events?incident_id=3&limit=100&offset=0', json=mock_response)

    client = Client(base_url='https://server', verify=False)
    args = {
        'incident_id': '3'
    }
    _, outputs, _ = get_incident_events_command(client, args)

    assert outputs == {'Illusive.Incident(val.incidentId == obj.incidentId)': {'Event': [
                      {'eventId': '11', 'eventTimeUTC': '1234', 'hasForensics': True},
                      {'eventId': '22', 'eventTimeUTC': '1234', 'hasForensics': True}],
        'eventsNumber': 2, 'incidentId': 3}}


def test_get_forensics_analyzers_command(requests_mock):
    mock_response1 = [{'analyzerName': 'bbb', 'analyzerValue': '1234'},
                      {'analyzerName': 'aaa', 'analyzerValue': '4321'}]
    mock_response2 = 3
    requests_mock.get('https://server/api/v1/forensics/analyzers?event_id=3', json=mock_response1)
    requests_mock.get('https://server/api/v1/incidents/id?event_id=3', json=mock_response2)

    client = Client(base_url='https://server', verify=False)
    args = {
        'event_id': '3'
    }
    _, outputs, _ = get_forensics_analyzers_command(client, args)

    assert outputs == {'Illusive.Event(val.eventId == obj.eventId)': {'ForensicsAnalyzers':
                       [{'analyzerName': 'bbb', 'analyzerValue': '1234'},
                        {'analyzerName': 'aaa', 'analyzerValue': '4321'}], 'eventId': 3, 'incidentId': 3}}


def test_get_forensics_triggering_process_info_command(requests_mock):
    mock_response = {'processes': [{'commandLine': 'bbb', 'name': '1234', 'parent': '1234', 'sha256': '1234'},
                     {'commandLine': 'aaa', 'name': '34556', 'parent': 'dfg', 'sha256': 'erf'}]}
    requests_mock.get('https://server/api/v1/forensics/triggering_process_info?event_id=3', json=mock_response)

    client = Client(base_url='https://server', verify=False)
    args = {
        'event_id': '3'
    }
    _, outputs, _ = get_forensics_triggering_process_info_command(client, args)

    assert outputs == {'Illusive.Event(val.eventId == obj.eventId)': {'ForensicsTriggeringProcess': [
                      {'commandLine': 'bbb', 'name': '1234', 'parent': '1234', 'sha256': '1234'},
                      {'commandLine': 'aaa', 'name': '34556', 'parent': 'dfg', 'sha256': 'erf'}], 'eventId': '3'}}


def test_get_forensics_artifacts_command(requests_mock):
    mock_response = b''
    mock_response2 = 3
    requests_mock.get('https://server/api/v1/incidents/id?event_id=3', json=mock_response2)
    requests_mock.get('https://server/api/v1/forensics/artifacts?event_id=3&artifacts_type=DESKTOP_SCREENSHOT',
                      content=mock_response)

    client = Client(base_url='https://server', verify=False)
    args = {
        'event_id': '3',
        'artifact_type': 'DESKTOP_SCREENSHOT'
    }
    get_forensics_artifacts_command(client, args)
