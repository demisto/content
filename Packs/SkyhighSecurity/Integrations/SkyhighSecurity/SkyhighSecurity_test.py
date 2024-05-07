import json
import requests_mock
from freezegun import freeze_time
import demistomock as demisto
from SkyhighSecurity import main


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def util_load_text(path: str) -> str:
    with open(path) as f:
        return f.read()


def test_incident_query_command(mocker):
    """
    Given:
        - An app client object
        - Relevant arguments
    When:
        - skyhigh-security-incident-query command is executed
    Then:
        - Ensure the output is a list of incidents in the correct format
    """
    mocker.patch.object(demisto, 'params', return_value={'url': 'https://www.example.com/', 'insecure': True})
    mocker.patch.object(demisto, 'args', return_value={'limit': 3})
    mocker.patch.object(demisto, 'command', return_value='skyhigh-security-incident-query')
    response = mocker.patch.object(demisto, 'results')

    with requests_mock.Mocker() as m:
        m.post('https://www.example.com/shnapi/rest/external/api/v1/queryIncidents?limit=3',
               json=util_load_json('test_data/incidents.json'))
        main()

    assert len(response.call_args[0][0]['Contents']) > 0
    assert response.call_args[0][0]['Contents'][0]['incidentId'] == 'CAP-1111'


def test_status_update_command(mocker):
    """
    Given:
        - An app client object
        - Relevant arguments
    When:
        - skyhigh-security-incident-status-update command is executed
    Then:
        - Ensure the readable output is in the correct format
    """
    mocker.patch.object(demisto, 'params', return_value={'url': 'https://www.example.com/', 'insecure': True})
    mocker.patch.object(demisto, 'args', return_value={'incident_ids': 'CAP-1111', 'status': 'archived'})
    mocker.patch.object(demisto, 'command', return_value='skyhigh-security-incident-status-update')
    response = mocker.patch.object(demisto, 'results')

    with requests_mock.Mocker() as m:
        m.post('https://www.example.com/shnapi/rest/external/api/v1/modifyIncidents', json={})
        main()

    assert response.call_args[0][0].get('HumanReadable') == 'Status updated for user'


def test_anomaly_activity_list_command_empty_response(mocker):
    """
    Given:
        - An app client object
        - Relevant arguments
    When:
        - skyhigh-security-anomaly-activity-list command is executed
        - The request returns 200 OK with no data.
    Then:
        - Ensure the readable output is in the correct format
    """
    mocker.patch.object(demisto, 'params', return_value={'url': 'https://www.example.com/', 'insecure': True})
    mocker.patch.object(demisto, 'args', return_value={'anomaly_id': '1111'})
    mocker.patch.object(demisto, 'command', return_value='skyhigh-security-anomaly-activity-list')
    response = mocker.patch.object(demisto, 'results')
    with requests_mock.Mocker() as m:
        m.post('https://www.example.com/shnapi/rest/external/api/v1/queryActivities', status_code=200)
        main()
    assert response.call_args[0][0].get('HumanReadable') == 'No activities found for anomaly ID 1111'


def test_anomaly_activity_list_command_with_response(mocker):
    """
    Given:
        - An app client object
        - Relevant arguments
        - Response with data
    When:
        - skyhigh-security-anomaly-activity-list command is executed
        - The request returns 200 OK with with fata.
    Then:
        - Ensure the readable output is in the correct format
    """
    mocker.patch.object(demisto, 'params', return_value={'url': 'https://www.example.com/', 'insecure': True})
    mocker.patch.object(demisto, 'args', return_value={'anomaly_id': '1111'})
    mocker.patch.object(demisto, 'command', return_value='skyhigh-security-anomaly-activity-list')
    response = mocker.patch.object(demisto, 'results')
    with requests_mock.Mocker() as m:
        m.post('https://www.example.com/shnapi/rest/external/api/v1/queryActivities',
               text=util_load_text('test_data/activities.txt'),
               status_code=200)
        main()
    assert len(response.call_args[0][0]['Contents']) > 0
    assert 'Anomaly Activity List' in response.call_args[0][0]['HumanReadable']


def test_csv2json():
    """
    Given:
        - Response text.
    When:
        - Executing the csv2json function.
    Then:
        - Verify that the text is in the right format.
    """
    from SkyhighSecurity import csv2json
    response = util_load_text('test_data/activities.txt')
    results = csv2json(response)
    assert type(results) is list
    assert results[0] == {'Severity': 'High', 'ID': '34290314', 'Service / Domain Name': 'Microsoft Exchange Online',
                          'Date / Time': '10-Feb-2021 00:07:19', 'Anomaly Type': 'Data Transfer', 'Activity Type': 'Upload',
                          'Response': 'Allowed', 'User Risk Level': 'Medium',
                          'User / IP Address': 'c1eeefb535697e4434adc4c9edd7d4f8788f6cbe053a60d12ad0cbf100c12345',
                          'Anomaly Value': '199612833', 'Threshold': '90040000', 'DestinationHost': 'outlook.office365.com',
                          'Valid': 'Yes'}


def test_policy_dictionary_list_command(mocker):
    """
    Given:
        - An app client object
        - Relevant arguments
    When:
        - skyhigh-security-policy-dictionary-list command is executed
    Then:
        - Ensure the output is a list of policies in the correct format
    """
    mocker.patch.object(demisto, 'params', return_value={'url': 'https://www.example.com/', 'insecure': True})
    mocker.patch.object(demisto, 'args', return_value={'limit': 3})
    mocker.patch.object(demisto, 'command', return_value='skyhigh-security-policy-dictionary-list')
    response = mocker.patch.object(demisto, 'results')

    with requests_mock.Mocker() as m:
        m.get('https://www.example.com/shnapi/rest/dlp/dictionary', json=util_load_json('test_data/policies.json'))
        main()

    assert len(response.call_args[0][0]['Contents']) > 0
    assert response.call_args[0][0]['Contents'][0]['ID'] == 1111


def test_policy_dictionary_update_command(mocker):
    """
    Given:
        - An app client object
        - Relevant arguments
    When:
        - skyhigh-security-policy-dictionary-update command is executed
    Then:
        - Ensure the readable output is in the correct format
    """
    mocker.patch.object(demisto, 'params', return_value={'url': 'https://www.example.com/', 'insecure': True})
    mocker.patch.object(demisto, 'args', return_value={
        'dictionary_id': '1111', 'name': '(Default) Internal Domains', 'content': 'gmail.com, outlook.com'
    })
    mocker.patch.object(demisto, 'command', return_value='skyhigh-security-policy-dictionary-update')
    response = mocker.patch.object(demisto, 'results')

    with requests_mock.Mocker() as m:
        m.put('https://www.example.com/shnapi/rest/dlp/dictionary', json={})
        main()

    assert response.call_args[0][0].get('HumanReadable') == 'Dictionary id: 1111 was updated.'


def mock_incident_query(limit, start_time):
    if start_time == '2022-06-17T00:00:00.000000Z':
        return util_load_json('test_data/incidents.json')
    else:
        return {}


@freeze_time('2022/06/20 00:00:00')
def test_fetch_incidents(mocker):
    """
    Given:
        - An app client object
    When:
        - fetch-incidents command is executed
    Then:
        - Ensure the output in the first interval is a list of 3 (max_fetch) incidents
        - Ensure the output of the second interval is a list of 0 incidents
    """
    from SkyhighSecurity import Client, fetch_incidents

    client = Client(base_url='https://www.example.com/', verify=False)
    params = {'max_fetch': 3}
    mocker.patch.object(Client, "incident_query", side_effect=mock_incident_query)
    mocker.patch.object(demisto, "getLastRun", return_value={})

    last_run, incidents = fetch_incidents(client, params)

    assert len(incidents) > 0
    assert last_run.get('start_time') == '2022-03-19T05:21:19.552Z'
    assert len(last_run.get('ids')) > 0

    mocker.patch.object(demisto, "getLastRun", return_value=last_run)
    last_run, incidents = fetch_incidents(client, params)

    assert len(incidents) == 0
