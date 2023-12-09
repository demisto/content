import json
import io
import requests_mock
from freezegun import freeze_time
import demistomock as demisto
from SkyhighSecurity import main


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


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


def test_anomaly_activity_list_command(mocker):
    """
    Given:
        - An app client object
        - Relevant arguments
    When:
        - skyhigh-security-anomaly-activity-list command is executed
    Then:
        - Ensure the readable output is in the correct format
    """
    mocker.patch.object(demisto, 'params', return_value={'url': 'https://www.example.com/', 'insecure': True})
    mocker.patch.object(demisto, 'args', return_value={'anomaly_id': '1111'})
    mocker.patch.object(demisto, 'command', return_value='skyhigh-security-anomaly-activity-list')
    response = mocker.patch.object(demisto, 'results')

    with requests_mock.Mocker() as m:
        m.post('https://www.example.com/shnapi/rest/external/api/v1/queryActivities', json={})
        main()

    assert response.call_args[0][0].get('HumanReadable') == '**No entries.**\n'


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
