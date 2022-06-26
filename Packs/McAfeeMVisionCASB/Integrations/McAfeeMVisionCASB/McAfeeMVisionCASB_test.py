import json
import io
import requests_mock
from freezegun import freeze_time
import demistomock as demisto


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_incident_query_command():
    from McAfeeMVisionCASB import Client, incident_query_command

    client = Client(base_url='https://www.example.com/', verify=False)
    args = {'limit': 3}

    with requests_mock.Mocker() as m:
        m.post('https://www.example.com/external/api/v1/queryIncidents?limit=3', json=util_load_json('test_data/incidents.json'))
        response = incident_query_command(client, args)

    assert len(response.outputs) == 3
    assert response.outputs[0]['incidentId'] == 'CAP-1111'


def test_status_update_command():
    from McAfeeMVisionCASB import Client, status_update_command

    client = Client(base_url='https://www.example.com/', verify=False)
    args = {'incident_ids': [1111, 2222], 'status': 'RESOLVED'}

    with requests_mock.Mocker() as m:
        m.post('https://www.example.com/external/api/v1/modifyIncidents', json={})
        response = status_update_command(client, args)

    assert response.readable_output == 'Status updated for user'


def test_anomaly_activity_list_command():
    from McAfeeMVisionCASB import Client, anomaly_activity_list_command

    client = Client(base_url='https://www.example.com/', verify=False)
    args = {'anomaly_id': 3333}

    with requests_mock.Mocker() as m:
        m.post('https://www.example.com/external/api/v1/queryActivities', json={})
        response = anomaly_activity_list_command(client, args)

    assert len(response.outputs) == 0


def test_policy_dictionary_list_command():
    from McAfeeMVisionCASB import Client, policy_dictionary_list_command

    client = Client(base_url='https://www.example.com/', verify=False)
    args = {'limit': 2}

    with requests_mock.Mocker() as m:
        m.get('https://www.example.com/dlp/dictionary', json=util_load_json('test_data/policies.json'))
        response = policy_dictionary_list_command(client, args)

    assert len(response.outputs) == 2
    assert response.outputs[0]['ID'] == 1111


def test_policy_dictionary_update_command():
    from McAfeeMVisionCASB import Client, policy_dictionary_update_command

    client = Client(base_url='https://www.example.com/', verify=False)
    args = {'dictionary_id': 1111, 'name': 'Test', 'content': ['gmail.com', 'outlook.com']}

    with requests_mock.Mocker() as m:
        m.put('https://www.example.com/dlp/dictionary', json={})
        response = policy_dictionary_update_command(client, args)

    assert response.readable_output == f'Dictionary id: {args.get("dictionary_id")} was updated.'


def mock_incident_query(limit, start_time):
    if start_time == '2022-06-17T00:00:00.000000Z':
        return util_load_json('test_data/incidents.json')
    else:
        return {}


@freeze_time('2022/06/20 00:00:00')
def test_fetch_incidents(mocker):
    from McAfeeMVisionCASB import Client, fetch_incidents

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
