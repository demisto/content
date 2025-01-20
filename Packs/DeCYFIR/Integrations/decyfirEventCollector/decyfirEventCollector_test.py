from datetime import datetime, timedelta
import json


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_empty_get_event_format(mocker):
    from decyfirEventCollector import Client
    mock_decyfir_event_response = []
    mock_pa_event_response = []

    client = Client(
        base_url='test_url',
        verify=False,
    )

    data = client.get_event_format(mock_decyfir_event_response, '')
    assert data == mock_pa_event_response


def test_get_event_format(mocker):
    from decyfirEventCollector import Client, VAR_ACCESS_LOGS
    mock_decyfir_event_response = util_load_json('test_data/decyfir_events_data.json')
    mock_pa_event_response = util_load_json('test_data/events_data.json')

    client = Client(
        base_url='test_url',
        verify=False,
    )

    data = client.get_event_format(mock_decyfir_event_response, VAR_ACCESS_LOGS)
    assert data[0] == mock_pa_event_response[0]


def test_get_dr_event_format(mocker):
    from decyfirEventCollector import Client, VAR_DR_KEYWORDS_LOGS
    mock_decyfir_dr_event_response = util_load_json('test_data/decyfir_dr_events_data.json')
    mock_dr_pa_event_response = util_load_json('test_data/dr_events_data.json')
    client = Client(
        base_url='test_url',
        verify=False,
    )
    dr_data = client.get_event_format(mock_decyfir_dr_event_response, VAR_DR_KEYWORDS_LOGS)
    assert dr_data[0] == mock_dr_pa_event_response[0]
    assert dr_data[1] == mock_dr_pa_event_response[1]


def test_fetch_events(mocker):
    from decyfirEventCollector import Client, VAR_ACCESS_LOGS, fetch_events
    mock_decyfir_event_response = util_load_json('test_data/decyfir_events_data.json')
    mock_pa_event_response = util_load_json('test_data/events_data.json')
    date_format = '%Y-%m-%dT%H:%M:%SZ'
    client = Client(
        base_url='test_url',
        verify=False,
    )
    mocker.patch.object(client, 'get_decyfir_event_logs', return_value=mock_decyfir_event_response)
    last_fetch = (datetime.now() - timedelta(days=2)).strftime(date_format)
    last_run = {
        'last_fetch': last_fetch
    }
    last_fetch, events = fetch_events(
        client=client,
        decyfir_api_key='api_key',
        first_fetch='1 days',
        last_run=last_run, max_fetch=1,
    )
    data = client.get_event_format(events, VAR_ACCESS_LOGS)
    assert data[0] == mock_pa_event_response[0]


def test_request_decyfir_api(mocker):
    from decyfirEventCollector import Client
    mock_decyfir_event_response = util_load_json('test_data/decyfir_events_data.json')

    client = Client(
        base_url='test_url',
        verify=False,
    )
    mocker.patch.object(client, 'request_decyfir_events_api', return_value=mock_decyfir_event_response)
    request_params = {
        "key": 'key',
        "size": 1,
    }
    events_resp = client.request_decyfir_events_api(request_params=request_params, event_type='')
    assert events_resp[0] == mock_decyfir_event_response[0]


def test_test_event_logs_command(mocker):
    from decyfirEventCollector import Client, test_event_logs_command
    mock_decyfir_event_response = util_load_json('test_data/decyfir_events_data.json')
    client = Client(
        base_url='test_url',
        verify=False,
    )
    mocker.patch.object(client, 'request_decyfir_events_api', return_value=mock_decyfir_event_response)

    resp = test_event_logs_command(client, '')
    assert resp == 'ok'
