import json
import pytest
from CommonServerPython import DemistoException
import demistomock as demisto  # noqa: F401

BASE_URL = 'https://console.runzero.com/api/v1.0'


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def get_actual_events():
    return [
        {
            'id': '991926c7-2d35-47fb-a146-e587db439c8e',
            'created_at': 1673732462,
            'client_id': 'client_uuid',
            'organization_id': 'organization_uuid',
            'site_id': '00000000-0000-0000-0000-000000000000',
            'action': 'agent-offline',
            'source_id': 'source_uuid',
            'source_name': 'M-source_name_identifier',
            'source_type': 'agent',
            'target_id': 'organization_uuid',
            'target_name': 'target_name',
            'target_type': 'organization',
            'success': True,
            "details": {
                "agent_external_ip": "agent_external_ip",
                "agent_host_id": "7baf78c1a76f179ec1ef93b6c6e5c986",
                "agent_id": "source_uuid",
                "agent_internal_ip": "agent_internal_ip",
                "agent_last_seen": 1673732462,
                "agent_name": "M-source_name_identifier",
                "agent_os": "darwin",
                "agent_tags": "",
                "agent_version": "3.4.16 (build 20230111225731) [d3db1a68496adeccad22e606a2ee947a7e9acc04]",
                "organization_id": "organization_uuid",
                "organization_name": "target_name",
                "site_id": "00000000-0000-0000-0000-000000000000",
                "site_name": ""
            },
            "state": "processed",
            "processor_id": "00000000-0000-0000-0000-000000000000",
            "processed_at": 1673732475,
            '_time': '2023-01-14T21:41:02.000Z',
        },
        {
            "id": "a0d93736-fe84-4948-be43-d862011ab7e2",
            "created_at": 1673738408,
            "client_id": "client_uuid",
            "organization_id": "organization_uuid",
            "site_id": "00000000-0000-0000-0000-000000000000",
            "action": "agent-status",
            "source_id": "source_uuid",
            "source_name": "M-source_name_identifier",
            "source_type": "agent",
            "target_id": "organization_uuid",
            "target_name": "target_name",
            "target_type": "organization",
            "success": True,
            "details": {
                "agent_connected": False,
                "agent_external_ip": "agent_external_ip",
                "agent_host_id": "7baf78c1a76f179ec1ef93b6c6e5c986",
                "agent_id": "source_uuid",
                "agent_internal_ip": "agent_internal_ip",
                "agent_last_seen": 1673732462,
                "agent_name": "M-source_name_identifier",
                "agent_os": "darwin",
                "agent_tags": "",
                "agent_version": "3.4.16 (build 20230111225731) [d3db1a68496adeccad22e606a2ee947a7e9acc04]",
                "organization_id": "organization_uuid",
                "organization_name": "target_name",
                "site_id": "00000000-0000-0000-0000-000000000000",
                "site_name": ""
            },
            "state": "",
            "processor_id": "00000000-0000-0000-0000-000000000000",
            "processed_at": 0,
            '_time': '2023-01-14T23:20:08.000Z',
        }
    ]


def get_client():
    from RunZeroEventCollector import Client
    return Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        client_id='',
        client_secret='',
    )


def test_sort_events_by_ids():
    from RunZeroEventCollector import sort_events
    mock_response = util_load_json('test_data/system_event_logs.json')
    events_sorted = sort_events(mock_response)
    for i in range(1, len(events_sorted)):
        assert events_sorted[i]['created_at'] > events_sorted[i - 1]['created_at']


def test_get_events_command(requests_mock):
    """
    Tests the get-events command function.

        Given:
            - requests_mock instance to generate the appropriate get_alert API response,
              loaded from a local JSON file.

        When:
            - Running the 'get_events_command' command.

        Then:
            - Checks the output of the command function with the expected output.
    """
    from RunZeroEventCollector import get_events_command
    mock_response = util_load_json('test_data/system_event_logs.json')
    requests_mock.post(
        'https://console.runzero.com/api/v1.0/account/api/token',
        json={'access_token': 'access_token'})

    requests_mock.get(
        'https://console.runzero.com/api/v1.0/account/events.json?search=created_at:>1673719953',
        json=mock_response)

    client = get_client()

    events, commandResult = get_events_command(
        client=client,
        query_string='created_at:>1673719953',
        limit=2
    )

    assert events == get_actual_events()


def test_fetch_events(requests_mock):
    """
    Tests the fetch-incidents command function.

        Given:
            - requests_mock instance to generate the appropriate get_alert API response,
              loaded from a local JSON file.

        When:
            - Running the 'fetch_incidents' command.

        Then:
            - Checks the output of the command function with the expected output.
    """
    from RunZeroEventCollector import fetch_events

    mock_response = util_load_json('test_data/system_event_logs.json')

    requests_mock.post(
        'https://console.runzero.com/api/v1.0/account/api/token',
        json={'access_token': 'access_token'})

    requests_mock.get(
        'https://console.runzero.com/api/v1.0/account/events.json?search=created_at:>1673719953',
        json=mock_response)

    client = get_client()

    last_run = {
        'last_fetch': 1673719953
    }

    _, events = fetch_events(
        client=client,
        max_results=2,
        last_run=last_run,
        first_fetch_time=1673719953,
    )

    assert events == get_actual_events()


def test_parse_event():
    from RunZeroEventCollector import add_time_to_event
    my_json = util_load_json('test_data/system_event_logs.json')
    parsed_event = add_time_to_event(my_json[0])
    assert parsed_event == get_actual_events()[0]


def test_fetch_system_event_logs(requests_mock):
    client = get_client()
    expected_res = util_load_json('test_data/system_event_logs.json')[0]
    requests_mock.post(
        'https://console.runzero.com/api/v1.0/account/api/token',
        json={'access_token': 'access_token'})
    requests_mock.get(
        'https://console.runzero.com/api/v1.0/account/events.json',
        json=expected_res)

    actual_response = client.fetch_system_event_logs('search_query')
    assert actual_response == expected_res


def test_get_api_token(requests_mock):
    client = get_client()
    requests_mock.post(
        'https://console.runzero.com/api/v1.0/account/api/token',
        exc=Exception('Forbidden'))

    with pytest.raises(DemistoException) as e:
        client.get_api_token()
    assert e.value.message == 'Authorization Error: make sure API Key is correctly set'


def test_http_request(requests_mock):
    client = get_client()
    expected_res = util_load_json('test_data/system_event_logs.json')[0]
    requests_mock.post(
        'https://console.runzero.com/api/v1.0/account/api/token',
        json={'api_token': 'api_token'})
    requests_mock.get(
        'https://console.runzero.com/api/v1.0/account/events.json',
        json=expected_res)
    actual_response = client.http_request('GET', '/account/events.json', {})
    assert actual_response == expected_res


def test_test_module(requests_mock):
    from RunZeroEventCollector import test_module
    client = get_client()
    expected_res = util_load_json('test_data/system_event_logs.json')

    requests_mock.post(
        'https://console.runzero.com/api/v1.0/account/api/token',
        json={'access_token': 'access_token'})

    requests_mock.get(
        'https://console.runzero.com/api/v1.0/account/events.json',
        json=expected_res)

    raw = test_module(client, 1)
    assert raw == 'ok'


def test_main(mocker):
    """
    Given:
        - All return values from helper functions are valid
    When:
        - main function test-module is executed
    Then:
        - Return ok result to War-Room
    """
    from RunZeroEventCollector import main

    mocker.patch.object(
        demisto, 'params', return_value={
            'client_id': '',
            'url': '',
            'client_secret': {'password': 'test_api'},
        }
    )
    mocker.patch('RunZeroEventCollector.Client.get_api_token', return_value={'access_token': 'access_token'})
    mocker.patch('RunZeroEventCollector.Client.http_request', return_value=util_load_json('test_data/system_event_logs.json'))
    mocker.patch.object(
        demisto, 'command',
        return_value='test-module'
    )
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    assert demisto.results.call_args[0][0] == 'ok'
