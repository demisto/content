import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
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
    from RunZeroEventCollector import Client, get_events_command
    mock_response = util_load_json('test_data/system_event_logs.json')
    requests_mock.post(
        'https://console.runzero.com/api/v1.0/account/api/token',
        json={'access_token': 'access_token'})

    requests_mock.get(
        'https://console.runzero.com/api/v1.0/account/events.json?search=created_at:>1673719953',
        json=mock_response)

    client = Client(
        base_url='https://console.runzero.com/api/v1.0',
        verify=False,
        proxy=False,
        data={}
    )

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
    from RunZeroEventCollector import Client, fetch_events

    mock_response = util_load_json('test_data/system_event_logs.json')
    
    requests_mock.post(
        'https://console.runzero.com/api/v1.0/account/api/token',
        json={'access_token': 'access_token'})
    
    requests_mock.get(
        'https://console.runzero.com/api/v1.0/account/events.json?search=created_at:>1673719953',
        json=mock_response)

    client = Client(
        base_url='https://console.runzero.com/api/v1.0',
        verify=False,
        proxy=False,
        data={}
    )

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
