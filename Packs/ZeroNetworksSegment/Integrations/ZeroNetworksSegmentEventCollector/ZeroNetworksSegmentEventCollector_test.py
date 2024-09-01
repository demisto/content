
import json
import pytest
from ZeroNetworksSegmentEventCollector import (Client, process_events, initialize_start_timestamp,
                                               get_max_results_and_limit, handle_log_types, update_last_run, fetch_events,
                                               get_events, create_id, fetch_all_events, AUDIT_TYPE, NETWORK_ACTIVITIES_TYPE)
from CommonServerPython import *
import hashlib
import demistomock as demisto  # noqa: F401


class MockClient(Client):
    def __init__(self, server_url: str, proxy: bool, verify: bool, headers: dict):
        pass

    def search_events(self, limit, cursor, log_type, filters=None):
        if cursor <= 123456:
            return {
                'items': [{'id': 1, 'timestamp': 123456}, {'id': 2, 'timestamp': 123457}],
                'scrollCursor': 123457
            }
        elif cursor == 123457:
            return {
                'items': [{'id': 2, 'timestamp': 123457}, {'id': 3, 'timestamp': 12345678}],
                'scrollCursor': 12345678
            }
        elif cursor == 12345678:
            return {
                'items': [{'id': 3, 'timestamp': 12345678}, {'id': 4, 'timestamp': 12345678}],
                'scrollCursor': 12345678
            }
        else:
            return {
                'items': [],
                'scrollCursor': ''
            }


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f)


@pytest.mark.parametrize('inputs, expected_outputs', [
    (test_case['inputs'], test_case['expected_outputs'])
    for test_case in util_load_json('test_data/test_process_events_params.json')['test_cases']
])
def test_process_events(mocker, inputs, expected_outputs):
    def mock_create_id_function(event, log_type):
        return event.get('id')

    mocker.patch('ZeroNetworksSegmentEventCollector.create_id', side_effect=mock_create_id_function)
    input_events, input_previous_ids, input_last_event_time, max_results, num_results = inputs
    expected_events, expected_ids, expected_last_event_time, expected_num_results = expected_outputs

    new_events, updated_ids, updated_last_event_time = process_events(
        input_events, input_previous_ids, input_last_event_time, max_results, num_results, "audit"
    )

    assert new_events == expected_events
    assert updated_ids == expected_ids
    assert updated_last_event_time == expected_last_event_time


def test_initialize_start_timestamp_with_existing_timestamp(mocker):
    last_run = {'audit': {'last_fetch': 1234567890}}
    result = initialize_start_timestamp(last_run, 'audit')
    assert result == 1234567890


def test_initialize_start_timestamp_with_arg_from(mocker):
    arg_from = 111111
    last_run = {'audit': {'last_fetch': 1234567890}}
    result = initialize_start_timestamp(last_run, 'audit', arg_from)
    assert result == 111111


@pytest.mark.parametrize("params, log_type, expected", [
    (test_case["params"], test_case["log_type"], test_case['expected'])
    for test_case in util_load_json('test_data/test_get_max_results_params.json')['test_cases']
])
def test_get_max_results_and_limit_with_param(params, log_type, expected):
    result = get_max_results_and_limit(params, log_type)
    assert result == tuple(expected)


@pytest.mark.parametrize("event_types_to_fetch, expected", [
    (
        ['Audit', 'Network Activities'],
        [AUDIT_TYPE, NETWORK_ACTIVITIES_TYPE]
    ),
    (
        ['Audit'],
        [AUDIT_TYPE]
    ),
    (
        [],
        []
    )
])
def test_handle_log_types(event_types_to_fetch, expected):
    result = handle_log_types(event_types_to_fetch)
    assert result == expected


def test_partial_valid_event_types():
    """Test that partial valid event types raise an exception."""
    event_types = ['fake_type']
    with pytest.raises(DemistoException) as e:
        handle_log_types(event_types)
    assert "Event type title 'fake_type' is not valid." in str(e)


@pytest.mark.parametrize(
    "last_run, log_type, last_event_time, previous_ids, expected",
    [(case['last_run'], case['log_type'], case['last_event_time'],
      case['previous_ids'], case['expected']) for case in util_load_json('test_data/test_update_last_run_params.json')]
)
def test_update_last_run(last_run, log_type, last_event_time, previous_ids, expected):
    last_run_result = update_last_run(last_run, log_type, last_event_time, previous_ids)
    assert last_run_result == expected


@pytest.mark.parametrize(
    "params, last_run, expected_last_run, expected_collected_events, expected_split_logs, start_timestamp",
    [(case['params'], case['last_run'], case['expected_last_run'],
      case['expected_collected_events'], case['expected_split_logs'],
      case['start_timestamp']) for case in util_load_json('test_data/test_fetch_events_params.json')['test_cases']]
)
def test_fetch_events(mocker, params, last_run, expected_last_run, expected_collected_events, expected_split_logs,
                      start_timestamp):
    def mock_create_id_function(event, log_type):
        return event.get('id')

    mocker.patch('ZeroNetworksSegmentEventCollector.create_id', side_effect=mock_create_id_function)
    mocker.patch('ZeroNetworksSegmentEventCollector.initialize_start_timestamp', return_value=start_timestamp)

    mock_client = MockClient('', False, False, {})

    result_last_run, result_collected_events = fetch_events(mock_client, params, last_run, start_timestamp, 'audit', [])

    assert result_last_run == expected_last_run
    assert result_collected_events == expected_collected_events


@pytest.mark.parametrize(
    "args, last_run, expected_events, expected_hr",
    [
        # Basic case without from_date
        (
            {},
            {},
            [{'id': 1, 'timestamp': 123456, 'source_log_type': 'audit'}, {'id': 2, 'timestamp': 123457,
                                                                          'source_log_type': 'audit'}],
            'mocked HR output'
        ),
        # Case with from_date
        (
            {'from_date': '2024-08-25T12:34:56.000Z'},
            {},
            [{'id': 1, 'timestamp': 123456, 'source_log_type': 'audit'}, {'id': 2, 'timestamp': 123457,
                                                                          'source_log_type': 'audit'}],
            'mocked HR output'
        ),
        # Case with no events returned
        (
            {},
            {},
            [],
            'mocked HR output'
        )
    ]
)
def test_get_events(mocker, args, last_run, expected_events, expected_hr):
    mock_fetch_events = mocker.patch('ZeroNetworksSegmentEventCollector.fetch_events')
    mock_fetch_events.return_value = (last_run, expected_events)

    mock_table_to_markdown = mocker.patch('ZeroNetworksSegmentEventCollector.tableToMarkdown')
    mock_table_to_markdown.return_value = expected_hr

    mock_client = MockClient("", False, False, {})

    result_events, _ = get_events(mock_client, args, last_run, params={}, log_types=['audit'])

    assert result_events == expected_events
    if result_events:
        mock_table_to_markdown.assert_called_once_with(name='Audit Events', t=expected_events)


def compute_hash(combined_string):
    hash_object = hashlib.sha256(combined_string.encode())
    return hash_object.hexdigest()


@pytest.mark.parametrize(
    "event, log_type, expected_id",
    [
        # Test case for AUDIT_TYPE with all fields present
        (
            {
                "timestamp": "1234567890",
                "reportedObjectId": "123",
                "performed_by": {"id": "user"}
            },
            AUDIT_TYPE,
            compute_hash("1234567890-123-user")
        ),
        # Test case for AUDIT_TYPE with missing performed_by name
        (
            {
                "timestamp": "1234567890",
                "reportedObjectId": "123",
                "performed_by": {}
            },
            AUDIT_TYPE,
            compute_hash("1234567890-123-")
        ),
        # Test case for NETWORK_ACTIVITIES_TYPE with all fields present
        (
            {
                "timestamp": "0987654321",
                "src": {"assetId": "src-asset"},
                "dst": {"assetId": "dst-asset"}
            },
            NETWORK_ACTIVITIES_TYPE,
            compute_hash("0987654321-src-asset-dst-asset")
        ),
        # Test case for NETWORK_ACTIVITIES_TYPE with missing src or dst assetId
        (
            {
                "timestamp": "0987654321",
                "src": {},
                "dst": {"assetId": "dst-asset"}
            },
            NETWORK_ACTIVITIES_TYPE,
            compute_hash("0987654321--dst-asset")
        ),
        (
            {
                "timestamp": "0987654321",
                "src": {"assetId": "src-asset"},
                "dst": {}
            },
            NETWORK_ACTIVITIES_TYPE,
            compute_hash("0987654321-src-asset-")
        ),
        # Test case with missing timestamp
        (
            {
                "reportedObjectId": "123",
                "performed_by": {"id": "user"}
            },
            AUDIT_TYPE,
            compute_hash("None-123-user")
        ),
        # Test case with empty event
        (
            {},
            AUDIT_TYPE,
            compute_hash("None--")
        )
    ]
)
def test_create_id(event, log_type, expected_id):
    result = create_id(event, log_type)
    assert result == expected_id


def test_fetch_events_limit_logic(mocker):
    mocker.patch('ZeroNetworksSegmentEventCollector.initialize_start_timestamp', return_value=1000)
    mocker.patch('ZeroNetworksSegmentEventCollector.get_max_results_and_limit', return_value=(1, 1))
    mocker.patch('ZeroNetworksSegmentEventCollector.handle_log_types', return_value=['audit'])
    mock_search_events = mocker.patch('ZeroNetworksSegmentEventCollector.Client.search_events',
                                      return_value={'items': [{'id': 1, 'timestamp': 1}], 'scrollCursor': '1'})
    mocker.patch('ZeroNetworksSegmentEventCollector.process_events', return_value=([], {}, 0))

    params = {"network_activity_filters": []}
    last_run = {}
    client = Client("", False, False, {})
    # Call the function
    last_run, all_events = fetch_events(client, params, last_run, 1000, 'audit', [])

    # Check if limit increased as expected
    calls = list(mock_search_events.call_args_list)
    first_call_limit = calls[0][0][0]  # Limit in the first call
    assert first_call_limit == 1

    second_call_limit = calls[1][0][0]  # Limit in the second call
    assert second_call_limit == 2

    assert len(calls) == 2


@pytest.mark.parametrize(
    "last_run, log_types, mock_initialize_start_timestamp, mock_fetch_events_side_effect, expected_last_run, expected_all_events",
    [
        (
            {"last_fetch": "2023-01-01T00:00:00Z"},
            [],
            "2023-01-01T00:00:00Z",
            [],
            {"last_fetch": "2023-01-01T00:00:00Z"},
            []
        ),
        (
            {},
            ["audit", "network_activities"],
            "FAKE_DATE",
            [
                ({"audit": {"last_fetch": "FIRSE_DATE"}}, [{"event_id": 1, "type": "Audit"}]),
                ({"audit": {"last_fetch": "FIRSE_DATE"}, "network_activities": {
                 "last_fetch": "SECOND_DATE"}}, [{"event_id": 2, "type": "network_activities"}])
            ],
            {"audit": {"last_fetch": "FIRSE_DATE"}, "network_activities": {"last_fetch": "SECOND_DATE"}},
            [
                {"event_id": 1, "type": "Audit"},
                {"event_id": 2, "type": "network_activities"}
            ]
        ),
        (
            {"audit": {"last_fetch": "2023-01-01T00:00:00Z"}},
            ["network_activities"],
            "2023-01-01T00:00:00Z",
            [
                ({"audit": {"last_fetch": "2023-01-01T00:00:00Z"},
                 "network_activities": {"last_fetch": "New_fetch_time"}}, [{"event_id": 1, "type": "Audit"}]),
            ],
            {"audit": {"last_fetch": "2023-01-01T00:00:00Z"}, "network_activities": {"last_fetch": "New_fetch_time"}},
            [
                {"event_id": 1, "type": "Audit"},
            ]
        ),
    ]
)
def test_fetch_all_events(mocker, last_run, log_types, mock_initialize_start_timestamp, mock_fetch_events_side_effect,
                          expected_last_run, expected_all_events):
    """Test the fetch_all_events function with mocked dependencies."""
    mocker.patch('ZeroNetworksSegmentEventCollector.initialize_start_timestamp',
                 return_value=mock_initialize_start_timestamp)
    mocker.patch('ZeroNetworksSegmentEventCollector.fetch_events', side_effect=mock_fetch_events_side_effect)

    client = MockClient("", False, False, {})

    result_last_run, result_all_events = fetch_all_events(client, {}, last_run, log_types)

    assert result_last_run == expected_last_run
    assert result_all_events == expected_all_events
