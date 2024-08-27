"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import pytest
from ZeroNetworksSegmentEventCollector import (Client, process_events, prepare_filters, initialize_start_timestamp,
                                               get_max_results_and_limit, get_log_types, update_last_run, fetch_events,
                                               get_events, create_id, AUDIT_TYPE, NETWORK_ACTIVITIES_TYPE)
from CommonServerPython import *
import hashlib


class MockClient(Client):
    def __init__(self, server_url: str, proxy: bool, verify: bool, headers: dict):
        pass

    def search_events(self, limit, cursor, log_type, filters=None):
        if cursor == 1000:
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

    input_previous_ids = set(input_previous_ids)
    expected_ids = set(expected_ids)

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


def test_prepare_filters_with_filters():
    params = {"network_activity_filters": '[{"id":"srcRiskLevel","includeValues":["1"]}]'}
    result = prepare_filters(params)

    assert result == '%5B%7B"id"%3A"srcRiskLevel"%2C"includeValues"%3A%5B"1"%5D%7D%5D'


@pytest.mark.parametrize("params, expected", [
    (
        {"isFetchNetwork": True},
        [AUDIT_TYPE, NETWORK_ACTIVITIES_TYPE]
    ),
    (
        {"isFetchNetwork": False},
        [AUDIT_TYPE]
    )
])
def test_get_log_types(params, expected):
    result = get_log_types(params)
    assert result == expected


@pytest.mark.parametrize("last_run, log_type, last_event_time, previous_ids, expected", [
    (
        {},
        'audit',
        1000,
        {1, 2, 3},
        {
            'audit': {
                'last_fetch': 1000,
                'previous_ids': {1, 2, 3}
            }
        }
    ),
    (
        {
            'audit': {
                'last_fetch': 900,
                'previous_ids': {1}
            }
        },
        'audit',
        1000,
        {1, 2, 3},
        {
            'audit': {
                'last_fetch': 1000,
                'previous_ids': {1, 2, 3}
            }
        }
    ),
    (
        {
            'network_activities': {
                'last_fetch': 2000,
                'previous_ids': {2, 3}
            }
        },
        'audit',
        1000,
        {1, 2, 3},
        {
            'audit': {
                'last_fetch': 1000,
                'previous_ids': {1, 2, 3}
            },
            'network_activities': {
                'last_fetch': 2000,
                'previous_ids': {2, 3}
            }
        }
    )
])
def test_update_last_run(last_run, log_type, last_event_time, previous_ids, expected):
    last_run_result = update_last_run(last_run, log_type, last_event_time, previous_ids)
    assert last_run_result == expected


@pytest.mark.parametrize(
    "params, last_run, arg_from, expected_last_run, expected_collected_events",
    [
        # Basic scenario with a few events
        (
            {'max_fetch_audit': '2'},
            {},
            None,
            {
                'audit': {'last_fetch': 123457, 'previous_ids': {2}}
            },
            [{'id': 1, 'timestamp': 123456, '_TIME': '1970-01-01T00:02:03.000Z', 'source_log_type': 'audit'},
             {'id': 2, 'timestamp': 123457, '_TIME': '1970-01-01T00:02:03.000Z', 'source_log_type': 'audit'}]
        ),
        # Case with more events than max_fetch
        (
            {'max_fetch_audit': '3'},
            {},
            None,
            {
                'audit': {'last_fetch': 12345678, 'previous_ids': {3}}
            },
            [{'id': 1, 'timestamp': 123456, '_TIME': '1970-01-01T00:02:03.000Z', 'source_log_type': 'audit'},
             {'id': 2, 'timestamp': 123457, '_TIME': '1970-01-01T00:02:03.000Z', 'source_log_type': 'audit'},
             {'id': 3, 'timestamp': 12345678, '_TIME': '1970-01-01T03:25:45.000Z', 'source_log_type': 'audit'}]
        ),
        # Case with events number equals to max_fetch
        (
            {'max_fetch_audit': '4'},
            {},
            None,
            {
                'audit': {'last_fetch': 12345678, 'previous_ids': {3, 4}}
            },
            [{'id': 1, 'timestamp': 123456, '_TIME': '1970-01-01T00:02:03.000Z', 'source_log_type': 'audit'},
             {'id': 2, 'timestamp': 123457, '_TIME': '1970-01-01T00:02:03.000Z', 'source_log_type': 'audit'},
             {'id': 3, 'timestamp': 12345678, '_TIME': '1970-01-01T03:25:45.000Z', 'source_log_type': 'audit'},
             {'id': 4, 'timestamp': 12345678, '_TIME': '1970-01-01T03:25:45.000Z', 'source_log_type': 'audit'}]
        ),
        # Case with existing last_run and provided from_date
        (
            {'max_fetch_audit': '3'},
            {'audit': {'last_fetch': 123456, 'previous_ids': {1}}},
            '2024-08-25T12:34:56.000Z',
            {
                'audit': {'last_fetch': 12345678, 'previous_ids': {3, 4}}
            },
            [{'id': 2, 'timestamp': 123457, '_TIME': '1970-01-01T00:02:03.000Z', 'source_log_type': 'audit'},
             {'id': 3, 'timestamp': 12345678, '_TIME': '1970-01-01T03:25:45.000Z', 'source_log_type': 'audit'},
             {'id': 4, 'timestamp': 12345678, '_TIME': '1970-01-01T03:25:45.000Z', 'source_log_type': 'audit'}]
        ),
        # Case with existing last_run and provided from_date
        (
            {'max_fetch_audit': '3'},
            {'audit': {'last_fetch': 12345678, 'previous_ids': {3}}},
            '2024-08-25T12:34:56.000Z',
            {
                'audit': {'last_fetch': 12345678, 'previous_ids': {3, 4}}
            },
            [{'id': 4, 'timestamp': 12345678, '_TIME': '1970-01-01T03:25:45.000Z', 'source_log_type': 'audit'}]
        )
    ]
)
def test_fetch_events(mocker, params, last_run, arg_from, expected_last_run, expected_collected_events):
    def mock_create_id_function(event, log_type):
        return event.get('id')

    mocker.patch('ZeroNetworksSegmentEventCollector.create_id', side_effect=mock_create_id_function)
    if not last_run or last_run == {'audit': {'last_fetch': 123456, 'previous_ids': {1}}}:
        mocker.patch('ZeroNetworksSegmentEventCollector.initialize_start_timestamp', return_value=1000)
    else:
        mocker.patch('ZeroNetworksSegmentEventCollector.initialize_start_timestamp', return_value=12345678)

    mocker.patch('ZeroNetworksSegmentEventCollector.prepare_filters')
    mock_client = MockClient('', False, False, {})

    result_last_run, result_collected_events = fetch_events(mock_client, params, last_run, arg_from)

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
    # Mock fetch_events
    mock_fetch_events = mocker.patch('ZeroNetworksSegmentEventCollector.fetch_events')
    mock_fetch_events.return_value = (last_run, expected_events)

    # Mock tableToMarkdown
    mock_table_to_markdown = mocker.patch('ZeroNetworksSegmentEventCollector.tableToMarkdown')
    mock_table_to_markdown.return_value = expected_hr

    # Create a mock client instance
    mock_client = MockClient("", False, False, {})

    # Call the function
    result_events, _ = get_events(mock_client, args, last_run)

    # Assertions
    assert result_events == expected_events
    mock_table_to_markdown.assert_called_once_with(name='Events', t=expected_events)


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
