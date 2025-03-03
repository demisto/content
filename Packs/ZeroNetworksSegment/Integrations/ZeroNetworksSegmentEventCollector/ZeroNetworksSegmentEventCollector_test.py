
import json
import pytest
from ZeroNetworksSegmentEventCollector import (Client, process_events, initialize_start_timestamp,
                                               get_max_results_and_limit, handle_log_types, update_last_run, fetch_events,
                                               get_events, create_id, fetch_all_events, AUDIT, NETWORK_ACTIVITIES)
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
    """
    Given:
        - Mocked `create_id` function.
        - Inputs including `input_events`, `input_previous_ids`, `input_last_event_time`, and any other relevant parameters.

    When:
        Calling the process_events function with the provided inputs.

    Then:
        - Verify that `new_events` matches the `expected_events`.
        - Ensure that `updated_ids` matches the `expected_ids`.
        - Confirm that `updated_last_event_time` matches the `expected_last_event_time`.
    """
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


def test_initialize_start_timestamp_with_existing_timestamp():
    """
    Given
            A dictionary with a nested structure and a specific key
    When
            Calling `initialize_start_timestamp` with the dictionary and the key
    Then
            The function should return the value associated with the specified key
            The result is verified to match the expected value
    """
    last_run = {'audit': {'last_fetch': 1234567890}}
    result = initialize_start_timestamp(last_run, 'audit')
    assert result == 1234567890


@pytest.mark.parametrize("params, log_type, expected", [
    (test_case["params"], test_case["log_type"], test_case['expected'])
    for test_case in util_load_json('test_data/test_get_max_results_params.json')['test_cases']
])
def test_get_max_results_and_limit_with_param(params, log_type, expected):
    """
    Given:
        - A set of parameters (params) which include configuration options related to fetching results.
        - A log type (log_type) indicating the type of log data being processed.
        - An expected tuple (expected) representing the maximum number of results and a limit value.

    When:
        Calling the get_max_results_and_limit function with the provided parameters and log type.

    Then:
        Verify that the function returns a tuple matching the expected result, ensuring it correctly processes
        the parameters to determine the maximum results and limit.
    """
    result = get_max_results_and_limit(params, log_type)
    assert result == tuple(expected)


@pytest.mark.parametrize("event_types_to_fetch, expected", [
    (
        ['Audit', 'Network Activities'],
        [AUDIT, NETWORK_ACTIVITIES]
    ),
    (
        ['Audit'],
        [AUDIT]
    ),
    (
        [],
        []
    )
])
def test_handle_log_types(event_types_to_fetch, expected):
    """
    Given:
        - A list or set of event types to fetch (event_types_to_fetch).
        - An expected result (expected) representing the processed event types.

    When:
        Calling the handle_log_types function with the provided event types to fetch.

    Then:
        Verify that the function returns the expected result, confirming that it correctly processes the event types
        as intended.
    """
    result = handle_log_types(event_types_to_fetch)
    assert result == expected


def test_handle_not_valid_log_types():
    """
    Given:
        - An `event_types` list containing invalid event types, such as `['fake_type']`.

    When:
        Calling the `handle_log_types` function with the provided `event_types` list.

    Then:
        - Verify that `handle_log_types` raises a `DemistoException`.
        - Ensure that the exception message includes "Event type title 'fake_type' is not valid."
    """
    event_types = ['fake_type']
    with pytest.raises(DemistoException) as e:
        handle_log_types(event_types)
    assert "'fake_type' is not valid event type, please select from the following list:" in str(e)


@pytest.mark.parametrize(
    "last_run, log_type, last_event_time, previous_ids, expected",
    [(case['last_run'], case['log_type'], case['last_event_time'],
      case['previous_ids'], case['expected']) for case in util_load_json('test_data/test_update_last_run_params.json')]
)
def test_update_last_run(last_run, log_type, last_event_time, previous_ids, expected):
    """
    Given:
        - Initial input values (`last_run`, `log_type`, `last_event_time`, `previous_ids`).
        - An expected result after processing.

    When:
        Calling the `update_last_run` function with the given inputs.

    Then:
        Verify that the function returns the expected result, ensuring it processes the inputs correctly.
    """
    last_run_result = update_last_run(last_run, log_type, last_event_time, previous_ids)
    assert last_run_result == expected


@pytest.mark.parametrize(
    "max_results, limit, last_run, expected_last_run, expected_collected_events, start_timestamp",
    [(case['max_results'], case['limit'], case['last_run'], case['expected_last_run'],
      case['expected_collected_events'], case['start_timestamp'])
     for case in util_load_json('test_data/test_fetch_events_params.json')['test_cases']]
)
def test_fetch_events(mocker, max_results, limit, last_run, expected_last_run,
                      expected_collected_events, start_timestamp):
    """
    Given:
        - A mock setup for dependencies (`mocker`, `mock_create_id_function`, `MockClient`).
        - Input parameters for the `fetch_events` function (`params`, `last_run`, `start_timestamp`).
        - Expected results after fetching events (`expected_last_run`, `expected_collected_events`).

    When:
        Calling the `fetch_events` function with the mocked client and provided inputs.

    Then:
        Verify that the function returns the expected `last_run` and `collected_events`, ensuring it processes the inputs
        correctly and integrates with the mocks as intended.
    """
    def mock_create_id_function(event, log_type):
        return event.get('id')

    mocker.patch('ZeroNetworksSegmentEventCollector.create_id', side_effect=mock_create_id_function)
    mocker.patch('ZeroNetworksSegmentEventCollector.initialize_start_timestamp', return_value=start_timestamp)

    mock_client = MockClient('', False, False, {})

    result_last_run, result_collected_events = fetch_events(mock_client, last_run, start_timestamp, 'audit', [],
                                                            max_results, limit)

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
    """
    Given:
        - A mock setup for dependencies (`mocker`, `mock_fetch_events`, `mock_table_to_markdown`).
        - Input arguments for the `get_events` function (`args`, `last_run`, `params`, `log_types`).
        - Expected results for events and human-readable output (`expected_events`, `expected_hr`).

    When:
        Calling the `get_events` function with the mocked client and provided inputs.

    Then:
        Verify that the function returns the expected events and performs the correct integration with the mocks:
        - Ensure the returned events match `expected_events`.
        - Confirm that `tableToMarkdown` was called once with the correct parameters if events are present.
    """
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
        # Test case for AUDIT with all fields present
        (
            {
                "timestamp": "1234567890",
                "reportedObjectId": "123",
                "performedBy": {"id": "user"}
            },
            AUDIT,
            compute_hash("1234567890-123-user")
        ),
        # Test case for AUDIT with missing performedBy name
        (
            {
                "timestamp": "1234567890",
                "reportedObjectId": "123",
                "performedBy": {}
            },
            AUDIT,
            compute_hash("1234567890-123-")
        ),
        # Test case for NETWORK_ACTIVITIES with all fields present
        (
            {
                "timestamp": "0987654321",
                "src": {"assetId": "src-asset"},
                "dst": {"assetId": "dst-asset"}
            },
            NETWORK_ACTIVITIES,
            compute_hash("0987654321-src-asset-dst-asset")
        ),
        # Test case for NETWORK_ACTIVITIES with missing src or dst assetId
        (
            {
                "timestamp": "0987654321",
                "src": {},
                "dst": {"assetId": "dst-asset"}
            },
            NETWORK_ACTIVITIES,
            compute_hash("0987654321--dst-asset")
        ),
        (
            {
                "timestamp": "0987654321",
                "src": {"assetId": "src-asset"},
                "dst": {}
            },
            NETWORK_ACTIVITIES,
            compute_hash("0987654321-src-asset-")
        ),
        # Test case with missing timestamp
        (
            {
                "reportedObjectId": "123",
                "performedBy": {"id": "user"}
            },
            AUDIT,
            compute_hash("None-123-user")
        ),
        # Test case with empty event
        (
            {},
            AUDIT,
            compute_hash("None--")
        )
    ]
)
def test_create_id(event, log_type, expected_id):
    """
    Given:
        - An `event` and a `log_type` used to generate an ID.
        - An `expected_id` that represents the anticipated result.

    When:
        Calling the `create_id` function with the provided `event` and `log_type`.

    Then:
        Verify that the function returns the expected ID, ensuring it generates the ID correctly based on the inputs.
    """
    result = create_id(event, log_type)
    assert result == expected_id


def test_fetch_events_limit_logic(mocker):
    """
    Given:
        - Mocked functions such as `initialize_start_timestamp`, `get_max_results_and_limit`, and others.
        - Specific parameters and inputs required by `fetch_events`.

    When:
        Calling the `fetch_events` function with these parameters and a limit value.

    Then:
        - Verify that the limit values in the calls to `mock_search_events` increase as expected.
        - Ensure that the number of calls to `mock_search_events` matches the expected count.
    """
    mocker.patch('ZeroNetworksSegmentEventCollector.initialize_start_timestamp', return_value=1000)
    mocker.patch('ZeroNetworksSegmentEventCollector.handle_log_types', return_value=['audit'])
    mock_search_events = mocker.patch('ZeroNetworksSegmentEventCollector.Client.search_events',
                                      return_value={'items': [{'id': 1, 'timestamp': 1}], 'scrollCursor': '1'})
    mocker.patch('ZeroNetworksSegmentEventCollector.process_events', return_value=([], {}, 0))

    max_results, limit = (1, 1)
    last_run = {}
    client = Client("", False, False, {})

    fetch_events(client, last_run, 1000, 'audit', [], max_results, limit)

    calls = list(mock_search_events.call_args_list)
    first_call_limit = calls[0][0][0]  # Limit in the first call
    assert first_call_limit == 1

    second_call_limit = calls[1][0][0]  # Limit in the second call
    assert second_call_limit == 2

    assert len(calls) == 2


@pytest.mark.parametrize(
    "last_run, log_types, mock_initialize_start_timestamp, mock_fetch_events_side_effect, expected_last_run, expected_all_events",
    [(case["last_run"], case["log_types"], case["mock_initialize_start_timestamp"],
      case["mock_fetch_events_side_effect"], case["expected_last_run"],
      case["expected_all_events"]) for case in util_load_json('test_data/test_fetch_all_events_params.json')['test_cases']]
)
def test_fetch_all_events(mocker, last_run, log_types, mock_initialize_start_timestamp, mock_fetch_events_side_effect,
                          expected_last_run, expected_all_events):
    """
    Given:
        - A mock setup for dependencies (`mocker`, `mock_initialize_start_timestamp`, `mock_fetch_events_side_effect`).
        - Initial state (`last_run`) and a list of `log_types`.
        - Expected results for the last run and all events after fetching (`expected_last_run`, `expected_all_events`).

    When:
        Calling the `fetch_all_events` function with the mocked client, initial state, and log types.

    Then:
        Verify that the function returns the expected `last_run` and `all_events`, ensuring it correctly integrates with the mocks
        and processes the inputs as intended.
    """
    mocker.patch('ZeroNetworksSegmentEventCollector.initialize_start_timestamp', return_value=mock_initialize_start_timestamp)
    mocker.patch('ZeroNetworksSegmentEventCollector.fetch_events', side_effect=mock_fetch_events_side_effect)

    client = MockClient("", False, False, {})

    result_last_run, result_all_events = fetch_all_events(client, {}, last_run, log_types)

    assert result_last_run == expected_last_run
    assert result_all_events == expected_all_events
