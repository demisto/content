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
                                        get_max_results_and_limit, get_log_types, update_last_run,
                                        AUDIT_TYPE, NETWORK_ACTIVITIES_TYPE)
from CommonServerPython import *


class MockClient(Client):
    def __init__(self, server_url: str, proxy: bool, verify: bool, headers: dict):
        pass

    def search_command(self, limit, cursor) -> None:
        return


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f)


@pytest.mark.parametrize('inputs, expected_outputs', [
    (test_case['inputs'], test_case['expected_outputs'])
    for test_case in util_load_json('test_data/test_process_events_params.json')['test_cases']
])
def test_process_events(inputs, expected_outputs):
    input_events, input_previous_ids, input_last_event_time, max_results, num_results = inputs
    expected_events, expected_ids, expected_last_event_time, expected_num_results = expected_outputs

    input_previous_ids = set(input_previous_ids)
    expected_ids = set(expected_ids)

    new_events, updated_ids, updated_last_event_time, num_results_ans = process_events(
        input_events, input_previous_ids, input_last_event_time, max_results, num_results, "audit"
    )

    assert num_results_ans == expected_num_results
    assert new_events == expected_events
    assert updated_ids == expected_ids
    assert updated_last_event_time == expected_last_event_time


def test_initialize_start_timestamp_with_existing_timestamp(mocker):
    mock_date_to_timestamp = mocker.patch("CommonServerPython.date_to_timestamp")
    last_run = {'type1': {'last_fetch': 1234567890}}
    result = initialize_start_timestamp(last_run, 'type1')
    assert result == 1234567890
    mock_date_to_timestamp.assert_not_called()


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
