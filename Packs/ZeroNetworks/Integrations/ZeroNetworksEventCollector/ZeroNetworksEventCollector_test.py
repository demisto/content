"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import pytest
from ZeroNetworksEventCollector import Client, process_events, fetch_events


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
        input_events, input_previous_ids, input_last_event_time, max_results, num_results
    )

    assert num_results_ans == expected_num_results
    assert new_events == expected_events
    assert updated_ids == expected_ids
    assert updated_last_event_time == expected_last_event_time


@pytest.mark.parametrize('mock_return_value, inputs, expected_results', [
    (test_case['mock_return_value'], test_case['inputs'], test_case['expected_results'])
    for test_case in util_load_json('test_data/test_fetch_events_params.json')['test_cases']
])
def test_fetch_events(mocker, mock_return_value, inputs, expected_results):
    client = MockClient("", False, False, {})
    mocker.patch.object(client, 'search_events', return_value=mock_return_value)

    new_last_run, new_events = fetch_events(client, inputs[0], inputs[1])
    last_fetch = expected_results[0].get("last_fetch")
    previous_ids = set(expected_results[0].get("previous_ids"))

    assert new_last_run.get("last_fetch") == last_fetch
    assert new_last_run.get("previous_ids") == previous_ids
    assert new_events == expected_results[1]
