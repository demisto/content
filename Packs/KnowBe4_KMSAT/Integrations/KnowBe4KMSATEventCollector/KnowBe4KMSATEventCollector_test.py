import datetime
import pytest
import json
import io
from CommonServerPython import parse_date_string
from KnowBe4KMSATEventCollector import Client


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


MOCK_ENTRY = util_load_json('test_data/mock_event.json')
BASE_URL = 'https://api.events.knowbe4.com'


def test_test_module(requests_mock):
    """
    Given:
        - test-module call
    When:
        - A response with an OK status_code is retrieved from the API call.
    Then:
        - Make sure 'ok' is returned.
    """
    from KnowBe4KMSATEventCollector import test_module

    requests_mock.get(
        f'{BASE_URL}/events',
        json=MOCK_ENTRY
    )
    assert test_module(Client(base_url=BASE_URL)) == 'ok'


@pytest.mark.parametrize('last_run, mock_item, expected_last_run, expected_fetched_events', [
    ({'latest_event_time': "2022-08-05T10:05:03.000Z"}, MOCK_ENTRY,
     {'latest_event_time': "2022-08-09T10:05:13.890Z"}, MOCK_ENTRY.get('data', [])[0:-1]),
    ({'latest_event_time': parse_date_string("2022-08-05T10:05:03.000Z")}, MOCK_ENTRY,
     {'latest_event_time': "2022-08-09T10:05:13.890Z"}, MOCK_ENTRY.get('data', [])[0:-1])])
def test_fetch_events(requests_mock, last_run, mock_item, expected_last_run, expected_fetched_events):
    """
    Given:
        - last_run marker and a mock with 2 events that occurred after the last run and 1 that occurred before.
        - case 1: The last run object is a string (an example of last run that was fetched from previous interval).
        - case 2: The last run object is a datetime object (an example of last run that was created by a default datetime.now()
                  in the previous interval due to no fetched events).
    When:
        - Calling fetch events.
    Then:
        - Make sure 2 events returned.
        - Verify the new lastRun is calculated correctly.
        - Verify that the function handle the different last_run types correctly.
    """
    from KnowBe4KMSATEventCollector import fetch_events

    requests_mock.get(
        f'{BASE_URL}/events',
        json=mock_item
    )
    events, new_last_run = fetch_events(Client(base_url=BASE_URL), last_run=last_run)
    expected_last_run == new_last_run
    assert events == expected_fetched_events
    assert len(events) == len(expected_fetched_events)


@pytest.mark.parametrize('last_run, fetched_events, expected_filtered_list_size, expected_filtered_list_elements', [
    ({'latest_event_time': datetime.datetime(2022, 5, 17, 10, 5, 3)},
     [{'occurred_date': "2022-08-09T10:05:13.890Z"}], 1, [{'occurred_date': "2022-08-09T10:05:13.890Z"}]),
    ({'latest_event_time': datetime.datetime(2022, 5, 17, 10, 5, 3)},
     [{'occurred_date': "2022-03-09T10:05:13.890Z"}], 0, []),
    ({'latest_event_time': datetime.datetime(2022, 5, 17, 10, 5, 3)}, [{'occurred_date': "2022-08-09T10:05:13.890Z"},
     {'occurred_date': "2022-03-09T10:05:13.890Z"}], 1, [{'occurred_date': "2022-08-09T10:05:13.890Z"}]),
])
def test_eliminate_duplicated_events(last_run, fetched_events, expected_filtered_list_size, expected_filtered_list_elements):
    """
    Given
    - A list of fetched events and a last_run date
    - Case 1: last_run object and a list with 1 event that occurred after the last_run.
    - Case 2: last_run object and a list with 1 event that occurred before the last_run.
    - Case 3: last_run object and a list with 1 event that occurred after the last_run and 1 event that occurred before it.

    When
    - Running eliminate_duplicated_events helper function.

    Then
    - Validate that all the events with the earlier than last_run 'occurred_date' are filtered out.
    - Case 1: Ensure that the event wasn't filtered out of the events list.
    - Case 2: Ensure that the event was filtered out of the events list.
    - Case 3: Ensure that the event that occurred after that last run wasn't filtered out of the events list
              and that the event that occurred before the last run was filtered.
    """
    from KnowBe4KMSATEventCollector import eliminate_duplicated_events
    filtered_events_list = eliminate_duplicated_events(fetched_events, last_run)
    assert len(filtered_events_list) == expected_filtered_list_size
    for event in filtered_events_list:
        assert event in expected_filtered_list_elements


@pytest.mark.parametrize('last_run, events, expected_results', [
    ({'latest_event_time': datetime.datetime(2022, 5, 17, 10, 5, 3)},
     [{'occurred_date': "2022-08-09T10:05:13.890Z"}], False),
    ({'latest_event_time': datetime.datetime(2022, 5, 17, 10, 5, 3)},
     [{'occurred_date': "2022-03-09T10:05:13.890Z"}], True)])
def test_check_if_last_run_reached(last_run, events, expected_results):
    """
    Given
    - A list of fetched events and a last_run date.
    - Case 1: latest event that occurred before the first event in the events list.
    - Case 2: latest event that occurred after the first event in the events list.

    When
    - Running check_if_last_run_reached helper function.

    Then
    - Validate that the answer returend from the function is correct.
    - Case 1: Ensure that the function returned False.
    - Case 2: Ensure that the function returend True.
    """
    from KnowBe4KMSATEventCollector import check_if_last_run_reached
    assert check_if_last_run_reached(last_run, events[0]) == expected_results


@pytest.mark.parametrize('mock_item, expected_results, expected_length', [
    (MOCK_ENTRY, MOCK_ENTRY.get('data', []), 3),
    ({}, 'No events were found.', 21)])
def test_get_events(requests_mock, mock_item, expected_results, expected_length):
    """
    Given:
        - a mock response.
        - Case 1: A mock response with 3 events.
        - Case 2: Empty mock response.
    When:
        - Running the kms-get-events command.
    Then:
        - Make sure all of the events are returned as part of the CommandResult.
        - Case 1: Ensure the same 3 events were found.
        - Case 2: Should print that no events we found.
    """
    from KnowBe4KMSATEventCollector import get_events_command

    requests_mock.get(
        f'{BASE_URL}/events',
        json=mock_item
    )
    args = {
        'should_push_events': False
    }

    results = get_events_command(Client(base_url=BASE_URL), args=args, vendor='', product='')

    if mock_item:
        assert results.outputs == expected_results
        assert len(results.outputs) == expected_length
    else:
        assert results.readable_output == expected_results
        assert len(results.readable_output) == expected_length
