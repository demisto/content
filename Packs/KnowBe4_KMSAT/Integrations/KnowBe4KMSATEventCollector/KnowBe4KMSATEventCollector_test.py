import datetime
import pytest
import json
import io
from KnowBe4KMSATEventCollector import Client
from CommonServerPython import DemistoException


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

# def test_fetch_events(requests_mock):
#     """
#     Given:
#         - fetch-events call
#     When:
#         - Calling fetch events:
#                 1. without marking, but with first_fetch
#                 2. only marking from last_run
#     Then:
#         - Make sure 3 events returned.
#         - Verify the new lastRun is calculated correctly.
#     """
#     from KnowBe4KMSATEventCollector import fetch_events

#     last_run = {'page': '0'}
#     requests_mock.get(
#         f'{BASE_URL}/logs',
#         json=MOCK_ENTRY
#     )

#     events, new_last_run = fetch_events(Client(base_url=BASE_URL), last_run=last_run,
#                                         first_fetch_time=datetime.strptime("2020-01-01", "%Y-%m-%d"), max_fetch=2000)
#     assert len(events) == 3
#     assert events[0].get('id') == "786a515c-1cbd-4a8c-a94a-61ad877c893c"
#     assert new_last_run['page'] == 2


@pytest.mark.parametrize('last_run, fetched_events, expected_filtered_list_size, expected_filtered_list_elements', [
    ({'latest_event_time': datetime.datetime(2022, 5, 17, 10, 5, 3)},
     [{'occurred_date': datetime.datetime(2022, 6, 17, 12, 3, 1)}], 1,
     [{'occurred_date': datetime.datetime(2022, 6, 17, 12, 3, 1)}]),
    ({'latest_event_time': datetime.datetime(2022, 5, 17, 10, 5, 3)},
     [{'occurred_date': datetime.datetime(2022, 4, 17, 12, 3, 1)}], 0,
     []), ({'latest_event_time': datetime.datetime(2022, 5, 17, 10, 5, 3)},
           [{'occurred_date': datetime.datetime(2022, 6, 17, 12, 3, 1)},
            {'occurred_date': datetime.datetime(2022, 4, 17, 12, 3, 1)}], 1,
           [{'occurred_date': datetime.datetime(2022, 6, 17, 12, 3, 1)}]),
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
     [{'occurred_date': datetime.datetime(2022, 6, 17, 12, 3, 1)}], False),
    ({'latest_event_time': datetime.datetime(2022, 5, 17, 10, 5, 3)},
     [{'occurred_date': datetime.datetime(2022, 5, 16, 9, 3, 1)}], True)])
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


@pytest.mark.parametrize('limit', [126, 1, 101, 235, -1, -100])
def test_validate_limit(limit):
    """
    Given
    - a limit parameter which is not divisible by 100/negative limit.

    When
    - executing the validate limit

    Then
    - make sure an exception is raised
    """
    from KnowBe4KMSATEventCollector import validate_limit

    with pytest.raises(DemistoException):
        validate_limit(limit)
