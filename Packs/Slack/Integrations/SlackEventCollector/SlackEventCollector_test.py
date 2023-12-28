import json
import pytest

from copy import deepcopy
from SlackEventCollector import Client, prepare_query_params
from requests import Session

""" Helpers """


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


MOCK_ENTRY = util_load_json('test_data/mock_event.json')


class MockResponse:
    def __init__(self, data: list):
        self.ok = True
        self.status_code = 200
        self.data = {'entries': [self.create_mock_entry(**e) for e in data]}

    def create_mock_entry(self, **kwargs) -> dict:
        return deepcopy(MOCK_ENTRY) | kwargs

    def json(self):
        return self.data

    def raise_for_status(self):
        pass


""" Test methods """


@pytest.mark.parametrize('params, expected_params', [
    ({'limit': '1'}, {'limit': 1}),
    ({'oldest': '1643806800'}, {'limit': 1000, 'oldest': 1643806800}),
    ({'latest': '02/02/2022 15:00:00'}, {'limit': 1000, 'latest': 1643814000}),
    ({'action': 'user_login'}, {'limit': 1000, 'action': 'user_login'}),
])
def test_slack_events_params_good(params, expected_params):
    """
    Given:
        - Various dictionary values.
    When:
        - preparing the parameters.
    Then:
        - Make sure they are parsed correctly.
    """
    assert expected_params.items() <= prepare_query_params(params).items()


@pytest.mark.parametrize('params', [
    {'limit': 'hello'},
    {'oldest': 'hello'},
    {'latest': 'hello'}
])
def test_slack_events_params_bad(params):
    """
    Given:
        - Various dictionary values.
    When:
        - Parsing them as a SlackEventsParams object.
    Then:
        - Make sure a ValueError exception is raised.
    """
    with pytest.raises(ValueError):
        prepare_query_params(params)


def test_fetch_events_with_two_iterations(mocker):
    """
    Given:
        - fetch-events command execution.
    When:
        - Limit parameter value is 300.
        - A single /logs API call retrieves 200 events.
    Then:
        - Make sure the logs API is called twice.
    """
    from SlackEventCollector import fetch_events_command

    last_run = {}

    mock_response = MockResponse([{'id': '1', 'date_create': 1521214343}] * 200)
    mock_response.data['response_metadata'] = {'next_cursor': 'mock_cursor'}
    mock_request = mocker.patch.object(Session, 'request', return_value=mock_response)
    fetch_events_command(Client(base_url=''), params={'limit': '300'}, last_run=last_run)
    assert mock_request.call_count == 2


def test_get_events(mocker):
    """
    Given:
        - slack-get-events call
    When:
        - Three following results are retrieved from the API:
            1. id = 1, date_create = 1521214343
            2. id = 2, date_create = 1521214343
            3. id = 3, date_create = 1521214345
    Then:
        - Make sure all of the events are returned as part of the CommandResult.
    """
    from SlackEventCollector import get_events_command

    mock_response = MockResponse([
        {'id': '3', 'date_create': 1521214345},
        {'id': '2', 'date_create': 1521214343},
        {'id': '1', 'date_create': 1521214343},
    ])
    mocker.patch.object(Session, 'request', return_value=mock_response)
    _, results = get_events_command(Client(base_url=''), args={})

    assert len(results.raw_response.get('entries', [])) == 3
    assert results.raw_response == mock_response.json()


def test_test_module(mocker):
    """
    Given:
        - test-module call
    When:
        - A response with an OK status_code is retrieved from the API call.
    Then:
        - Make sure 'ok' is returned.
    """
    from SlackEventCollector import test_module_command

    mocker.patch.object(Session, 'request', return_value=MockResponse([]))
    assert test_module_command(Client(base_url=''), {}) == 'ok'


def test_fetch_events_(mocker):
    """
    Given:
        - fetch-events command execution.
    When:
        - The first call to the "fetch_events_command": the last run is empty, and there are 6 results (in 2 pages)
           assert we returned 4 events according to the limit, and returned the "last_search_stop_point_event_id", "cursor",
           and newest_event_fetched.
        - Second call to "fetch_events_command": last run has a 'cursor' and API returned a response with 3 events
          (that were already fetched)
            assert we return only 2 events (the remaining from the first round) and the last run contains only the
            "last_fetched_event".
        - Third, call "fetch_events_command" we got an empty response.
            assert the last run stayed the same.
        - The fourth call "fetch_events_command" was in the "last run" the "last_fetched_event", There were 6 results (in 2 pages)
           assert we returned 4 events according to the limit,
           and returned the "last_fetched_event" "last_search_stop_point_event_id", "cursor", and newest_event_fetched.
    """
    from SlackEventCollector import fetch_events_command, Client

    # first round
    mock_response1 = MockResponse([
        {'id': '6', 'date_create': 6},
        {'id': '5', 'date_create': 5},
        {'id': '4', 'date_create': 4},
    ])
    mock_response1.data['response_metadata'] = {'next_cursor': 'mock_response2'}
    mock_response2 = MockResponse([
        {'id': '3', 'date_create': 3},
        {'id': '2', 'date_create': 2},
        {'id': '1', 'date_create': 1},
    ])
    mocker.patch.object(Client, '_http_request', side_effect=[mock_response1.data,
                                                              mock_response2.data])
    events, last_run = fetch_events_command(Client(base_url=''), params={'limit': 4}, last_run={})
    assert len(events) == 4  # 4 events according to the limit
    assert last_run == {'cursor': 'mock_response2',  # The cursor was returned because we still haven't finished
                                                     # fetching the events from the mock_response2.
                        'last_search_stop_point_event_id': '2',  # the id where to start collect next run.
                        'newest_event_fetched': {'last_event_id': '6', 'last_event_time': 6}}
    # the next nowest event thet we fetchd alredy. This is just the next one because we haven't
    # finished bringing all the previous events yet

    # Second round
    mocker.patch.object(Client, '_http_request', side_effect=[mock_response2.data])
    events, last_run = fetch_events_command(Client(base_url=''), params={'limit': 4}, last_run=last_run)
    assert len(events) == 2  # 2 events that remains
    assert last_run == {'last_fetched_event': {'last_event_id': '6', 'last_event_time': 6}}  # the last fetched event

    # Third round
    mocker.patch.object(Client, '_http_request', return_value={})
    events, last_run = fetch_events_command(Client(base_url=''), params={'limit': 4}, last_run=last_run)
    assert len(events) == 0  # 0 events because an empty response
    assert last_run == {'last_fetched_event': {'last_event_id': '6', 'last_event_time': 6}}  # the last run didn't change

    # fourth round
    mock_response3 = MockResponse([
        {'id': '11', 'date_create': 11},
        {'id': '10', 'date_create': 10},
        {'id': '9', 'date_create': 9},
    ])
    mock_response3.data['response_metadata'] = {'next_cursor': 'mock_response4'}

    mock_response4 = MockResponse([
        {'id': '8', 'date_create': 8},
        {'id': '7', 'date_create': 7},
        {'id': '6', 'date_create': 6},
    ])
    mocker.patch.object(Client, '_http_request', side_effect=[mock_response3.data, mock_response4.data])
    events, last_run = fetch_events_command(Client(base_url=''), params={'limit': 4}, last_run=last_run)
    assert len(events) == 4  # 4 events according to the limit
    assert last_run == {'cursor': 'mock_response4',  # The cursor was returned because we still haven't finished
                                                     # fetching the events from the mock_response4.
                        'last_fetched_event': {'last_event_id': '6', 'last_event_time': 6},  # The last event we collected
                                                                                             # (in the previous search)
                        'last_search_stop_point_event_id': '7',  # the id where to start (downwards) collect next run.
                        'newest_event_fetched': {'last_event_id': '11', 'last_event_time': 11}}  # The last event we collected
    # (in this search)
    mocker.patch.object(Client, '_http_request', side_effect=[mock_response4.data])
    events, last_run = fetch_events_command(Client(base_url=''), params={'limit': 4}, last_run=last_run)

    assert len(events) == 1  # 1 event remains
    assert last_run == {'last_fetched_event': {'last_event_id': '11', 'last_event_time': 11}}
