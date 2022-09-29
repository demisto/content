import io
import json
import pytest

from copy import deepcopy
from SlackEventCollector import Client, prepare_query_params
from requests import Session


""" Helpers """


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
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


def test_fetch_events(mocker):
    """
    Given:
        - fetch-events call, where oldest = 1521214343, last_id = 1
    When:
        - Three following results are retrieved from the API:
            1. id = 1, date_create = 1521214343
            2. id = 2, date_create = 1521214343
            3. id = 3, date_create = 1521214345
    Then:
        - Make sure only events 2 and 3 are returned (1 should not).
        - Verify the new lastRun is calculated correctly.
    """
    from SlackEventCollector import fetch_events_command

    last_run = {'last_id': '1'}

    mock_response = MockResponse([
        {'id': '3', 'date_create': 1521214345},
        {'id': '2', 'date_create': 1521214343},
        {'id': '1', 'date_create': 1521214343},
    ])
    mocker.patch.object(Session, 'request', return_value=mock_response)
    events, new_last_run = fetch_events_command(Client(base_url=''), params={}, last_run=last_run)

    assert len(events) == 2
    assert events[0].get('id') != '1'
    assert new_last_run['last_id'] == '3'


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
