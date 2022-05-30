import io
import json
import pydantic
import pytest

from copy import deepcopy
from SlackEventCollector import SlackEventsParams, SlackEventClient, SlackGetEvents
from requests import Session


""" Helpers """


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


MOCK_ENTRY = util_load_json('test_data/mock_event.json')


class MockResponse:
    def __init__(self, data: list):
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
        - Parsing them as a SlackEventsParams object.
    Then:
        - Make sure they are parsed correctly.
    """
    actual_params = SlackEventsParams.parse_obj(params)
    assert actual_params.dict(exclude_none=True) == expected_params


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
        - Make sure a ValidationError exception is raised.
    """
    with pytest.raises(pydantic.error_wrappers.ValidationError):
        SlackEventsParams.parse_obj(params)


def test_fetch_events_exceeds_limit(mocker):
    """
    Given:
        - Fetch Events with limit = 1
    When:
        - Calling SlackGetEvents.run()
        - Two results are retrieved from the API.
    Then:
        - Make sure only 1 event is actually returned.
    """
    params = {'limit': '1', 'user_token': {'password': 'mock_token'}}
    mock_response = MockResponse([{'id': '2'}, {'id': '1'}])
    mocker.patch.object(Session, 'request', return_value=mock_response)
    assert len(mock_response.json().get('entries')) == 2

    client = SlackEventClient(params)
    events = SlackGetEvents(client).run()
    assert len(events) == 1


def test_remove_duplicates(mocker):
    """
    Given:
        - Fetch Events where oldest = 1521214343, last_id = 1
    When:
        - Calling SlackGetEvents.run()
        - Three following results are retrieved from the API:
            1. id = 1, date_create = 1521214343
            2. id = 2, date_create = 1521214343
            3. id = 3, date_create = 1521214345
    Then:
        - Make sure only events 2 and 3 are returned.
    """
    params = {'oldest': 1521214343, 'last_id': '1', 'user_token': {'password': 'mock_token'}}
    mock_response = MockResponse([
        {'id': '3', 'date_create': 1521214345},
        {'id': '2', 'date_create': 1521214343},
        {'id': '1', 'date_create': 1521214343},
    ])
    mocker.patch.object(Session, 'request', return_value=mock_response)

    client = SlackEventClient(params)
    events = SlackGetEvents(client).run()
    assert len(events) == 2
    assert events[0].get('id') == '2'
    assert events[1].get('id') == '3'
