import io
import json
import pytest

from copy import deepcopy
from SafeNetTrustedAccessEventCollector import Client
from requests import Session


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
    from SafeNetTrustedAccessEventCollector import fetch_events_command

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
    from SafeNetTrustedAccessEventCollector import get_events_command

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
    from SafeNetTrustedAccessEventCollector import test_module

    mocker.patch.object(Session, 'request', return_value=MockResponse([]))
    assert test_module(Client(base_url='')) == 'ok'
