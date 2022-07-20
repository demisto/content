import io
import json
from datetime import datetime
from SafeNetTrustedAccessEventCollector import Client


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


MOCK_ENTRY = util_load_json('test_data/mock_event.json')
BASE_URL = 'https://sta.example.com/tenant_code'


def test_fetch_events(requests_mock):
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

    last_run = {'marker': '22222'}

    events, new_last_run = fetch_events_command(Client(base_url=''),
                                                last_run=last_run,
                                                first_fetch=datetime.strptime("2020-01-01", "%Y-%m-%d"),
                                                limit=1000)

    assert len(events) == 2
    assert events[0].get('id') != '1'
    assert new_last_run['last_id'] == '3'


def test_get_events(requests_mock):
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

    _, results = get_events_command(Client(base_url=''), args={})

    assert len(results.raw_response.get('entries', [])) == 3
    assert results.raw_response == mock_response.json()


def test_test_module(requests_mock):
    """
    Given:
        - test-module call
    When:
        - A response with an OK status_code is retrieved from the API call.
    Then:
        - Make sure 'ok' is returned.
    """
    from SafeNetTrustedAccessEventCollector import test_module

    requests_mock.post(
        BASE_URL,
        json=MOCK_ENTRY
    )
    assert test_module(Client(base_url=BASE_URL)) == 'ok'
