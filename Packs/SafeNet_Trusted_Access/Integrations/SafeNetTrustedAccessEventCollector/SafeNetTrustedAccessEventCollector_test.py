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
        - fetch-events call
    When:
        - Calling fetch events:
                1. without marking, but with first_fetch
                2. only marking from last_run
    Then:
        - Make sure 3 events returned.
        - Verify the new lastRun is calculated correctly.
    """
    from SafeNetTrustedAccessEventCollector import fetch_events_command

    last_run = {'marker': '22222'}
    requests_mock.get(
        f'{BASE_URL}/logs',
        json=MOCK_ENTRY
    )

    events, new_last_run = fetch_events_command(Client(base_url=BASE_URL),
                                                last_run=last_run,
                                                first_fetch=datetime.strptime("2020-01-01", "%Y-%m-%d"),
                                                limit=2000)

    assert len(events) == 3
    assert events[0].get('id') == 'ID1'
    assert new_last_run['marker'] == 11111111111


def test_get_events(requests_mock):
    """
    Given:
        - sta-get-events call
    When:
        - Running the command with since, until and marker parameters
    Then:
        - Make sure all of the events are returned as part of the CommandResult.
    """
    from SafeNetTrustedAccessEventCollector import get_events_command

    requests_mock.get(
        f'{BASE_URL}/logs',
        json=MOCK_ENTRY
    )
    args = {
        'marker': 11111,
        'since': '01.01.2022',
        'until': 'today'
    }

    events, results = get_events_command(Client(base_url=BASE_URL), args=args)

    assert len(events) == 3
    assert results.raw_response == MOCK_ENTRY


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

    requests_mock.get(
        f'{BASE_URL}/logs',
        json=MOCK_ENTRY
    )
    assert test_module(Client(base_url=BASE_URL)) == 'ok'
