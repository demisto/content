import datetime
import json
import io
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
    from KnowBe4KMSATEventCollector import fetch_events

    last_run = {'page': '0'}
    requests_mock.get(
        f'{BASE_URL}/logs',
        json=MOCK_ENTRY
    )

    events, new_last_run = fetch_events(Client(base_url=BASE_URL), last_run=last_run,
                                        first_fetch_time=datetime.strptime("2020-01-01", "%Y-%m-%d"), max_fetch=2000)
    assert len(events) == 3
    assert events[0].get('id') == "786a515c-1cbd-4a8c-a94a-61ad877c893c"
    assert new_last_run['page'] == 2
