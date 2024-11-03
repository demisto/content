import json

from NetBoxEventCollector import LOG_TYPES

BASE_URL = 'https://www.example.com/api/extras'


# helper function to load json file
def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_add_time_key_to_events():
    """
    Given:
        - list of events
    When:
        - Calling add_time_key_to_events
    Then:
        - Ensure the _time key is added to the events
    """
    from NetBoxEventCollector import add_time_key_to_events

    events = util_load_json('test_data/netbox-get-events.json')
    events = add_time_key_to_events(events)

    assert events[0]['_time'] == '2022-12-04T14:33:52.067484Z'
    assert events[4]['_time'] == '2022-12-07T08:19:57.810348Z'


def test_get_events_command(requests_mock):
    """
    Given:
        - NetBox client and limit of events to fetch
    When:
        - Calling get_events_command
    Then:
        - Ensure the events are returned as expected and the pagination is working as expected
    """
    from NetBoxEventCollector import Client, get_events_command

    for log_type in LOG_TYPES:
        requests_mock.get(f'{BASE_URL}/{log_type}?limit=4&ordering=&id__gte=0',
                          json=util_load_json(f'test_data/get_events_{log_type}-01.json'))
        requests_mock.get(f'{BASE_URL}/{log_type}/?id__gte=0&limit=2&offset=2&ordering=',
                          json=util_load_json(f'test_data/get_events_{log_type}-02.json'))

    client = Client(base_url=BASE_URL, verify=False)
    events, _ = get_events_command(client, limit=4)

    mock_events = util_load_json('test_data/netbox-get-events.json')

    assert events == mock_events


def test_fetch_events_command(requests_mock):
    """
        Given:
            - NetBox client and max_fetch, last_run and first_fetch_time
        When:
            - Calling fetch_events_command
        Then:
            - Ensure the events are returned as expected and the next_run is as expected
    """
    from NetBoxEventCollector import Client, fetch_events_command

    # mock the first fetch id
    requests_mock.get(f'{BASE_URL}/journal-entries?ordering=id&limit=1&created_after=2022-01-01T00:00:00Z',
                      json={'results': [{'id': 5}]})
    requests_mock.get(f'{BASE_URL}/object-changes?ordering=id&limit=1&time_after=2022-01-01T00:00:00Z',
                      json={'results': [{'id': 9}]})

    # mock the events
    requests_mock.get(f'{BASE_URL}/journal-entries?limit=2&ordering=id&id__gte=5',
                      json=util_load_json('test_data/fetch_events_journal-entries.json'))
    requests_mock.get(f'{BASE_URL}/object-changes?limit=2&ordering=id&id__gte=9',
                      json=util_load_json('test_data/fetch_events_object-changes.json'))

    client = Client(base_url=BASE_URL, verify=False)
    next_run, events = fetch_events_command(client, max_fetch=2, last_run={}, first_fetch_time='2022-01-01T00:00:00Z')

    mock_events = util_load_json('test_data/netbox-fetch-events.json')

    assert events == mock_events
    assert next_run == {'journal-entries': 7, 'object-changes': 11}
