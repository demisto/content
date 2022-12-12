import json
import io


BASE_URL = 'https://www.example.com/api/extras'
LOG_TYPES = ['journal-entries', 'object-changes']


# helper function to load json file
def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_get_events(mocker, requests_mock):
    from NetBoxEventCollector import Client, get_events

    for log_type in LOG_TYPES:
        requests_mock.get(f'{BASE_URL}/{log_type}?limit=4&ordering=&id__gte=0',
                          json=util_load_json(f'test_data/get_events_{log_type}-01.json'))
        requests_mock.get(f'{BASE_URL}/{log_type}/?id__gte=0&limit=2&offset=2&ordering=',
                          json=util_load_json(f'test_data/get_events_{log_type}-02.json'))

    client = Client(base_url=BASE_URL, verify=False)
    events, _ = get_events(client, limit=4)

    mock_events = util_load_json('test_data/netbox-get-events.json')

    assert events == mock_events


def test_fetch_events(mocker, requests_mock):
    from NetBoxEventCollector import Client, fetch_events

    # mock the first fetch id
    requests_mock.get(f'{BASE_URL}/journal-entries?ordering=id&limit=1&created_after=2022-01-01T02%3A00%3A00Z',
                      json={'results': [{'id': 5}]})
    requests_mock.get(f'{BASE_URL}/object-changes?ordering=id&limit=1&time_after=2022-01-01T02%3A00%3A00Z',
                      json={'results': [{'id': 9}]})

    # mock the events
    requests_mock.get(f'{BASE_URL}/journal-entries?limit=2&ordering=id&id__gte=5',
                      json=util_load_json('test_data/fetch_events_journal-entries.json'))
    requests_mock.get(f'{BASE_URL}/object-changes?limit=2&ordering=id&id__gte=9',
                      json=util_load_json('test_data/fetch_events_object-changes.json'))

    client = Client(base_url=BASE_URL, verify=False)
    next_run, events = fetch_events(client, max_fetch=2, last_run={}, first_fetch_time=1640995200)

    mock_events = util_load_json('test_data/netbox-fetch-events.json')

    assert events == mock_events
    assert next_run == {'journal-entries': 7, 'object-changes': 11}
