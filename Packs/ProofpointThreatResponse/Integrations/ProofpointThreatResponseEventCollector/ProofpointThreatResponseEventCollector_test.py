from freezegun import freeze_time

from CommonServerPython import *
from ProofpointThreatResponseEventCollector import fetch_events_command, TIME_FORMAT, Client, list_incidents_command, \
    find_and_remove_large_entry, remove_large_events


def test_fetch_events_command(requests_mock):
    """
    Given:
    - fetch events command

    When:
    - Running fetch-events command

    Then:
    - Ensure last-fetch id is 2
    """
    base_url = 'https://server_url/'
    with open('./test_data/raw_response.json') as f:
        incidents = json.loads(f.read())
    with open('./test_data/expected_result.json') as f:
        expected_result = json.loads(f.read())
    requests_mock.get(f'{base_url}api/incidents', json=incidents)
    client = Client(base_url=base_url,
                    verify=True,
                    headers={},
                    proxy=False)
    first_fetch, _ = parse_date_range('2 hours', date_format=TIME_FORMAT)
    events, last_fetch = fetch_events_command(client=client, first_fetch=first_fetch, last_run={},
                                              fetch_limit='100',
                                              incidents_states=['open'])
    assert events == expected_result
    assert last_fetch.get('last_fetch') == {'open': '2018-06-01T17:56:09Z'}


@freeze_time("2023-01-01T01:00:00")
def test_fetch_events_command_empty_response(requests_mock):
    """
    Given:
    - fetch events command

    When:
    - Running fetch-events command and no incidents in the given time

    Then:
    - Ensure last fetch is set to now minus 2 minutes.
    """
    base_url = 'https://server_url/'

    requests_mock.get(f'{base_url}api/incidents', json={})
    client = Client(base_url=base_url,
                    verify=True,
                    headers={},
                    proxy=False)
    first_fetch, _ = parse_date_range('2 hours', date_format=TIME_FORMAT)
    events, last_fetch = fetch_events_command(client=client, first_fetch=first_fetch, last_run={},
                                              fetch_limit='100',
                                              incidents_states=['open'])
    assert last_fetch.get('last_fetch') == {'open': '2023-01-01T00:58:00Z'}


def test_list_incidents_command(requests_mock):
    """
    Given:
    - list_incidents_command

    When:
    - Want to list all existing incidents

    Then:
    - Ensure List Incidents Results in human-readable.
    """
    base_url = 'https://server_url/'
    with open('./test_data/raw_response.json') as f:
        incidents = json.loads(f.read())
    requests_mock.get(f'{base_url}api/incidents', json=incidents)
    client = Client(base_url=base_url,
                    verify=True,
                    headers={},
                    proxy=False)
    args = {'limit': 2}
    incidents, human_readable, raw_response = list_incidents_command(client, args)
    assert 'List Incidents Results:' in human_readable


def test_find_and_remove_large_entry():
    test_event = {
        'key1': 'large value' * 1250000,  # Each repetition adds around 1 MB
        'key2': {
            'nested_key': 'small value',
            'nested_big_key': 'large value' * 1250000  # Each repetition adds around 1 MB
        }
    }

    find_and_remove_large_entry(test_event)

    assert test_event['key1'] == ''
    assert test_event['key2']['nested_big_key'] == ''
    assert test_event['key2']['nested_key'] == 'small value'


def test_remove_large_events():
    test_event = {
        'key1': 'large value' * 1250000,  # Each repetition adds around 1 MB
        'key2': {
            'nested_key': 'small value',
            'nested_big_key': 'large value' * 1250000  # Each repetition adds around 1 MB
        }
    }
    test_events = [test_event]

    remove_large_events(test_events)

    assert len(test_events) == 1
    assert test_event['key1'] == ''
    assert test_event['key2']['nested_big_key'] == ''
    assert test_event['key2']['nested_key'] == 'small value'
