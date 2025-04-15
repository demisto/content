from CommonServerPython import *
from ProofpointThreatResponseEventCollector import fetch_events_command, TIME_FORMAT, Client, list_incidents_command


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
                                              fetch_delta='6 hours',
                                              incidents_states=['open'])
    assert events == expected_result


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
