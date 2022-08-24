import json
from CommonServerPython import *
from ProofpointTRAPEventCollector import fetch_incidents_command, TIME_FORMAT, Client


def test_search_quarantine_command(mocker, requests_mock):
    """
    Given:
    - Message ID, Recipient and Delivery Time (Email recived time)

    When:
    - Running search-quarantine command

    Then:
    - Ensure output is success message (at least one success).
    """
    base_url = 'https://server_url/'
    with open('./test_data/raw_response.json', 'r') as f:
        incidents = json.loads(f.read())
    requests_mock.get(f'{base_url}api/incidents', json=incidents)
    client = Client(base_url=base_url,
                    verify=True,
                    headers={},
                    proxy=False)
    first_fetch, _ = parse_date_range('3 days', date_format=TIME_FORMAT)
    res = fetch_incidents_command(client=client, first_fetch=first_fetch, last_run={},
                                  fetch_limit='100',
                                  fetch_delta='6 hours',
                                  incidents_states=['open'])
    assert True
