import json
from datetime import datetime, timedelta

BASE_URL = 'https://test.cyberint.io/alert'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


def load_mock_response(file_name: str) -> dict:
    """
    Load one of the mock responses to be used for assertion.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    """
    with open(f'test_data/{file_name}', mode='r', encoding='utf-8') as json_file:
        return json.loads(json_file.read())


def test_cyberint_alerts_fetch_command(requests_mock):
    """
    Scenario: List alerts
    Given:
     - User has provided valid credentials.
    When:
     - cyberint_alert_list is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from Cyberint import Client, cyberint_alerts_fetch_command
    mock_response = load_mock_response('list_alerts.json')
    requests_mock.post(f'{BASE_URL}/api/v1/alerts', json=mock_response)
    client = Client(base_url=BASE_URL, verify_ssl=False, access_token='xxx', proxy=False)
    result = cyberint_alerts_fetch_command(client, {})
    assert len(result.outputs) == 3
    assert result.outputs_prefix == 'Cyberint.Alert'
    assert result.outputs[0].get('ref_id') == 'ARG-3'


def test_cyberint_alerts_status_update_command(requests_mock):
    """
    Scenario: Update alert statuses.
    Given:
     - User has provided valid credentials.
    When:
     - cyberint_alert_update is called.
     - Fetch incidents - for each incident
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from Cyberint import Client, cyberint_alerts_status_update
    mock_response = {}
    requests_mock.put(f'{BASE_URL}/api/v1/alerts/status', json=mock_response)
    client = Client(base_url=BASE_URL, verify_ssl=False, access_token='xxx', proxy=False)
    result = cyberint_alerts_status_update(client, {'alert_ref_ids': 'alert1',
                                                     'status': 'acknowledged'})
    assert len(result.outputs) == 1
    assert result.outputs_prefix == 'Cyberint.Alert'
    assert result.outputs[0].get('ref_id') == 'alert1'
    result = cyberint_alerts_status_update(client, {'alert_ref_ids': 'alert1,alert2',
                                                     'status': 'acknowledged'})
    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'Cyberint.Alert'
    assert result.outputs[1].get('ref_id') == 'alert2'


def test_fetch_incidents(requests_mock) -> None:
    """
    Scenario: Fetch incidents.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - Every time fetch_incident is called (either timed or by command).
    Then:
     - Ensure number of incidents is correct.
     - Ensure last_fetch is correctly configured according to mock response.
    """
    from Cyberint import Client, fetch_incidents
    mock_response = load_mock_response('list_alerts.json')
    requests_mock.post(f'{BASE_URL}/api/v1/alerts', json=mock_response)
    client = Client(base_url=BASE_URL, verify_ssl=False, access_token='xxx', proxy=False)
    last_fetch, incidents = fetch_incidents(client, {'last_fetch': 100000000}, '3 days', [], [],
                                            [], [], 50)
    wanted_time = datetime.timestamp(datetime.strptime('2020-12-30T00:00:57Z', DATE_FORMAT))
    assert last_fetch.get('last_fetch') == wanted_time * 1000
    assert len(incidents) == 3
    assert incidents[0].get('name') == 'Cyberint alert ARG-3: Company Customer Credentials Exposed'


def test_fetch_incidents_no_last_fetch(requests_mock):
    """
    Scenario: Fetch incidents for the first time, so there is no last_fetch available.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
     - First time running fetch incidents.
    When:
     - Every time fetch_incident is called (either timed or by command).
    Then:
     - Ensure number of incidents is correct.
     - Ensure last_fetch is correctly configured according to mock response.
    """
    from Cyberint import Client, fetch_incidents
    mock_response = load_mock_response('list_alerts.json')
    requests_mock.post(f'{BASE_URL}/api/v1/alerts', json=mock_response)
    client = Client(base_url=BASE_URL, verify_ssl=False, access_token='xxx', proxy=False)
    last_fetch, incidents = fetch_incidents(client, {'last_fetch': 100000000}, '3 days', [], [],
                                            [], [], 50)
    wanted_time = datetime.timestamp(datetime.strptime('2020-12-30T00:00:57Z', DATE_FORMAT))
    assert last_fetch.get('last_fetch') == wanted_time * 1000
    assert len(incidents) == 3
    assert incidents[0].get('name') == 'Cyberint alert ARG-3: Company Customer Credentials Exposed'


def test_fetch_incidents_empty_response(requests_mock):
    """
        Scenario: Fetch incidents but there are no incidents to return.
        Given:
         - User has provided valid credentials.
         - Headers and JWT token have been set.
        When:
         - Every time fetch_incident is called (either timed or by command).
         - There are no incidents to return.
        Then:
         - Ensure number of incidents is correct (None).
         - Ensure last_fetch is correctly configured according to mock response.
        """
    from Cyberint import Client, fetch_incidents
    mock_response = load_mock_response('empty.json')
    requests_mock.post(f'{BASE_URL}/api/v1/alerts', json=mock_response)
    client = Client(base_url=BASE_URL, verify_ssl=False, access_token='xxx', proxy=False)
    last_fetch, incidents = fetch_incidents(client, {'last_fetch': 100000000}, '3 days', [], [],
                                            [], [], 50)
    assert last_fetch.get('last_fetch') == 100001000
    assert len(incidents) == 0


def test_set_date_pair():
    """
        Scenario: Set date_start and date_end for both creation and modification.
        Given:
         - User has provided valid credentials.
        When:
         - Every time cyberint_list_alerts is called.
        Then:
         - Ensure dates return match what is needed (correct format)
    """
    from Cyberint import set_date_pair
    start_time = '2020-12-01T00:00:00Z'
    end_time = '2020-12-05T00:00:00Z'
    assert set_date_pair(start_time, end_time, None) == (start_time, end_time)
    range = '3 Days'
    assert set_date_pair(start_time, end_time, range) == (datetime.strftime(datetime.now() -
                                                                            timedelta(days=3),
                                                                            DATE_FORMAT),
                                                          datetime.strftime(datetime.now(),
                                                                            DATE_FORMAT))
    assert set_date_pair(start_time, None, None) == (start_time, datetime.strftime(datetime.now(),
                                                                                   DATE_FORMAT))
    assert set_date_pair(None, end_time, None) == (datetime.strftime(datetime.
                                                                     fromisocalendar(2020, 2, 1),
                                                                     DATE_FORMAT), end_time)
