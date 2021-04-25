import json
import io

BASE_URL = 'https://gateway.qg2.apps.qualys.eu/'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'


def load_mock_response(file_name: str) -> dict:
    """
    Load one of the mock responses to be used for assertion.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    """
    with open(f'{file_name}', mode='r', encoding='utf-8') as json_file:
        return json.loads(json_file.read())


def util_load_json(path) -> dict:
    with io.open(path, mode='r', encoding='utf-8') as file:
        return json.loads(file.read())


def util_load_file(path) -> str:
    with io.open(path, mode='r', encoding='utf-8') as file:
        return file.read()


def test_list_events_command(requests_mock) -> None:
    """
    Scenario: List events.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - list_events_command is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key fields is correct.
    """
    from QualysFIM import Client, list_events_command
    mock_response = util_load_json('test_data/list_events.json')
    requests_mock.post(f'{BASE_URL}fim/v2/events/search', json=mock_response)
    requests_mock.post(f'{BASE_URL}/auth', json={})
    client = Client(base_url=BASE_URL, verify=False, proxy=False, auth=('a', 'b'))
    result = list_events_command(client, {'sort': 'most_recent'})
    assert result.outputs_prefix == 'QualysFIM.Event'
    assert len(result.raw_response) == 2
    assert result.outputs_key_field == 'id'


def test_get_event_command(requests_mock) -> None:
    """
    Scenario: List events.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - get_event_command is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure outputs key fields is correct.
    """
    from QualysFIM import Client, get_event_command
    mock_response = util_load_json('test_data/get_event.json')
    requests_mock.get(f'{BASE_URL}fim/v1/events/123456', json=mock_response)
    requests_mock.post(f'{BASE_URL}/auth', json={})
    client = Client(base_url=BASE_URL, verify=False, proxy=False, auth=('a', 'b'))
    result = get_event_command(client, {'event_id': '123456'})
    assert result.outputs_prefix == 'QualysFIM.Event'
    assert result.outputs_key_field == 'id'


def test_list_incidents_command(requests_mock) -> None:
    """
    Scenario: List incidents
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - list_incidents_command is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
     - Ensure outputs key fields is correct.
    """

    from QualysFIM import Client, list_incidents_command
    mock_response = util_load_json('test_data/list_incidents.json')
    requests_mock.post(f'{BASE_URL}fim/v3/incidents/search', json=mock_response)
    requests_mock.post(f'{BASE_URL}/auth', json={})
    client = Client(base_url=BASE_URL, verify=False, proxy=False, auth=('a', 'b'))
    result = list_incidents_command(client, {'sort': 'most_recent'})
    assert result.outputs_prefix == 'QualysFIM.Incident'
    assert len(result.raw_response) == 2
    assert result.outputs[0].get('id') == '75539bfc-c0e7-4bcb-b55a-48065ef89ebe'
    assert result.outputs[1].get('id') == '5a6d0462-1c2e-4e36-a13b-6264bd3c222f'
    assert result.outputs_key_field == 'id'


def test_get_incident_events_command(requests_mock) -> None:
    """
    Scenario: List incident's events
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - list_incidents_events_command is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key fields is correct.
    """

    from QualysFIM import Client, list_incident_events_command
    mock_response = util_load_json('test_data/get_incident_events.json')
    requests_mock.post(f'{BASE_URL}fim/v2/incidents/None/events/search',
                       json=mock_response)
    requests_mock.post(f'{BASE_URL}/auth', json={})
    client = Client(base_url=BASE_URL, verify=False, proxy=False, auth=('a', 'b'))
    result = list_incident_events_command(client, {'limit': '10'})
    assert result.outputs_prefix == 'QualysFIM.Event'
    assert len(result.raw_response) == 10
    assert result.outputs_key_field == 'id'


def test_create_incident_command(requests_mock) -> None:
    """
        Scenario: Create Incident.
        Given:
         - User has provided valid credentials.
         - Headers and JWT token have been set.
        When:
         - create_incident_command is called.
        Then:
         - Ensure outputs prefix is correct.
         - Ensure outputs key fields is correct.
        """
    from QualysFIM import Client, create_incident_command
    mock_response = util_load_json('test_data/create_incident.json')
    requests_mock.post(f'{BASE_URL}fim/v3/incidents/create', json=mock_response)
    mock_response = util_load_json('test_data/list_incidents.json')
    requests_mock.post(f'{BASE_URL}fim/v3/incidents/search', json=mock_response)
    requests_mock.post(f'{BASE_URL}/auth', json={})
    client = Client(base_url=BASE_URL, verify=False, proxy=False, auth=('a', 'b'))
    result = create_incident_command(client, {'name': 'test'})
    assert result.outputs_prefix == 'QualysFIM.Incident'
    assert result.outputs_key_field == 'id'


def test_approve_incident_command(requests_mock) -> None:
    """
        Scenario: Approve Incident.
        Given:
         - User has provided valid credentials.
         - Headers and JWT token have been set.
        When:
         - approve_incident_command is called.
        Then:
         - Ensure outputs prefix is correct.
         - Ensure outputs key fields is correct.
        """
    from QualysFIM import Client, approve_incident_command
    mock_response = util_load_json('test_data/approve_incident.json')
    requests_mock.post(f'{BASE_URL}fim/v3/incidents/None/approve', json=mock_response)
    requests_mock.post(f'{BASE_URL}/auth', json={})
    client = Client(base_url=BASE_URL, verify=False, proxy=False, auth=('a', 'b'))
    result = approve_incident_command(client, {'approval_status': 'test',
                                               'change_type': 'test',
                                               'comment': 'test',
                                               'disposition_category': 'test'})
    assert result.outputs_prefix == 'QualysFIM.Incident'
    assert result.outputs_key_field == 'id'


def test_list_assets_command(requests_mock) -> None:
    """
    Scenario: List Assets.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - list_assets_command is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key fields is correct.
    """
    from QualysFIM import Client, list_assets_command
    mock_response = util_load_json('test_data/list_assets.json')
    requests_mock.post(f'{BASE_URL}fim/v3/assets/search', json=mock_response)
    requests_mock.post(f'{BASE_URL}/auth', json={})
    client = Client(base_url=BASE_URL, verify=False, proxy=False, auth=('a', 'b'))
    result = list_assets_command(client, {})
    assert result.outputs_prefix == 'QualysFIM.Asset'
    assert len(result.outputs) == 2
    assert result.outputs_key_field == 'id'


def test_fetch_incidents_command(requests_mock) -> None:
    """
    Scenario: Fetch Incidents.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - fetch_incidents is called.
    Then:
     - Ensure a sample value from the API matches what is generated in the context.
     - Ensure occurred time is correct.
    """
    from QualysFIM import Client, fetch_incidents
    mock_response = util_load_json('test_data/fetch_incidents.json')
    requests_mock.post(f'{BASE_URL}fim/v3/incidents/search', json=mock_response)
    requests_mock.post(f'{BASE_URL}/auth', json={})
    client = Client(base_url=BASE_URL, verify=False, proxy=False, auth=('a', 'b'))
    next_run, incidents = fetch_incidents(client=client, last_run={}, fetch_filter='',
                                          first_fetch_time='3 days', max_fetch='2')
    raw_json = json.loads(incidents[0].get('rawJSON'))
    assert raw_json.get('id') == '75539bfc-c0e7-4bcb-b55a-48065ef89ebe'
    assert raw_json.get('createdBy').get('date') == 1613378492427
