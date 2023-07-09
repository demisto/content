import io
import json
import pytest
from CommonServerPython import IncidentSeverity
from RecordedFutureASI import Client, fetch_incidents

TEST_PROJECT_ID = 'fakeprojectid'


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture()
def client():
    client = Client(base_url='https://api.securitytrails.com/v1/asi',
                    project_id=TEST_PROJECT_ID,
                    verify=True,
                    min_severity='Informational',
                    host_incident_limit=10,
                    headers={'APIKEY': 'key'})
    return client


def test_test_module_valid(requests_mock, client):
    """
    Tests that the test command correctly attempts to send a request
    """
    from RecordedFutureASI import test_module
    requests_mock.get(url=f'https://api.securitytrails.com/v1/asi/rules/{TEST_PROJECT_ID}/recent/issues',
                      status_code=200, json="{}")

    assert test_module(client) == 'ok'


def test_current_issues_command(requests_mock, client):
    """
    Test !asi-project-issues-fetch correctly gets issues from the current issues endpoint and returns
    incidents
    """
    mock_response = util_load_json('test_data/current-issues.json')
    requests_mock.get(f'https://api.securitytrails.com/v1/asi/rules/{TEST_PROJECT_ID}/recent/issues',
                      json=mock_response)
    last_run, incidents = fetch_incidents(client, {}, False, False)
    assert len(incidents) == 3
    assert incidents[0]['severity'] == IncidentSeverity.CRITICAL
    assert incidents[0]['name'] == mock_response['data'][0]['name']
    assert incidents[1]['severity'] == IncidentSeverity.MEDIUM
    assert incidents[1]['name'] == mock_response['data'][1]['name']
    assert incidents[2]['severity'] == IncidentSeverity.LOW
    assert incidents[2]['name'] == mock_response['data'][2]['name']


def test_added_issues_command(requests_mock, client):
    """
    Test !asi-project-issues-fetch issues_start=1646769704 correctly uses the activity endpoint and returns
    added incidents
    """
    last_run = 1234
    mock_response = util_load_json('test_data/added-issues.json')
    requests_mock.get(f'https://api.securitytrails.com/v1/asi/rules/history/{TEST_PROJECT_ID}/activity'
                      f'?rule_action=added&start={last_run}',
                      json=mock_response)
    last_run, incidents = fetch_incidents(client, {'last_fetch': last_run}, False, False)
    assert len(incidents) == 3
    assert incidents[0]['severity'] == IncidentSeverity.CRITICAL
    assert incidents[0]['name'] == mock_response['data'][0]['added_rules'][0]['name']
    assert incidents[1]['severity'] == IncidentSeverity.MEDIUM
    assert incidents[1]['name'] == mock_response['data'][0]['added_rules'][1]['name']
    assert incidents[2]['severity'] == IncidentSeverity.LOW
    assert incidents[2]['name'] == mock_response['data'][0]['added_rules'][2]['name']


def test_min_severity_filtering(requests_mock, client):
    """
    Test that a min_severity of Moderate correctly filters out informational rules
    """
    mock_response = util_load_json('test_data/current-issues.json')
    requests_mock.get(f'https://api.securitytrails.com/v1/asi/rules/{TEST_PROJECT_ID}/recent/issues',
                      json=mock_response)
    client.min_severity = 'Moderate'
    last_run, incidents = fetch_incidents(client, {}, False, False)
    assert len(incidents) == 2
    assert incidents[0]['severity'] == IncidentSeverity.CRITICAL
    assert incidents[0]['name'] == mock_response['data'][0]['name']
    assert incidents[1]['severity'] == IncidentSeverity.MEDIUM
    assert incidents[1]['name'] == mock_response['data'][1]['name']


def test_incident_count_limit(requests_mock, client):
    """
    Test that a setting a max incident number to 2 returns 2 incidents with the last one being
    a warning that too many incidents were available
    """
    mock_response = util_load_json('test_data/current-issues.json')
    requests_mock.get(f'https://api.securitytrails.com/v1/asi/rules/{TEST_PROJECT_ID}/recent/issues',
                      json=mock_response)
    client.host_incident_limit = 2
    last_run, incidents = fetch_incidents(client, {}, False, False)
    assert len(incidents) == 2
    assert incidents[0]['severity'] == IncidentSeverity.CRITICAL
    assert incidents[0]['name'] == mock_response['data'][0]['name']
    assert incidents[1]['severity'] == IncidentSeverity.LOW
    assert incidents[1]['name'] == '❗Attack Surface Intelligence: 3+ Changes'


def test_incident_by_host_recent(requests_mock, client):
    """
    Test that By Host issues returns nothing if last_fetch is past any acans
    """
    mock_response = util_load_json('test_data/by-host-issues.json')
    requests_mock.get(f'https://api.securitytrails.com/v1/asi/rules/history/{TEST_PROJECT_ID}/activity/by_host/compare',
                      json=mock_response)
    last_run, incidents = fetch_incidents(client, {'last_fetch': 99999999999}, True, False)
    assert len(incidents) == 0


def test_incident_by_host(requests_mock, client):
    """
    Test that By Host issues are loaded correctly
    """
    mock_response = util_load_json('test_data/by-host-issues.json')
    requests_mock.get(f'https://api.securitytrails.com/v1/asi/rules/history/{TEST_PROJECT_ID}/activity/by_host/compare',
                      json=mock_response)
    last_run, incidents = fetch_incidents(client, {'last_fetch': 1234}, True, False)
    assert len(incidents) == 3
    assert incidents[0]['severity'] == IncidentSeverity.CRITICAL
    assert incidents[0]['name'] == "Attack Surface Risk Increase: registration.example.com (0 --> 95)"
    assert len(json.loads(incidents[0]['rawJSON'])['rules']) == 1
    assert incidents[1]['severity'] == IncidentSeverity.MEDIUM
    assert incidents[1]['name'] == "Attack Surface Risk Increase: ip.example.com (0 --> 65)"
    assert len(json.loads(incidents[1]['rawJSON'])['rules']) == 1
    assert incidents[2]['severity'] == IncidentSeverity.MEDIUM
    assert incidents[2]['name'] == "Attack Surface Risk Increase: stage.example.com (20 --> 26)"
    assert len(json.loads(incidents[2]['rawJSON'])['rules']) == 2


def test_incident_by_host_partial_filter(requests_mock, client):
    """
    Test that By Host issues filter severity correctly and can eliminate a subset of rules from a host
    """
    mock_response = util_load_json('test_data/by-host-issues.json')
    requests_mock.get(f'https://api.securitytrails.com/v1/asi/rules/history/{TEST_PROJECT_ID}/activity/by_host/compare',
                      json=mock_response)
    client.min_severity = 'Moderate'
    last_run, incidents = fetch_incidents(client, {'last_fetch': 1234}, True, False)
    assert len(incidents) == 3
    assert incidents[0]['severity'] == IncidentSeverity.CRITICAL
    assert len(json.loads(incidents[0]['rawJSON'])['rules']) == 1
    assert incidents[1]['severity'] == IncidentSeverity.MEDIUM
    assert len(json.loads(incidents[1]['rawJSON'])['rules']) == 1
    assert incidents[2]['severity'] == IncidentSeverity.MEDIUM
    assert len(json.loads(incidents[2]['rawJSON'])['rules']) == 1


def test_incident_by_host_full_filter(requests_mock, client):
    """
    Test that By Host issues filter severity correctly and eliminates hosts entirely
    """
    mock_response = util_load_json('test_data/by-host-issues.json')
    requests_mock.get(f'https://api.securitytrails.com/v1/asi/rules/history/{TEST_PROJECT_ID}/activity/by_host/compare',
                      json=mock_response)
    client.min_severity = 'Critical'
    last_run, incidents = fetch_incidents(client, {'last_fetch': 1234}, True, False)
    assert len(incidents) == 1
    assert incidents[0]['severity'] == IncidentSeverity.CRITICAL
    assert len(json.loads(incidents[0]['rawJSON'])['rules']) == 1


def test_incident_by_host_by_issue(requests_mock, client):
    """
    Test that By Host By Issue expands each array of rules for each host
    """
    mock_response = util_load_json('test_data/by-host-issues.json')
    requests_mock.get(f'https://api.securitytrails.com/v1/asi/rules/history/{TEST_PROJECT_ID}/activity/by_host/compare',
                      json=mock_response)
    last_run, incidents = fetch_incidents(client, {'last_fetch': 1234}, True, True)
    assert len(incidents) == 4
    assert incidents[0]['severity'] == IncidentSeverity.CRITICAL
    assert incidents[0]['name'].endswith('[registration.example.com]')
    assert json.loads(incidents[0]['rawJSON'])['rules'][0]['name'] in incidents[0]['name']
    # NOTE :: Make sure classification titles are used
    assert json.loads(incidents[0]['rawJSON'])['rules'][0]['classification'] == 'Critical'
    assert incidents[1]['severity'] == IncidentSeverity.MEDIUM
    assert incidents[1]['name'].endswith('[ip.example.com]')
    assert json.loads(incidents[1]['rawJSON'])['rules'][0]['name'] in incidents[1]['name']
    assert incidents[2]['severity'] == IncidentSeverity.MEDIUM
    assert incidents[2]['name'].endswith('[stage.example.com]')
    assert json.loads(incidents[2]['rawJSON'])['rules'][0]['name'] in incidents[2]['name']
    assert incidents[3]['severity'] == IncidentSeverity.LOW
    assert incidents[3]['name'].endswith('[stage.example.com]')
    assert json.loads(incidents[3]['rawJSON'])['rules'][0]['name'] in incidents[3]['name']


def test_incident_by_host_by_issue_filter(requests_mock, client):
    """
    Test that By Host By Issue expands each array of rules and applies min_severity correcctly
    """
    mock_response = util_load_json('test_data/by-host-issues.json')
    requests_mock.get(f'https://api.securitytrails.com/v1/asi/rules/history/{TEST_PROJECT_ID}/activity/by_host/compare',
                      json=mock_response)
    client.min_severity = 'Moderate'
    last_run, incidents = fetch_incidents(client, {'last_fetch': 1234}, True, True)
    assert len(incidents) == 3
    assert incidents[0]['severity'] == IncidentSeverity.CRITICAL
    assert incidents[1]['severity'] == IncidentSeverity.MEDIUM
    assert incidents[2]['severity'] == IncidentSeverity.MEDIUM


def test_incident_total_limit(requests_mock, client):
    """
    Some APIs limit how many results are returned. So if the total is over the XSOAR limit, a warning Incident should
    be created
    """
    mock_response = util_load_json('test_data/by-host-issues.json')
    requests_mock.get(f'https://api.securitytrails.com/v1/asi/rules/history/{TEST_PROJECT_ID}/activity/by_host/compare',
                      json=mock_response)
    client.host_incident_limit = 5
    last_run, incidents = fetch_incidents(client, {'last_fetch': 1234}, True, True)
    assert len(incidents) == 5
    assert incidents[4]['severity'] == IncidentSeverity.LOW
    assert incidents[4]['name'] == '❗Attack Surface Intelligence: 10+ Changes'
