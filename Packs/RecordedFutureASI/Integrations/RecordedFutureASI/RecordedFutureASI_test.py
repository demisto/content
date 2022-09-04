import json
import io
from CommonServerPython import IncidentSeverity
from RecordedFutureASI import Client, fetch_incidents
import pytest

TEST_PROJECT_ID = 'fakeprojectid'


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture()
def client():
    client = Client(base_url='https://api.securitytrails.com/v1/asi',
                    project_id=TEST_PROJECT_ID,
                    verify=True,
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
    last_run, incidents = fetch_incidents(client, {})
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
    last_run, incidents = fetch_incidents(client, {'last_fetch': last_run})
    assert len(incidents) == 3
    assert incidents[0]['severity'] == IncidentSeverity.CRITICAL
    assert incidents[0]['name'] == mock_response['data'][0]['added_rules'][0]['name']
    assert incidents[1]['severity'] == IncidentSeverity.MEDIUM
    assert incidents[1]['name'] == mock_response['data'][0]['added_rules'][1]['name']
    assert incidents[2]['severity'] == IncidentSeverity.LOW
    assert incidents[2]['name'] == mock_response['data'][0]['added_rules'][2]['name']
