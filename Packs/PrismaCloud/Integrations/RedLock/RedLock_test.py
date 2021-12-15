import pytest
import json
from freezegun import freeze_time
import demistomock as demisto

integration_params = {
    'url': 'http://test.com',
    'credentials': {'identifier': 'test', 'password': 'pass'},
    'fetch_time': '3 days',
    'proxy': 'false',
    'unsecure': 'false',
}


def load_json(file: str):
    with open(file) as f:
        return json.load(f)


@pytest.fixture(autouse=True)
def set_mocks(mocker):
    mocker.patch.object(demisto, 'params', return_value=integration_params)


def test_fetch_incident(mocker):
    from RedLock import fetch_incidents
    example_alerts = load_json('test_data/example_alert.json')
    mocker.patch('RedLock.req', return_value=example_alerts)
    incidents, last_fetches, last_seen_time = fetch_incidents(limit=50)
    assert len(incidents) == 2, 'There are two alerts in example response'
    for incident, alert in zip(incidents, example_alerts.get('items')):
        policy_name = demisto.get(alert, 'policy.name')
        policy_name = policy_name if policy_name else 'No policy'
        assert incident.get('name') == f"{policy_name} - {alert.get('id')}"
    assert last_seen_time == 1633109203697


@freeze_time("2021-07-10T16:34:14.758295 UTC+1")
def test_empty_incident(mocker):
    from RedLock import fetch_incidents
    mocker.patch('RedLock.req', return_value={'items': []})
    incidents, last_fetches, last_seen_time = fetch_incidents(50)
    assert len(incidents) == 0, 'There are no alerts in example response'
    assert last_seen_time == 1625679254000


def test_fetch():
    from RedLock import fetch_incidents
    all_incidents = []
    for _ in range(10):
        incidents, last_fetches, last_seen_time = fetch_incidents(5)
        demisto.setLastRun({'time': last_seen_time, 'last_fetches': last_fetches})
        all_incidents.extend(incidents)
    print(incidents)

def test_redlock_list_scans(mocker):
    """
        Given
            - The response from the API call of redlock-list-scans command.
        When
            - calling redlock-list-scans
        Then
            - Validate that the readable output and the context entry of the command is as expected

    """
    from RedLock import redlock_list_scans
    list_scans_response = {
        'data': [{
            'id': '111111111',
            'attributes': {
                'name': ['test name'],
                'type': ['test type'],
                'user': ['test user'],
                'scanTime': '2021-10-18T14:38:53.654174'
            }
        }]
    }
    expected_readable_output = '### Scans List:\n|ID|Name|Scan Time|Type|User|\n|---|---|---|---|---|\n| 111111111 |' \
                               ' test name | 2021-10-18T14:38:53.654174 | test type | test user |\n'
    expected_context_entry = {'Redlock.Scans(val.id == obj.id)': [{'id': '111111111',
                                                                   'name': ['test name'],
                                                                   'type': ['test type'],
                                                                   'user': ['test user'],
                                                                   'scanTime': '2021-10-18T14:38:53.654174'}]}
    mocker.patch('RedLock.req', return_value=list_scans_response)
    mocker.patch.object(demisto, 'results')
    redlock_list_scans()
    assert demisto.results.call_args[0][0].get('HumanReadable') == expected_readable_output
    assert demisto.results.call_args[0][0].get('EntryContext') == expected_context_entry


def test_redlock_get_scan_status(mocker):
    """
        Given
            - The response from the API call of redlock-get-scan-status command.
        When
            - calling redlock-get-scan-status
        Then
            - Validate that the readable output and the context entry of the command is as expected

    """
    from RedLock import redlock_get_scan_status
    get_status_response = {
        'data': {
            'id': '111111111',
            'attributes': {
                'status': 'test'
            }
        }
    }
    expected_readable_output = '### Scan Status:\n|ID|Status|\n|---|---|\n| 111111111 | test |\n'
    expected_context_entry = {'Redlock.Scans(val.id == obj.id)': {'id': '111111111',
                                                                  'status': 'test'}}
    mocker.patch('RedLock.req', return_value=get_status_response)
    mocker.patch.object(demisto, 'results')
    redlock_get_scan_status()
    assert demisto.results.call_args[0][0].get('HumanReadable') == expected_readable_output
    assert demisto.results.call_args[0][0].get('EntryContext') == expected_context_entry


def test_redlock_get_scan_results(mocker):
    """
        Given
            - The response from the API call of redlock-get-scan-result command.
        When
            - calling redlock-get-scan-result
        Then
            - Validate that the readable output and the context entry of the command is as expected

    """
    from RedLock import redlock_get_scan_results
    get_result_response = {
        'data': [{
            'id': '111111111',
            'attributes': {
                'name': 'test',
                'policyId': '2222',
                'desc': 'test',
                'severity': 'high'
            }}]
    }
    expected_readable_output = '### Scan Results:\n|Description|ID|Name|Policy ID|Severity|\n|---|---|---|---|---|\n|' \
                               ' test | 111111111 | test | 2222 | high |\n'
    expected_context_entry = {'Redlock.Scans(val.id == obj.id)': {'id': None,
                                                                  'results': [
                                                                      {'id': '111111111',
                                                                       'attributes': {'name': 'test',
                                                                                      'policyId': '2222',
                                                                                      'desc': 'test',
                                                                                      'severity': 'high'}}]}}
    mocker.patch('RedLock.req', return_value=get_result_response)
    mocker.patch.object(demisto, 'results')
    redlock_get_scan_results()
    assert demisto.results.call_args[0][0].get('HumanReadable') == expected_readable_output
    assert demisto.results.call_args[0][0].get('EntryContext') == expected_context_entry
