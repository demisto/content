import json


ATA_CENTER_URL = 'https://atacenter.contoso.com/api/management'


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_get_suspicious_activity(requests_mock):
    """
    Given:
     - Microsoft ATA client

    When:
     - Running get-suspicious-activity command

    Then:
     - Ensure command runs successfully
     - Verify command outputs
    """
    from MicrosoftAdvancedThreatAnalytics import Client, get_suspicious_activity

    mock_response = util_load_json('test_data/suspicious_activity.json')
    requests_mock.get(f'{ATA_CENTER_URL}/suspiciousActivities/', json=mock_response)
    honeytoken_activity = [mock_response[1]]

    client = Client(
        base_url=ATA_CENTER_URL
    )
    args = {
        'status': 'Open',
        'severity': 'Medium,High',
        'Type': 'HoneytokenActivitySuspiciousActivity',
        'start_time': '2020-07-20T13:00:00',
        'end_time': '2020-07-29T14:00:00'
    }

    response = get_suspicious_activity(client, args)

    assert response.outputs == honeytoken_activity
    assert response.outputs_prefix == 'MicrosoftATA.SuspiciousActivity'
    assert response.outputs_key_field == 'Id'


def test_get_suspicious_activity_details(requests_mock):
    """
    Given:
     - Microsoft ATA client
     - Suspicious activity ID to retrieve

    When:
     - Running get-suspicious-activity command

    Then:
     - Ensure command runs successfully
     - Verify command outputs
    """
    from MicrosoftAdvancedThreatAnalytics import Client, get_suspicious_activity

    suspicious_activity_id = '5f1fe6b383eaed101ce19b58'

    mock_response = util_load_json('test_data/suspicious_activity.json')
    honeytoken_activity = mock_response[1]
    requests_mock.get(f'{ATA_CENTER_URL}/suspiciousActivities/{suspicious_activity_id}', json=mock_response[1])
    details_mock_response = util_load_json('test_data/suspicious_activity_details.json')
    requests_mock.get(f'{ATA_CENTER_URL}/suspiciousActivities/{suspicious_activity_id}/details',
                      json=details_mock_response)
    honeytoken_activity = [honeytoken_activity]
    honeytoken_activity[0]['DetailsRecords'] = details_mock_response.get('DetailsRecords')

    client = Client(
        base_url=ATA_CENTER_URL
    )
    args = {'id': suspicious_activity_id}

    response = get_suspicious_activity(client, args)

    assert response.outputs == honeytoken_activity
    assert response.outputs_prefix == 'MicrosoftATA.SuspiciousActivity'
    assert response.outputs_key_field == 'Id'


def test_update_suspicious_activity_status(requests_mock):
    """
    Given:
     - Microsoft ATA client

    When:
     - Running update-suspicious-activity-status command

    Then:
     - Ensure command runs successfully
     - Verify expected body is sent in the request
     - Verify command human readable output
    """
    from MicrosoftAdvancedThreatAnalytics import Client, update_suspicious_activity_status

    suspicious_activity_id = '5f183c5283eaed101cd8c309'
    suspicious_activity_status = 'Close'

    requests_mock.post(f'{ATA_CENTER_URL}/suspiciousActivities/{suspicious_activity_id}', status_code=204)

    client = Client(
        base_url=ATA_CENTER_URL,
    )
    args = {
        'id': suspicious_activity_id,
        'status': suspicious_activity_status
    }

    response = update_suspicious_activity_status(client, args)

    assert requests_mock.request_history[0].json() == {'Status': suspicious_activity_status}
    assert response == f'Suspicious activity {suspicious_activity_id} status was ' \
                       f'updated to {suspicious_activity_status} successfully.'


def test_delete_suspicious_activity(requests_mock):
    """
    Given:
     - Microsoft ATA client
     - Suspicious activity ID to delete

    When:
     - Running update-suspicious-activity-status command

    Then:
     - Ensure command runs successfully
     - Verify expected body is sent in the request
     - Verify command human readable output
    """
    from MicrosoftAdvancedThreatAnalytics import Client, update_suspicious_activity_status

    suspicious_activity_id = '5f183c5283eaed101cd8c309'
    suspicious_activity_status = 'Delete'

    requests_mock.delete(f'{ATA_CENTER_URL}/suspiciousActivities/{suspicious_activity_id}', status_code=204)

    client = Client(
        base_url=ATA_CENTER_URL,
    )
    args = {
        'id': suspicious_activity_id,
        'status': suspicious_activity_status
    }

    response = update_suspicious_activity_status(client, args)

    assert requests_mock.request_history[0].json() == {'shouldDeleteSametype': False}
    assert response == f'Suspicious activity {suspicious_activity_id} was deleted successfully.'


def test_get_monitoring_alert(requests_mock):
    """
    Given:
     - Microsoft ATA client

    When:
     - Running get-monitoring-alert command

    Then:
     - Ensure command runs successfully
     - Verify command outputs
    """
    from MicrosoftAdvancedThreatAnalytics import Client, get_monitoring_alert

    mock_response = util_load_json('test_data/monitoring_alert.json')
    requests_mock.get(f'{ATA_CENTER_URL}/monitoringAlerts', json=mock_response)

    client = Client(
        base_url=ATA_CENTER_URL
    )

    response = get_monitoring_alert(client, {})

    assert response.outputs == mock_response
    assert response.outputs_prefix == 'MicrosoftATA.MonitoringAlert'
    assert response.outputs_key_field == 'Id'


def test_entity_get_computer(requests_mock):
    """
    Given:
     - Microsoft ATA client
     - Computer entity ID to retrieve

    When:
     - Running entity-get command

    Then:
     - Ensure command runs successfully
     - Verify command outputs
    """
    from MicrosoftAdvancedThreatAnalytics import Client, get_entity

    computer_entity_id = '6b0e48f5-6c63-449c-8b6f-c749e18e28b3'

    mock_response = util_load_json('test_data/entity_computer.json')
    requests_mock.get(f'{ATA_CENTER_URL}/uniqueEntities/{computer_entity_id}', json=mock_response)
    profile_mock_response = util_load_json('test_data/entity_profile_computer.json')
    requests_mock.get(f'{ATA_CENTER_URL}/uniqueEntities/{computer_entity_id}/profile', json=profile_mock_response)
    mock_response['Profile'] = profile_mock_response

    client = Client(
        base_url=ATA_CENTER_URL
    )
    args = {'id': computer_entity_id}

    response = get_entity(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == 'MicrosoftATA.Entity'
    assert response.outputs_key_field == 'Id'


def test_fetch_incidents(requests_mock):
    """
    Given:
     - Microsoft ATA client

    When:
     - Running fetch incidents

    Then:
     - Ensure fetch runs successfully
     - Verify expected incident is returned (only DnsReconnaissanceSuspiciousActivity)
    """
    from MicrosoftAdvancedThreatAnalytics import Client, fetch_incidents

    mock_response = util_load_json('test_data/suspicious_activity.json')
    requests_mock.get(f'{ATA_CENTER_URL}/suspiciousActivities/', json=mock_response)

    client = Client(base_url=ATA_CENTER_URL)

    response = fetch_incidents(
        client,
        last_run={'last_fetch': '2020-08-08T13:17:05.9092818Z'},
        first_fetch_time='1 day',
        max_results=50,
        activity_status_to_fetch=['Open'],
        min_severity=1,
        activity_type_to_fetch=[]
    )
    assert response[0] == {'last_fetch': '2020-08-09T09:18:22.5496318Z'}
    assert response[1] == [{
        'name': 'DnsReconnaissanceSuspiciousActivity - 5f2fbf7283eaed101cf41361',
        'occurred': '2020-08-09T09:18:22.5496318Z',
        'rawJSON': json.dumps(mock_response[0])
    }]
