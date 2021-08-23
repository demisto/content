import json
from datetime import datetime
import pytest
import demistomock as demisto
from CommonServerPython import DemistoException, EntryType
from SophosCentral import Client

BASE_URL = 'https://api-eu02.central.sophos.com'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'


def init_mock_client(requests_mock, integration_context=None):
    integration_context = integration_context or {}
    mock_client_data = load_mock_response('client_data.json')
    requests_mock.get('https://api.central.sophos.com/whoami/v1', json=mock_client_data)
    return Client(bearer_token='this', client_id='is', verify=False,
                  client_secret='Cactus', proxy=False, integration_context=integration_context)


def load_mock_response(file_name: str) -> dict:
    """
    Load one of the mock responses to be used for assertion.

    Args:
        file_name (str): Name of the mock response JSON file to return.
    """
    with open(f'test_data/{file_name}', mode='r', encoding='utf-8') as json_file:
        return json.loads(json_file.read())


def test_sophos_central_alert_list_command(requests_mock) -> None:
    """
    Scenario: List alerts
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_alert_list is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from SophosCentral import sophos_central_alert_list_command
    mock_response = load_mock_response('alert_list.json')
    requests_mock.get(f'{BASE_URL}/common/v1/alerts', json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_alert_list_command(client, {'limit': '14'})
    assert len(result.outputs) == 3
    assert result.outputs_prefix == 'SophosCentral.Alert'
    assert result.outputs[0].get('id') == '56931431-9faf-480c-ba1d-8d7541eae259'


def test_sophos_central_alert_get_command(requests_mock) -> None:
    """
    Scenario: Get a single alert.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_alert_get is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from SophosCentral import sophos_central_alert_get_command
    mock_response = load_mock_response('alert_single.json')
    alert_id = '56931431-9faf-480c-ba1d-8d7541eae259'
    requests_mock.get(f'{BASE_URL}/common/v1/alerts/{alert_id}', json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_alert_get_command(client, {'alert_id': alert_id})
    assert result.outputs_prefix == 'SophosCentral.Alert'
    assert result.outputs.get('id') == '70e3781d-c0f6-4e72-b6aa-3c3ef21f3dbb'


def test_sophos_central_alert_action_command(requests_mock) -> None:
    """
    Scenario: Take an action against one or more alerts.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_alert_action is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from SophosCentral import sophos_central_alert_action_command
    mock_response = load_mock_response('alert_action.json')
    alert_id = '56931431-9faf-480c-ba1d-8d7541eae259'
    requests_mock.post(f'{BASE_URL}/common/v1/alerts/{alert_id}/actions', json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_alert_action_command(client, {'alert_id': alert_id,
                                                          'action': 'clearThreat', 'message': 'b'})
    assert len(result.outputs) == 1
    assert result.outputs_prefix == 'SophosCentral.AlertAction'
    assert result.outputs[0].get('alertId') == '25c7b132-56d8-4bce-9d1b-6c51a7eb3c78'

    alert_ids = ['56931431-9faf-480c-ba1d-8d7541eae259'] * 3
    result = sophos_central_alert_action_command(client, {'alert_id': alert_ids,
                                                          'action': 'clearThreat', 'message': 'b'})
    assert len(result.outputs) == 3


def test_sophos_central_alert_search_command(requests_mock) -> None:
    """
    Scenario: Search for specific alerts.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_alert_search is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from SophosCentral import sophos_central_alert_search_command
    mock_response = load_mock_response('alert_list.json')
    requests_mock.post(f'{BASE_URL}/common/v1/alerts/search', json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_alert_search_command(client, {'limit': '14'})
    assert len(result.outputs) == 3
    assert result.outputs_prefix == 'SophosCentral.Alert'
    assert result.outputs[0].get('id') == '56931431-9faf-480c-ba1d-8d7541eae259'


def test_sophos_central_endpoint_list_command(requests_mock) -> None:
    """
    Scenario: List endpoints.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_endpoint_scan is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from SophosCentral import sophos_central_endpoint_list_command
    mock_response = load_mock_response('endpoint_list.json')
    requests_mock.get(f'{BASE_URL}/endpoint/v1/endpoints', json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_endpoint_list_command(client, {'limit': '17'})
    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'SophosCentral.Endpoint'
    assert result.outputs[0].get('id') == '6e9567ea-bb50-40c5-9f12-42eb308e4c9b'


def test_sophos_central_endpoint_scan_command(requests_mock) -> None:
    """
    Scenario: Scan one or more endpoints.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_endpoint_scan is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from SophosCentral import sophos_central_endpoint_scan_command
    mock_response = load_mock_response('endpoint_scan.json')
    endpoint_id = '6e9567ea-bb50-40c5-9f12-42eb308e4c9b'
    requests_mock.post(f'{BASE_URL}/endpoint/v1/endpoints/{endpoint_id}/scans', json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_endpoint_scan_command(client, {'endpoint_id': endpoint_id})
    assert len(result.outputs) == 1
    assert result.outputs_prefix == 'SophosCentral.EndpointScan'
    assert result.outputs[0].get('id') == '6e9567ea-bb50-40c5-9f12-42eb308e4c9b'

    endpoint_ids = ['6e9567ea-bb50-40c5-9f12-42eb308e4c9b'] * 3
    result = sophos_central_endpoint_scan_command(client, {'endpoint_id': endpoint_ids})
    assert len(result.outputs) == 3


def test_sophos_central_endpoint_tamper_get_command(requests_mock) -> None:
    """
    Scenario: Get tamper protection information for one or more endpoints.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_endpoint_tamper_get is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from SophosCentral import sophos_central_endpoint_tamper_get_command
    mock_response = load_mock_response('endpoint_tamper.json')
    endpoint_id = '6e9567ea-bb50-40c5-9f12-42eb308e4c9b'
    requests_mock.get(f'{BASE_URL}/endpoint/v1/endpoints/{endpoint_id}/tamper-protection',
                      json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_endpoint_tamper_get_command(client, {'endpoint_id': endpoint_id,
                                                                 'get_password': True})
    assert len(result.outputs) == 1
    assert result.outputs_prefix == 'SophosCentral.EndpointTamper'
    assert result.outputs[0].get('password') == '1234567890'

    endpoint_ids = ['6e9567ea-bb50-40c5-9f12-42eb308e4c9b'] * 3
    result = sophos_central_endpoint_tamper_get_command(client, {'endpoint_id': endpoint_ids,
                                                                 'get_password': True})
    assert len(result.outputs) == 3


def test_sophos_central_endpoint_tamper_update_command(requests_mock) -> None:
    """
    Scenario: Update tamper protection information for one or more endpoints.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_endpoint_tamper_update is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from SophosCentral import sophos_central_endpoint_tamper_update_command
    mock_response = load_mock_response('endpoint_tamper.json')
    endpoint_id = '6e9567ea-bb50-40c5-9f12-42eb308e4c9b'
    requests_mock.post(f'{BASE_URL}/endpoint/v1/endpoints/{endpoint_id}/tamper-protection',
                       json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_endpoint_tamper_update_command(client, {'endpoint_id': endpoint_id,
                                                                    'get_password': True})
    assert len(result.outputs) == 1
    assert result.outputs_prefix == 'SophosCentral.EndpointTamper'
    assert result.outputs[0].get('password') == '1234567890'

    endpoint_ids = ['6e9567ea-bb50-40c5-9f12-42eb308e4c9b'] * 3
    result = sophos_central_endpoint_tamper_update_command(client, {'endpoint_id': endpoint_ids,
                                                                    'get_password': True})
    assert len(result.outputs) == 3


def test_sophos_central_allowed_item_list_command(requests_mock) -> None:
    """
    Scenario: List allowed items.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_allowed_item_list is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from SophosCentral import sophos_central_allowed_item_list_command
    mock_response = load_mock_response('allowed_item_list.json')
    requests_mock.get(f'{BASE_URL}/endpoint/v1/settings/allowed-items',
                      json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_allowed_item_list_command(client, {'page_size': '30',
                                                               'page': '1'})
    assert len(result.outputs) == 3
    assert result.outputs_prefix == 'SophosCentral.AllowedItem'
    assert result.outputs[0].get('id') == 'a28c7ee1-8ad9-4b5c-8f15-4d913436ce18'


def test_sophos_central_allowed_item_get_command(requests_mock) -> None:
    """
    Scenario: Get a single allowed item.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_allowed_item_get is called
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from SophosCentral import sophos_central_allowed_item_get_command
    mock_response = load_mock_response('allowed_item_single.json')
    allowed_item_id = 'a28c7ee1-8ad9-4b5c-8f15-4d913436ce18'
    requests_mock.get(f'{BASE_URL}/endpoint/v1/settings/allowed-items/{allowed_item_id}',
                      json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_allowed_item_get_command(client, {'allowed_item_id': allowed_item_id})
    assert result.outputs_prefix == 'SophosCentral.AllowedItem'
    assert result.outputs.get('id') == '811fa316-d485-4499-a979-3e1c0a89f1fd'


def test_sophos_central_allowed_item_add_command(requests_mock) -> None:
    """
    Scenario: Add an allowed item.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_allowed_item_list is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from SophosCentral import sophos_central_allowed_item_add_command
    mock_response = load_mock_response('allowed_item_single.json')
    requests_mock.post(f'{BASE_URL}/endpoint/v1/settings/allowed-items',
                       json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_allowed_item_add_command(client, {})
    assert result.outputs_prefix == 'SophosCentral.AllowedItem'
    assert result.outputs.get('id') == '811fa316-d485-4499-a979-3e1c0a89f1fd'


def test_sophos_central_allowed_item_update_command(requests_mock) -> None:
    """
    Scenario: Update an existing allowed item.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_allowed_item_update is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from SophosCentral import sophos_central_allowed_item_update_command
    mock_response = load_mock_response('allowed_item_single.json')
    allowed_item_id = 'a28c7ee1-8ad9-4b5c-8f15-4d913436ce18'
    requests_mock.patch(f'{BASE_URL}/endpoint/v1/settings/allowed-items/{allowed_item_id}',
                        json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_allowed_item_update_command(client,
                                                        {'allowed_item_id': allowed_item_id})
    assert result.outputs_prefix == 'SophosCentral.AllowedItem'
    assert result.outputs.get('id') == '811fa316-d485-4499-a979-3e1c0a89f1fd'


def test_sophos_central_allowed_item_delete_command(requests_mock) -> None:
    """
    Scenario: Delete an existing allowed item.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_allowed_item_delete is called.
    Then:
     - Ensure the output is correct.
     - Ensure outputs prefix is correct.
    """
    from SophosCentral import sophos_central_allowed_item_delete_command
    mock_response = load_mock_response('deleted.json')
    allowed_item_id = 'a28c7ee1-8ad9-4b5c-8f15-4d913436ce18'
    requests_mock.delete(f'{BASE_URL}/endpoint/v1/settings/allowed-items/{allowed_item_id}',
                         json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_allowed_item_delete_command(client,
                                                        {'allowed_item_id': allowed_item_id})
    assert result.outputs == {'deletedItemId': allowed_item_id}
    assert result.outputs_prefix == 'SophosCentral.DeletedAllowedItem'


def test_sophos_central_blocked_item_list_command(requests_mock) -> None:
    """
    Scenario: List blocked items.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_blocked_item_list is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from SophosCentral import sophos_central_blocked_item_list_command
    mock_response = load_mock_response('blocked_item_list.json')
    requests_mock.get(f'{BASE_URL}/endpoint/v1/settings/blocked-items',
                      json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_blocked_item_list_command(client, {'page_size': '30',
                                                               'page': '1'})
    assert len(result.outputs) == 3
    assert result.outputs_prefix == 'SophosCentral.BlockedItem'
    assert result.outputs[0].get('id') == '6b0d0fb1-4254-45b0-896a-2eb36d0e2368'


def test_sophos_central_blocked_item_get_command(requests_mock) -> None:
    """
    Scenario: Get a single blocked item.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_blocked_item_get is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from SophosCentral import sophos_central_blocked_item_get_command
    mock_response = load_mock_response('blocked_item_single.json')
    blocked_item_id = 'a28c7ee1-8ad9-4b5c-8f15-4d913436ce18'
    requests_mock.get(f'{BASE_URL}/endpoint/v1/settings/blocked-items/{blocked_item_id}',
                      json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_blocked_item_get_command(client, {'blocked_item_id': blocked_item_id})
    assert result.outputs_prefix == 'SophosCentral.BlockedItem'
    assert result.outputs.get('id') == '998ffd3d-4a44-40da-8c1f-b18ace4ff735'


def test_sophos_central_blocked_item_add_command(requests_mock) -> None:
    """
    Scenario: Add a new blocked item.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_blocked_item_add is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from SophosCentral import sophos_central_blocked_item_add_command
    mock_response = load_mock_response('blocked_item_single.json')
    requests_mock.post(f'{BASE_URL}/endpoint/v1/settings/blocked-items',
                       json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_blocked_item_add_command(client, {})
    assert result.outputs_prefix == 'SophosCentral.BlockedItem'
    assert result.outputs.get('id') == '998ffd3d-4a44-40da-8c1f-b18ace4ff735'


def test_sophos_central_blocked_item_delete_command(requests_mock) -> None:
    """
    Scenario: Delete an existing blocked item.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_blocked_item_delete is called.
    Then:
     - Ensure the output is correct.
     - Ensure outputs prefix is correct.
    """
    from SophosCentral import sophos_central_blocked_item_delete_command
    mock_response = load_mock_response('deleted.json')
    blocked_item_id = 'a28c7ee1-8ad9-4b5c-8f15-4d913436ce18'
    requests_mock.delete(f'{BASE_URL}/endpoint/v1/settings/blocked-items/{blocked_item_id}',
                         json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_blocked_item_delete_command(client,
                                                        {'blocked_item_id': blocked_item_id})
    assert result.outputs == {'deletedItemId': blocked_item_id}
    assert result.outputs_prefix == 'SophosCentral.DeletedBlockedItem'


def test_sophos_central_scan_exclusion_list_command(requests_mock) -> None:
    """
    Scenario: List scan exclusions.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_scan_exclusion_list is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from SophosCentral import sophos_central_scan_exclusion_list_command
    mock_response = load_mock_response('scan_exclusion_list.json')
    requests_mock.get(f'{BASE_URL}/endpoint/v1/settings/exclusions/scanning',
                      json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_scan_exclusion_list_command(client, {'page_size': '30',
                                                                 'page': '1'})
    assert len(result.outputs) == 3
    assert result.outputs_prefix == 'SophosCentral.ScanExclusion'
    assert result.outputs[0].get('id') == '369b0956-a7b6-44fc-b1cc-bd7b3279c663'


def test_sophos_central_scan_exclusion_get_command(requests_mock) -> None:
    """
    Scenario: Get a single scan exclusion.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_scan_exclusion_get is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from SophosCentral import sophos_central_scan_exclusion_get_command
    mock_response = load_mock_response('scan_exclusion_single.json')
    scan_exclusion_id = '16bac29f-17a4-4c3a-9370-8c5968c5ac7d'
    requests_mock.get(f'{BASE_URL}/endpoint/v1/settings/exclusions/scanning/{scan_exclusion_id}',
                      json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_scan_exclusion_get_command(client, {'exclusion_id': scan_exclusion_id})
    assert result.outputs_prefix == 'SophosCentral.ScanExclusion'
    assert result.outputs.get('id') == '16bac29f-17a4-4c3a-9370-8c5968c5ac7d'


def test_sophos_central_scan_exclusion_add_command(requests_mock) -> None:
    """
    Scenario: Add a new scan exclusion.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_scan_exclusion_add is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from SophosCentral import sophos_central_scan_exclusion_add_command
    mock_response = load_mock_response('scan_exclusion_single.json')
    requests_mock.post(f'{BASE_URL}/endpoint/v1/settings/exclusions/scanning',
                       json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_scan_exclusion_add_command(client, {})
    assert result.outputs_prefix == 'SophosCentral.ScanExclusion'
    assert result.outputs.get('id') == '16bac29f-17a4-4c3a-9370-8c5968c5ac7d'


def test_sophos_central_scan_exclusion_update_command(requests_mock) -> None:
    """
    Scenario: Update an existing scan exclusion.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_scan_exclusion_update is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from SophosCentral import sophos_central_scan_exclusion_update_command
    mock_response = load_mock_response('scan_exclusion_single.json')
    scan_exclusion_id = '16bac29f-17a4-4c3a-9370-8c5968c5ac7d'
    requests_mock.patch(f'{BASE_URL}/endpoint/v1/settings/exclusions/scanning/{scan_exclusion_id}',
                        json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_scan_exclusion_update_command(client,
                                                          {'exclusion_id': scan_exclusion_id})
    assert result.outputs_prefix == 'SophosCentral.ScanExclusion'
    assert result.outputs.get('id') == '16bac29f-17a4-4c3a-9370-8c5968c5ac7d'


def test_sophos_central_scan_exclusion_delete_command(requests_mock) -> None:
    """
    Scenario: Delete an existing scan exclusion.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_scan_exclusion_update is called.
    Then:
     - Ensure the output is correct.
     - Ensure outputs prefix is correct.
    """
    from SophosCentral import sophos_central_scan_exclusion_delete_command
    mock_response = load_mock_response('deleted.json')
    scan_exclusion_id = '16bac29f-17a4-4c3a-9370-8c5968c5ac7d'
    requests_mock.delete(f'{BASE_URL}/endpoint/v1/settings/exclusions/scanning/{scan_exclusion_id}',
                         json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_scan_exclusion_delete_command(client,
                                                          {'exclusion_id': scan_exclusion_id})
    assert result.outputs == {'deletedExclusionId': scan_exclusion_id}
    assert result.outputs_prefix == 'SophosCentral.DeletedScanExclusion'


def test_sophos_central_exploit_mitigation_list_command(requests_mock) -> None:
    """
    Scenario: List all exploit mitigations.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_exploit_mitigation_list is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from SophosCentral import sophos_central_exploit_mitigation_list_command
    mock_response = load_mock_response('exploit_mitigation_list.json')
    requests_mock.get(f'{BASE_URL}/endpoint/v1/settings/exploit-mitigation/applications',
                      json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_exploit_mitigation_list_command(client, {'page_size': '30',
                                                                     'page': '1'})
    assert len(result.outputs) == 3
    assert result.outputs_prefix == 'SophosCentral.ExploitMitigation'
    assert result.outputs[0].get('id') == '30fbb4cf-2961-4ffc-937e-97c57f468838'


def test_sophos_central_exploit_mitigation_get_command(requests_mock) -> None:
    """
    Scenario: Get a single exploit mitigation.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_exploit_mitigation_get is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from SophosCentral import sophos_central_exploit_mitigation_get_command
    mock_response = load_mock_response('exploit_mitigation_single.json')
    exploit_id = 'c2824651-26c1-4470-addf-7b6bb6ac90b4'
    requests_mock.get(f'{BASE_URL}/endpoint/v1/settings/'
                      f'exploit-mitigation/applications/{exploit_id}', json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_exploit_mitigation_get_command(client, {'mitigation_id': exploit_id})
    assert result.outputs_prefix == 'SophosCentral.ExploitMitigation'
    assert result.outputs.get('id') == 'c2824651-26c1-4470-addf-7b6bb6ac90b4'


def test_sophos_central_exploit_mitigation_add_command(requests_mock) -> None:
    """
    Scenario: Add a new exploit mitigation.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_exploit_mitigation_add is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from SophosCentral import sophos_central_exploit_mitigation_add_command
    mock_response = load_mock_response('exploit_mitigation_single.json')
    exploit_id = 'c2824651-26c1-4470-addf-7b6bb6ac90b4'
    requests_mock.post(f'{BASE_URL}/endpoint/v1/settings/exploit-mitigation/applications',
                       json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_exploit_mitigation_add_command(client, {'mitigation_id': exploit_id})
    assert result.outputs_prefix == 'SophosCentral.ExploitMitigation'
    assert result.outputs.get('id') == 'c2824651-26c1-4470-addf-7b6bb6ac90b4'


def test_sophos_central_exploit_mitigation_update_command(requests_mock) -> None:
    """
    Scenario: Update an existing exploit mitigation.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_exploit_mitigation_update is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from SophosCentral import sophos_central_exploit_mitigation_update_command
    mock_response = load_mock_response('exploit_mitigation_single.json')
    exploit_id = 'c2824651-26c1-4470-addf-7b6bb6ac90b4'
    requests_mock.patch(f'{BASE_URL}/endpoint/v1/settings/'
                        f'exploit-mitigation/applications/{exploit_id}',
                        json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_exploit_mitigation_update_command(client, {'mitigation_id': exploit_id})
    assert result.outputs_prefix == 'SophosCentral.ExploitMitigation'
    assert result.outputs.get('id') == 'c2824651-26c1-4470-addf-7b6bb6ac90b4'


def test_sophos_central_exploit_mitigation_delete_command(requests_mock) -> None:
    """
    Scenario: Delete an existing exploit mitigation.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_exploit_mitigation_delete is called.
    Then:
     - Ensure the output is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from SophosCentral import sophos_central_exploit_mitigation_delete_command
    mock_response = load_mock_response('deleted.json')
    exploit_id = 'c2824651-26c1-4470-addf-7b6bb6ac90b4'
    requests_mock.delete(f'{BASE_URL}/endpoint/v1/settings/'
                         f'exploit-mitigation/applications/{exploit_id}',
                         json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_exploit_mitigation_delete_command(client, {'mitigation_id': exploit_id})
    assert result.outputs == {'deletedMitigationId': exploit_id}
    assert result.outputs_prefix == 'SophosCentral.DeletedExploitMitigation'


def test_sophos_central_detected_exploit_list_command(requests_mock) -> None:
    """
    Scenario: List all detected exploits.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_detected_exploit_list is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from SophosCentral import sophos_central_detected_exploit_list_command
    mock_response = load_mock_response('detected_exploit_list.json')
    requests_mock.get(f'{BASE_URL}/endpoint/v1/settings/exploit-mitigation/detected-exploits',
                      json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_detected_exploit_list_command(client, {'page_size': '30',
                                                                   'page': '1'})
    assert len(result.outputs) == 3
    assert result.outputs_prefix == 'SophosCentral.DetectedExploit'
    assert result.outputs[0].get('id') == 'b81aac51-2fc0-ab6a-asdf-7b6bb6ac90b4'


def test_sophos_central_detected_exploit_get_command(requests_mock) -> None:
    """
    Scenario: Get a single detected exploit.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_detected_exploit_get is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from SophosCentral import sophos_central_detected_exploit_get_command
    mock_response = load_mock_response('detected_exploit_single.json')
    exploit_id = 'b81aac51-2fc0-ab6a-asdf-7b6bb6ac90b4'
    requests_mock.get(f'{BASE_URL}/endpoint/v1/settings/'
                      f'exploit-mitigation/detected-exploits/{exploit_id}', json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_detected_exploit_get_command(client,
                                                         {'detected_exploit_id': exploit_id})
    assert result.outputs_prefix == 'SophosCentral.DetectedExploit'
    assert result.outputs.get('id') == 'b81aac51-2fc0-ab6a-asdf-7b6bb6ac90b4'


def test_retrieve_jwt_token(requests_mock) -> None:
    """
    Scenario: Get a JWT token with or without a saved one in the integration context.
    Given:
     - User has provided valid credentials.
    When:
     - Every time before a command is run.
    Then:
     - Ensure the JWT token is correct (same as either the mocked context integration or response).
    """
    from SophosCentral import retrieve_jwt_token
    mock_response = load_mock_response('auth_token.json')
    requests_mock.post('https://id.sophos.com/api/v2/oauth2/token', json=mock_response)

    result = retrieve_jwt_token('a', 'b', {})
    assert result == 'xxxxxxx'

    result = retrieve_jwt_token('a', 'b', {'bearer_token': 'aaaa', 'valid_until': 999999999999999})
    assert result == 'aaaa'


def test_get_client_data(requests_mock) -> None:
    """
    Scenario: Get the client data before executing a command.
    Given:
     - User has provided valid credentials.
     - JWT token has been returned by retrieve_jwt_token().
    When:
     - Every time after retrieve_jwt_token() and before any command.
    Then:
     - Ensure base URL is correct according to mock response.
     - Ensure headers are correct according to given fake JWT token and mock response.
    """
    from SophosCentral import Client
    mock_response = load_mock_response('client_data.json')
    requests_mock.get('https://api.central.sophos.com/whoami/v1', json=mock_response)

    headers, base_url = Client.get_client_data('aaaa')
    assert base_url == 'https://api-eu02.central.sophos.com/'
    assert headers == {'Authorization': 'Bearer aaaa',
                       'X-Tenant-ID': '11f104c5-cc4a-4a9f-bb9c-632c936dfb9f'}


class TestFetchIncidents:
    @staticmethod
    def test_sanity(requests_mock) -> None:
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
        from SophosCentral import fetch_incidents
        client = init_mock_client(requests_mock)
        mock_response = load_mock_response('alert_list.json')
        requests_mock.post(f'{BASE_URL}/common/v1/alerts/search', json=mock_response)
        last_fetch, incidents = fetch_incidents(client, {'last_fetch': 1}, '1 days', ['x'], ['x'], '50')
        wanted_time = datetime.timestamp(datetime.strptime('2020-11-04T09:31:19.895Z', DATE_FORMAT))
        assert last_fetch.get('last_fetch') == wanted_time * 1000
        assert len(incidents) == 3
        assert incidents[0].get('name') == 'Sophos Central Alert 56931431-9faf-480c-ba1d-8d7541eae259'

    @staticmethod
    def test_no_last_fetch(requests_mock):
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
        from SophosCentral import fetch_incidents
        client = init_mock_client(requests_mock)
        mock_response = load_mock_response('alert_list.json')
        requests_mock.post(f'{BASE_URL}/common/v1/alerts/search', json=mock_response)
        last_fetch, incidents = fetch_incidents(client, {}, '12 years', ['x'], ['x'], '50')
        wanted_time = datetime.timestamp(datetime.strptime('2020-11-04T09:31:19.895Z', DATE_FORMAT))
        assert last_fetch.get('last_fetch') == wanted_time * 1000
        assert len(incidents) == 3
        assert incidents[0].get('name') == 'Sophos Central Alert 56931431-9faf-480c-ba1d-8d7541eae259'

    @staticmethod
    def test_empty_response(requests_mock):
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
        from SophosCentral import fetch_incidents
        client = init_mock_client(requests_mock)
        mock_response = load_mock_response('empty.json')
        requests_mock.post(f'{BASE_URL}/common/v1/alerts/search', json=mock_response)
        last_fetch, incidents = fetch_incidents(client, {'last_fetch': 100000000}, '3 days', ['x'],
                                                ['x'], '50')
        assert last_fetch.get('last_fetch') == 100000001
        assert len(incidents) == 0


class TestMain:
    @staticmethod
    def init_mocks(mocker, requests_mock, command):
        init_mock_client(requests_mock)
        mock_response = load_mock_response('auth_token.json')
        requests_mock.post('https://id.sophos.com/api/v2/oauth2/token', json=mock_response)

        mocker.patch.object(demisto, 'command', return_value=command)

    @staticmethod
    def test_fetch_incident(mocker, requests_mock):
        """
        Scenario: Fetch incidents from main (same scenarion as TestFetchIncident:test_sanity).

        Given:
        - User has provided valid credentials.
        - Headers and JWT token have been set.

        When:
        - Every time fetch_incident is called (either timed or by command).

        Then:
        - Ensure number of incidents is correct.
        - Ensure last_fetch is correctly configured according to mock response.

        """
        from SophosCentral import main
        TestMain.init_mocks(mocker, requests_mock, 'fetch-incidents')
        mock_response = load_mock_response('alert_list.json')
        requests_mock.post(f'{BASE_URL}/common/v1/alerts/search', json=mock_response)
        mocker.patch.object(demisto, 'params', return_value={
            'first_fetch_time': '1 days',
            'fetch_severity': ['x'],
            'fetch_category': ['x'],
            'max_fetch': '50',
        })
        mocker.patch.object(demisto, 'getLastRun', return_value={'last_fetch': 1})
        demisto_incidents_mock = mocker.patch.object(demisto, 'incidents')
        demisto_set_last_run_mock = mocker.patch.object(demisto, 'setLastRun')

        main()

        assert demisto_set_last_run_mock.call_count == 1
        assert demisto_incidents_mock.call_count == 1
        incidents = demisto_incidents_mock.call_args.args[0]
        last_fetch = demisto_set_last_run_mock.call_args.args[0]

        wanted_time = datetime.timestamp(datetime.strptime('2020-11-04T09:31:19.895Z', DATE_FORMAT))
        assert last_fetch.get('last_fetch') == wanted_time * 1000
        assert len(incidents) == 3
        assert incidents[0].get('name') == 'Sophos Central Alert 56931431-9faf-480c-ba1d-8d7541eae259'

    @staticmethod
    def test_sophos_central_detected_exploit_list_command(mocker, requests_mock) -> None:
        """
        Scenario: List all detected exploits from main
            (same scenario as test_sophos_central_detected_exploit_list_command).

        Given:
        - User has provided valid credentials.
        - Headers and JWT token have been set.

        When:
        - sophos_central_detected_exploit_list is called.

        Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.

        """
        from SophosCentral import main
        TestMain.init_mocks(mocker, requests_mock, 'sophos-central-detected-exploit-list')

        mock_response = load_mock_response('detected_exploit_list.json')
        requests_mock.get(f'{BASE_URL}/endpoint/v1/settings/exploit-mitigation/detected-exploits',
                          json=mock_response)
        mocker.patch.object(demisto, 'args', return_value={
            'page_size': '30',
            'page': '1',
        })
        demisto_results_mock = mocker.patch.object(demisto, 'results')

        main()

        entry_context = demisto_results_mock.call_args.args[0]['EntryContext']
        output = next(iter(entry_context.values()))
        assert len(output) == 3
        assert list(entry_context.keys())[0].startswith('SophosCentral.DetectedExploit')
        assert output[0].get('id') == 'b81aac51-2fc0-ab6a-asdf-7b6bb6ac90b4'

    @staticmethod
    def test_invalid_command(mocker, requests_mock):
        from SophosCentral import main
        TestMain.init_mocks(mocker, requests_mock, 'not-a-command')
        demisto_results_mock = mocker.patch.object(demisto, 'results')

        with pytest.raises(SystemExit):
            main()

        error_entry = demisto_results_mock.call_args.args[0]
        assert error_entry['Type'] == EntryType.ERROR
        assert 'The "not-a-command" command was not implemented.' in error_entry['Contents']


def test_validate_item_fields() -> None:
    """
    Scenario: Validate arguments for creating / updating items before sending to API.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - When add/update_item is called.
    Then:
     - Ensure correct arguments do not raise an error (e.g certificateSigner type with a
     value in the corresponding variable.)
     - Ensure faulty arguments do raise an error (e.g. certificateSigner
     type without a corresponding value for it).
    """
    from SophosCentral import validate_item_fields
    args = {'item_type': 'certificateSigner', 'certificate_signer': 'xxx'}
    validate_item_fields(args)
    args = {'item_type': 'certificateSigner', 'path': 'xxx'}
    with pytest.raises(DemistoException):
        validate_item_fields(args)


@pytest.mark.parametrize(
    'input_id, expected',
    [
        ('', ''),
        ('ba', 'ab'),
        ('aabb', 'aabb'),
        ('badcxwzy', 'abcdwxyz'),
        ('badc-fehgji-xwzy', 'abcd-efghij-wxyz'),
    ]
)
def test_flip_chars(input_id, expected) -> None:
    from SophosCentral import flip_chars
    assert flip_chars(input_id) == expected


class TestCreateAlertOutput:
    @staticmethod
    def test_failure_person_request(requests_mock):
        """
        Scenario: Creating an alert output.

        Given:
        - an alert with a person and managed agent object set.
        - an error while trying to get the person data.

        When:
        - creating a context object for an alert.

        Then:
        - an empty string will be returned.

        """
        from SophosCentral import create_alert_output
        client = init_mock_client(requests_mock)
        requests_mock.get(f'{BASE_URL}/common/v1/directory/users/5d407889-8659-46ab-86c5-4f227302df78', exc=ValueError)

        alert = load_mock_response('alert_single.json')
        output = create_alert_output(client, alert, ['id', 'name'])

        assert output['personName'] == ''

    @staticmethod
    def test_with_person_cache(requests_mock):
        """
        Scenario: Creating an alert output.

        Given:
        - an alert with a person and managed agent object set.
        - the person info appear in the cache.

        When:
        - creating a context object for an alert.

        Then:
        - get the name from the cache.

        """
        from SophosCentral import create_alert_output
        client = init_mock_client(requests_mock, {'person_mapping': {'5d407889-8659-46ab-86c5-4f227302df78': 'Cactus'}})
        requests_mock.get(f'{BASE_URL}/common/v1/directory/users/5d407889-8659-46ab-86c5-4f227302df78', exc=ValueError)

        alert = load_mock_response('alert_single.json')
        output = create_alert_output(client, alert, ['id', 'name'])

        assert output['personName'] == 'Cactus'

    @staticmethod
    def test_without_relevant_person_cache(requests_mock):
        """
        Scenario: Creating an alert output.

        Given:
        - an alert with a person and managed agent object set.
        - the person info doesn't appear in the cache.

        When:
        - creating a context object for an alert.

        Then:
        - get the name using the API.

        """
        from SophosCentral import create_alert_output
        client = init_mock_client(requests_mock, {'person_mapping': {'12345678-1337-1337-1337-1234567890ab': 'Not Cactus'}})
        mock_response = load_mock_response('person.json')
        requests_mock.get(f'{BASE_URL}/common/v1/directory/users/5d407889-8659-46ab-86c5-4f227302df78', json=mock_response)

        alert = load_mock_response('alert_single.json')
        output = create_alert_output(client, alert, ['id', 'name'])

        assert output['personName'] == r'Group\Cactus'
        assert '5d407889-8659-46ab-86c5-4f227302df78' in client.integration_context['person_mapping']

    @staticmethod
    def test_with_managed_agent_cache(requests_mock):
        """
        Scenario: Creating an alert output.

        Given:
        - an alert with a person and managed agent object set.
        - the managed agent info appear in the cache.

        When:
        - creating a context object for an alert.

        Then:
        - get the name from the cache.

        """
        from SophosCentral import create_alert_output
        client = init_mock_client(requests_mock, {
            'managed_agent_mapping': {'6e9567ea-bb50-40c5-9f12-42eb308e4c9b': 'MyComputer'}})

        alert = load_mock_response('alert_single.json')
        output = create_alert_output(client, alert, ['id', 'name'])

        # print(output)

        assert output['managedAgentName'] == 'MyComputer'
