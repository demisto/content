import json
from datetime import datetime
from pytest import raises
from CommonServerPython import DemistoException

BASE_URL = 'https://api-eu02.central.sophos.com'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'


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
     - Ensure the number of fields in each output is correct.
     - Ensure outputs prefix is correct.
     - Ensure the raw response matches the mocked API response.
    """
    from SophosCentral import Client, sophos_central_alert_list_command
    mock_response = load_mock_response('alert_list.json')
    requests_mock.get(f'{BASE_URL}/common/v1/alerts', json=mock_response)
    client = Client(base_url=BASE_URL, headers={'a': 'b'}, verify=False, client_id='a',
                    client_secret='b', proxy=False)

    result = sophos_central_alert_list_command(client, {'limit': '50'})
    assert len(result.outputs) == 3
    assert len(result.outputs[0]) == 14
    assert result.outputs_prefix == 'SophosCentral.Alert'
    assert result.raw_response == mock_response


def test_sophos_central_alert_get_command(requests_mock) -> None:
    """
    Scenario: Get a single alert.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_alert_get is called.
    Then:
     - Ensure the number of fields in each output is correct.
     - Ensure outputs prefix is correct.
     - Ensure the raw response matches the mocked API response.
    """
    from SophosCentral import Client, sophos_central_alert_get_command
    mock_response = load_mock_response('alert_single.json')
    alert_id = '56931431-9faf-480c-ba1d-8d7541eae259'
    requests_mock.get(f'{BASE_URL}/common/v1/alerts/{alert_id}', json=mock_response)
    client = Client(base_url=BASE_URL, headers={'a': 'b'}, verify=False, client_id='a',
                    client_secret='b', proxy=False)

    result = sophos_central_alert_get_command(client, {'alert_id': alert_id})
    assert len(result.outputs) == 14
    assert result.outputs_prefix == 'SophosCentral.Alert'
    assert result.raw_response == mock_response


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
     - Ensure the number of fields in each output is correct.
     - Ensure outputs prefix is correct.
     - Ensure the raw response matches the mocked API response.
    """
    from SophosCentral import Client, sophos_central_alert_action_command
    mock_response = load_mock_response('alert_action.json')
    alert_id = '56931431-9faf-480c-ba1d-8d7541eae259'
    requests_mock.post(f'{BASE_URL}/common/v1/alerts/{alert_id}/actions', json=mock_response)
    client = Client(base_url=BASE_URL, headers={'a': 'b'}, verify=False, client_id='a',
                    client_secret='b', proxy=False)

    result = sophos_central_alert_action_command(client, {'alert_id': alert_id, 'action': 'a',
                                                          'message': 'b'})
    assert len(result.outputs) == 1
    assert len(result.outputs[0]) == 8
    assert result.outputs_prefix == 'SophosCentral.AlertAction'
    assert result.raw_response[0] == mock_response

    alert_ids = ['56931431-9faf-480c-ba1d-8d7541eae259'] * 3
    result = sophos_central_alert_action_command(client, {'alert_id': alert_ids, 'action': 'a',
                                                          'message': 'b'})
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
     - Ensure the number of fields in each output is correct.
     - Ensure outputs prefix is correct.
     - Ensure the raw response matches the mocked API response.
    """
    from SophosCentral import Client, sophos_central_alert_search_command
    mock_response = load_mock_response('alert_list.json')
    requests_mock.post(f'{BASE_URL}/common/v1/alerts/search', json=mock_response)
    client = Client(base_url=BASE_URL, headers={'a': 'b'}, verify=False, client_id='a',
                    client_secret='b', proxy=False)

    result = sophos_central_alert_search_command(client, {'limit': '50'})
    assert len(result.outputs) == 3
    assert len(result.outputs[0]) == 14
    assert result.outputs_prefix == 'SophosCentral.Alert'
    assert result.raw_response == mock_response


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
     - Ensure the number of fields in each output is correct.
     - Ensure outputs prefix is correct.
     - Ensure the raw response matches the mocked API response.
    """
    from SophosCentral import Client, sophos_central_endpoint_list_command
    mock_response = load_mock_response('endpoint_list.json')
    requests_mock.get(f'{BASE_URL}/endpoint/v1/endpoints', json=mock_response)
    client = Client(base_url=BASE_URL, headers={'a': 'b'}, verify=False, client_id='a',
                    client_secret='b', proxy=False)

    result = sophos_central_endpoint_list_command(client, {'limit': '50'})
    assert len(result.outputs) == 2
    assert len(result.outputs[0]) == 17
    assert result.outputs_prefix == 'SophosCentral.Endpoint'
    assert result.raw_response == mock_response


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
     - Ensure the number of fields in each output is correct.
     - Ensure outputs prefix is correct.
     - Ensure the raw response matches the mocked API response.
    """
    from SophosCentral import Client, sophos_central_endpoint_scan_command
    mock_response = load_mock_response('endpoint_scan.json')
    endpoint_id = '6e9567ea-bb50-40c5-9f12-42eb308e4c9b'
    requests_mock.post(f'{BASE_URL}/endpoint/v1/endpoints/{endpoint_id}/scans', json=mock_response)
    client = Client(base_url=BASE_URL, headers={'a': 'b'}, verify=False, client_id='a',
                    client_secret='b', proxy=False)

    result = sophos_central_endpoint_scan_command(client, {'endpoint_id': endpoint_id})
    assert len(result.outputs) == 1
    assert len(result.outputs[0]) == 3
    assert result.outputs_prefix == 'SophosCentral.EndpointScan'
    assert result.raw_response[0] == mock_response

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
     - Ensure the number of fields in each output is correct.
     - Ensure outputs prefix is correct.
     - Ensure the raw response matches the mocked API response.
    """
    from SophosCentral import Client, sophos_central_endpoint_tamper_get_command
    mock_response = load_mock_response('endpoint_tamper.json')
    endpoint_id = '6e9567ea-bb50-40c5-9f12-42eb308e4c9b'
    requests_mock.get(f'{BASE_URL}/endpoint/v1/endpoints/{endpoint_id}/tamper-protection',
                      json=mock_response)
    client = Client(base_url=BASE_URL, headers={'a': 'b'}, verify=False, client_id='a',
                    client_secret='b', proxy=False)

    result = sophos_central_endpoint_tamper_get_command(client, {'endpoint_id': endpoint_id,
                                                                 'get_password': True})
    assert len(result.outputs) == 1
    assert len(result.outputs[0]) == 3
    assert result.outputs_prefix == 'SophosCentral.EndpointTamper'
    assert result.raw_response[0] == mock_response

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
     - Ensure the number of fields in each output is correct.
     - Ensure outputs prefix is correct.
     - Ensure the raw response matches the mocked API response.
    """
    from SophosCentral import Client, sophos_central_endpoint_tamper_update_command
    mock_response = load_mock_response('endpoint_tamper.json')
    endpoint_id = '6e9567ea-bb50-40c5-9f12-42eb308e4c9b'
    requests_mock.post(f'{BASE_URL}/endpoint/v1/endpoints/{endpoint_id}/tamper-protection',
                       json=mock_response)
    client = Client(base_url=BASE_URL, headers={'a': 'b'}, verify=False, client_id='a',
                    client_secret='b', proxy=False)

    result = sophos_central_endpoint_tamper_update_command(client, {'endpoint_id': endpoint_id,
                                                                    'get_password': True})
    assert len(result.outputs) == 1
    assert len(result.outputs[0]) == 3
    assert result.outputs_prefix == 'SophosCentral.EndpointTamper'
    assert result.raw_response[0] == mock_response

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
     - Ensure the number of fields in each output is correct.
     - Ensure outputs prefix is correct.
     - Ensure the raw response matches the mocked API response.
    """
    from SophosCentral import Client, sophos_central_allowed_item_list_command
    mock_response = load_mock_response('allowed_item_list.json')
    requests_mock.get(f'{BASE_URL}/endpoint/v1/settings/allowed-items',
                      json=mock_response)
    client = Client(base_url=BASE_URL, headers={'a': 'b'}, verify=False, client_id='a',
                    client_secret='b', proxy=False)

    result = sophos_central_allowed_item_list_command(client, {'page_size': '30',
                                                               'page': '1'})
    assert len(result.outputs) == 3
    assert len(result.outputs[0]) == 9
    assert result.outputs_prefix == 'SophosCentral.AllowedItem'
    assert result.raw_response == mock_response


def test_sophos_central_allowed_item_get_command(requests_mock) -> None:
    """
    Scenario: Get a single allowed item.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_allowed_item_get is called
    Then:
     - Ensure the number of fields in each output is correct.
     - Ensure outputs prefix is correct.
     - Ensure the raw response matches the mocked API response.
    """
    from SophosCentral import Client, sophos_central_allowed_item_get_command
    mock_response = load_mock_response('allowed_item_single.json')
    allowed_item_id = 'a28c7ee1-8ad9-4b5c-8f15-4d913436ce18'
    requests_mock.get(f'{BASE_URL}/endpoint/v1/settings/allowed-items/{allowed_item_id}',
                      json=mock_response)
    client = Client(base_url=BASE_URL, headers={'a': 'b'}, verify=False, client_id='a',
                    client_secret='b', proxy=False)

    result = sophos_central_allowed_item_get_command(client, {'allowed_item_id': allowed_item_id})
    assert len(result.outputs) == 9
    assert result.outputs_prefix == 'SophosCentral.AllowedItem'
    assert result.raw_response == mock_response


def test_sophos_central_allowed_item_add_command(requests_mock) -> None:
    """
    Scenario: Add an allowed item.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_allowed_item_list is called.
    Then:
     - Ensure the number of fields in each output is correct.
     - Ensure outputs prefix is correct.
     - Ensure the raw response matches the mocked API response.
    """
    from SophosCentral import Client, sophos_central_allowed_item_add_command
    mock_response = load_mock_response('allowed_item_single.json')
    requests_mock.post(f'{BASE_URL}/endpoint/v1/settings/allowed-items',
                       json=mock_response)
    client = Client(base_url=BASE_URL, headers={'a': 'b'}, verify=False, client_id='a',
                    client_secret='b', proxy=False)

    result = sophos_central_allowed_item_add_command(client, {})
    assert len(result.outputs) == 9
    assert result.outputs_prefix == 'SophosCentral.AllowedItem'
    assert result.raw_response == mock_response


def test_sophos_central_allowed_item_update_command(requests_mock) -> None:
    """
    Scenario: Update an existing allowed item.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_allowed_item_update is called.
    Then:
     - Ensure the number of fields in each output is correct.
     - Ensure outputs prefix is correct.
     - Ensure the raw response matches the mocked API response.
    """
    from SophosCentral import Client, sophos_central_allowed_item_update_command
    mock_response = load_mock_response('allowed_item_single.json')
    allowed_item_id = 'a28c7ee1-8ad9-4b5c-8f15-4d913436ce18'
    requests_mock.patch(f'{BASE_URL}/endpoint/v1/settings/allowed-items/{allowed_item_id}',
                        json=mock_response)
    client = Client(base_url=BASE_URL, headers={'a': 'b'}, verify=False, client_id='a',
                    client_secret='b', proxy=False)

    result = sophos_central_allowed_item_update_command(client,
                                                        {'allowed_item_id': allowed_item_id})
    assert len(result.outputs) == 9
    assert result.outputs_prefix == 'SophosCentral.AllowedItem'
    assert result.raw_response == mock_response


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
     - Ensure the raw response matches the mocked API response.
    """
    from SophosCentral import Client, sophos_central_allowed_item_delete_command
    mock_response = load_mock_response('deleted.json')
    allowed_item_id = 'a28c7ee1-8ad9-4b5c-8f15-4d913436ce18'
    requests_mock.delete(f'{BASE_URL}/endpoint/v1/settings/allowed-items/{allowed_item_id}',
                         json=mock_response)
    client = Client(base_url=BASE_URL, headers={'a': 'b'}, verify=False, client_id='a',
                    client_secret='b', proxy=False)

    result = sophos_central_allowed_item_delete_command(client,
                                                        {'allowed_item_id': allowed_item_id})
    assert result.outputs == {'deletedItemId': allowed_item_id}
    assert result.outputs_prefix == 'SophosCentral.DeletedAllowedItem'
    assert result.raw_response == mock_response


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
     - Ensure the number of fields in each output is correct.
     - Ensure outputs prefix is correct.
     - Ensure the raw response matches the mocked API response.
    """
    from SophosCentral import Client, sophos_central_blocked_item_list_command
    mock_response = load_mock_response('blocked_item_list.json')
    requests_mock.get(f'{BASE_URL}/endpoint/v1/settings/blocked-items',
                      json=mock_response)
    client = Client(base_url=BASE_URL, headers={'a': 'b'}, verify=False, client_id='a',
                    client_secret='b', proxy=False)

    result = sophos_central_blocked_item_list_command(client, {'page_size': '30',
                                                               'page': '1'})
    assert len(result.outputs) == 3
    assert len(result.outputs[0]) == 9
    assert result.outputs_prefix == 'SophosCentral.BlockedItem'
    assert result.raw_response == mock_response


def test_sophos_central_blocked_item_get_command(requests_mock) -> None:
    """
    Scenario: Get a single blocked item.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_blocked_item_get is called.
    Then:
     - Ensure the number of fields in each output is correct.
     - Ensure outputs prefix is correct.
     - Ensure the raw response matches the mocked API response.
    """
    from SophosCentral import Client, sophos_central_blocked_item_get_command
    mock_response = load_mock_response('blocked_item_single.json')
    blocked_item_id = 'a28c7ee1-8ad9-4b5c-8f15-4d913436ce18'
    requests_mock.get(f'{BASE_URL}/endpoint/v1/settings/blocked-items/{blocked_item_id}',
                      json=mock_response)
    client = Client(base_url=BASE_URL, headers={'a': 'b'}, verify=False, client_id='a',
                    client_secret='b', proxy=False)

    result = sophos_central_blocked_item_get_command(client, {'blocked_item_id': blocked_item_id})
    assert len(result.outputs) == 9
    assert result.outputs_prefix == 'SophosCentral.BlockedItem'
    assert result.raw_response == mock_response


def test_sophos_central_blocked_item_add_command(requests_mock) -> None:
    """
    Scenario: Add a new blocked item.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_blocked_item_add is called.
    Then:
     - Ensure the number of fields in each output is correct.
     - Ensure outputs prefix is correct.
     - Ensure the raw response matches the mocked API response.
    """
    from SophosCentral import Client, sophos_central_blocked_item_add_command
    mock_response = load_mock_response('blocked_item_single.json')
    requests_mock.post(f'{BASE_URL}/endpoint/v1/settings/blocked-items',
                       json=mock_response)
    client = Client(base_url=BASE_URL, headers={'a': 'b'}, verify=False, client_id='a',
                    client_secret='b', proxy=False)

    result = sophos_central_blocked_item_add_command(client, {})
    assert len(result.outputs) == 9
    assert result.outputs_prefix == 'SophosCentral.BlockedItem'
    assert result.raw_response == mock_response


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
     - Ensure the raw response matches the mocked API response.
    """
    from SophosCentral import Client, sophos_central_blocked_item_delete_command
    mock_response = load_mock_response('deleted.json')
    blocked_item_id = 'a28c7ee1-8ad9-4b5c-8f15-4d913436ce18'
    requests_mock.delete(f'{BASE_URL}/endpoint/v1/settings/blocked-items/{blocked_item_id}',
                         json=mock_response)
    client = Client(base_url=BASE_URL, headers={'a': 'b'}, verify=False, client_id='a',
                    client_secret='b', proxy=False)

    result = sophos_central_blocked_item_delete_command(client,
                                                        {'blocked_item_id': blocked_item_id})
    assert result.outputs == {'deletedItemId': blocked_item_id}
    assert result.outputs_prefix == 'SophosCentral.DeletedBlockedItem'
    assert result.raw_response == mock_response


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
     - Ensure the number of fields in each output is correct.
     - Ensure outputs prefix is correct.
     - Ensure the raw response matches the mocked API response.
    """
    from SophosCentral import Client, sophos_central_scan_exclusion_list_command
    mock_response = load_mock_response('scan_exclusion_list.json')
    requests_mock.get(f'{BASE_URL}/endpoint/v1/settings/exclusions/scanning',
                      json=mock_response)
    client = Client(base_url=BASE_URL, headers={'a': 'b'}, verify=False, client_id='a',
                    client_secret='b', proxy=False)

    result = sophos_central_scan_exclusion_list_command(client, {'page_size': '30',
                                                                 'page': '1'})
    assert len(result.outputs) == 3
    assert len(result.outputs[0]) == 6
    assert result.outputs_prefix == 'SophosCentral.ScanExclusion'
    assert result.raw_response == mock_response


def test_sophos_central_scan_exclusion_get_command(requests_mock) -> None:
    """
    Scenario: Get a single scan exclusion.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_scan_exclusion_get is called.
    Then:
     - Ensure the number of fields in each output is correct.
     - Ensure outputs prefix is correct.
     - Ensure the raw response matches the mocked API response.
    """
    from SophosCentral import Client, sophos_central_scan_exclusion_get_command
    mock_response = load_mock_response('scan_exclusion_single.json')
    scan_exclusion_id = '16bac29f-17a4-4c3a-9370-8c5968c5ac7d'
    requests_mock.get(f'{BASE_URL}/endpoint/v1/settings/exclusions/scanning/{scan_exclusion_id}',
                      json=mock_response)
    client = Client(base_url=BASE_URL, headers={'a': 'b'}, verify=False, client_id='a',
                    client_secret='b', proxy=False)

    result = sophos_central_scan_exclusion_get_command(client, {'exclusion_id': scan_exclusion_id})
    assert len(result.outputs) == 6
    assert result.outputs_prefix == 'SophosCentral.ScanExclusion'
    assert result.raw_response == mock_response


def test_sophos_central_scan_exclusion_add_command(requests_mock) -> None:
    """
    Scenario: Add a new scan exclusion.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_scan_exclusion_add is called.
    Then:
     - Ensure the number of fields in each output is correct.
     - Ensure outputs prefix is correct.
     - Ensure the raw response matches the mocked API response.
    """
    from SophosCentral import Client, sophos_central_scan_exclusion_add_command
    mock_response = load_mock_response('scan_exclusion_single.json')
    requests_mock.post(f'{BASE_URL}/endpoint/v1/settings/exclusions/scanning',
                       json=mock_response)
    client = Client(base_url=BASE_URL, headers={'a': 'b'}, verify=False, client_id='a',
                    client_secret='b', proxy=False)

    result = sophos_central_scan_exclusion_add_command(client, {})
    assert len(result.outputs) == 6
    assert result.outputs_prefix == 'SophosCentral.ScanExclusion'
    assert result.raw_response == mock_response


def test_sophos_central_scan_exclusion_update_command(requests_mock) -> None:
    """
    Scenario: Update an existing scan exclusion.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_scan_exclusion_update is called.
    Then:
     - Ensure the number of fields in each output is correct.
     - Ensure outputs prefix is correct.
     - Ensure the raw response matches the mocked API response.
    """
    from SophosCentral import Client, sophos_central_scan_exclusion_update_command
    mock_response = load_mock_response('scan_exclusion_single.json')
    scan_exclusion_id = '16bac29f-17a4-4c3a-9370-8c5968c5ac7d'
    requests_mock.patch(f'{BASE_URL}/endpoint/v1/settings/exclusions/scanning/{scan_exclusion_id}',
                        json=mock_response)
    client = Client(base_url=BASE_URL, headers={'a': 'b'}, verify=False, client_id='a',
                    client_secret='b', proxy=False)

    result = sophos_central_scan_exclusion_update_command(client,
                                                          {'exclusion_id': scan_exclusion_id})
    assert len(result.outputs) == 6
    assert result.outputs_prefix == 'SophosCentral.ScanExclusion'
    assert result.raw_response == mock_response


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
     - Ensure the raw response matches the mocked API response.
    """
    from SophosCentral import Client, sophos_central_scan_exclusion_delete_command
    mock_response = load_mock_response('deleted.json')
    scan_exclusion_id = '16bac29f-17a4-4c3a-9370-8c5968c5ac7d'
    requests_mock.delete(f'{BASE_URL}/endpoint/v1/settings/exclusions/scanning/{scan_exclusion_id}',
                         json=mock_response)
    client = Client(base_url=BASE_URL, headers={'a': 'b'}, verify=False, client_id='a',
                    client_secret='b', proxy=False)

    result = sophos_central_scan_exclusion_delete_command(client,
                                                          {'exclusion_id': scan_exclusion_id})
    assert result.outputs == {'deletedExclusionId': scan_exclusion_id}
    assert result.outputs_prefix == 'SophosCentral.DeletedScanExclusion'
    assert result.raw_response == mock_response


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
     - Ensure the number of fields in each output is correct.
     - Ensure outputs prefix is correct.
     - Ensure the raw response matches the mocked API response.
    """
    from SophosCentral import Client, sophos_central_exploit_mitigation_list_command
    mock_response = load_mock_response('exploit_mitigation_list.json')
    requests_mock.get(f'{BASE_URL}/endpoint/v1/settings/exploit-mitigation/applications',
                      json=mock_response)
    client = Client(base_url=BASE_URL, headers={'a': 'b'}, verify=False, client_id='a',
                    client_secret='b', proxy=False)

    result = sophos_central_exploit_mitigation_list_command(client, {'page_size': '30',
                                                                     'page': '1'})
    assert len(result.outputs) == 3
    assert len(result.outputs[0]) == 5
    assert result.outputs_prefix == 'SophosCentral.ExploitMitigation'
    assert result.raw_response == mock_response


def test_sophos_central_exploit_mitigation_get_command(requests_mock) -> None:
    """
    Scenario: Get a single exploit mitigation.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_exploit_mitigation_get is called.
    Then:
     - Ensure the number of fields in each output is correct.
     - Ensure outputs prefix is correct.
     - Ensure the raw response matches the mocked API response.
    """
    from SophosCentral import Client, sophos_central_exploit_mitigation_get_command
    mock_response = load_mock_response('exploit_mitigation_single.json')
    exploit_id = 'c2824651-26c1-4470-addf-7b6bb6ac90b4'
    requests_mock.get(f'{BASE_URL}/endpoint/v1/settings/'
                      f'exploit-mitigation/applications/{exploit_id}', json=mock_response)
    client = Client(base_url=BASE_URL, headers={'a': 'b'}, verify=False, client_id='a',
                    client_secret='b', proxy=False)

    result = sophos_central_exploit_mitigation_get_command(client, {'mitigation_id': exploit_id})
    assert len(result.outputs) == 5
    assert result.outputs_prefix == 'SophosCentral.ExploitMitigation'
    assert result.raw_response == mock_response


def test_sophos_central_exploit_mitigation_add_command(requests_mock) -> None:
    """
    Scenario: Add a new exploit mitigation.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_exploit_mitigation_add is called.
    Then:
     - Ensure the number of fields in each output is correct.
     - Ensure outputs prefix is correct.
     - Ensure the raw response matches the mocked API response.
    """
    from SophosCentral import Client, sophos_central_exploit_mitigation_add_command
    mock_response = load_mock_response('exploit_mitigation_single.json')
    exploit_id = 'c2824651-26c1-4470-addf-7b6bb6ac90b4'
    requests_mock.post(f'{BASE_URL}/endpoint/v1/settings/exploit-mitigation/applications',
                       json=mock_response)
    client = Client(base_url=BASE_URL, headers={'a': 'b'}, verify=False, client_id='a',
                    client_secret='b', proxy=False)

    result = sophos_central_exploit_mitigation_add_command(client, {'mitigation_id': exploit_id})
    assert len(result.outputs) == 5
    assert result.outputs_prefix == 'SophosCentral.ExploitMitigation'
    assert result.raw_response == mock_response


def test_sophos_central_exploit_mitigation_update_command(requests_mock) -> None:
    """
    Scenario: Update an existing exploit mitigation.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_exploit_mitigation_update is called.
    Then:
     - Ensure the number of fields in each output is correct.
     - Ensure outputs prefix is correct.
     - Ensure the raw response matches the mocked API response.
    """
    from SophosCentral import Client, sophos_central_exploit_mitigation_update_command
    mock_response = load_mock_response('exploit_mitigation_single.json')
    exploit_id = 'c2824651-26c1-4470-addf-7b6bb6ac90b4'
    requests_mock.patch(f'{BASE_URL}/endpoint/v1/settings/'
                        f'exploit-mitigation/applications/{exploit_id}',
                        json=mock_response)
    client = Client(base_url=BASE_URL, headers={'a': 'b'}, verify=False, client_id='a',
                    client_secret='b', proxy=False)

    result = sophos_central_exploit_mitigation_update_command(client, {'mitigation_id': exploit_id})
    assert len(result.outputs) == 5
    assert result.outputs_prefix == 'SophosCentral.ExploitMitigation'
    assert result.raw_response == mock_response


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
     - Ensure the raw response matches the mocked API response.
    """
    from SophosCentral import Client, sophos_central_exploit_mitigation_delete_command
    mock_response = load_mock_response('deleted.json')
    exploit_id = 'c2824651-26c1-4470-addf-7b6bb6ac90b4'
    requests_mock.delete(f'{BASE_URL}/endpoint/v1/settings/'
                         f'exploit-mitigation/applications/{exploit_id}',
                         json=mock_response)
    client = Client(base_url=BASE_URL, headers={'a': 'b'}, verify=False, client_id='a',
                    client_secret='b', proxy=False)

    result = sophos_central_exploit_mitigation_delete_command(client, {'mitigation_id': exploit_id})
    assert result.outputs == {'deletedMitigationId': exploit_id}
    assert result.outputs_prefix == 'SophosCentral.DeletedExploitMitigation'
    assert result.raw_response == mock_response


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
     - Ensure the number of fields in each output is correct.
     - Ensure outputs prefix is correct.
     - Ensure the raw response matches the mocked API response.
    """
    from SophosCentral import Client, sophos_central_detected_exploit_list_command
    mock_response = load_mock_response('detected_exploit_list.json')
    requests_mock.get(f'{BASE_URL}/endpoint/v1/settings/exploit-mitigation/detected-exploits',
                      json=mock_response)
    client = Client(base_url=BASE_URL, headers={'a': 'b'}, verify=False, client_id='a',
                    client_secret='b', proxy=False)

    result = sophos_central_detected_exploit_list_command(client, {'page_size': '30',
                                                                   'page': '1'})
    assert len(result.outputs) == 3
    assert len(result.outputs[0]) == 10
    assert result.outputs_prefix == 'SophosCentral.DetectedExploit'
    assert result.raw_response == mock_response


def test_sophos_central_detected_exploit_get_command(requests_mock) -> None:
    """
    Scenario: Get a single detected exploit.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_detected_exploit_get is called.
    Then:
     - Ensure the number of fields in each output is correct.
     - Ensure outputs prefix is correct.
     - Ensure the raw response matches the mocked API response.
    """
    from SophosCentral import Client, sophos_central_detected_exploit_get_command
    mock_response = load_mock_response('detected_exploit_single.json')
    exploit_id = 'b81aac51-2fc0-ab6a-asdf-7b6bb6ac90b4'
    requests_mock.get(f'{BASE_URL}/endpoint/v1/settings/'
                      f'exploit-mitigation/detected-exploits/{exploit_id}', json=mock_response)
    client = Client(base_url=BASE_URL, headers={'a': 'b'}, verify=False, client_id='a',
                    client_secret='b', proxy=False)

    result = sophos_central_detected_exploit_get_command(client,
                                                         {'detected_exploit_id': exploit_id})
    assert len(result.outputs) == 10
    assert result.outputs_prefix == 'SophosCentral.DetectedExploit'
    assert result.raw_response == mock_response


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
    from SophosCentral import get_client_data
    mock_response = load_mock_response('client_data.json')
    requests_mock.get('https://api.central.sophos.com/whoami/v1', json=mock_response)

    headers, base_url = get_client_data('aaaa')
    assert base_url == 'https://api-eu02.central.sophos.com/'
    assert headers == {'Authorization': 'Bearer aaaa',
                       'X-Tenant-ID': '11f104c5-cc4a-4a9f-bb9c-632c936dfb9f'}


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
    from SophosCentral import Client, fetch_incidents
    client = Client(base_url=BASE_URL, headers={'a': 'b'}, verify=False, client_id='a',
                    client_secret='b', proxy=False)
    mock_response = load_mock_response('alert_list.json')
    requests_mock.post(f'{BASE_URL}/common/v1/alerts/search', json=mock_response)

    last_fetch, incidents = fetch_incidents(client, {'last_fetch': 1}, '3 days', ['x'], ['x'], '50')
    wanted_time = datetime.timestamp(datetime.strptime('2020-11-04T09:31:19.895Z', DATE_FORMAT))
    assert last_fetch.get('last_fetch') == wanted_time * 1000
    assert len(incidents) == 3
    assert incidents[0].get('name') == 'Sophos Central Alert 56931431-9faf-480c-ba1d-8d7541eae259'


def test_validate_item_fields() -> None:
    """
    Scenario: Validate arguments for creating / updating items before sending to API.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - When add/update_item is called.
    Then:
     - Ensure correct arguments do not raise an error.
     - Ensure faulty arguments do raise an error.
    """
    from SophosCentral import validate_item_fields
    args = {'item_type': 'certificateSigner', 'certificate_signer': 'xxx'}
    validate_item_fields(args)
    args = {'item_type': 'certificateSigner', 'path': 'xxx'}
    with raises(DemistoException):
        validate_item_fields(args)
