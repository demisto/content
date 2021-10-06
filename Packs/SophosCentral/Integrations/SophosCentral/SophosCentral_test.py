import json
from datetime import datetime
import pytest
import requests
from pytest import raises
import demistomock as demisto
from CommonServerPython import (
    DemistoException,
    EntryType,
    set_integration_context,
    get_integration_context,
)
from SophosCentral import Client
from unittest import mock
from unittest.mock import patch


BASE_URL = "https://api-eu02.central.sophos.com"
TENANT_BASE_URL = "dummy_url"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


# pytest fixture for testing arguments of a function and calling
# BaseClient's "_http_request" method.
@pytest.fixture
def argtest():
    def _argtest(**_kwargs):
        class TestArgs(object):
            def __call__(self, *args, **kwargs):
                self.args = list(args)
                self.kwargs = kwargs
                return _kwargs["_http_request"](*args, **kwargs)

        return TestArgs()

    return _argtest


def init_mock_client(requests_mock, integration_context=None):
    integration_context = integration_context or {}
    mock_client_data = load_mock_response("whoami_tenant.json")
    requests_mock.get("https://api.central.sophos.com/whoami/v1", json=mock_client_data)
    return Client(
        bearer_token="this",
        client_id="is",
        verify=False,
        client_secret="Cactus",
        proxy=False,
        integration_context=integration_context,
    )


def load_mock_response(file_name: str) -> dict:
    """
    Load one of the mock responses to be used for assertion.

    Args:
        file_name (str): Name of the mock response JSON file to return.
    """
    with open(f"test_data/{file_name}", mode="r", encoding="utf-8") as json_file:
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

    mock_response = load_mock_response("alert_list.json")
    requests_mock.get(f"{BASE_URL}/common/v1/alerts", json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_alert_list_command(client, {"limit": "14"})
    assert len(result.outputs) == 3
    assert result.outputs_prefix == "SophosCentral.Alert"
    assert result.outputs[0].get("id") == "56931431-9faf-480c-ba1d-8d7541eae259"


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

    mock_response = load_mock_response("alert_single.json")
    alert_id = "56931431-9faf-480c-ba1d-8d7541eae259"
    requests_mock.get(f"{BASE_URL}/common/v1/alerts/{alert_id}", json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_alert_get_command(client, {"alert_id": alert_id})
    assert result.outputs_prefix == "SophosCentral.Alert"
    assert result.outputs.get("id") == "70e3781d-c0f6-4e72-b6aa-3c3ef21f3dbb"


def test_sophos_central_alert_get_command_exception() -> None:
    """
    Scenario: Exception raised while getting a single alert.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_alert_get is called.
    Then:
     - Ensure that the valid result is returned when any exception is raised.
    """
    from SophosCentral import sophos_central_alert_get_command

    alert_id = "56931431-9faf-480c-ba1d-8d7541eae259"
    client = mock.Mock()
    client.get_alert.side_effect = DemistoException("Demisto Exception")

    result = sophos_central_alert_get_command(client, {"alert_id": alert_id})
    assert result.readable_output == f"Unable to find the following alert: {alert_id}"


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

    mock_response = load_mock_response("alert_action.json")
    alert_id = "56931431-9faf-480c-ba1d-8d7541eae259"
    requests_mock.post(
        f"{BASE_URL}/common/v1/alerts/{alert_id}/actions", json=mock_response
    )
    client = init_mock_client(requests_mock)

    result = sophos_central_alert_action_command(
        client, {"alert_id": alert_id, "action": "clearThreat", "message": "b"}
    )
    assert len(result.outputs) == 1
    assert result.outputs_prefix == "SophosCentral.AlertAction"
    assert result.outputs[0].get("alertId") == "25c7b132-56d8-4bce-9d1b-6c51a7eb3c78"

    alert_ids = ["56931431-9faf-480c-ba1d-8d7541eae259"] * 3
    result = sophos_central_alert_action_command(
        client, {"alert_id": alert_ids, "action": "clearThreat", "message": "b"}
    )
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

    mock_response = load_mock_response("alert_list.json")
    requests_mock.post(f"{BASE_URL}/common/v1/alerts/search", json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_alert_search_command(
        client, {"limit": "14", "date_range": "2 hours"}
    )
    assert len(result.outputs) == 3
    assert result.outputs_prefix == "SophosCentral.Alert"
    assert result.outputs[0].get("id") == "56931431-9faf-480c-ba1d-8d7541eae259"


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

    mock_response = load_mock_response("endpoint_list.json")
    requests_mock.get(f"{BASE_URL}/endpoint/v1/endpoints", json=mock_response)
    client = init_mock_client(requests_mock)

    result = sophos_central_endpoint_list_command(client, {"limit": "17"})
    assert len(result.outputs) == 2
    assert result.outputs_prefix == "SophosCentral.Endpoint"
    assert result.outputs[0].get("id") == "6e9567ea-bb50-40c5-9f12-42eb308e4c9b"


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

    mock_response = load_mock_response("endpoint_scan.json")
    endpoint_id = "6e9567ea-bb50-40c5-9f12-42eb308e4c9b"
    requests_mock.post(
        f"{BASE_URL}/endpoint/v1/endpoints/{endpoint_id}/scans", json=mock_response
    )
    client = init_mock_client(requests_mock)

    result = sophos_central_endpoint_scan_command(client, {"endpoint_id": endpoint_id})
    assert len(result.outputs) == 1
    assert result.outputs_prefix == "SophosCentral.EndpointScan"
    assert result.outputs[0].get("id") == "6e9567ea-bb50-40c5-9f12-42eb308e4c9b"

    endpoint_ids = ["6e9567ea-bb50-40c5-9f12-42eb308e4c9b"] * 3
    result = sophos_central_endpoint_scan_command(client, {"endpoint_id": endpoint_ids})
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

    mock_response = load_mock_response("endpoint_tamper.json")
    endpoint_id = "6e9567ea-bb50-40c5-9f12-42eb308e4c9b"
    requests_mock.get(
        f"{BASE_URL}/endpoint/v1/endpoints/{endpoint_id}/tamper-protection",
        json=mock_response,
    )
    client = init_mock_client(requests_mock)

    result = sophos_central_endpoint_tamper_get_command(
        client, {"endpoint_id": endpoint_id, "get_password": True}
    )
    assert len(result.outputs) == 1
    assert result.outputs_prefix == "SophosCentral.EndpointTamper"
    assert result.outputs[0].get("password") == "1234567890"

    endpoint_ids = ["6e9567ea-bb50-40c5-9f12-42eb308e4c9b"] * 3
    result = sophos_central_endpoint_tamper_get_command(
        client, {"endpoint_id": endpoint_ids, "get_password": True}
    )
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

    mock_response = load_mock_response("endpoint_tamper.json")
    endpoint_id = "6e9567ea-bb50-40c5-9f12-42eb308e4c9b"
    requests_mock.post(
        f"{BASE_URL}/endpoint/v1/endpoints/{endpoint_id}/tamper-protection",
        json=mock_response,
    )
    client = init_mock_client(requests_mock)

    result = sophos_central_endpoint_tamper_update_command(
        client, {"endpoint_id": endpoint_id, "get_password": True}
    )
    assert len(result.outputs) == 1
    assert result.outputs_prefix == "SophosCentral.EndpointTamper"
    assert result.outputs[0].get("password") == "1234567890"

    endpoint_ids = ["6e9567ea-bb50-40c5-9f12-42eb308e4c9b"] * 3
    result = sophos_central_endpoint_tamper_update_command(
        client, {"endpoint_id": endpoint_ids, "get_password": True}
    )
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

    mock_response = load_mock_response("allowed_item_list.json")
    requests_mock.get(
        f"{BASE_URL}/endpoint/v1/settings/allowed-items", json=mock_response
    )
    client = init_mock_client(requests_mock)

    result = sophos_central_allowed_item_list_command(
        client, {"page_size": "30", "page": "1"}
    )
    assert len(result.outputs) == 3
    assert result.outputs_prefix == "SophosCentral.AllowedItem"
    assert result.outputs[0].get("id") == "a28c7ee1-8ad9-4b5c-8f15-4d913436ce18"


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

    mock_response = load_mock_response("allowed_item_single.json")
    allowed_item_id = "a28c7ee1-8ad9-4b5c-8f15-4d913436ce18"
    requests_mock.get(
        f"{BASE_URL}/endpoint/v1/settings/allowed-items/{allowed_item_id}",
        json=mock_response,
    )
    client = init_mock_client(requests_mock)

    result = sophos_central_allowed_item_get_command(
        client, {"allowed_item_id": allowed_item_id}
    )
    assert result.outputs_prefix == "SophosCentral.AllowedItem"
    assert result.outputs.get("id") == "811fa316-d485-4499-a979-3e1c0a89f1fd"


def test_sophos_central_allowed_item_get_command_exception() -> None:
    """
    Scenario: Exception raised while getting a single allowed item.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_allowed_item_get is called
    Then:
     - Ensure that the valid result is returned when any exception is raised.
    """
    from SophosCentral import sophos_central_allowed_item_get_command

    allowed_item_id = "a28c7ee1-8ad9-4b5c-8f15-4d913436ce18"
    client = mock.Mock()
    client.get_allowed_item.side_effect = DemistoException("Demisto Exception")

    result = sophos_central_allowed_item_get_command(
        client, {"allowed_item_id": allowed_item_id}
    )
    assert result.readable_output == f"Unable to find item: {allowed_item_id}"


def test_sophos_central_allowed_item_add_command(requests_mock) -> None:
    """
    Scenario: Add an allowed item.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_allowed_item_add is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from SophosCentral import sophos_central_allowed_item_add_command

    mock_response = load_mock_response("allowed_item_single.json")
    requests_mock.post(
        f"{BASE_URL}/endpoint/v1/settings/allowed-items", json=mock_response
    )
    client = init_mock_client(requests_mock)

    result = sophos_central_allowed_item_add_command(client, {})
    assert result.outputs_prefix == "SophosCentral.AllowedItem"
    assert result.outputs.get("id") == "811fa316-d485-4499-a979-3e1c0a89f1fd"


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

    mock_response = load_mock_response("allowed_item_single.json")
    allowed_item_id = "a28c7ee1-8ad9-4b5c-8f15-4d913436ce18"
    requests_mock.patch(
        f"{BASE_URL}/endpoint/v1/settings/allowed-items/{allowed_item_id}",
        json=mock_response,
    )
    client = init_mock_client(requests_mock)

    result = sophos_central_allowed_item_update_command(
        client, {"allowed_item_id": allowed_item_id}
    )
    assert result.outputs_prefix == "SophosCentral.AllowedItem"
    assert result.outputs.get("id") == "811fa316-d485-4499-a979-3e1c0a89f1fd"


def test_sophos_central_allowed_item_update_command_exception() -> None:
    """
    Scenario: Exception occured while Update an existing allowed item.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_allowed_item_update is called.
    Then:
     - Ensure that the valid result is returned when any exception is raised.
    """
    from SophosCentral import sophos_central_allowed_item_update_command

    allowed_item_id = "a28c7ee1-8ad9-4b5c-8f15-4d913436ce18"
    client = mock.Mock()
    client.update_allowed_item.side_effect = DemistoException("Demisto Exception")

    result = sophos_central_allowed_item_update_command(
        client, {"allowed_item_id": allowed_item_id}
    )
    assert result.readable_output == f"Unable to update item: {allowed_item_id}"


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

    mock_response = load_mock_response("deleted.json")
    allowed_item_id = "a28c7ee1-8ad9-4b5c-8f15-4d913436ce18"
    requests_mock.delete(
        f"{BASE_URL}/endpoint/v1/settings/allowed-items/{allowed_item_id}",
        json=mock_response,
    )
    client = init_mock_client(requests_mock)

    result = sophos_central_allowed_item_delete_command(
        client, {"allowed_item_id": allowed_item_id}
    )
    assert result.outputs == {"deletedItemId": allowed_item_id}
    assert result.outputs_prefix == "SophosCentral.DeletedAllowedItem"


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

    mock_response = load_mock_response("blocked_item_list.json")
    requests_mock.get(
        f"{BASE_URL}/endpoint/v1/settings/blocked-items", json=mock_response
    )
    client = init_mock_client(requests_mock)

    result = sophos_central_blocked_item_list_command(
        client, {"page_size": "30", "page": "1"}
    )
    assert len(result.outputs) == 3
    assert result.outputs_prefix == "SophosCentral.BlockedItem"
    assert result.outputs[0].get("id") == "6b0d0fb1-4254-45b0-896a-2eb36d0e2368"


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

    mock_response = load_mock_response("blocked_item_single.json")
    blocked_item_id = "a28c7ee1-8ad9-4b5c-8f15-4d913436ce18"
    requests_mock.get(
        f"{BASE_URL}/endpoint/v1/settings/blocked-items/{blocked_item_id}",
        json=mock_response,
    )
    client = init_mock_client(requests_mock)

    result = sophos_central_blocked_item_get_command(
        client, {"blocked_item_id": blocked_item_id}
    )
    assert result.outputs_prefix == "SophosCentral.BlockedItem"
    assert result.outputs.get("id") == "998ffd3d-4a44-40da-8c1f-b18ace4ff735"


def test_sophos_central_blocked_item_get_command_exception() -> None:
    """
    Scenario: Exception raised while getting a single blocked item.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_blocked_item_get is called.
    Then:
     - Ensure that the valid result is returned when any exception is raised.
    """
    from SophosCentral import sophos_central_blocked_item_get_command

    blocked_item_id = "a28c7ee1-8ad9-4b5c-8f15-4d913436ce18"
    client = mock.Mock()
    client.get_blocked_item.side_effect = DemistoException("Demisto Exception")

    result = sophos_central_blocked_item_get_command(
        client, {"blocked_item_id": blocked_item_id}
    )
    assert result.readable_output == f"Unable to find item: {blocked_item_id}"


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

    mock_response = load_mock_response("blocked_item_single.json")
    requests_mock.post(
        f"{BASE_URL}/endpoint/v1/settings/blocked-items", json=mock_response
    )
    client = init_mock_client(requests_mock)

    result = sophos_central_blocked_item_add_command(client, {})
    assert result.outputs_prefix == "SophosCentral.BlockedItem"
    assert result.outputs.get("id") == "998ffd3d-4a44-40da-8c1f-b18ace4ff735"


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

    mock_response = load_mock_response("deleted.json")
    blocked_item_id = "a28c7ee1-8ad9-4b5c-8f15-4d913436ce18"
    requests_mock.delete(
        f"{BASE_URL}/endpoint/v1/settings/blocked-items/{blocked_item_id}",
        json=mock_response,
    )
    client = init_mock_client(requests_mock)

    result = sophos_central_blocked_item_delete_command(
        client, {"blocked_item_id": blocked_item_id}
    )
    assert result.outputs == {"deletedItemId": blocked_item_id}
    assert result.outputs_prefix == "SophosCentral.DeletedBlockedItem"


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

    mock_response = load_mock_response("scan_exclusion_list.json")
    requests_mock.get(
        f"{BASE_URL}/endpoint/v1/settings/exclusions/scanning", json=mock_response
    )
    client = init_mock_client(requests_mock)

    result = sophos_central_scan_exclusion_list_command(
        client, {"page_size": "30", "page": "1"}
    )
    assert len(result.outputs) == 3
    assert result.outputs_prefix == "SophosCentral.ScanExclusion"
    assert result.outputs[0].get("id") == "369b0956-a7b6-44fc-b1cc-bd7b3279c663"


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

    mock_response = load_mock_response("scan_exclusion_single.json")
    scan_exclusion_id = "16bac29f-17a4-4c3a-9370-8c5968c5ac7d"
    requests_mock.get(
        f"{BASE_URL}/endpoint/v1/settings/exclusions/scanning/{scan_exclusion_id}",
        json=mock_response,
    )
    client = init_mock_client(requests_mock)

    result = sophos_central_scan_exclusion_get_command(
        client, {"exclusion_id": scan_exclusion_id}
    )
    assert result.outputs_prefix == "SophosCentral.ScanExclusion"
    assert result.outputs.get("id") == "16bac29f-17a4-4c3a-9370-8c5968c5ac7d"


def test_sophos_central_scan_exclusion_get_command_exception() -> None:
    """
    Scenario: Exception raised while getting a single scan exclusion.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_scan_exclusion_get is called.
    Then:
     - Ensure that the valid result is returned when any exception is raised.
    """
    from SophosCentral import sophos_central_scan_exclusion_get_command

    scan_exclusion_id = "16bac29f-17a4-4c3a-9370-8c5968c5ac7d"
    client = mock.Mock()
    client.get_scan_exclusion.side_effect = DemistoException("Demisto Exception")

    result = sophos_central_scan_exclusion_get_command(
        client, {"exclusion_id": scan_exclusion_id}
    )
    assert result.outputs_prefix == f"Unable to find exclusion: {scan_exclusion_id}"


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

    mock_response = load_mock_response("scan_exclusion_single.json")
    requests_mock.post(
        f"{BASE_URL}/endpoint/v1/settings/exclusions/scanning", json=mock_response
    )
    client = init_mock_client(requests_mock)

    result = sophos_central_scan_exclusion_add_command(client, {})
    assert result.outputs_prefix == "SophosCentral.ScanExclusion"
    assert result.outputs.get("id") == "16bac29f-17a4-4c3a-9370-8c5968c5ac7d"


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

    mock_response = load_mock_response("scan_exclusion_single.json")
    scan_exclusion_id = "16bac29f-17a4-4c3a-9370-8c5968c5ac7d"
    requests_mock.patch(
        f"{BASE_URL}/endpoint/v1/settings/exclusions/scanning/{scan_exclusion_id}",
        json=mock_response,
    )
    client = init_mock_client(requests_mock)

    result = sophos_central_scan_exclusion_update_command(
        client, {"exclusion_id": scan_exclusion_id}
    )
    assert result.outputs_prefix == "SophosCentral.ScanExclusion"
    assert result.outputs.get("id") == "16bac29f-17a4-4c3a-9370-8c5968c5ac7d"


def test_sophos_central_scan_exclusion_update_command_exception() -> None:
    """
    Scenario: Exception raised while updating an existing scan exclusion.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_scan_exclusion_update is called.
    Then:
     - Ensure that the valid result is returned when any exception is raised.
    """
    from SophosCentral import sophos_central_scan_exclusion_update_command

    scan_exclusion_id = "16bac29f-17a4-4c3a-9370-8c5968c5ac7d"
    client = mock.Mock()
    client.update_scan_exclusion.side_effect = DemistoException("Demisto Exception")

    result = sophos_central_scan_exclusion_update_command(
        client, {"exclusion_id": scan_exclusion_id}
    )
    assert result.outputs_prefix == f"Unable to update exclusion: {scan_exclusion_id}"


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

    mock_response = load_mock_response("deleted.json")
    scan_exclusion_id = "16bac29f-17a4-4c3a-9370-8c5968c5ac7d"
    requests_mock.delete(
        f"{BASE_URL}/endpoint/v1/settings/exclusions/scanning/{scan_exclusion_id}",
        json=mock_response,
    )
    client = init_mock_client(requests_mock)

    result = sophos_central_scan_exclusion_delete_command(
        client, {"exclusion_id": scan_exclusion_id}
    )
    assert result.outputs == {"deletedExclusionId": scan_exclusion_id}
    assert result.outputs_prefix == "SophosCentral.DeletedScanExclusion"


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

    mock_response = load_mock_response("exploit_mitigation_list.json")
    requests_mock.get(
        f"{BASE_URL}/endpoint/v1/settings/exploit-mitigation/applications",
        json=mock_response,
    )
    client = init_mock_client(requests_mock)

    result = sophos_central_exploit_mitigation_list_command(
        client, {"page_size": "30", "page": "1"}
    )
    assert len(result.outputs) == 3
    assert result.outputs_prefix == "SophosCentral.ExploitMitigation"
    assert result.outputs[0].get("id") == "30fbb4cf-2961-4ffc-937e-97c57f468838"


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

    mock_response = load_mock_response("exploit_mitigation_single.json")
    exploit_id = "c2824651-26c1-4470-addf-7b6bb6ac90b4"
    requests_mock.get(
        f"{BASE_URL}/endpoint/v1/settings/"
        f"exploit-mitigation/applications/{exploit_id}",
        json=mock_response,
    )
    client = init_mock_client(requests_mock)

    result = sophos_central_exploit_mitigation_get_command(
        client, {"mitigation_id": exploit_id}
    )
    assert result.outputs_prefix == "SophosCentral.ExploitMitigation"
    assert result.outputs.get("id") == "c2824651-26c1-4470-addf-7b6bb6ac90b4"


def test_sophos_central_exploit_mitigation_get_command_exception() -> None:
    """
    Scenario: Exception raised while getting a single exploit mitigation.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_exploit_mitigation_get is called.
    Then:
     - Ensure that the valid result is returned when any exception is raised.
    """
    from SophosCentral import sophos_central_exploit_mitigation_get_command

    exploit_id = "c2824651-26c1-4470-addf-7b6bb6ac90b4"
    client = mock.Mock()
    client.get_exploit_mitigation.side_effect = DemistoException("Demisto Exception")

    result = sophos_central_exploit_mitigation_get_command(
        client, {"mitigation_id": exploit_id}
    )
    assert result.outputs_prefix == f"Unable to find mitigation: {exploit_id}"


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

    mock_response = load_mock_response("exploit_mitigation_single.json")
    exploit_id = "c2824651-26c1-4470-addf-7b6bb6ac90b4"
    requests_mock.post(
        f"{BASE_URL}/endpoint/v1/settings/exploit-mitigation/applications",
        json=mock_response,
    )
    client = init_mock_client(requests_mock)

    result = sophos_central_exploit_mitigation_add_command(
        client, {"mitigation_id": exploit_id}
    )
    assert result.outputs_prefix == "SophosCentral.ExploitMitigation"
    assert result.outputs.get("id") == "c2824651-26c1-4470-addf-7b6bb6ac90b4"


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

    mock_response = load_mock_response("exploit_mitigation_single.json")
    exploit_id = "c2824651-26c1-4470-addf-7b6bb6ac90b4"
    requests_mock.patch(
        f"{BASE_URL}/endpoint/v1/settings/"
        f"exploit-mitigation/applications/{exploit_id}",
        json=mock_response,
    )
    client = init_mock_client(requests_mock)

    result = sophos_central_exploit_mitigation_update_command(
        client, {"mitigation_id": exploit_id}
    )
    assert result.outputs_prefix == "SophosCentral.ExploitMitigation"
    assert result.outputs.get("id") == "c2824651-26c1-4470-addf-7b6bb6ac90b4"


def test_sophos_central_exploit_mitigation_update_command_exception() -> None:
    """
    Scenario: Exception raised while updating an existing exploit mitigation.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_exploit_mitigation_update is called.
    Then:
     - Ensure that the valid result is returned when any exception is raised.
    """
    from SophosCentral import sophos_central_exploit_mitigation_update_command

    exploit_id = "c2824651-26c1-4470-addf-7b6bb6ac90b4"
    client = mock.Mock()
    client.update_exploit_mitigation.side_effect = DemistoException("Demisto Exception")

    result = sophos_central_exploit_mitigation_update_command(
        client, {"mitigation_id": exploit_id}
    )
    assert result.outputs_prefix == f"Unable to update mitigation: {exploit_id}"


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

    mock_response = load_mock_response("deleted.json")
    exploit_id = "c2824651-26c1-4470-addf-7b6bb6ac90b4"
    requests_mock.delete(
        f"{BASE_URL}/endpoint/v1/settings/"
        f"exploit-mitigation/applications/{exploit_id}",
        json=mock_response,
    )
    client = init_mock_client(requests_mock)

    result = sophos_central_exploit_mitigation_delete_command(
        client, {"mitigation_id": exploit_id}
    )
    assert result.outputs == {"deletedMitigationId": exploit_id}
    assert result.outputs_prefix == "SophosCentral.DeletedExploitMitigation"


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

    mock_response = load_mock_response("detected_exploit_list.json")
    requests_mock.get(
        f"{BASE_URL}/endpoint/v1/settings/exploit-mitigation/detected-exploits",
        json=mock_response,
    )
    client = init_mock_client(requests_mock)

    result = sophos_central_detected_exploit_list_command(
        client, {"page_size": "30", "page": "1"}
    )
    assert len(result.outputs) == 3
    assert result.outputs_prefix == "SophosCentral.DetectedExploit"
    assert result.outputs[0].get("id") == "b81aac51-2fc0-ab6a-asdf-7b6bb6ac90b4"


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

    mock_response = load_mock_response("detected_exploit_single.json")
    exploit_id = "b81aac51-2fc0-ab6a-asdf-7b6bb6ac90b4"
    requests_mock.get(
        f"{BASE_URL}/endpoint/v1/settings/"
        f"exploit-mitigation/detected-exploits/{exploit_id}",
        json=mock_response,
    )
    client = init_mock_client(requests_mock)

    result = sophos_central_detected_exploit_get_command(
        client, {"detected_exploit_id": exploit_id}
    )
    assert result.outputs_prefix == "SophosCentral.DetectedExploit"
    assert result.outputs.get("id") == "b81aac51-2fc0-ab6a-asdf-7b6bb6ac90b4"


def test_sophos_central_detected_exploit_get_command_exception() -> None:
    """
    Scenario: Exception raised while getting a single detected exploit.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos_central_detected_exploit_get is called.
    Then:
     - Ensure that the valid result is returned when any exception is raised.
    """
    from SophosCentral import sophos_central_detected_exploit_get_command

    exploit_id = "b81aac51-2fc0-ab6a-asdf-7b6bb6ac90b4"
    client = mock.Mock()
    client.get_detected_exploit.side_effect = DemistoException("Demisto Exception")

    result = sophos_central_detected_exploit_get_command(
        client, {"detected_exploit_id": exploit_id}
    )
    assert result.outputs_prefix == f"Unable to find exploit: {exploit_id}"


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

    mock_response = load_mock_response("auth_token.json")
    requests_mock.post("https://id.sophos.com/api/v2/oauth2/token", json=mock_response)

    result = retrieve_jwt_token("a", "b", {})
    assert result == "xxxxxxx"

    result = retrieve_jwt_token(
        "a", "b", {"bearer_token": "aaaa", "valid_until": 999999999999999}
    )
    assert result == "aaaa"


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
        mock_response = load_mock_response("alert_list.json")
        requests_mock.post(f"{BASE_URL}/common/v1/alerts/search", json=mock_response)
        last_fetch, incidents = fetch_incidents(
            client, {"last_fetch": 1}, "1 days", ["x"], ["x"], "50"
        )
        wanted_time = datetime.timestamp(
            datetime.strptime("2020-11-04T09:31:19.895Z", DATE_FORMAT)
        )
        assert last_fetch.get("last_fetch") == wanted_time * 1000
        assert len(incidents) == 3
        assert (
            incidents[0].get("name")
            == "Sophos Central Alert 56931431-9faf-480c-ba1d-8d7541eae259"
        )

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
        mock_response = load_mock_response("alert_list.json")
        requests_mock.post(f"{BASE_URL}/common/v1/alerts/search", json=mock_response)
        last_fetch, incidents = fetch_incidents(
            client, {}, "12 years", ["x"], ["x"], "50"
        )
        wanted_time = datetime.timestamp(
            datetime.strptime("2020-11-04T09:31:19.895Z", DATE_FORMAT)
        )
        assert last_fetch.get("last_fetch") == wanted_time * 1000
        assert len(incidents) == 3
        assert (
            incidents[0].get("name")
            == "Sophos Central Alert 56931431-9faf-480c-ba1d-8d7541eae259"
        )

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
        mock_response = load_mock_response("empty.json")
        requests_mock.post(f"{BASE_URL}/common/v1/alerts/search", json=mock_response)
        last_fetch, incidents = fetch_incidents(
            client, {"last_fetch": 100000000}, "3 days", ["x"], ["x"], "50"
        )
        assert last_fetch.get("last_fetch") == 100000001
        assert len(incidents) == 0


class TestMain:
    @staticmethod
    def init_mocks(mocker, requests_mock, command):
        init_mock_client(requests_mock)
        mock_response = load_mock_response("auth_token.json")
        requests_mock.post(
            "https://id.sophos.com/api/v2/oauth2/token", json=mock_response
        )

        mocker.patch.object(demisto, "command", return_value=command)

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

        TestMain.init_mocks(mocker, requests_mock, "fetch-incidents")
        mock_response = load_mock_response("alert_list.json")
        requests_mock.post(f"{BASE_URL}/common/v1/alerts/search", json=mock_response)
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "first_fetch_time": "1 days",
                "fetch_severity": ["x"],
                "fetch_category": ["x"],
                "max_fetch": "50",
            },
        )
        mocker.patch.object(demisto, "getLastRun", return_value={"last_fetch": 1})
        demisto_incidents_mock = mocker.patch.object(demisto, "incidents")
        demisto_set_last_run_mock = mocker.patch.object(demisto, "setLastRun")

        main()

        assert demisto_set_last_run_mock.call_count == 1
        assert demisto_incidents_mock.call_count == 1
        incidents = (
            demisto_incidents_mock.call_args.args[0]
            if isinstance(demisto_incidents_mock.call_args.args[0], dict)
            else demisto_incidents_mock.call_args[0][0]
        )
        last_fetch = (
            demisto_set_last_run_mock.call_args.args[0]
            if isinstance(demisto_set_last_run_mock.call_args.args[0], dict)
            else demisto_set_last_run_mock.call_args[0][0]
        )

        wanted_time = datetime.timestamp(
            datetime.strptime("2020-11-04T09:31:19.895Z", DATE_FORMAT)
        )
        assert last_fetch.get("last_fetch") == wanted_time * 1000
        assert len(incidents) == 3
        assert (
            incidents[0].get("name")
            == "Sophos Central Alert 56931431-9faf-480c-ba1d-8d7541eae259"
        )

    @staticmethod
    def test_sophos_central_detected_exploit_list_command(
        mocker, requests_mock
    ) -> None:
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

        TestMain.init_mocks(
            mocker, requests_mock, "sophos-central-detected-exploit-list"
        )

        mock_response = load_mock_response("detected_exploit_list.json")
        requests_mock.get(
            f"{BASE_URL}/endpoint/v1/settings/exploit-mitigation/detected-exploits",
            json=mock_response,
        )
        mocker.patch.object(
            demisto,
            "args",
            return_value={
                "page_size": "30",
                "page": "1",
            },
        )
        demisto_results_mock = mocker.patch.object(demisto, "results")

        main()

        entry_context = (
            demisto_results_mock.call_args.args[0]["EntryContext"]
            if isinstance(demisto_results_mock.call_args.args[0], dict)
            else demisto_results_mock.call_args[0][0]["EntryContext"]
        )
        output = next(iter(entry_context.values()))
        assert len(output) == 3
        assert list(entry_context.keys())[0].startswith("SophosCentral.DetectedExploit")
        assert output[0].get("id") == "b81aac51-2fc0-ab6a-asdf-7b6bb6ac90b4"

    @staticmethod
    def test_invalid_command(mocker, requests_mock):
        from SophosCentral import main

        TestMain.init_mocks(mocker, requests_mock, "not-a-command")
        demisto_results_mock = mocker.patch.object(demisto, "results")

        with pytest.raises(SystemExit):
            main()

        error_entry = (
            demisto_results_mock.call_args.args[0]
            if isinstance(demisto_results_mock.call_args.args[0], dict)
            else demisto_results_mock.call_args[0][0]
        )
        assert error_entry["Type"] == EntryType.ERROR
        assert (
            'The "not-a-command" command was not implemented.'
            in error_entry["Contents"]
        )


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

    args = {"item_type": "certificateSigner", "certificate_signer": "xxx"}
    validate_item_fields(args)
    args = {"item_type": "certificateSigner", "path": "xxx"}
    with raises(DemistoException):
        validate_item_fields(args)


@pytest.mark.parametrize(
    "input_id, expected",
    [
        ("", ""),
        ("ba", "ab"),
        ("acb", "cab"),
        ("aabb", "aabb"),
        ("badcxwzy", "abcdwxyz"),
        ("bad-fehgi-xwzyr", "abd-efghi-wxyzr"),
        ("badc-fehgji-xwzy", "abcd-efghij-wxyz"),
    ],
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
        requests_mock.get(
            f"{BASE_URL}/common/v1/directory/users/5d407889-8659-46ab-86c5-4f227302df78",
            exc=ValueError,
        )

        alert = load_mock_response("alert_single.json")
        output = create_alert_output(client, alert, ["id", "name"])

        assert output["personName"] == ""

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

        client = init_mock_client(
            requests_mock,
            {"person_mapping": {"5d407889-8659-46ab-86c5-4f227302df78": "Cactus"}},
        )
        requests_mock.get(
            f"{BASE_URL}/common/v1/directory/users/5d407889-8659-46ab-86c5-4f227302df78",
            exc=ValueError,
        )

        alert = load_mock_response("alert_single.json")
        output = create_alert_output(client, alert, ["id", "name"])

        assert output["personName"] == "Cactus"

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

        client = init_mock_client(
            requests_mock,
            {"person_mapping": {"12345678-1337-1337-1337-1234567890ab": "Not Cactus"}},
        )
        mock_response = load_mock_response("person.json")
        requests_mock.get(
            f"{BASE_URL}/common/v1/directory/users/5d407889-8659-46ab-86c5-4f227302df78",
            json=mock_response,
        )

        alert = load_mock_response("alert_single.json")
        output = create_alert_output(client, alert, ["id", "name"])

        assert output["personName"] == r"Group\Cactus"
        assert (
            "5d407889-8659-46ab-86c5-4f227302df78"
            in client.integration_context["person_mapping"]
        )

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

        client = init_mock_client(
            requests_mock,
            {
                "managed_agent_mapping": {
                    "6e9567ea-bb50-40c5-9f12-42eb308e4c9b": "MyComputer"
                }
            },
        )

        alert = load_mock_response("alert_single.json")
        output = create_alert_output(client, alert, ["id", "name"])
        assert output["managedAgentName"] == "MyComputer"


def test_test_module(requests_mock) -> None:
    """
    Scenario: Test the validity of the connection.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - test_module is called.
    Then:
     - Ensure the returns value is correct.
    """
    from SophosCentral import test_module

    mock_response = load_mock_response("alert_list.json")
    requests_mock.get(f"{BASE_URL}/common/v1/alerts", json=mock_response)
    client = init_mock_client(requests_mock)

    result = test_module(client)
    assert result == "ok"


def test_test_module_exception() -> None:
    """
    Scenario: Exception raised while testing the validity of the connection.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - test_module is called.
    Then:
     - Ensure the valid Exception.
    """
    from SophosCentral import test_module

    result = None
    try:
        client = mock.Mock()
        client.list_alert.side_effect = DemistoException("Demisto Exception")
        result = test_module(client)
    except Exception as exception:
        assert result is None
        assert str(exception) == "Demisto Exception"


@patch("demistomock.params")
@patch("demistomock.info")
@patch("demistomock.command")
@patch("SophosCentral.retrieve_jwt_token")
@patch("SophosCentral.return_error")
def test_main_generic_exception(
    mock_return_error,
    mock_retrieve_jwt_token,
    mock_demisto_command,
    mock_demisto_info,
    mock_demisto_params,
) -> None:
    """
    Scenario: Exception raised while Parsing and Validating integration params.
    Given:
    When:
     - main method is called.
    Then:
     - Ensure the valid Exception.
    """
    from SophosCentral import main

    mock_demisto_params.return_value = {"credentials": {"identifier": "identifier"}}

    mock_demisto_info.return_value = {}
    mock_return_error.return_value = {}
    mock_demisto_command.return_value = "dummy_command"
    mock_retrieve_jwt_token.side_effect = Exception("main-exception")
    main()
    assert mock_return_error.called
    mock_return_error.assert_called_with(
        "Failed to execute dummy_command command. Error: main-exception"
    )


@patch("demistomock.params")
@patch("demistomock.info")
@patch("demistomock.command")
@patch("SophosCentral.retrieve_jwt_token")
@patch("SophosCentral.return_error")
def test_main_content_parsing_exception(
    mock_return_error,
    mock_retrieve_jwt_token,
    mock_demisto_command,
    mock_demisto_info,
    mock_demisto_params,
) -> None:
    """
    Scenario: Exception raised while Parsing and Validating integration params.
    Given:
    When:
     - main method is called.
    Then:
     - Ensure the valid Exception.
    """
    from SophosCentral import main

    mock_demisto_params.return_value = {"credentials": {"identifier": "identifier"}}

    mock_demisto_info.return_value = {}
    mock_return_error.return_value = {}
    mock_demisto_command.return_value = "dummy_command"
    mock_retrieve_jwt_token.side_effect = Exception(
        "Error parsing the query params or request body"
    )
    main()
    assert mock_return_error.called
    mock_return_error.assert_called_with(
        "Failed to execute dummy_command command. Error: Make sure the arguments are correctly formatted."
    )


@patch("demistomock.params")
@patch("demistomock.info")
@patch("demistomock.command")
@patch("SophosCentral.retrieve_jwt_token")
@patch("SophosCentral.return_error")
def test_main_unauthorized_exception(
    mock_return_error,
    mock_retrieve_jwt_token,
    mock_demisto_command,
    mock_demisto_info,
    mock_demisto_params,
) -> None:
    """
    Scenario: Exception raised while Parsing and Validating integration params.
    Given:
    When:
     - main method is called.
    Then:
     - Ensure the valid Exception.
    """
    from SophosCentral import main

    mock_demisto_params.return_value = {"credentials": {"identifier": "identifier"}}

    mock_demisto_info.return_value = {}
    mock_return_error.return_value = {}
    mock_demisto_command.return_value = "dummy_command"
    mock_retrieve_jwt_token.side_effect = Exception("Unauthorized")
    main()
    assert mock_return_error.called
    mock_return_error.assert_called_with(
        "Failed to execute dummy_command command. Error: Wrong credentials (ID and / or secret) given."
    )


@pytest.mark.parametrize(
    "cache,result",
    [
        ({}, False),
        ({"base_url": ""}, False),
        ({"tenant_id": ""}, False),
        ({"base_url": "", "tenant_id": ""}, True),
    ],
)
def test_cache_exists(cache, result):
    """
    Scenario: Validate "_cache_exists" method behaves correctly in various cases.
    When:
     - User execute any command
    Then:
     - Should return True only if both base_url and tenant_id exist in the cache.
     - Should return in all other cases.
    """
    set_integration_context(cache)

    from SophosCentral import Client

    assert Client._cache_exists() == result

    # clean up the cache
    set_integration_context({})


@pytest.mark.parametrize(
    "client_data,response",
    [
        (
            "whoami_tenant.json",
            {
                "creds_type": "tenant",
                "entity_id": "11f104c5-cc4a-4a9f-bb9c-632c936dfb9f",
                "base_url": "https://api-eu02.central.sophos.com",
            },
        ),
        (
            "whoami_partner.json",
            {
                "creds_type": "partner",
                "entity_id": "5AC55058-622D-4929-8E5D-8FF554F312FE",
                "base_url": None,
            },
        ),
        (
            "whoami_organization.json",
            {
                "creds_type": "organization",
                "entity_id": "C37A4BC7-715A-48FD-AE03-D184A391B136",
                "base_url": None,
            },
        ),
    ],
)
def test_whoami(requests_mock, client_data, response):
    """
    Scenario: "whoami" API call in various cases.
    When:
     - When user executes any command, "whoami" API would be called in order to
     get base_url or partner/org. ID
    Then:
     - Should return proper response retrieved from API in case of success.
    """
    from SophosCentral import Client, COMMON_BASE_URL

    mock_client_data = load_mock_response(client_data)
    requests_mock.get(f"{COMMON_BASE_URL}/whoami/v1", json=mock_client_data)

    whoami = Client._whoami(bearer_token="dummy_token")
    creds_type, entity_id, base_url = (
        str(whoami.get("idType")).lower(),
        whoami.get("id"),
        whoami.get("apiHosts", {}).get("dataRegion"),
    )

    assert isinstance(whoami, dict)
    assert creds_type == response.get("creds_type")
    assert entity_id == response.get("entity_id")
    assert base_url == response.get("base_url")


def test_whoami_failure(requests_mock):
    """
    Scenario: "whoami" API call in various cases.
    When:
     - When user executes any command, "whoami" API would be called in order to
     get base_url or partner/org. ID
    Then:
     - Should raise proper exception in case of API call failure.
    """
    from SophosCentral import Client, COMMON_BASE_URL

    requests_mock.get(f"{COMMON_BASE_URL}/whoami/v1", status_code=401)

    with raises(
        DemistoException,
        match="An HTTP error occurred while validating the given tenant ID: ",
    ):
        Client._whoami(bearer_token="dummy_token")


@pytest.mark.parametrize(
    "exception,error",
    [
        (
            requests.exceptions.ConnectTimeout,
            "Connection error occurred while validating the given tenant ID: ",
        ),
        (
            requests.exceptions.Timeout,
            "Request timed out while validating the given tenant ID: ",
        ),
        (
            requests.exceptions.RequestException,
            "An error occurred while making REST API call to validate the given tenant ID: ",
        ),
        (Exception, "An error occurred while processing the API response: "),
    ],
)
def test_whoami_exceptions(requests_mock, exception, error):
    """
    Scenario: "whoami" API call in various cases.
    When:
     - When user executes any command, "whoami" API would be called in order to
     get base_url or partner/org. ID
    Then:
     - Should raise proper exception in case of API call failure.
    """
    from SophosCentral import Client, COMMON_BASE_URL

    requests_mock.get(f"{COMMON_BASE_URL}/whoami/v1", exc=exception)

    with raises(DemistoException, match=error):
        Client._whoami(bearer_token="dummy_token")


@pytest.mark.parametrize("creds_type", ["partner", "organization"])
def test_get_tenant_base_url(requests_mock, creds_type):
    """
    Scenario: Test "search tenant" API in various cases.
    When:
     - When user enters tenant ID as input, it'll be validated by searching
     the tenant in partner/organization.
    Then:
     - Should return proper response retrieved from API in case of success.
    """
    from SophosCentral import Client, COMMON_BASE_URL

    mock_client_data = load_mock_response("tenant_search.json")
    # Change base URL for proper assertion
    mock_client_data["apiHost"] += f"/{creds_type}"
    requests_mock.get(
        f"{COMMON_BASE_URL}/{creds_type}/v1/tenants/dummy-tenant-id",
        json=mock_client_data,
    )

    base_url = Client._get_tenant_base_url(
        bearer_token="dummy-token",
        entity_id="dummy-entity-id",
        tenant_id="dummy-tenant-id",
        creds_type=creds_type,
    )

    assert base_url == f"dummy_url/{creds_type}"


@pytest.mark.parametrize("creds_type", ["partner", "organization"])
def test_get_tenant_base_url_not_found(requests_mock, creds_type):
    """
    Scenario: Test "search tenant" API in various cases.
    When:
     - When user enters tenant ID as input, it'll be validated by searching
     the tenant in partner/organization.
    Then:
     - Should return proper base URL in case of invalid
     tenant ID provided for partner/organization.
    """
    from SophosCentral import Client, COMMON_BASE_URL

    requests_mock.get(
        f"{COMMON_BASE_URL}/{creds_type}/v1/tenants/dummy-tenant-id",
        status_code=404,
    )

    base_url = Client._get_tenant_base_url(
        bearer_token="dummy-token",
        entity_id="dummy-entity-id",
        tenant_id="dummy-tenant-id",
        creds_type=creds_type,
    )

    assert base_url == ""


@pytest.mark.parametrize(
    "exception,error",
    [
        (
            requests.exceptions.ConnectTimeout,
            "Connection error occurred while validating the given tenant ID: ",
        ),
        (
            requests.exceptions.Timeout,
            "Request timed out while validating the given tenant ID: ",
        ),
        (
            requests.exceptions.RequestException,
            "An error occurred while making REST API call to validate the given tenant ID: ",
        ),
        (Exception, "An error occurred while processing the API response: "),
    ],
)
def test_get_tenant_base_url_exceptions(requests_mock, exception, error):
    """
    Scenario: Test "search tenant" API in various cases.
    When:
     - When user enters tenant ID as input, it'll be validated by searching
     the tenant in partner/organization.
    Then:
     - Should return proper error message in case of API call failure.
    """
    from SophosCentral import Client, COMMON_BASE_URL

    requests_mock.get(
        f"{COMMON_BASE_URL}/partner/v1/tenants/dummy-tenant-id", exc=exception
    )

    with raises(DemistoException, match=error):
        Client._get_tenant_base_url(
            bearer_token="dummy-token",
            entity_id="dummy-entity-id",
            tenant_id="dummy-tenant-id",
            creds_type="partner",
        )


def test_get_client_data_case1() -> None:
    """
    Scenario: Get the client data before executing a command.
    Given:
     - User has provided valid credentials.
     - JWT token has been returned by retrieve_jwt_token().
    When:
     - Every time after retrieve_jwt_token() and before any command.
     - Case1: When cache exists and the input tenant id is same as stored in cache.
     In this case, no API calls would be made and the cached tenant ID and base URL
     would be used.
    Then:
     - Ensure base URL is correct according to mock response.
     - Ensure headers are correct according to given fake JWT token and mock response.
    """
    from SophosCentral import Client

    # set the cache
    set_integration_context(
        {"base_url": "cached-base-url", "tenant_id": "cached-tenant-id"}
    )

    headers, base_url = Client.get_client_data(
        tenant_id="cached-tenant-id", bearer_token="dummy-bearer-token"
    )
    assert base_url == "cached-base-url"
    assert headers == {
        "Authorization": "Bearer dummy-bearer-token",
        "X-Tenant-ID": "cached-tenant-id",
    }

    # clean up the cache
    set_integration_context({})


def test_get_client_data_case2(requests_mock) -> None:
    """
    Scenario: Get the client data before executing a command.
    Given:
     - User has provided valid credentials.
     - JWT token has been returned by retrieve_jwt_token().
    When:
     - Every time after retrieve_jwt_token() and before any command.
     - Case2: When cache does not exist and the input tenant id is provided
     with tenant level credentials.
    Then:
     - A proper error should be raised stating that tenant ID field should be empty
     if tenant level credentials are being used.
    """
    from SophosCentral import Client, COMMON_BASE_URL

    # empty the cache
    set_integration_context({})

    # mock whoami response
    mock_client_data = load_mock_response("whoami_tenant.json")
    requests_mock.get(f"{COMMON_BASE_URL}/whoami/v1", json=mock_client_data)

    error_msg = "Value provided in tenant ID field is not same as configured tenant whose credentials are entered."

    with raises(DemistoException, match=error_msg):
        Client.get_client_data(
            tenant_id="dummy-tenant-id", bearer_token="dummy-bearer-token"
        )


@pytest.mark.parametrize("creds_type", ["partner", "organization"])
def test_get_client_data_case3(requests_mock, creds_type) -> None:
    """
    Scenario: Get the client data before executing a command.
    Given:
     - User has provided valid credentials.
     - JWT token has been returned by retrieve_jwt_token().
    When:
     - Every time after retrieve_jwt_token() and before any command.
     - Case3: When cache does not exist and the input tenant id is provided and it is valid
     with partner/organization level credentials.
    Then:
     - Ensure base URL is correct according to mock response.
     - Ensure headers are correct according to given fake JWT token and mock response.
     - Cache should be updated with new tenant ID and base URL.
    """
    from SophosCentral import Client, COMMON_BASE_URL

    set_integration_context({"bearer_token": "dummy-bearer-token"})
    tenant_id = "dummy-tenant-id"

    # mock whoami response
    mock_client_data = load_mock_response(f"whoami_{creds_type}.json")
    requests_mock.get(f"{COMMON_BASE_URL}/whoami/v1", json=mock_client_data)

    # mock search tenant response
    mock_client_data = load_mock_response("tenant_search.json")
    requests_mock.get(
        f"{COMMON_BASE_URL}/{creds_type}/v1/tenants/{tenant_id}", json=mock_client_data
    )

    headers, base_url = Client.get_client_data(
        tenant_id=tenant_id, bearer_token="dummy-bearer-token"
    )

    assert base_url == "dummy_url/"
    assert headers == {
        "Authorization": "Bearer dummy-bearer-token",
        "X-Tenant-ID": tenant_id,
    }

    cache = get_integration_context()
    # existing cache should not be lost
    assert "bearer_token" in cache
    assert cache.get("bearer_token") == "dummy-bearer-token"

    assert "base_url" in cache
    assert "tenant_id" in cache

    assert cache.get("base_url") == "dummy_url/"
    assert cache.get("tenant_id") == tenant_id

    # clean up the cache
    set_integration_context({})


@pytest.mark.parametrize("creds_type", ["partner", "organization"])
def test_get_client_data_case4(requests_mock, creds_type) -> None:
    """
    Scenario: Get the client data before executing a command.
    Given:
     - User has provided valid credentials.
     - JWT token has been returned by retrieve_jwt_token().
    When:
     - Every time after retrieve_jwt_token() and before any command.
     - Case4: When cache does not exist and the input tenant id is provided and it is invalid
     with partner/organization level credentials.
    Then:
     - A proper error should be raised stating that the provided tenant ID is
     invalid in partner/organization.
     - Cache should not be updated.
    """
    from SophosCentral import Client, COMMON_BASE_URL

    set_integration_context({"bearer_token": "dummy-bearer-token"})
    tenant_id = "dummy-invalid-tenant-id"

    # mock whoami response
    mock_client_data = load_mock_response(f"whoami_{creds_type}.json")
    requests_mock.get(f"{COMMON_BASE_URL}/whoami/v1", json=mock_client_data)

    # mock search tenant response
    requests_mock.get(
        f"{COMMON_BASE_URL}/{creds_type}/v1/tenants/{tenant_id}", status_code=404
    )

    error_msg = (
        f"Value provided in tenant ID is not from managed tenants of "
        f"configured {creds_type} whose credentials are entered"
    )
    with raises(DemistoException, match=error_msg):
        Client.get_client_data(tenant_id=tenant_id, bearer_token="dummy-bearer-token")

    cache = get_integration_context()
    # existing cache should not be lost
    assert "bearer_token" in cache
    assert cache.get("bearer_token") == "dummy-bearer-token"

    assert "base_url" not in cache
    assert "tenant_id" not in cache

    # clean up the cache
    set_integration_context({})


@pytest.mark.parametrize("creds_type", ["partner", "organization"])
def test_get_client_data_case5(requests_mock, creds_type) -> None:
    """
    Scenario: Get the client data before executing a command.
    Given:
     - User has provided valid credentials.
     - JWT token has been returned by retrieve_jwt_token().
    When:
     - Every time after retrieve_jwt_token() and before any command.
     - Case5: When cache does not exist and the input tenant id is not provided
     with partner/organization level credentials.
    Then:
     - A proper error should be raised stating that the tenant ID is required
     with partner/organization level credentials.
     - Cache should not be updated.
    """
    from SophosCentral import Client, COMMON_BASE_URL

    set_integration_context({"bearer_token": "dummy-bearer-token"})
    tenant_id = None

    # mock whoami response
    mock_client_data = load_mock_response(f"whoami_{creds_type}.json")
    requests_mock.get(f"{COMMON_BASE_URL}/whoami/v1", json=mock_client_data)

    error_msg = (
        f"Tenant ID field is mandatory to configure {creds_type} user's credential"
    )
    with raises(DemistoException, match=error_msg):
        Client.get_client_data(tenant_id=tenant_id, bearer_token="dummy-bearer-token")

    cache = get_integration_context()
    # existing cache should not be lost
    assert "bearer_token" in cache
    assert cache.get("bearer_token") == "dummy-bearer-token"

    assert "base_url" not in cache
    assert "tenant_id" not in cache

    # clean up the cache
    set_integration_context({})


def test_get_client_data_case6(requests_mock) -> None:
    """
    Scenario: Get the client data before executing a command.
    Given:
     - User has provided valid credentials.
     - JWT token has been returned by retrieve_jwt_token().
    When:
     - Every time after retrieve_jwt_token() and before any command.
     - Case6: When cache does not exist and the input tenant id is not provided
     with tenant level credentials.
    Then:
     - Ensure base URL is correct according to mock response.
     - Ensure headers are correct according to given fake JWT token and mock response.
     - Cache should be updated with new tenant ID and base URL.
    """
    from SophosCentral import Client, COMMON_BASE_URL

    set_integration_context({"bearer_token": "dummy-bearer-token"})
    tenant_id = ""

    # mock whoami response
    mock_client_data = load_mock_response("whoami_tenant.json")
    requests_mock.get(f"{COMMON_BASE_URL}/whoami/v1", json=mock_client_data)

    headers, base_url = Client.get_client_data(
        tenant_id=tenant_id, bearer_token="dummy-bearer-token"
    )

    assert base_url == "https://api-eu02.central.sophos.com/"
    assert headers == {
        "Authorization": "Bearer dummy-bearer-token",
        "X-Tenant-ID": "11f104c5-cc4a-4a9f-bb9c-632c936dfb9f",
    }

    # assert cache updates
    cache = get_integration_context()
    # existing cache should not be lost
    assert "bearer_token" in cache
    assert cache.get("bearer_token") == "dummy-bearer-token"

    assert "base_url" in cache
    assert "tenant_id" in cache

    assert cache.get("base_url") == "https://api-eu02.central.sophos.com/"
    assert cache.get("tenant_id") == "11f104c5-cc4a-4a9f-bb9c-632c936dfb9f"

    # clean up the cache
    set_integration_context({})


@pytest.mark.parametrize("creds_type", ["partner", "organization"])
def test_get_client_data_case7(requests_mock, creds_type) -> None:
    """
    Scenario: Get the client data before executing a command.
    Given:
     - User has provided valid credentials.
     - JWT token has been returned by retrieve_jwt_token().
    When:
     - Every time after retrieve_jwt_token() and before any command.
     - Case7: When cache exists and the input tenant id (non empty) is different
     from cached one with partner/organization level credentials.
    Then:
     - Ensure base URL is correct according to mock response.
     - Ensure headers are correct according to given fake JWT token and mock response.
     - Cache should be updated with new tenant ID and base URL.
    """
    from SophosCentral import Client, COMMON_BASE_URL

    set_integration_context(
        {
            "bearer_token": "dummy-bearer-token",
            "base_url": "cached-base-url",
            "tenant_id": "cached-tenant-id",
        }
    )
    tenant_id = "different-tenant-id"

    # mock whoami response
    mock_client_data = load_mock_response(f"whoami_{creds_type}.json")
    requests_mock.get(f"{COMMON_BASE_URL}/whoami/v1", json=mock_client_data)

    # mock search tenant response
    mock_client_data = load_mock_response("tenant_search.json")
    requests_mock.get(
        f"{COMMON_BASE_URL}/{creds_type}/v1/tenants/{tenant_id}", json=mock_client_data
    )

    headers, base_url = Client.get_client_data(
        tenant_id=tenant_id, bearer_token="dummy-bearer-token"
    )

    assert base_url == "dummy_url/"
    assert headers == {
        "Authorization": "Bearer dummy-bearer-token",
        "X-Tenant-ID": tenant_id,
    }

    # assert cache updates
    cache = get_integration_context()
    # existing cache should not be lost
    assert "bearer_token" in cache
    assert cache.get("bearer_token") == "dummy-bearer-token"

    assert "base_url" in cache
    assert "tenant_id" in cache

    # cache should be updated
    assert cache.get("base_url") == "dummy_url/"
    assert cache.get("tenant_id") == tenant_id

    # clean up the cache
    set_integration_context({})


def test_get_client_data_case8(requests_mock) -> None:
    """
    Scenario: Get the client data before executing a command.
    Given:
     - User has provided valid credentials.
     - JWT token has been returned by retrieve_jwt_token().
    When:
     - Every time after retrieve_jwt_token() and before any command.
     - Case8: When cache exists and the input tenant id (empty) is different
     from cached one with tenant level credentials.
    Then:
     - Ensure base URL is correct according to mock response.
     - Ensure headers are correct according to given fake JWT token and mock response.
     - Cache should be updated with new tenant ID and base URL.
    """
    from SophosCentral import Client, COMMON_BASE_URL

    set_integration_context(
        {
            "bearer_token": "dummy-bearer-token",
            "base_url": "cached-base-url",
            "tenant_id": "cached-tenant-id",
        }
    )
    tenant_id = ""

    # mock whoami response
    mock_client_data = load_mock_response("whoami_tenant.json")
    requests_mock.get(f"{COMMON_BASE_URL}/whoami/v1", json=mock_client_data)

    headers, base_url = Client.get_client_data(
        tenant_id=tenant_id, bearer_token="dummy-bearer-token"
    )

    assert base_url == "https://api-eu02.central.sophos.com/"
    assert headers == {
        "Authorization": "Bearer dummy-bearer-token",
        "X-Tenant-ID": "11f104c5-cc4a-4a9f-bb9c-632c936dfb9f",
    }

    # assert cache updates
    cache = get_integration_context()
    # existing cache should not be lost
    assert "bearer_token" in cache
    assert cache.get("bearer_token") == "dummy-bearer-token"

    assert "base_url" in cache
    assert "tenant_id" in cache

    # cache should be updated
    assert cache.get("base_url") == "https://api-eu02.central.sophos.com/"
    assert cache.get("tenant_id") == "11f104c5-cc4a-4a9f-bb9c-632c936dfb9f"

    # clean up the cache
    set_integration_context({})


@pytest.mark.parametrize(
    "new_context,resultant_context",
    [
        (
            {
                "base_url": "cached-base-url",
                "tenant_id": "cached-tenant-id",
            },
            {
                "bearer_token": "dummy-bearer-token",
                "base_url": "cached-base-url",
                "tenant_id": "cached-tenant-id",
            },
        ),
        ({}, {"bearer_token": "dummy-bearer-token"}),
    ],
)
def test_update_integration_context(new_context, resultant_context) -> None:
    """
    Scenario: Upgrade existing integration context with new kv pairs.
    Given:
     - Integration context already exists.
    When:
     - Whenever new key-value pairs are required to be added in existing integration context.
    Then:
     - Ensure new key values are updated without the loss of existing context.
    """
    # set integration context
    set_integration_context({"bearer_token": "dummy-bearer-token"})

    from SophosCentral import Client

    Client._update_integration_context(new_context)

    new_context = get_integration_context()
    assert new_context == resultant_context


@pytest.mark.parametrize(
    "context",
    [
        {},
        {"dummy_key": "dummy_val"},
        {"dummy_key1": "dummy_val1", "dummy_key2": "dummy_val2"},
    ],
)
def test_invalidate_context(context) -> None:
    """
    Scenario: Demisto integration context should be invalidated if client credentials are changed.
    Given:
     - User has provided new credentials.
    When:
     - When user changes credentials (client-id and secret).
    Then:
     - Integration context should be invalidated.
    """
    from SophosCentral import invalidate_context

    set_integration_context(context)
    invalidate_context("new_client_id")
    assert get_integration_context() == {"client_id": "new_client_id"}


@pytest.mark.parametrize(
    "context,client_id,as_expected",
    [
        ({"client_id": "dummy_id"}, "dummy_id", False),
        ({}, "dummy_id", True),
        ({"client_id": ""}, "dummy_id", True),
        ({"client_id": "other_dummy_id"}, "dummy_id", True),
        ({"token": "token_value"}, "dummy_id", True),
    ],
)
def test_creds_changed(context, client_id, as_expected) -> None:
    """
    Scenario: To detect changes in credentials.
    When:
     - When user changes credentials (client-id and secret).
    Then:
     - Change in credentials should be detected correctly.
    """
    from SophosCentral import creds_changed

    set_integration_context(context)
    assert creds_changed(get_integration_context(), client_id) is as_expected


def test_insecure_connection(requests_mock):
    """
    Scenario: Test behaviour in case of invalid SSL certificate.
    When:
     - API server does not have a valid SSL certificate and the verification fails.
    Then:
     - A proper error message should be displayed to the user.
    """
    from SophosCentral import Client, COMMON_BASE_URL

    requests_mock.get(f"{COMMON_BASE_URL}/whoami/v1", exc=requests.exceptions.SSLError)

    # assert that a valid exception is raised with proper error message
    with raises(DemistoException, match="SSL Certificate Verification Failed.*"):
        Client._whoami(bearer_token="dummy_token")


def test_proxy_error(requests_mock):
    """
    Scenario: Test behaviour in case of proxy error.
    When:
     - XSOAR system proxy is invalid or not reachable.
    Then:
     - A proper error message should be displayed to the user.
    """
    from SophosCentral import Client, COMMON_BASE_URL

    requests_mock.get(
        f"{COMMON_BASE_URL}/whoami/v1", exc=requests.exceptions.ProxyError
    )

    # assert that a valid exception is raised with proper error message
    with raises(DemistoException, match="Proxy Error.*"):
        Client._whoami(bearer_token="dummy_token")


def test_cache_with_tenant_level_creds(requests_mock):
    """
    Scenario: Test behaviour of cache in case of tenant level credentials.
    When:
     - User has configured tenant level credentials without providing tenant ID.
    Then:
     - Cache should be updated with proper fields and subsequent calls should use cache
       instead of calling APIs.
    """
    # set integration context
    set_integration_context({})

    from SophosCentral import Client, COMMON_BASE_URL

    # mock whoami response
    requests_mock.get(
        f"{COMMON_BASE_URL}/whoami/v1", json=load_mock_response("whoami_tenant.json")
    )

    Client.get_client_data("", "dummy-token")

    context = get_integration_context()
    assert context == {
        "base_url": "https://api-eu02.central.sophos.com/",
        "tenant_id": "11f104c5-cc4a-4a9f-bb9c-632c936dfb9f",
        "is_tenant_level": True,
    }

    # make a subsequent call. Following exception should not be raised and cached base URL should be used.
    # This would ensure that no API is being called.
    requests_mock.get(f"{COMMON_BASE_URL}/whoami/v1", exc=requests.exceptions.HTTPError)
    Client.get_client_data("", "dummy-token")

    # assert the cache after next call.
    assert context == {
        "base_url": "https://api-eu02.central.sophos.com/",
        "tenant_id": "11f104c5-cc4a-4a9f-bb9c-632c936dfb9f",
        "is_tenant_level": True,
    }


def test_isolate_endpoint_command(requests_mock) -> None:
    """
    Scenario: Endpoint isolation command.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos-central-isolate-endpoint is called.
    Then:
     - Ensure the request body is correct.
     - Ensure the response is correct in case of success.
    """
    from SophosCentral import sophos_central_isolate_endpoint_command

    endpoint_id = "25de27bc-b07a-4728-b7b2-a021365ebbcd"
    mock_response = load_mock_response("isolate_endpoint.json")
    mock_response["items"][0]["id"] = endpoint_id
    requests_mock.post(
        f"{BASE_URL}/endpoint/v1/endpoints/isolation",
        json=mock_response,
        status_code=202,
    )
    client = init_mock_client(requests_mock)

    result = sophos_central_isolate_endpoint_command(
        client, {"endpoint_id": endpoint_id}
    )
    assert result.outputs_prefix == "SophosCentral.EndpointIsolation"
    assert result.outputs.get("items")[0].get("id") == endpoint_id
    assert result.readable_output == "Endpoint(s) isolated successfully."


def test_isolate_endpoint_command_exception(requests_mock) -> None:
    """
    Scenario: Endpoint isolation command.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos-central-isolate-endpoint is called.
    Then:
     - Ensure the request body is correct.
     - Ensure the response is correct in case of failure.
    """
    from SophosCentral import sophos_central_isolate_endpoint_command

    endpoint_id = "25de27bc-b07a-4728-b7b2-a021365ebbcd"
    mock_response = load_mock_response("isolate_endpoint.json")
    mock_response["items"][0]["id"] = endpoint_id
    requests_mock.post(
        f"{BASE_URL}/endpoint/v1/endpoints/isolation",
        json=mock_response,
        status_code=400,
    )
    client = init_mock_client(requests_mock)

    with pytest.raises(DemistoException):
        sophos_central_isolate_endpoint_command(client, {"endpoint_id": endpoint_id})


def test_deisolate_endpoint_command(requests_mock) -> None:
    """
    Scenario: Endpoint de-isolation command.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos-central-deisolate-endpoint is called.
    Then:
     - Ensure the request body is correct.
     - Ensure the response is correct in case of success.
    """
    from SophosCentral import sophos_central_deisolate_endpoint_command

    endpoint_id = "25de27bc-b07a-4728-b7b2-a021365ebbcd"
    mock_response = load_mock_response("deisolate_endpoint.json")
    mock_response["items"][0]["id"] = endpoint_id
    requests_mock.post(
        f"{BASE_URL}/endpoint/v1/endpoints/isolation",
        json=mock_response,
        status_code=202,
    )
    client = init_mock_client(requests_mock)

    result = sophos_central_deisolate_endpoint_command(
        client, {"endpoint_id": endpoint_id}
    )
    assert result.outputs_prefix == "SophosCentral.EndpointIsolation"
    assert result.outputs.get("items")[0].get("id") == endpoint_id
    assert result.readable_output == "Endpoint(s) de-isolated successfully."


def test_deisolate_endpoint_command_exception(requests_mock) -> None:
    """
    Scenario: Endpoint isolation command.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - sophos-central-isolate-endpoint is called.
    Then:
     - Ensure the request body is correct.
     - Ensure the response is correct in case of failure.
    """
    from SophosCentral import sophos_central_deisolate_endpoint_command

    endpoint_id = "25de27bc-b07a-4728-b7b2-a021365ebbcd"
    mock_response = load_mock_response("isolate_endpoint.json")
    mock_response["items"][0]["id"] = endpoint_id
    requests_mock.post(
        f"{BASE_URL}/endpoint/v1/endpoints/isolation",
        json=mock_response,
        status_code=400,
    )
    client = init_mock_client(requests_mock)

    with pytest.raises(DemistoException):
        sophos_central_deisolate_endpoint_command(client, {"endpoint_id": endpoint_id})
