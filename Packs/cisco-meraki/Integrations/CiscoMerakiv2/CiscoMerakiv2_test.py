import json
import os
import unittest.mock
from typing import Any, Callable

import CiscoMerakiv2
import pytest

import CommonServerPython

TEST_DATA = "test_data"
BASE_URL = "https://api.meraki.com/api/v1"


def load_json_file(file_name: str) -> list[dict[str, Any]] | dict[str, Any]:
    """Load the content of a JSON file.

    Args:
        file_name (str): Name of the JSON file to read and load.
    Returns:
        list[dict[str, Any]] | dict[str, Any]: Loaded file's content.
    """
    file_path = os.path.join(TEST_DATA, file_name)

    with open(file_path, mode="r", encoding="utf-8") as mock_file:
        return json.loads(mock_file.read())


@pytest.fixture()
def mock_client() -> CiscoMerakiv2.Client:
    """Establish a mock connection to the client with an API key.

    Returns:
        Client: Mock connection to client.
    """
    return CiscoMerakiv2.Client(
        base_url="https://api.meraki.com",
        api_key="Pokemon",
    )


@pytest.mark.parametrize(
    (
        "list_command,"
        "args,"
        "endpoint_suffix,"
        "response_file,"
        "table_file,"
        "readable_output_title,"
        "table_headers,"
        "outputs_key_field,"
        "outputs_prefix"
    ),
    [
        (
            CiscoMerakiv2.list_organization_command,
            {},
            "organizations",
            "organization_response.json",
            "organization_table.json",
            "Organization(s)",
            CiscoMerakiv2.ORGANIZATION_TABLE_HEADERS,
            "id",
            CiscoMerakiv2.ORGANIZATION_PREFIX,
        ),
        (
            CiscoMerakiv2.list_network_command,
            {"organization_id": "123"},
            "organizations/123/networks",
            "network_response.json",
            "network_table.json",
            "Network(s)",
            CiscoMerakiv2.NETWORK_TABLE_HEADERS,
            "id",
            CiscoMerakiv2.NETWORK_PREFIX,
        ),
        (
            CiscoMerakiv2.list_organization_inventory_command,
            {"organization_id": "123"},
            "organizations/123/inventory/devices",
            "inventory_response.json",
            "inventory_table.json",
            "Inventory Device(s)",
            CiscoMerakiv2.INVENTORY_TABLE_HEADERS,
            "serial",
            CiscoMerakiv2.INVENTORY_PREFIX,
        ),
        (
            CiscoMerakiv2.search_organization_device_command,
            {"organization_id": "123"},
            "organizations/123/devices",
            "device_response.json",
            "device_table.json",
            "Device(s)",
            CiscoMerakiv2.DEVICE_TABLE_HEADERS,
            "serial",
            CiscoMerakiv2.DEVICE_PREFIX,
        ),
        (
            CiscoMerakiv2.list_device_status_command,
            {"organization_id": "123"},
            "organizations/123/devices/statuses",
            "device_status_response.json",
            "device_status_table.json",
            "Device Status(es)",
            CiscoMerakiv2.DEVICE_STATUS_TABLE_HEADERS,
            "serial",
            CiscoMerakiv2.DEVICE_STATUS_PREFIX,
        ),
        (
            CiscoMerakiv2.list_organization_uplink_status_command,
            {"organization_id": "123"},
            "organizations/123/uplinks/statuses",
            "uplink_status_response.json",
            "uplink_status_table.json",
            "Uplink Status(es)",
            CiscoMerakiv2.ORGANIZATION_UPLINK_STATUS_TABLE_HEADERS,
            "serial",
            CiscoMerakiv2.ORGANIZATION_UPLINK_STATUS_PREFIX,
        ),
        (
            CiscoMerakiv2.list_organization_client_command,
            {"organization_id": "123", "mac": "456"},
            "organizations/123/clients/search",
            "client_response.json",
            "client_table.json",
            "Client k74272e MAC 00:00:00:00:00:00 Record(s)",
            CiscoMerakiv2.CLIENT_TABLE_HEADERS,
            "clientId",
            CiscoMerakiv2.CLIENT_PREFIX,
        ),
        (
            CiscoMerakiv2.list_network_client_command,
            {"network_id": "123"},
            "networks/123/clients",
            "network_client_response.json",
            "network_client_table.json",
            "Network Monitor Client(s)",
            CiscoMerakiv2.NETWORK_CLIENT_TABLE_HEADERS,
            "id",
            CiscoMerakiv2.NETWORK_CLIENT_PREFIX,
        ),
        (
            CiscoMerakiv2.list_network_client_policy_command,
            {"network_id": "123"},
            "networks/123/policies/byClient",
            "client_policy_response.json",
            "client_policy_table.json",
            "Client's Policies",
            CiscoMerakiv2.CLIENT_POLICY_TABLE_HEADERS,
            "clientId",
            CiscoMerakiv2.CLIENT_POLICY_PREFIX,
        ),
    ],
)
def test_list_commands_manual_pagination(
    requests_mock,
    mock_client: CiscoMerakiv2.Client,
    list_command: Callable[[CiscoMerakiv2.Client, dict[str, Any]], list[CommonServerPython.CommandResults]],
    args: dict[str, Any],
    endpoint_suffix: str,
    response_file: str,
    table_file: str,
    readable_output_title: str,
    table_headers: list[str],
    outputs_key_field: str,
    outputs_prefix: str,
) -> None:
    """
    Scenario:
    - Test retrieving a list of objects.

    Given:
    - Command args and a `page_size`.

    When:
    - list_organization_command
    - list_network_command
    - list_organization_inventory_command
    - search_organization_device_command
    - list_device_status_command
    - list_organization_uplink_status_command
    - list_organization_client_command
    - list_network_client_command
    - list_network_client_policy_command

    Then:
    - Ensure that there is only one CommandResults.
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults readable_output is correct.
    - Ensure that the CommandResults raw_response is correct.
    """
    args["page_size"] = 5

    mock_response = load_json_file(response_file)
    mock_table = load_json_file(table_file)

    requests_mock.get(
        url=CommonServerPython.urljoin(BASE_URL, endpoint_suffix),
        json=mock_response,
    )

    command_results = list_command(mock_client, args)

    assert len(command_results) == 1
    assert command_results[0].outputs_prefix.endswith(outputs_prefix)
    assert command_results[0].outputs_key_field == outputs_key_field
    assert command_results[0].outputs == mock_response
    assert command_results[0].readable_output == CommonServerPython.tableToMarkdown(
        name=readable_output_title,
        t=mock_table,
        headers=table_headers,
        removeNull=True,
    )
    assert command_results[0].raw_response == mock_response


@pytest.mark.parametrize(
    (
        "list_command,"
        "args,"
        "endpoint_suffix,"
        "readable_output_title,"
        "table_headers,"
        "outputs_key_field,"
        "outputs_prefix"
    ),
    [
        (
            CiscoMerakiv2.list_organization_command,
            {},
            "organizations",
            "Organization(s)",
            CiscoMerakiv2.ORGANIZATION_TABLE_HEADERS,
            "id",
            CiscoMerakiv2.ORGANIZATION_PREFIX,
        ),
        (
            CiscoMerakiv2.list_network_command,
            {"organization_id": "123"},
            "organizations/123/networks",
            "Network(s)",
            CiscoMerakiv2.NETWORK_TABLE_HEADERS,
            "id",
            CiscoMerakiv2.NETWORK_PREFIX,
        ),
        (
            CiscoMerakiv2.list_organization_inventory_command,
            {"organization_id": "123"},
            "organizations/123/inventory/devices",
            "Inventory Device(s)",
            CiscoMerakiv2.INVENTORY_TABLE_HEADERS,
            "serial",
            CiscoMerakiv2.INVENTORY_PREFIX,
        ),
        (
            CiscoMerakiv2.search_organization_device_command,
            {"organization_id": "123"},
            "organizations/123/devices",
            "Device(s)",
            CiscoMerakiv2.DEVICE_TABLE_HEADERS,
            "serial",
            CiscoMerakiv2.DEVICE_PREFIX,
        ),
        (
            CiscoMerakiv2.list_device_status_command,
            {"organization_id": "123"},
            "organizations/123/devices/statuses",
            "Device Status(es)",
            CiscoMerakiv2.DEVICE_STATUS_TABLE_HEADERS,
            "serial",
            CiscoMerakiv2.DEVICE_STATUS_PREFIX,
        ),
        (
            CiscoMerakiv2.list_organization_uplink_status_command,
            {"organization_id": "123"},
            "organizations/123/uplinks/statuses",
            "Uplink Status(es)",
            CiscoMerakiv2.ORGANIZATION_UPLINK_STATUS_TABLE_HEADERS,
            "serial",
            CiscoMerakiv2.ORGANIZATION_UPLINK_STATUS_PREFIX,
        ),
        (
            CiscoMerakiv2.list_network_client_command,
            {"network_id": "123"},
            "networks/123/clients",
            "Network Monitor Client(s)",
            CiscoMerakiv2.NETWORK_CLIENT_TABLE_HEADERS,
            "id",
            CiscoMerakiv2.NETWORK_CLIENT_PREFIX,
        ),
        (
            CiscoMerakiv2.list_network_client_policy_command,
            {"network_id": "123"},
            "networks/123/policies/byClient",
            "Client's Policies",
            CiscoMerakiv2.CLIENT_POLICY_TABLE_HEADERS,
            "clientId",
            CiscoMerakiv2.CLIENT_POLICY_PREFIX,
        ),
    ],
)
def test_list_commands_automatic_pagination(
    requests_mock,
    mock_client: CiscoMerakiv2.Client,
    list_command: Callable[[CiscoMerakiv2.Client, dict[str, Any]], list[CommonServerPython.CommandResults]],
    args: dict[str, Any],
    endpoint_suffix: str,
    readable_output_title: str,
    table_headers: list[str],
    outputs_key_field: str,
    outputs_prefix: str,
) -> None:
    """
    Scenario:
    - Test retrieving a list of objects through making multiple HTTP requests.

    Given:
    - Command args and a `limit`.

    When:
    - list_organization_command
    - list_network_command
    - list_organization_inventory_command
    - search_organization_device_command
    - list_device_status_command
    - list_organization_uplink_status_command
    - list_network_client_command
    - list_network_client_policy_command

    Then:
    - Ensure that there is only one CommandResults.
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults readable_output is correct.
    - Ensure that the CommandResults raw_response is correct.
    """
    args["limit"] = 5

    endpoint = CommonServerPython.urljoin(BASE_URL, endpoint_suffix)
    requests_mock.get(
        url=endpoint,
        json=[{}],
        headers={"Link": f"<{endpoint}?startingAfter=1>; rel=next"},
    )

    for i in range(1, args["limit"]):
        requests_mock.get(
            url=f"{endpoint}?startingAfter={i}",
            json=[{}],
            headers={"Link": f"<{endpoint}?startingAfter={i + 1}>; rel=next"},
        )

    command_results = list_command(mock_client, args)
    expected_result: list[dict] = [{}] * args["limit"]

    assert len(command_results) == 1
    assert command_results[0].outputs_prefix.endswith(outputs_prefix)
    assert command_results[0].outputs_key_field == outputs_key_field
    assert command_results[0].outputs == expected_result
    assert command_results[0].readable_output == CommonServerPython.tableToMarkdown(
        name=readable_output_title,
        t=expected_result,
        headers=table_headers,
        removeNull=True,
    )
    assert command_results[0].raw_response == expected_result


def test_organization_client_automatic_pagination(requests_mock, mock_client: CiscoMerakiv2.Client) -> None:
    """
    Scenario:
    - Test retrieving a list of objects through making multiple HTTP requests.

    Given:
    - Command args and a `limit`.

    When:
    - list_organization_client_command

    Then:
    - Ensure that there is only one CommandResults.
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults readable_output is correct.
    - Ensure that the CommandResults raw_response is correct.
    """
    args: dict[str, Any] = {
        "limit": 5,
        "organization_id": "123",
        "mac": "456",
    }

    endpoint = CommonServerPython.urljoin(BASE_URL, "organizations/123/clients/search")
    requests_mock.get(
        url=endpoint,
        json={},
        headers={"Link": f"<{endpoint}?startingAfter=1>; rel=next"},
    )

    for i in range(1, args["limit"]):
        requests_mock.get(
            url=f"{endpoint}?startingAfter={i}",
            json={"records": [{}]},
            headers={"Link": f"<{endpoint}?startingAfter={i + 1}>; rel=next"},
        )

    command_results = CiscoMerakiv2.list_organization_client_command(mock_client, args)
    expected_result: dict[str, list[dict]] = {"records": [{}] * args["limit"]}

    assert len(command_results) == 1
    assert command_results[0].outputs_prefix.endswith(CiscoMerakiv2.CLIENT_PREFIX)
    assert command_results[0].outputs_key_field == "clientId"
    assert command_results[0].outputs == expected_result
    assert command_results[0].readable_output == CommonServerPython.tableToMarkdown(
        name="Client None MAC None Record(s)",
        t=expected_result,
        headers=CiscoMerakiv2.CLIENT_TABLE_HEADERS,
        removeNull=True,
    )
    assert command_results[0].raw_response == expected_result


@pytest.mark.parametrize(
    "list_command, outputs_prefix, mock_response",
    [
        (
            CiscoMerakiv2.list_organization_command,
            CiscoMerakiv2.ORGANIZATION_PREFIX,
            [],
        ),
        (
            CiscoMerakiv2.list_network_command,
            CiscoMerakiv2.NETWORK_PREFIX,
            [],
        ),
        (
            CiscoMerakiv2.list_organization_inventory_command,
            CiscoMerakiv2.INVENTORY_PREFIX,
            [],
        ),
        (
            CiscoMerakiv2.search_organization_device_command,
            CiscoMerakiv2.DEVICE_PREFIX,
            [],
        ),
        (
            CiscoMerakiv2.list_device_status_command,
            CiscoMerakiv2.DEVICE_STATUS_PREFIX,
            [],
        ),
        (
            CiscoMerakiv2.list_organization_uplink_status_command,
            CiscoMerakiv2.ORGANIZATION_UPLINK_STATUS_PREFIX,
            [],
        ),
        (
            CiscoMerakiv2.list_organization_client_command,
            CiscoMerakiv2.CLIENT_PREFIX,
            {},
        ),
        (
            CiscoMerakiv2.list_network_client_command,
            CiscoMerakiv2.NETWORK_CLIENT_PREFIX,
            [],
        ),
        (
            CiscoMerakiv2.list_network_client_policy_command,
            CiscoMerakiv2.CLIENT_POLICY_PREFIX,
            [],
        ),
    ],
)
def test_list_commands_next_link(
    requests_mock,
    mock_client: CiscoMerakiv2.Client,
    list_command: Callable[[CiscoMerakiv2.Client, dict[str, Any]], list[CommonServerPython.CommandResults]],
    outputs_prefix: str,
    mock_response: list | dict,
) -> None:
    """
    Scenario:
    - Test retrieving a list of objects.

    Given:
    - The `next_token` to call.

    When:
    - list_organization_command
    - list_network_command
    - list_organization_inventory_command
    - search_organization_device_command
    - list_device_status_command
    - list_organization_uplink_status_command
    - list_organization_client_command
    - list_network_client_command
    - list_network_client_policy_command

    Then:
    - Ensure that there are only two CommandResults.
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults readable_output is correct.
    - Ensure that the CommandResults outputs is correct.
    """
    args = {"next_token": BASE_URL}

    requests_mock.get(
        url=BASE_URL,
        json=mock_response,
        headers={
            "Link": (
                f"<{BASE_URL}?perPage=5&startingAfter=0>; rel=first,"
                f" <{BASE_URL}?endingBefore=000&perPage=5>; rel=prev,"
                f" <{BASE_URL}?perPage=5&startingAfter=111>; rel=next,"
                f" <{BASE_URL}?endingBefore=222&perPage=5>; rel=last"
            )
        },
    )

    command_results = list_command(mock_client, args)

    expected_outputs = {
        "Prev": f"{BASE_URL}?endingBefore=000&perPage=5",
        "Next": f"{BASE_URL}?perPage=5&startingAfter=111",
        "First": f"{BASE_URL}?perPage=5&startingAfter=0",
        "Last": f"{BASE_URL}?endingBefore=222&perPage=5",
    }

    assert len(command_results) == 2
    assert command_results[1].outputs_prefix.endswith(f"{outputs_prefix}LinkTokens")
    assert command_results[1].readable_output == (
        f"{outputs_prefix} Link Tokens for next_token='{expected_outputs['Next']}'."
    )
    assert command_results[1].outputs == expected_outputs


@pytest.mark.parametrize(
    (
        "list_command,"
        "args,"
        "endpoint_suffix,"
        "response_file,"
        "table_file,"
        "readable_output_title,"
        "table_headers,"
        "outputs_key_field,"
        "outputs_prefix"
    ),
    [
        (
            CiscoMerakiv2.list_organization_command,
            {"organization_id": "123"},
            "organizations/123",
            "organization_response.json",
            "organization_table.json",
            "Organization(s)",
            CiscoMerakiv2.ORGANIZATION_TABLE_HEADERS,
            "id",
            CiscoMerakiv2.ORGANIZATION_PREFIX,
        ),
        (
            CiscoMerakiv2.list_network_command,
            {"network_id": "123"},
            "networks/123",
            "network_response.json",
            "network_table.json",
            "Network(s)",
            CiscoMerakiv2.NETWORK_TABLE_HEADERS,
            "id",
            CiscoMerakiv2.NETWORK_PREFIX,
        ),
        (
            CiscoMerakiv2.list_organization_inventory_command,
            {"organization_id": "123", "serial": "456"},
            "organizations/123/inventory/devices/456",
            "inventory_response.json",
            "inventory_table.json",
            "Inventory Device(s)",
            CiscoMerakiv2.INVENTORY_TABLE_HEADERS,
            "serial",
            CiscoMerakiv2.INVENTORY_PREFIX,
        ),
        (
            CiscoMerakiv2.list_network_client_command,
            {"network_id": "123", "client_id": "456"},
            "networks/123/clients/456",
            "network_client_response.json",
            "network_client_table.json",
            "Network Monitor Client(s)",
            CiscoMerakiv2.NETWORK_CLIENT_TABLE_HEADERS,
            "id",
            CiscoMerakiv2.NETWORK_CLIENT_PREFIX,
        ),
    ],
)
def test_list_commands_get_single(
    requests_mock,
    mock_client: CiscoMerakiv2.Client,
    list_command: Callable[[CiscoMerakiv2.Client, dict[str, Any]], list[CommonServerPython.CommandResults]],
    args: dict[str, Any],
    endpoint_suffix: str,
    response_file: str,
    table_file: str,
    readable_output_title: str,
    table_headers: list[str],
    outputs_key_field: str,
    outputs_prefix: str,
) -> None:
    """
    Scenario:
    - Test retrieving a single of record.

    Given:
    - An identifier used for retrieving a single record.

    When:
    - list_organization_command
    - list_network_command
    - list_organization_inventory_command
    - list_network_client_command

    Then:
    - Ensure that there is only one CommandResults.
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults readable_output is correct.
    - Ensure that the CommandResults raw_response is correct.
    """
    mock_response = load_json_file(response_file)
    mock_table = load_json_file(table_file)

    requests_mock.get(
        url=CommonServerPython.urljoin(BASE_URL, endpoint_suffix),
        json=next(iter(mock_response)),
    )

    command_results = list_command(mock_client, args)

    assert len(command_results) == 1
    assert command_results[0].outputs_prefix.endswith(outputs_prefix)
    assert command_results[0].outputs_key_field == outputs_key_field
    assert command_results[0].outputs == mock_response
    assert command_results[0].readable_output == CommonServerPython.tableToMarkdown(
        name=readable_output_title,
        t=mock_table,
        headers=table_headers,
        removeNull=True,
    )
    assert command_results[0].raw_response == mock_response


def test_claim_device_command(requests_mock, mock_client: CiscoMerakiv2.Client) -> None:
    """
    Scenario:
    - Test claiming a device into a network.

    Given:
    - The network to claim into and a list of serial numbers.

    When:
    - claim_device_command

    Then:
    - Ensure that the CommandResults readable_output is correct.
    """
    args = {"network_id": "123", "serials": "111,222,333,444,555"}
    mock_response: dict[str, Any] = {
        "serials": [
            "111",
            "222",
            "333",
        ],
        "errors": [
            {"serial": "444", "errors": ["Device already claimed"]},
            {"serial": "555", "errors": ["Device already claimed"]},
        ],
    }

    requests_mock.post(
        url=CommonServerPython.urljoin(BASE_URL, f"networks/{args['network_id']}/devices/claim"),
        json=mock_response,
    )

    command_results = CiscoMerakiv2.claim_device_command(mock_client, args)

    expected_readable_output = (
        f"## The device(s) were successfully claimed into the network '{args['network_id']}':"
        f"\n- {mock_response['serials'][0]}"
        f"\n- {mock_response['serials'][1]}"
        f"\n- {mock_response['serials'][2]}"
        "\n## The device(s) couldn't be claimed for the following reason(s):"
        f"\n- {mock_response['errors'][0]['serial']} failed due to: {mock_response['errors'][0]['errors']}."
        f"\n- {mock_response['errors'][1]['serial']} failed due to: {mock_response['errors'][1]['errors']}."
    )

    assert command_results.readable_output == expected_readable_output


def test_update_device_command(requests_mock, mock_client: CiscoMerakiv2.Client) -> None:
    """
    Scenario:
    - Test updating a device.

    Given:
    - An serial number and optional parameters.

    When:
    - update_device_command

    Then:
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults readable_output is correct.
    - Ensure that the CommandResults raw_response is correct.
    """
    args = {
        "serial": "123",
        "floor_plan_id": "null",
        "switch_profile_id": "null",
    }

    mock_response = next(iter(load_json_file("device_response.json")))
    mock_table = load_json_file("device_table.json")

    requests_mock.put(
        url=CommonServerPython.urljoin(BASE_URL, "devices/123"),
        json=mock_response,
    )

    command_results = CiscoMerakiv2.update_device_command(mock_client, args)

    assert command_results.outputs_prefix.endswith(CiscoMerakiv2.DEVICE_PREFIX)
    assert command_results.outputs_key_field == "serial"
    assert command_results.outputs == mock_response
    assert command_results.readable_output == CommonServerPython.tableToMarkdown(
        name=f"The device '{args['serial']}' was successfully updated.",
        t=mock_table,
        headers=CiscoMerakiv2.DEVICE_TABLE_HEADERS,
        removeNull=True,
    )
    assert command_results.raw_response == mock_response


def test_remove_device_command(requests_mock, mock_client: CiscoMerakiv2.Client) -> None:
    """
    Scenario:
    - Test removing a device from a network.

    Given:
    - The network to remove from and a serial number.

    When:
    - remove_device_command

    Then:
    - Ensure that the CommandResults readable_output is correct.
    """
    args = {"network_id": "123", "serial": "111"}

    requests_mock.post(
        url=CommonServerPython.urljoin(BASE_URL, f"networks/{args['network_id']}/devices/remove"),
        json={},
    )

    command_results = CiscoMerakiv2.remove_device_command(mock_client, args)

    assert command_results.readable_output == (
        f"## The device with the serial number: '{args['serial']}'"
        f" was successfully removed from the network '{args['network_id']}'."
    )


@pytest.mark.parametrize(
    (
        "list_command,"
        "args,"
        "endpoint_suffix,"
        "response_file,"
        "table_file,"
        "readable_output_title,"
        "table_headers,"
        "outputs_key_field,"
        "outputs_prefix"
    ),
    [
        (
            CiscoMerakiv2.list_device_command,
            {"network_id": "123"},
            "networks/123/devices",
            "device_response.json",
            "device_table.json",
            "Device(s)",
            CiscoMerakiv2.DEVICE_TABLE_HEADERS,
            "serial",
            CiscoMerakiv2.DEVICE_PREFIX,
        ),
        (
            CiscoMerakiv2.list_ssid_appliance_command,
            {"network_id": "123"},
            "networks/123/appliance/ssids",
            "ssid_appliance_response.json",
            "ssid_appliance_table.json",
            "MX SSID(s)",
            CiscoMerakiv2.SSID_APPLIANCE_TABLE_HEADERS,
            "number",
            f"{CiscoMerakiv2.SSID_PREFIX}.{CiscoMerakiv2.APPLIANCE_PREFIX}",
        ),
        (
            CiscoMerakiv2.list_ssid_wireless_command,
            {"network_id": "123"},
            "networks/123/wireless/ssids",
            "ssid_wireless_response.json",
            "ssid_wireless_table.json",
            "MR SSID(s)",
            CiscoMerakiv2.SSID_WIRELESS_TABLE_HEADERS,
            "number",
            f"{CiscoMerakiv2.SSID_PREFIX}.{CiscoMerakiv2.WIRELESS_PREFIX}",
        ),
        (
            CiscoMerakiv2.list_organization_adaptive_policy_acl_command,
            {"organization_id": "123"},
            "organizations/123/adaptivePolicy/acls",
            "adaptive_policy_acl_response.json",
            "adaptive_policy_acl_table.json",
            "Adaptive Policy ACL(s)",
            CiscoMerakiv2.ADAPTIVE_POLICY_ACL_TABLE_HEADERS,
            "aclId",
            CiscoMerakiv2.ADAPTIVE_POLICY_ACL_PREFIX,
        ),
        (
            CiscoMerakiv2.list_organization_adaptive_policy_command,
            {"organization_id": "123"},
            "organizations/123/adaptivePolicy/policies",
            "adaptive_policy_response.json",
            "adaptive_policy_table.json",
            "Adaptive Policy(ies)",
            CiscoMerakiv2.ADAPTIVE_POLICY_TABLE_HEADERS,
            "adaptivePolicyId",
            CiscoMerakiv2.ADAPTIVE_POLICY_PREFIX,
        ),
        (
            CiscoMerakiv2.list_organization_adaptive_policy_group_command,
            {"organization_id": "123"},
            "organizations/123/adaptivePolicy/groups",
            "adaptive_policy_group_response.json",
            "adaptive_policy_group_table.json",
            "Adaptive Policy Group(s)",
            CiscoMerakiv2.ADAPTIVE_POLICY_GROUP_TABLE_HEADERS,
            "groupId",
            CiscoMerakiv2.ADAPTIVE_POLICY_GROUP_PREFIX,
        ),
        (
            CiscoMerakiv2.list_organization_branding_policy_command,
            {"organization_id": "123"},
            "organizations/123/brandingPolicies",
            "branding_policy_response.json",
            "branding_policy_table.json",
            "Branding Policy(ies)",
            CiscoMerakiv2.BRANDING_POLICY_TABLE_HEADERS,
            "name",
            CiscoMerakiv2.BRANDING_POLICY_PREFIX,
        ),
        (
            CiscoMerakiv2.list_network_group_policy_command,
            {"network_id": "123"},
            "networks/123/groupPolicies",
            "group_policy_response.json",
            "group_policy_table.json",
            "Group Policy(ies)",
            CiscoMerakiv2.GROUP_POLICY_TABLE_HEADERS,
            "name",
            CiscoMerakiv2.GROUP_POLICY_PREFIX,
        ),
        (
            CiscoMerakiv2.list_network_vlan_profile_command,
            {"network_id": "123"},
            "networks/123/vlanProfiles",
            "vlan_profile_response.json",
            "vlan_profile_table.json",
            "VLAN Profile(s)",
            CiscoMerakiv2.VLAN_PROFILE_TABLE_HEADERS,
            "iname",
            CiscoMerakiv2.VLAN_PROFILE_PREFIX,
        ),
        (
            CiscoMerakiv2.list_network_appliance_vlan_command,
            {"network_id": "123"},
            "networks/123/appliance/vlans",
            "appliance_vlan_response.json",
            "appliance_vlan_table.json",
            "MX VLAN(s)",
            CiscoMerakiv2.APPLIANCE_VLAN_TABLE_HEADERS,
            "id",
            CiscoMerakiv2.APPLIANCE_VLAN_PREFIX,
        ),
    ],
)
def test_list_commands_no_pagination_limit(
    requests_mock,
    mock_client: CiscoMerakiv2.Client,
    list_command: Callable[[CiscoMerakiv2.Client, dict[str, Any]], CommonServerPython.CommandResults],
    args: dict[str, Any],
    endpoint_suffix: str,
    response_file: str,
    table_file: str,
    readable_output_title: str,
    table_headers: list[str],
    outputs_key_field: str,
    outputs_prefix: str,
) -> None:
    """
    Scenario:
    - Test retrieving a list of objects.

    Given:
    - Command args and a `limit`.

    When:
    - list_device_command
    - list_ssid_appliance_command
    - list_ssid_wireless_command
    - list_organization_adaptive_policy_acl_command
    - list_organization_adaptive_policy_command
    - list_organization_adaptive_policy_group_command
    - list_organization_branding_policy_command
    - list_network_group_policy_command
    - list_network_vlan_profile_command
    - list_network_appliance_vlan_command

    Then:
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults readable_output is correct.
    - Ensure that the CommandResults raw_response is correct.
    """
    args["limit"] = "3"

    mock_response = load_json_file(response_file)
    mock_table = load_json_file(table_file)

    requests_mock.get(
        url=CommonServerPython.urljoin(BASE_URL, endpoint_suffix),
        json=mock_response,
    )

    command_results = list_command(mock_client, args)

    assert command_results.outputs_prefix.endswith(outputs_prefix)
    assert command_results.outputs_key_field == outputs_key_field
    assert command_results.outputs == mock_response
    assert command_results.readable_output == CommonServerPython.tableToMarkdown(
        name=readable_output_title,
        t=mock_table,
        headers=table_headers,
        removeNull=True,
    )
    assert command_results.raw_response == mock_response


@pytest.mark.parametrize(
    (
        "list_command,"
        "args,"
        "endpoint_suffix,"
        "response_file,"
        "table_file,"
        "readable_output_title,"
        "table_headers,"
        "outputs_key_field,"
        "outputs_prefix"
    ),
    [
        (
            CiscoMerakiv2.list_device_command,
            {"serial": "123"},
            "devices/123",
            "device_response.json",
            "device_table.json",
            "Device(s)",
            CiscoMerakiv2.DEVICE_TABLE_HEADERS,
            "serial",
            CiscoMerakiv2.DEVICE_PREFIX,
        ),
        (
            CiscoMerakiv2.list_ssid_appliance_command,
            {"network_id": "123", "number": "456"},
            "networks/123/appliance/ssids/456",
            "ssid_appliance_response.json",
            "ssid_appliance_table.json",
            "MX SSID(s)",
            CiscoMerakiv2.SSID_APPLIANCE_TABLE_HEADERS,
            "number",
            f"{CiscoMerakiv2.SSID_PREFIX}.{CiscoMerakiv2.APPLIANCE_PREFIX}",
        ),
        (
            CiscoMerakiv2.list_ssid_wireless_command,
            {"network_id": "123", "number": "456"},
            "networks/123/wireless/ssids/456",
            "ssid_wireless_response.json",
            "ssid_wireless_table.json",
            "MR SSID(s)",
            CiscoMerakiv2.SSID_WIRELESS_TABLE_HEADERS,
            "number",
            f"{CiscoMerakiv2.SSID_PREFIX}.{CiscoMerakiv2.WIRELESS_PREFIX}",
        ),
        (
            CiscoMerakiv2.list_organization_adaptive_policy_acl_command,
            {"organization_id": "123", "acl_id": "456"},
            "organizations/123/adaptivePolicy/acls/456",
            "adaptive_policy_acl_response.json",
            "adaptive_policy_acl_table.json",
            "Adaptive Policy ACL(s)",
            CiscoMerakiv2.ADAPTIVE_POLICY_ACL_TABLE_HEADERS,
            "aclId",
            CiscoMerakiv2.ADAPTIVE_POLICY_ACL_PREFIX,
        ),
        (
            CiscoMerakiv2.list_organization_adaptive_policy_command,
            {"organization_id": "123", "adaptive_policy_id": "456"},
            "organizations/123/adaptivePolicy/policies/456",
            "adaptive_policy_response.json",
            "adaptive_policy_table.json",
            "Adaptive Policy(ies)",
            CiscoMerakiv2.ADAPTIVE_POLICY_TABLE_HEADERS,
            "adaptivePolicyId",
            CiscoMerakiv2.ADAPTIVE_POLICY_PREFIX,
        ),
        (
            CiscoMerakiv2.list_organization_adaptive_policy_group_command,
            {"organization_id": "123", "adaptive_policy_group_id": "456"},
            "organizations/123/adaptivePolicy/groups/456",
            "adaptive_policy_group_response.json",
            "adaptive_policy_group_table.json",
            "Adaptive Policy Group(s)",
            CiscoMerakiv2.ADAPTIVE_POLICY_GROUP_TABLE_HEADERS,
            "groupId",
            CiscoMerakiv2.ADAPTIVE_POLICY_GROUP_PREFIX,
        ),
        (
            CiscoMerakiv2.list_organization_branding_policy_command,
            {"organization_id": "123", "branding_policy_id": "456"},
            "organizations/123/brandingPolicies/456",
            "branding_policy_response.json",
            "branding_policy_table.json",
            "Branding Policy(ies)",
            CiscoMerakiv2.BRANDING_POLICY_TABLE_HEADERS,
            "name",
            CiscoMerakiv2.BRANDING_POLICY_PREFIX,
        ),
        (
            CiscoMerakiv2.list_network_group_policy_command,
            {"network_id": "123", "group_policy_id": "456"},
            "networks/123/groupPolicies/456",
            "group_policy_response.json",
            "group_policy_table.json",
            "Group Policy(ies)",
            CiscoMerakiv2.GROUP_POLICY_TABLE_HEADERS,
            "name",
            CiscoMerakiv2.GROUP_POLICY_PREFIX,
        ),
        (
            CiscoMerakiv2.list_network_vlan_profile_command,
            {"network_id": "123", "iname": "456"},
            "networks/123/vlanProfiles/456",
            "vlan_profile_response.json",
            "vlan_profile_table.json",
            "VLAN Profile(s)",
            CiscoMerakiv2.VLAN_PROFILE_TABLE_HEADERS,
            "iname",
            CiscoMerakiv2.VLAN_PROFILE_PREFIX,
        ),
        (
            CiscoMerakiv2.list_network_appliance_vlan_command,
            {"network_id": "123", "vlan_id": "456"},
            "networks/123/appliance/vlans/456",
            "appliance_vlan_response.json",
            "appliance_vlan_table.json",
            "MX VLAN(s)",
            CiscoMerakiv2.APPLIANCE_VLAN_TABLE_HEADERS,
            "id",
            CiscoMerakiv2.APPLIANCE_VLAN_PREFIX,
        ),
    ],
)
def test_list_commands_no_pagination_get_single(
    requests_mock,
    mock_client: CiscoMerakiv2.Client,
    list_command: Callable[[CiscoMerakiv2.Client, dict[str, Any]], CommonServerPython.CommandResults],
    args: dict[str, Any],
    endpoint_suffix: str,
    response_file: str,
    table_file: str,
    readable_output_title: str,
    table_headers: list[str],
    outputs_key_field: str,
    outputs_prefix: str,
) -> None:
    """
    Scenario:
    - Test retrieving a single of record.

    Given:
    - An identifier used for retrieving a single record.

    When:
    - list_device_command
    - list_ssid_appliance_command
    - list_ssid_wireless_command
    - list_organization_adaptive_policy_acl_command
    - list_organization_adaptive_policy_command
    - list_organization_adaptive_policy_group_command
    - list_organization_branding_policy_command
    - list_network_group_policy_command
    - list_network_vlan_profile_command
    - list_network_appliance_vlan_command

    Then:
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults readable_output is correct.
    - Ensure that the CommandResults raw_response is correct.
    """
    mock_response = load_json_file(response_file)
    mock_table = load_json_file(table_file)

    requests_mock.get(
        url=CommonServerPython.urljoin(BASE_URL, endpoint_suffix),
        json=next(iter(mock_response)),
    )

    command_results = list_command(mock_client, args)

    assert command_results.outputs_prefix.endswith(outputs_prefix)
    assert command_results.outputs_key_field == outputs_key_field
    assert command_results.outputs == mock_response
    assert command_results.readable_output == CommonServerPython.tableToMarkdown(
        name=readable_output_title,
        t=mock_table,
        headers=table_headers,
        removeNull=True,
    )
    assert command_results.raw_response == mock_response


@pytest.mark.parametrize(
    (
        "get_command,"
        "args,"
        "endpoint_suffix,"
        "response_file,"
        "table_file,"
        "readable_output_title,"
        "table_headers,"
        "outputs_key_field,"
        "outputs_prefix"
    ),
    [
        (
            CiscoMerakiv2.list_organization_adaptive_policy_settings_command,
            {"organization_id": "123"},
            "organizations/123/adaptivePolicy/settings",
            "adaptive_policy_settings_response.json",
            "adaptive_policy_settings_table.json",
            "Adaptive Policy Settings",
            None,
            "organizationId",
            CiscoMerakiv2.ADAPTIVE_POLICY_SETTINGS_PREFIX,
        ),
        (
            CiscoMerakiv2.list_network_l3firewall_rule_command,
            {"network_id": "123"},
            "networks/123/appliance/firewall/l3FirewallRules",
            "l3firewall_rule_response.json",
            "l3firewall_rule_table.json",
            "L3 Firewall Rule(s)",
            CiscoMerakiv2.L3FIREWALL_RULE_TABLE_HEADERS,
            "networkId",
            CiscoMerakiv2.L3FIREWALL_RULE_PREFIX,
        ),
        (
            CiscoMerakiv2.list_network_l7firewall_rule_command,
            {"network_id": "123"},
            "networks/123/appliance/firewall/l7FirewallRules",
            "l7firewall_rule_response.json",
            "l7firewall_rule_table.json",
            "L7 Firewall Rule(s)",
            CiscoMerakiv2.L7FIREWALL_RULE_TABLE_HEADERS,
            "networkId",
            CiscoMerakiv2.L7FIREWALL_RULE_PREFIX,
        ),
    ],
)
def test_get_commands(
    requests_mock,
    mock_client: CiscoMerakiv2.Client,
    get_command: Callable[[CiscoMerakiv2.Client, dict[str, Any]], CommonServerPython.CommandResults],
    args: dict[str, Any],
    endpoint_suffix: str,
    response_file: str,
    table_file: str,
    readable_output_title: str,
    table_headers: list[str] | None,
    outputs_key_field: str,
    outputs_prefix: str,
) -> None:
    """
    Scenario:
    - Test get commands.

    Given:
    - An identifier used for retrieving a single record.

    When:
    - list_organization_adaptive_policy_settings_command
    - list_network_l3firewall_rule_command
    - list_network_l7firewall_rule_command

    Then:
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults readable_output is correct.
    - Ensure that the CommandResults raw_response is correct.
    """
    mock_response = load_json_file(response_file)
    mock_table = load_json_file(table_file)

    assert isinstance(mock_response, dict)

    requests_mock.get(
        url=CommonServerPython.urljoin(BASE_URL, endpoint_suffix),
        json=mock_response,
    )

    command_results = get_command(mock_client, args)

    assert command_results.outputs_prefix.endswith(outputs_prefix)
    assert command_results.outputs_key_field == outputs_key_field
    assert command_results.outputs == {
        outputs_key_field: args[CommonServerPython.camel_case_to_underscore(outputs_key_field)],
        **mock_response,
    }
    assert command_results.readable_output == CommonServerPython.tableToMarkdown(
        name=readable_output_title,
        t=mock_table,
        headers=table_headers,
        removeNull=True,
    )
    assert command_results.raw_response == mock_response


@pytest.mark.parametrize(
    (
        "update_command,"
        "endpoint_suffix,"
        "response_file,"
        "table_file,"
        "readable_output_title,"
        "table_headers,"
        "outputs_prefix"
    ),
    [
        (
            CiscoMerakiv2.update_network_l3firewall_rule_command,
            "networks/123/appliance/firewall/l3FirewallRules",
            "l3firewall_rule_response.json",
            "l3firewall_rule_table.json",
            "The L3 firewall rules for the network '123' were successfully updated.",
            CiscoMerakiv2.L3FIREWALL_RULE_TABLE_HEADERS,
            CiscoMerakiv2.L3FIREWALL_RULE_PREFIX,
        ),
        (
            CiscoMerakiv2.update_network_l7firewall_rule_command,
            "networks/123/appliance/firewall/l7FirewallRules",
            "l7firewall_rule_response.json",
            "l7firewall_rule_table.json",
            "The L7 firewall rules for the network '123' were successfully updated.",
            CiscoMerakiv2.L7FIREWALL_RULE_TABLE_HEADERS,
            CiscoMerakiv2.L7FIREWALL_RULE_PREFIX,
        ),
    ],
)
def test_update_firewall_rule_commands_multiple_rules(
    requests_mock,
    mock_client: CiscoMerakiv2.Client,
    update_command: Callable[[CiscoMerakiv2.Client, dict[str, Any]], CommonServerPython.CommandResults],
    endpoint_suffix: str,
    response_file: str,
    table_file: str,
    readable_output_title: str,
    table_headers: list[str],
    outputs_prefix: str,
) -> None:
    """
    Scenario:
    - Test update firewall rule commands with multiple rules.

    Given:
    - An `entry_id` with multiple rules and `override` set to False.

    When:
    - update_network_l3firewall_rule_command
    - update_network_l7firewall_rule_command

    Then:
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults readable_output is correct.
    - Ensure that the CommandResults raw_response is correct.
    """
    args = {
        "network_id": "123",
        "override": "false",
        "entry_id": "456",
    }
    outputs_key_field = "networkId"

    mock_response = load_json_file(response_file)
    mock_table = load_json_file(table_file)

    assert isinstance(mock_response, dict)

    endpoint = CommonServerPython.urljoin(BASE_URL, endpoint_suffix)
    requests_mock.get(
        url=endpoint,
        json=mock_response,
    )
    requests_mock.put(
        url=endpoint,
        json=mock_response,
    )

    read_data = json.dumps(mock_response["rules"])
    mocked_open = unittest.mock.mock_open(read_data=read_data)

    with unittest.mock.patch("builtins.open", mocked_open):
        command_results = update_command(mock_client, args)

    assert command_results.outputs_prefix.endswith(outputs_prefix)
    assert command_results.outputs_key_field == outputs_key_field
    assert command_results.outputs == {
        outputs_key_field: args[CommonServerPython.camel_case_to_underscore(outputs_key_field)],
        **mock_response,
    }
    assert command_results.readable_output == CommonServerPython.tableToMarkdown(
        name=readable_output_title,
        t=mock_table,
        headers=table_headers,
        removeNull=True,
    )
    assert command_results.raw_response == mock_response


@pytest.mark.parametrize(
    (
        "update_command,"
        "args,"
        "endpoint_suffix,"
        "response_file,"
        "table_file,"
        "readable_output_title,"
        "table_headers,"
        "outputs_prefix"
    ),
    [
        (
            CiscoMerakiv2.update_network_l3firewall_rule_command,
            {
                "network_id": "123",
                "dest_cidr": "456",
                "protocol": "tcp",
                "policy": "allow",
                "src_cidr": "789",
            },
            "networks/123/appliance/firewall/l3FirewallRules",
            "l3firewall_rule_response.json",
            "l3firewall_rule_table.json",
            "The L3 firewall rules for the network '123' were successfully updated.",
            CiscoMerakiv2.L3FIREWALL_RULE_TABLE_HEADERS,
            CiscoMerakiv2.L3FIREWALL_RULE_PREFIX,
        ),
        (
            CiscoMerakiv2.update_network_l7firewall_rule_command,
            {
                "network_id": "123",
                "value": "456",
                "type": "application",
                "policy": "deny",
            },
            "networks/123/appliance/firewall/l7FirewallRules",
            "l7firewall_rule_response.json",
            "l7firewall_rule_table.json",
            "The L7 firewall rules for the network '123' were successfully updated.",
            CiscoMerakiv2.L7FIREWALL_RULE_TABLE_HEADERS,
            CiscoMerakiv2.L7FIREWALL_RULE_PREFIX,
        ),
    ],
)
def test_update_firewall_rule_commands_single_rule(
    requests_mock,
    mock_client: CiscoMerakiv2.Client,
    update_command: Callable[[CiscoMerakiv2.Client, dict[str, Any]], CommonServerPython.CommandResults],
    args: dict[str, Any],
    endpoint_suffix: str,
    response_file: str,
    table_file: str,
    readable_output_title: str,
    table_headers: list[str],
    outputs_prefix: str,
) -> None:
    """
    Scenario:
    - Test update firewall rule commands with a single rule.

    Given:
    - Required arguments to create a firewall rule.

    When:
    - update_network_l3firewall_rule_command
    - update_network_l7firewall_rule_command

    Then:
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults readable_output is correct.
    - Ensure that the CommandResults raw_response is correct.
    """
    outputs_key_field = "networkId"

    mock_response = load_json_file(response_file)
    mock_table = load_json_file(table_file)

    assert isinstance(mock_response, dict)

    requests_mock.put(
        url=CommonServerPython.urljoin(BASE_URL, endpoint_suffix),
        json=mock_response,
    )
    command_results = update_command(mock_client, args)

    assert command_results.outputs_prefix.endswith(outputs_prefix)
    assert command_results.outputs_key_field == outputs_key_field
    assert command_results.outputs == {
        outputs_key_field: args[CommonServerPython.camel_case_to_underscore(outputs_key_field)],
        **mock_response,
    }
    assert command_results.readable_output == CommonServerPython.tableToMarkdown(
        name=readable_output_title,
        t=mock_table,
        headers=table_headers,
        removeNull=True,
    )
    assert command_results.raw_response == mock_response


@pytest.mark.parametrize(
    "delete_command,endpoint_suffix,readable_output,",
    [
        (
            CiscoMerakiv2.delete_network_l3firewall_rule_command,
            "networks/123/appliance/firewall/l3FirewallRules",
            "## The L3 firewall rules of the network '123' were successfully deleted.",
        ),
        (
            CiscoMerakiv2.delete_network_l7firewall_rule_command,
            "networks/123/appliance/firewall/l7FirewallRules",
            "## The L7 firewall rules of the network '123' were successfully deleted.",
        ),
    ],
)
def test_delete_firewall_rule_commands(
    requests_mock,
    mock_client: CiscoMerakiv2.Client,
    delete_command: Callable[[CiscoMerakiv2.Client, dict[str, Any]], CommonServerPython.CommandResults],
    endpoint_suffix: str,
    readable_output: str,
) -> None:
    """
    Scenario:
    - Test delete firewall rule commands.

    Given:
    - The network ID.

    When:
    - delete_network_l3firewall_rule_command
    - delete_network_l7firewall_rule_command

    Then:
    - Ensure that the CommandResults readable_output is correct.
    """
    args = {"network_id": "123"}

    requests_mock.put(
        url=CommonServerPython.urljoin(BASE_URL, endpoint_suffix),
        json={},
    )
    command_results = delete_command(mock_client, args)

    assert command_results.readable_output == readable_output


@pytest.mark.parametrize(
    "command",
    [
        CiscoMerakiv2.list_network_command,
        CiscoMerakiv2.list_organization_inventory_command,
        CiscoMerakiv2.search_organization_device_command,
        CiscoMerakiv2.list_device_command,
        CiscoMerakiv2.list_device_status_command,
        CiscoMerakiv2.list_organization_uplink_status_command,
        CiscoMerakiv2.list_organization_client_command,
        CiscoMerakiv2.list_network_client_command,
        CiscoMerakiv2.list_network_l3firewall_rule_command,
        CiscoMerakiv2.list_network_l7firewall_rule_command,
        CiscoMerakiv2.update_network_l3firewall_rule_command,
        CiscoMerakiv2.update_network_l7firewall_rule_command,
        CiscoMerakiv2.delete_network_l3firewall_rule_command,
        CiscoMerakiv2.delete_network_l7firewall_rule_command,
    ],
)
def test_input_arguments_error(
    mock_client: CiscoMerakiv2.Client,
    command: Callable[[CiscoMerakiv2.Client, dict[str, Any]], CommonServerPython.CommandResults],
) -> None:
    """
    Scenario:
    - Test an error is raised when required arguments aren't given.

    Given:
    - Nothing.

    When:
    - list_network_command
    - list_organization_inventory_command
    - search_organization_device_command
    - list_device_command
    - list_device_status_command
    - list_organization_uplink_status_command
    - list_organization_client_command
    - list_network_client_command
    - list_network_l3firewall_rule_command
    - list_network_l7firewall_rule_command
    - update_network_l3firewall_rule_command
    - update_network_l7firewall_rule_command

    Then:
    - Ensure a DemistoException is raised.
    """
    with pytest.raises(CommonServerPython.DemistoException):
        command(mock_client, {})
