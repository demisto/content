import json
import os
from typing import Any, Callable

import CommonServerPython
import FortiGate
import pytest

TEST_DATA = "test_data"
BASE_URL = "https://www.example.com"
API_URL = CommonServerPython.urljoin(BASE_URL, "api/v2")


def load_mock_response(file_name: str) -> str:
    """Load mock file that simulates an API response.

    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """
    file_path = os.path.join(TEST_DATA, file_name)

    with open(file_path, mode="r", encoding="utf-8") as mock_file:
        return json.loads(mock_file.read())


@pytest.fixture()
def mock_client(requests_mock) -> FortiGate.Client:
    """
    Establish a mock connection to the client with a username and password.

    Returns:
        Client: Mock connection to client.
    """
    return FortiGate.Client(
        base_url=BASE_URL,
        username="Pokemon",
        password="Pikachu",
    )


@pytest.mark.parametrize(
    "args, include_ipv6, expected_result",
    [
        (
            {"address": "0.0.0.0", "mask": "0.0.0.0"},
            False,
            "ipmask",
        ),
        (
            {"start_ip": "0.0.0.0", "end_ip": "0.0.0.00"},
            False,
            "iprange",
        ),
        (
            {"fqdn": "example.com"},
            False,
            "fqdn",
        ),
        (
            {"country": "US"},
            False,
            "geography",
        ),
        (
            {"mac_addresses": ["00:00:00:00:00:00"]},
            False,
            "mac",
        ),
        (
            {"address": "0.0.0.0", "mask": "0.0.0.0", "allow_routing": True},
            False,
            "ipmask",
        ),
        (
            {"fqdn": "example.com", "allow_routing": True},
            False,
            "fqdn",
        ),
        (
            {"address": "0000:0000:0000:0000:0000:0000:0000:0000", "mask": "64"},
            True,
            "ipprefix",
        ),
        (
            {"sdn_connector": "connector_id"},
            True,
            "dynamic",
        ),
    ],
)
def test_get_address_type_success(args: dict[str, Any], include_ipv6: bool, expected_result: str):
    """
    Scenario:
    - Test the get_address_type function's success handling for valid arguments.

    Given:
    - A dictionary of arguments that are complete and correctly isolated per group.

    When:
    - get_address_type is called with these arguments and the include_ipv6 flag.

    Then:
    - Ensure that the correct address type string is returned for each set of arguments.
    """
    result = FortiGate.get_address_type(args, include_ipv6)
    assert result == expected_result


@pytest.mark.parametrize(
    "args,error_message",
    [
        (
            {},
            (
                "No group of arguments is fully set. Please provide arguments from one of the following groups: "
                "['Subnet', 'IP Range', 'FQDN', 'Geography', 'Device (Mac Address)']"
            ),
        ),
        (
            {"start_ip": "0.0.0.0"},
            "Missing arguments for the group IP Range, please provide all: ['start_ip', 'end_ip']",
        ),
        (
            {"address": "0.0.0.0", "fqdn": "example.com"},
            "Arguments must only come from one group. Mixed groups: Subnet, FQDN",
        ),
    ],
)
def test_get_address_type_error(args: dict[str, Any], error_message: str):
    """
    Scenario:
    - Test the get_address_type function's error handling for invalid arguments.

    Given:
    - A dictionary of arguments that are incomplete or incorrectly combined.

    When:
    - No arguments provided.
    - Partial arguments from a group are provided.
    - Mixing between argument groups.

    Then:
    - Ensure that a DemistoException is raised with the correct error message.
    - Ensure that the actual error message matches the expected error message.
    """
    with pytest.raises(CommonServerPython.DemistoException) as exc_info:
        FortiGate.get_address_type(args)

    assert str(exc_info.value) == error_message


@pytest.mark.parametrize(
    "mac_addresses",
    [
        ["00:00:00:00:00:ZZ"],
        ["ZZ:ZZ:ZZ:ZZ:ZZ:ZZ"],
    ],
)
def test_validate_mac_addresses_error(mac_addresses: list[str]):
    with pytest.raises(CommonServerPython.DemistoException) as exc_info:
        FortiGate.validate_mac_addresses(mac_addresses)

    assert "Invalid MAC address" in str(exc_info.value)


@pytest.mark.parametrize(
    "ipv4_addresses",
    [
        ("256.256.256.256"),  # Invalid IPv4 address
    ],
)
def test_validate_optional_ipv4_addresses_error(ipv4_addresses):
    with pytest.raises(CommonServerPython.DemistoException) as exc_info:
        FortiGate.validate_optional_ipv4_addresses(ipv4_addresses)

    assert "Invalid IPv4 address" in str(exc_info.value)


@pytest.mark.parametrize(
    "ipv6_networks",
    [("gggg:gggg:gggg:gggg:gggg:gggg:gggg:gggg")],
)
def test_validate_optional_ipv6_networks_error(ipv6_networks: list[str]):
    with pytest.raises(CommonServerPython.DemistoException) as e_info:
        FortiGate.validate_optional_ipv6_networks(ipv6_networks)

    assert "Invalid IPv6 address" in str(e_info.value)


@pytest.mark.parametrize(
    "mask",
    [129, -1],
)
def test_validate_mask_error(mask: int):
    with pytest.raises(CommonServerPython.DemistoException) as e_info:
        FortiGate.validate_mask(mask)

    assert "Invalid mask" in str(e_info.value)


@pytest.mark.parametrize(
    "given,expected",
    [
        ("camelCase", "camel-case"),
        ("PascalCase", "pascal-case"),
        ("snake_case", "snake-case"),
        ("kebab-case", "kebab-case"),
        ("CONSTANT_CASE", "constant-case"),
        ("Title Case", "title-case"),
    ],
)
def test_to_kebab_case(given: str, expected: str):
    assert FortiGate.to_kebab_case(given) == expected


@pytest.mark.parametrize(
    "items, expected_table",
    [
        (
            [
                {
                    "Name": "Router1",
                    "AssociatedInterface": "eth0",
                    "StartIP": "0.0.0.0",
                    "EndIP": "0.0.0.0",
                }
            ],
            [
                {
                    "Name": "Router1",
                    "Interface": "eth0",
                    "Type": None,
                    "Comments": None,
                    "Routable": None,
                    "Details": "0.0.0.0-0.0.0.0",
                }
            ],
        ),
        (
            [
                {
                    "Country": "US",
                }
            ],
            [
                {
                    "Name": None,
                    "Interface": None,
                    "Type": None,
                    "Comments": None,
                    "Routable": None,
                    "Details": "US",
                }
            ],
        ),
        (
            [
                {"FQDN": "example.com"},
                {"MACAddresses": "00:00:00:00:00:00"},
            ],
            [
                {
                    "Name": None,
                    "Interface": None,
                    "Type": None,
                    "Comments": None,
                    "Routable": None,
                    "Details": "example.com",
                },
                {
                    "Name": None,
                    "Interface": None,
                    "Type": None,
                    "Comments": None,
                    "Routable": None,
                    "Details": "00:00:00:00:00:00",
                },
            ],
        ),
    ],
)
def test_build_address_table(items, expected_table):
    """
    Scenario:
    - Test the build_address_table function's ability to correctly format data into a table.

    Given:
    - A list of dictionaries, each representing an item with address-related data.

    When:
    - build_address_table is called with these items.

    Then:
    - Ensure that the function returns a correctly formatted table matching the expected output.
    """
    assert FortiGate.build_address_table(items) == expected_table


@pytest.mark.parametrize(
    "list_command,response_file,outputs_file,endpoint_suffix,outputs_prefix,outputs_key_field",
    [
        (
            FortiGate.list_firewall_address_ipv4s_command,
            "address_ipv4_response.json",
            "address_ipv4_outputs.json",
            FortiGate.Client.ADDRESS_IPV4_ENDPOINT,
            FortiGate.ADDRESS_CONTEXT,
            "Name",
        ),
        (
            FortiGate.list_firewall_address_ipv6s_command,
            "address_ipv6_response.json",
            "address_ipv6_outputs.json",
            FortiGate.Client.ADDRESS_IPV6_ENDPOINT,
            FortiGate.ADDRESS6_CONTEXT,
            "Name",
        ),
        (
            FortiGate.list_firewall_address_ipv4_multicasts_command,
            "address_ipv4_multicast_response.json",
            "address_ipv4_multicast_outputs.json",
            FortiGate.Client.ADDRESS_IPV4_MULTICAST_ENDPOINT,
            FortiGate.ADDRESS_MULTICAST_CONTEXT,
            "Name",
        ),
        (
            FortiGate.list_firewall_address_ipv6_multicasts_command,
            "address_ipv6_multicast_response.json",
            "address_ipv6_multicast_outputs.json",
            FortiGate.Client.ADDRESS_IPV6_MULTICAST_ENDPOINT,
            FortiGate.ADDRESS6_MULTICAST_CONTEXT,
            "Name",
        ),
        (
            FortiGate.list_firewall_address_ipv4_groups_command,
            "address_ipv4_group_response.json",
            "address_ipv4_group_outputs.json",
            FortiGate.Client.ADDRESS_IPV4_GROUP_ENDPOINT,
            FortiGate.ADDRESS_GROUP_CONTEXT,
            "Name",
        ),
        (
            FortiGate.list_firewall_address_ipv6_groups_command,
            "address_ipv6_group_response.json",
            "address_ipv6_group_outputs.json",
            FortiGate.Client.ADDRESS_IPV6_GROUP_ENDPOINT,
            FortiGate.ADDRESS6_GROUP_CONTEXT,
            "Name",
        ),
        (
            FortiGate.list_firewall_services_command,
            "service_response.json",
            "service_outputs.json",
            FortiGate.Client.SERVICE_ENDPOINT,
            FortiGate.SERVICE_CONTEXT,
            "Name",
        ),
        (
            FortiGate.list_firewall_service_groups_command,
            "service_group_response.json",
            "service_group_outputs.json",
            FortiGate.Client.SERVICE_GROUP_ENDPOINT,
            FortiGate.SERVICE_GROUP_CONTEXT,
            "Name",
        ),
        (
            FortiGate.list_firewall_policies_command,
            "policy_response.json",
            "policy_outputs.json",
            FortiGate.Client.POLICY_ENDPOINT,
            FortiGate.POLICY_CONTEXT,
            "ID",
        ),
        (
            FortiGate.list_system_vdoms_command,
            "vdom_response.json",
            "vdom_outputs.json",
            "cmdb/system/vdom",
            FortiGate.VDOM_CONTEXT,
            "Name",
        ),
    ],
)
def test_list_commands(
    requests_mock,
    mock_client: FortiGate.Client,
    list_command: Callable[[FortiGate.Client, dict[str, Any]], CommonServerPython.CommandResults],
    response_file: str,
    outputs_file: str,
    endpoint_suffix: str,
    outputs_prefix: str,
    outputs_key_field: str,
):
    """
    Scenario:
    - Test retrieving a list of objects.

    Given:
    - vdom, filter_field, filter_value, format_fields.

    When:
    - list_firewall_address_ipv4s_command
    - list_firewall_address_ipv6s_command
    - list_firewall_address_ipv4_multicasts_command
    - list_firewall_address_ipv6_multicasts_command
    - list_firewall_address_ipv4_groups_command
    - list_firewall_address_ipv6_groups_command
    - list_firewall_services_command
    - list_firewall_service_groups_command
    - list_firewall_policies_command

    Then:
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults raw_response is correct.
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    """
    args = {
        "vdom": "Pokemon",
        "filter_field": "Lior",
        "filter_value": "SB",
        "format_fields": ["I", "Choose", "You"],
    }

    response = load_mock_response(response_file)
    outputs = load_mock_response(outputs_file)

    requests_mock.get(
        url=CommonServerPython.urljoin(API_URL, endpoint_suffix),
        json=response,
    )

    command_results = list_command(mock_client, args)

    assert command_results.outputs == outputs
    assert command_results.raw_response == response
    assert command_results.outputs_prefix == outputs_prefix
    assert command_results.outputs_key_field == outputs_key_field


@pytest.mark.parametrize(
    "delete_command,identifier_field,endpoint_suffix,firewall_object,outputs_prefix,outputs_key_field",
    [
        (
            FortiGate.delete_firewall_address_ipv4_command,
            "name",
            FortiGate.Client.ADDRESS_IPV4_ENDPOINT,
            "address",
            FortiGate.ADDRESS_CONTEXT,
            "Name",
        ),
        (
            FortiGate.delete_firewall_address_ipv6_command,
            "name",
            FortiGate.Client.ADDRESS_IPV6_ENDPOINT,
            "address",
            FortiGate.ADDRESS6_CONTEXT,
            "Name",
        ),
        (
            FortiGate.delete_firewall_address_ipv4_multicast_command,
            "name",
            FortiGate.Client.ADDRESS_IPV4_MULTICAST_ENDPOINT,
            "address multicast IPv4",
            FortiGate.ADDRESS_MULTICAST_CONTEXT,
            "Name",
        ),
        (
            FortiGate.delete_firewall_address_ipv6_multicast_command,
            "name",
            FortiGate.Client.ADDRESS_IPV6_MULTICAST_ENDPOINT,
            "address multicast IPv6",
            FortiGate.ADDRESS6_MULTICAST_CONTEXT,
            "Name",
        ),
        (
            FortiGate.delete_firewall_address_ipv4_group_command,
            "name",
            FortiGate.Client.ADDRESS_IPV4_GROUP_ENDPOINT,
            "address IPv4 group",
            FortiGate.ADDRESS_GROUP_CONTEXT,
            "Name",
        ),
        (
            FortiGate.delete_firewall_address_ipv6_group_command,
            "name",
            FortiGate.Client.ADDRESS_IPV6_GROUP_ENDPOINT,
            "address IPv6 group",
            FortiGate.ADDRESS6_GROUP_CONTEXT,
            "Name",
        ),
        (
            FortiGate.delete_firewall_service_command,
            "name",
            FortiGate.Client.SERVICE_ENDPOINT,
            "service",
            FortiGate.SERVICE_CONTEXT,
            "Name",
        ),
        (
            FortiGate.delete_firewall_service_group_command,
            "groupName",
            FortiGate.Client.SERVICE_GROUP_ENDPOINT,
            "service group",
            FortiGate.SERVICE_GROUP_CONTEXT,
            "Name",
        ),
        (
            FortiGate.delete_firewall_policy_command,
            "policyID",
            FortiGate.Client.POLICY_ENDPOINT,
            "policy",
            FortiGate.POLICY_CONTEXT,
            "ID",
        ),
    ],
)
def test_delete_commands(
    requests_mock,
    mock_client: FortiGate.Client,
    delete_command: Callable[[FortiGate.Client, dict[str, Any]], CommonServerPython.CommandResults],
    identifier_field: dict[str, Any],
    endpoint_suffix: str,
    firewall_object: str,
    outputs_prefix: str,
    outputs_key_field: str,
):
    """
    Scenario:
    - Test delete an object.

    Given:
    - Identifier.

    When:
    - delete_firewall_address_ipv4_command
    - delete_firewall_address_ipv6_command
    - delete_firewall_address_ipv4_multicast_command
    - delete_firewall_address_ipv6_multicast_command
    - delete_firewall_address_ipv4_group_command
    - delete_firewall_address_ipv6_group_command
    - delete_firewall_service_command
    - delete_firewall_service_group_command

    Then:
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults readable_output is correct.
    - Ensure that the CommandResults raw_response is correct.
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    """
    args = {identifier_field: "pikachu"}
    response = load_mock_response("non_get_response.json")

    requests_mock.delete(
        url=CommonServerPython.urljoin(
            url=API_URL,
            suffix=CommonServerPython.urljoin(endpoint_suffix, args[identifier_field]),
        ),
        json=response,
    )

    command_results = delete_command(mock_client, args)

    assert command_results.outputs == {outputs_key_field: args[identifier_field], "Deleted": True}
    assert (
        command_results.readable_output
        == f"The firewall {firewall_object} '{args[identifier_field]}' was successfully deleted."
    )
    assert command_results.raw_response == response
    assert command_results.outputs_prefix == outputs_prefix
    assert command_results.outputs_key_field == outputs_key_field


@pytest.mark.parametrize(
    "address_command,args,http_method,endpoint_suffix,action,outputs,outputs_prefix,firewall_object,return_type",
    [
        (
            FortiGate.create_firewall_address_ipv4_command,
            {
                "name": "Pikachu",
                "address": "0.0.0.0",
                "mask": "1.1.1.1",
            },
            "POST",
            FortiGate.Client.ADDRESS_IPV4_ENDPOINT,
            "created",
            {
                "Name": "Pikachu",
                "IPAddress": "0.0.0.0",
                "Mask": "1.1.1.1",
            },
            FortiGate.ADDRESS_CONTEXT,
            "address",
            None,
        ),
        (
            FortiGate.update_firewall_address_ipv4_command,
            {
                "name": "Pikachu",
                "type": "Device (Mac Address)",
                "mac_addresses": "00:00:5e:00:53:af,00:B0:D0:63:C2:26,00:50:56:00:00:00-00:50:56:3F:FF:FF",
            },
            "PUT",
            FortiGate.Client.ADDRESS_IPV4_ENDPOINT,
            "updated",
            {
                "Name": "Pikachu",
                "MAC": "00:00:5e:00:53:af,00:B0:D0:63:C2:26,00:50:56:00:00:00-00:50:56:3F:FF:FF",
            },
            FortiGate.ADDRESS_CONTEXT,
            "address",
            "mac",
        ),
        (
            FortiGate.create_firewall_address_ipv6_command,
            {
                "name": "Pikachu",
                "sdn_connector": "Lior",
            },
            "POST",
            FortiGate.Client.ADDRESS_IPV6_ENDPOINT,
            "created",
            {
                "Name": "Pikachu",
                "SDN": "Lior",
            },
            FortiGate.ADDRESS6_CONTEXT,
            "address",
            None,
        ),
        (
            FortiGate.update_firewall_address_ipv6_command,
            {
                "name": "Pikachu",
                "address": "0000:0000::",
                "mask": "64",
            },
            "PUT",
            FortiGate.Client.ADDRESS_IPV6_ENDPOINT,
            "updated",
            {
                "Name": "Pikachu",
                "IPAddress": "0000:0000::",
                "Mask": "64",
            },
            FortiGate.ADDRESS6_CONTEXT,
            "address",
            "ipprefix",
        ),
        (
            FortiGate.create_firewall_address_ipv4_multicast_command,
            {
                "name": "Pikachu",
                "type": "Broadcast Subnet",
                "first_ip": "0.0.0.0",
                "final_ip": "1.1.1.1",
            },
            "POST",
            FortiGate.Client.ADDRESS_IPV4_MULTICAST_ENDPOINT,
            "created",
            {
                "Name": "Pikachu",
                "Type": "Broadcast Subnet",
                "FirstIP": "0.0.0.0",
                "FinalIP": "1.1.1.1",
            },
            FortiGate.ADDRESS_MULTICAST_CONTEXT,
            "address multicast IPv4",
            None,
        ),
        (
            FortiGate.update_firewall_address_ipv4_multicast_command,
            {
                "name": "Pikachu",
                "type": "Multicast IP Range",
                "first_ip": "0.0.0.0",
                "final_ip": "1.1.1.1",
            },
            "PUT",
            FortiGate.Client.ADDRESS_IPV4_MULTICAST_ENDPOINT,
            "updated",
            {
                "Name": "Pikachu",
                "Type": "Multicast IP Range",
                "FirstIP": "0.0.0.0",
                "FinalIP": "1.1.1.1",
            },
            FortiGate.ADDRESS_MULTICAST_CONTEXT,
            "address multicast IPv4",
            "multicastrange",
        ),
        (
            FortiGate.create_firewall_address_ipv6_multicast_command,
            {
                "name": "Pikachu",
                "address": "0000:0000:0000:0000:0000:0000:0000:0000",
                "mask": "64",
            },
            "POST",
            FortiGate.Client.ADDRESS_IPV6_MULTICAST_ENDPOINT,
            "created",
            {
                "Name": "Pikachu",
                "IPAddress": "0000:0000:0000:0000:0000:0000:0000:0000",
                "Mask": "64",
            },
            FortiGate.ADDRESS6_MULTICAST_CONTEXT,
            "address multicast IPv6",
            None,
        ),
        (
            FortiGate.update_firewall_address_ipv6_multicast_command,
            {
                "name": "Pikachu",
                "address": "0000:0000:0000:0000:0000:0000:0000:0000",
                "mask": "64",
            },
            "PUT",
            FortiGate.Client.ADDRESS_IPV6_MULTICAST_ENDPOINT,
            "updated",
            {
                "Name": "Pikachu",
                "IPAddress": "0000:0000:0000:0000:0000:0000:0000:0000",
                "Mask": "64",
            },
            FortiGate.ADDRESS6_MULTICAST_CONTEXT,
            "address multicast IPv6",
            None,
        ),
    ],
)
def test_firewall_address_commands(
    requests_mock,
    mock_client: FortiGate.Client,
    address_command: Callable[[FortiGate.Client, dict[str, Any]], CommonServerPython.CommandResults],
    args: dict[str, Any],
    http_method: str,
    endpoint_suffix: str,
    action: str,
    outputs: dict[str, Any],
    outputs_prefix: str,
    firewall_object: str,
    return_type: str | None,
):
    """
    Scenario:
    - Test create and update firewall address commands.

    Given:
    - arguments for creation or editing.

    When:
    - create_firewall_address_ipv4_command
    - update_firewall_address_ipv4_command
    - create_firewall_address_ipv6_command
    - update_firewall_address_ipv6_command
    - create_firewall_address_ipv4_multicast_command
    - update_firewall_address_ipv4_multicast_command
    - create_firewall_address_ipv6_multicast_command
    - update_firewall_address_ipv6_multicast_command

    Then:
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults readable_output is correct.
    - Ensure that the CommandResults raw_response is correct.
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    """
    response = load_mock_response("non_get_response.json")
    endpoint = CommonServerPython.urljoin(API_URL, endpoint_suffix)
    is_post = http_method == "POST"

    # Mock the GET request to validate the given and API's type are the same.
    if not is_post and "multicast IPv6" not in firewall_object:
        requests_mock.get(
            url=CommonServerPython.urljoin(endpoint, args["name"]),
            json={"results": [{"type": return_type}]},
        )

    requests_mock.request(
        method=http_method,
        url=endpoint if is_post else CommonServerPython.urljoin(endpoint, args["name"]),
        json=response,
    )

    command_results = address_command(mock_client, args)

    assert (
        command_results.readable_output == f"The firewall {firewall_object} '{args['name']}' was successfully {action}."
    )
    assert command_results.raw_response == response
    assert command_results.outputs == outputs
    assert command_results.outputs_prefix == outputs_prefix
    assert command_results.outputs_key_field == "Name"
