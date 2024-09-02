import json
import os
from typing import Any, Callable

import CommonServerPython
import FortiGate
import pytest

TEST_DATA = "test_data"
BASE_URL = "https://www.example.com"
API_URL = CommonServerPython.urljoin(BASE_URL, "api/v2")


def load_mock_response(file_name: str) -> dict[str, Any]:
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
def mock_client() -> FortiGate.Client:
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
                "No group of arguments was fully set. Please provide arguments from one of the following groups: "
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
    "args, expected_result",
    [
        ({"start_ip": "0.0.0.0", "end_ip": "0.0.0.0", "tcpRange": "80"}, FortiGate.TCP_UDP_SCTP),
        ({"tcpRange": "80"}, FortiGate.TCP_UDP_SCTP),
        ({"udpRange": "80"}, FortiGate.TCP_UDP_SCTP),
        ({"sctpRange": "80"}, FortiGate.TCP_UDP_SCTP),
        ({"ip_protocol": "6"}, FortiGate.IP),
        ({"icmp_version": "icmp", "icmp_type": "8", "icmp_code": "0"}, FortiGate.ICMP),
        ({"icmp_version": "icmp6", "icmp_type": "128", "icmp_code": "0"}, FortiGate.ICMP6),
    ],
)
def test_get_service_type_success(args: dict[str, Any], expected_result: str):
    """
    Scenario:
    - Test the get_service_type function's success handling for valid arguments.

    Given:
    - A dictionary of arguments that are complete and correctly isolated per protocol type.

    When:
    - get_service_type is called with these arguments.

    Then:
    - Ensure that the correct service type string is returned for each set of arguments.
    """
    result = FortiGate.get_service_type(args)
    assert result == expected_result


@pytest.mark.parametrize(
    "args, error_message",
    [
        (
            {},
            (
                (
                    "No protocol type arguments were fully set."
                    " Please provide arguments from one of the following protocol types:"
                    " ['TCP/UDP/SCTP', 'IP', 'ICMP/ICMP6']"
                )
            ),
        ),
        (
            {"start_ip": "0.0.0.0"},
            (
                "Missing arguments for the protocol type TCP/UDP/SCTP,"
                " please provide at least one of: tcpRange, udpRange, sctpRange."
            ),
        ),
        (
            {"icmp_type": "8"},
            "Missing arguments for the protocol type ICMP/ICMP6, please provide: icmp_version",
        ),
        (
            {"start_ip": "0.0.0.0", "ip_protocol": "6"},
            "Arguments must only come from one protocol type. Mixed protocol types: IP, TCP/UDP/SCTP",
        ),
    ],
)
def test_get_service_type_error(args: dict[str, Any], error_message: str):
    """
    Scenario:
    - Test the get_service_type function's error handling for invalid arguments.

    Given:
    - A dictionary of arguments that are incomplete or incorrectly combined.

    When:
    - No arguments provided.
    - Partial arguments from a protocol type are provided.
    - Mixing between protocol type arguments.

    Then:
    - Ensure that a DemistoException is raised with the correct error message.
    - Ensure that the actual error message matches the expected error message.
    """
    with pytest.raises(CommonServerPython.DemistoException) as exc_info:
        FortiGate.get_service_type(args)

    assert str(exc_info.value) == error_message


@pytest.mark.parametrize(
    "mac_addresses",
    [
        ["00:00:00:00:00:ZZ"],
        ["ZZ:ZZ:ZZ:ZZ:ZZ:ZZ"],
    ],
)
def test_validate_mac_addresses_error(mac_addresses: list[str]):
    """
    Scenario:
    - Test the validate_mac_addresses function's error handling for invalid MAC addresses.

    Given:
    - A list of invalid MAC addresses.

    When:
    - MAC addresses do not conform to the standard MAC address format.

    Then:
    - Ensure that a DemistoException is raised with a message indicating an invalid MAC address.
    - Ensure that the actual error message contains "Invalid MAC address".
    """
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
    """
    Scenario:
    - Test the validate_optional_ipv4_addresses function's error handling for invalid IPv4 addresses.

    Given:
    - A list of invalid IPv4 addresses.

    When:
    - IPv4 addresses are not in the correct format or range.

    Then:
    - Ensure that a DemistoException is raised with a message indicating an invalid IPv4 address.
    - Ensure that the actual error message contains "Invalid IPv4 address".
    """
    with pytest.raises(CommonServerPython.DemistoException) as exc_info:
        FortiGate.validate_optional_ipv4_addresses(ipv4_addresses)

    assert "Invalid IPv4 address" in str(exc_info.value)


@pytest.mark.parametrize(
    "ipv6_networks",
    [("gggg:gggg:gggg:gggg:gggg:gggg:gggg:gggg")],
)
def test_validate_optional_ipv6_networks_error(ipv6_networks: str):
    """
    Scenario:
    - Test the validate_optional_ipv6_networks function's error handling for invalid IPv6 addresses.

    Given:
    - A list of invalid IPv6 addresses.

    When:
    - IPv6 addresses do not conform to the standard IPv6 format.

    Then:
    - Ensure that a DemistoException is raised with a message indicating an invalid IPv6 address.
    - Ensure that the actual error message contains "Invalid IPv6 address".
    """
    with pytest.raises(CommonServerPython.DemistoException) as e_info:
        FortiGate.validate_optional_ipv6_networks(ipv6_networks)

    assert "Invalid IPv6 address" in str(e_info.value)


@pytest.mark.parametrize(
    "mask",
    [129, -1],
)
def test_validate_mask_error(mask: int):
    """
    Scenario:
    - Test the validate_mask function's error handling for invalid mask values.

    Given:
    - Invalid mask values (either too large or negative).

    When:
    - Mask values are outside the valid range for subnet masks.

    Then:
    - Ensure that a DemistoException is raised with a message indicating an invalid mask.
    - Ensure that the actual error message contains "Invalid mask".
    """
    with pytest.raises(CommonServerPython.DemistoException) as e_info:
        FortiGate.validate_mask(mask)

    assert "Invalid mask" in str(e_info.value)


@pytest.mark.parametrize(
    "command,args,error_message",
    [
        (
            FortiGate.update_firewall_address_ipv4_group_command,
            {"address": "1"},
            "`address` or `excluded_addresses` must be set with `action`.",
        ),
        (
            FortiGate.update_firewall_address_ipv6_group_command,
            {"action": "add"},
            "`members` must be set with `action`.",
        ),
    ],
)
def test_update_group_errors(
    mock_client: FortiGate.Client,
    command: Callable[[FortiGate.Client, dict[str, Any]], CommonServerPython.CommandResults],
    args: dict[str, Any],
    error_message: str,
):
    """
    Scenario:
    - Test the update group function's error handling for incorrect parameter combinations.

    Given:
    - A combination of parameters where 'action' or the group items are missing.

    When:
    - group items is provided but 'action' is missing, meaning an action must be specified for the input items.
    - 'action' is provided but group items is missing, meaning an action must be specified for the input items.

    Then:
    - Ensure that a DemistoException is raised with the correct error message.
    - Ensure that the actual error message matches the expected error message based on the given parameter.
    """
    with pytest.raises(CommonServerPython.DemistoException) as exc_info:
        command(mock_client, args)

    assert str(exc_info.value) == error_message


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
    "build_table, items, expected_table",
    [
        (
            FortiGate.build_address_table,
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
            FortiGate.build_address_table,
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
            FortiGate.build_address_table,
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
        (
            FortiGate.build_address_group_table,
            [
                {
                    "Name": "Group1",
                    "Type": "Type1",
                    "Comment": "A sample group",
                    "ExcludeMember": "Member1",
                    "AllowRouting": True,
                    "Member": {"Name": "MemberName1"},
                }
            ],
            [
                {
                    "Name": "Group1",
                    "Type": "Type1",
                    "Comments": "A sample group",
                    "Exclude Members": "Member1",
                    "Routable": True,
                    "Details": "MemberName1",
                }
            ],
        ),
        (
            FortiGate.build_service_table,
            [
                {
                    "Name": "Service1",
                    "Category": "Cat1",
                    "Protocol": FortiGate.TCP_UDP_SCTP,
                    "Ports": {"TCP": "80", "UDP": "53", "SCTP": "10000"},
                    "IPRange": "0.0.0.0-0.0.0.0",
                }
            ],
            [
                {
                    "Name": "Service1",
                    "Category": "Cat1",
                    "Protocol": FortiGate.TCP_UDP_SCTP,
                    "Details": "TCP/80 UDP/53 SCTP/10000",
                    "IP/FQDN": "0.0.0.0-0.0.0.0",
                }
            ],
        ),
        (
            FortiGate.build_service_group_table,
            [
                {
                    "Name": "Group1",
                    "Comment": "A sample group",
                    "Member": {"Name": ["Member1", "Member2"]},
                }
            ],
            [
                {
                    "Name": "Group1",
                    "Comments": "A sample group",
                    "Members": ["Member1", "Member2"],
                }
            ],
        ),
        (
            FortiGate.build_policy_table,
            [
                {
                    "ID": "1",
                    "Name": "Policy1",
                    "SourceInterface": "Interface1",
                    "DestinationInterface": "Interface2",
                    "Schedule": "Always",
                    "Service": "Web",
                    "Action": "Allow",
                    "NAT": "Enabled",
                    "Security": "Profile1",
                    "Log": "Enabled",
                    "Source": "0.0.0.0",
                    "Destination": "0.0.0.0",
                },
                {
                    "ID": "2",
                    "Name": "Policy2",
                    "SourceInterface": "Interface3",
                    "DestinationInterface": "Interface4",
                    "Schedule": "Night",
                    "Service": "Email",
                    "Action": "Deny",
                    "NAT": "Disabled",
                    "Security": "Profile2",
                    "Log": "Disabled",
                    "Source6": "0000::0",
                    "Destination6": "0000::0",
                },
            ],
            [
                {
                    "ID": "1",
                    "Name": "Policy1",
                    "From": "Interface1",
                    "To": "Interface2",
                    "Schedule": "Always",
                    "Service": "Web",
                    "Action": "Allow",
                    "NAT": "Enabled",
                    "Security Profiles": "Profile1",
                    "Log": "Enabled",
                    "Source": "0.0.0.0",
                    "Destination": "0.0.0.0",
                },
                {
                    "ID": "2",
                    "Name": "Policy2",
                    "From": "Interface3",
                    "To": "Interface4",
                    "Schedule": "Night",
                    "Service": "Email",
                    "Action": "Deny",
                    "NAT": "Disabled",
                    "Security Profiles": "Profile2",
                    "Log": "Disabled",
                    "Source": "0000::0",
                    "Destination": "0000::0",
                },
            ],
        ),
    ],
)
def test_build_table(build_table: Callable, items: dict[str, Any], expected_table: dict[str, Any]):
    """
    Scenario:
    - Test the build table function's ability to correctly format data into a different tables.
    """
    assert build_table(items) == expected_table


@pytest.mark.parametrize(
    "item, expected_result",
    [
        ({"Ports": {"TCP": "80 443", "UDP": "53", "SCTP": "10000"}}, "TCP/80 TCP/443 UDP/53 SCTP/10000"),
        ({"Ports": {}}, ""),
        ({"Ports": {"TCP": "22"}}, "TCP/22"),
    ],
)
def test_handle_tcp_udp_sctp(item: dict[str, Any], expected_result: str):
    """Validates that the function correctly handles different combinations of TCP, UDP, and SCTP port ranges."""
    assert FortiGate.handle_tcp_udp_sctp(item) == expected_result


@pytest.mark.parametrize(
    "item, expected_result",
    [({"ProtocolNumber": 4}, "IP/4"), ({"ProtocolNumber": 0}, "Any"), ({}, "Any")],
)
def test_handle_ip(item, expected_result):
    """Checks if the function correctly handles the IP protocol number."""
    assert FortiGate.handle_ip(item) == expected_result


@pytest.mark.parametrize(
    "item, expected_result",
    [
        ({"Protocol": "ICMP", "ICMPType": 8, "ICMPCode": 1}, "ICMP/1"),
        ({"Protocol": "ICMP", "ICMPType": 8, "ICMPCode": 0}, "ICMP/ANY"),
        ({"Protocol": "ICMP6", "ICMPType": 128}, "ICMP6/ANY"),
        ({"Protocol": "ICMP"}, "ANY"),
        ({}, "ANY"),
    ],
)
def test_handle_icmp_icmp6(item, expected_result):
    """Ensures that the function correctly processes ICMP and ICMP6 protocol types and codes."""
    assert FortiGate.handle_icmp_icmp6(item) == expected_result


def test_map_keys():
    """
    Test the map_keys function to ensure it correctly maps keys from an old dictionary to a new dictionary.
    """
    old_dict = {"key1": "value1", "key2": {"subkey1": "subvalue1", "subkey2": "subvalue2"}}
    mappings = [
        FortiGate.Mapping(old_keys=["key1"], new_keys=["newKey1"]),
        FortiGate.Mapping(old_keys=["key2", "subkey1"], new_keys=["newKey2", "newSubKey1"]),
        FortiGate.Mapping(old_keys=["nonexistentKey"], new_keys=["newKey3"], default_value="defaultValue"),
        FortiGate.Mapping(
            old_keys=["key2", "subkey2"],
            new_keys=["newKey2", "newSubKey2"],
            default_value=None,
            value_changer=lambda x: x.upper(),
        ),
    ]
    expected_result = {
        "newKey1": "value1",
        "newKey2": {"newSubKey1": "subvalue1", "newSubKey2": "SUBVALUE2"},
        "newKey3": "defaultValue",
    }

    assert FortiGate.map_keys(old_dict, mappings) == expected_result


@pytest.mark.parametrize(
    "input_items, action, current_items, expected_result",
    [
        (
            ["item3", "item4"],
            "add",
            ["item1", "item2"],
            ["item1", "item2", "item3", "item4"],
        ),
        (
            ["item2", "item3"],
            "remove",
            ["item1", "item2", "item3"],
            ["item1"],
        ),
        (
            ["item3"],
            None,
            ["item1", "item2"],
            ["item1", "item2"],
        ),
        (
            ["item2", "item3"],
            "add",
            ["item1", "item2"],
            ["item1", "item2", "item3"],
        ),
    ],
)
def test_handle_group_items_by_action(input_items, action, current_items, expected_result):
    """
    Scenario:
    - Test adding or removing items from a group.

    Given:
    - A list of input items and a list of current items in the group.
    - An action specifying whether to add or remove items.

    When:
    - handle_group_items_by_action is invoked with different combinations of input items, actions, and current items.

    Then:
    - Ensure that the returned list of items is correct for each scenario.
    """
    result = FortiGate.handle_group_items_by_action(input_items, action, current_items)
    assert set(result) == set(expected_result)


@pytest.mark.parametrize(
    "obj, action, tcp_port_ranges, udp_port_ranges, sctp_port_ranges, expected_result",
    [
        (
            {"tcp-portrange": "80 443", "udp-portrange": "53", "sctp-portrange": "10000"},
            "add",
            ["8080"],
            ["69"],
            ["12345"],
            {
                "tcp_port_ranges": ["80", "443", "8080"],
                "udp_port_ranges": ["53", "69"],
                "sctp_port_ranges": ["10000", "12345"],
            },
        ),
        (
            {"tcp-portrange": "80 443", "udp-portrange": "53", "sctp-portrange": "10000"},
            "remove",
            ["443"],
            ["53"],
            ["10000"],
            {"tcp_port_ranges": ["80"], "udp_port_ranges": [], "sctp_port_ranges": []},
        ),
        (
            {},
            "add",
            ["22"],
            ["123"],
            ["9999"],
            {"tcp_port_ranges": ["22"], "udp_port_ranges": ["123"], "sctp_port_ranges": ["9999"]},
        ),
    ],
)
def test_handle_action_for_port_ranges(
    obj, action, tcp_port_ranges, udp_port_ranges, sctp_port_ranges, expected_result
):
    """Test the handle_action_for_port_ranges function with different actions and port ranges.

    Scenarios:
        - Adding new port ranges.
        - Removing existing port ranges.
        - Handling None action.
        - Handling empty initial port ranges.
    """
    result = FortiGate.handle_action_for_port_ranges(obj, action, tcp_port_ranges, udp_port_ranges, sctp_port_ranges)

    for key in expected_result:
        assert set(result[key]) == set(expected_result[key])


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
        (
            FortiGate.list_banned_ips_command,
            "banned_ip_response.json",
            "banned_ip_outputs.json",
            CommonServerPython.urljoin(FortiGate.Client.BANNED_IP_ENDPOINT, "select"),
            FortiGate.BANNED_IP_CONTEXT,
            "IP",
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
    - list_system_vdoms_command
    - list_banned_ips_command

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
        == f"## The firewall {firewall_object} '{args[identifier_field]}' was successfully deleted."
    )
    assert command_results.raw_response == response
    assert command_results.outputs_prefix == outputs_prefix
    assert command_results.outputs_key_field == outputs_key_field


@pytest.mark.parametrize(
    "command,args,http_method,endpoint_suffix,action,outputs,outputs_prefix,firewall_object,return_value",
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
            {"type": "mac"},
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
            {"type": "ipprefix"},
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
            {"type": "multicastrange"},
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
        (
            FortiGate.create_firewall_address_ipv4_group_command,
            {
                "groupName": "Pikachu",
                "type": "group",
                "address": "pikachu,use,thunderbolt",
                "excluded_addresses": "pikachu,use,irontail",
                "allow_routing": "enable",
            },
            "POST",
            FortiGate.Client.ADDRESS_IPV4_GROUP_ENDPOINT,
            "created",
            {
                "Name": "Pikachu",
                "Address": "pikachu,use,thunderbolt",
            },
            FortiGate.ADDRESS_GROUP_CONTEXT,
            "address IPv4 group",
            None,
        ),
        (
            FortiGate.create_firewall_address_ipv6_group_command,
            {
                "name": "Pikachu",
                "members": "pikachu,use,thunderbolt",
            },
            "POST",
            FortiGate.Client.ADDRESS_IPV6_GROUP_ENDPOINT,
            "created",
            {
                "Name": "Pikachu",
                "Address": "pikachu,use,thunderbolt",
            },
            FortiGate.ADDRESS6_GROUP_CONTEXT,
            "address IPv6 group",
            None,
        ),
        (
            FortiGate.create_firewall_service_command,
            {
                "serviceName": "Pikachu",
                "category": "thunder",
                "tcpRange": "1-2",
            },
            "POST",
            FortiGate.Client.SERVICE_ENDPOINT,
            "created",
            {
                "Name": "Pikachu",
                "Ports": {
                    "TCP": "1-2",
                    "UDP": "",
                    "SCTP": "",
                },
            },
            FortiGate.SERVICE_CONTEXT,
            "service",
            None,
        ),
        (
            FortiGate.update_firewall_service_command,
            {
                "name": "Pikachu",
                "category": "thunder",
                "tcpRange": "1-2",
                "action": "add",
            },
            "PUT",
            FortiGate.Client.SERVICE_ENDPOINT,
            "updated",
            {
                "Name": "Pikachu",
                "Ports": {
                    "TCP": "1-2",
                    "UDP": "",
                    "SCTP": "",
                },
            },
            FortiGate.SERVICE_CONTEXT,
            "service",
            {
                "protocol": FortiGate.TCP_UDP_SCTP,
                "tcp-portrange": "1-2 3-4",
                "udp-portrange": "1-2",
            },
        ),
        (
            FortiGate.create_firewall_service_group_command,
            {
                "name": "Pikachu",
                "members": "use,thunderbolt",
            },
            "POST",
            FortiGate.Client.SERVICE_GROUP_ENDPOINT,
            "created",
            {
                "Name": "Pikachu",
                "Members": "use,thunderbolt",
            },
            FortiGate.SERVICE_GROUP_CONTEXT,
            "service group",
            None,
        ),
        (
            FortiGate.create_firewall_policy_command,
            {
                "policyName": "Pikachu",
                "sourceIntf": "use,thunderbolt",
                "dstIntf": "chikorita",
                "service": "mudkip",
                "source": "voltorb",
                "destination": "gengar",
                "action": "deny",
            },
            "POST",
            FortiGate.Client.POLICY_ENDPOINT,
            "created",
            {
                "Name": "Pikachu",
                "Description": None,
                "Status": "enable",
                "Service": "mudkip",
                "Action": "deny",
                "Log": "enable",
                "Source": {
                    "Interface": "use,thunderbolt",
                    "Address": [{"name": "voltorb"}],
                    "Address6": [{"name": ""}],
                },
                "Destination": {
                    "Interface": "chikorita",
                    "Address": [{"name": "gengar"}],
                    "Address6": [{"name": ""}],
                },
                "NAT": "enable",
            },
            FortiGate.POLICY_CONTEXT,
            "policy",
            None,
        ),
    ],
)
def test_create_and_update_commands(
    requests_mock,
    mock_client: FortiGate.Client,
    command: Callable[[FortiGate.Client, dict[str, Any]], CommonServerPython.CommandResults],
    args: dict[str, Any],
    http_method: str,
    endpoint_suffix: str,
    action: str,
    outputs: dict[str, Any],
    outputs_prefix: str,
    firewall_object: str,
    return_value: str | None,
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
    - create_firewall_service_command
    - update_firewall_service_command
    - create_firewall_service_group_command
    - create_firewall_policy_command

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
    identifier = next(iter(args.values()))

    # Mock the GET request to validate the given and API's type are the same.
    if not is_post and "multicast IPv6" not in firewall_object:
        requests_mock.get(
            url=CommonServerPython.urljoin(endpoint, identifier),
            json={"results": [return_value]},
        )

    requests_mock.request(
        method=http_method,
        url=endpoint if is_post else CommonServerPython.urljoin(endpoint, identifier),
        json=response,
    )

    command_results = command(mock_client, args)

    assert (
        command_results.readable_output
        == f"## The firewall {firewall_object} '{identifier}' was successfully {action}."
    )
    assert command_results.raw_response == response
    assert command_results.outputs == outputs
    assert command_results.outputs_prefix == outputs_prefix
    assert command_results.outputs_key_field == "Name"


@pytest.mark.parametrize(
    "command,args,endpoint_suffix,outputs,outputs_prefix,firewall_object,response1,response2",
    [
        (
            FortiGate.update_firewall_address_ipv4_group_command,
            {
                "groupName": "Pikachu",
                "address": "pikachu,use,thunderbolt",
                "excluded_addresses": "prepare,for,trouble",
                "allow_routing": "enable",
                "action": "remove",
            },
            FortiGate.Client.ADDRESS_IPV4_GROUP_ENDPOINT,
            {
                "Name": "Pikachu",
                "Address": {"Name": ["go"]},
                "UUID": "12345",
            },
            FortiGate.ADDRESS_GROUP_CONTEXT,
            "address IPv4 group",
            {
                "results": [
                    {
                        "member": [
                            {"name": "go"},
                            {"name": "pikachu"},
                            {"name": "use"},
                            {"name": "thunderbolt"},
                        ],
                        "exclude-member": [
                            {"name": "prepare"},
                            {"name": "for"},
                            {"name": "double"},
                            {"name": "trouble"},
                        ],
                    }
                ]
            },
            {
                "results": [
                    {
                        "uuid": "12345",
                        "member": [{"name": "go"}],
                        "exclude-member": [{"name": "double"}],
                    }
                ]
            },
        ),
        (
            FortiGate.update_firewall_address_ipv6_group_command,
            {
                "name": "Pikachu",
                "members": "pikachu,use,thunderbolt",
                "action": "add",
            },
            FortiGate.Client.ADDRESS_IPV6_GROUP_ENDPOINT,
            {
                "Name": "Pikachu",
                "Address": {"Name": ["go", "pikachu", "use", "thunderbolt"]},
            },
            FortiGate.ADDRESS6_GROUP_CONTEXT,
            "address IPv6 group",
            {
                "results": [
                    {
                        "member": [
                            {"name": "go"},
                            {"name": "pikachu"},
                            {"name": "use"},
                        ],
                    }
                ]
            },
            {
                "results": [
                    {
                        "member": [
                            {"name": "go"},
                            {"name": "pikachu"},
                            {"name": "use"},
                            {"name": "thunderbolt"},
                        ],
                    }
                ]
            },
        ),
        (
            FortiGate.update_firewall_service_group_command,
            {
                "groupName": "Pikachu",
                "serviceName": "pikachu,use,thunderbolt",
                "action": "add",
            },
            FortiGate.Client.SERVICE_GROUP_ENDPOINT,
            {
                "Name": "Pikachu",
                "Service": {"Name": ["go", "pikachu", "use", "thunderbolt"]},
            },
            FortiGate.SERVICE_GROUP_CONTEXT,
            "service group",
            {
                "results": [
                    {
                        "member": [
                            {"name": "go"},
                            {"name": "pikachu"},
                            {"name": "use"},
                        ],
                    }
                ]
            },
            {
                "results": [
                    {
                        "member": [
                            {"name": "go"},
                            {"name": "pikachu"},
                            {"name": "use"},
                            {"name": "thunderbolt"},
                        ],
                    }
                ]
            },
        ),
    ],
)
def test_update_group_commands(
    requests_mock,
    mock_client: FortiGate.Client,
    command: Callable[[FortiGate.Client, dict[str, Any]], CommonServerPython.CommandResults],
    args: dict[str, Any],
    endpoint_suffix: str,
    outputs: dict[str, Any],
    outputs_prefix: str,
    firewall_object: str,
    response1: dict[str, Any],
    response2: dict[str, Any],
):
    """
    Scenario:
    - Test update firewall group commands.

    Given:
    - arguments for editing.

    When:
    - update_firewall_address_ipv4_group_command
    - update_firewall_address_ipv6_group_command

    Then:
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults readable_output is correct.
    - Ensure that the CommandResults raw_response is correct.
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    """
    identifier = next(iter(args.values()))
    endpoint = CommonServerPython.urljoin(API_URL, f"{endpoint_suffix}/{identifier}")

    # Mock the GET request to fetch current items in group
    requests_mock.get(
        url=endpoint,
        json=response1,
    )
    # Mock the PUT request to update the group
    requests_mock.put(
        url=endpoint,
        json={},
    )
    # Mock the GET request to fetch the updated group
    requests_mock.get(
        url=endpoint,
        json=response2,
    )

    command_results = command(mock_client, args)

    assert (
        command_results.readable_output == f"## The firewall {firewall_object} '{identifier}' was successfully updated."
    )
    assert command_results.raw_response == response2
    assert command_results.outputs == outputs
    assert command_results.outputs_prefix == outputs_prefix
    assert command_results.outputs_key_field == "Name"


@pytest.mark.parametrize(
    "command,args,endpoint_suffix,action",
    [
        (
            FortiGate.ban_ip_command,
            {"ip_address": "0.0.0.0,0000:0000:0000:0000:0000:0000:0000:0000", "source": "ips"},
            "add_users",
            "banned",
        ),
        (
            FortiGate.unban_ip_command,
            {"ip_address": "0.0.0.0,0000:0000:0000:0000:0000:0000:0000:0000"},
            "clear_users",
            "unbanned",
        ),
    ],
)
def test_banned_ip_commands(
    requests_mock,
    mock_client: FortiGate.Client,
    command: Callable[[FortiGate.Client, dict[str, Any]], CommonServerPython.CommandResults],
    args: dict[str, Any],
    endpoint_suffix: str,
    action: str,
):
    """
    Scenario:
    - Test banning and unbanning IP addresses

    Given:
    - IP addresses.

    When:
    - ban_ip_command
    - unban_IP_command

    Then:
    - Ensure that the CommandResults readable_output is correct.
    - Ensure that the CommandResults raw_response is correct.
    """
    response = load_mock_response("non_get_response.json")
    endpoint = CommonServerPython.urljoin(API_URL, f"{FortiGate.Client.BANNED_IP_ENDPOINT}/{endpoint_suffix}")

    requests_mock.post(
        url=endpoint,
        json=response,
    )

    command_results = command(mock_client, args)

    assert command_results.readable_output == f"## The IPs '{next(iter(args.values()))}' were successfully {action}."
    assert command_results.raw_response == response
    assert command_results.outputs_prefix == FortiGate.BANNED_IP_CONTEXT


@pytest.mark.parametrize(
    "args, response, expected_error",
    [
        (
            {"name": "testService", "tcpRange": "80", "icmp_version": "icmp", "action": "remove"},
            {"protocol": FortiGate.TCP_UDP_SCTP},
            "Arguments must only come from one protocol type. Mixed protocol types: TCP/UDP/SCTP, ICMP/ICMP6",
        ),
        (
            {"name": "testService", "action": "add"},
            {},
            f"'action' and '{FortiGate.TCP_UDP_SCTP}' must be set together.",
        ),
    ],
)
def test_update_firewall_service_command_error(
    requests_mock,
    mock_client: FortiGate.Client,
    args: dict[str, Any],
    response: dict[str, Any],
    expected_error: str,
):
    """
    Test the update_firewall_service_command function for failure scenarios.

    Scenarios:
    - Mismatch between input protocol type and API protocol type.
    - Action provided without TCP/UDP/SCTP parameters.
    """
    requests_mock.get(
        url=CommonServerPython.urljoin(API_URL, f"{FortiGate.Client.SERVICE_ENDPOINT}/{args['name']}"),
        json=response,
    )

    with pytest.raises(CommonServerPython.DemistoException) as exc_info:
        FortiGate.update_firewall_service_command(mock_client, args)

    assert str(exc_info.value) == expected_error


def test_move_firewall_policy_command(requests_mock, mock_client: FortiGate.Client):
    """
    Scenario:
    - Test move_firewall_policy_command.

    Given:
    - arguments for creation or editing.

    When:
    - move_firewall_policy_command is called

    Then:
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults readable_output is correct.
    - Ensure that the CommandResults raw_response is correct.
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    """
    args = {
        "policyID": "Pikachu",
        "position": "after",
        "neighbor": "1",
    }
    response = load_mock_response("non_get_response.json")

    requests_mock.put(
        url=CommonServerPython.urljoin(API_URL, f"{FortiGate.Client.POLICY_ENDPOINT}/{args['policyID']}"),
        json=response,
    )

    command_results = FortiGate.move_firewall_policy_command(mock_client, args)

    assert command_results.readable_output == f"## The firewall policy '{args['policyID']}' was successfully moved."
    assert command_results.raw_response == response
    assert command_results.outputs == {"ID": "Pikachu", "Moved": True}
    assert command_results.outputs_prefix == FortiGate.POLICY_CONTEXT
    assert command_results.outputs_key_field == "ID"


def test_update_firewall_policy_command(requests_mock, mock_client: FortiGate.Client):
    """
    Scenario:
    - Test update_firewall_policy_command.

    Given:
    - arguments for creation or editing.

    When:
    - update_firewall_policy_command is called

    Then:
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults readable_output is correct.
    - Ensure that the CommandResults raw_response is correct.
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    """
    args = {
        "policyID": "2",
        "field": "service",
        "value": "boo",
        "keep_original_data": True,
        "add_or_remove": "add",
    }
    response = load_mock_response("policy_response.json")
    outputs = load_mock_response("policy_outputs.json")[0]
    response["results"] = [response["results"][0]]

    requests_mock.get(
        url=CommonServerPython.urljoin(API_URL, f"{FortiGate.Client.POLICY_ENDPOINT}/{args['policyID']}"),
        json=response,
    )
    requests_mock.put(
        url=CommonServerPython.urljoin(API_URL, f"{FortiGate.Client.POLICY_ENDPOINT}/{args['policyID']}"),
        json={},
    )
    response["results"][0]["service"].append({"name": "boo"})
    requests_mock.get(
        url=CommonServerPython.urljoin(API_URL, f"{FortiGate.Client.POLICY_ENDPOINT}/{args['policyID']}"),
        json=response,
    )

    command_results = FortiGate.update_firewall_policy_command(mock_client, args)
    outputs["Service"].append("boo")
    outputs.pop("VDOM")

    assert command_results.readable_output == f"## The firewall policy '{args['policyID']}' was successfully updated."
    assert command_results.raw_response == response
    assert command_results.outputs == outputs
    assert command_results.outputs_prefix == FortiGate.POLICY_CONTEXT
    assert command_results.outputs_key_field == "ID"


def test_update_firewall_policy_command_error(mock_client: FortiGate.Client):
    """
    Test the update_firewall_policy_command function for failure scenarios.

    Scenarios:
    - If 'keep_original_data' is set to True, but 'add_or_remove' isn't set.

    Then:
    - Ensure that the error message is the same.
    """
    with pytest.raises(CommonServerPython.DemistoException) as exc_info:
        FortiGate.update_firewall_policy_command(mock_client, {"keep_original_data": "true"})

    assert str(exc_info.value) == "If 'keep_original_data' is set to True, 'add_or_remove' must also be set."


def test_list_firewall_policies_return_all_policy_name(mock_client: FortiGate.Client, requests_mock):
    """
        Given: Args to run list_firewall_policies command with policyName to filter by which does not match any policy.
        When: Running list_firewall_policies command.
        Then: Validate no results are returned.
    """

    args = {
        "vdom": "Pokemon",
        "filter_field": "Lior",
        "filter_value": "SB",
        "format_fields": ["I", "Choose", "You"],
        "policyName": "Non-exist-policy"
    }

    response = load_mock_response("policy_response.json")

    requests_mock.get(
        url=CommonServerPython.urljoin(API_URL, FortiGate.Client.POLICY_ENDPOINT),
        json=response,
    )

    command_results = FortiGate.list_firewall_policies_command(mock_client, args)

    assert len(command_results.outputs) == 0
