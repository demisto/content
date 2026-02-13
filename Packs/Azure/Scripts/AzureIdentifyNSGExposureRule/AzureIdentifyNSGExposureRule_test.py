import demistomock as demisto  # noqa: F401
import pytest
import json
from CommonServerPython import DemistoException
import ipaddress


def util_load_json(path):
    with open(path) as f:
        return json.loads(f.read())


def test_get_nsg_rules(mocker):
    """
    Tests that the get_nsg_rules function correctly identifies valid command responses and returns a correctly
    formatted and ordered list of NSG rules.
    """
    from AzureIdentifyNSGExposureRule import get_nsg_rules

    command_response = util_load_json("./test_data/command_response.json")

    mocker.patch.object(demisto, "executeCommand", return_value=command_response)

    sorted_rules_result, instance_to_use_result = get_nsg_rules("fake-subscription-id", "fake-resource-group", "test-nsg", "")

    # Validate that the response contains 5 rules
    assert len(sorted_rules_result) == 5

    # Validate that the correct integration instance's response was identified
    assert instance_to_use_result == "azure-correct-instance"

    # Validate that nsg rule entries are sorted in ascending order by priority
    priorities = [rule["properties"]["priority"] for rule in sorted_rules_result]
    assert priorities == sorted(priorities), f"Rules are not sorted by priority. Found order: {priorities}"


def test_find_available_priorities_success():
    """
    Test find_available_priorities function with valid inputs that should return available priorities.
    """
    from AzureIdentifyNSGExposureRule import find_available_priorities

    nsg_rules = util_load_json("./test_data/sorted_nsg_rules.json")

    # Test finding 2 available priorities before priority 105
    # Available should be 104 and 101 (counting down from 104)
    result = find_available_priorities(105, nsg_rules, 2)

    assert len(result) == 2
    assert 104 in result
    assert 101 in result
    # Ensure none of the existing priorities are returned
    existing_priorities = [102, 103, 105, 107, 117]
    for priority in result:
        assert priority not in existing_priorities


def test_find_available_priorities_single():
    """
    Test find_available_priorities function when requesting a single priority.
    """
    from AzureIdentifyNSGExposureRule import find_available_priorities

    nsg_rules = util_load_json("./test_data/sorted_nsg_rules.json")

    # Test finding 1 available priority before priority 107
    # Available should be 106
    result = find_available_priorities(107, nsg_rules, 1)

    assert len(result) == 1
    assert result[0] == 106


def test_find_available_priorities_insufficient():
    """
    Test find_available_priorities function when there aren't enough available priorities.
    """
    from AzureIdentifyNSGExposureRule import find_available_priorities

    # Create rules that occupy most priorities near 100
    nsg_rules = util_load_json("./test_data/sorted_nsg_rules.json")

    # Try to find 5 available priorities before 105 when there aren't enough
    with pytest.raises(DemistoException) as exc_info:
        find_available_priorities(105, nsg_rules, 5)

    assert "Requested 5 available priority values, but only found" in str(exc_info.value)


def test_find_available_priorities_edge_case_near_limit():
    """
    Test find_available_priorities function near the lower limit of 100.
    """
    from AzureIdentifyNSGExposureRule import find_available_priorities

    nsg_rules = util_load_json("./test_data/sorted_nsg_rules.json")

    # Find available priorities before 103 (should find 101 and 100)
    result = find_available_priorities(103, nsg_rules, 2)

    assert len(result) == 2
    assert 101 in result
    assert 100 in result


def test_process_nsg_info_success(mocker):
    """
    Test process_nsg_info function with valid arguments.
    """
    from AzureIdentifyNSGExposureRule import process_nsg_info

    nsg_rules = util_load_json("./test_data/sorted_nsg_rules.json")

    # Mock the get_nsg_rules function
    mocker.patch("AzureIdentifyNSGExposureRule.get_nsg_rules", return_value=(nsg_rules, "azure-correct-instance"))

    # Mock find_matching_rule function (assuming it exists)
    mocker.patch("AzureIdentifyNSGExposureRule.find_matching_rule", return_value=("AllowSshToAll", 102))

    args = {
        "subscription_id": "fake-subscription-id",
        "resource_group_name": "fake-resource-group",
        "network_security_group_name": "test-nsg",
        "private_ip_addresses": "1.2.3.4",
        "port": "22",
        "protocol": "TCP",
        "priority_count": "2",
        "integration_instance": "",
    }

    result = process_nsg_info(args)

    expected_result = {
        "MatchingRuleName": "AllowSshToAll",
        "MatchingRulePriority": 102,
        "NextAvailablePriorityValues": [101, 100],
        "IntegrationInstance": "azure-correct-instance",
    }

    # Validate CommandResults structure
    assert result.outputs == expected_result


def test_process_nsg_info_multiple_ips(mocker):
    """
    Test process_nsg_info function with multiple IP addresses.
    """
    from AzureIdentifyNSGExposureRule import process_nsg_info

    nsg_rules = util_load_json("./test_data/sorted_nsg_rules.json")

    # Mock the get_nsg_rules function
    mocker.patch("AzureIdentifyNSGExposureRule.get_nsg_rules", return_value=(nsg_rules, "azure-correct-instance"))

    # Mock find_matching_rule function
    mocker.patch("AzureIdentifyNSGExposureRule.find_matching_rule", return_value=("AllowRDPtoJumpBoxes", 103))

    args = {
        "subscription_id": "fake-subscription-id",
        "resource_group_name": "fake-resource-group",
        "network_security_group_name": "test-nsg",
        "private_ip_addresses": ["1.2.3.4", "1.2.3.5"],
        "port": "3389",
        "protocol": "TCP",
        "priority_count": "1",
        "integration_instance": "",
    }

    result = process_nsg_info(args)

    # Should succeed with multiple IPs
    expected_results = {
        "MatchingRuleName": "AllowRDPtoJumpBoxes",
        "MatchingRulePriority": 103,
        "NextAvailablePriorityValues": [101],
        "IntegrationInstance": "azure-correct-instance",
    }

    assert result.outputs == expected_results


def test_process_nsg_info_comma_separated_ips(mocker):
    """
    Test process_nsg_info function with comma-separated IP addresses in a string.
    """
    from AzureIdentifyNSGExposureRule import process_nsg_info

    nsg_rules = util_load_json("./test_data/sorted_nsg_rules.json")

    # Mock the get_nsg_rules function
    mocker.patch("AzureIdentifyNSGExposureRule.get_nsg_rules", return_value=(nsg_rules, "azure-correct-instance"))

    # Mock find_matching_rule function
    mocker.patch("AzureIdentifyNSGExposureRule.find_matching_rule", return_value=("AllowHTTPServices", 105))

    args = {
        "subscription_id": "fake-subscription-id",
        "resource_group_name": "fake-resource-group",
        "network_security_group_name": "test-nsg",
        "private_ip_addresses": "1.2.3.4, 1.2.3.5, 1.2.3.6",
        "port": "80",
        "protocol": "TCP",
        "priority_count": "1",
        "integration_instance": "",
    }

    result = process_nsg_info(args)

    expected_result = {
        "MatchingRuleName": "AllowHTTPServices",
        "MatchingRulePriority": 105,
        "NextAvailablePriorityValues": [104],
        "IntegrationInstance": "azure-correct-instance",
    }

    # Should succeed with comma-separated IPs
    assert result.outputs == expected_result


def test_process_nsg_info_invalid_ips():
    """
    Test process_nsg_info function with invalid IP addresses.
    """
    from AzureIdentifyNSGExposureRule import process_nsg_info

    args = {
        "subscription_id": "fake-subscription-id",
        "resource_group_name": "fake-resource-group",
        "network_security_group_name": "test-nsg",
        "private_ip_addresses": "invalid-ip",
        "port": "22",
        "protocol": "TCP",
        "priority_count": "2",
        "integration_instance": "",
    }

    with pytest.raises(ValueError) as exc_info:
        process_nsg_info(args)

    assert str(exc_info.value) == "Invalid IP address provided: invalid-ip"


def test_process_nsg_info_empty_ips():
    """
    Test process_nsg_info function with empty IP addresses.
    """
    from AzureIdentifyNSGExposureRule import process_nsg_info

    args = {
        "subscription_id": "fake-subscription-id",
        "resource_group_name": "fake-resource-group",
        "network_security_group_name": "test-nsg",
        "private_ip_addresses": "",
        "port": "22",
        "protocol": "TCP",
        "priority_count": "2",
        "integration_instance": "",
    }

    with pytest.raises(ValueError) as exc_info:
        process_nsg_info(args)

    assert "At least one valid IP address must be provided" in str(exc_info.value)


def test_port_matches_range_single_port():
    """
    Test _port_matches_range function with a single port.
    """
    from AzureIdentifyNSGExposureRule import _port_matches_range

    result = _port_matches_range(80, "80")
    assert result is True


def test_port_matches_range_multiple_ports():
    """
    Test _port_matches_range function with a multiple individual ports.
    """
    from AzureIdentifyNSGExposureRule import _port_matches_range

    result = _port_matches_range(80, "80,443")
    assert result is True


def test_port_matches_range_multiple_ports_with_range():
    """
    Test _port_matches_range function with multiple ports and ranges
    """
    from AzureIdentifyNSGExposureRule import _port_matches_range

    result = _port_matches_range(80, "22, 79-81")
    assert result is True


def test_ip_matches_prefix_in_cidr():
    """
    Test _ip_matches_prefix function when the target IP address is within a CIDR prefix
    """
    from AzureIdentifyNSGExposureRule import _ip_matches_prefix

    target_ip_obj = ipaddress.ip_address("10.0.0.5")
    result = _ip_matches_prefix(target_ip_obj, "10.0.0.0/24")
    assert result is True


def test_ip_matches_prefix_not_in_cidr():
    """
    Test _ip_matches_prefix function when the target IP address is not within a CIDR prefix
    """
    from AzureIdentifyNSGExposureRule import _ip_matches_prefix

    target_ip_obj = ipaddress.ip_address("10.0.0.5")
    result = _ip_matches_prefix(target_ip_obj, "10.0.1.0/24")
    assert result is False


def test_ip_matches_prefix_invalid_prefix():
    """
    Test _ip_matches_prefix function when the provided prefix string is invalid
    """
    from AzureIdentifyNSGExposureRule import _ip_matches_prefix

    target_ip_obj = ipaddress.ip_address("10.0.0.5")
    result = _ip_matches_prefix(target_ip_obj, "10.0.0.0/42")
    assert result is False
