import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from typing import Any
import traceback
import ipaddress
import json


def get_nsg_rules(subscription_id: str, rg_name: str, nsg_name: str, integration_instance: str) -> tuple[list, str]:
    """
    Runs command 'azure-nsg-security-rules-list' to fetch all rules in a given Azure NSG.

    Args:
        subscription_id (str): Azure Subscription ID
        rg_name (str): The name of the Azure Resource Group where the NSG is located
        nsg_name (str): The name of the NSG to fetch rules from
        integration_instance (str): The name of the Azure integration instance to use for the command

    Returns:
        tuple[list, str]:
            - List of retrieved NSG Inbound rules, sorted in ascending priority order
            - String with name of the Integration instance that successfully retrieved NSG rules

    Raises:
        DemistoException: If there's an error fetching NSG rules
    """
    cmd_args = {
        "subscription_id": subscription_id,
        "resource_group_name": rg_name,
        "network_security_group_name": nsg_name,
        "using": integration_instance,
    }
    result = demisto.executeCommand("azure-nsg-security-rules-list", cmd_args)

    nsg_rules = []

    if result and len(result) > 1:
        # If multiple entries were returned, such as when multiple Azure integration instances are configured,
        # Identify the first entry with valid results.
        for entry in result:
            if not isError(entry):
                nsg_rules = [entry]
                break
        else:
            # If all entries are errors, use the first entry
            nsg_rules = [result[0]]
    else:
        nsg_rules = result

    if isError(nsg_rules) or not nsg_rules:
        raise DemistoException(
            f"Error retrieving security group details with command 'azure-nsg-security-rules-list'.\n"
            f"Error: {json.dumps(nsg_rules[0]['Contents'])}"
        )

    instance_to_use = dict_safe_get(nsg_rules, (0, "Metadata", "instance"))

    # Get all Inbound rules
    inbound_rules = [
        rule for rule in nsg_rules[0]["Contents"] if rule.get("properties", {}).get("direction", "").lower() == "inbound"
    ]

    # Sort inbound rules by priority (ascending order)
    sorted_rules = sorted(inbound_rules, key=lambda rule: rule.get("properties", {}).get("priority", 0))

    if not sorted_rules:
        raise DemistoException("No inbound NSG rules found in the specified Network Security Group.")

    return sorted_rules, instance_to_use


def find_matching_rule(
    port: int,
    protocol: str,
    destination_ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
    nsg_rules: list[dict],
) -> tuple[str, int]:
    """
    Find the first NSG Allow rule that matches the specified port, protocol, and any of the destination IPs.

    Args:
        port (int): The destination port to match
        protocol (str): The protocol to match (case-insensitive)
        destination_ips (list[IPv4Address | IPv6Address]): The destination IP addresses to match (rule matches if ANY IP matches)
        nsg_rules (list[dict]): List of NSG command results

    Returns:
        tuple[str, int]: (rule_name, rule_priority)

    Raises:
        DemistoException: If no matching NSG inbound rule is found
    """
    # Normalize protocol for case-insensitive comparison
    protocol_normalized = protocol.lower()

    for rule in nsg_rules:
        properties = rule.get("properties", {})

        # Skip rules that don't allow traffic
        if properties.get("access", "").lower() != "allow":
            continue

        # Check protocol match (case-insensitive)
        rule_protocol = properties.get("protocol", "").lower()
        if rule_protocol != "*" and rule_protocol != protocol_normalized:
            continue

        # Check port match
        if not _matches_port(port, properties):
            continue

        # Check if ANY of the destination IPs match
        if not _matches_destination_ip(destination_ips, properties):
            continue

        # Found a matching rule
        return rule.get("name", ""), properties.get("priority", 0)

    # No matching rule found
    raise DemistoException("No matching NSG inbound rule found for the specified IP/Port/Protocol.")


def _matches_port(target_port: int, rule_properties: dict) -> bool:
    """
    Check if the target port matches the rule's destination port configuration.

    Args:
        target_port (int): The port to check
        rule_properties (dict): The rule properties containing port information

    Returns:
        bool: True if the port matches, False otherwise
    """
    # Check single port range field
    single_port_range = rule_properties.get("destinationPortRange", "")
    if single_port_range and _port_matches_range(target_port, single_port_range):
        return True

    # Check multiple port ranges field
    multiple_port_ranges = rule_properties.get("destinationPortRanges", [])
    return any(_port_matches_range(target_port, port_range) for port_range in multiple_port_ranges)


def _port_matches_range(target_port: int, port_range: str) -> bool:
    """
    Check if a port matches a port range specification.

    Args:
        target_port (int): The port to check
        port_range (str): Port range specification (e.g., "80", "80-90", "80,443,8080-8090", "*")

    Returns:
        bool: True if the port matches, False otherwise
    """
    # Handle wildcard
    if port_range.strip() == "*":
        return True

    # Split by commas to handle multiple ports/ranges
    port_specs = [spec.strip() for spec in port_range.split(",")]

    for spec in port_specs:
        if "-" in spec:
            # Handle range (e.g., "8080-8090")
            try:
                start_port_str, end_port_str = spec.split("-", 1)
                start_port = int(start_port_str.strip())
                end_port = int(end_port_str.strip())
                if start_port <= target_port <= end_port:
                    return True
            except (ValueError, IndexError):
                continue
        else:
            # Handle individual port
            try:
                if int(spec) == target_port:
                    return True
            except ValueError:
                continue

    return False


def _matches_destination_ip(target_ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address], rule_properties: dict) -> bool:
    """
    Check if any of the target IPs match the rule's destination address configuration.

    Args:
        target_ips (list[IPv4Address | IPv6Address]): The IP addresses to check (rule matches if ANY IP matches)
        rule_properties (dict): The rule properties containing address information

    Returns:
        bool: True if any IP matches, False otherwise
    """
    # Check single destination address prefix
    single_prefix = rule_properties.get("destinationAddressPrefix", "")
    if single_prefix:
        for target_ip_obj in target_ips:
            if _ip_matches_prefix(target_ip_obj, single_prefix):
                return True

    # Check multiple destination address prefixes
    multiple_prefixes = rule_properties.get("destinationAddressPrefixes", [])
    for prefix in multiple_prefixes:
        for target_ip_obj in target_ips:
            if _ip_matches_prefix(target_ip_obj, prefix):
                return True

    return False


def _ip_matches_prefix(target_ip_obj: Any, address_prefix: str) -> bool:
    """
    Check if an IP address matches an address prefix.

    Args:
        target_ip_obj: ipaddress.IPv4Address or ipaddress.IPv6Address object
        address_prefix (str): Address prefix (e.g., "10.0.0.0/24", "192.168.1.100", "*")

    Returns:
        bool: True if the IP matches, False otherwise
    """
    if not address_prefix or address_prefix.strip() == "":
        return False

    address_prefix = address_prefix.strip()

    # Handle wildcard
    if address_prefix == "*":
        return True

    try:
        # Try to parse as network (CIDR notation)
        if "/" in address_prefix:
            network = ipaddress.ip_network(address_prefix, strict=False)
            return target_ip_obj in network
        else:
            # Try to parse as individual IP address
            prefix_ip = ipaddress.ip_address(address_prefix)
            return target_ip_obj == prefix_ip
    except ValueError:
        return False


def find_available_priorities(target_rule_priority: int, nsg_rules: list, priority_count: int) -> list[int]:
    """
    Identifies unused NSG rule priority values below the target priority that can be used to insert new
    rules above it.

    Args:
        target_rule_priority (int): The priority of the rule you want to find available priorities before.
        nsg_rules (list[dict]): List of NSG command results
        priority_count (int):  Number of priorities needed

    Raises:
        DemistoException: if the requested number of available priorities are not found.

    Returns:
        list[int]: List of available priorities before the target rule priority
    """
    rule_priorities = []

    # Store all used priority values
    for rule in nsg_rules:
        rule_priorities.append(int(rule.get("properties").get("priority", 0)))

    # Format values as a set for easier evaluation
    rule_priorities_set = set(rule_priorities)

    available_priorities = []

    # Find available priorities counting down from target_rule_priority - 1
    # Only goes down to 100, as this is the lowest value supported by Azure NSG rules
    for priority in range(target_rule_priority - 1, 99, -1):  # Count down from target-1 to 100
        if priority not in rule_priorities_set:
            available_priorities.append(priority)
            # Stop once we have found the requested number of priorities
            if len(available_priorities) >= priority_count:
                break

    # Raise error if requested priority count exceeds the number available
    if len(available_priorities) < priority_count:
        raise DemistoException(
            f"Requested {priority_count} available priority values, but only found {len(available_priorities)} "
            f"below the matching rule's priority of {target_rule_priority}."
        )

    return available_priorities


def process_nsg_info(args: dict[str, Any]) -> CommandResults:
    """
    Main command function to identify NSG rule causing an exposure.

    Args:
        args (Dict[str, Any]): Demisto.args() object

    Returns:
        CommandResults: Demisto CommandResults object containing:
            - MatchingRuleName: Name of the matching NSG rule
            - MatchingRulePriority: Priority of the matching rule
            - NextAvailablePriorityValues: List of available priorities
            - IntegrationInstance: Azure integration instance used

    Raises:
        ValueError: If required parameters are missing or invalid
        DemistoException: If Azure API operations fail
    """
    subscription_id = args.get("subscription_id", "")
    rg_name = args.get("resource_group_name", "")
    nsg_name = args.get("network_security_group_name", "")
    destination_ip_input = args.get("private_ip_addresses", "")
    port = int(args.get("port", ""))
    protocol = args.get("protocol", "")
    priority_count = arg_to_number(args.get("priority_count"), required=True) or 0
    integration_instance = args.get("integration_instance", "")

    # Format provided IP addresses as a list. Handle both single IP and list of IPs
    destination_ips = []
    if isinstance(destination_ip_input, list):
        destination_ips = destination_ip_input
    elif isinstance(destination_ip_input, str):
        # Handle comma-separated IPs in a single string or single IP
        destination_ips = [ip.strip() for ip in destination_ip_input.split(",") if ip.strip()]

    if not destination_ips:
        raise ValueError("At least one valid IP address must be provided in private_ip_address parameter")

    # Validate that all provided IPs are valid IP addresses and create IP Address objects
    valid_ips = []
    for ip in destination_ips:
        try:
            valid_ips.append(ipaddress.ip_address(ip))
        except ValueError:
            raise ValueError(f"Invalid IP address provided: {ip}")

    if not valid_ips:
        raise ValueError("No valid IP addresses found in private_ip_address parameter")

    # Retrieve NSG rules and identify the Azure integration instance to use
    nsg_rules, instance_to_use = get_nsg_rules(subscription_id, rg_name, nsg_name, integration_instance)

    # Find the name and priority value of the first Allow rule that matches the provided criteria
    matching_rule_name, priority = find_matching_rule(port, protocol, valid_ips, nsg_rules)

    # Identify available priority values to insert new rules ahead of the matched rule
    available_priorities = find_available_priorities(priority, nsg_rules, priority_count)

    return CommandResults(
        outputs_prefix="AzurePublicExposure",
        outputs_key_field="MatchingRuleName",
        outputs={
            "MatchingRuleName": matching_rule_name,
            "MatchingRulePriority": priority,
            "NextAvailablePriorityValues": available_priorities,
            "IntegrationInstance": instance_to_use,
        },
    )


def main():
    try:
        return_results(process_nsg_info(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute AzureIdentifyNSGExposureRule. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
