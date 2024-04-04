import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any
import traceback


''' STANDALONE FUNCTION '''


def is_port_in_range(port_range: str, port: str) -> bool:
    """
    Breaks a string port range (i.e. '20-25') into integers for comparison
    Args:
        port_range (str): string based port range from the GCP firewall rule.
        port (str): port supplied in script args.

    Returns:
        bool: whether there was a match between the supplied port in args and the supplied range.
    """
    start, end = port_range.split('-')
    return int(start) <= int(port) <= int(end)


def is_there_traffic_match(port: str, protocol: str, rule: dict, network_tags: list) -> bool:
    """
    Determines if there's a match between the supplied port, protocol, and possible target tag combination
    and the GCP firewall rule.
    The function checks:
    if the rule is an ingress rule,
    if the source is from the internet (0.0.0.0/0),
    if the rule is enabled, and if it's an allow rule.
    It also checks if the target tags are relevant (if they show up in keys or tag match), and if the protocol and ports match
    the supplied protocol and port.

    Args:
        port (str): The port supplied in script args.
        protocol (str): The protocol supplied in script args. This should be a string representing a
                        network protocol (e.g., 'tcp', 'udp', 'icmp').
        rule (dict): A dictionary representing a GCP firewall rule. This is pulled from the integration command.
        network_tags (list): A list of network tags. This can be empty.

    Returns:
        bool: True if there's a match between the supplied port, protocol, and possible target tag combination
              and the GCP firewall rule. False otherwise.
    """
    # Match rule needs to be direction ingress, source from internet (0.0.0.0/0), enabled and an allow rule.
    if (
        rule.get('direction') == 'INGRESS'
        and '0.0.0.0/0' in rule.get('sourceRanges', [])
        and rule.get('disabled') is False
        and 'allowed' in rule
    ):
        # Test if targetTags are relevant or not (if show up in keys or tag match)
        target_tags_verdict = ('targetTags' not in rule.keys() or len(set(rule.get('targetTags', [])) & set(network_tags)) > 0)
        for entry in rule['allowed']:
            # Match is all protocol AND either no target tags OR target tags match
            if entry.get('IPProtocol') == 'all' and target_tags_verdict:
                return True
            # Complicated because just {'IPProtocol': 'udp'} means all udp ports
            # therefore if protocol match but no ports, this is a match
            elif entry.get('IPProtocol') == protocol.lower() and 'ports' not in entry:
                return True
            # Else need to go through all ports to see if range or not
            elif entry.get('IPProtocol') == protocol.lower() and 'ports' in entry:
                for port_entry in entry.get('ports', []):
                    if "-" in port_entry:
                        res = is_port_in_range(port_entry, port)
                        if res and target_tags_verdict:
                            return True
                    else:
                        if port == port_entry and target_tags_verdict:
                            return True
    return False


''' COMMAND FUNCTION '''


def gcp_offending_firewall_rule(args: dict[str, Any]) -> CommandResults:
    """
    Determine potential offending firewall rules in GCP based on port, protocol and possibly target tags (network tags).
    Args:
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """

    project_id = args["project_id"]
    network_url = args["network_url"]
    port = args["port"]
    protocol = args["protocol"]
    network_tags = args.get("network_tags", [])

    # Using `demisto.executeCommand` instead of `execute_command` because for
    # multiple integration instances we can expect one too error out.
    network_url_filter = f"network=\"{network_url}\""
    fw_rules = demisto.executeCommand(
        "gcp-compute-list-firewall", {"project_id": project_id, "filters": network_url_filter}
    )
    fw_rules_returned = [
        instance
        for instance in fw_rules
        if (not isError(instance) and instance.get("Contents", {}).get("id"))
    ]
    if not fw_rules_returned:
        return CommandResults(readable_output="Could not find specified firewall info.")
    final_match_list = []
    for rule in fw_rules_returned[0].get('Contents', {}).get('items', []):
        if is_there_traffic_match(port, protocol, rule, network_tags):
            final_match_list.append(rule['name'])
    if not final_match_list:
        return CommandResults(readable_output="Could not find any potential offending firewall rules.")

    return CommandResults(
        outputs={'GCPOffendingFirewallRule': final_match_list},
        raw_response={'GCPOffendingFirewallRule': final_match_list},
        readable_output=f"Potential Offending GCP Firewall Rule(s) Found: {final_match_list}",
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(gcp_offending_firewall_rule(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute GCPOffendingFirewallRule. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
