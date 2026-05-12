import demistomock as demisto
from CommonServerPython import *


def check_rule_ha_info(rule: dict, peer_hostid: str, ha_state_data: list[dict]) -> str:
    # If this rule comes from a device in an HA pair, identify which device is active
    this_rules_device_state = next((h["status"] for h in ha_state_data if h["hostid"] == rule["hostid"]), None)
    active_ha_peer = rule["hostid"] if this_rules_device_state == "active" else peer_hostid

    return active_ha_peer


def get_local_rules(rule_hitcount_data: list[dict], ha_state_data: list[dict], system_info: list[dict]) -> tuple[int, list[dict]]:
    """
    Extracts unused local firewall rules from the given rule hit count data.  Rules that are unused on a device that is
    in an HA pair which does have hits for the same rule are not returned, as this indicates the rule is actually
    used.  Hitcount data is not synchronized between HA peers.

    Args:
        rule_hitcount_data (List[Dict]): The rule hit count data. Must include both used and unused rules.
        ha_state_data (List[Dict]): The high availability state data for all firewalls for which rules are being
        analyzed.
        system_info (List[Dict]): The system information for all firewalls for which rules are being analyzed.

    Returns:
        Tuple[int, List[Dict]]: A tuple containing:
            - The total number of local rules analyzed.
            - A list of local firewall rules with zero hits, formatted as summaries,
              excluding rules where the HA peer has hits.
    """
    # Create a mapping of each hostid to its HA peer hostid
    ha_peer_map = {item["hostid"]: item["peer"] for item in ha_state_data}

    # Get local rules only, ignoring any pushed from Panorama
    local_rules = [rule for rule in rule_hitcount_data if not rule.get("is_from_panorama")]

    # Count the total number of local rules analyzed, excluding rule data from standby HA peers so the rule is counted
    # only once per pair
    total_local_rules = 0
    for rule in local_rules:
        peer_hostid = None
        active_ha_peer = None

        # Get the HA peer's hostid
        peer_hostid = ha_peer_map.get(rule["hostid"], None)
        if peer_hostid:
            active_ha_peer = check_rule_ha_info(rule, peer_hostid, ha_state_data)

            # If this rule comes from an HA pair and this device isn't active, don't count it
            if rule["hostid"] != active_ha_peer:
                continue

        total_local_rules = total_local_rules + 1

    # Get local rule entries with a hit count of 0
    unused_local_rules = [rule for rule in local_rules if rule["hit_count"] == 0]

    # Create a mapping of each hostid to its hostname
    hostid_name_map = {item["hostid"]: item["hostname"] for item in system_info}

    summaries = []
    for rule in unused_local_rules:
        # Initialize variables at the start of each iteration
        peer_hostid = None
        active_ha_peer = None

        # Get the HA peer's hostid
        peer_hostid = ha_peer_map.get(rule["hostid"], None)
        if peer_hostid:
            active_ha_peer = check_rule_ha_info(rule, peer_hostid, ha_state_data)

            # Get hitcount data for this rule on the HA peer
            peer_rule = next((r for r in local_rules if r["hostid"] == peer_hostid and r["name"] == rule["name"]), None)

            # Skip this rule if it has zero hits but the same rule on the peer does have hits
            if peer_rule and peer_rule["hit_count"] > 0 and rule["hostid"] != active_ha_peer:
                continue

            # If this rule has zero hits on both devices in the HA pair, skip this rule if it's not from the active device
            elif peer_rule and peer_rule["hit_count"] == 0 and rule["hit_count"] == 0 and rule["hostid"] != active_ha_peer:
                continue

        # Create a summary of the unused rule
        summary = {
            "name": rule["name"],
            "instanceName": rule["instanceName"],
            "position": rule["position"],
            "rulebase": rule["rulebase"],
            "hostid": rule["hostid"],
            "hostname": hostid_name_map.get(rule["hostid"]),
            "vsys": rule["vsys"],
            "activeHAPeer": active_ha_peer,
        }

        summaries.append(summary)

    return total_local_rules, summaries


def analyze_panorama_rules(
    rule_hitcount_data: list[dict], ha_state_data: list[dict], system_info: list[dict]
) -> tuple[int, list[dict], list[dict]]:
    """
    Analyzes the Panorama firewall rules and returns a summary of rules that are unused on all devices
    as well as rules that are used on some firewalls but not all.  Rules with zero hits on devices whose HA peer
    does have hits will exclude the hostid of the peer without hits.

    Args:
        rule_hitcount_data (List[Dict]): The rule hit count data.  Must include both used and unused rules.
        ha_state_data (List[Dict]): Data about the high availability (HA) state of the devices.
        system_info (List[Dict]): The system information for all firewalls for which rules are being analyzed.

    Returns:
        Tuple[int, List[Dict], List[Dict]]: A tuple containing:
            - The total number of Panorama rules analyzed
            - A list of Panorama firewall rules that have zero hits across all host IDs.
            - A list of Panorama firewall rules that have hits on at least some host IDs.
    """
    unused_panorama_rules = []
    used_panorama_rules = []

    # Create a mapping of hostid to peer hostid
    ha_peer_map = {item["hostid"]: item["peer"] for item in ha_state_data}

    # Create a mapping of each hostid to its hostname
    hostid_name_map = {item["hostid"]: item["hostname"] for item in system_info}

    # Get rules pushed from Panorama
    panorama_rules = [rule for rule in rule_hitcount_data if rule.get("is_from_panorama")]

    # Count the number of unique Panorama rules analyzed
    unique_entries = set()
    for rule in panorama_rules:
        unique_tuple = (
            rule["from_dg_name"],
            rule["instanceName"],
            rule["is_from_panorama"],
            rule["name"],
            rule["position"],
            rule["rulebase"],
        )
        unique_entries.add(unique_tuple)

    total_panorama_rules = len(unique_entries)

    # Group Panorama rules by name
    rules_by_name: dict[str, list[dict]] = {}
    for rule in panorama_rules:
        rules_by_name.setdefault(rule["name"], []).append(rule)

    for rule_name, rules in rules_by_name.items():
        # Identify rules that have no hits on any device we have data for
        all_zero = all(rule["hit_count"] == 0 for rule in rules)
        if all_zero:
            unused_rule = {
                "name": rule_name,
                "instanceName": rules[0]["instanceName"],
                "position": rules[0]["position"],
                "rulebase": rules[0]["rulebase"],
                "from_dg_name": rules[0]["from_dg_name"],
            }
            unused_panorama_rules.append(unused_rule)

        elif any(rule["hit_count"] > 0 for rule in rules if rule["name"] == rule_name):
            # Create a summary for rules used on at least some hostids
            summary = {
                "name": rule_name,
                "instanceName": rules[0]["instanceName"],
                "position": rules[0]["position"],
                "rulebase": rules[0]["rulebase"],
                "from_dg_name": rules[0]["from_dg_name"],
                "hostids_with_zero_hits": [rule["hostid"] for rule in rules if rule["hit_count"] == 0],
                "hostnames_with_zero_hits": [hostid_name_map.get(rule["hostid"]) for rule in rules if rule["hit_count"] == 0],
                "hostids_with_hits": [rule["hostid"] for rule in rules if rule["hit_count"] > 0],
                "hostnames_with_hits": [hostid_name_map.get(rule["hostid"]) for rule in rules if rule["hit_count"] > 0],
            }

            # Identify rules with zero hits on devices where the device is an HA Peer of a device with hits
            # and do not include them in the output, as it is normal for a standby HA Peer to have no hits.
            for hostid in summary["hostids_with_hits"]:
                if hostid in ha_peer_map and ha_peer_map[hostid] in summary["hostids_with_zero_hits"]:
                    summary["hostids_with_zero_hits"].remove(ha_peer_map[hostid])
                    summary["hostnames_with_zero_hits"].remove(hostid_name_map.get(ha_peer_map[hostid]))

            # Do not include rules that have no hosts with zero hits after accounting for HA pairs, as this indicates
            # that the rule is used on all devices and not a target for clean-up.
            if len(summary["hostids_with_zero_hits"]) == 0:
                continue

            used_panorama_rules.append(summary)

    return total_panorama_rules, unused_panorama_rules, used_panorama_rules


def main():
    try:
        context = demisto.context()
        rule_hitcount_data = context.get("PANOS", {}).get("RuleHitCount", [])
        ha_state_data = context.get("PANOS", {}).get("HAState", [])
        system_info = context.get("PANOS", {}).get("ShowSystemInfo", {})

        # Format System Info as a single list of individual device entries if multiple Result entries are present
        # from separate Integration instances
        if isinstance(system_info, list):
            system_info = [item.get("Result", []) for item in system_info]
            system_info = [item for sublist in system_info for item in sublist]
        else:
            system_info = system_info.get("Result", [])

        # Ensure data lists are properly formatted
        rule_hitcount_data = rule_hitcount_data if isinstance(rule_hitcount_data, list) else [rule_hitcount_data]
        ha_state_data = ha_state_data if isinstance(ha_state_data, list) else [ha_state_data]
        system_info = system_info if isinstance(system_info, list) else [system_info]

        # Check that all necessary data is present
        missing_data = [
            data
            for data, value in [("RuleHitCount", rule_hitcount_data), ("HAState", ha_state_data), ("ShowSystemInfo", system_info)]
            if not value
        ]

        if missing_data:
            necessary_commands = {
                "RuleHitCount": "pan-os-get-rule-hitcounts",
                "HAState": "pan-os-platform-get-ha-state",
                "ShowSystemInfo": "pan-os-platform-get-system-info",
            }

            # Create detailed error messages for each missing data type
            error_messages = []
            for data_type in missing_data:
                command = necessary_commands.get(data_type, "the necessary")
                error_messages.append(f"Missing data: {data_type}. Please run the '{command}' command to populate this data.")

            raise Exception("\n".join(error_messages))

        # Analyze rule hitcounts for Panorama pushed rules
        total_panorama_rules, panorama_unused_rules, panorama_used_rules = analyze_panorama_rules(
            rule_hitcount_data, ha_state_data, system_info
        )

        # Analyze rule hitcounts for local rules
        total_local_rules, local_unused_rules = get_local_rules(rule_hitcount_data, ha_state_data, system_info)

        results = CommandResults(
            outputs_prefix="PANOS.UnusedRules",
            outputs={
                "TotalLocalRulesAnalyzed": total_local_rules,
                "TotalPanoramaRulesAnalyzed": total_panorama_rules,
                "UnusedPanoramaRules": panorama_unused_rules,
                "UsedPanoramaRules": panorama_used_rules,
                "UnusedLocalRules": local_unused_rules,
                "ignore_auto_extract": True,
            },
        )

        return_results(results)

    except Exception as ex:
        return_error(f"Failed to execute PAN-OS-AnalyzeRuleHitCounts. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
