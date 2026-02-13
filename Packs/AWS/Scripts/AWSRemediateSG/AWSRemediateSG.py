import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from typing import Any
import copy
import traceback
from random import randint
import re

PRIVATE_CIDRS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
MAX_TAGS = 50


def parse_tag_field(tags_string: str | None):
    """
    Parses a list representation of key and value with the form of 'key=<name>,value=<value>.
    You can specify up to 50 tags per resource.
    Args:
        tags_string: The name and value list
    Returns:
        A list of dicts with the form {"key": <key>, "value": <value>}
    """
    tags = []
    list_tags = argToList(tags_string, separator=";")
    if len(list_tags) > MAX_TAGS:
        list_tags = list_tags[0:50]
        demisto.debug("Number of tags is larger then 50, parsing only first 50 tags.")
    # According to the AWS Tag restrictions docs.
    regex = re.compile(r"^key=([a-zA-Z0-9\s+\-=._:/@]{1,128}),value=(.{0,256})$", flags=re.UNICODE)
    for tag in list_tags:
        match_tag = regex.match(tag)
        if match_tag is None:
            raise ValueError(
                f"Could not parse given tag data: {tag}."
                "Please make sure you provided like so: key=abc,value=123;key=fed,value=456"
            )
        tags.append({"Key": match_tag.group(1), "Value": match_tag.group(2)})

    return tags


def split_rule(rule: dict, port: int, protocol: str) -> list[dict]:
    """
    Split a security group rule to exclude a specific port while preserving other port ranges.

    For rules with port ranges, this function creates new rules that exclude the specified port.
    If the port is at the beginning or end of a range, the original rule is modified.
    If the port is in the middle, two new rules are created to cover the ranges before and after.
    For "all traffic" rules (no FromPort), creates specific TCP/UDP rules excluding the target port.

    Args:
        rule (dict): Security group rule dictionary from AWS EC2 API response
        port (int): TCP/UDP port number to be excluded from the rule
        protocol (str): Protocol of the port to be restricted ("tcp" or "udp")

    Returns:
        list[dict]: List of replacement security group rules with the specified port excluded
    """
    res_list = []

    rule = copy.deepcopy(rule)
    # Check if 'FromPort' is in rule, else it is an "all traffic rule".
    if "FromPort" in rule:
        # Port of interest is in front or back of range, therefore, edit the rule without the given port.
        if rule["FromPort"] == port:
            rule["FromPort"] = port + 1
            res_list.append(rule)
        elif rule["ToPort"] == port:
            rule["ToPort"] = port - 1
            res_list.append(rule)
        # If in the middle, create two rules.
        else:
            rule_copy = copy.deepcopy(rule)
            rule["ToPort"] = port - 1
            res_list.append(rule)
            rule_copy["FromPort"] = port + 1
            res_list.append(rule_copy)
    else:
        # Splitting up "all traffic" rules.  Creates rules for the target protocol that exclude
        # the specified port, plus a rule allowing all ports on the opposite protocol.
        opposite = "udp" if protocol == "tcp" else "tcp"
        description = (
            f"Allow rule created by Cortex remediation from All Traffic rule " f"omitting {protocol.upper()} port {port}."
        )
        ip_ranges = [{"CidrIp": "0.0.0.0/0", "Description": description}]
        base_fields: dict = {"Ipv6Ranges": [], "PrefixListIds": [], "UserIdGroupPairs": []}

        # Target protocol: all ports below the excluded port
        res_list.append({**base_fields, "IpProtocol": protocol, "IpRanges": ip_ranges, "FromPort": 0, "ToPort": port - 1})
        # Target protocol: all ports above the excluded port
        res_list.append({**base_fields, "IpProtocol": protocol, "IpRanges": ip_ranges, "FromPort": port + 1, "ToPort": 65535})
        # Opposite protocol: all ports
        res_list.append({**base_fields, "IpProtocol": opposite, "IpRanges": ip_ranges, "FromPort": 0, "ToPort": 65535})
    return res_list


def sg_fix(
    account_id: str,
    sg_info: list,
    port: int,
    protocol: str,
    integration_instance: str,
    region: str,
    tags: list[dict] | None = None,
) -> dict:
    """
    Analyze a security group and create a remediated version that removes overly permissive rules.

    This function examines all ingress rules in a security group, identifies rules that expose
    the specified port to 0.0.0.0/0, and creates a new security group with those rules modified
    or removed. Private IP ranges (RFC 1918) are automatically allowed for the restricted port.

    Args:
        account_id (str): AWS account ID where the security group exists
        sg_info (list): Response from aws-ec2-security-groups-describe command containing SG details
        port (int): TCP/UDP port number to restrict from public access
        protocol (str): Protocol of the port to be restricted ("tcp" or "udp")
        integration_instance (str): AWS integration instance name to use for API calls
        region (str): AWS EC2 region where the security group is located
        tags (list[dict] | None): Optional list of tag dicts ({"Key": ..., "Value": ...}) to merge
            with the old security group's tags when creating the new security group.

    Returns:
        dict: Dictionary containing the new security group ID under 'new-sg' key,
              or empty dict if no changes were needed

    Raises:
        DemistoException: If security group creation or rule modification fails
    """
    info = dict_safe_get(sg_info, (0, "Contents", "SecurityGroups", 0))
    recreate_list: list[dict] = []
    # Keep track of change in SG or not.
    change = False
    for rule in info["IpPermissions"]:
        if rule.get("IpRanges"):
            # Check if 'FromPort' is in rule, else it is an "all traffic rule".
            if "FromPort" in rule:
                # Don't add to recreate list if it targets just the port of interest.
                if (
                    rule["FromPort"] == port
                    and port == rule["ToPort"]
                    and any(d["CidrIp"] == "0.0.0.0/0" for d in rule["IpRanges"])
                    and rule["IpProtocol"] == protocol
                ):
                    change = True
                # Identify if specified port is within a broader range on the rule - split it into separate
                # rules, omitting the given port
                elif (
                    rule["FromPort"] <= port
                    and port <= rule["ToPort"]
                    and any(d["CidrIp"] == "0.0.0.0/0" for d in rule["IpRanges"])
                    and rule["IpProtocol"] == protocol
                ):  # noqa: E127
                    recreate_list.extend(split_rule(rule, port, protocol))
                    change = True
                # If rule doesn't need to be modified, include in list for new SG as-is
                else:
                    recreate_list.append(rule)
            # If rule is an "all traffic" rule, create separate rules allowing all ports EXCEPT the specified one.
            elif any(d["CidrIp"] == "0.0.0.0/0" for d in rule["IpRanges"]):
                recreate_list.extend(split_rule(rule, port, protocol))
                change = True
            else:
                recreate_list.append(rule)

    if change is False:
        return {}
    else:
        # Add rules that allow private IPs (RFC 1918) to the specific port.
        for cidr in PRIVATE_CIDRS:
            recreate_list.append(
                {
                    "IpProtocol": protocol,
                    "IpRanges": [
                        {
                            "CidrIp": cidr,
                            "Description": "Internal access rule automatically created by Cortex remediation.",
                        }
                    ],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "UserIdGroupPairs": [],
                    "FromPort": port,
                    "ToPort": port,
                }
            )

        # Create the empty Security Group
        # Check if the name already contains the cortex remediation suffix
        if "_cortex_remediation_" in info["GroupName"]:
            # Replace the random number
            base_name = info["GroupName"].rsplit("_cortex_remediation_", 1)[0]
            new_name = base_name + "_cortex_remediation_" + str(randint(1000, 9999))
        else:
            new_name = info["GroupName"] + "_cortex_remediation_" + str(randint(1000, 9999))
        description = "Copied from Security Group " + info["GroupName"] + " by Cortex."
        create_group_cmd_args = {
            "account_id": account_id,
            "group_name": new_name,
            "vpc_id": info["VpcId"],
            "description": description,
            "region": region,
            "using": integration_instance,
        }

        new_sg = demisto.executeCommand("aws-ec2-security-group-create", create_group_cmd_args)

        if isError(new_sg):
            raise DemistoException(
                f"Error on creating new security group with command 'aws-ec2-security-group-create'.\n"
                f"Error: {json.dumps(new_sg[0]['Contents'])}"
            )

        new_id = dict_safe_get(new_sg, (0, "Contents", "GroupId"))

        # Apply old SG's tags to new SG, merged with any tags provided via the script argument.
        # Script-provided tags take precedence over old SG tags when keys conflict.
        tags_data = info.get("Tags", []) or []
        if tags:
            # Build a dict keyed by tag Key from old SG tags, then overlay script-provided tags.
            merged: dict[str, str] = {tag["Key"]: tag["Value"] for tag in tags_data}
            for tag in tags:
                merged[tag["Key"]] = tag["Value"]
            tags_data = [{"Key": k, "Value": v} for k, v in merged.items()]
        if tags_data:
            formatted_tags = ";".join([f"key={tag['Key']},value={tag['Value']}" for tag in tags_data])
            create_tags_cmd_args = {
                "account_id": account_id,
                "region": region,
                "resources": new_id,
                "tags": formatted_tags,
                "using": integration_instance,
            }

            create_tags_result = demisto.executeCommand("aws-ec2-tags-create", create_tags_cmd_args)

            if isError(create_tags_result):
                raise DemistoException(
                    f"Error on creating tags for new security group with command 'aws-ec2-tags-create'.\n"
                    f"Error: {json.dumps(create_tags_result[0]['Contents'])}"
                )

    if recreate_list:
        create_ingress_rule_cmd_args = {
            "account_id": account_id,
            "group_id": new_id,
            "ip_permissions": json.dumps(recreate_list),
            "region": region,
            "using": integration_instance,
        }
        new_ingress_rule_res = demisto.executeCommand("aws-ec2-security-group-ingress-authorize", create_ingress_rule_cmd_args)

        if isError(new_ingress_rule_res):
            if "already exists" in new_ingress_rule_res[0]["Contents"]:
                pass
            else:
                raise DemistoException(
                    f"Error on adding security group ingress rules to new security group with command "
                    f"'aws-ec2-security-group-ingress-authorize'.\nError: {json.dumps(new_ingress_rule_res[0]['Contents'])}"
                )

    # AWS auto-creates a default all-traffic egress rule (IpProtocol "-1", 0.0.0.0/0) on every new SG.
    # We need to match the original SG's egress configuration:
    #   1. Original has NO egress rules at all → revoke the AWS default.
    #   2. Original has ONLY the default all-traffic rule (IPv4 only) → keep the AWS default (do nothing).
    #   3. Original has the default all-traffic rule PLUS other rules/ranges → add only the non-default
    #      parts; keep the AWS default (don't revoke it, since the original had it too).
    #   4. Original has egress rules but NO default all-traffic rule → add its rules, revoke the default.
    #
    # Note: AWS may combine multiple CIDRs/ranges with the same IpProtocol into a single IpPermissions
    # entry. An all-traffic entry may also contain Ipv6Ranges (e.g., ::/0), additional IpRanges,
    # PrefixListIds, or UserIdGroupPairs that must be preserved even when stripping the default
    # 0.0.0.0/0 CIDR.
    original_egress = info.get("IpPermissionsEgress", [])
    original_has_all_traffic = any(
        egress["IpProtocol"] == "-1" and any(r.get("CidrIp") == "0.0.0.0/0" for r in egress.get("IpRanges", []))
        for egress in original_egress
    )

    # Collect egress rules to add to the new SG, stripping out the default 0.0.0.0/0 IPv4 CIDR
    # from any all-traffic entries (since AWS auto-creates it on the new SG). If the entry has
    # other IpRanges, Ipv6Ranges, PrefixListIds, or UserIdGroupPairs, preserve those in a
    # modified copy.
    egress_rules: list[dict] = []
    for egress in original_egress:
        is_all_traffic_with_default = egress["IpProtocol"] == "-1" and any(
            r.get("CidrIp") == "0.0.0.0/0" for r in egress.get("IpRanges", [])
        )
        if is_all_traffic_with_default:
            # Strip the default 0.0.0.0/0 CIDR; check if anything else remains in this entry.
            other_ip_ranges = [r for r in egress.get("IpRanges", []) if r.get("CidrIp") != "0.0.0.0/0"]
            has_ipv6 = bool(egress.get("Ipv6Ranges"))
            has_prefix_lists = bool(egress.get("PrefixListIds"))
            has_user_groups = bool(egress.get("UserIdGroupPairs"))

            if other_ip_ranges or has_ipv6 or has_prefix_lists or has_user_groups:
                # Entry has additional ranges/groups beyond the default — preserve them.
                modified_egress = copy.deepcopy(egress)
                modified_egress["IpRanges"] = other_ip_ranges
                egress_rules.append(modified_egress)
            # Otherwise, entry was purely the default 0.0.0.0/0 — skip it (AWS auto-creates it).
        else:
            egress_rules.append(egress)

    if egress_rules:
        create_egress_rule_cmd_args = {
            "account_id": account_id,
            "group_id": new_id,
            "ip_permissions": json.dumps(egress_rules),
            "region": region,
            "using": integration_instance,
        }
        new_egress_rule_res = demisto.executeCommand("aws-ec2-security-group-egress-authorize", create_egress_rule_cmd_args)
        # Don't error if the message is that the rule already exists.
        if isError(new_egress_rule_res):
            if "already exists" in new_egress_rule_res[0]["Contents"]:
                pass
            else:
                raise DemistoException(
                    f"Error on adding security group egress rules to new security group with command "
                    f"'aws-ec2-security-group-egress-authorize'.\nError: {json.dumps(new_egress_rule_res[0]['Contents'])}"
                )

    # Revoke the AWS auto-created default all-traffic egress rule if the original SG did not have one.
    # Cases where we revoke: no egress rules at all (case 1), or specific rules without all-traffic (case 4).
    # Cases where we keep it: original had only the default (case 2), or had it alongside others (case 3).
    if not original_has_all_traffic:
        all_traffic_rule = json.dumps(
            [
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "UserIdGroupPairs": [],
                }
            ]
        )
        revoke_egress_rule_cmd_args = {
            "account_id": account_id,
            "group_id": new_id,
            "ip_permissions": all_traffic_rule,
            "region": region,
            "using": integration_instance,
        }
        removed_egress_rule_res = demisto.executeCommand("aws-ec2-security-group-egress-revoke", revoke_egress_rule_cmd_args)
        if isError(removed_egress_rule_res):
            raise DemistoException(
                f"Error on removing default egress `allow all` rule on new security group with command "
                f"'aws-ec2-security-group-egress-revoke'.\nError: {json.dumps(removed_egress_rule_res)}"
            )
    return {"new-sg": new_id}


def fix_excessive_access(
    account_id: str,
    sg_list: list,
    port: int,
    protocol: str,
    integration_instance: str,
    region: str,
    cached_sg_data: dict | None = None,
    tags: list[dict] | None = None,
) -> list[dict]:
    """
    Process multiple security groups to remediate excessive public access to a specific port.

    This function iterates through a list of security group IDs, retrieves their current
    configuration, and creates remediated versions that remove public access to the specified
    port while preserving access from private IP ranges.

    Args:
        account_id (str): AWS account ID where the security groups exist
        sg_list (list): List of security group IDs to remediate
        port (int): TCP/UDP port number to restrict from public access
        protocol (str): Protocol of the port to be restricted ("tcp" or "udp")
        integration_instance (str): AWS integration instance name to use for API calls
        region (str): AWS EC2 region where the security groups are located
        cached_sg_data (dict | None): Optional pre-fetched SG data keyed by SG ID, used to
            avoid redundant describe calls when data was already retrieved during instance
            identification.
        tags (list[dict] | None): Optional list of tag dicts ({"Key": ..., "Value": ...}) to merge
            with each old security group's tags when creating new security groups.

    Returns:
        list[dict]: List of dictionaries containing mapping between old and new security groups.
                   Each dict contains 'old-sg' and 'new-sg' keys with respective security group IDs.

    Raises:
        DemistoException: If security group description or remediation fails
    """
    replace_list = []
    for sg in sg_list:
        # Use cached data if available for this SG, otherwise fetch it.
        if cached_sg_data and sg in cached_sg_data:
            sg_info = cached_sg_data[sg]
        else:
            cmd_args = {"group_ids": sg, "using": integration_instance, "account_id": account_id, "region": region}
            sg_info = demisto.executeCommand("aws-ec2-security-groups-describe", cmd_args)
            if isError(sg_info):
                raise DemistoException(
                    f"Error on describing security group with command 'aws-ec2-security-groups-describe'.\n"
                    f"Error: {json.dumps(sg_info[0]['Contents'])}"
                )
        if sg_info:
            res = sg_fix(account_id, sg_info, port, protocol, integration_instance, region, tags)
            # Need interface, old sg and new sg.
            if res.get("new-sg"):
                res["old-sg"] = sg
                replace_list.append(res)
    return replace_list


def identify_integration_instance(account_id: str, sg: str, region: str) -> tuple[str, list]:
    """
    Runs command 'aws-ec2-security-groups-describe' to identify the AWS integration instance that can be used.

    Also returns the SG data that was fetched during identification, so callers can reuse it
    without making a redundant describe call.

    Args:
        account_id (str): AWS Account ID
        sg (str): The ID of a single Security Group to check
        region (str): AWS Region where the Security Group is located

    Returns:
        tuple[str, list]: A tuple of (instance_name, sg_info) where instance_name is the AWS
            integration instance name and sg_info is the describe response data for the SG.

    Raises:
        DemistoException: If there's an error describing the security group
    """
    cmd_args = {"group_ids": sg, "account_id": account_id, "region": region}
    result = demisto.executeCommand("aws-ec2-security-groups-describe", cmd_args)

    sg_info = []

    if result and len(result) > 1:
        # If multiple entries were returned, such as when multiple AWS integration instances are configured,
        # Identify the first entry with valid results.
        for entry in result:
            if not isError(entry):
                sg_info = [entry]
                break
        else:
            # If all entries are errors, use the first entry
            sg_info = [result[0]]
    else:
        sg_info = result

    if not sg_info:
        raise DemistoException(
            "Error retrieving security group details with command 'aws-ec2-security-groups-describe'.\n"
            "Error: No results returned."
        )
    if isError(sg_info):
        raise DemistoException(
            f"Error retrieving security group details with command 'aws-ec2-security-groups-describe'.\n"
            f"Error: {json.dumps(sg_info[0]['Contents'])}"
        )

    instance_to_use = dict_safe_get(sg_info, (0, "Metadata", "instance"))
    return instance_to_use, sg_info


def aws_recreate_sg(args: dict[str, Any]) -> CommandResults:
    """
    Main command function to remediate overly permissive security group rules.

    This function creates new security groups that are copies of existing ones but with
    public access removed for sensitive ports. The new security groups maintain access
    from private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) for the specified port.
    Over-permissive is defined as allowing access from 0.0.0.0/0 (internet) to sensitive ports.

    Args:
        args (Dict[str, Any]): Demisto.args() object

    Returns:
        CommandResults: Demisto CommandResults object containing:
            - ResourceID: The resource identifier that was remediated
            - ReplacementSet: List of old-to-new security group mappings
            - UpdatedSGList: Complete list of security groups with replacements applied

    Raises:
        ValueError: If required parameters are missing
        DemistoException: If AWS API operations fail during remediation
    """
    account_id = args.get("account_id", "")
    resource_id = args.get("resource_id", "")
    sg_list = [sg.strip() for sg in args.get("sg_list", "").split(",") if sg.strip()]
    port = int(args.get("port", 0))
    protocol = args.get("protocol", "")
    region = args.get("region", "")
    integration_instance = args.get("integration_instance", "")
    tags = parse_tag_field(args.get("tags"))

    if not account_id or not sg_list or not port or not protocol:
        raise ValueError("account_id, sg_list, instance_id, port, and protocol all need to be specified")

    cached_sg_data: dict | None = None
    if not integration_instance:
        integration_instance, first_sg_info = identify_integration_instance(account_id, sg_list[0], region)
        # Cache the SG data already fetched during instance identification to avoid a redundant API call.
        cached_sg_data = {sg_list[0]: first_sg_info}

    replace_list = fix_excessive_access(account_id, sg_list, port, protocol, integration_instance, region, cached_sg_data, tags)

    if replace_list:
        # Create updated_sg_list with old SGs replaced by new ones
        updated_sg_list = sg_list.copy()
        for replacement in replace_list:
            old_sg = replacement.get("old-sg")
            new_sg = replacement.get("new-sg")
            if old_sg and new_sg and old_sg in updated_sg_list:
                # Replace the old SG with the new SG in the list
                index = updated_sg_list.index(old_sg)
                updated_sg_list[index] = new_sg

        return CommandResults(
            outputs_prefix="AWSPublicExposure.SGReplacements",
            outputs_key_field="ResourceID",
            outputs={
                "ResourceID": resource_id,
                "ReplacementSet": replace_list,
                "UpdatedSGList": updated_sg_list,
                "RemediationRequired": True,
            },
        )
    else:
        return CommandResults(
            outputs_prefix="AWSPublicExposure.SGReplacements",
            outputs_key_field="ResourceID",
            readable_output="No security groups required remediation based on the provided inputs.",
            outputs={"ResourceID": resource_id, "ReplacementSet": [], "UpdatedSGList": "", "RemediationRequired": False},
        )


def main():
    try:
        return_results(aws_recreate_sg(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute AWSRemediateSG. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
