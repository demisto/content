import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from typing import Any
import traceback
from random import randint


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
    # Check if 'FromPort' is in rule, else it is an "all traffic rule".
    if "FromPort" in rule:
        # Port of interest is in front of back of range, therefore, edit the original rule without the given port.
        if rule["FromPort"] == port:
            rule["FromPort"] = rule["FromPort"] + 1
            res_list.append(rule)
        elif rule["ToPort"] == port:
            rule["ToPort"] = rule["ToPort"] - 1
            res_list.append(rule)
        # If in the middle, create two rules.
        else:
            rule_copy = rule.copy()
            rule["ToPort"] = port - 1
            res_list.append(rule)
            rule_copy["FromPort"] = port + 1
            res_list.append(rule_copy)
    else:
        # Splitting up "all traffic" rules.  Creates an additional rule that continues to allow traffic
        # to all ports using the opposite protocol specified.
        if protocol == "tcp":
            res_list = [
                {
                    "IpProtocol": "tcp",
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0",
                            "Description": f"Allow rule created by Cortex remediation from All Traffic rule "
                            f"omitting TCP port {port}.",
                        },
                    ],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "UserIdGroupPairs": [],
                    "FromPort": 0,
                    "ToPort": port - 1,
                },
                {
                    "IpProtocol": "tcp",
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0",
                            "Description": f"Allow rule created by Cortex remediation from All Traffic rule "
                            f"omitting TCP port {port}.",
                        },
                    ],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "UserIdGroupPairs": [],
                    "FromPort": port + 1,
                    "ToPort": 65535,
                },
                {
                    "IpProtocol": "udp",
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0",
                            "Description": f"Allow rule created by Cortex remediation from All Traffic rule "
                            f"omitting TCP port {port}.",
                        },
                    ],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "UserIdGroupPairs": [],
                    "FromPort": 0,
                    "ToPort": 65535,
                },
            ]
        else:
            res_list = [
                {
                    "IpProtocol": "udp",
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0",
                            "Description": f"Allow rule created by Cortex remediation from All Traffic rule "
                            f"omitting UDP port {port}.",
                        },
                    ],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "UserIdGroupPairs": [],
                    "FromPort": 0,
                    "ToPort": port - 1,
                },
                {
                    "IpProtocol": "udp",
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0",
                            "Description": f"Allow rule created by Cortex remediation from All Traffic rule "
                            f"omitting UDP port {port}.",
                        },
                    ],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "UserIdGroupPairs": [],
                    "FromPort": port + 1,
                    "ToPort": 65535,
                },
                {
                    "IpProtocol": "tcp",
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0",
                            "Description": f"Allow rule created by Cortex remediation from All Traffic rule "
                            f"omitting UDP port {port}.",
                        },
                    ],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "UserIdGroupPairs": [],
                    "FromPort": 0,
                    "ToPort": 65535,
                },
            ]
    return res_list


def sg_fix(account_id: str, sg_info: list, port: int, protocol: str, integration_instance: str, region: str) -> dict:
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

    Returns:
        dict: Dictionary containing the new security group ID under 'new-sg' key,
              or empty dict if no changes were needed

    Raises:
        DemistoException: If security group creation or rule modification fails
    """
    info = dict_safe_get(sg_info, (0, "Contents", "SecurityGroups", 0))
    recreate_list = []
    # Keep track of change in SG or not.
    change = False
    for rule in info["IpPermissions"]:
        if rule.get("IpRanges") and len(rule.get("IpRanges")) > 0:
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
                    fixed = split_rule(rule, port, protocol)
                    for rule_fix in fixed:
                        new_rule = (str([rule_fix])).replace("'", '"')
                        recreate_list.append(new_rule)
                        change = True
                # If rule doesn't need to be modified, include in list for new SG as-is
                else:
                    new_rule = (str([rule])).replace("'", '"')
                    recreate_list.append(new_rule)
            # If rule is an "all traffic" rule, create separate rules allowing all ports EXCEPT the specified one.
            elif rule.get("IpRanges") and any(d["CidrIp"] == "0.0.0.0/0" for d in rule["IpRanges"]):
                fixed = split_rule(rule, port, protocol)
                change = True
                for rule_fix in fixed:
                    new_rule = (str([rule_fix])).replace("'", '"')
                    recreate_list.append(new_rule)
            else:
                new_rule = (str([rule])).replace("'", '"')
                recreate_list.append(new_rule)

    if change is False:
        return {}
    else:
        # Add rules that allow private_ips to specific port.
        priv_ips_list = [
            [
                {
                    "IpProtocol": protocol,
                    "IpRanges": [
                        {
                            "CidrIp": "10.0.0.0/8",
                            "Description": "Internal access rule automatically created by Cortex remediation.",
                        }
                    ],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "UserIdGroupPairs": [],
                    "FromPort": port,
                    "ToPort": port,
                }
            ],
            [
                {
                    "IpProtocol": protocol,
                    "IpRanges": [
                        {
                            "CidrIp": "172.16.0.0/12",
                            "Description": "Internal access rule automatically created by Cortex remediation.",
                        }
                    ],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "UserIdGroupPairs": [],
                    "FromPort": port,
                    "ToPort": port,
                }
            ],
            [
                {
                    "IpProtocol": protocol,
                    "IpRanges": [
                        {
                            "CidrIp": "192.168.0.0/16",
                            "Description": "Internal access rule automatically created by Cortex remediation.",
                        }
                    ],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "UserIdGroupPairs": [],
                    "FromPort": port,
                    "ToPort": port,
                }
            ],
        ]
        for priv in priv_ips_list:
            recreate_list.append(str(priv).replace("'", '"'))

        # Create the empty Security Group
        new_name = info["GroupName"] + "_cortex_remediation_" + str(randint(100, 999))
        description = "copied from Security Group " + info["GroupName"] + " by Cortex."
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

        # Apply old SG's tags to new SG
        tags_data = info.get("Tags")
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

    for item in recreate_list:
        create_ingress_rule_cmd_args = {
            "account_id": account_id,
            "group_id": new_id,
            "ip_permissions": item,
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

    # Check if there was a rule for `all traffic` (added by default), but break if it is the only egress rule.
    match_all_traffic = False
    for egress in info["IpPermissionsEgress"]:
        if egress["IpProtocol"] == "-1":
            if len(info["IpPermissionsEgress"]) == 1:
                break
            match_all_traffic = True
        e_format = str([egress]).replace("'", '"')
        create_egress_rule_cmd_args = {
            "account_id": account_id,
            "groupId": new_id,
            "ip_permissions": e_format,
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

    # If `all traffic` rule before, remove the default one.
    if match_all_traffic is True:
        all_traffic_rule = (
            """[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [],"""
            + """"PrefixListIds": [], "UserIdGroupPairs": []}]"""
        )
        revoke_egress_rule_cmd_args = {
            "account_id": account_id,
            "groupId": new_id,
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
    account_id: str, sg_list: list, port: int, protocol: str, integration_instance: str, region: str
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

    Returns:
        list[dict]: List of dictionaries containing mapping between old and new security groups.
                   Each dict contains 'old-sg' and 'new-sg' keys with respective security group IDs.

    Raises:
        DemistoException: If security group description or remediation fails
    """
    replace_list = []
    for sg in sg_list:
        cmd_args = {"group_ids": sg, "using": integration_instance, "account_id": account_id, "region": region}
        sg_info = demisto.executeCommand("aws-ec2-security-groups-describe", cmd_args)
        if isError(sg_info):
            raise DemistoException(
                f"Error on describing security group with command 'aws-ec2-security-groups-describe'.\n"
                f"Error: {json.dumps(sg_info[0]['Contents'])}"
            )
        elif sg_info:
            res = sg_fix(account_id, sg_info, port, protocol, integration_instance, region)
            # Need interface, old sg and new sg.
            if res.get("new-sg"):
                res["old-sg"] = sg
                replace_list.append(res)
    return replace_list


def identify_integration_instance(account_id: str, sg: str, region: str) -> str:
    """
    Runs command 'aws-ec2-security-groups-describe' to identify the AWS integration instance can be used.

    Args:
        account_id (str): AWS Account ID
        sg (str): The ID of a single Security Group to check
        region (str): AWS Region where the Security Group is located

    Returns:
        str: The name of the AWS integration instance that can be used to interact with the specified Security Group

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

    if isError(sg_info) or not sg_info:
        raise DemistoException(
            f"Error retrieving security group details with command 'aws-ec2-security-groups-describe'.\n"
            f"Error: {json.dumps(sg_info[0]['Contents'])}"
        )

    instance_to_use = dict_safe_get(sg_info, (0, "Metadata", "instance"))
    return instance_to_use

    
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

    if not account_id or not sg_list or not port or not protocol:
        raise ValueError("account_id, sg_list, instance_id, port, and protocol all need to be specified")

    if not integration_instance:
        integration_instance = identify_integration_instance(account_id, sg_list[0], region)

    replace_list = fix_excessive_access(account_id, sg_list, port, protocol, integration_instance, region)

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
                "RemediationRequired": True
            },
        )
    else:
        return CommandResults(
            outputs_prefix="AWSPublicExposure.SGReplacements",
            outputs_key_field="ResourceID",
            readable_output="No security groups required remediation based on the provided inputs.",
            outputs={
                "ResourceID": resource_id,
                "ReplacementSet": [],
                "UpdatedSGList": "",
                "RemediationRequired": False
            },
        )


def main():
    try:
        return_results(aws_recreate_sg(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute AWSRemediateSG. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
