import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Dict, Any, List
import traceback
from random import randint


def split_rule(rule: Dict, port: int, protocol: str) -> List[Dict]:
    """
    If there are rules with ranges of ports, split them up

    Args:
        rule (Dict): SG rule as a dictionary
        port (int): TCP/UDP Port to be restricted
        protocol (str): Protocol of the port to be restricted

    Returns:
        List: List of replacement rules=
    """
    res_list = []
    # Check if 'FromPort' is in rule, else it is an "all traffic rule".
    if rule.get('FromPort'):
        # Port of interest is in front of back of range, therefore, edit the original rule.
        if rule['FromPort'] == port:
            rule['FromPort'] = rule['FromPort'] + 1
            res_list.append(rule)
        elif rule['ToPort'] == port:
            rule['ToPort'] = rule['ToPort'] - 1
            res_list.append(rule)
        # If in the middle, create two rules.
        else:
            rule_copy = rule.copy()
            rule['ToPort'] = port - 1
            res_list.append(rule)
            rule_copy['FromPort'] = port + 1
            res_list.append(rule_copy)
    else:
        # Splitting up "all traffic" rules.
        if protocol == 'tcp':
            res_list = [{'IpProtocol': 'tcp', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}], 'Ipv6Ranges': [], 'PrefixListIds': [],
                         'UserIdGroupPairs': [], 'FromPort': 0, 'ToPort': port - 1},
                        {'IpProtocol': 'tcp', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}], 'Ipv6Ranges': [], 'PrefixListIds': [],
                         'UserIdGroupPairs': [], 'FromPort': port + 1, 'ToPort': 65535},
                        {'IpProtocol': 'udp', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}], 'Ipv6Ranges': [], 'PrefixListIds': [],
                         'UserIdGroupPairs': [], 'FromPort': 0, 'ToPort': 65535}]
        else:
            res_list = [{'IpProtocol': 'udp', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}], 'Ipv6Ranges': [], 'PrefixListIds': [],
                         'UserIdGroupPairs': [], 'FromPort': 0, 'ToPort': port - 1},
                        {'IpProtocol': 'udp', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}], 'Ipv6Ranges': [], 'PrefixListIds': [],
                         'UserIdGroupPairs': [], 'FromPort': port + 1, 'ToPort': 65535},
                        {'IpProtocol': 'tcp', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}], 'Ipv6Ranges': [], 'PrefixListIds': [],
                         'UserIdGroupPairs': [], 'FromPort': 0, 'ToPort': 65535}]
    return(res_list)


def sg_fix(sg_info: List, port: int, protocol: str) -> Dict:
    """
    For a SG determine what needs to be recreated.
    Calls split_rule() if there are rules with ranges of ports to be split up

    Args:
        sg_info (List): List of information pulled from "aws-ec2-describe-security-groups" command
        port (int): TCP/UDP Port to be restricted
        protocol (str): Protocol of the port to be restricted

    Returns:
        Dict: Dict of the new SG to be used
    """
    info = sg_info[0]['Contents']['AWS.EC2.SecurityGroups(val.GroupId === obj.GroupId)'][0]
    recreate_list = []
    # Keep track of change in SG or not.
    change = False
    for rule in info['IpPermissions']:
        # Check if 'FromPort' is in rule, else it is an "all traffic rule".
        if rule.get('FromPort'):
            # Don't recrete if it targets just the port of interest.
            if rule['FromPort'] == port and port == rule['ToPort'] and rule['IpRanges'][0]['CidrIp'] == "0.0.0.0/0" and \
               rule['IpProtocol'] == protocol:
                change = True
            elif rule['FromPort'] <= port and port <= rule['ToPort'] and rule['IpRanges'][0]['CidrIp'] == "0.0.0.0/0" and \
                 rule['IpProtocol'] == protocol:  # noqa: E127
                fixed = split_rule(rule, port, protocol)
                for rule_fix in fixed:
                    new_rule = (str([rule_fix])).replace("'", "\"")
                    recreate_list.append(new_rule)
                    change = True
            else:
                new_rule = (str([rule])).replace("'", "\"")
                recreate_list.append(new_rule)
        elif rule['IpRanges'][0]['CidrIp'] == "0.0.0.0/0":
            fixed = split_rule(rule, port, protocol)
            change = True
            for rule_fix in fixed:
                new_rule = (str([rule_fix])).replace("'", "\"")
                recreate_list.append(new_rule)
        else:
            new_rule = (str([rule])).replace("'", "\"")
            recreate_list.append(new_rule)
    if change is False:
        return {}
    else:
        # Add rules that allow private_ips to specific port.
        priv_ips_list = [[{'IpProtocol': protocol, 'IpRanges': [{'CidrIp': '10.0.0.0/8'}], 'Ipv6Ranges': [],
                           'PrefixListIds': [], 'UserIdGroupPairs': [], 'FromPort': port, 'ToPort': port}],
                         [{'IpProtocol': protocol, 'IpRanges': [{'CidrIp': '172.16.0.0/12'}], 'Ipv6Ranges': [],
                             'PrefixListIds': [], 'UserIdGroupPairs': [], 'FromPort': port, 'ToPort': port}],
                         [{'IpProtocol': protocol, 'IpRanges': [{'CidrIp': '192.168.0.0/16'}], 'Ipv6Ranges': [],
                           'PrefixListIds': [], 'UserIdGroupPairs': [], 'FromPort': port, 'ToPort': port}]]
        for priv in priv_ips_list:
            recreate_list.append(str(priv).replace("'", "\""))
        new_name = info['GroupName'] + "_xpanse_ar_" + str(randint(100, 999))
        description = "copied from rule " + info['GroupName'] + " by Xpanse Active Response module"
        new_sg = demisto.executeCommand("aws-ec2-create-security-group",
                                        {"groupName": new_name, "vpcId": info['VpcId'], "description": description})
        if isError(new_sg):
            raise ValueError('Error on creating new security group')
        new_id = new_sg[0]['Contents']['AWS.EC2.SecurityGroups']['GroupId']
    for item in recreate_list:
        res = demisto.executeCommand("aws-ec2-authorize-security-group-ingress-rule",
                                     {"groupId": new_id, "IpPermissionsFull": item})
        if isError(res):
            if "already exists" in res[0]['Contents']:
                pass
            else:
                raise ValueError('Error on adding security group ingress rules to new security group')
    # Check if there was a rule for `all traffic` (added by default), but break if it is the only egress rule.
    match_all_trafic = False
    for egress in info['IpPermissionsEgress']:
        if egress["IpProtocol"] == '-1':
            if len(info['IpPermissionsEgress']) == 1:
                break
            match_all_trafic = True
        e_format = str([egress]).replace("'", "\"")
        res = demisto.executeCommand("aws-ec2-authorize-security-group-egress-rule",
                                     {"groupId": new_id, "IpPermissionsFull": e_format})
        # Don't error if the message is that the rule already exists.
        if isError(res):
            if "already exists" in res[0]['Contents']:
                pass
            else:
                raise ValueError('Error on adding security group egress rules to new security group')
    # If `all traffic` rule before, remove the default one.
    if match_all_trafic is True:
        all_traffic_rule = """[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [],""" + \
                           """"PrefixListIds": [], "UserIdGroupPairs": []}]"""
        res = demisto.executeCommand("aws-ec2-revoke-security-group-egress-rule",
                                     {"groupId": new_id, "IpPermissionsFull": all_traffic_rule})
        if isError(res):
            raise ValueError('Error on removing egress `allow all` rule on new security group')
    return {'new-sg': new_id}


def replace_sgs(replace_list: List, int_sg_mapping: Dict):
    """
    Replace the actual SGs on the interface

    Args:
        replace_list (List): list of SGs to be replaced
        int_sg_mapping: interface to security group mapping

    Returns:
        none
    """
    for entry in replace_list:
        int_sg_mapping[entry['int']].remove(entry['old-sg'])
        int_sg_mapping[entry['int']].append(entry['new-sg'])
        formatted_list = ','.join(int_sg_mapping[entry['int']])
        res = demisto.executeCommand("aws-ec2-modify-network-interface-attribute",
                                     {"networkInterfaceId": entry['int'], "groups": formatted_list})
        if isError(res):
            raise ValueError('Error on replacing security group(s) on network interface')


def determine_excessive_access(int_sg_mapping: Dict, port: int, protocol: str) -> List:
    """
    Pulls info on each SG and then calls sg_fix() to actually create the new SGs

    Args:
        int_sg_mapping (Dict): interface to security group mapping
        port (int): TCP/UDP Port to be restricted
        protocol (str): Protocol of the port to be restricted

    Returns:
        List: list of SGs to be replaced
    """
    replace_list = []
    for mapping in int_sg_mapping.keys():
        for sg in int_sg_mapping[mapping]:
            sg_info = demisto.executeCommand("aws-ec2-describe-security-groups", {"groupIds": sg})
            if isError(sg_info):
                raise ValueError('Error on describing security group')
            elif sg_info:
                res = sg_fix(sg_info, port, protocol)
                # Need interface, old sg and new sg.
                if res.get('new-sg'):
                    res['old-sg'] = sg
                    res['int'] = mapping
                    replace_list.append(res)
    return replace_list


def instance_info(instance_id: str, public_ip: str) -> Dict:
    """
    Finds interface with public_ip and from this creates interface ID/SG mapping

    Args:
        instance_id (str): EC2 Instance ID
        public_ip (str): Public IP address of the EC2 instance

    Returns:
        Dict: interface to security group mapping
    """
    instance_info = demisto.executeCommand("aws-ec2-describe-instances", {"instanceIds": instance_id})
    if instance_info[0].get('Contents').get('AWS.EC2.Instances(val.InstanceId === obj.InstanceId)')[0].get('NetworkInterfaces'):
        interfaces = instance_info[0].get('Contents').get(
            'AWS.EC2.Instances(val.InstanceId === obj.InstanceId)')[0].get('NetworkInterfaces')
        match = False
        mapping_dict = {}
        for interface in interfaces:
            if interface.get('Association'):
                if interface.get('Association').get('PublicIp') == public_ip:
                    match = True
                    group_list = []
                    for sg in interface['Groups']:
                        group_list.append(sg['GroupId'])
                    mapping_dict[interface['NetworkInterfaceId']] = group_list
        if match is False:
            raise ValueError('could not find interface with public IP association')
        return mapping_dict
    else:
        raise ValueError('failed to pull information on EC2 instance')


def aws_recreate_sg(args: Dict[str, Any]) -> str:
    """
    Main command that determines what interface on an EC2 instance has an over-permissive security group on,
    determine which security groups have over-permissive rules and to replace them with a copy of the security group
    that has only the over-permissive portion removed.  Over-permissive is defined as sensitive ports (SSH, RDP, etc)
    being exposed to the internet via IPv4.

    Args:
        args (Dict[str, Any]): Demisto.args() object

    Returns:
        str: human readable message of what SGs were replaced on what interface
    """

    instance_id = args.get('instance_id', None)
    port = int(args.get('port', None))
    protocol = args.get('protocol', None)
    public_ip = args.get('public_ip', None)

    if not instance_id or not port or not protocol or not public_ip:
        raise ValueError('instance_id, port, protocol and public_ip all need to be specified')

    # Determine interface with public IP and associated SGs.
    int_sg_mapping = instance_info(instance_id, public_ip)
    # Determine what SGs are overpermissive for particular port.
    replace_list = determine_excessive_access(int_sg_mapping, port, protocol)
    if len(replace_list) == 0:
        raise ValueError('No security groups were found to need to be replaced')
    replace_sgs(replace_list, int_sg_mapping)
    display_message = f"For interface {replace_list[0]['int']}: \r\n"
    for replace in replace_list:
        display_message += f"replaced SG {replace['old-sg']} with {replace['new-sg']} \r\n"
    return display_message


''' MAIN FUNCTION '''


def main():
    try:
        return_results(aws_recreate_sg(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute AWSRecreateSG. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
