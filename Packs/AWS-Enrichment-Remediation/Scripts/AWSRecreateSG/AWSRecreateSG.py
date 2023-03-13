import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Dict, Any, List
import traceback
import json
from random import randint


def split_rule(rule: Dict, port: int, protocol: str) -> List[Dict]:
    res_list=[]
    #Check if 'FromPort' is in rule, else it is an "all traffic rule".
    if rule.get('FromPort'):
        #Port of interest is in front of back of range, therefore, edit the original rule.
        if rule['FromPort'] == port:
            rule['FromPort'] = rule['FromPort'] + 1
            res_list.append(rule)
        elif rule['ToPort'] == port:
            rule['ToPort'] = rule['ToPort'] - 1
            res_list.append(rule)
        #If in the middle, create two rules.
        else:
            rule_copy = rule.copy()
            rule['ToPort'] = port - 1
            res_list.append(rule)
            rule_copy['FromPort'] = port + 1
            res_list.append(rule_copy)
    else:
        #TODO good place for some clean up
        if protocol == 'tcp':
            rule1 = rule.copy()
            rule2 = rule.copy()
            rule3 = rule.copy()
            rule1['FromPort'] = 0
            rule1['ToPort'] = port - 1
            rule1["IpProtocol"] = 'tcp'
            rule2['FromPort'] = port +1
            rule2['ToPort'] = 65535
            rule2["IpProtocol"] = 'tcp'
            rule3['FromPort'] = 0
            rule3['ToPort'] = 65535
            rule3["IpProtocol"] = 'udp'
            res_list.append(rule1)
            res_list.append(rule2)
            res_list.append(rule3)
        else:
            rule1 = rule.copy()
            rule2 = rule.copy()
            rule3 = rule.copy()
            rule1['FromPort'] = 0
            rule1['ToPort'] = port - 1
            rule1["IpProtocol"] = 'udp'
            rule2['FromPort'] = port +1
            rule2['ToPort'] = 65535
            rule2["IpProtocol"] = 'udp'
            rule3['FromPort'] = 0
            rule3['ToPort'] = 65535
            rule3["IpProtocol"] = 'tcp'
            res_list.append(rule1)
            res_list.append(rule2)
            res_list.append(rule3)
    return(res_list)

def sg_fix(sg_info: Dict, port: int, protocol: str) -> Dict:

    info = sg_info[0]['Contents']['AWS.EC2.SecurityGroups(val.GroupId === obj.GroupId)'][0]
    recreate_list=[]
    no_change = True
    for rule in info['IpPermissions']:
        #Check if 'FromPort' is in rule, else it is an "all traffic rule".
        if rule.get('FromPort'):
            #Don't recrete if it targets just the port of interest.
            if rule['FromPort'] == port and port == rule['ToPort'] and rule['IpRanges'][0]['CidrIp'] == "0.0.0.0/0" and rule['IpProtocol'] == protocol:
                no_change = False
            elif rule['FromPort'] <= port and port <= rule['ToPort'] and rule['IpRanges'][0]['CidrIp'] == "0.0.0.0/0" and rule['IpProtocol'] == protocol:
                fixed = split_rule(rule, port, protocol)
                for rule_fix in fixed:
                    new_rule = (str([rule_fix])).replace("'","\"")
                    recreate_list.append(new_rule)
                    no_change = False
            else:
                new_rule = (str([rule])).replace("'","\"")
                recreate_list.append(new_rule)
        elif rule['IpRanges'][0]['CidrIp'] == "0.0.0.0/0":
            fixed = split_rule(rule, port, protocol)
            no_change = False
            for rule_fix in fixed:
                new_rule = (str([rule_fix])).replace("'","\"")
                recreate_list.append(new_rule)
        else:
            new_rule = (str([rule])).replace("'","\"")
            recreate_list.append(new_rule)
    if no_change:
        return False
    else:
        #Add rules that allow private_ips to specific port.
        priv_ips_list=[[{'IpProtocol': protocol, 'IpRanges': [{'CidrIp': '10.0.0.0/8'}], 'Ipv6Ranges': [], 'PrefixListIds': [], 'UserIdGroupPairs': [], 'FromPort': port, 'ToPort': port}],
              [{'IpProtocol': protocol, 'IpRanges': [{'CidrIp': '172.16.0.0/12'}], 'Ipv6Ranges': [], 'PrefixListIds': [], 'UserIdGroupPairs': [], 'FromPort': port, 'ToPort': port}],
              [{'IpProtocol': protocol, 'IpRanges': [{'CidrIp': '192.168.0.0/16'}], 'Ipv6Ranges': [], 'PrefixListIds': [], 'UserIdGroupPairs': [], 'FromPort': port, 'ToPort': port}]]
        for priv in priv_ips_list:
            recreate_list.append(str(priv).replace("'","\""))
        new_name = info['GroupName'] + "_active_response_" + str(randint(100, 999))
        description = "copied from rule " + info['GroupName'] + " by Xpanse Active Response module"
        new_sg = demisto.executeCommand("aws-ec2-create-security-group", {"groupName":new_name, "vpcId":info['VpcId'], "description":description})
        new_id = new_sg[0]['Contents']['AWS.EC2.SecurityGroups']['GroupId']
    for item in recreate_list:
        demisto.executeCommand("aws-ec2-authorize-security-group-ingress-rule", {"groupId":new_id, "IpPermissionsFull":item})
    #Check if there was a rule for `all traffic` (added by default), but break if it is the only egress rule.
    match_all_trafic = False
    for egress in info['IpPermissionsEgress']:
        if egress["IpProtocol"] == '-1':
            if len(info['IpPermissionsEgress']) == 1:
                break
            match_all_trafic = True
        e_format = str([egress]).replace("'","\"")
        demisto.executeCommand("aws-ec2-authorize-security-group-egress-rule", {"groupId":new_id, "IpPermissionsFull":e_format})
    #If `all traffic` rule before, remove the default one.
    if match_all_trafic == True:
        all_traffic_rule = """[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [], "PrefixListIds": [], "UserIdGroupPairs": []}]"""
        demisto.executeCommand("aws-ec2-revoke-security-group-egress-rule", {"groupId":new_id, "IpPermissionsFull":all_traffic_rule})
    return {'new-sg':new_id}


def replace_sgs(replace_list: List,int_sg_mapping: Dict):
    for entry in replace_list:
        int_sg_mapping[entry['int']].remove(entry['old-sg'])
        int_sg_mapping[entry['int']].append(entry['new-sg'])
        formatted_list = ','.join(int_sg_mapping[entry['int']])
        demisto.executeCommand("aws-ec2-modify-network-interface-attribute", {"networkInterfaceId":entry['int'], "groups":formatted_list})

def determine_excessive_access(int_sg_mapping: Dict, port: int, protocol: str) -> List:
    replace_list=[]
    for mapping in int_sg_mapping.keys():
        for sg in int_sg_mapping[mapping]:
            sg_info = demisto.executeCommand("aws-ec2-describe-security-groups", {"groupIds":sg})
            if sg_info:
                res = sg_fix(sg_info, port, protocol)
                #Need interface, old sg and new sg.
                if res:
                    res['old-sg'] = sg
                    res['int'] = mapping
                    replace_list.append(res)
    return replace_list


def instance_info(instance_id: str, public_ip: str) -> Dict:
    instance_info = demisto.executeCommand("aws-ec2-describe-instances", {"instanceIds":instance_id})
    if instance_info[0].get('Contents').get('AWS.EC2.Instances(val.InstanceId === obj.InstanceId)')[0].get('NetworkInterfaces'):
        interfaces = instance_info[0].get('Contents').get('AWS.EC2.Instances(val.InstanceId === obj.InstanceId)')[0].get('NetworkInterfaces')
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
        if match == False:
            raise ValueError('could not find interface with public IP association')
        return mapping_dict
    else:
        raise ValueError('failed to pull information on EC2 instance')

''' COMMAND FUNCTION '''


def aws_recreate_sg_command(args: Dict[str, Any]) -> List:

    instance_id = args.get('instance_id', None)
    port = int(args.get('port', None))
    protocol = args.get('protocol', None)
    public_ip = args.get('public_ip', None)

    if not instance_id or not port or not protocol or not public_ip:
        raise ValueError('instance_id, port, protocol and public_ip all need to be specified')

    #Determine interface with public IP and associated SGs.
    int_sg_mapping = instance_info(instance_id,public_ip)
    #Determine what SGs are overpermissive for particular port.
    replace_list = determine_excessive_access(int_sg_mapping, port, protocol)
    replace_sgs(replace_list,int_sg_mapping)
    return replace_list



''' MAIN FUNCTION '''


def main():
    try:
        return_results(aws_recreate_sg_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute AWSRecreateSG. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
