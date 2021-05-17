import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import json
import copy


def get_dict_value(data, key):
    """ Returns dict value for a given key (case insensitive) """
    for key_name in data.keys():
        if key_name.lower() == key.lower():
            return data[key_name]

    return None


def get_ec2_sg_public_rules(group_id, ip_permissions, checked_protocol=None, checked_from_port=None,
                            checked_to_port=None, region=None, include_ipv6='no'):
    """
        Get the list of public
        which can be passed on to the following command:
        aws-ec2-revoke-security-group-ingress-rule
    """

    # If the SG only has one rule, we have to convert the dict to a list with one element
    if (isinstance(ip_permissions, dict)):
        ip_permissions = [ip_permissions]

    public_rules = []
    for rule in ip_permissions:
        # Check protocol
        protocol = get_dict_value(rule, 'IpProtocol')
        if protocol != '-1':
            if checked_protocol.lower() != protocol.lower():
                continue

        bad_rule = {
            'groupId': group_id,
            'ipProtocol': protocol
        }

        if region:
            bad_rule.update(region=region)

        # Check the ports
        from_port = get_dict_value(rule, 'FromPort')
        to_port = get_dict_value(rule, 'ToPort')
        if from_port and to_port:
            if from_port < checked_from_port and to_port < checked_from_port:
                continue
            elif from_port > checked_to_port and to_port > checked_to_port:
                continue

            bad_rule.update({
                'fromPort': from_port,
                'toPort': to_port
            })

        # Process IPV4
        ip_ranges = get_dict_value(rule, 'ipv4Ranges')
        if not ip_ranges:
            ip_ranges = get_dict_value(rule, 'IpRanges')

        if ip_ranges:
            for ip_range in ip_ranges:
                cidr_ip = get_dict_value(ip_range, 'CidrIp')
                if cidr_ip == '0.0.0.0/0':
                    tmp = copy.copy(bad_rule)
                    tmp['cidrIp'] = '0.0.0.0/0'
                    public_rules.append(tmp)

        # Process IPv6
        if include_ipv6 == 'yes':
            ip_ranges = get_dict_value(rule, 'Ipv6Ranges')
            if ip_ranges:
                for ip_range in ip_ranges:
                    cidr_ip = get_dict_value(ip_range, 'CidrIpv6')
                    if cidr_ip == '::/0':
                        tmp = copy.copy(bad_rule)
                        tmp['cidrIp'] = '::/0'
                        public_rules.append(tmp)

    return public_rules


def main(args):
    ip_perms = args.get('ipPermissions')

    if isinstance(ip_perms, str):
        try:
            ip_perms = json.loads(ip_perms)
        except json.JSONDecodeError:
            return_error('Unable to parse ipPermissions. Invalid JSON string.')

    # If checked from_port or to_port is not specified
    # it will default to 0-65535 (all port)
    if args.get('fromPort'):
        from_port = int(args.get('fromPort'))
    else:
        from_port = 0

    if args.get('toPort'):
        to_port = int(args.get('toPort'))
    else:
        to_port = 65535

    public_rules = get_ec2_sg_public_rules(
        group_id=args.get('groupId'),
        ip_permissions=ip_perms,
        checked_protocol=args.get('protocol'),
        checked_from_port=from_port,
        checked_to_port=to_port,
        region=args.get('region'),
        include_ipv6=args.get('includeIPv6')
    )

    readable_output = tableToMarkdown('Public Security Group Rules', public_rules,
                                      ['groupId', 'ipProtocol', 'fromPort', 'toPort', 'cidrIp', 'region']
                                      )

    context = {
        'AWS': {
            'EC2': {
                'SecurityGroup': {
                    'PublicRules': public_rules
                }
            }
        }
    }

    return_outputs(readable_output, context, raw_response=public_rules)


if __name__ in ('builtins', '__builtin__'):
    main(demisto.args())
