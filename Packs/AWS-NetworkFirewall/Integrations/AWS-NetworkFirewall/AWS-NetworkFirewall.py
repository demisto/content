import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

# flake8: noqa
import boto3
import json
import datetime  # type: ignore
from botocore.config import Config
from botocore.parsers import ResponseParserError
import urllib3.util


# Disable insecure warnings
urllib3.disable_warnings()


"""PARAMETERS"""
AWS_DEFAULT_REGION = demisto.params().get('defaultRegion')
AWS_ROLE_ARN = demisto.params().get('roleArn')
AWS_ROLE_SESSION_NAME = demisto.params().get('roleSessionName')
AWS_ROLE_SESSION_DURATION = demisto.params().get('sessionDuration')
AWS_ROLE_POLICY = None
AWS_ACCESS_KEY_ID = demisto.params().get('access_key')
AWS_SECRET_ACCESS_KEY = demisto.params().get('secret_key')
VERIFY_CERTIFICATE = not demisto.params().get('insecure', True)
proxies = handle_proxy(proxy_param_name='proxy', checkbox_default_value=False)
config = Config(
    connect_timeout=1,
    retries=dict(
        max_attempts=5
    ),
    proxies=proxies
)


"""HELPER FUNCTIONS"""


def myconverter(o):
    if isinstance(o, datetime.datetime):  # type: ignore
        return o.__str__()


def parse_resource_ids(resource_id):
    if resource_id is None:
        return None
    id_list = resource_id.replace(" ", "")
    resourceIds = id_list.split(",")
    return resourceIds


def parse_tag_field(tags_str):
    tags = []
    regex = re.compile(
        r'key=([\w\d_:.-]+),value=([ /\w\d@_,.*-]+)', flags=re.I)
    if demisto.args().get('tag_key') and demisto.args().get('tag_value'):
        if demisto.args().get('tags'):
            return_error(
                "Please select either the arguments 'tag_key' and 'tag_value' or only 'tags'.")
        tags.append({
            'Key': demisto.args().get('tag_key'),
            'Value': demisto.args().get('tag_value')
        })
    else:
        if tags_str is not None:
            for f in tags_str.split(';'):
                match = regex.match(f)
                if match is None:
                    demisto.log('could not parse field: %s' % (f,))
                    continue

                tags.append({
                    'Key': match.group(1),
                    'Value': match.group(2)
                })

    return tags


def aws_session(service='network-firewall', region=None, roleArn=None, roleSessionName=None,
                roleSessionDuration=None, rolePolicy=None):
    kwargs = {}
    if roleArn and roleSessionName is not None:
        kwargs.update({
            'RoleArn': roleArn,
            'RoleSessionName': roleSessionName,
        })
    elif AWS_ROLE_ARN and AWS_ROLE_SESSION_NAME is not None:
        kwargs.update({
            'RoleArn': AWS_ROLE_ARN,
            'RoleSessionName': AWS_ROLE_SESSION_NAME,
        })

    if roleSessionDuration is not None:
        kwargs.update({'DurationSeconds': int(roleSessionDuration)})
    elif AWS_ROLE_SESSION_DURATION is not None:
        kwargs.update({'DurationSeconds': int(AWS_ROLE_SESSION_DURATION)})

    if rolePolicy is not None:
        kwargs.update({'Policy': rolePolicy})
    elif AWS_ROLE_POLICY is not None:
        kwargs.update({'Policy': AWS_ROLE_POLICY})
    if kwargs and AWS_ACCESS_KEY_ID is None:

        if AWS_ACCESS_KEY_ID is None:
            sts_client = boto3.client(
                'sts', config=config, verify=VERIFY_CERTIFICATE)
            sts_response = sts_client.assume_role(**kwargs)
            if region is not None:
                client = boto3.client(
                    service_name=service,
                    region_name=region,
                    aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                    aws_session_token=sts_response['Credentials']['SessionToken'],
                    verify=VERIFY_CERTIFICATE,
                    config=config
                )
            else:
                client = boto3.client(
                    service_name=service,
                    region_name=AWS_DEFAULT_REGION,
                    aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                    aws_session_token=sts_response['Credentials']['SessionToken'],
                    verify=VERIFY_CERTIFICATE,
                    config=config
                )
    elif AWS_ACCESS_KEY_ID and AWS_ROLE_ARN:
        sts_client = boto3.client(
            service_name='sts',
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            verify=VERIFY_CERTIFICATE,
            config=config
        )
        kwargs.update({
            'RoleArn': AWS_ROLE_ARN,
            'RoleSessionName': AWS_ROLE_SESSION_NAME,
        })
        sts_response = sts_client.assume_role(**kwargs)
        client = boto3.client(
            service_name=service,
            region_name=AWS_DEFAULT_REGION,
            aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
            aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
            aws_session_token=sts_response['Credentials']['SessionToken'],
            verify=VERIFY_CERTIFICATE,
            config=config
        )
    else:
        if region is not None:
            client = boto3.client(
                service_name=service,
                region_name=region,
                aws_access_key_id=AWS_ACCESS_KEY_ID,
                aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                verify=VERIFY_CERTIFICATE,
                config=config
            )
        else:
            client = boto3.client(
                service_name=service,
                region_name=AWS_DEFAULT_REGION,
                aws_access_key_id=AWS_ACCESS_KEY_ID,
                aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                verify=VERIFY_CERTIFICATE,
                config=config
            )

    return client


def associate_firewall_policy_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "UpdateToken": args.get("update_token", None),
        "FirewallArn": args.get("firewall_arn", None),
        "FirewallName": args.get("firewall_name", None),
        "FirewallPolicyArn": args.get("firewall_policy_arn", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.associate_firewall_policy(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    outputs = {
        'AWS-NetworkFirewall.AssociationResults.FirewallPolicy(val.FirewallArn === obj.FirewallArn)': response}
    del response['ResponseMetadata']
    table_header = 'AWS Network Firewall AssociateFirewallPolicy'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def associate_subnets_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "UpdateToken": args.get("update_token", None),
        "FirewallArn": args.get("firewall_arn", None),
        "FirewallName": args.get("firewall_name", None),
        "SubnetMappings": [],
    }
    subnet_ids = parse_resource_ids(args.get("subnet_mappings_subnet_ids"))
    for subnet_id in subnet_ids:
        kwargs["SubnetMappings"].append({
            "SubnetId": subnet_id
        })

    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.associate_subnets(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    outputs = {
        'AWS-NetworkFirewall.AssociationResults.Subnets(val.FirewallArn === obj.FirewallArn)': response}
    del response['ResponseMetadata']
    table_header = 'AWS Network Firewall AssociateSubnets'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def create_firewall_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "FirewallName": args.get("firewall_name", None),
        "FirewallPolicyArn": args.get("firewall_policy_arn", None),
        "VpcId": args.get("vpc_id", None),
        "SubnetMappings": [],
        "DeleteProtection": True if args.get("delete_protection", "") == "true" else None,
        "SubnetChangeProtection": True if args.get("subnet_change_protection", "") == "true" else None,
        "FirewallPolicyChangeProtection": True if args.get("firewall_policy_change_protection", "") == "true" else None,
        "Description": args.get("description", None),
        "Tags": parse_tag_field(args.get("tags")),
    }
    subnet_ids = parse_resource_ids(args.get("subnet_mappings_subnet_ids"))
    for subnet_id in subnet_ids:
        kwargs["SubnetMappings"].append({
            "SubnetId": subnet_id
        })
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.create_firewall(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    outputs = {
        'AWS-NetworkFirewall.Firewall(val.Firewall.FirewallArn === obj.Firewall.FirewallArn)': response}
    del response['ResponseMetadata']
    table_header = 'AWS Network Firewall CreateFirewall'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def create_firewall_policy_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "FirewallPolicyName": args.get("firewall_policy_name", None),
        "FirewallPolicy": safe_load_json(args.get("firewall_policy_json",None)),
        "Description": args.get("description", None),
        "Tags": parse_tag_field(args.get("tags")),

    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.create_firewall_policy(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    outputs = {
        'AWS-NetworkFirewall.FirewallPolicy(val.FirewallPolicyResponse.FirewallPolicyArn === obj.FirewallPolicyResponse.FirewallPolicyArn)': response}
    del response['ResponseMetadata']
    table_header = 'AWS Network Firewall CreateFirewallPolicy'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def create_rule_group_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "RuleGroupName": args.get("rule_group_name", None),
        "RuleGroup": safe_load_json(args.get("rule_group_json")),
        "Rules": args.get("rules", None),
        "Type": args.get("type", None),
        "Capacity": int(args.get("capacity", None)),
        "Description": args.get("description", None),
        "Tags": parse_tag_field(args.get("tags")),

    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.create_rule_group(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    outputs = {
        'AWS-NetworkFirewall.RuleGroup(val.RuleGroupResponse.RuleGroupArn === obj.RuleGroupResponse.RuleGroupArn)': response}
    del response['ResponseMetadata']
    table_header = 'AWS Network Firewall CreateRuleGroup'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def delete_firewall_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "FirewallName": args.get("firewall_name", None),
        "FirewallArn": args.get("firewall_arn", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.delete_firewall(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    outputs = {
        'AWS-NetworkFirewall.Firewall(val.Firewall.FirewallArn === obj.Firewall.FirewallArn)': response}
    del response['ResponseMetadata']
    table_header = 'AWS Network Firewall DeleteFirewall'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def delete_firewall_policy_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "FirewallPolicyName": args.get("firewall_policy_name", None),
        "FirewallPolicyArn": args.get("firewall_policy_arn", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.delete_firewall_policy(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    outputs = {
        'AWS-NetworkFirewall.FirewallPolicy(val.FirewallPolicyResponse.FirewallPolicyArn === obj.FirewallPolicyResponse.FirewallPolicyArn)': response}
    del response['ResponseMetadata']
    table_header = 'AWS Network Firewall DeleteFirewallPolicy'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def delete_resource_policy_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "ResourceArn": args.get("resource_arn", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.delete_resource_policy(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    outputs = None
    del response['ResponseMetadata']
    table_header = 'AWS Network Firewall DeleteResourcePolicy'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def delete_rule_group_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "RuleGroupName": args.get("rule_group_name", None),
        "RuleGroupArn": args.get("rule_group_arn", None),
        "Type": args.get("type", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.delete_rule_group(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    outputs = {
        'AWS-NetworkFirewall.RuleGroup(val.RuleGroupResponse.RuleGroupArn === obj.RuleGroupResponse.RuleGroupArn)': response}
    del response['ResponseMetadata']
    table_header = 'AWS Network Firewall DeleteRuleGroup'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def describe_firewall_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "FirewallName": args.get("firewall_name", None),
        "FirewallArn": args.get("firewall_arn", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.describe_firewall(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    outputs = {
        'AWS-NetworkFirewall.Firewall(val.Firewall.FirewallArn === obj.Firewall.FirewallArn)': response}
    del response['ResponseMetadata']
    table_header = 'AWS Network Firewall DescribeFirewall'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def describe_firewall_policy_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "FirewallPolicyName": args.get("firewall_policy_name", None),
        "FirewallPolicyArn": args.get("firewall_policy_arn", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.describe_firewall_policy(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    outputs = {
        'AWS-NetworkFirewall.FirewallPolicy(val.FirewallPolicyResponse.FirewallPolicyArn === obj.FirewallPolicyResponse.FirewallPolicyArn)': response}
    del response['ResponseMetadata']
    table_header = 'AWS Network Firewall DescribeFirewallPolicy'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def describe_logging_configuration_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "FirewallArn": args.get("firewall_arn", None),
        "FirewallName": args.get("firewall_name", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.describe_logging_configuration(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    outputs = {
        'AWS-NetworkFirewall.Logging(val.FirewallArn === obj.FirewallArn)': response}
    del response['ResponseMetadata']
    table_header = 'AWS Network Firewall DescribeLoggingConfiguration'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def describe_resource_policy_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "ResourceArn": args.get("resource_arn", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.describe_resource_policy(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    outputs = {'AWS-Network Firewall.Policy': response['Policy']}
    del response['ResponseMetadata']
    table_header = 'AWS Network Firewall DescribeResourcePolicy'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def describe_rule_group_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "RuleGroupName": args.get("rule_group_name", None),
        "RuleGroupArn": args.get("rule_group_arn", None),
        "Type": args.get("type", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.describe_rule_group(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    outputs = {
        'AWS-NetworkFirewall.RuleGroup(val.RuleGroupResponse.RuleGroupArn === obj.RuleGroupResponse.RuleGroupArn)': response}
    del response['ResponseMetadata']
    table_header = 'AWS Network Firewall DescribeRuleGroup'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def disassociate_subnets_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "UpdateToken": args.get("update_token", None),
        "FirewallArn": args.get("firewall_arn", None),
        "FirewallName": args.get("firewall_name", None),
        "SubnetIds": parse_resource_ids(args.get("subnet_ids", ""))
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.disassociate_subnets(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    outputs = {
        'AWS-NetworkFirewall.AssociationResults.Subnets(val.FirewallArn === obj.FirewallArn)': response}
    del response['ResponseMetadata']
    table_header = 'AWS Network Firewall DisassociateSubnets'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def list_firewall_policies_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "NextToken": args.get("next_token", None),
        "MaxResults": args.get("max_results", None),
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.list_firewall_policies(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    outputs = {
        'AWS-NetworkFirewall.FirewallPolicies(val.Arn === obj.Arn)': response.get('FirewallPolicies')}
    del response['ResponseMetadata']
    table_header = 'AWS Network Firewall ListFirewallPolicies'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def list_firewalls_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "NextToken": args.get("next_token", None),
        "VpcIds": parse_resource_ids(args.get("vpc_ids", None)),
    }

    kwargs = remove_empty_elements(kwargs)

    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")

    response = client.list_firewalls(**kwargs)

    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    outputs = {
        'AWS-NetworkFirewall.Firewalls(val.FirewallArn === obj.FirewallArn)': response.get('Firewalls')}
    del response['ResponseMetadata']
    table_header = 'AWS Network Firewall ListFirewalls'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def list_rule_groups_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "NextToken": args.get("next_token", None),
        "MaxResults": args.get("max_results",None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.list_rule_groups(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    outputs = {
        'AWS-NetworkFirewall.RuleGroups(val.Arn === obj.Arn)': response.get('RuleGroups')}
    del response['ResponseMetadata']
    table_header = 'AWS Network Firewall ListRuleGroups'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def list_tags_for_resource_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "NextToken": args.get("next_token", None),
        "ResourceArn": args.get("resource_arn", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.list_tags_for_resource(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    outputs = {'AWS-NetworkFirewall': response}
    del response['ResponseMetadata']
    table_header = 'AWS Network Firewall ListTagsForResource'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def put_resource_policy_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "ResourceArn": args.get("resource_arn", None),
        "Policy": args.get("policy", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.put_resource_policy(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    outputs = None
    del response['ResponseMetadata']
    table_header = 'AWS Network Firewall PutResourcePolicy'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def tag_resource_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "ResourceArn": args.get("resource_arn", None),
        "Tags": parse_tag_field(args.get("tags")),

    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.tag_resource(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    outputs = None
    del response['ResponseMetadata']
    table_header = 'AWS Network Firewall TagResource'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def untag_resource_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "ResourceArn": args.get("resource_arn", None),
        "TagKeys": parse_resource_ids(args.get("tag_keys", ""))
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.untag_resource(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    outputs = None
    del response['ResponseMetadata']
    table_header = 'AWS Network Firewall UntagResource'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def update_firewall_delete_protection_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "UpdateToken": args.get("update_token", None),
        "FirewallArn": args.get("firewall_arn", None),
        "FirewallName": args.get("firewall_name", None),
        "DeleteProtection": True if args.get("delete_protection", "") == "True" else False
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.update_firewall_delete_protection(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    outputs = {
        'AWS-NetworkFirewall.FirewallAttributes(val.FirewallArn === obj.FirewallArn)': response}
    del response['ResponseMetadata']
    table_header = 'AWS Network Firewall UpdateFirewallDeleteProtection'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def update_firewall_description_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "UpdateToken": args.get("update_token", None),
        "FirewallArn": args.get("firewall_arn", None),
        "FirewallName": args.get("firewall_name", None),
        "Description": args.get("description", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.update_firewall_description(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    outputs = {
        'AWS-NetworkFirewall.FirewallAttributes(val.FirewallArn === obj.FirewallArn)': response}
    del response['ResponseMetadata']
    table_header = 'AWS Network Firewall UpdateFirewallDescription'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def update_firewall_policy_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "UpdateToken": args.get("update_token", None),
        "FirewallPolicyArn": args.get("firewall_policy_arn", None),
        "FirewallPolicyName": args.get("firewall_policy_name", None),
        "FirewallPolicy": safe_load_json(args.get("firewall_policy_json", None)),
        "Description": args.get("description", None),
        "DryRun": True if args.get("dry_run", "") == "true" else None
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.update_firewall_policy(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    outputs = {
        'AWS-NetworkFirewall.FirewallPolicy(val.FirewallPolicyResponse.FirewallPolicyArn === obj.FirewallPolicyResponse.FirewallPolicyArn)': response}
    del response['ResponseMetadata']
    table_header = 'AWS Network Firewall UpdateFirewallPolicy'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def update_firewall_policy_change_protection_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "UpdateToken": args.get("update_token", None),
        "FirewallArn": args.get("firewall_arn", None),
        "FirewallName": args.get("firewall_name", None),
        "FirewallPolicyChangeProtection": True if args.get("firewall_policy_change_protection", "") == "True" else False
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.update_firewall_policy_change_protection(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    outputs = {
        'AWS-NetworkFirewall.FirewallAttributes(val.FirewallArn === obj.FirewallArn)': response}
    del response['ResponseMetadata']
    table_header = 'AWS Network Firewall UpdateFirewallPolicyChangeProtection'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def update_logging_configuration_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "FirewallArn": args.get("firewall_arn", None),
        "FirewallName": args.get("firewall_name", None),
        "LoggingConfiguration": safe_load_json(args.get("logging_configuration_json", None)),
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.update_logging_configuration(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    outputs = {
        'AWS-NetworkFirewall.Logging(val.FirewallArn === obj.FirewallArn)': response}
    del response['ResponseMetadata']
    table_header = 'AWS Network Firewall UpdateLoggingConfiguration'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def update_rule_group_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "UpdateToken": args.get("update_token", None),
        "RuleGroupArn": args.get("rule_group_arn", None),
        "RuleGroupName": args.get("rule_group_name", None),
        "RuleGroup": safe_load_json(args.get("rule_group_json", None)),
        "Rules": args.get("rules", None),
        "Type": args.get("type", None),
        "Description": args.get("description", None),
        "DryRun": True if args.get("dry_run", "") == "true" else None
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.update_rule_group(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    outputs = {
        'AWS-NetworkFirewall.RuleGroup(val.RuleGroupResponse.RuleGroupArn === obj.RuleGroupResponse.RuleGroupArn)': response}
    del response['ResponseMetadata']
    table_header = 'AWS Network Firewall UpdateRuleGroup'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def update_subnet_change_protection_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "UpdateToken": args.get("update_token", None),
        "FirewallArn": args.get("firewall_arn", None),
        "FirewallName": args.get("firewall_name", None),
        "SubnetChangeProtection": True if args.get("subnet_change_protection", "") == "True" else False
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.update_subnet_change_protection(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    outputs = {
        'AWS-NetworkFirewall.FirewallAttributes(val.FirewallArn === obj.FirewallArn)': response}
    del response['ResponseMetadata']
    table_header = 'AWS Network Firewall UpdateSubnetChangeProtection'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():  # pragma: no cover
    args = demisto.args()
    human_readable = None
    outputs = None
    try:
        LOG('Command being called is {command}'.format(
            command=demisto.command()))
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            client = aws_session()
            response = client.REPLACE_WITH_TEST_FUNCTION()
            if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                demisto.results('ok')

        elif demisto.command() == 'aws-network-firewall-associate-firewall-policy':
            human_readable, outputs, response = associate_firewall_policy_command(
                args)
        elif demisto.command() == 'aws-network-firewall-associate-subnets':
            human_readable, outputs, response = associate_subnets_command(args)
        elif demisto.command() == 'aws-network-firewall-create-firewall':
            human_readable, outputs, response = create_firewall_command(args)
        elif demisto.command() == 'aws-network-firewall-create-firewall-policy':
            human_readable, outputs, response = create_firewall_policy_command(
                args)
        elif demisto.command() == 'aws-network-firewall-create-rule-group':
            human_readable, outputs, response = create_rule_group_command(args)
        elif demisto.command() == 'aws-network-firewall-delete-firewall':
            human_readable, outputs, response = delete_firewall_command(args)
        elif demisto.command() == 'aws-network-firewall-delete-firewall-policy':
            human_readable, outputs, response = delete_firewall_policy_command(
                args)
        elif demisto.command() == 'aws-network-firewall-delete-resource-policy':
            human_readable, outputs, response = delete_resource_policy_command(
                args)
        elif demisto.command() == 'aws-network-firewall-delete-rule-group':
            human_readable, outputs, response = delete_rule_group_command(args)
        elif demisto.command() == 'aws-network-firewall-describe-firewall':
            human_readable, outputs, response = describe_firewall_command(args)
        elif demisto.command() == 'aws-network-firewall-describe-firewall-policy':
            human_readable, outputs, response = describe_firewall_policy_command(
                args)
        elif demisto.command() == 'aws-network-firewall-describe-logging-configuration':
            human_readable, outputs, response = describe_logging_configuration_command(
                args)
        elif demisto.command() == 'aws-network-firewall-describe-resource-policy':
            human_readable, outputs, response = describe_resource_policy_command(
                args)
        elif demisto.command() == 'aws-network-firewall-describe-rule-group':
            human_readable, outputs, response = describe_rule_group_command(
                args)
        elif demisto.command() == 'aws-network-firewall-disassociate-subnets':
            human_readable, outputs, response = disassociate_subnets_command(
                args)
        elif demisto.command() == 'aws-network-firewall-list-firewall-policies':
            human_readable, outputs, response = list_firewall_policies_command(
                args)
        elif demisto.command() == 'aws-network-firewall-list-firewalls':
            human_readable, outputs, response = list_firewalls_command(args)
        elif demisto.command() == 'aws-network-firewall-list-rule-groups':
            human_readable, outputs, response = list_rule_groups_command(args)
        elif demisto.command() == 'aws-network-firewall-list-tags-for-resource':
            human_readable, outputs, response = list_tags_for_resource_command(
                args)
        elif demisto.command() == 'aws-network-firewall-put-resource-policy':
            human_readable, outputs, response = put_resource_policy_command(
                args)
        elif demisto.command() == 'aws-network-firewall-tag-resource':
            human_readable, outputs, response = tag_resource_command(args)
        elif demisto.command() == 'aws-network-firewall-untag-resource':
            human_readable, outputs, response = untag_resource_command(args)
        elif demisto.command() == 'aws-network-firewall-update-firewall-delete-protection':
            human_readable, outputs, response = update_firewall_delete_protection_command(
                args)
        elif demisto.command() == 'aws-network-firewall-update-firewall-description':
            human_readable, outputs, response = update_firewall_description_command(
                args)
        elif demisto.command() == 'aws-network-firewall-update-firewall-policy':
            human_readable, outputs, response = update_firewall_policy_command(
                args)
        elif demisto.command() == 'aws-network-firewall-update-firewall-policy-change-protection':
            human_readable, outputs, response = update_firewall_policy_change_protection_command(
                args)
        elif demisto.command() == 'aws-network-firewall-update-logging-configuration':
            human_readable, outputs, response = update_logging_configuration_command(
                args)
        elif demisto.command() == 'aws-network-firewall-update-rule-group':
            human_readable, outputs, response = update_rule_group_command(args)
        elif demisto.command() == 'aws-network-firewall-update-subnet-change-protection':
            human_readable, outputs, response = update_subnet_change_protection_command(
                args)
        return_outputs(human_readable, outputs, response)

    except ResponseParserError as e:
        return_error('Could not connect to the AWS endpoint. Please check that the region is valid. {error}'.format(
            error=type(e)))
        LOG(e)
    except Exception as e:
        LOG(e)
        return_error('Error has occurred in the AWS network-firewall Integration: {code} {message}'.format(
            code=type(e), message=e))


if __name__ in ["__builtin__", "builtins", '__main__']:  # pragma: no cover
    main()
