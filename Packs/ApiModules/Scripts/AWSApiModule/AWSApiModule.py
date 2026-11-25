import boto3
from boto3 import Session
from botocore.config import Config
from botocore.client import BaseClient as BotoClient
from botocore.exceptions import ClientError
import demistomock as demisto  # noqa: F401

from concurrent.futures import ThreadPoolExecutor
from enum import Enum
from datetime import date, datetime

from CommonServerPython import *

from CommonServerUserPython import *

from COOCApiModule import *  # noqa: E402

STS_ENDPOINTS = {
    "us-gov-west-1": "https://sts.us-gov-west-1.amazonaws.com",
    "us-gov-east-1": "https://sts.us-gov-east-1.amazonaws.com",
}  # See: https://docs.aws.amazon.com/general/latest/gr/sts.html
MAX_TAGS = 50
MAX_FILTERS = 50
MAX_FILTER_VALUES = 200
MAX_LIMIT_VALUE = 1000
DEFAULT_LIMIT_VALUE = 50
MAX_TARGET_VALUES = 5
MAX_TRIPLE_FILTER_VALUE = 5

# COOC (AWSIntegration) client defaults
DEFAULT_MAX_RETRIES: int = 5
DEFAULT_MAX_WORKERS: int = 5
DEFAULT_SESSION_NAME = "cortex-session"
DEFAULT_PROXYDOME_CERTFICATE_PATH = os.getenv("EGRESSPROXY_CA_PATH") or "/etc/certs/egress.crt"
DEFAULT_PROXYDOME = os.getenv("CRTX_HTTP_PROXY") or "10.181.0.100:11117"
DEFAULT_REGION = "us-east-1"

# Commands whose boto3 service name can't be derived from the command name (aws-<service>-...).
COMMAND_SERVICE_MAP = {
    "aws-billing-cost-usage-list": "ce",
    "aws-billing-forecast-list": "ce",
    "aws-billing-budgets-list": "budgets",
    "aws-billing-budget-notification-list": "budgets",
}

REQUIRED_ACTIONS: list[str] = [
    "ec2:RevokeSecurityGroupEgress",
    "ec2:ModifyImageAttribute",
    "ec2:ModifyInstanceAttribute",
    "ec2:ModifySnapshotAttribute",
    "ec2:RevokeSecurityGroupIngress",
    "ec2:CreateSnapshot",
    "ec2:DescribeVpcs",
    "ec2:DescribeSubnets",
    "ec2:DescribeIpamResourceDiscoveries",
    "ec2:DescribeIpamResourceDiscoveryAssociations",
    "ec2:DescribeImages",
    "ec2:CreateImage",
    "ec2:DeregisterImage",
    "ec2:CopyImage",
    "ec2:DescribeSnapshots",
    "ec2:DeleteSnapshot",
    "ec2:CopySnapshot",
    "ec2:DescribeRegions",
    "eks:ListClusters",
    "eks:DescribeCluster",
    "eks:AssociateAccessPolicy",
    "eks:CreateAccessEntry",
    "eks:TagResource",
    "eks:UpdateAccessEntry",
    "ec2:CreateSecurityGroup",
    "ec2:CreateNetworkAcl",
    "ec2:GetIpamDiscoveredPublicAddresses",
    "ec2:CreateTags",
    "ec2:DeleteSecurityGroup",
    "ec2:DescribeAddresses",
    "ec2:AllocateAddress",
    "ec2:AssociateAddress",
    "ec2:DisassociateAddress",
    "ec2:ReleaseAddress",
    "ec2:DescribeInstances",
    "ec2:DescribeInstanceStatus",
    "ec2:DescribeSecurityGroups",
    "ec2:AuthorizeSecurityGroupEgress",
    "ec2:AuthorizeSecurityGroupIngress",
    "ec2:ModifyInstanceMetadataOptions",
    "ec2:MonitorInstances",
    "ec2:UnmonitorInstances",
    "ec2:RebootInstances",
    "ec2:DescribeIamInstanceProfileAssociations",
    "ec2:GetPasswordData",
    "ec2:DescribeReservedInstances",
    "ec2:StartInstances",
    "ec2:StopInstances",
    "ec2:TerminateInstances",
    "ec2:RunInstances",
    "ec2:ModifyNetworkInterfaceAttribute",
    "ec2:CreateFleet",
    "ec2:DeleteFleets",
    "ec2:DescribeFleets",
    "ec2:DescribeFleetInstances",
    "ec2:ModifyFleet",
    "eks:UpdateClusterConfig",
    "ec2:DescribeVolumes",
    "ec2:ModifyVolume",
    "ec2:CreateVolume",
    "ec2:AttachVolume",
    "ec2:DetachVolume",
    "ec2:DeleteVolume",
    "ec2:DescribeLaunchTemplates",
    "ec2:CreateLaunchTemplate",
    "ec2:DeleteLaunchTemplate",
    "ec2:DeleteVpc",
    "ec2:CreateVpcEndpoint",
    "ec2:DescribeInternetGateways",
    "ec2:DetachInternetGateway",
    "ec2:DeleteInternetGateway",
    "ec2:DeleteSubnet",
    "ec2:CreateNetworkAclEntry",
    "ec2:DescribeKeyPairs",
    "ec2:AllocateHosts",
    "ec2:ReleaseHosts",
    "ec2:CreateTrafficMirrorSession",
    "ssm:ListAssociationVersions",
    "ssm:DescribeAssociation",
    "ssm:ListAssociations",
    "ssm:GetInventory",
    "ssm:AddTagsToResource",
    "ssm:RemoveTagsFromResource",
    "ssm:ListTagsForResource",
    "ssm:ListDocuments",
    "ssm:DescribeDocument",
    "ssm:DescribeAutomationExecutions",
    "ssm:StartAutomationExecution",
    "ssm:GetAutomationExecution",
    "ssm:StopAutomationExecution",
    "ssm:ListCommands",
    "ssm:CancelCommand",
    "ssm:SendCommand",
    "ssm:DescribeParameters",
    "kms:CreateGrant",
    "kms:Decrypt",
    "kms:DescribeKey",
    "kms:GenerateDataKey",
    "kms:EnableKeyRotation",
    "secretsmanager:CreateSecret",
    "secretsmanager:RotateSecret",
    "secretsmanager:TagResource",
    "rds:AddTagsToResource",
    "rds:CreateTenantDatabase",
    "rds:ModifyDBCluster",
    "rds:DescribeDBInstances",
    "rds:ModifyDBClusterSnapshotAttribute",
    "rds:ModifyDBInstance",
    "rds:ModifyDBSnapshotAttribute",
    "redshift:ModifyCluster",
    "s3:CreateBucket",
    "s3:ListAllMyBuckets",
    "s3:ListBucket",
    "s3:PutBucketAcl",
    "s3:PutBucketLogging",
    "s3:PutBucketVersioning",
    "s3:PutBucketPolicy",
    "s3:PutBucketPublicAccessBlock",
    "s3:PutObject",
    "s3:GetObject",
    "s3:GetBucketPolicy",
    "s3:GetBucketWebsite",
    "s3:GetBucketAcl",
    "s3:GetBucketPublicAccessBlock",
    "s3:GetEncryptionConfiguration",
    "s3:DeleteBucketPolicy",
    "s3:ListBuckets",
    "s3:DeleteBucket",
    "iam:PassRole",
    "iam:DeleteLoginProfile",
    "iam:PutUserPolicy",
    "iam:RemoveRoleFromInstanceProfile",
    "iam:UpdateAccessKey",
    "iam:GetAccountPasswordPolicy",
    "iam:UpdateAccountPasswordPolicy",
    "iam:GetAccountAuthorizationDetails",
    "ecs:UpdateClusterSettings",
    "acm:UpdateCertificateOptions",
    "cloudtrail:DescribeTrails",
    "lambda:GetFunctionConfiguration",
    "lambda:GetFunctionUrlConfig",
    "lambda:GetPolicy",
    "lambda:InvokeFunction",
    "lambda:UpdateFunctionUrlConfig",
    "lambda:UpdateFunctionConfiguration",
    "lambda:GetFunction",
    "lambda:ListFunctions",
    "lambda:ListAliases",
    "lambda:GetAccountSettings",
    "lambda:ListVersionsByFunction",
    "lambda:DeleteFunctionUrlConfig",
    "lambda:CreateFunction",
    "lambda:ListLayerVersions",
    "lambda:DeleteFunction",
    "lambda:DeleteLayerVersion",
    "lambda:PublishLayerVersion",
    "elasticloadbalancing:ModifyLoadBalancerAttributes",
    "ce:GetCostAndUsage",
    "ce:GetCostForecast",
    "budgets:DescribeBudgets",
    "budgets:DescribeNotificationsForBudget",
    "logs:CreateLogGroup",
    "logs:CreateLogStream",
    "logs:DeleteLogGroup",
    "logs:DeleteLogStream",
    "logs:FilterLogEvents",
    "logs:DescribeLogGroups",
    "logs:DescribeLogStreams",
    "logs:PutRetentionPolicy",
    "logs:DeleteRetentionPolicy",
    "logs:PutLogEvents",
    "logs:PutMetricFilter",
    "logs:DeleteMetricFilter",
    "logs:DescribeMetricFilters",
    "logs:TagResource",
    "network-firewall:DescribeFirewall",
    "network-firewall:ListFirewalls",
    "network-firewall:DescribeFirewallPolicy",
    "network-firewall:CreateFirewall",
    "network-firewall:DeleteFirewall",
    "network-firewall:UpdateFirewallDeleteProtection",
    "network-firewall:UpdateFirewallDescription",
    "network-firewall:UpdateSubnetChangeProtection",
    "network-firewall:AssociateSubnets",
    "network-firewall:DisassociateSubnets",
    "network-firewall:TagResource",
    "network-firewall:ListFirewallPolicies",
    "network-firewall:CreateFirewallPolicy",
    "network-firewall:UpdateFirewallPolicy",
    "network-firewall:DeleteFirewallPolicy",
    "network-firewall:AssociateFirewallPolicy",
    "network-firewall:UpdateFirewallPolicyChangeProtection",
    "network-firewall:CreateRuleGroup",
    "network-firewall:DeleteRuleGroup",
    "network-firewall:DescribeRuleGroup",
    "network-firewall:ListRuleGroups",
    "network-firewall:UpdateRuleGroup",
    "network-firewall:DeleteResourcePolicy",
    "network-firewall:PutResourcePolicy",
    "network-firewall:DescribeResourcePolicy",
    "network-firewall:ListTagsForResource",
    "network-firewall:UntagResource",
    "network-firewall:DescribeLoggingConfiguration",
    "network-firewall:UpdateLoggingConfiguration",
]


def validate_params(aws_default_region, aws_role_arn, aws_role_session_name, aws_access_key_id, aws_secret_access_key):
    """
    Validates that the provided parameters are compatible with the appropriate authentication method.
    """
    if not aws_default_region:
        raise DemistoException("You must specify AWS default region.")

    if bool(aws_access_key_id) != bool(aws_secret_access_key):
        raise DemistoException("You must provide Access Key id and Secret key id to configure the instance with credentials.")
    if bool(aws_role_arn) != bool(aws_role_session_name):
        raise DemistoException("Role session name is required when using role ARN.")


def extract_session_from_secret(secret_key, session_token):
    """
    Extract the session token from the secret_key field.
    """
    if secret_key and "@@@" in secret_key and not session_token:
        return secret_key.split("@@@")[0], secret_key.split("@@@")[1]
    else:
        return secret_key, session_token


def handle_port_range(args: dict) -> tuple:
    """
    Parse and extract port range information from command arguments.

    Handles port specification in multiple formats:
    - Individual from_port and to_port arguments
    - Single port argument that can be a port number or range (e.g., "80" or "80-443")

    Args:
        args (dict): Command arguments dictionary containing port specifications

    Returns:
        tuple: A tuple containing (from_port, to_port) as integers, or (None, None) if no ports specified
    """
    from_port = arg_to_number(args.get("from_port"))
    to_port = arg_to_number(args.get("to_port"))

    def parse_port_range(port: str) -> tuple[Optional[int], Optional[int]]:
        """Parse port argument which can be a single port or range (min-max)."""
        if not port:
            return None, None

        if "-" in port:
            from_port, to_port = port.split("-", 1)
            return int(from_port.strip()), int(to_port.strip())
        else:
            _port: int = int(port.strip())
            return _port, _port

    if args.get("port") and (not from_port and not to_port):
        from_port, to_port = parse_port_range(args.get("port", ""))
    return from_port, to_port


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
                f"Could not parse field: {tag}. Please make sure you provided like so: key=abc,value=123;key=fed,value=456"
            )
        tags.append({"Key": match_tag.group(1), "Value": match_tag.group(2)})

    return tags


def print_debug_logs(client: BotoClient, message: str):
    """
    Print debug logs with service prefix and command context.
    Args:
        client (BotoClient): The AWS client object
        message (str): The debug message to log
    """
    service_name = client.meta.service_model.service_name
    demisto.debug(f"[{service_name}] {demisto.command()}: {message}")


def convert_datetimes_to_iso_safe(data):
    """
    Converts datetime objects in a data structure to ISO 8601 strings
    by serializing to and then deserializing from JSON using a custom encoder.
    """
    json_string = json.dumps(data, cls=ISOEncoder)
    return json.loads(json_string)


def parse_filter_field(filter_string: str | None):
    """
    Parses a list representation of name and values with the form of 'name=<name>,values=<values>.
    You can specify up to 50 filters and up to 200 values per filter in a single request.
    Filter strings can be up to 255 characters in length.
    Args:
        filter_string: The name and values list
    Returns:
        A list of dicts with the form {"Name": <key>, "Values": [<value>]}
    """
    filters = []
    list_filters = argToList(filter_string, separator=";")
    if len(list_filters) > MAX_FILTERS:
        list_filters = list_filters[0:50]
        demisto.debug("Number of filter is larger then 50, parsing only first 50 filters.")
    regex = re.compile(
        r"^name=([\w:.-]+),values=([ \w@,.*-\/:]+)",
        flags=re.I,
    )
    for filter in list_filters:
        match_filter = regex.match(filter)
        if match_filter is None:
            raise ValueError(
                f"Could not parse field: {filter}. Please make sure you provided "
                "like so: name=<name>,values=<values>;name=<name>,values=<value1>,<value2>..."
            )
        demisto.debug(
            f'Number of filter values for filter {match_filter.group(1)} is {len(match_filter.group(2).split(","))}'
            f' if larger than {MAX_FILTER_VALUES},'
            f' parsing only first {MAX_FILTER_VALUES} values.'
        )
        filters.append({"Name": match_filter.group(1), "Values": match_filter.group(2).split(",")[0:MAX_FILTER_VALUES]})

    return filters


def parse_resource_ids(resource_id: str | None) -> list[str]:
    if resource_id is None:
        raise ValueError("Resource ID cannot be empty")
    id_list = resource_id.replace(" ", "")
    resource_ids = id_list.split(",")
    return resource_ids


def parse_target_field(target_string: str | None):
    """
    Parses a list representation of key and values with the form of 'key=<key>,values=<values>.
    the maximum number of values for a key might be lower than the global maximum of 50.
    Key minimum length of 1, maximum length of 163.

    Args:
        target_string (str): The key and values list
    Returns:
        A list of dicts with the form {"Key": <key>, "Values": [<value>]}
    """
    targets = []
    list_targets = argToList(target_string, separator=";")
    regex = re.compile(
        r"^key=(^[\\p{L}\\p{Z}\\p{N}_.:/=\-@]*$|resource-groups:ResourceTypeFilters|resource-groups:Name),"
        r"values=([ \w@,.*-\/:]+)",
        flags=re.I,
    )
    for target in list_targets:
        match_target = regex.match(target)
        if match_target is None:
            raise ValueError(
                f"Could not parse target: {target}. Please make sure you provided "
                "like so: key=<key>,values=<values>;key=<key>,values=<value1>,<value2>... And the key matches the regex "
                "pattern required by AWS documentation. For more information see "
                "https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_Target.html#API_Target_Contents"
            )
        demisto.debug(
            f'Number of target values for {match_target.group(1)} is {len(match_target.group(2).split(","))}'
            f' if larger than {MAX_TARGET_VALUES},'
            f' parsing only first {MAX_TARGET_VALUES} values.'
        )
        targets.append({"Key": match_target.group(1), "Values": match_target.group(2).split(",")[0:MAX_TARGET_VALUES]})

    return targets


def parse_key_values_2_dict(parameters_str: str) -> dict:
    """
    Parses a list representation of key and values 'key=<key1>,values=<value>,<value>;key=<key2>,values=<value>,<value>.

    Args:
        parameters_str (str): The key and values list
    Returns:
        A dictionary containing the parameters
        {"key1" : [ "string", "string"], "key2" : [ "string", "string"]}
    """
    if not parameters_str:
        return {}

    parameters = {}
    list_parameters = argToList(parameters_str, separator=";")
    regex = re.compile(
        r"^key=([\w:.-]+),values=([ \w@,.*-\/:]+)",
        flags=re.I,
    )
    for param in list_parameters:
        match_param = regex.match(param)
        if match_param is None:
            raise ValueError(
                f"Could not parse the parameter: {param}. Please make sure you provided "
                "like so: key=<key>,values=<values>;key=<key>,values=<value1>,<value2>..."
            )
        demisto.debug(f'Number of parameter values for filter {match_param.group(1)} is {len(match_param.group(2).split(","))}')
        parameters[match_param.group(1)] = match_param.group(2).split(",")
    return parameters


def parse_key_1_value_to_dict(key_value_str: str) -> dict:
    """
    Parses a list representation of key and value 'key=<key1>,value=<value>;key=<key2>,value=<value>.

    Args:
        key_value_str (str): The key and values list
    Returns:
        A dictionary containing the parameters
        {"key1" : "value", "key2" : "value"}
    """
    if not key_value_str:
        return {}

    results = {}
    list_variables = argToList(key_value_str, separator=";")
    regex = re.compile(
        r"^key=(\b[^0-9][\w]+),value=([ \w@,.*-\/:]+)",
        flags=re.I,
    )
    for var in list_variables:
        match_var = regex.match(var)
        if match_var is None:
            raise ValueError(
                f"Could not parse the parameter: {var}. Please make sure you provided "
                "like so: key=<key>,value=<value>;key=<key>,value=<value2>..."
            )
        results[match_var.group(1)] = match_var.group(2)
    return results


def parse_name_value_type_format_filter(filter_string: str | None):
    """
    Parses a list representation of key, values and type with the form of 'key=<key>,values=<values>,type=<type>'.
    You can specify up to 50 filters, up to 200 values, and 1 type per filter in a single request.
    Args:
        filter_string: The key, values and type list
    Returns:
        A list of dicts with the form {"Key": <key>, "Values": [<value>], "Type": <type>}
    """
    filters = []
    list_filters = argToList(filter_string, separator=";")
    if len(list_filters) > MAX_TRIPLE_FILTER_VALUE:
        list_filters = list_filters[0:MAX_TRIPLE_FILTER_VALUE]
        demisto.debug(
            f"Number of filter is larger then {MAX_TRIPLE_FILTER_VALUE}, parsing only first {MAX_TRIPLE_FILTER_VALUE} filters."
        )
    regex = re.compile(
        r"^key=([\w:.-]+),values=([ \w@,.*-\/:]+),type=([\w:.-]+)",
        flags=re.I,
    )
    for f in list_filters:
        match_filter = regex.match(f)
        if match_filter is None:
            raise ValueError(
                f"Could not parse field: {f}. Please make sure you provided "
                "like so: key=<key>,values=<values>,type=<type>;key=<key>,values=<value1>,<value2>,type=<type>..."
            )
        demisto.debug(
            f'Number of filter values for filter {match_filter.group(1)} is {len(match_filter.group(2).split(","))}'
            f' if larger than {MAX_FILTER_VALUES},'
            f' parsing only first {MAX_FILTER_VALUES} values.'
        )
        filters.append(
            {
                "Key": match_filter.group(1),
                "Values": match_filter.group(2).split(",")[0:MAX_FILTER_VALUES],
                "Type": match_filter.group(3),
            }
        )

    return filters


def parse_parameter_filters(filter_string: str | None) -> list[dict[str, Any]]:
    """
    Parses a list representation of SSM Parameter Store filters with the form of
    'key=<key>,option=<option>,values=<values>'. The option pair is optional (AWS defaults it to Equals).
    The values pair must be last, so everything after it is treated as a comma-separated list of values.
    Args:
        filter_string: The key, option and values list, separated by ';'.
    Returns:
        A list of dicts with the form {"Key": <key>, "Values": [<value>], "Option": <option>}
    """
    filters: list[dict[str, Any]] = []
    # The key and values character sets follow the AWS tag key/value pattern (letters, digits, spaces, and _ . : / = + - @),
    # plus * in values. The negative lookahead rejects an option pair placed after the values pair.
    regex = re.compile(
        r"^key=(?P<key>[\w :./=+@-]+),(?:option=(?P<option>\w+),)?values=(?!(?:[^,]*,)*\s*option=)(?P<values>[\w ,:./=+@*-]+)$",
        flags=re.I,
    )
    for parameter_filter in argToList(filter_string, separator=";"):
        if not parameter_filter:
            continue
        match_filter = regex.match(parameter_filter.strip())
        if match_filter is None:
            raise ValueError(
                f"Could not parse the filter: {parameter_filter}. Please make sure you provided "
                "like so: key=<key>,values=<value1>,<value2>;key=<key>,option=<option>,values=<value>..."
            )
        values = [value for value in argToList(match_filter["values"]) if value]
        if not values:
            raise ValueError(f"Could not parse the filter: {parameter_filter}. The values pair must contain at least one value.")
        filters.append(
            remove_empty_elements(
                {
                    "Key": match_filter["key"],
                    "Option": match_filter["option"],
                    "Values": values,
                }
            )
        )

    return filters


def parse_resource_arn_priority_field(refs_string: str | None) -> list:
    """
    Parses a list representation of stateless rule group references with the form of
    'ResourceArn=<arn>,Priority=<priority>;ResourceArn=<arn>,Priority=<priority>'.

    Args:
        refs_string: The references list string.
    Returns:
        A list of dicts with the form {"ResourceArn": <arn>, "Priority": <priority>}.
    """
    references: list = []
    list_refs = argToList(refs_string, separator=";")
    regex = re.compile(r"^ResourceArn=(arn:aws.*),Priority=(\d+)$", flags=re.UNICODE)
    for ref in list_refs:
        match_ref = regex.match(ref)
        if match_ref is None:
            raise ValueError(
                f"Could not parse field: {ref}. Please make sure you provided like so: "
                "ResourceArn=arn:aws1,Priority=priority1;ResourceArn=arn:aws2,Priority=priority2"
            )
        references.append({"ResourceArn": match_ref.group(1), "Priority": int(match_ref.group(2))})

    return references


def parse_key_value_items_field(items_string: str | None, required_key: str, format_hint: str) -> list[dict]:
    """
    Parses a list representation of items with the form of
    'Key1=<value>,Key2=<value>;Key1=<value>,Key2=<value>'.

    Each item is separated by ';' and its fields by ','. Every field must be provided as 'Key=Value',
    and the given required_key must be present in each item.

    Args:
        items_string: The items list string.
        required_key: The key that must be present in each parsed item.
        format_hint: An example of the expected format, appended to error messages.
    Returns:
        A list of dicts, each mapping the parsed field keys to their values.
    """
    items: list[dict] = []
    for item in argToList(items_string, separator=";"):
        fields: dict = {}
        for field in argToList(item, separator=","):
            key, sep, value = field.partition("=")
            if not sep or not value:
                raise ValueError(f"Could not parse field: {item}. Please make sure you provided like so: {format_hint}")
            fields[key.strip()] = value.strip()

        if required_key not in fields:
            raise ValueError(f"Could not parse field: {item}. {required_key} is required for each item.")

        items.append(fields)

    return items


def parse_stateful_rule_group_references_field(refs_string: str | None) -> list:
    """
    Parses a list representation of stateful rule group references with the form of
    'ResourceArn=<arn>,Priority=<priority>,Override=<action>,DeepThreatInspection=<bool>;ResourceArn=<arn>,Priority=<priority>'.

    Each reference is separated by ';' and its fields by ','. Only ResourceArn is required; Priority, Override
    (mapped to {"Action": <action>}) and DeepThreatInspection are optional and dropped when not provided.

    Args:
        refs_string: The references list string.
    Returns:
        A list of dicts with the form
        {"ResourceArn": <arn>, "Priority": <priority>, "Override": {"Action": <action>}, "DeepThreatInspection": <bool>}.
    """
    format_hint = (
        "ResourceArn=arn:aws1,Priority=priority1,Override=action1,DeepThreatInspection=true;"
        "ResourceArn=arn:aws2,Priority=priority2"
    )
    references: list = []
    for fields in parse_key_value_items_field(refs_string, required_key="ResourceArn", format_hint=format_hint):
        if not re.match(r"^arn:aws", fields["ResourceArn"]):
            raise ValueError(f"Could not parse field: {fields}. ResourceArn must be a valid ARN starting with 'arn:aws'.")

        reference = {
            "ResourceArn": fields.get("ResourceArn"),
            "Priority": arg_to_number(fields.get("Priority")),
            "Override": {"Action": fields.get("Override")},
            "DeepThreatInspection": arg_to_bool_or_none(fields.get("DeepThreatInspection")),
        }
        references.append(remove_empty_elements(reference))

    return references


def parse_subnet_mappings_field(mappings_string: str | None) -> list:
    """
    Parses a list representation of subnet mappings with the form of
    'SubnetId=<id>,IPAddressType=<type>;SubnetId=<id>,IPAddressType=<type>'.

    Each mapping is separated by ';' and its fields by ','. Only SubnetId is required; IPAddressType is
    optional and dropped when not provided.

    Args:
        mappings_string: The subnet mappings list string.
    Returns:
        A list of dicts with the form {"SubnetId": <id>, "IPAddressType": <type>}.
    """
    format_hint = "SubnetId=id1,IPAddressType=type1;SubnetId=id2,IPAddressType=type2"
    mappings: list = []
    for fields in parse_key_value_items_field(mappings_string, required_key="SubnetId", format_hint=format_hint):
        subnet_mapping = {
            "SubnetId": fields.get("SubnetId"),
            "IPAddressType": fields.get("IPAddressType"),
        }
        mappings.append(remove_empty_elements(subnet_mapping))

    return mappings


def parse_json_arg(args: dict, arg_name: str) -> dict | list | None:
    """
    Parses a single JSON-string command argument into its corresponding Python object, raising a clear
    per-argument error when the value is not valid JSON so the user knows exactly which argument to fix.

    Args:
        args (dict): The command arguments dictionary to read the value from.
        arg_name (str): The name of the command argument to read from ``args`` and parse as JSON.

    Returns:
        dict | list | None: The parsed Python object (typically a dict or list),
            or None if the argument is missing or empty.

    Raises:
        DemistoException: If the argument value is present but is not valid JSON.
    """
    raw_value = args.get(arg_name)
    if not raw_value:
        return None
    try:
        return json.loads(raw_value)
    except json.JSONDecodeError as error:
        raise DemistoException(f"Invalid JSON in '{arg_name}': {error}")


def validate_iso8601_date(dt: str | None) -> str | None:
    """
    Validates that a date string matches the AWS UTC timestamp format and returns it unchanged.

    AWS requires timestamps in UTC format: YYYY-MM-DDTHH:MM:SSZ
    (e.g. '2024-01-15T10:30:00Z').

    Args:
        dt (str | None): A date string expected in AWS UTC format (YYYY-MM-DDTHH:MM:SSZ).

    Returns:
        str | None: The original date string if valid, or None if dt is falsy.

    Raises:
        DemistoException: If the date string does not match the required AWS UTC format.
    """
    if not dt:
        return None
    try:
        datetime.strptime(dt, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as e:
        raise DemistoException(
            f"Invalid date format: '{dt}'. " f"Expected AWS UTC format: YYYY-MM-DDTHH:MM:SSZ (e.g. '2024-01-15T10:30:00Z').\n{e}"
        )
    return dt


def build_pagination_kwargs(
    args: Dict[str, Any],
    minimum_limit: int = 1,
    max_limit: int = MAX_LIMIT_VALUE,
    next_token_name: str = "NextToken",
    limit_name: str = "MaxResults",
) -> Dict[str, Any]:
    """
    Build pagination parameters for AWS API calls with proper validation and limits.

    Args:
        args (Dict[str, Any]): Command arguments containing pagination parameters
        minimum_limit (int): The minimum possible limit for the pagination command.
        max_limit (int): The maximum possible limit for the pagination command.
        next_token_name (str): The name of the next token argument in AWS.
        limit_name (str): The name of the limit argument in AWS.

    Returns:
        Dict[str, Any]: Validated pagination parameters for AWS API

    Raises:
        ValueError: If limit exceeds maximum allowed value or is invalid
    """
    kwargs: Dict[str, Any] = {}

    limit_arg = args.get("limit")

    # Parse and validate limit
    try:
        if limit_arg is not None:
            limit = arg_to_number(limit_arg)
        else:
            limit = DEFAULT_LIMIT_VALUE  # Default limit
    except (ValueError, TypeError) as e:
        raise ValueError(f"Invalid limit parameter: {limit_arg}. Must be a valid number.") from e

    # Validate limit lower constraints
    if limit is not None and limit < minimum_limit:
        raise ValueError(f"Limit must be at least {minimum_limit}.")

    # AWS API upper constraints
    if limit is not None and limit > max_limit:
        demisto.debug(f"Requested limit {limit} exceeds maximum {max_limit}, using {max_limit}")
        limit = max_limit

    # Handle pagination with next_token (for continuing previous requests)
    if next_token := args.get("next_token"):
        if (not isinstance(next_token, str)) or (len(next_token.strip()) == 0):
            raise ValueError("next_token must be a non-empty string")
        kwargs[next_token_name] = next_token.strip()
    kwargs.update({limit_name: limit})
    return kwargs


def process_instance_data(instance: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process and extract relevant data from a single EC2 instance.

    Args:
        instance (Dict[str, Any]): Raw instance data from AWS API

    Returns:
        Dict[str, Any]: Processed instance data
    """
    instance_data = {
        "InstanceId": instance.get("InstanceId"),
        "ImageId": instance.get("ImageId"),
        "State": instance.get("State", {}).get("Name"),
        "PublicIPAddress": instance.get("PublicIpAddress"),
        "PrivateIpAddress": instance.get("PrivateIpAddress"),
        "Type": instance.get("InstanceType"),
        "LaunchDate": instance.get("LaunchTime"),
        "PublicDNSName": instance.get("PublicDnsName"),
        "Monitoring": instance.get("Monitoring", {}).get("State"),
        "AvailabilityZone": instance.get("Placement", {}).get("AvailabilityZone"),
    }
    instance_data = remove_empty_elements(instance_data)
    return instance_data


def serialize_response_with_datetime_encoding(response: Dict[str, Any]) -> Dict[str, Any]:
    """
    Serialize AWS API response with proper datetime encoding for JSON compatibility.

    Args:
        response (Dict[str, Any]): Raw AWS API response containing datetime objects

    Returns:
        Dict[str, Any]: Serialized response with datetime objects converted to strings

    Raises:
        DemistoException: If serialization fails
    """
    try:
        # Use DatetimeEncoder to handle datetime objects
        serialized_json = json.dumps(response, cls=DatetimeEncoder)
        return json.loads(serialized_json)
    except (ValueError, TypeError) as e:
        demisto.error(f"Failed to serialize response with datetime encoding: {str(e)}")
    except Exception as e:
        demisto.error(f"Unexpected error during response serialization: {str(e)}")
    return response


class AWSServices(str, Enum):
    S3 = "s3"
    IAM = "iam"
    EC2 = "ec2"
    RDS = "rds"
    EKS = "eks"
    LAMBDA = "lambda"
    CloudTrail = "cloudtrail"
    ECS = "ecs"
    ACM = "acm"
    KMS = "kms"
    ELB = "elb"
    CostExplorer = "ce"
    BUDGETS = "budgets"
    SSM = "ssm"
    Redshift = "redshift"
    CloudWatchLogs = "logs"
    NetworkFirewall = "network-firewall"
    STS = "sts"


class DatetimeEncoder(json.JSONEncoder):
    # pylint: disable=method-hidden
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime("%Y-%m-%dT%H:%M:%S")
        elif isinstance(obj, date):
            return obj.strftime("%Y-%m-%d")
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


class AWSErrorHandler:
    """
    Centralized error handling for AWS boto3 client errors.
    Provides specialized handling for permission errors and general AWS API errors.
    """

    # Permission-related error codes that should be handled specially
    PERMISSION_ERROR_CODES = [
        "AccessDenied",
        "UnauthorizedOperation",
        "Forbidden",
        "AccessDeniedException",
        "UnauthorizedOperationException",
        "InsufficientPrivilegesException",
        "NotAuthorized",
    ]

    @classmethod
    def handle_response_error(cls, response: dict, account_id: str | None = None) -> None:
        """
        Handle boto3 response errors.
        For permission errors, returns a structured error entry using return_error.
        For other errors, raises DemistoException with informative error message.
        Args:
            err (ClientError): The boto3 ClientError exception
            account_id (str, optional): AWS account ID. If not provided, will try to get from demisto.args()
        """
        # Create informative error message
        detailed_error = (
            f"AWS API Error occurred while executing: {demisto.command()} with arguments: {list(demisto.args().keys())}\n"
            f"Request Id: {response.get('ResponseMetadata',{}).get('RequestId', 'N/A')}\n"
            f"HTTP Status Code: {response.get('ResponseMetadata',{}).get('HTTPStatusCode', 'N/A')}"
        )

        return_error(detailed_error)

    @classmethod
    def handle_client_error(cls, err: ClientError, account_id: str | None = None) -> None:
        """
        Handle boto3 client errors with special handling for permission issues.
        For permission errors, returns a structured error entry using return_error.
        For other errors, raises DemistoException with informative error message.
        Args:
            err (ClientError): The boto3 ClientError exception
            account_id (str, optional): AWS account ID. If not provided, will try to get from demisto.args()
        """
        try:
            demisto.debug(f"The original error message: {err}")
            error_code = err.response.get("Error", {}).get("Code")
            error_message = err.response.get("Error", {}).get("Message")
            http_status_code = err.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            demisto.debug(f"[AWSErrorHandler] Got a client error: {error_message}")
            if not error_code or not error_message or not http_status_code:
                return_error(err)
            # Check if this is a permission-related error
            if (error_code in cls.PERMISSION_ERROR_CODES) or (http_status_code in [401, 403]):
                cls._handle_permission_error(err, error_code, error_message, account_id)
            else:
                cls._handle_general_error(err, error_code, error_message)
        except Exception as e:
            demisto.debug(f"[AWSErrorHandler] Unhandled error: {str(e)}")
            return_error(err)

    @classmethod
    def _handle_permission_error(
        cls, err: ClientError, error_code: str, error_message: str, account_id: str | None = None
    ) -> None:
        """
        Handle permission-related errors by returning structured error entry.
        Args:
            err (ClientError): The boto3 ClientError exception
            error_code (str): The AWS error code
            error_message (str): The AWS error message
            account_id (str, optional): AWS account ID
        """
        # Get account_id from args if not provided
        if not account_id:
            account_id = demisto.args().get("account_id", "unknown")

        action = cls._extract_action_from_message(error_message)
        # When encountering an unauthorized error, an encoded authorization message may be returned with different
        # encoding each time. This will create different error entries for each unauthorized error and will confuse the user.
        # Therefore we will omit the actual encoded message.
        demisto.info(f"Original error message: {error_message}")
        error_entry = {
            "account_id": account_id,
            "message": cls.remove_encoded_authorization_message(error_message),
            "name": action,
        }
        demisto.debug(f"Permission error detected: {error_entry}")
        return_multiple_permissions_error([error_entry])

    @classmethod
    def remove_encoded_authorization_message(cls, message: str) -> str:
        """
        Remove encoded authorization messages from AWS error responses.
        Args:
            message (str): Original error message
        Returns:
            str: Cleaned error message without encoded authorization details
        """
        index = message.lower().find("encoded authorization failure message:")
        if index != -1:  # substring found
            return message[:index]
        else:
            return message

    @classmethod
    def _handle_general_error(cls, err: ClientError, error_code: str, error_message: str) -> None:
        """
        Handle general (non-permission) errors with informative error messages.
        Args:
            err (ClientError): The boto3 ClientError exception
            error_code (str): The AWS error code
            error_message (str): The AWS error message
        """
        # Get additional error details
        request_id = err.response.get("ResponseMetadata", {}).get("RequestId", "N/A")
        http_status = err.response.get("ResponseMetadata", {}).get("HTTPStatusCode", "N/A")

        # Create informative error message
        detailed_error = (
            f"AWS API Error occurred while executing: {demisto.command()} with arguments: {list(demisto.args().keys())}\n"
            f"Error Code: {error_code}\n"
            f"Error Message: {error_message}\n"
            f"HTTP Status Code: {http_status}\n"
            f"Request ID: {request_id}"
        )

        demisto.error(f"AWS API Error: {detailed_error}")
        return_error(detailed_error)

    @classmethod
    def _extract_action_from_message(cls, error_message: str) -> str:
        """
        Extract AWS permission name from error message using regex patterns.
        Args:
            error_message (str): The AWS error message
        Returns:
            str: The extracted permission name or 'unknown' if not found
        """
        # Sanitize input to prevent regex injection
        if not error_message or not isinstance(error_message, str):
            return "unknown"

        for action in REQUIRED_ACTIONS:
            try:
                match = re.search(action, error_message, re.IGNORECASE)
                if match and match.group(0) == action:
                    return action
            except re.error:
                pass

        return "unknown"


class AWSIntegration(CloudIntegration):
    """COOC AWS implementation of ``CloudIntegration``.

    Builds boto3 service clients for both authentication paths:

    - **Cortex Cloud platform**: short-lived CTS credentials, requests routed through ProxyDome.
    - **XSOAR / XSIAM marketplace**: access keys from the ``credentials`` integration parameter,
      optionally exchanged via STS ``AssumeRole`` when ``role_arn`` is configured.

    - **Registered commands** (``@AWSIntegration.register``): ``(client, args)``, or ``(args, client)``
      when registered with ``polling=True``.
    - **Existing commands** (``commands_mapping``): ``(client, args)``, or ``(args, client)`` when the
      ``polling_timeout`` argument is present.
    - **Multi-account**: when ``access_role_name`` and ``accounts_to_access`` are configured, the
      command runs once per account, each on its own ``AWSIntegration`` instance.
    """

    cloud_type = CloudTypes.AWS.value
    uses_proxy_env = True

    # ------------------------------------------------------------------
    # CloudIntegration implementation
    # ------------------------------------------------------------------

    def get_client(self) -> BotoClient:
        """Build a boto3 client for the service of ``self.command``."""
        return self.get_service_client(credentials=self.get_credentials(), service=self._resolve_service(self.command))

    def health_check(self, credentials: dict, account_id: str, connector_id: str) -> HealthCheckError | None:
        """Check that a client can be created for every AWS service.

        Args:
            credentials: CTS credentials for ``account_id``.
            account_id: The AWS account ID being checked.
            connector_id: The Cortex connector ID.

        Returns:
            ``None`` if all services connected, otherwise a single aggregated ``HealthCheckError``.
        """
        failed_services: list[str] = []
        try:
            for service in AWSServices:
                try:
                    self.get_service_client(
                        credentials=credentials,
                        service=service,
                        config=Config(connect_timeout=3, read_timeout=3, retries={"max_attempts": 1}),
                    )
                    demisto.info(f"[AWS Automation Health Check] Successfully created client for {service.value}")
                except Exception as service_error:
                    demisto.error(
                        f"[AWS Automation Health Check] Failed to create client for {service.value}: {str(service_error)}"
                    )
                    failed_services.append(service.value)

            if failed_services:
                error_msg = f"Failed to connect to AWS services: {', '.join(failed_services)}"
                demisto.info(f"[AWS Automation Health Check] Connectivity error: {error_msg}")
                return HealthCheckError(
                    account_id=account_id,
                    connector_id=connector_id,
                    message=error_msg,
                    error_type=ErrorType.CONNECTIVITY_ERROR,
                )

            demisto.info("[AWS Automation Health Check] All services connected successfully")
            return None

        except Exception as err:
            demisto.error(f"[AWS Automation Health Check] Unexpected error during health check: {err}")
            return HealthCheckError(
                account_id=account_id,
                connector_id=connector_id,
                message=f"Unexpected error during health check: {str(err)}",
                error_type=ErrorType.INTERNAL_ERROR,
            )

    def test_module(self) -> str:
        """Validate marketplace credentials by calling ``sts:GetCallerIdentity``.

        ``GetCallerIdentity`` requires no IAM permissions and validates the full auth chain,
        including assumed-role sessions. Building a boto3 client alone makes no network call,
        so invalid credentials would otherwise pass silently.
        """
        sts_client = self.get_service_client(
            credentials={},
            service=AWSServices.STS,
            config=Config(connect_timeout=5, read_timeout=5, retries={"max_attempts": 1}),
        )
        sts_client.get_caller_identity()
        demisto.info("[AWS] test-module: sts.GetCallerIdentity succeeded")
        return "ok"

    def handle_error(self, error: Exception) -> None:
        """Route boto3 ``ClientError``s through ``AWSErrorHandler``; any other error is handled by the base class."""
        if isinstance(error, ClientError):
            AWSErrorHandler.handle_client_error(error, self.account_id)
            return
        super().handle_error(error)

    def execute_command(self, commands_mapping: dict) -> CommandResults | list[CommandResults] | None:
        """Execute ``self.command``, fanning out across accounts when multi-account access is configured.

        When both ``access_role_name`` and ``accounts_to_access`` are set, the command runs in
        parallel for every listed account and per-account errors are returned as error entries
        without aborting the batch. Otherwise it runs once for ``self.account_id``.
        """
        # Set the STS regional endpoint mode once, on the main thread, before any parallel execution.
        if not self.connector_id and (regional := self.params.get("sts_regional_endpoint")):
            demisto.debug(f"Setting AWS_STS_REGIONAL_ENDPOINTS={regional}")
            os.environ["AWS_STS_REGIONAL_ENDPOINTS"] = regional.lower()

        role_name = (self.params.get("access_role_name") or "").removeprefix("role/")
        accounts = argToList(self.params.get("accounts_to_access"))
        if role_name and accounts:
            return self._execute_multi_account(commands_mapping, role_name, accounts)

        return self.execute_single_account(commands_mapping)

    def execute_single_account(self, commands_mapping: dict) -> CommandResults | list[CommandResults] | None:
        """Execute ``self.command`` once for ``self.account_id`` (registered handler first, then ``commands_mapping``)."""
        return super().execute_command(commands_mapping)

    def execute_mapped_command(self, handler: Callable) -> CommandResults | list[CommandResults] | None:
        """Call an existing command: ``(args, client)`` for polling commands, ``(client, args)`` otherwise.

        Existing polling commands are detected by the ``polling_timeout`` argument.
        """
        client = self.get_client()
        if self.args.get("polling_timeout") is not None:
            demisto.debug(f"The command={self.command} is a polling command, call it with args as the first argument.")
            return handler(self.args, client)
        return handler(client, self.args)

    # ------------------------------------------------------------------
    # AWS-specific helpers
    # ------------------------------------------------------------------

    def get_service_client(self, credentials: dict, service: AWSServices, config: Config | None = None) -> BotoClient:
        """Create and configure a boto3 client for ``service`` from ``self.params`` and ``self.args``.

        Args:
            credentials: CTS credentials. Empty on the marketplace path.
            service: The AWS service to build the client for.
            config: Additional botocore configuration merged on top of the base config.

        Returns:
            The configured boto3 client.
        """
        params = self.params
        region: str = self.args.get("region") or params.get("region", "") or DEFAULT_REGION
        is_platform_path: bool = bool(credentials) or bool(self.connector_id)

        aws_session = self._build_session(credentials, params, region, is_platform_path)

        read_timeout, connect_timeout = get_timeout(params.get("timeout"))
        retries_raw = params.get("retries")
        retries = min(int(retries_raw if retries_raw not in (None, "") else DEFAULT_MAX_RETRIES), 10)
        base_config = Config(connect_timeout=connect_timeout, read_timeout=read_timeout, retries={"max_attempts": retries})
        if is_platform_path:
            base_config = base_config.merge(
                Config(
                    proxies={"https": DEFAULT_PROXYDOME},
                    proxies_config={"proxy_ca_bundle": DEFAULT_PROXYDOME_CERTFICATE_PATH},
                )
            )
        client_config = base_config.merge(config) if config else base_config

        # Platform requests go through ProxyDome, which presents a self-signed cert. On the marketplace
        # path SSL verification is on unless the user checked "Trust any certificate (not secure)".
        verify_ssl: str | bool = (
            DEFAULT_PROXYDOME_CERTFICATE_PATH if is_platform_path else not argToBoolean(params.get("insecure", False))
        )
        endpoint_url: str | None = params.get("endpoint_url") or None

        client = aws_session.client(service.value, verify=verify_ssl, config=client_config, endpoint_url=endpoint_url)
        if is_platform_path:
            self._register_proxydome_header(client)
        return client

    @staticmethod
    def _resolve_service(command: str) -> AWSServices:
        """Map a command name (``aws-<service>-...``) to its AWS service."""
        if command in COMMAND_SERVICE_MAP:
            return AWSServices(COMMAND_SERVICE_MAP[command])
        if "network-firewall" in command:
            return AWSServices("network-firewall")
        return AWSServices(command.split("-")[1])

    @staticmethod
    def _build_session(credentials: dict, params: dict, region: str, is_platform_path: bool) -> Session:
        """Build a boto3 session from CTS credentials (platform) or configured access keys (marketplace)."""
        if is_platform_path:
            return Session(
                aws_access_key_id=credentials.get("key"),
                aws_secret_access_key=credentials.get("access_token"),
                aws_session_token=credentials.get("session_token"),
                region_name=region,
            )

        creds_param = params.get("credentials") or {}
        access_key_id: str = creds_param.get("identifier", "")
        secret_access_key: str = creds_param.get("password", "")
        if not (access_key_id and secret_access_key):
            raise DemistoException(
                "AWS credentials are not configured. Provide an Access Key and Secret Key "
                "on the integration instance, or run the integration through a Cortex Cloud connector."
            )

        if not params.get("role_arn"):
            return Session(aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key, region_name=region)

        tmp_creds = AWSIntegration._assume_role_credentials(params, access_key_id, secret_access_key, region)
        return Session(
            aws_access_key_id=tmp_creds["AccessKeyId"],
            aws_secret_access_key=tmp_creds["SecretAccessKey"],
            aws_session_token=tmp_creds["SessionToken"],
            region_name=region,
        )

    @staticmethod
    def _assume_role_credentials(params: dict, access_key_id: str, secret_access_key: str, region: str) -> dict:
        """Call STS ``AssumeRole`` with the marketplace access keys and return the temporary credentials.

        Returns:
            ``{"AccessKeyId", "SecretAccessKey", "SessionToken", ...}`` from the STS response.
        """
        role_arn: str = params.get("role_arn", "")
        role_session_name: str = params.get("role_session_name") or DEFAULT_SESSION_NAME
        session_duration = arg_to_number(params.get("session_duration"))
        sts_region: str = params.get("sts_region") or region
        sts_endpoint_url: str | None = params.get("sts_endpoint_url") or None

        sts_client = boto3.client(
            "sts",
            region_name=sts_region,
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            endpoint_url=sts_endpoint_url,
            config=Config(connect_timeout=10, read_timeout=10, retries={"max_attempts": 1}),
            verify=not argToBoolean(params.get("insecure", False)),
        )
        assume_kwargs: dict = {"RoleArn": role_arn, "RoleSessionName": role_session_name}
        if session_duration is not None:
            assume_kwargs["DurationSeconds"] = session_duration

        demisto.debug(f"[AWS] Calling sts.AssumeRole with {assume_kwargs=}")
        return sts_client.assume_role(**assume_kwargs)["Credentials"]

    @staticmethod
    def _register_proxydome_header(boto_client: BotoClient) -> None:
        """Inject the ProxyDome ``x-caller-id`` header into every request sent by ``boto_client``."""
        proxydome_token: str = get_proxydome_token()

        def _add_proxydome_header(request, **kwargs):
            request.headers["x-caller-id"] = proxydome_token

        boto_client.meta.events.register_last("before-send.*.*", _add_proxydome_header)

    def for_account(self, account_id: str, role_name: str) -> "AWSIntegration":
        """Return a new ``AWSIntegration`` for ``self.command`` in ``account_id``, assuming ``role_name`` there.

        Each instance has its own ``account_id`` and credentials cache, so parallel threads never share a token.
        """
        return type(self)(
            command=self.command,
            args=self.args | {self.account_id_arg: account_id},
            params=self.params | {"role_arn": f"arn:aws:iam::{account_id}:role/{role_name}"},
        )

    def _execute_multi_account(self, commands_mapping: dict, role_name: str, accounts: list[str]) -> list[CommandResults]:
        """Run ``self.command`` for each account in parallel, assuming ``role_name`` in every account."""
        max_workers = arg_to_number(self.params.get("max_workers")) or DEFAULT_MAX_WORKERS
        demisto.debug(f"[AWS] Multi-account fan-out: command={self.command}, {len(accounts)=}, {max_workers=}")

        def _run_for_account(account_id: str) -> list[CommandResults]:
            try:
                result = self.for_account(account_id, role_name).execute_single_account(commands_mapping)
                return self._tag_results_with_account(result, account_id)
            except Exception as e:
                demisto.error(f"[AWS] Error for account {account_id}: {e}")
                return [
                    CommandResults(
                        readable_output=f"#### Error for account `{account_id}`\n{e}",
                        entry_type=EntryType.ERROR,
                        content_format=EntryFormat.MARKDOWN,
                    )
                ]

        results: list[CommandResults] = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for account_results in executor.map(_run_for_account, accounts):
                results.extend(account_results)
        return results

    @staticmethod
    def _tag_results_with_account(result: CommandResults | list[CommandResults] | None, account_id: str) -> list[CommandResults]:
        """Prefix readable output with the account and add ``AccountId`` to dict outputs."""
        if result is None:
            return [CommandResults(readable_output=f"#### Result for account `{account_id}`:\nNo result returned.")]
        results_list = result if isinstance(result, list) else [result]
        for res in results_list:
            res.readable_output = f"#### Result for account `{account_id}`:\n{res.readable_output or ''}"
            outputs = res.outputs if isinstance(res.outputs, list) else [res.outputs]
            for output in outputs:
                if isinstance(output, dict):
                    output.setdefault("AccountId", account_id)
        return results_list


class AWSClient:
    def __init__(
        self,
        aws_default_region,
        aws_role_arn,
        aws_role_session_name,
        aws_role_session_duration,
        aws_role_policy,
        aws_access_key_id,
        aws_secret_access_key,
        verify_certificate,
        timeout,
        retries,
        aws_session_token=None,
        sts_endpoint_url=None,
        endpoint_url=None,
        sts_region=None,
    ):
        self.sts_endpoint_url = sts_endpoint_url
        self.endpoint_url = endpoint_url
        self.aws_default_region = aws_default_region
        self.aws_role_arn = aws_role_arn
        self.aws_role_session_name = aws_role_session_name
        # handle cases where aws_role_session_duration can be also empty string
        self.aws_role_session_duration = aws_role_session_duration if aws_role_session_duration else None
        self.aws_role_policy = aws_role_policy
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key, self.aws_session_token = extract_session_from_secret(aws_secret_access_key, aws_session_token)
        self.verify_certificate = verify_certificate
        self.sts_region = sts_region

        sts_regional_endpoint = demisto.params().get("sts_regional_endpoint") or None
        if sts_regional_endpoint:
            demisto.debug(f"Sets the environment variable AWS_STS_REGIONAL_ENDPOINTS={sts_regional_endpoint}")
            os.environ["AWS_STS_REGIONAL_ENDPOINTS"] = sts_regional_endpoint.lower()

        proxies = handle_proxy(proxy_param_name="proxy", checkbox_default_value=False)
        (read_timeout, connect_timeout) = AWSClient.get_timeout(timeout)
        if int(retries) > 10:
            retries = 10
        self.config = Config(
            connect_timeout=connect_timeout, read_timeout=read_timeout, retries={"max_attempts": int(retries)}, proxies=proxies
        )

    def update_config(self):
        command_config = {}
        retries = demisto.getArg("retries")  # Supports retries and timeout parameters on the command execution level
        if retries is not None:
            command_config["retries"] = {"max_attempts": int(retries)}
        timeout = demisto.getArg("timeout")
        if timeout is not None:
            (read_timeout, connect_timeout) = AWSClient.get_timeout(timeout)
            command_config["read_timeout"] = read_timeout
            command_config["connect_timeout"] = connect_timeout
        if retries or timeout:
            demisto.debug(f"Merging client config settings: {command_config}")
            self.config = self.config.merge(Config(**command_config))  # type: ignore[arg-type]

    def aws_session(
        self, service, region=None, role_arn=None, role_session_name=None, role_session_duration=None, role_policy=None
    ):
        kwargs = {}
        client = None

        self.update_config()

        if role_arn and role_session_name is not None:
            kwargs.update(
                {
                    "RoleArn": role_arn,
                    "RoleSessionName": role_session_name,
                }
            )
        elif self.aws_role_arn and self.aws_role_session_name is not None:
            kwargs.update(
                {
                    "RoleArn": self.aws_role_arn,
                    "RoleSessionName": self.aws_role_session_name,
                }
            )

        if role_session_duration is not None:
            kwargs.update({"DurationSeconds": int(role_session_duration)})
        elif self.aws_role_session_duration is not None:
            kwargs.update({"DurationSeconds": int(self.aws_role_session_duration)})

        if role_policy is not None:
            kwargs.update({"Policy": role_policy})
        elif self.aws_role_policy is not None:
            kwargs.update({"Policy": self.aws_role_policy})

        demisto.debug(f"{kwargs=}")
        self.sts_endpoint_url = self.sts_endpoint_url or STS_ENDPOINTS.get(region) or STS_ENDPOINTS.get(self.aws_default_region)

        calculated_sts_region = self.sts_region
        if not calculated_sts_region:
            calculated_sts_region = region if region else self.aws_default_region
        demisto.debug(
            f"Calculated sts region: {calculated_sts_region}, {self.sts_region=}, {region=}, {self.aws_default_region=}"
        )

        if kwargs and not self.aws_access_key_id:  # login with Role ARN
            if not self.aws_access_key_id:
                sts_client = boto3.client(
                    "sts",
                    config=self.config,
                    verify=self.verify_certificate,
                    region_name=calculated_sts_region,
                    endpoint_url=self.sts_endpoint_url,
                )
                sts_response = sts_client.assume_role(**kwargs)
                client = boto3.client(
                    service_name=service,
                    region_name=region if region else self.aws_default_region,
                    aws_access_key_id=sts_response["Credentials"]["AccessKeyId"],
                    aws_secret_access_key=sts_response["Credentials"]["SecretAccessKey"],
                    aws_session_token=sts_response["Credentials"]["SessionToken"],
                    verify=self.verify_certificate,
                    config=self.config,
                    endpoint_url=self.endpoint_url,
                )
        elif self.aws_access_key_id and (role_arn or self.aws_role_arn):  # login with Access Key ID and Role ARN
            sts_client = boto3.client(
                service_name="sts",
                region_name=calculated_sts_region,
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                verify=self.verify_certificate,
                config=self.config,
                endpoint_url=self.sts_endpoint_url,
            )
            kwargs.update(
                {
                    "RoleArn": role_arn or self.aws_role_arn,
                    "RoleSessionName": role_session_name or self.aws_role_session_name,
                }
            )
            sts_response = sts_client.assume_role(**kwargs)
            client = boto3.client(
                service_name=service,
                region_name=region if region else self.aws_default_region,
                aws_access_key_id=sts_response["Credentials"]["AccessKeyId"],
                aws_secret_access_key=sts_response["Credentials"]["SecretAccessKey"],
                aws_session_token=sts_response["Credentials"]["SessionToken"],
                verify=self.verify_certificate,
                config=self.config,
                endpoint_url=self.endpoint_url,
            )
        elif self.aws_session_token and not self.aws_role_arn:  # login with session token
            client = boto3.client(
                service_name=service,
                region_name=region if region else self.aws_default_region,
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                aws_session_token=self.aws_session_token,
                verify=self.verify_certificate,
                config=self.config,
                endpoint_url=self.endpoint_url,
            )
        elif self.aws_access_key_id and not self.aws_role_arn:  # login with access key id
            client = boto3.client(
                service_name=service,
                region_name=region if region else self.aws_default_region,
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                verify=self.verify_certificate,
                config=self.config,
                endpoint_url=self.endpoint_url,
            )
        else:  # login with default permissions, permissions pulled from the ec2 metadata
            client = boto3.client(
                service_name=service, region_name=region if region else self.aws_default_region, endpoint_url=self.endpoint_url
            )

        return client

    @staticmethod
    def get_timeout(timeout):
        if not timeout:
            timeout = "60,10"  # default values
        try:
            if isinstance(timeout, int):
                read_timeout = timeout
                connect_timeout = 10

            else:
                timeout_vals = timeout.split(",")
                read_timeout = int(timeout_vals[0])
                # the default connect timeout is 10
                connect_timeout = 10 if len(timeout_vals) == 1 else int(timeout_vals[1])

        except ValueError:
            raise DemistoException(
                "You can specify just the read timeout (for example 60) or also the connect "
                "timeout followed after a comma (for example 60,10). If a connect timeout is not "
                "specified, a default of 10 second will be used."
            )
        return read_timeout, connect_timeout
