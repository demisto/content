import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

# flake8: noqa
import boto3
import json
from botocore.config import Config
from botocore.parsers import ResponseParserError
import urllib3.util
from datetime import timezone
from dateparser import parse

# Disable insecure warnings
urllib3.disable_warnings()

'''PARAMETERS'''
AWS_DEFAULT_REGION = demisto.params().get('defaultRegion')
AWS_ROLE_ARN = demisto.params().get('roleArn')
AWS_ROLE_SESSION_NAME = demisto.params().get('roleSessionName')
AWS_ROLE_SESSION_DURATION = demisto.params().get('sessionDuration')
AWS_ROLE_POLICY = None
AWS_ACCESS_KEY_ID = demisto.params().get('access_key')
AWS_SECRET_ACCESS_KEY = demisto.params().get('secret_key')
VERIFY_CERTIFICATE = not demisto.params().get('insecure', True)
AWS_SH_SEVERITY = demisto.params().get('sh_severity')
ARCHIVE_FINDINGS = demisto.params().get('archiveFindings', False)
ADDITIONAL_FILTERS = demisto.params().get('additionalFilters', '')

'''HELPER FUNCTIONS'''


def parse_resource_ids(resource_ids: str) -> list:
    """
    Parses a string with comma separated ids to list of ids
    Args:
        resource_ids: Comma separated ids

    Returns:
        A list of ids
    """
    if not resource_ids:
        return []
    id_list = resource_ids.replace(" ", '')
    resourceIds = id_list.split(",")
    return resourceIds


def parse_tag_field(tags_str: str) -> list:
    """
    Parses a string representation of keys and values with the form of 'key=<key>,value=<value> separated by a ';'.
    Args:
        tags_str: The keys and values string

    Returns:
        A list of dicts with the form {'Key': <key>, 'Value': <value>}
    """
    tags = []
    regex = re.compile(
        r'key=([\w\d_:.-]+),value=([ /\w\d@_,.*-]+)', flags=re.I)
    regex_parse_result = regex.findall(tags_str)
    for key, value in regex_parse_result:
        tags.append({
            'Key': key,
            'Value': value
        })
    return tags


def generate_kwargs_for_get_findings(args: dict) -> dict:
    """
    Generates the kwargs for 'get_findings' command according to arguments in args.
    Args:
        args: Demisto args

    Returns:
        Kwargs suitable for get_findings command
    """
    kwargs = {
        'Filters': {
            'ProductArn': [{
                'Value': args.get('product_arn_value', None),
                'Comparison': args.get('product_arn_comparison', None),

            }],
            'AwsAccountId': [{
                'Value': args.get('aws_account_id_value', None),
                'Comparison': args.get('aws_account_id_comparison', None),

            }],
            'Id': [{
                'Value': args.get('id_value', None),
                'Comparison': args.get('id_comparison', None),

            }],
            'GeneratorId': [{
                'Value': args.get('generator_id_value', None),
                'Comparison': args.get('generator_id_comparison', None),

            }],
            'Type': [{
                'Value': args.get('type_value', None),
                'Comparison': args.get('type_comparison', None),

            }],
            'FirstObservedAt': [{
                'Start': args.get('first_observed_at_start', None),
                'End': args.get('first_observed_at_end', None),
                'DateRange': {
                    'Unit': args.get('date_range_unit', None),

                },

            }],
            'LastObservedAt': [{
                'Start': args.get('last_observed_at_start', None),
                'End': args.get('last_observed_at_end', None),
                'DateRange': {
                    'Unit': args.get('date_range_unit', None),
                },
            }],
            'CreatedAt': [{
                'Start': args.get('created_at_start', None),
                'End': args.get('created_at_end', None),
                'DateRange': {
                    'Unit': args.get('date_range_unit', None),
                },
            }],
            'UpdatedAt': [{
                'Start': args.get('updated_at_start', None),
                'End': args.get('updated_at_end', None),
                'DateRange': {
                    'Unit': args.get('date_range_unit', None),
                },
            }],
            'SeverityLabel': [{
                'Value': args.get('severity_label_value', None),
                'Comparison': args.get('severity_label_comparison', None),

            }],
            'Title': [{
                'Value': args.get('title_value', None),
                'Comparison': args.get('title_comparison', None),

            }],
            'Description': [{
                'Value': args.get('description_value', None),
                'Comparison': args.get('description_comparison', None),

            }],
            'RecommendationText': [{
                'Value': args.get('recommendation_text_value', None),
                'Comparison': args.get('recommendation_text_comparison', None),

            }],
            'SourceUrl': [{
                'Value': args.get('source_url_value', None),
                'Comparison': args.get('source_url_comparison', None),

            }],
            'ProductFields': [{
                'Key': args.get('product_fields_key', None),
                'Value': args.get('product_fields_value', None),
                'Comparison': args.get('product_fields_comparison', None),

            }],
            'ProductName': [{
                'Value': args.get('product_name_value', None),
                'Comparison': args.get('product_name_comparison', None),

            }],
            'CompanyName': [{
                'Value': args.get('company_name_value', None),
                'Comparison': args.get('company_name_comparison', None),

            }],
            'UserDefinedFields': [{
                'Key': args.get('user_defined_fields_key', None),
                'Value': args.get('user_defined_fields_value', None),
                'Comparison': args.get('user_defined_fields_comparison', None),

            }],
            'MalwareName': [{
                'Value': args.get('malware_name_value', None),
                'Comparison': args.get('malware_name_comparison', None),

            }],
            'MalwareType': [{
                'Value': args.get('malware_type_value', None),
                'Comparison': args.get('malware_type_comparison', None),

            }],
            'MalwarePath': [{
                'Value': args.get('malware_path_value', None),
                'Comparison': args.get('malware_path_comparison', None),

            }],
            'MalwareState': [{
                'Value': args.get('malware_state_value', None),
                'Comparison': args.get('malware_state_comparison', None),

            }],
            'NetworkDirection': [{
                'Value': args.get('network_direction_value', None),
                'Comparison': args.get('network_direction_comparison', None),

            }],
            'NetworkProtocol': [{
                'Value': args.get('network_protocol_value', None),
                'Comparison': args.get('network_protocol_comparison', None),

            }],
            'NetworkSourceIpV4': [{
                'Cidr': args.get('network_source_ip_v4_cidr', None),

            }],
            'NetworkSourceIpV6': [{
                'Cidr': args.get('network_source_ip_v6_cidr', None),

            }],
            'NetworkSourceDomain': [{
                'Value': args.get('network_source_domain_value', None),
                'Comparison': args.get('network_source_domain_comparison', None),

            }],
            'NetworkSourceMac': [{
                'Value': args.get('network_source_mac_value', None),
                'Comparison': args.get('network_source_mac_comparison', None),

            }],
            'NetworkDestinationIpV4': [{
                'Cidr': args.get('network_destination_ip_v4_cidr', None),

            }],
            'NetworkDestinationIpV6': [{
                'Cidr': args.get('network_destination_ip_v6_cidr', None),

            }],
            'NetworkDestinationDomain': [{
                'Value': args.get('network_destination_domain_value', None),
                'Comparison': args.get('network_destination_domain_comparison', None),

            }],
            'ProcessName': [{
                'Value': args.get('process_name_value', None),
                'Comparison': args.get('process_name_comparison', None),

            }],
            'ProcessPath': [{
                'Value': args.get('process_path_value', None),
                'Comparison': args.get('process_path_comparison', None),

            }],

            'ProcessLaunchedAt': [{
                'Start': args.get('process_launched_at_start', None),
                'End': args.get('process_launched_at_end', None),
                'DateRange': {
                    'Unit': args.get('date_range_unit', None),
                },
            }],
            'ProcessTerminatedAt': [{
                'Start': args.get('process_terminated_at_start', None),
                'End': args.get('process_terminated_at_end', None),
                'DateRange': {
                    'Unit': args.get('date_range_unit', None),
                },
            }],
            'ThreatIntelIndicatorType': [{
                'Value': args.get('threat_intel_indicator_type_value', None),
                'Comparison': args.get('threat_intel_indicator_type_comparison', None),

            }],
            'ThreatIntelIndicatorValue': [{
                'Value': args.get('threat_intel_indicator_value_value', None),
                'Comparison': args.get('threat_intel_indicator_value_comparison', None),

            }],
            'ThreatIntelIndicatorCategory': [{
                'Value': args.get('threat_intel_indicator_category_value', None),
                'Comparison': args.get('threat_intel_indicator_category_comparison', None),

            }],
            'ThreatIntelIndicatorLastObservedAt': [{
                'Start': args.get('threat_intel_indicator_last_observed_at_start', None),
                'End': args.get('threat_intel_indicator_last_observed_at_end', None),
                'DateRange': {
                    'Unit': args.get('date_range_unit', None),

                },

            }],
            'ThreatIntelIndicatorSource': [{
                'Value': args.get('threat_intel_indicator_source_value', None),
                'Comparison': args.get('threat_intel_indicator_source_comparison', None),

            }],
            'ThreatIntelIndicatorSourceUrl': [{
                'Value': args.get('threat_intel_indicator_source_url_value', None),
                'Comparison': args.get('threat_intel_indicator_source_url_comparison', None),

            }],
            'ResourceType': [{
                'Value': args.get('resource_type_value', None),
                'Comparison': args.get('resource_type_comparison', None),

            }],
            'ResourceId': [{
                'Value': args.get('resource_id_value', None),
                'Comparison': args.get('resource_id_comparison', None),

            }],
            'ResourcePartition': [{
                'Value': args.get('resource_partition_value', None),
                'Comparison': args.get('resource_partition_comparison', None),

            }],
            'ResourceRegion': [{
                'Value': args.get('resource_region_value', None),
                'Comparison': args.get('resource_region_comparison', None),

            }],
            'ResourceTags': [{
                'Key': args.get('resource_tags_key', None),
                'Value': args.get('resource_tags_value', None),
                'Comparison': args.get('resource_tags_comparison', None),

            }],
            'ResourceAwsEc2InstanceType': [{
                'Value': args.get('resource_aws_ec2_instance_type_value', None),
                'Comparison': args.get('resource_aws_ec2_instance_type_comparison', None),

            }],
            'ResourceAwsEc2InstanceImageId': [{
                'Value': args.get('resource_aws_ec2_instance_image_id_value', None),
                'Comparison': args.get('resource_aws_ec2_instance_image_id_comparison', None),

            }],
            'ResourceAwsEc2InstanceIpV4Addresses': [{
                'Cidr': args.get('resource_aws_ec2_instance_ip_v4_addresses_cidr', None),

            }],
            'ResourceAwsEc2InstanceIpV6Addresses': [{
                'Cidr': args.get('resource_aws_ec2_instance_ip_v6_addresses_cidr', None),

            }],
            'ResourceAwsEc2InstanceKeyName': [{
                'Value': args.get('resource_aws_ec2_instance_key_name_value', None),
                'Comparison': args.get('resource_aws_ec2_instance_key_name_comparison', None),

            }],
            'ResourceAwsEc2InstanceIamInstanceProfileArn': [{
                'Value': args.get('resource_aws_ec2_instance_iam_instance_profile_arn_value', None),
                'Comparison': args.get('resource_aws_ec2_instance_iam_instance_profile_arn_comparison', None),

            }],
            'ResourceAwsEc2InstanceVpcId': [{
                'Value': args.get('resource_aws_ec2_instance_vpc_id_value', None),
                'Comparison': args.get('resource_aws_ec2_instance_vpc_id_comparison', None),

            }],
            'ResourceAwsEc2InstanceSubnetId': [{
                'Value': args.get('resource_aws_ec2_instance_subnet_id_value', None),
                'Comparison': args.get('resource_aws_ec2_instance_subnet_id_comparison', None),

            }],
            'ResourceAwsEc2InstanceLaunchedAt': [{
                'Start': args.get('resource_aws_ec2_instance_launched_at_start', None),
                'End': args.get('resource_aws_ec2_instance_launched_at_end', None),
                'DateRange': {
                    'Unit': args.get('date_range_unit', None),
                },
            }],
            'ResourceAwsS3BucketOwnerId': [{
                'Value': args.get('resource_aws_s3_bucket_owner_id_value', None),
                'Comparison': args.get('resource_aws_s3_bucket_owner_id_comparison', None),

            }],
            'ResourceAwsS3BucketOwnerName': [{
                'Value': args.get('resource_aws_s3_bucket_owner_name_value', None),
                'Comparison': args.get('resource_aws_s3_bucket_owner_name_comparison', None),

            }],
            'ResourceAwsIamAccessKeyUserName': [{
                'Value': args.get('resource_aws_iam_access_key_user_name_value', None),
                'Comparison': args.get('resource_aws_iam_access_key_user_name_comparison', None),

            }],
            'ResourceAwsIamAccessKeyStatus': [{
                'Value': args.get('resource_aws_iam_access_key_status_value', None),
                'Comparison': args.get('resource_aws_iam_access_key_status_comparison', None),

            }],
            'ResourceAwsIamAccessKeyCreatedAt': [{
                'Start': args.get('resource_aws_iam_access_key_created_at_start', None),
                'End': args.get('resource_aws_iam_access_key_created_at_end', None),
                'DateRange': {
                    'Unit': args.get('date_range_unit', None),
                },
            }],
            'ResourceContainerName': [{
                'Value': args.get('resource_container_name_value', None),
                'Comparison': args.get('resource_container_name_comparison', None),

            }],
            'ResourceContainerImageId': [{
                'Value': args.get('resource_container_image_id_value', None),
                'Comparison': args.get('resource_container_image_id_comparison', None),

            }],
            'ResourceContainerImageName': [{
                'Value': args.get('resource_container_image_name_value', None),
                'Comparison': args.get('resource_container_image_name_comparison', None),

            }],
            'ResourceContainerLaunchedAt': [{
                'Start': args.get('resource_container_launched_at_start', None),
                'End': args.get('resource_container_launched_at_end', None),
                'DateRange': {
                    'Unit': args.get('date_range_unit', None),
                },
            }],
            'ResourceDetailsOther': [{
                'Key': args.get('resource_details_other_key', None),
                'Value': args.get('resource_details_other_value', None),
                'Comparison': args.get('resource_details_other_comparison', None),

            }],
            'ComplianceStatus': [{
                'Value': args.get('compliance_status_value', None),
                'Comparison': args.get('compliance_status_comparison', None),

            }],
            'VerificationState': [{
                'Value': args.get('verification_state_value', None),
                'Comparison': args.get('verification_state_comparison', None),

            }],
            'WorkflowState': [{
                'Value': args.get('workflow_state_value', None),
                'Comparison': args.get('workflow_state_comparison', None),

            }],
            'RecordState': [{
                'Value': args.get('record_state_value', None),
                'Comparison': args.get('record_state_comparison', None),

            }],
            'RelatedFindingsProductArn': [{
                'Value': args.get('related_findings_product_arn_value', None),
                'Comparison': args.get('related_findings_product_arn_comparison', None),

            }],
            'RelatedFindingsId': [{
                'Value': args.get('related_findings_id_value', None),
                'Comparison': args.get('related_findings_id_comparison', None),

            }],
            'NoteText': [{
                'Value': args.get('note_text_value', None),
                'Comparison': args.get('note_text_comparison', None),

            }],
            'NoteUpdatedAt': [{
                'Start': args.get('note_updated_at_start', None),
                'End': args.get('note_updated_at_end', None),
                'DateRange': {
                    'Unit': args.get('date_range_unit', None),
                },
            }],
            'NoteUpdatedBy': [{
                'Value': args.get('note_updated_by_value', None),
                'Comparison': args.get('note_updated_by_comparison', None),

            }],
            'Keyword': [{
                'Value': args.get('keyword_value', None),

            }],

        },
        'SortCriteria': [{
            'Field': args.get('sort_criteria_field', None),
            'SortOrder': args.get('sort_criteria_sort_order', None),

        }],
        'NextToken': args.get('next_token', None),

    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")

    kwargs['MaxResults'] = 100
    return kwargs


def aws_session(config,
                service='securityhub',
                region=None,
                roleArn=None,
                roleSessionName=None,
                roleSessionDuration=None,
                rolePolicy=None,
                ):
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
    if kwargs and not AWS_ACCESS_KEY_ID:

        if not AWS_ACCESS_KEY_ID:
            sts_client = boto3.client('sts', config=config, verify=VERIFY_CERTIFICATE)
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


def parse_filter_field(string_filters: str = ADDITIONAL_FILTERS) -> dict:
    """
    Parses string with sets of name, value and comparison into a dict
    Args:
        string_filters: A string of the form 'name=<name1>,value=<value1>,comparison=<comparison1>;name=<name2>...'

    Returns:
        A dict of the form {<name1>:[{'Value': <value1>, 'Comparison': <comparison1>}],<name2>:[{...}]}
    """
    filters = {}
    regex = re.compile(r'name=([\w\d_:.-]+),value=([\w\d_:.-]*),comparison=([ /\w\d@_,.\*-]+)', flags=re.I)
    regex_parse_result = regex.findall(string_filters)
    if regex_parse_result:
        for name, value, comparison in regex_parse_result:
            filters.update({
                name: [{
                    'Value': value,
                    'Comparison': comparison.upper()
                }]
            })
    else:
        demisto.info(f'could not parse filter: {string_filters}')

    return filters


def severity_mapping(severity: int) -> int:
    """
    Maps AWS finding severity to demisto severity
    Args:
        severity: AWS finding severity

    Returns:
        Demisto severity
    """
    if 1 <= severity <= 30:
        demisto_severity = 1
    elif 31 <= severity <= 70:
        demisto_severity = 2
    elif 71 <= severity <= 100:
        demisto_severity = 3
    else:
        demisto_severity = 0

    return demisto_severity


def sh_severity_mapping(severity: str):
    """
    Maps AWS finding string severity (LOW, Medium, High) into AWS finding number severity
    Args:
        severity: AWS finding string severity

    Returns:
        The number representation of the AWS finding severity
    """
    severity_mapper = {
        'Low': 1,
        'Medium': 31,
        'High': 71
    }
    return severity_mapper.get(severity, 0)


def disable_security_hub_command(client, args):
    kwargs = safe_load_json(args.get('raw_json', "{ }")) if args.get('raw_json') else {}
    response = client.disable_security_hub(**kwargs)
    outputs = {'AWS-SecurityHub': response}
    del response['ResponseMetadata']
    table_header = 'AWS SecurityHub DisableSecurityHub'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def enable_security_hub_command(client, args):
    kwargs = {
        'Tags': parse_tag_field(args.get('tags', '')),

    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.enable_security_hub(**kwargs)
    outputs = {'AWS-SecurityHub': response}
    del response['ResponseMetadata']
    table_header = 'AWS SecurityHub EnableSecurityHub'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def get_master_account_command(client, args):
    kwargs = safe_load_json(args.get('raw_json', "{ }")) if args.get('raw_json') else {}
    response = client.get_master_account(**kwargs)
    outputs = {'AWS-SecurityHub': response}
    del response['ResponseMetadata']
    table_header = 'AWS SecurityHub GetMasterAccount'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def get_findings_command(client, args):
    kwargs = generate_kwargs_for_get_findings(args)
    findings = []
    response = client.get_findings(**kwargs)
    next_token = response.get('NextToken')
    while next_token:
        findings.extend(response.get('Findings'))
        response = client.get_findings(NextToken=next_token)
        next_token = response.get('NextToken')
    outputs = {'AWS-SecurityHub.Findings(val.Id === obj.Id)': findings}
    table_header = 'AWS SecurityHub GetFindings'
    human_readable = aws_table_to_markdown(findings, table_header)
    return human_readable, outputs, findings


def list_members_command(client, args):
    kwargs = {
        'OnlyAssociated': True if args.get('only_associated', '') == 'true' else None,
        'NextToken': args.get('next_token', None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.list_members(**kwargs)
    outputs = {'AWS-SecurityHub': response}
    del response['ResponseMetadata']
    table_header = 'AWS SecurityHub ListMembers'
    human_readable = tableToMarkdown(table_header, response.get('Members', []))
    return human_readable, outputs, response


def update_findings_command(client, args):
    kwargs = {
        'Filters': {
            'Id': [
                {
                    'Value': args.get('findingId'),
                    'Comparison': 'EQUALS'
                },
            ]
        },
        'RecordState': args.get('record_state'),
    }
    if args.get('note') and args.get('updatedBy'):
        kwargs.update({'Note': {'Text': args.get('note'), 'UpdatedBy': args.get('updatedBy')}})

    response = client.update_findings(**kwargs)
    outputs = {'AWS-SecurityHub': response}
    del response['ResponseMetadata']
    table_header = 'AWS SecurityHub UpdateFindings'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def batch_update_findings_command(client, args):
    kwargs = {
        'FindingIdentifiers': [{
            'Id': args.get('finding_identifiers_id', None),
            'ProductArn': args.get('finding_identifiers_product_arn', None),

        }],
        'Note': {
            'Text': args.get('note_text', None),
            'UpdatedBy': args.get('note_updated_by', None),

        },
        'Severity': {
            'Label': args.get('severity_label', None),

        },
        'VerificationState': args.get('verification_state', None),
        'Types': parse_resource_ids(args.get('types', '')),
        'UserDefinedFields': json.loads(args.get('user_defined_fields', "{}")),
        'Workflow': {
            'Status': args.get('workflow_status', None),

        },
        'RelatedFindings': [{
            'ProductArn': args.get('related_findings_product_arn', None),
            'Id': args.get('related_findings_id', None),

        }],

    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.batch_update_findings(**kwargs)
    outputs = {
        'AWS-SecurityHub.ProcessedFindings': response['ProcessedFindings']}
    del response['ResponseMetadata']
    if response.get('UnprocessedFindings'):
        return_error(response['UnprocessedFindings'])
    table_header = 'AWS SecurityHub BatchUpdateFindings'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def fetch_incidents(client):
    last_run = demisto.getLastRun().get('lastRun', None)
    next_token = demisto.getLastRun().get('next_token', None)
    if last_run is None:
        first_fetch_timestamp = demisto.params().get('first_fetch_timestamp', '15 days').strip()
        date_from = parse(f'{first_fetch_timestamp} UTC')
        last_run = date_from.isoformat()  # type: ignore

    now = datetime.now(timezone.utc)

    filters = {
        'CreatedAt': [{
            'Start': last_run,
            'End': now.isoformat()
        }],
        'SeverityNormalized': [{
            'Gte': sh_severity_mapping(AWS_SH_SEVERITY),
        }]
    }
    if ADDITIONAL_FILTERS is not None:
        filters.update(parse_filter_field())
    if next_token:
        try:
            response = client.get_findings(NextToken=next_token)
        # In case a new request is made with another input the nextToken will be revoked
        except client.exceptions.InvalidInputException:
            response = client.get_findings(Filters=filters)
    else:
        response = client.get_findings(Filters=filters)
    findings = response['Findings']
    next_token = response.get('NextToken')
    incidents = [{
        'occurred': finding['CreatedAt'],
        'severity': severity_mapping(finding['Severity']['Normalized']),
        'rawJSON': json.dumps(finding)
    }
        for finding in findings]
    demisto.setLastRun({'lastRun': max(findings, key=lambda finding: finding.get('CreatedAt')).get('CreatedAt'),
                        'next_token': next_token})
    demisto.incidents(incidents)

    if ARCHIVE_FINDINGS:
        kwargs = {
            'FindingIdentifiers': [
                {'Id': finding['Id'], 'ProductArn': finding['ProductArn']} for finding in findings
            ],
            'Workflow': {
                'Status': 'NOTIFIED',
            },
            'Note': {
                'Text': 'Archived by Demisto',
                'UpdatedBy': 'Demisto'
            }
        }

        client.batch_update_findings(**kwargs)


def test_function(client):
    response = client.get_findings()
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return 'ok', {}, {}


def main():  # pragma: no cover
    proxies = handle_proxy(proxy_param_name='proxy', checkbox_default_value=False)
    config = Config(
        connect_timeout=1,
        retries=dict(
            max_attempts=5
        ),
        proxies=proxies
    )
    args = demisto.args()
    client = aws_session(
        config=config,
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    command = demisto.command()
    try:
        LOG('Command being called is {command}'.format(
            command=command))

        if command == 'test-module':
            # This is the call made when pressing the integration test button.
            human_readable, outputs, response = test_function(client)
        elif command == 'aws-securityhub-get-findings':
            human_readable, outputs, response = get_findings_command(client, args)
        elif command == 'aws-securityhub-get-master-account':
            human_readable, outputs, response = get_master_account_command(client, args)
        elif command == 'aws-securityhub-list-members':
            human_readable, outputs, response = list_members_command(client, args)
        elif command == 'aws-securityhub-enable-security-hub':
            human_readable, outputs, response = enable_security_hub_command(client, args)
        elif command == 'aws-securityhub-disable-security-hub':
            human_readable, outputs, response = disable_security_hub_command(client, args)
        elif command == 'aws-securityhub-update-findings':
            human_readable, outputs, response = update_findings_command(client, args)
        elif command == 'aws-securityhub-batch-update-findings':
            human_readable, outputs, response = batch_update_findings_command(client, args)
        elif command == 'fetch-incidents':
            fetch_incidents(client)
            return
        return_outputs(human_readable, outputs, response)

    except ResponseParserError as e:
        return_error('Could not connect to the AWS endpoint. Please check that the region is valid. {error}'.format(
            error=type(e)), error=e)
    except Exception as e:
        return_error('Error has occurred in the AWS securityhub Integration: {code} {message}'.format(
            code=type(e), message=e), error=e)


if __name__ in ['__builtin__', 'builtins', '__main__']:  # pragma: no cover
    main()
