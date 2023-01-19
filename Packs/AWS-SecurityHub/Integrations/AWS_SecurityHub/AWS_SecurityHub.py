import boto3
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import urllib3.util
from datetime import timezone
from dateparser import parse

# Disable insecure warnings
urllib3.disable_warnings()

MIRROR_DIRECTION_MAPPING = {
    "None": None,
    "Incoming": "In",
    "Outgoing": "Out",
    "Incoming And Outgoing": "Both",
}

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


def parse_filter_field(string_filters) -> dict:
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
    if 1 <= severity <= 39:
        demisto_severity = 1
    elif 40 <= severity <= 69:
        demisto_severity = 2
    elif 70 <= severity <= 89:
        demisto_severity = 3
    elif 90 <= severity <= 100:
        demisto_severity = 4
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
        'Informational': 0,
        'Low': 1,
        'Medium': 40,
        'High': 70,
        'Critical': 90
    }
    return severity_mapper.get(severity, 0)


def create_filters_list_dictionaries(arr: List[str], compare_param: str) -> List[Dict]:
    """ Returns the object for the filters dictionary.
        Args:
            arr: List[str] - An array of strings
            compare_param: str - The comparison string. can be EQUALS or PREFIX.
        Returns:
            The correct object to add to filters.
    """
    result_arr = []
    for item in arr:
        d = {
            'Comparison': compare_param,
            'Value': item
        }
        result_arr.append(d)
    return result_arr


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
    response = client.get_findings(**kwargs)
    findings = response.get('Findings', [])
    next_token = response.get('NextToken')
    while next_token:
        kwargs['NextToken'] = next_token
        findings.extend(response.get('Findings'))
        response = client.get_findings(**kwargs)
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
    response['Members'] = convert_members_date_type(response.get('Members', []))
    outputs = {'AWS-SecurityHub': response}
    del response['ResponseMetadata']
    table_header = 'AWS SecurityHub ListMembers'
    human_readable = tableToMarkdown(table_header, response.get('Members', []))
    return human_readable, outputs, response


def convert_members_date_type(members):
    new_ls = []
    for member in members:
        if isinstance(updated_at := member.get('UpdatedAt'), datetime):
            member['UpdatedAt'] = updated_at.isoformat()
        if isinstance(invited_at := member.get('InvitedAt'), datetime):
            member['InvitedAt'] = invited_at.isoformat()
        new_ls.append(member)
    return new_ls


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
        'RecordState': args.get('recordState'),
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


def fetch_incidents(client, aws_sh_severity, archive_findings, additional_filters, mirror_direction):
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
            'Gte': sh_severity_mapping(aws_sh_severity),
        }]
    }
    if additional_filters is not None:
        filters.update(parse_filter_field(additional_filters))
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
        'rawJSON': json.dumps(finding),
        'dbotMirrorId': finding['Id'],
        'mirror_direction': mirror_direction,
        'mirror_instance': demisto.integrationInstance()
    }
        for finding in findings]
    if findings:
        # in case we got finding, we should get the latest created one and increase it by 1 ms so the next fetch
        # wont include it in the query and fetch duplicates
        last_created_finding = max(findings, key=lambda finding: finding.get('CreatedAt')).get('CreatedAt')
        last_created_finding_dt = parse(last_created_finding) + timedelta(milliseconds=1)  # type: ignore[operator]
        last_run = last_created_finding_dt.isoformat()  # type: ignore[union-attr]
    demisto.setLastRun({'lastRun': last_run,
                        'next_token': next_token})
    demisto.incidents(incidents)

    if archive_findings:
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


def get_remote_data_command(client: boto3.client, args: Dict[str, Any]):
    """
    get-remote-data command: Returns an updated incident and entries
    Args:
        client: XSOAR client to use
        args:
            id: incident id to retrieve
            lastUpdate: when was the last time we retrieved data

    Returns:

    """
    incident_id = args.get('id', '')
    demisto.debug(f'Getting updated for remote incident {incident_id}')
    last_update = args.get('lastUpdate')
    demisto.debug(f'last update is {last_update}')
    kwargs = generate_kwargs_for_get_findings(args)
    response = client.get_findings(**kwargs)
    findings = response.get('Findings', [{}])
    demisto.debug(f'the findings are {findings}')
    entries = []
    # for finding in findings:


def get_modified_remote_data_command(client: boto3.client, args: Dict[str, str], aws_sh_severity: str,
                                     additional_filters: str, finding_types: List[str], workflow_status: List[str],
                                     product_name: List[str]) -> GetModifiedRemoteDataResponse:
    """ Checks if there were any updates in the incidents on AWS Security Hub, that match the given filters.
            Then returns a list of the updated incident ids.
        Args:
            client: boto3.client - An AWS client.
            args: Dict[str, str] - The argument to the function.
            aws_sh_severity: str - The severity we want to filter by.
            additional_filters: str - More filters that the user provided.
            finding_types: List[str] - A list of finding types to filter by.
            workflow_status: List[str] - A list of workflow statuses to filter by.
            product_name: List[str] - A list of product name to filter by.
        Returns:
            A GetModifiedRemoteDataResponse object that contains a list of the updated incident ids.
    """
    last_update = args.get('lastUpdate', None)
    filters = {}
    if last_update:
        remote_args = GetModifiedRemoteDataArgs(args)
        now = datetime.now(timezone.utc)
        filters['CreatedAt'] = [{
            'Start': remote_args.last_update,
            'End': now.isoformat()
        }]
    if aws_sh_severity:
        filters['SeverityNormalized'] = [{
            'Gte': sh_severity_mapping(aws_sh_severity)
        }]
    if additional_filters:
        filters.update(parse_filter_field(additional_filters))
    if finding_types:
        filters['Type'] = create_filters_list_dictionaries(finding_types, 'PREFIX')
    if workflow_status:
        statuses = [stat.upper() for stat in workflow_status]
        filters['WorkflowStatus'] = create_filters_list_dictionaries(statuses, 'EQUALS')
    if product_name:
        filters['ProductName'] = create_filters_list_dictionaries(product_name, 'EQUALS')
    demisto.debug(f'The filters are: {filters} \nEND OF FILTERS')
    response = client.get_findings(Filters=filters)
    findings = response.get('Findings')
    next_token = response.get('NextToken')
    demisto.debug(f'Findings are: {findings}')
    modified_incident_ids = []
    while findings:
        for finding in findings:
            confidence = finding.get('Confidence', None)
            criticality = finding.get('Criticality', None)
            related_findings = finding.get('RelatedFindings', None)
            severity_normalized = finding.get('Severity', {}).get('Normalized', None)
            finding_types = finding.get('Types', None)
            user_defined_fields = finding.get('UserDefinedFields', None)
            verification_state = finding.get('VerificationState', None)
            workflow_status = finding.get('Workflow', {}).get('Status', None)
            if confidence or criticality or related_findings or severity_normalized or finding_types or \
                    user_defined_fields or verification_state or workflow_status:
                demisto.debug(f'A new incident id: {finding.get("Id")} ** with the product name {finding.get("ProductName")}\n')
                modified_incident_ids.append(finding.get('Id'))
            else:
                demisto.debug('No important changes\n')
        if next_token:
            demisto.debug(f'In pagination part. The next token is {next_token}\nEND TOKEN')
            response = client.get_findings(Filters=filters, NextToken=next_token)
            demisto.debug('After call in pagination.')
            findings = response.get('Findings')
            demisto.debug(f'The new next token is {next_token}')
            next_token = response.get('NextToken')
        else:
            demisto.debug('End of loop')
            findings = None
    demisto.debug(f'The incident ids are: {modified_incident_ids}')
    return GetModifiedRemoteDataResponse(modified_incident_ids=modified_incident_ids)


def test_function(client):
    response = client.get_findings()
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return 'ok', {}, {}


def main():  # pragma: no cover

    args = demisto.args()
    command = demisto.command()
    params = demisto.params()

    aws_default_region = params.get('defaultRegion')
    aws_role_arn = params.get('roleArn')
    aws_role_session_name = params.get('roleSessionName')
    aws_role_session_duration = params.get('sessionDuration')
    aws_role_policy = None
    aws_access_key_id = params.get('credentials', {}).get('identifier') or params.get('access_key')
    aws_secret_access_key = params.get('credentials', {}).get('password') or params.get('secret_key')
    verify_certificate = not params.get('insecure', True)
    timeout = params.get('timeout')
    retries = params.get('retries') or 5
    aws_sh_severity = params.get('sh_severity')
    archive_findings = params.get('archiveFindings', False)
    additional_filters = params.get('additionalFilters', '')
    mirror_direction = MIRROR_DIRECTION_MAPPING[params.get("mirror_direction")]
    finding_type = params.get('finding_type', '')
    workflow_status = params.get('workflow_status', '')
    product_name = argToList(params.get('product_name', ''))
    mapper_out = params.get('mapper_out', '')

    try:
        validate_params(aws_default_region, aws_role_arn, aws_role_session_name, aws_access_key_id,
                        aws_secret_access_key)
        aws_client = AWSClient(aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
                               aws_role_policy, aws_access_key_id, aws_secret_access_key, verify_certificate, timeout,
                               retries)
        client = aws_client.aws_session(
            service='securityhub',
            region=args.get('region'),
            role_arn=args.get('roleArn'),
            role_session_name=args.get('roleSessionName'),
            role_session_duration=args.get('roleSessionDuration')
        )

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
            fetch_incidents(client, aws_sh_severity, archive_findings, additional_filters, mirror_direction)
            return
        elif command == 'get-remote-data':
            get_remote_data_command(client, args)
            return
        elif command == 'get-modified-remote-data':
            return_results(get_modified_remote_data_command(client, args, aws_sh_severity, additional_filters,
                                                            finding_type, workflow_status, product_name))
        return_outputs(human_readable, outputs, response)

    except Exception as e:
        return_error('Error has occurred in the AWS securityhub Integration: {code} {message}'.format(
            code=type(e), message=e), error=e)


from AWSApiModule import *  # noqa: E402

if __name__ in ['__builtin__', 'builtins', '__main__']:  # pragma: no cover
    main()
