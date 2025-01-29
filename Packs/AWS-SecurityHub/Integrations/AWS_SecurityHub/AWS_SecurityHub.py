import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import boto3

import urllib3.util
from datetime import UTC
from dateparser import parse

# Disable insecure warnings
urllib3.disable_warnings()

MIRROR_DIRECTION_MAPPING = {
    "None": None,
    "Incoming": "In",
    "Outgoing": "Out",
    "Incoming And Outgoing": "Both",
}

OUT_FIELDS = ['Confidence', 'Criticality', 'Note.Text', 'Note.UpdatedBy', 'Severity.Label', 'VerificationState',
              'Workflow.Status']
FindingIdentifiers_lIST = ['FindingIdentifiers.Id', 'FindingIdentifiers.ProductArn']

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


def is_advanced_filters_contain_all_fields(filters_list: list) -> bool:
    """
    Check if all the filters in the list contain the fields "name", "value", and "comparison".

    Args:
        filters_list (list): A list of filters.

    Returns:
        bool: True if all the filters contain the fields "name", "value", and "comparison", False otherwise.
    """
    return all(
        "name" in filter_str
        and "value" in filter_str
        and "comparison" in filter_str
        for filter_str in filters_list
    )


def is_advanced_filter_fields_in_right_order(filters_list: list) -> bool:
    """
    Check if the fields "name", "value", and "comparison" appear in the correct order in each filter string in the list.

    Args:
        filters_list (list): A list of filter strings.

    Returns:
        bool: True if the fields "name", "value", and "comparison" appear in the correct order
        in each filter string in the list, False otherwise.
    """
    for filter_str in filters_list:
        name_index = filter_str.find('name=')
        value_index = filter_str.find('value=')
        comparison_index = filter_str.find('comparison=')
        if not name_index < value_index < comparison_index:
            return False
    return True


def is_valid_advanced_filters(string_filters: str) -> bool:
    filters_list = string_filters.split(';')
    return is_advanced_filters_contain_all_fields(filters_list)\
        and is_advanced_filter_fields_in_right_order(filters_list)


def parse_filter_field(string_filters) -> dict:
    """
    Parses string with sets of name, value and comparison into a dict
    Args:
        string_filters: A string of the form 'name=<name1>,value=<value1>,comparison=<comparison1>;name=<name2>...'

    Returns:
        A dict of the form {<name1>:[{'Value': <value1>, 'Comparison': <comparison1>}],<name2>:[{...}]}
    """
    filters: dict = {}
    if is_valid_advanced_filters(string_filters):
        try:
            filters_list = string_filters.split(';')
            filters = {split_str[0].split('=')[1]: [{'Value': split_str[1].split('=')[1],
                                                    'Comparison': split_str[2].split('=')[1].upper()}]
                       for split_str in [filter_str.split(',') for filter_str in filters_list]}
        except Exception:
            demisto.error(f'Failed parsing filters: {string_filters}\n error: {Exception}')
    else:
        demisto.info(f'Advanced filters does not contain all fields or fields are not in\
            the correct order: name,value,comparison: {string_filters}\
            Will run with an empty filter.')
    return filters


def severity_mapping(severity: str) -> int:
    """
    Maps AWS finding severity to demisto severity
    Args:
        severity: AWS finding severity

    Returns:
        Demisto severity
    """
    if severity == 'LOW':
        demisto_severity = 1
    elif severity == 'MEDIUM':
        demisto_severity = 2
    elif severity == 'HIGH':
        demisto_severity = 3
    elif severity == 'CRITICAL':
        demisto_severity = 4
    else:
        demisto_severity = 0

    return demisto_severity


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


def build_severity_label_obj(label: str) -> List:
    """ Returns the object for the severity label in the fetch.
        Args:
            label: str - The severity label the user provided.
        Returns:
            A list of dictionaries to be sent in the filters object.
    """
    severity_dict = {
        'Informational': 0,
        'Low': 1,
        'Medium': 2,
        'High': 3,
        'Critical': 4
    }
    severity_label_obj = []
    num = severity_dict.get(label, -1)  # -1 is smaller than all -> all the severities will be in the object.
    for lbl in severity_dict:
        key = severity_dict.get(lbl, 5)  # 5 is bigger than all -> all the severities will be in the object.
        # in order to get incident with equal or higher severity we need to add all the relevant severities to this
        # object, and then the API will return all the incidents that are equal to one of the severities we provided.
        if key >= num:
            severity_label_obj.append({
                'Comparison': 'EQUALS',
                'Value': lbl.upper()
            })
    return severity_label_obj


def last_update_to_time(last_update: str) -> int:
    """
        Converting the lastUpdate string to int
        Args:
            last_update: str
        Returns:
            The int representing the date.
        """
    if not last_update:
        raise ValueError('Missing lastUpdate')
    else:
        date_time = dateparser.parse(last_update, settings={'TIMEZONE': 'UTC'})
        if not date_time:
            raise ValueError('Invalid date.')
        else:
            demisto.debug('In last_update_to_time returning the result')
            return int(date_time.timestamp())


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
    if 'Master' in response:
        response['Master'] = convert_members_date_type([response.get('Master')])
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


def fetch_incidents(client, aws_sh_severity, archive_findings, additional_filters, mirror_direction, finding_types,
                    workflow_status, product_name):
    last_run = demisto.getLastRun().get('lastRun', None)
    next_token = demisto.getLastRun().get('next_token', None)
    if last_run is None:
        first_fetch_timestamp = demisto.params().get('first_fetch_timestamp', '15 days').strip()
        date_from = parse(f'{first_fetch_timestamp} UTC')
        last_run = date_from.isoformat()  # type: ignore

    now = datetime.now(UTC)

    filters = {
        'CreatedAt': [{
            'Start': last_run,
            'End': now.isoformat()
        }]
    }
    if aws_sh_severity:
        filters['SeverityLabel'] = build_severity_label_obj(aws_sh_severity)
    if additional_filters is not None:
        filters.update(parse_filter_field(additional_filters))
    if finding_types:
        filters['Type'] = create_filters_list_dictionaries(finding_types, 'PREFIX')
    if workflow_status:
        statuses = [stat.upper() for stat in workflow_status]
        filters['WorkflowStatus'] = create_filters_list_dictionaries(statuses, 'EQUALS')
    if product_name:
        filters['ProductName'] = create_filters_list_dictionaries(product_name, 'EQUALS')
    demisto.debug(f'The filters to the fetch are: {filters}')
    if next_token:
        try:
            response = client.get_findings(NextToken=next_token)

        # In case a new request is made with another input the nextToken will be revoked
        except client.exceptions.InvalidInputException as e:
            demisto.debug(f'The {next_token=} is not valid.\nThe exception is {e}')
            response = client.get_findings(Filters=filters)
    else:
        response = client.get_findings(Filters=filters)
    findings = response['Findings']
    next_token = response.get('NextToken')
    demisto.debug(f'The findings in the fetch_incidents are: {findings}')
    incidents = []
    for finding in findings:
        finding.update({
            'mirror_direction': mirror_direction,
            'mirror_instance': demisto.integrationInstance()
        })
        incidents.append({
            'occurred': finding['CreatedAt'],
            'severity': severity_mapping(finding['Severity']['Label']),
            'rawJSON': json.dumps(finding)
        })
    if findings:
        # in case we got finding, we should get the latest created one and increase it by 1 ms so the next fetch
        # wont include it in the query and fetch duplicates
        last_created_finding = max(findings, key=lambda finding: finding.get('CreatedAt')).get('CreatedAt')
        last_created_finding_dt = parse(last_created_finding) + timedelta(milliseconds=1)  # type: ignore[operator]
        last_run = last_created_finding_dt.isoformat()  # type: ignore[union-attr]
    demisto.setLastRun({'lastRun': last_run,
                        'next_token': next_token})
    demisto.incidents(incidents)

    if archive_findings and findings:
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


def get_remote_data_command(client: boto3.client, args: Dict[str, Any]) -> GetRemoteDataResponse:  # type: ignore
    """
    get-remote-data command: Returns an updated incident and entries
    Args:
        client: XSOAR client to use
        args:
            id: incident id to retrieve
            lastUpdate: when was the last time we retrieved data

    Returns:
        GetRemoteDataResponse object, which contain the incident data to update.
    """
    remote_args = GetRemoteDataArgs(args)
    remote_incident_id = remote_args.remote_incident_id
    # The incident can be updated in a 3rd party provider, which can cause a delayed update in AWS Security Hub,
    # that can lead to XSOAR missing the update. This is way the -60 seconds
    last_update_time = last_update_to_time(remote_args.last_update) - 60
    demisto.debug(f'Performing get-remote-data command with incident id: {remote_incident_id} and {last_update_time=}')

    filters = {
        'Id': [
            {
                'Comparison': 'EQUALS',
                'Value': remote_incident_id
            }
        ]
    }
    response = client.get_findings(Filters=filters)  # type: ignore
    demisto.debug(f'The response is: {response} \nEnd of response.')
    finding = response.get('Findings')[0]  # a list with one dict in it
    incident_last_update = finding.get('UpdatedAt', '')
    incident_last_update_time = last_update_to_time(incident_last_update)
    demisto.debug(f'The incident last update time is: {incident_last_update}\nAnd {incident_last_update_time=}')

    if last_update_time < incident_last_update_time:
        demisto.debug(f'Updated incident {remote_incident_id}')
        return GetRemoteDataResponse(mirrored_object=finding, entries=[{}])
    else:
        demisto.debug('Nothing new in the incident.')
        return GetRemoteDataResponse(mirrored_object={}, entries=[{}])


def get_mapping_fields_command() -> GetMappingFieldsResponse:
    """
    Returns the list of fields to map in outgoing mirroring, for incidents and detections.
    """
    incident_type_scheme = SchemeTypeMapping(type_name='AWS Security Hub Finding')
    demisto.debug('Collecting incident mapping.')

    for field in OUT_FIELDS + FindingIdentifiers_lIST:
        incident_type_scheme.add_field(field)

    mapping_response = GetMappingFieldsResponse()
    mapping_response.add_scheme_type(incident_type_scheme)

    return mapping_response


def update_remote_system_command(client: boto3.client, args: Dict[str, Any], resolve_findings: bool) -> str:  # type: ignore
    """
    Mirrors out local changes to the remote system.
    Args:
        client: boto3.client - AWS client
        args: A dictionary containing the data regarding a modified incident, including: data, entries,
            incident_changed, remote_incident_id, inc_status, delta.
        resolve_findings: bool - Whether to resolve an incident in Security Hub, that was closed in XSOAR.

    Returns:
        The remote incident id that was modified. This is important when the incident is newly created remotely.
    """
    parsed_args = UpdateRemoteSystemArgs(args)
    delta = parsed_args.delta
    remote_incident_id = parsed_args.remote_incident_id
    data = parsed_args.data
    demisto.debug(f'Got the following {parsed_args.inc_status=}, {data=}, {delta=} '
                  f'and remote ID: {remote_incident_id}.')

    if parsed_args.incident_changed and delta:
        demisto.debug(f'Got the following delta keys {list(delta.keys())}.\n'
                      f'Incident id {remote_incident_id} and incident change: '
                      f'{parsed_args.incident_changed}')
        kwargs = {
            "FindingIdentifiers": [{
                "Id": data.get('FindingIdentifiers.Id'),
                "ProductArn": data.get('FindingIdentifiers.ProductArn')
            }],
            'Severity': {
                "Label": delta.get('Severity.Label')
            },
            # should contain only 1 state
            'VerificationState': delta.get('VerificationState')[0] if delta.get('VerificationState') else None,
            'Confidence': int(delta.get('Confidence')) if delta.get('Confidence') else None,
            'Criticality': int(delta.get('Criticality')) if delta.get('Criticality') else None,
            # should contain only 1 status
            'Workflow': {
                "Status": delta.get('Workflow.Status')[0] if delta.get('Workflow.Status') else None
            }
        }

        if delta.get('Note.Text'):
            kwargs['Note'] = {
                'Text': delta.get('Note.Text') or data.get('Note.Text'),
                'UpdatedBy': delta.get('Note.UpdatedBy') or data.get('Note.UpdatedBy')
            }
        demisto.debug(f'The {resolve_findings=} ,{parsed_args.inc_status=}')
        if parsed_args.inc_status == IncidentStatus.DONE and resolve_findings:
            kwargs['Workflow']['Status'] = 'RESOLVED'  # type: ignore[index]
            parsed_args.data['Workflow.Status'] = ['RESOLVED']
            demisto.debug(f"{parsed_args.data['Workflow.Status']=}")

        kwargs = remove_empty_elements(kwargs)
        demisto.debug(f'{kwargs=}')
        response = client.batch_update_findings(**kwargs)   # type: ignore
        demisto.debug(f'The update remote system response is: {response}')
    else:
        demisto.debug(f'Skipping updating remote incident {remote_incident_id} as it did not change.')
    return remote_incident_id


def test_function(client):
    response = client.get_findings()
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return 'ok', {}, {}
    return 'Failed to execute test-module command', {}, {}


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
    mirror_direction = MIRROR_DIRECTION_MAPPING[params.get('mirror_direction')]
    finding_type = params.get('finding_type', '')
    workflow_status = params.get('workflow_status', '')
    product_name = argToList(params.get('product_name', ''))
    resolve_findings = params.get('resolve_finding')
    sts_endpoint_url = params.get('sts_endpoint_url') or None
    endpoint_url = params.get('endpoint_url') or None

    try:
        validate_params(aws_default_region, aws_role_arn, aws_role_session_name, aws_access_key_id,
                        aws_secret_access_key)
        aws_client = AWSClient(aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
                               aws_role_policy, aws_access_key_id, aws_secret_access_key, verify_certificate, timeout,
                               retries, sts_endpoint_url=sts_endpoint_url, endpoint_url=endpoint_url)
        client = aws_client.aws_session(
            service='securityhub',
            region=args.get('region'),
            role_arn=args.get('roleArn'),
            role_session_name=args.get('roleSessionName'),
            role_session_duration=args.get('roleSessionDuration')
        )

        LOG(f'Command being called is {command}')

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
            fetch_incidents(client, aws_sh_severity, archive_findings, additional_filters, mirror_direction,
                            finding_type, workflow_status, product_name)
            return
        elif command == 'get-remote-data':
            return_results(get_remote_data_command(client, args))
            return
        elif command == 'update-remote-system':
            return_results(update_remote_system_command(client, args, resolve_findings))
            return
        elif command == 'get-mapping-fields':
            return_results(get_mapping_fields_command())
            return
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

        return_outputs(human_readable, outputs, response)

    except Exception as e:
        return_error(f'Error has occurred in the AWS securityhub Integration: {type(e)} {e}', error=e)


from AWSApiModule import *  # noqa: E402

if __name__ in ['__builtin__', 'builtins', '__main__']:  # pragma: no cover
    main()
