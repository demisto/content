import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from AWSApiModule import *  # noqa: E402
from typing import Callable
import urllib3.util
import boto3

import urllib3
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
SERVICE = 'wafv2'
OUTPUT_PREFIX = 'AWS.Waf'
OPERATOR_TO_STATEMENT_OPERATOR = {'And': 'AndStatement', 'Or': 'OrStatement', 'Not': 'NotStatement'}

''' HELPER FUNCTIONS '''


def get_tags_dict_from_args(tag_keys: list, tag_values: list) -> List[dict]:
    tags: list = []
    if len(tag_keys) != len(tag_values):
        raise DemistoException('Tha tags_keys and tag_values arguments must be at the same length.')

    # keys and values are in the same length
    n = len(tag_keys)
    for i in range(n):
        tag = {'Key': tag_keys[i], 'Value': tag_values[i]}
        tags.append(tag)

    return tags


def build_regex_pattern_object(regex_patterns: list) -> List[dict]:
    regex_patterns_objects: list = [
        {'RegexString': regex_pattern} for regex_pattern in regex_patterns
    ]
    return regex_patterns_objects


def build_visibility_config_object(metric_name: str,
                                   cloud_watch_metrics_enabled: bool,
                                   sampled_requests_enabled: bool) -> dict:
    return {
        'CloudWatchMetricsEnabled': cloud_watch_metrics_enabled,
        'MetricName': metric_name,
        'SampledRequestsEnabled': sampled_requests_enabled
    }


def build_ip_rule_object(args: dict) -> dict:
    ip_rule: dict = {'Statement': {}}
    ip_set_arn = argToList(args.get('ip_set_arn')) or []
    condition_operator = args.get('condition_operator', '')
    if len(ip_set_arn) > 1 and not condition_operator:
        raise DemistoException('Please provide a value to the condition_operator argument '
                               'when ip_set_arn has more than one value.')

    if len(ip_set_arn) == 1:
        ip_rule['Statement'] = {'IPSetReferenceStatement': {
            'ARN': ip_set_arn[0]
        }}
    elif len(ip_set_arn) > 1:
        statement_operator = OPERATOR_TO_STATEMENT_OPERATOR[condition_operator]
        ip_rule['Statement'][statement_operator] = {'Statements': []}
        for ip_set in ip_set_arn:
            ip_rule['Statement'][statement_operator]['Statements'].append({'IPSetReferenceStatement': {
                'ARN': ip_set
            }})

    return ip_rule


def build_country_rule_object(args: dict) -> dict:
    country_codes = argToList(args.get('country_codes')) or []

    ip_rule: dict = {
        'Statement': {'GeoMatchStatement': {'CountryCodes': country_codes}}
    }
    return ip_rule


def build_rule_object(args: dict, rule_group_visibility_config: dict,
                      build_rule_method: Callable[[dict], dict]) -> dict:
    name = args.get('rule_name', '')
    rule_visibility_config = build_visibility_config_object(
        metric_name=name,
        cloud_watch_metrics_enabled=rule_group_visibility_config.get('CloudWatchMetricsEnabled'),
        sampled_requests_enabled=rule_group_visibility_config.get('SampledRequestsEnabled'))

    rule = {
        'Name': name,
        'Priority': arg_to_number(args.get('priority', '')) or 0,
        'Action': {
            args.get('action'): {}
        },
        'VisibilityConfig': rule_visibility_config,

    }
    rule |= build_rule_method(args)

    return rule


''' COMMAND FUNCTIONS '''


def connection_test(client: boto3.client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    pass


def create_ip_set_command(client: boto3.client, args) -> CommandResults:
    tag_keys = argToList(args.get('tag_key')) or []
    tag_values = argToList(args.get('tag_value')) or []
    kwargs = {
        'Name': args.get('name', ''),
        'Scope': args.get('scope', ''),
        'IPAddressVersion': args.get('ip_version', ''),
        'Addresses': argToList(args.get('addresses')) or [],
    }

    if description := args.get('description'):
        kwargs |= {'Description': description}
    if tags := get_tags_dict_from_args(tag_keys, tag_values):
        kwargs |= {'Tags': tags}

    response = client.create_ip_set(**kwargs)
    outputs = response.get('Summary', {})

    readable_output = f'AWS Waf ip set with id {outputs.get("Id", "")} was created successfully'

    return CommandResults(readable_output=readable_output,
                          outputs=outputs,
                          raw_response=response,
                          outputs_prefix=f'{OUTPUT_PREFIX}.IPSet',
                          outputs_key_field='Id')


def get_ip_set_command(client: boto3.client, args) -> CommandResults:
    kwargs = {
        'Name': args.get('name', ''),
        'Scope': args.get('scope', ''),
        'Id': args.get('id', '')
    }

    response = client.get_ip_set(**kwargs)

    outputs = response.get('IPSet', {})

    readable_output = tableToMarkdown('IP Set', outputs)

    return CommandResults(readable_output=readable_output,
                          outputs=outputs,
                          raw_response=response,
                          outputs_prefix=f'{OUTPUT_PREFIX}.IpSet',
                          outputs_key_field='Id')


def update_ip_set_command(client: boto3.client, args) -> CommandResults:
    kwargs = {
        'Name': args.get('name', ''),
        'Scope': args.get('scope', ''),
        'Id': args.get('id', '')
    }

    addresses_to_update = argToList(args.get('addresses')) or []
    overwrite = argToBoolean(args.get('is_overwrite')) or False

    get_response = client.get_ip_set(**kwargs)

    lock_token = get_response.get('LockToken', '')
    original_addresses = get_response.get('IPSet', {}).get('Addresses')
    if not overwrite:
        addresses_to_update.extend(original_addresses)

    kwargs |= {'LockToken': lock_token, 'Addresses': addresses_to_update}

    if description := args.get('description'):
        kwargs |= {'Description': description}

    response = client.update_ip_set(**kwargs)

    readable_output = f'AWS Waf ip set with id {args.get("Id", "")} was updated successfully. ' \
                      f'Next Lock Token: {response.get("NextLockToken")}'

    return CommandResults(readable_output=readable_output,
                          raw_response=response)


def list_ip_set_command(client: boto3.client, args) -> CommandResults:
    kwargs = {
        'Scope': args.get('scope', ''),
        'Limit': arg_to_number(args.get('limit')) or 50
    }

    if next_marker := args.get('next_token'):
        kwargs |= {'NextMarker': next_marker}

    response = client.list_ip_sets(**kwargs)
    ip_sets = response.get('IPSets', [])
    readable_output = tableToMarkdown('List IP Sets', ip_sets, is_auto_json_transform=True)
    outputs = {f'{OUTPUT_PREFIX}.IpSet(val.Id === obj.Id)': ip_sets, 'IpSetNextToken': response.get('NextMarker', '')}

    return CommandResults(readable_output=readable_output,
                          outputs=outputs,
                          raw_response=response)


def delete_ip_set_command(client: boto3.client, args) -> CommandResults:
    kwargs = {
        'Name': args.get('name', ''),
        'Scope': args.get('scope', ''),
        'Id': args.get('id', '')
    }

    get_response = client.get_ip_set(**kwargs)

    kwargs |= {'LockToken': get_response.get('LockToken', '')}

    response = client.delete_ip_set(**kwargs)

    readable_output = f'AWS Waf ip set with id {args.get("id", "")} was deleted successfully'

    return CommandResults(readable_output=readable_output,
                          raw_response=response)


def create_regex_set_command(client: boto3.client, args) -> CommandResults:
    tag_keys = argToList(args.get('tag_key')) or []
    tag_values = argToList(args.get('tag_value')) or []
    regex_patterns = argToList(args.get('regex_pattern')) or []
    kwargs = {
        'Name': args.get('name', ''),
        'Scope': args.get('scope', ''),
        'RegularExpressionList': build_regex_pattern_object(regex_patterns)
    }

    if description := args.get('description'):
        kwargs |= {'Description': description}
    if tags := get_tags_dict_from_args(tag_keys, tag_values):
        kwargs |= {'Tags': tags}

    response = client.create_regex_pattern_set(**kwargs)
    outputs = response.get('Summary', {})

    readable_output = f'AWS Waf regex set with id {outputs.get("Id", "")} was created successfully'

    return CommandResults(readable_output=readable_output,
                          outputs=outputs,
                          raw_response=response,
                          outputs_prefix=f'{OUTPUT_PREFIX}.RegexSet',
                          outputs_key_field='Id')


def get_regex_set_command(client: boto3.client, args) -> CommandResults:
    kwargs = {
        'Name': args.get('name', ''),
        'Scope': args.get('scope', ''),
        'Id': args.get('id', '')
    }

    response = client.get_regex_pattern_set(**kwargs)

    outputs = response.get('RegexPatternSet', {})

    readable_output = tableToMarkdown('Regex Set', outputs)

    return CommandResults(readable_output=readable_output,
                          outputs=outputs,
                          raw_response=response,
                          outputs_prefix=f'{OUTPUT_PREFIX}.RegexSet',
                          outputs_key_field='Id')


def update_regex_set_command(client: boto3.client, args) -> CommandResults:
    kwargs = {
        'Name': args.get('name', ''),
        'Scope': args.get('scope', ''),
        'Id': args.get('id', '')
    }

    patterns_to_update = build_regex_pattern_object(argToList(args.get('regex_pattern')))
    overwrite = argToBoolean(args.get('is_overwrite')) or False

    get_response = client.get_regex_pattern_set(**kwargs)

    lock_token = get_response.get('LockToken', '')
    original_patterns = get_response.get('RegexPatternSet', {}).get('RegularExpressionList')
    if not overwrite:
        patterns_to_update.extend(original_patterns)

    kwargs |= {'LockToken': lock_token, 'RegularExpressionList': patterns_to_update}

    if description := args.get('description'):
        kwargs |= {'Description': description}

    response = client.update_regex_pattern_set(**kwargs)

    readable_output = f'AWS Waf ip set with id {args.get("Id", "")} was updated successfully. ' \
                      f'Next Lock Token: {response.get("NextLockToken")}'

    return CommandResults(readable_output=readable_output,
                          raw_response=response)


def list_regex_set_command(client: boto3.client, args) -> CommandResults:
    kwargs = {
        'Scope': args.get('scope', ''),
        'Limit': arg_to_number(args.get('limit')) or 50
    }

    if next_marker := args.get('next_token'):
        kwargs |= {'NextMarker': next_marker}

    response = client.list_regex_pattern_sets(**kwargs)
    regex_patterns = response.get('RegexPatternSets', [])
    readable_output = tableToMarkdown('List regex Sets', regex_patterns, is_auto_json_transform=True)
    outputs = {f'{OUTPUT_PREFIX}.RegexSet(val.Id === obj.Id)': regex_patterns, 'RegexSetNextToken': response.get('NextMarker', '')}

    return CommandResults(readable_output=readable_output,
                          outputs=outputs,
                          raw_response=response)


def delete_regex_set_command(client: boto3.client, args) -> CommandResults:
    kwargs = {
        'Name': args.get('name', ''),
        'Scope': args.get('scope', ''),
        'Id': args.get('id', '')
    }

    get_response = client.get_regex_pattern_set(**kwargs)

    kwargs |= {'LockToken': get_response.get('LockToken', '')}

    response = client.delete_regex_pattern_set(**kwargs)

    readable_output = f'AWS Waf regex set with id {args.get("id", "")} was deleted successfully'

    return CommandResults(readable_output=readable_output,
                          raw_response=response)


def list_rule_group_command(client: boto3.client, args) -> CommandResults:
    kwargs = {
        'Scope': args.get('scope', ''),
        'Limit': arg_to_number(args.get('limit')) or 50
    }

    if next_marker := args.get('next_token'):
        kwargs |= {'NextMarker': next_marker}

    response = client.list_rule_groups(**kwargs)
    rule_groups = response.get('RuleGroups', [])
    outputs = {f'{OUTPUT_PREFIX}.RuleGroup(val.Id === obj.Id)': rule_groups, 'RuleGroupNextToken': response.get('NextMarker', '')}
    readable_output = tableToMarkdown('List rule groups',
                                      rule_groups,
                                      headers=['Name', 'Id', 'ARN', 'Description'],
                                      is_auto_json_transform=True)

    return CommandResults(readable_output=readable_output,
                          outputs=outputs,
                          raw_response=response)


def get_rule_group_command(client: boto3.client, args) -> CommandResults:
    kwargs = {
        'Name': args.get('name', ''),
        'Scope': args.get('scope', ''),
        'Id': args.get('id', '')
    }

    response = client.get_rule_group(**kwargs)

    outputs = response.get('RuleGroup', {})

    readable_output = tableToMarkdown('Rule group', outputs, headers=['Id', 'Name', 'Description'])

    return CommandResults(readable_output=readable_output,
                          outputs=outputs,
                          raw_response=response,
                          outputs_prefix=f'{OUTPUT_PREFIX}.RuleGroup',
                          outputs_key_field='Id')


def delete_rule_group_command(client: boto3.client, args) -> CommandResults:
    kwargs = {
        'Name': args.get('name', ''),
        'Scope': args.get('scope', ''),
        'Id': args.get('id', '')
    }

    get_response = client.get_rule_group(**kwargs)

    kwargs |= {'LockToken': get_response.get('LockToken', '')}

    response = client.delete_rule_group(**kwargs)

    readable_output = f'AWS Waf rule group with id {args.get("id", "")} was deleted successfully'

    return CommandResults(readable_output=readable_output,
                          raw_response=response)


def update_rule(client: boto3.client, args, build_rule_func) -> dict:
    kwargs = {
        'Name': args.get('group_name', ''),
        'Scope': args.get('scope', ''),
        'Id': args.get('group_id', '')
    }

    response = client.get_rule_group(**kwargs)

    rule_group = response.get('RuleGroup', {})
    rules = rule_group.get('Rules', [])

    rule_group_visibility_config = rule_group.get('VisibilityConfig', {})

    # TODO change logic so would be good for deletion as well
    if build_rule_func == 'delete_rule':
        rule_name = args.get(('rule_name', ''))
        updated_rules = delete_rule(rule_name, rules)
    else:
        rule = build_rule_object(args, rule_group_visibility_config, build_rule_func)
        updated_rules = rules.copy()
        updated_rules.append(rule)

    kwargs |= {'LockToken': response.get('LockToken'),
               'Rules': updated_rules,
               'VisibilityConfig': rule_group_visibility_config
               }

    return client.update_rule_group(**kwargs)


def delete_rule(rule_name: str, rules: list) -> list:
    updated_rules = rules.copy()
    for rule in rules:
        if rule.get('Name') == rule_name:
            updated_rules.remove(rule)
            break
    return updated_rules

def create_rule_group_command(client: boto3.client, args) -> CommandResults:
    tag_keys = argToList(args.get('tag_key')) or []
    tag_values = argToList(args.get('tag_value')) or []
    name = args.get('name', '')
    cloud_watch_metrics_enabled = argToBoolean(args.get('cloud_watch_metrics_enabled', '')) or True
    metric_name = args.get('metric_name', '') or name
    sampled_requests_enabled = argToBoolean(args.get('sampled_requests_enabled', '')) or True

    kwargs = {
        'Name': name,
        'Scope': args.get('scope', ''),
        'Capacity': arg_to_number(args.get('capacity', '')),
        'VisibilityConfig': build_visibility_config_object(cloud_watch_metrics_enabled=cloud_watch_metrics_enabled,
                                                           metric_name=metric_name,
                                                           sampled_requests_enabled=sampled_requests_enabled)
    }

    if description := args.get('description'):
        kwargs |= {'Description': description}
    if tags := get_tags_dict_from_args(tag_keys, tag_values):
        kwargs |= {'Tags': tags}

    response = client.create_rule_group(**kwargs)
    outputs = response.get('Summary', {})

    readable_output = f'AWS Waf rule group with id {outputs.get("Id", "")} was created successfully'

    return CommandResults(readable_output=readable_output,
                          outputs=outputs,
                          raw_response=response,
                          outputs_prefix=f'{OUTPUT_PREFIX}.RuleGroup',
                          outputs_key_field='Id')


def create_ip_rule_command(client: boto3.client, args) -> CommandResults:
    response = update_rule(client, args, build_ip_rule_object)

    readable_output = f'AWS Waf ip rule with id {args.get("Id", "")} was created successfully. ' \
                      f'Next Lock Token: {response.get("NextLockToken")}'

    return CommandResults(readable_output=readable_output,
                          raw_response=response)


def create_country_rule_command(client: boto3.client, args) -> CommandResults:
    response = update_rule(client, args, build_country_rule_object)

    readable_output = f'AWS Waf country rule with id {args.get("Id", "")} was created successfully. ' \
                      f'Next Lock Token: {response.get("NextLockToken")}'

    return CommandResults(readable_output=readable_output,
                          raw_response=response)


def create_string_match_rule_command(client: boto3.client, args) -> CommandResults:
    # TODO need to change
    response = update_rule(client, args, build_country_rule_object)

    readable_output = f'AWS Waf string match rule with id {args.get("Id", "")} was created successfully. ' \
                      f'Next Lock Token: {response.get("NextLockToken")}'

    return CommandResults(readable_output=readable_output,
                          raw_response=response)


def delete_rule_command(client: boto3.client, args) -> CommandResults:
    response = update_rule(client, args, build_country_rule_object)

    readable_output = f'AWS Waf rule with id {args.get("Id", "")} was deleted successfully.'

    return CommandResults(readable_output=readable_output,
                          raw_response=response)


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    params = demisto.params()
    aws_default_region = params.get('defaultRegion')
    aws_role_arn = params.get('roleArn')
    aws_role_session_name = params.get('roleSessionName')
    aws_role_session_duration = params.get('sessionDuration')
    aws_role_policy = None
    aws_access_key_id = params.get('access_key', {}).get('password') or params.get('access_key')
    aws_secret_access_key = params.get('secret_key', {}).get('password') or params.get('secret_key')
    verify_certificate = not params.get('insecure', True)
    timeout = params.get('timeout') or 1
    retries = params.get('retries') or 5

    try:
        validate_params(aws_default_region, aws_role_arn, aws_role_session_name, aws_access_key_id,
                        aws_secret_access_key)

        aws_client = AWSClient(aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
                               aws_role_policy, aws_access_key_id, aws_secret_access_key, verify_certificate,
                               timeout, retries)
        args = demisto.args()

        client = aws_client.aws_session(service=SERVICE, region=args.get('region'))

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            result = connection_test(client)

        elif demisto.command() == 'aws-waf-ip-set-create':
            result = create_ip_set_command(client, args)
        elif demisto.command() == 'aws-waf-ip-set-get':
            result = get_ip_set_command(client, args)
        elif demisto.command() == 'aws-waf-ip-set-update':
            result = update_ip_set_command(client, args)
        elif demisto.command() == 'aws-waf-ip-set-list':
            result = list_ip_set_command(client, args)
        elif demisto.command() == 'aws-waf-ip-set-delete':
            result = delete_ip_set_command(client, args)

        elif demisto.command() == 'aws-waf-regex-set-create':
            result = create_regex_set_command(client, args)
        elif demisto.command() == 'aws-waf-regex-set-get':
            result = get_regex_set_command(client, args)
        elif demisto.command() == 'aws-waf-regex-set-update':
            result = update_regex_set_command(client, args)
        elif demisto.command() == 'aws-waf-regex-set-list':
            result = list_regex_set_command(client, args)
        elif demisto.command() == 'aws-waf-regex-set-delete':
            result = delete_regex_set_command(client, args)

        elif demisto.command() == 'aws-waf-rule-group-list':
            result = list_rule_group_command(client, args)
        elif demisto.command() == 'aws-waf-rule-group-get':
            result = get_rule_group_command(client, args)
        elif demisto.command() == 'aws-waf-rule-group-delete':
            result = delete_rule_group_command(client, args)
        elif demisto.command() == 'aws-waf-rule-group-create':
            result = create_rule_group_command(client, args)

        elif demisto.command() == 'aws-waf-ip-rule-create':
            result = create_ip_rule_command(client, args)
        elif demisto.command() == 'aws-waf-country-rule-create':
            result = create_country_rule_command(client, args)
        elif demisto.command() == 'aws-waf-string-match-rule-create':
            result = create_string_match_rule_command(client, args)
        elif demisto.command() == 'aws-waf-rule-delete':
            result = delete_rule_command(client, args)

        else:
            raise NotImplementedError(f'Command {demisto.command()} is not implemented in AWS WAF integration.')

        return_results(result)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
