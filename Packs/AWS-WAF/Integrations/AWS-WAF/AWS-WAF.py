import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from AWSApiModule import *  # noqa: E402
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
    regex_patterns_objects: list = []
    for regex_pattern in regex_patterns:
        regex_patterns_objects.append({'RegexString': regex_pattern})

    return regex_patterns_objects

''' COMMAND FUNCTIONS '''


def module(client: boto3.client) -> str:
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

    readable_output = tableToMarkdown('List IP Sets', response, is_auto_json_transform=True)

    return CommandResults(readable_output=readable_output,
                          outputs=response,
                          raw_response=response,
                          outputs_prefix=f'{OUTPUT_PREFIX}.IpSet',
                          outputs_key_field='Id')


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
    print(overwrite)

    get_response = client.get_regex_pattern_set(**kwargs)

    lock_token = get_response.get('LockToken', '')
    original_patterns = get_response.get('RegexPatternSet', {}).get('RegularExpressionList')
    if not overwrite:
        patterns_to_update.extend(original_patterns)

    print(patterns_to_update)
    print(original_patterns)

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

    readable_output = tableToMarkdown('List regex Sets', response, is_auto_json_transform=True)

    return CommandResults(readable_output=readable_output,
                          outputs=response,
                          raw_response=response,
                          outputs_prefix=f'{OUTPUT_PREFIX}.RegexSet',
                          outputs_key_field='Id')


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
        result = ''

        if demisto.command() == 'test-module':
            pass
            # This is the call made when pressing the integration test button.
            # result = connection_test(client)
            result = ''

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

        else:
            raise NotImplementedError(f'Command {demisto.command()} is not implemented in AWS WAF integration.')

        return_results(result)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
