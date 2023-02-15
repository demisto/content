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


def create_ip_set_command(client: boto3.session.Session.client, args) -> CommandResults:
    tag_keys = argToList(args.get('tag_key')) or []
    tag_values = args.get('tag_value') or []
    kwargs = {
        'Name': args.get('name', ''),
        'Scope': args.get('scope', ''),
        'Description': args.get('description'),
        'IPAddressVersion': args.get('ip_version', ''),
        'Tags': get_tags_dict_from_args(tag_keys, tag_values),
    }
    remove_nulls_from_dictionary(kwargs)
    kwargs |= {'Addresses': argToList(args.get('addresses')) or []}
    response = client.create_ip_set(**kwargs)
    outputs = response.get('Summary', {})

    readable_output = f'AWS Waf ip set with id {outputs.get("Id", "")} was created successfully'

    return CommandResults(readable_output=readable_output,
                          outputs=outputs,
                          raw_response=response,
                          outputs_prefix=f'{OUTPUT_PREFIX}.IpSet',
                          outputs_key_field='Id')


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

        client = aws_client.aws_session(service=SERVICE)
        result = ''

        if demisto.command() == 'test-module':
            pass
            # This is the call made when pressing the integration test button.
            # result = connection_test(client)
            result = ''

        elif demisto.command() == 'aws-waf-ip-set-create':
            result = create_ip_set_command(client, args)

        else:
            raise NotImplementedError(f'Command {demisto.command()} is not implemented in AWS WAF integration.')

        return_results(result)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
