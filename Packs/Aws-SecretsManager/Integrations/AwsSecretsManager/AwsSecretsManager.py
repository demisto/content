# ruff: noqa: RUF001
# we shouldnt break backwards compatibility for this error

import traceback

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import json
from datetime import datetime, date

import urllib3
from typing import Any

from AWSApiModule import *  # noqa: E402

SERVICE = 'secretsmanager'

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

''' HELPER FUNCTIONS '''


class DatetimeEncoder(json.JSONEncoder):
    # pylint: disable=method-hidden
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


''' COMMAND FUNCTIONS '''
SENSITIVE_COMMANDS = ["aws-secrets-manager-secret–value-get"]


def test_module(client: AWSClient):
    aws_client = client.aws_session(
        service=SERVICE
    )

    response = aws_client.list_secrets(MaxResults=1)

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results('ok')


def aws_secrets_manager_secret_list_command(client: AWSClient, args: dict[str, Any]):
    aws_client = client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )

    description = args.get('description')
    name = args.get('name')
    tag_key = args.get('tag_key')
    tag_value = args.get('tag_value')
    general_search = args.get('general_search')
    sort = args.get('sort', 'desc')
    limit = int(args.get('limit', 50))
    page = int(args.get('page', 1)) - 1
    page_size = int(args.get('page_size', 50))

    offset = page_size * page
    end = page_size * page + page_size

    filters = []
    if description:
        filters.append({'Key': 'description', 'Values': description})
    if name:
        filters.append({'Key': 'name', 'Values': name})
    if tag_key:
        filters.append({'Key': 'tag_key', 'Values': tag_key})
    if tag_value:
        filters.append({'Key': 'tag_value', 'Values': tag_value})
    if general_search:
        filters.append({'Key': 'all', 'Values': general_search})

    response = aws_client.list_secrets(Filters=filters, SortOrder=sort, MaxResults=limit)

    output = json.dumps(response, cls=DatetimeEncoder)
    response = json.loads(output)

    readable_output = [{'Name': secret.get('Name', ''),
                        'ARN': secret.get('ARN', ''),
                        'Description': secret.get('Description', ''),
                        'LastAccessedDate': secret.get('LastChangedDate', '')}
                       for secret in response['SecretList'][offset:end]]

    human_readable = tableToMarkdown('AWS Secrets List', readable_output)

    return_results(CommandResults(
        outputs_prefix='AWS.SecretsManager.Secret',
        outputs=response,
        outputs_key_field='Name',
        readable_output=human_readable
    ))


def aws_secrets_manager_secret_value_get_command(client: AWSClient, args: dict[str, Any]):
    client = client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )

    kwargs = {}

    if args.get('secret_id'):
        kwargs['SecretId'] = args.get('secret_id')
    else:
        return_error('Get command cannot be executed without "secret_id" param')

    if args.get('version_id'):
        kwargs['VersionId'] = args.get('version_id')
    if args.get('version_stage'):
        kwargs['VersionStage'] = args.get('version_stage')

    response = client.get_secret_value(**kwargs)

    output = json.dumps(response, cls=DatetimeEncoder)
    response = json.loads(output)

    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        return_error(f'Get command encountered an issue, got unexpected result! {response["ResponseMetadata"]}')

    readable_output = {'Name': response.get('Name', ''),
                       'ARN': response.get('ARN', ''),
                       'SecretBinary': response.get('SecretBinary', ''),
                       'SecretString': response.get('SecretString', ''),
                       'CreatedDate': response.get('CreatedDate', '')}

    human_readable = tableToMarkdown('AWS Get Secret', readable_output)

    return_results(CommandResults(
        outputs_prefix='AWS.SecretsManager.Secret.SecretValue',
        outputs=response,
        outputs_key_field='Name',
        readable_output=human_readable
    ))


def aws_secrets_manager_secret_delete_command(client: AWSClient, args):
    client = client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )

    kwargs = {}

    if args.get('secret_id'):
        kwargs['SecretId'] = args.get('secret_id')
    if args.get('days_of_recovery'):
        kwargs['RecoveryWindowInDays'] = int(args.get('days_of_recovery'))
    if args.get('delete_immediately') is not None:
        if args.get('days_of_recovery'):
            raise Exception('Delete command cannot be executed with both args: delete_immediately and days_of_recovery')
        kwargs['ForceDeleteWithoutRecovery'] = argToBoolean(args.get('delete_immediately'))

    response = client.delete_secret(**kwargs)

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Secret was Deleted")


def aws_secrets_manager_secret_restore_command(client: AWSClient, args: dict[str, Any]):
    client = client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )

    if not args.get('secret_id'):
        raise Exception('secret_id is mandatory inorder to run this command!')

    response = client.restore_secret(SecretId=args.get('secret_id'))

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("the secret was restored successfully")


def aws_secrets_manager_secret_policy_get_command(client: AWSClient, args: dict[str, Any]):
    client = client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )

    if not args.get('secret_id'):
        return_error('secret_id is mandatory inorder to run this command!')

    response = client.get_resource_policy(
        SecretId=args.get('secret_id')
    )

    readable_output = {'Name': response.get('Name', ''),
                       'ARN': response.get('ARN', ''),
                       'Policy': response.get('ResourcePolicy', '')}

    human_readable = tableToMarkdown('AWS Secret Policy', readable_output)

    return_results(CommandResults(
        outputs_prefix='AWS.SecretsManager.Policy',
        outputs=response,
        outputs_key_field='Name',
        readable_output=human_readable
    ))


def fetch_credentials(client: AWSClient, args: dict[str, Any]):  # pragma: no cover
    client = client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )

    creds_dict = {}
    if args.get('secret_id'):
        try:
            creds_dict[args.get('secret_id')] = client.get_secret_value(SecretId=args.get('secret_id'))
        except Exception as e:
            demisto.debug(f"Could not fetch credentials: {args.get('secret_id')}. Error: {e}")
    else:
        for secret in client.list_secrets()['SecretList']:
            creds_dict[secret.get('Name')] = client.get_secret_value(SecretId=secret.get('Name'))

    credentials = []
    for cred_key in creds_dict:
        try:
            secret_as_dict = json.loads(creds_dict[cred_key].get("SecretString"))

            if should_create_credential(secret_as_dict):
                credentials.append({
                    "user": secret_as_dict.get("username", ""),
                    "password": secret_as_dict.get("password", ""),
                    "workgroup": secret_as_dict.get("workgroup", ""),
                    "certificate": secret_as_dict.get("certificate", ""),
                    "name": f'{creds_dict[cred_key].get("Name")}',
                })
            else:
                demisto.debug(f'({creds_dict[cred_key]}) has no keys supporting the format')
        except Exception as e:
            demisto.debug(f'exception occured during parsing {e}')
            return_error(f'theres is a problem parsing ({creds_dict[cred_key]}) secret value, {e}')
    demisto.credentials(credentials)


def should_create_credential(secret_as_dict):
    return any(key in ["username", "password", "workgroup", "certificate"] for key in secret_as_dict)


def main():  # pragma: no cover:
    try:
        params = demisto.params()
        if argToBoolean(params.get('disable_sensitive_commands')) and demisto.command() in SENSITIVE_COMMANDS:
            raise ValueError('Sensitive commands are disabled. You can reenable them in the integration settings.')
        aws_default_region = params.get('defaultRegion')
        aws_role_arn = params.get('roleArn')
        aws_role_session_name = params.get('roleSessionName')
        aws_role_session_duration = params.get('sessionDuration')
        aws_role_policy = None
        aws_access_key_id = params.get('credentials', {}).get('identifier')
        aws_secret_access_key = params.get('credentials', {}).get('password')
        verify_certificate = not argToBoolean(params.get('insecure'))
        timeout = params.get('timeout')
        retries = int(params.get('retries')) if params.get('retries') else 5

        validate_params(aws_default_region, aws_role_arn, aws_role_session_name, aws_access_key_id,
                        aws_secret_access_key)

        aws_client = AWSClient(aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
                               aws_role_policy, aws_access_key_id, aws_secret_access_key, verify_certificate, timeout,
                               retries)

        args = demisto.args()

        if demisto.command() == 'test-module':
            test_module(aws_client)
        elif demisto.command() == 'aws-secrets-manager-secret-list':
            aws_secrets_manager_secret_list_command(aws_client, args)
        elif demisto.command() == 'aws-secrets-manager-secret–value-get':
            aws_secrets_manager_secret_value_get_command(aws_client, args)
        elif demisto.command() == 'aws-secrets-manager-secret–delete':
            aws_secrets_manager_secret_delete_command(aws_client, args)
        elif demisto.command() == 'aws-secrets-manager-secret–restore':
            aws_secrets_manager_secret_restore_command(aws_client, args)
        elif demisto.command() == 'aws-secrets-manager-secret–policy-get':
            aws_secrets_manager_secret_policy_get_command(aws_client, args)
        elif demisto.command() == 'fetch-credentials':
            fetch_credentials(aws_client, args)

    except Exception as e:
        demisto.debug(f'error from command {e}, {traceback.format_exc()}')
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
