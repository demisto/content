

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
from typing import Dict, Any
import botocore.exceptions


from AWSApiModule import *  # noqa: E402

SERVICE = 'secretsmanager'


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' HELPER FUNCTIONS '''

''' COMMAND FUNCTIONS '''


def test_module(client: AWSClient) -> str:
    aws_client = client.aws_session(
        service=SERVICE
    )

    response = aws_client.list_secrets(MaxResults=1)

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results('ok')


def aws_secrets_manager_secret_list_command(client: AWSClient, args: Dict[str, Any]) -> CommandResults:
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
    limit = args.get('limit', 50)
    page = args.get('page', 1)
    page_size = args.get('page_size', 50)

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


    response = aws_client.list_secrets(Filters=filters, SortOrder=sort)

    readable_output = [{'Name': secret.get('Name', ''),
                        'ARN': secret.get('ARN', ''),
                        'Description': secret.get('Description', ''),
                        'LastAccessedDate': secret.get('LastChangedDate', '')} for secret in response['SecretList']]

    human_readable = tableToMarkdown('AWS Secrets List', readable_output)

    return_results(CommandResults(
        outputs_prefix='AWS.SecretsManager.Secret',
        outputs=response,
        readable_output=human_readable
    ))


def aws_secrets_manager_secret_value_get_command(client: AWSClient, args: Dict[str, Any]) -> CommandResults:
    client = client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )

    kwargs = dict()

    if args.get('secret_id'):
        kwargs['SecretId'] = args.get('secret_id')
    else:
        return_error('Get command cannot be executed without "secret_id" param')

    if args.get('version_id'):
        kwargs['VersionId'] = args.get('version_id')
    if args.get('version_stage'):
        kwargs['VersionStage'] = args.get('version_stage')

    response = client.get_secret_value(**kwargs)

    if not response['ResponseMetadata']['HTTPStatusCode'] == 200:
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
        readable_output=human_readable
    ))

def aws_secrets_manager_secret_delete_command(client: AWSClient, args: Dict[str, Any]) -> CommandResults:
    client = client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )

    kwargs = dict()

    if args.get('secret_id'):
        kwargs['SecretId'] = args.get('secret_id')
    if args.get('days_of_recovery'):
        kwargs['RecoveryWindowInDays'] = int(args.get('days_of_recovery'))
    if args.get('delete_immediately'):
        if args.get('days_of_recovery'):
            return_error('Delete command cannot be executed with both args: delete_immediately and days_of_recovery')
        kwargs['ForceDeleteWithoutRecovery'] = args.get('delete_immediately', 'false').lower() == 'true'

    response = client.delete_secret(**kwargs)

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Secret was Deleted")

def aws_secrets_manager_secret_restore_command(client: AWSClient, args: Dict[str, Any]) -> CommandResults:
    client = client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )

    if not args.get('secret_id'):
        return_error('secret_id is mandatory inorder to run this command!')

    response = client.restore_secret(SecretId=args.get('secret_id'))

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("the secret was restored successfully")

def aws_secrets_manager_secret_policy_get_command(client: AWSClient, args: Dict[str, Any]) -> CommandResults:
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

    return CommandResults(
        outputs_prefix='AWS.SecretsManager.Policy',
        outputs=response,
        readable_output=human_readable
    )

def fetch_credentials(client: AWSClient, args: Dict[str, Any]) -> CommandResults:
    client = client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )

    creds_dict = dict()
    if args.get('secret_id'):
        try:
            creds_dict[args.get('secret_id')] = client.get_secret_value(SecretId=args.get('secret_id'))
        except Exception as e:
            demisto.debug(f"Could not fetch credentials: {args.get('secret_id')}. Error: {e}")
    else:
        for secret in client.list_secrets()['SecretList']:
            creds_dict[secret.get('Name')] = client.get_secret_value(SecretId=secret.get('Name'))

    credentials = []
    for cred_key in creds_dict.keys():
        credentials.append({
            "user": creds_dict[cred_key].get("Name"),
            "password": creds_dict[cred_key].get("SecretString"),
            "name": f'{cred_key}/{creds_dict[cred_key].get("Name")}',
        })
    demisto.credentials(credentials)

def main() -> None:
    try:
        params = demisto.params()
        aws_default_region = params.get('defaultRegion')
        aws_role_arn = params.get('roleArn')
        aws_role_session_name = params.get('roleSessionName')
        aws_role_session_duration = params.get('sessionDuration')
        aws_role_policy = None
        aws_access_key_id = params.get('access_key')
        aws_secret_access_key = params.get('secret_key')
        verify_certificate = not params.get('insecure', True)
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
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')

''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
