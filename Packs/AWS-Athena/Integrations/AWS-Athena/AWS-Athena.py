import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import boto3
import json
from datetime import datetime, date
from botocore.config import Config
from botocore.parsers import ResponseParserError
import urllib3.util

# Disable insecure warnings
urllib3.disable_warnings()

"""HELPER FUNCTIONS"""


class DatetimeEncoder(json.JSONEncoder):
    # pylint: disable=method-hidden
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


def start_query_execution_command(args, aws_client):
    client = aws_client.aws_session(
        service='athena',
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    data = []
    kwargs = {'QueryString': args.get('QueryString')}
    if args.get('ClientRequestToken') is not None:
        kwargs.update({'ClientRequestToken': args.get('ClientRequestToken')})
    if args.get('Database') is not None:
        kwargs.update({'QueryExecutionContext': {'Database': args.get('Database')}})
    if args.get('OutputLocation') is not None:
        kwargs.update({'ResultConfiguration': {'OutputLocation': args.get('OutputLocation')}})
    if args.get('EncryptionOption') is not None:
        kwargs.update({'ResultConfiguration': {'EncryptionConfiguration': {'EncryptionOption': args.get('EncryptionOption')}}})
    if args.get('KmsKey') is not None:
        kwargs.update({'ResultConfiguration': {'EncryptionConfiguration': {'KmsKey': args.get('KmsKey')}}})
    if args.get('WorkGroup') is not None:
        kwargs.update({'WorkGroup': args.get('WorkGroup')})

    response = client.start_query_execution(**kwargs)

    data.append({
        'QueryString': args.get('QueryString'),
        'QueryExecutionId': response['QueryExecutionId']
    })
    ec = {'AWS.Athena.Query': data}
    human_readable = tableToMarkdown('AWS Athena Query', data)
    return_outputs(human_readable, ec)


def stop_query_command(args, aws_client):
    client = aws_client.aws_session(
        service='athena',
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )

    response = client.stop_query_execution(QueryExecutionId=args.get('QueryExecutionId'))
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Query {query} was Deleted ".format(query=args.get('QueryExecutionId')))


def get_query_execution_command(args, aws_client):
    client = aws_client.aws_session(
        service='athena',
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    kwargs = {'QueryExecutionId': args.get('QueryExecutionId')}
    response = client.get_query_execution(**kwargs)
    try:
        raw = json.loads(json.dumps(response, cls=DatetimeEncoder))
    except ValueError as e:
        return_error('Could not decode/encode the raw response - {err_msg}'.format(err_msg=e))
    ec = {'AWS.Athena.Query(val.QueryExecutionId === obj.QueryExecutionId)': raw}
    human_readable = tableToMarkdown('AWS Athena Query', raw)
    return_outputs(human_readable, ec)


def get_query_results_command(args, aws_client):
    client = aws_client.aws_session(
        service='athena',
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    kwargs = {'QueryExecutionId': args.get('QueryExecutionId')}
    response = client.get_query_results(**kwargs)
    ec = {'AWS.Athena.Query(val.QueryExecutionId === obj.QueryExecutionId)': response}
    human_readable = tableToMarkdown('AWS Athena Query', response)
    return_outputs(human_readable, ec)


def main():
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
        retries = params.get('retries') or 5

        validate_params(aws_default_region, aws_role_arn, aws_role_session_name, aws_access_key_id,
                        aws_secret_access_key)
        aws_client = AWSClient(aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
                               aws_role_policy, aws_access_key_id, aws_secret_access_key, verify_certificate, timeout,
                               retries)

        command = demisto.command()
        args = demisto.args()

        LOG('Command being called is {command}'.format(command=demisto.command()))
        if demisto.command() == 'test-module':
            client = aws_client.aws_session(service='athena')
            response = client.list_named_queries()
            if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                demisto.results('ok')

        elif command == 'aws-athena-start-query':
            start_query_execution_command(args, aws_client)

        elif command == 'aws-athena-stop-query':
            stop_query_command(args, aws_client)

        elif command == 'aws-athena-get-query-execution':
            get_query_execution_command(args, aws_client)

        elif command == 'aws-athena-get-query-results':
            get_query_results_command(args, aws_client)

    except Exception as e:
        return_error('Error has occurred in the AWS Athena Integration: {error}\n {message}'.format(
            error=type(e), message=e))


from AWSApiModule import *  # noqa: E402


if __name__ in ['__builtin__', 'builtins', '__main__']:
    main()
