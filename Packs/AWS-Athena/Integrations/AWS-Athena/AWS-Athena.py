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

"""PARAMETERS"""
AWS_DEFAULT_REGION = demisto.params().get('defaultRegion')
AWS_ROLE_ARN = demisto.params().get('roleArn')
AWS_ROLE_SESSION_NAME = demisto.params().get('roleSessionName')
AWS_ROLE_SESSION_DURATION = demisto.params().get('sessionDuration')
AWS_ROLE_POLICY = None
AWS_ACCESS_KEY_ID = demisto.params().get('access_key')
AWS_SECRET_ACCESS_KEY = demisto.params().get('secret_key')
VERIFY_CERTIFICATE = not demisto.params().get('insecure', True)
proxies = handle_proxy(proxy_param_name='proxy', checkbox_default_value=False)
config = Config(
    connect_timeout=1,
    retries=dict(
        max_attempts=5
    ),
    proxies=proxies
)


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


def aws_session(service='athena', region=None, roleArn=None, roleSessionName=None, roleSessionDuration=None,
                rolePolicy=None):
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


def start_query_execution_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
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


def stop_query_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    response = client.stop_query_execution(QueryExecutionId=args.get('QueryExecutionId'))
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Query {query} was Deleted ".format(query=args.get('QueryExecutionId')))


def get_query_execution_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
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


def get_query_results_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {'QueryExecutionId': args.get('QueryExecutionId')}
    response = client.get_query_results(**kwargs)
    ec = {'AWS.Athena.Query(val.QueryExecutionId === obj.QueryExecutionId)': response}
    human_readable = tableToMarkdown('AWS Athena Query', response)
    return_outputs(human_readable, ec)


"""COMMAND BLOCK"""
try:
    LOG('Command being called is {command}'.format(command=demisto.command()))
    if demisto.command() == 'test-module':
        client = aws_session()
        response = client.list_named_queries()
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            demisto.results('ok')

    elif demisto.command() == 'aws-athena-start-query':
        start_query_execution_command(demisto.args())

    elif demisto.command() == 'aws-athena-stop-query':
        stop_query_command(demisto.args())

    elif demisto.command() == 'aws-athena-get-query-execution':
        get_query_execution_command(demisto.args())

    elif demisto.command() == 'aws-athena-get-query-results':
        get_query_results_command(demisto.args())


except ResponseParserError as e:
    return_error('Could not connect to the AWS endpoint. Please check that the region is valid.\n {error}'.format(
        error=type(e)))
    LOG(e)

except Exception as e:
    return_error('Error has occurred in the AWS Athena Integration: {error}\n {message}'.format(
        error=type(e), message=e))
