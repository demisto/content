import boto3
import demistomock as demisto  # noqa: F401
from botocore.config import Config
from CommonServerPython import *  # noqa: F401

"""IMPORTS"""
from datetime import date

import urllib3.util

# Disable insecure warnings
urllib3.disable_warnings()

# contrib mini deom


def parse_tag_field(tags_str):
    tags = []
    regex = re.compile(r'key=([\w\d_:.-]+),value=([ /\w\d@_,.\*-]+)', flags=re.I)
    for f in tags_str.split(';'):
        match = regex.match(f)
        if match is None:
            demisto.log('could not parse field: %s' % (f,))
            continue

        tags.append({
            'Key': match.group(1),
            'Value': match.group(2)
        })
    return tags


class DatetimeEncoder(json.JSONEncoder):
    # pylint: disable=method-hidden
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


def parse_resource_ids(resource_id):
    id_list = resource_id.replace(" ", "")
    resource_ids = id_list.split(",")
    return resource_ids


def create_entry(title, data, ec):
    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': data,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, data) if data else 'No result were found',
        'EntryContext': ec
    }


"""MAIN FUNCTIONS"""


def get_function(args, aws_client):
    client = aws_client.aws_session(
        service='lambda',
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    obj = vars(client._client_config)
    kwargs = {'FunctionName': args.get('functionName')}
    if args.get('qualifier') is not None:
        kwargs.update({'Qualifier': args.get('qualifier')})

    response = client.get_function(**kwargs)
    func = response['Configuration']
    data = ({
        'FunctionName': func['FunctionName'],
        'FunctionArn': func['FunctionArn'],
        'Runtime': func['Runtime'],
        'Region': obj['_user_provided_options']['region_name'],
    })

    raw = json.loads(json.dumps(response, cls=DatetimeEncoder))
    if raw:
        raw.update({'Region': obj['_user_provided_options']['region_name']})

    ec = {'AWS.Lambda.Functions(val.FunctionArn === obj.FunctionArn)': raw}
    human_readable = tableToMarkdown('AWS Lambda Functions', data)
    return_outputs(human_readable, ec)


def list_functions(args, aws_client):
    client = aws_client.aws_session(
        service='lambda',
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    obj = vars(client._client_config)
    data = []
    output = []

    paginator = client.get_paginator('list_functions')
    for response in paginator.paginate():
        for function in response['Functions']:
            data.append({
                'FunctionName': function['FunctionName'],
                'FunctionArn': function['FunctionArn'],
                'Runtime': function['Runtime'],
                'LastModified': function['LastModified'],
                'Region': obj['_user_provided_options']['region_name'],
            })
            output.append(function)

    raw = json.loads(json.dumps(response, cls=DatetimeEncoder))
    if raw:
        raw.update({'Region': obj['_user_provided_options']['region_name']})

    ec = {'AWS.Lambda.Functions(val.FunctionArn === obj.FunctionArn)': raw}
    human_readable = tableToMarkdown('AWS Lambda Functions', data)
    return_outputs(human_readable, ec)


def list_aliases(args, aws_client):
    client = aws_client.aws_session(
        service='lambda',
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )

    data = []
    output = []
    kwargs = {'FunctionName': args.get('functionName')}
    if args.get('functionVersion') is not None:
        kwargs.update({'FunctionVersion': args.get('functionVersion')})

    paginator = client.get_paginator('list_aliases')
    for response in paginator.paginate(**kwargs):
        for alias in response['Aliases']:
            data.append({
                'AliasArn': alias['AliasArn'],
                'Name': alias['Name'],
                'FunctionVersion': alias['FunctionVersion'],
            })
            output.append(alias)
    try:
        raw = json.loads(json.dumps(output, cls=DatetimeEncoder))
    except ValueError as e:
        return_error('Could not decode/encode the raw response - {err_msg}'.format(err_msg=e))
    ec = {'AWS.Lambda.Aliases(val.AliasArn === obj.AliasArn)': raw}
    human_readable = tableToMarkdown('AWS Lambda Aliases', data)
    return_outputs(human_readable, ec)


def invoke(args, aws_client):
    client = aws_client.aws_session(
        service='lambda',
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    obj = vars(client._client_config)
    kwargs = {'FunctionName': args.get('functionName')}
    if args.get('invocationType') is not None:
        kwargs.update({'InvocationType': args.get('invocationType')})
    if args.get('logType') is not None:
        kwargs.update({'LogType': args.get('logType')})
    if args.get('clientContext') is not None:
        kwargs.update({'ClientContext': args.get('clientContext')})
    if args.get('payload') is not None:
        payload = args.get('payload')
        if (not isinstance(payload, str)) or (not payload.startswith('{') and not payload.startswith('[')):
            payload = json.dumps(payload)
        kwargs.update({'Payload': payload})
    if args.get('qualifier') is not None:
        kwargs.update({'Qualifier': args.get('qualifier')})
    response = client.invoke(**kwargs)
    data = ({
        'FunctionName': args.get('functionName'),
        'Region': obj['_user_provided_options']['region_name'],
    })
    if 'LogResult' in response:
        data.update({'LogResult': base64.b64decode(response['LogResult']).decode("utf-8")})  # type:ignore
    if 'Payload' in response:
        data.update({'Payload': response['Payload'].read().decode("utf-8")})  # type:ignore
    if 'ExecutedVersion' in response:
        data.update({'ExecutedVersion': response['ExecutedVersion']})  # type:ignore
    if 'FunctionError' in response:
        data.update({'FunctionError': response['FunctionError']})

    ec = {'AWS.Lambda.InvokedFunctions(val.FunctionName === obj.FunctionName)': data}
    human_readable = tableToMarkdown('AWS Lambda Invoked Functions', data)
    return_outputs(human_readable, ec)


def remove_permission(args, aws_client):
    client = aws_client.aws_session(
        service='lambda',
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    kwargs = {
        'FunctionName': args.get('functionName'),
        'StatementId': args.get('StatementId')
    }
    if args.get('Qualifier') is not None:
        kwargs.update({'Qualifier': args.get('Qualifier')})
    if args.get('RevisionId') is not None:
        kwargs.update({'RevisionId': args.get('RevisionId')})

    response = client.remove_permission(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results('Permissions have been removed')


def get_account_settings(args, aws_client):
    client = aws_client.aws_session(
        service='lambda',
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    obj = vars(client._client_config)
    response = client.get_account_settings()
    account_limit = response['AccountLimit']
    account_usage = response['AccountUsage']
    data = {
        'AccountLimit': {
            'TotalCodeSize': str(account_limit['TotalCodeSize']),
            'CodeSizeUnzipped': str(account_limit['CodeSizeUnzipped']),
            'CodeSizeZipped': str(account_limit['CodeSizeZipped']),
            'ConcurrentExecutions': str(account_limit['ConcurrentExecutions']),
            'UnreservedConcurrentExecutions': str(account_limit['UnreservedConcurrentExecutions'])
        },
        'AccountUsage': {
            'TotalCodeSize': str(account_usage['TotalCodeSize']),
            'FunctionCount': str(account_usage['FunctionCount'])
        }
    }
    try:
        raw = json.loads(json.dumps(response, cls=DatetimeEncoder))
    except ValueError as e:
        return_error('Could not decode/encode the raw response - {err_msg}'.format(err_msg=e))
    if raw:
        raw.update({'Region': obj['_user_provided_options']['region_name']})

    ec = {'AWS.Lambda.Functions(val.Region === obj.Region)': raw}
    human_readable = tableToMarkdown('AWS Lambda Functions', data)
    return_outputs(human_readable, ec)


"""TEST FUNCTION"""


def test_function(aws_client):
    client = aws_client.aws_session(service='lambda')
    response = client.list_functions()
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results('ok')


def main():

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

    try:
        if command == 'test-module':
            test_function(aws_client)
        elif command == 'aws-lambda-get-function':
            get_function(args, aws_client)
        elif command == 'aws-lambda-list-functions':
            list_functions(args, aws_client)
        elif command == 'aws-lambda-list-aliases':
            list_aliases(args, aws_client)
        elif command == 'aws-lambda-invoke':
            invoke(args, aws_client)
        elif command == 'aws-lambda-remove-permission':
            remove_permission(args, aws_client)
        elif command == 'aws-lambda-get-account-settings':
            get_account_settings(args, aws_client)

    except Exception as e:
        return_error('Error has occurred in the AWS Lambda Integration: {error}\n {message}'.format(
            error=type(e), message=str(e)))


### GENERATED CODE ###
# This code was inserted in place of an API module.


def validate_params(aws_default_region, aws_role_arn, aws_role_session_name, aws_access_key_id, aws_secret_access_key):
    """
    Validates that the provided parameters are compatible with the appropriate authentication method.
    """
    if not aws_default_region:
        raise DemistoException('You must specify AWS default region.')

    if bool(aws_access_key_id) != bool(aws_secret_access_key):
        raise DemistoException('You must provide Access Key id and Secret key id to configure the instance with '
                               'credentials.')
    if bool(aws_role_arn) != bool(aws_role_session_name):
        raise DemistoException('Role session name is required when using role ARN.')


class AWSClient:

    def __init__(self, aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
                 aws_role_policy, aws_access_key_id, aws_secret_access_key, verify_certificate, timeout, retries):
        self.aws_default_region = aws_default_region
        self.aws_role_arn = aws_role_arn
        self.aws_role_session_name = aws_role_session_name
        self.aws_role_session_duration = aws_role_session_duration
        self.aws_role_policy = aws_role_policy
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.verify_certificate = verify_certificate

        proxies = handle_proxy(proxy_param_name='proxy', checkbox_default_value=False)
        (read_timeout, connect_timeout) = AWSClient.get_timeout(timeout)
        if int(retries) > 10:
            retries = 10
        self.config = Config(
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            retries=dict(
                max_attempts=int(retries)
            ),
            proxies=proxies
        )

    def update_config(self):
        command_config = {}
        retries = demisto.getArg('retries')  # Supports retries and timeout parameters on the command execution level
        if retries is not None:
            command_config['retries'] = dict(max_attempts=int(retries))
        timeout = demisto.getArg('timeout')
        if timeout is not None:
            (read_timeout, connect_timeout) = AWSClient.get_timeout(timeout)
            command_config['read_timeout'] = read_timeout
            command_config['connect_timeout'] = connect_timeout
        if retries or timeout:
            demisto.debug('Merging client config settings: {}'.format(command_config))
            self.config = self.config.merge(Config(**command_config))

    def aws_session(self, service, region=None, role_arn=None, role_session_name=None, role_session_duration=None,
                    role_policy=None):
        kwargs = {}

        self.update_config()

        if role_arn and role_session_name is not None:
            kwargs.update({
                'RoleArn': role_arn,
                'RoleSessionName': role_session_name,
            })
        elif self.aws_role_arn and self.aws_role_session_name is not None:
            kwargs.update({
                'RoleArn': self.aws_role_arn,
                'RoleSessionName': self.aws_role_session_name,
            })

        if role_session_duration is not None:
            kwargs.update({'DurationSeconds': int(role_session_duration)})
        elif self.aws_role_session_duration is not None:
            kwargs.update({'DurationSeconds': int(self.aws_role_session_duration)})

        if role_policy is not None:
            kwargs.update({'Policy': role_policy})
        elif self.aws_role_policy is not None:
            kwargs.update({'Policy': self.aws_role_policy})

        if kwargs and not self.aws_access_key_id:  # login with Role ARN

            if not self.aws_access_key_id:
                sts_client = boto3.client('sts', config=self.config, verify=self.verify_certificate,
                                          region_name=self.aws_default_region)
                sts_response = sts_client.assume_role(**kwargs)
                client = boto3.client(
                    service_name=service,
                    region_name=region if region else self.aws_default_region,
                    aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                    aws_session_token=sts_response['Credentials']['SessionToken'],
                    verify=self.verify_certificate,
                    config=self.config
                )
        elif self.aws_access_key_id and self.aws_role_arn:  # login with Access Key ID and Role ARN
            sts_client = boto3.client(
                service_name='sts',
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                verify=self.verify_certificate,
                config=self.config
            )
            kwargs.update({
                'RoleArn': self.aws_role_arn,
                'RoleSessionName': self.aws_role_session_name,
            })
            sts_response = sts_client.assume_role(**kwargs)
            client = boto3.client(
                service_name=service,
                region_name=self.aws_default_region,
                aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                aws_session_token=sts_response['Credentials']['SessionToken'],
                verify=self.verify_certificate,
                config=self.config
            )
        elif self.aws_access_key_id and not self.aws_role_arn:  # login with access key id
            client = boto3.client(
                service_name=service,
                region_name=region if region else self.aws_default_region,
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                verify=self.verify_certificate,
                config=self.config
            )
        else:  # login with default permissions, permissions pulled from the ec2 metadata
            client = boto3.client(service_name=service,
                                  region_name=region if region else self.aws_default_region)

        return client

    @staticmethod
    def get_timeout(timeout):
        if not timeout:
            timeout = "60,10"  # default values
        try:
            timeout_vals = timeout.split(',')
            read_timeout = int(timeout_vals[0])
        except ValueError:
            raise DemistoException("You can specify just the read timeout (for example 60) or also the connect "
                                   "timeout followed after a comma (for example 60,10). If a connect timeout is not "
                                   "specified, a default of 10 second will be used.")
        connect_timeout = 10 if len(timeout_vals) == 1 else int(timeout_vals[1])
        return read_timeout, connect_timeout


# python2 uses __builtin__ python3 uses builtins
if __name__ in ("__builtin__", "builtins"):
    main()
