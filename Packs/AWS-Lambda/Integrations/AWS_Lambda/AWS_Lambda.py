import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""IMPORTS"""
from datetime import date
import urllib3.util
# Disable insecure warnings
urllib3.disable_warnings()


def config_aws_session(args: dict, aws_client):
    return aws_client.aws_session(
        service='lambda',
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )


def parse_tag_field(tags_str):
    tags = []
    regex = re.compile(r'key=([\w\d_:.-]+),value=([ /\w\d@_,.\*-]+)', flags=re.I)
    for f in tags_str.split(';'):
        match = regex.match(f)
        if match is None:
            demisto.debug('could not parse field: %s' % (f,))
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

    obj = vars(aws_client._client_config)
    kwargs = {'FunctionName': args.get('functionName')}
    if args.get('qualifier') is not None:
        kwargs.update({'Qualifier': args.get('qualifier')})

    response = aws_client.get_function(**kwargs)
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

    obj = vars(aws_client._client_config)
    data = []
    output = []

    paginator = aws_client.get_paginator('list_functions')
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

    data = []
    output = []
    kwargs = {'FunctionName': args.get('functionName')}
    if args.get('functionVersion') is not None:
        kwargs.update({'FunctionVersion': args.get('functionVersion')})

    paginator = aws_client.get_paginator('list_aliases')
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

    obj = vars(aws_client._client_config)
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
    response = aws_client.invoke(**kwargs)
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

    kwargs = {
        'FunctionName': args.get('functionName'),
        'StatementId': args.get('StatementId')
    }
    if args.get('Qualifier') is not None:
        kwargs.update({'Qualifier': args.get('Qualifier')})
    if args.get('RevisionId') is not None:
        kwargs.update({'RevisionId': args.get('RevisionId')})

    response = aws_client.remove_permission(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results('Permissions have been removed')


def get_account_settings(args, aws_client):

    obj = vars(aws_client._client_config)
    response = aws_client.get_account_settings()
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


def get_policy_command(args: dict, aws_client) -> CommandResults:
    def parse_policy(data: dict[str, Any]) -> dict[str, str | None]:

        statement: dict = policy.get('Statement', {})[0]
        return {
            "Version": policy.get('Version'),
            "Id": policy.get('Id'),
            "Sid": statement.get('Sid'),
            "Effect": statement.get('Effect'),
            "Action": statement.get('Action'),
            "Resource": statement.get('Resource'),
            "RevisionId": data.get('RevisionId')
        }

    kwargs = {'FunctionName': args['functionName']}
    if qualifier := args.get('qualifier'):
        kwargs.update({'qualifier': qualifier})

    response = aws_client.get_policy(**kwargs)
    policy = json.loads(response["Policy"])
    response["Policy"] = policy

    parsed_policy = parse_policy(response)
    table_for_markdown = tableToMarkdown(name="Policy", t=parsed_policy)

    return CommandResults(
        outputs=response,
        readable_output=table_for_markdown,
        outputs_prefix="AWS.Lambda",
        outputs_key_field='Sid'
    )


def list_versions_by_function_command(args: dict, aws_client) -> CommandResults:
    def parse_versions(data: dict[str, Any]) -> dict[str, str | None]:
        versions: dict = data.get("Versions", [])[0]
        return {
            "Function Name": versions.get('FunctionName'),
            "Run Time": versions.get('RunTime'),
            "Role": versions.get('Role'),
            "Description": versions.get('Description'),
            "Last Modified": versions.get("LastModified"),
            "State": versions.get('State'),
            "Next Marker": data.get('NextMarker'),
        }

    kwargs = {'FunctionName': args['functionName']}
    if marker := args.get('Marker'):
        kwargs.update({'Marker': marker})

    if maxItems := args.get('MaxItems'):
        kwargs.update({'MaxItems': maxItems})

    response = aws_client.list_versions_by_function(**kwargs)
    parsed_versions = parse_versions(response)
    table_for_markdown = tableToMarkdown(name='Versions', t=parsed_versions)

    return CommandResults(
        outputs=response,
        readable_output=table_for_markdown,
        outputs_prefix="AWS.Lambda.Version",
        outputs_key_field='FunctionName'
    )


def get_function_url_config_command(args: dict, aws_client) -> CommandResults:
    def parse_url_config(data: dict[str, Any]) -> dict[str, str | None]:
        return {
            "Function Url": data.get('FunctionUrl'),
            "Function Arn": data.get('FunctionArn'),
            "Auth Type": data.get('AuthType'),
            "Creation Time": data.get('CreationTime'),
            "Last Modified Time": data.get("LastModifiedTime"),
            "Invoke Mode": data.get('InvokeMode'),
        }

    kwargs = {'FunctionName': args['functionName']}
    if qualifier := args.get('qualifier'):
        kwargs.update({'qualifier': qualifier})

    response = aws_client.get_function_url_config(**kwargs)
    parsed_url_config = parse_url_config(response)
    table_for_markdown = tableToMarkdown(name='Function URL Config', t=parsed_url_config)

    return CommandResults(
        outputs=response,
        readable_output=table_for_markdown,
        outputs_prefix="AWS.Lambda.FunctionURLConfig",
        outputs_key_field='FunctionName'
    )


def get_function_configuration_command(args: dict, aws_client) -> CommandResults:
    def parse_function_configuration(data: dict[str, Any]) -> dict[str, str | None]:
        return {
            "Function Name": data.get('FunctionName'),
            "Function Arn": data.get('FunctionArn'),
            "Description": data.get('Description'),
            "State": data.get('State'),
            "Runtime": data.get("Runtime"),
            "Code Sha256": data.get('CodeSha256'),
            "Revision Id": data.get('RevisionId'),
        }

    kwargs = {'FunctionName': args['functionName']}
    if qualifier := args.get('qualifier'):
        kwargs.update({'qualifier': qualifier})

    response = aws_client.get_function_configuration(**kwargs)
    parsed_function_configuration = parse_function_configuration(response)
    table_for_markdown = tableToMarkdown(name='Function Configuration', t=parsed_function_configuration)

    return CommandResults(
        outputs=response,
        readable_output=table_for_markdown,
        outputs_prefix="AWS.Lambda.FunctionConfig",
        outputs_key_field='FunctionName'
    )


def delete_function_url_config_command(args: dict, aws_client) -> CommandResults:

    kwargs = {'FunctionName': args['functionName']}
    if qualifier := args.get('qualifier'):
        kwargs.update({'qualifier': qualifier})

    aws_client.delete_function_url_config(**kwargs)

    return CommandResults(
        readable_output="Deleted Successfully"
    )


def delete_function_command(args: dict, aws_client) -> CommandResults:

    kwargs = {'FunctionName': args['functionName']}
    if qualifier := args.get('qualifier'):
        kwargs.update({'qualifier': qualifier})

    response = aws_client.delete_function(**kwargs)
    if response["ResponseMetadata"]["HTTPStatusCode"] == 204:
        return CommandResults(
            readable_output="Deleted Successfully"
        )


"""TEST FUNCTION"""


def test_function(aws_client):
    response = aws_client.list_functions()
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results('ok')


def main():

    params = demisto.params()
    command = demisto.command()
    args = demisto.args()
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
    sts_endpoint_url = params.get('sts_endpoint_url') or None
    endpoint_url = params.get('endpoint_url') or None
    validate_params(aws_default_region, aws_role_arn, aws_role_session_name, aws_access_key_id,
                    aws_secret_access_key)
    aws_client = AWSClient(aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
                           aws_role_policy, aws_access_key_id, aws_secret_access_key, verify_certificate, timeout,
                           retries, sts_endpoint_url=sts_endpoint_url, endpoint_url=endpoint_url)
    aws_client = config_aws_session(args, aws_client)
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
        elif command == 'aws-lambda-get-policy':
            return_results(get_policy_command(args, aws_client))
        elif command == 'aws-lambda-list-versions-by-function':
            return_results(list_versions_by_function_command(args, aws_client))
        elif command == 'aws-lambda-get-function-url-config':
            return_results(get_function_url_config_command(args, aws_client))
        elif command == 'aws-lambda-get-function-configuration':
            return_results(get_function_configuration_command(args, aws_client))
        elif command == 'aws-lambda-delete-function-url-config':
            return_results(delete_function_url_config_command(args, aws_client))
        elif command == 'aws-lambda-delete-function':
            return_results(delete_function_command(args, aws_client))
    except Exception as e:
        return_error(f'Error has occurred in the AWS Lambda Integration: {type(e)}\n {str(e)}')


from AWSApiModule import *  # noqa: E402

# python2 uses __builtin__ python3 uses builtins
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
