import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
from datetime import datetime, date

AWS_SERVICE_NAME = 'athena'


class DatetimeEncoder(json.JSONEncoder):
    # pylint: disable=method-hidden
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


def parse_rows_response(rows_data: list[dict]):
    keys: list[str] = [item['VarCharValue'] for item in rows_data[0]['Data']]
    raw_results = [item['Data'] for item in rows_data[1:]]
    result_data = []

    for raw_result in raw_results:
        current_item_data = {}

        for idx, value in enumerate(raw_result):
            if 'VarCharValue' in value:
                current_item_data[keys[idx]] = value['VarCharValue']

        result_data.append(current_item_data)

    return result_data


def start_query_execution_command(args: dict, aws_client):
    client = aws_client.aws_session(
        service=AWS_SERVICE_NAME,
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    data = []
    query_string: str = args['QueryString']
    kwargs: dict[str, Any] = {'QueryString': query_string}

    if args.get('ClientRequestToken'):
        kwargs.update({'ClientRequestToken': args['ClientRequestToken']})
    if args.get('Database'):
        kwargs.update({'QueryExecutionContext': {'Database': args['Database']}})
    if args.get('OutputLocation'):
        kwargs.update({'ResultConfiguration': {'OutputLocation': args['OutputLocation']}})
    if args.get('EncryptionOption'):
        kwargs.update({'ResultConfiguration': {'EncryptionConfiguration': {'EncryptionOption': args['EncryptionOption']}}})
    if args.get('KmsKey'):
        kwargs.update({'ResultConfiguration': {'EncryptionConfiguration': {'KmsKey': args['KmsKey']}}})
    if args.get('WorkGroup'):
        kwargs.update({'WorkGroup': args['WorkGroup']})

    response = client.start_query_execution(**kwargs)

    data.append({
        'QueryString': query_string,
        'QueryExecutionId': response['QueryExecutionId']
    })

    return_results(CommandResults(
        outputs_prefix='AWS.Athena.Query',
        outputs_key_field='QueryExecutionId',
        outputs=data,
        raw_response=response,
        readable_output=tableToMarkdown('AWS Athena Query', data),
    ))


def stop_query_command(args: dict, aws_client):
    client = aws_client.aws_session(
        service=AWS_SERVICE_NAME,
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    query_execution_id = args['QueryExecutionId']
    response = client.stop_query_execution(QueryExecutionId=query_execution_id)

    if response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
        demisto.results(f"The query {query_execution_id} was Deleted.")

    else:
        demisto.results(f"Failed to Delete the query {query_execution_id}.")
        demisto.debug("Response:\n" + str(response))


def get_query_execution_command(args: dict, aws_client):
    client = aws_client.aws_session(
        service=AWS_SERVICE_NAME,
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    kwargs = {'QueryExecutionId': args['QueryExecutionId']}
    response = client.get_query_execution(**kwargs)

    try:
        data = json.loads(json.dumps(response, cls=DatetimeEncoder))

    except ValueError as e:
        return_error('Could not parse the received response.')
        demisto.debug(f'Error:\n{e}\n'
                      f'Response:\n{response}')
        return

    return_results(CommandResults(
        outputs_prefix='AWS.Athena.Query',
        outputs_key_field='QueryExecutionId',
        outputs=data,
        raw_response=response,
        readable_output=tableToMarkdown('AWS Athena Query', data),
    ))


def get_query_results_command(args: dict, aws_client):
    client = aws_client.aws_session(
        service=AWS_SERVICE_NAME,
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    kwargs = {'QueryExecutionId': args['QueryExecutionId']}
    raw_response = client.get_query_results(**kwargs)

    parsed_response = parse_rows_response(rows_data=raw_response['ResultSet']['Rows'])

    return_results(CommandResults(
        outputs_prefix='AWS.Athena.Query',
        outputs=parsed_response,
        raw_response=raw_response,
        readable_output=tableToMarkdown('AWS Athena Query Results', parsed_response),
    ))


def main():
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    aws_role_arn = params.get('roleArn')
    aws_role_session_name = params.get('roleSessionName')
    aws_default_region = params.get('defaultRegion')
    aws_role_session_duration = params.get('sessionDuration')
    aws_access_key_id = demisto.get(params, 'credentials.identifier')
    aws_secret_access_key = demisto.get(params, 'credentials.password')
    verify_certificate = not params.get('insecure', True)
    timeout = params.get('timeout')
    retries = params.get('retries', 5)

    aws_client = AWSClient(aws_default_region=aws_default_region, aws_role_arn=aws_role_arn,
                           aws_role_session_name=aws_role_session_name, aws_role_session_duration=aws_role_session_duration,
                           aws_role_policy=None, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,
                           verify_certificate=verify_certificate, timeout=timeout, retries=retries)

    try:
        demisto.debug(f'Command being called is {command}')
        if demisto.command() == 'test-module':
            response = aws_client.aws_session(service=AWS_SERVICE_NAME).list_named_queries()
            if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                demisto.results('ok')

        elif demisto.command() == 'aws-athena-start-query':
            start_query_execution_command(args=args, aws_client=aws_client)

        elif demisto.command() == 'aws-athena-stop-query':
            stop_query_command(args=args, aws_client=aws_client)

        elif demisto.command() == 'aws-athena-get-query-execution':
            get_query_execution_command(args=args, aws_client=aws_client)

        elif demisto.command() == 'aws-athena-get-query-results':
            get_query_results_command(args=args, aws_client=aws_client)

    except Exception as e:
        return_error(f'Error: {e}')
        demisto.error(str(e))


from AWSApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
