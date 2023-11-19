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


def parse_rows_response(rows_data: list[dict]) -> list[dict]:
    """
    Parse and arrange the 'Rows' data from the response.

    Args:
        rows_data (list[dict]): The 'Rows' data from the response.

    Returns:
        list[dict]: The data in a parsed and arranged format.
    """
    if not rows_data or not rows_data[0].get('Data'):
        return []

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


def start_query_execution_command(args: dict, client):
    query_string: str = args['QueryString']
    query_limit: str | None = args.get('QueryLimit')

    if query_limit and 'LIMIT' not in query_string:
        query_string = f'{query_string} LIMIT {query_limit}'

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

    context_data = {
        'QueryString': query_string,
        'QueryExecutionId': response['QueryExecutionId']
    }

    return CommandResults(
        outputs_prefix='AWS.Athena.Query',
        outputs_key_field='QueryExecutionId',
        outputs=context_data,
        raw_response=response,
        readable_output=tableToMarkdown('AWS Athena Query Start', context_data),
    )


def stop_query_command(args: dict, client):
    query_execution_id: str = args['QueryExecutionId']
    response = client.stop_query_execution(QueryExecutionId=query_execution_id)

    if response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
        return CommandResults(readable_output=f"Query '{query_execution_id}' has been successfully stopped.")

    else:
        demisto.debug("Response:\n" + str(response))
        raise DemistoException(f"Failed to stop query '{query_execution_id}'.")


def get_query_execution_command(args: dict, client):
    query_execution_id: str = args['QueryExecutionId']
    raw_response = client.get_query_execution(QueryExecutionId=query_execution_id)

    try:
        raw_response = json.loads(json.dumps(raw_response, cls=DatetimeEncoder))

    except ValueError as e:
        return_error('Could not parse the received response.')
        demisto.debug(f'Error:\n{e}\n'
                      f'Response:\n{raw_response}')

    response = raw_response['QueryExecution']

    return CommandResults(
        outputs_prefix='AWS.Athena.Query',
        outputs_key_field='QueryExecutionId',
        outputs=response,
        raw_response=raw_response,
        readable_output=tableToMarkdown('AWS Athena Query Execution', response),
    )


@polling_function(
    name=demisto.command(),
    interval=arg_to_number(demisto.args().get('interval_in_seconds', 10)),
    timeout=arg_to_number(demisto.args().get('timeout_in_seconds', 300)),
    requires_polling_arg=True,
)
def get_query_results_command(args: dict, client):
    query_execution_id: str = args['QueryExecutionId']
    polling: bool = argToBoolean(args["polling"])

    try:
        raw_response = client.get_query_results(QueryExecutionId=query_execution_id)

    except client.exceptions.InvalidRequestException as e:
        error_message: str = e.response['Message']

        if polling and 'Query has not yet finished.' in error_message:
            return PollResult(
                response=None,
                continue_to_poll=True,
                partial_result=CommandResults(readable_output=error_message),
                args_for_next_run=args
            )

        else:
            raise

    parsed_response = parse_rows_response(rows_data=raw_response['ResultSet']['Rows'])

    for result_item in parsed_response:
        result_item['query_execution_id'] = query_execution_id

    result = CommandResults(
        outputs_prefix='AWS.Athena.QueryResults',
        outputs=parsed_response,
        raw_response=raw_response,
        readable_output=tableToMarkdown('AWS Athena Query Results', parsed_response),
    )

    return PollResult(
        response=result,
        continue_to_poll=False,
    )


def main():  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    aws_role_arn = params.get('roleArn')
    aws_role_session_name = params.get('roleSessionName')
    aws_default_region = params.get('defaultRegion')
    aws_role_session_duration = params.get('sessionDuration')
    aws_access_key_id = demisto.get(params, 'credentials.identifier') or params.get('access_key')
    aws_secret_access_key = demisto.get(params, 'credentials.password') or params.get('secret_key')
    verify_certificate = not params.get('insecure', True)
    timeout = params.get('timeout')
    retries = params.get('retries', 5)

    try:
        demisto.debug(f"Command being called is '{command}'.")

        aws_client = AWSClient(aws_default_region=aws_default_region, aws_role_arn=aws_role_arn,
                               aws_role_session_name=aws_role_session_name, aws_role_session_duration=aws_role_session_duration,
                               aws_role_policy=None, aws_access_key_id=aws_access_key_id,
                               aws_secret_access_key=aws_secret_access_key,
                               verify_certificate=verify_certificate, timeout=timeout, retries=retries)

        client = aws_client.aws_session(
            service=AWS_SERVICE_NAME,
            region=args.get('region'),
            role_arn=args.get('roleArn'),
            role_session_name=args.get('roleSessionName'),
            role_session_duration=args.get('roleSessionDuration'),
        )

        result: str | CommandResults

        if demisto.command() == 'test-module':
            response = client.list_named_queries()
            if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                result = 'ok'

            else:
                result = CommandResults(readable_output=f'Error: {response}')

        elif demisto.command() == 'aws-athena-start-query':
            result = start_query_execution_command(args=args, client=client)

        elif demisto.command() == 'aws-athena-stop-query':
            result = stop_query_command(args=args, client=client)

        elif demisto.command() == 'aws-athena-get-query-execution':
            result = get_query_execution_command(args=args, client=client)

        elif demisto.command() == 'aws-athena-get-query-results':
            result = get_query_results_command(args=args, client=client)

        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

        return_results(result)

    except Exception as e:
        return_error(f'Error: {e}')
        demisto.error(f'Error: {e}\n\nTraceback:\n{traceback.format_exc()}')


from AWSApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
