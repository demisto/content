from typing import Dict

import urllib3
from gql import Client, gql
from gql.transport.requests import RequestsHTTPTransport

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

# Disable insecure warnings
urllib3.disable_warnings()


def execute_query(client: Client, args: Dict) -> CommandResults:
    query = gql(args.get('query'))
    result = client.execute(query)
    command_results_args = {
        'outputs': result,
        'outputs_prefix': 'GraphQL'
    }
    if args.get('outputs_key_field'):
        command_results_args['outputs_key_field'] = args.get('outputs_key_field')
    return CommandResults(**command_results_args)


def main() -> None:
    command = demisto.command()
    try:
        params = demisto.params()
        request_params = {
            'url': params.get('url'),
            'verify': not params.get('insecure', False),
            'retries': 3,
        }
        if params.get('credentials'):
            request_params['auth'] = (
                params.get('credentials').get('identifier'), params.get('credentials').get('password')
            )
        if params.get('headers'):
            try:
                request_params['headers'] = json.loads(params.get('headers'))
            except json.JSONDecodeError as e:
                raise ValueError(f'Headers are not in valid JSON format: {e}')

        transport = RequestsHTTPTransport(**request_params)
        if not params.get('proxy'):
            transport.session.trust_env = False
        client = Client(transport=transport, fetch_schema_from_transport=True)

        demisto.debug(f'Command being called is {command}')
        if command == 'test-module':
            return_results('ok')
        elif command == 'graphql-query':
            return_results(execute_query(client, demisto.args()))
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {command} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
