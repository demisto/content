import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any, Callable

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def start_xql_query(self, data: dict) -> str:
        """Returns a simple python dict with the information provided
        in the input (dummy).

        :type data: ``dict``
        :param data: string to add in the dummy dict that is returned

        :return: dict as {"dummy": dummy}
        :rtype: ``str``
        """

        res = self._http_request(method='POST', url_suffix='/xql/start_xql_query', json_data=data)
        execution_id = res.get('reply', "")
        return execution_id

    def get_xql_query_results(self, data: dict) -> dict:
        """Returns a simple python dict with the information provided
        in the input (dummy).

        :type data: ``dict``
        :param data: string to add in the dummy dict that is returned

        :return: dict as {"dummy": dummy}
        :rtype: ``str``
        """

        res = self._http_request(method='POST', url_suffix='/xql/get_query_results', json_data=data)
        query_results = res.get('reply', "")
        return query_results

    def get_query_result_stream(self, data: dict) -> bytes:
        """Returns a simple python dict with the information provided
        in the input (dummy).

        :type data: ``dict``
        :param data: string to add in the dummy dict that is returned

        :return: dict as {"dummy": dummy}
        :rtype: ``str``
        """

        res = self._http_request(method='POST', url_suffix='/xql/get_query_results_stream', json_data=data, resp_type='response')
        return res.content

    def get_xql_quota(self, data: dict) -> str:
        """Returns a simple python dict with the information provided
        in the input (dummy).

        :type data: ``dict``
        :param data: string to add in the dummy dict that is returned

        :return: dict as {"dummy": dummy}
        :rtype: ``str``
        """

        res = self._http_request(method='POST', url_suffix='/xql/get_quota', json_data=data)
        return res


''' HELPER FUNCTIONS '''


def init_commands() -> dict:
    return {
        'test-module': test_module,
        'xdr-start-xql-query': start_xql_query_command,
        'xdr-get-xql-query-results': get_xql_query_results_polling_command,
    }


''' COMMAND FUNCTIONS '''


def test_module(client: Client,  args: Dict[str, Any]) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        client.get_xql_quota({'request_data': {}})
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def start_xql_query_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    query = stringEscape(args.get('query', ''))
    if not query:
        raise ValueError('query is not specified')
    time_frame = args.get('time_frame', '')
    tenant_ids = args.get('tenant_ids', [])
    converted_time = arg_to_datetime(time_frame) if time_frame else None
    data = {
        'request_data': {
            'query': query,
            'tenants': tenant_ids,
            'timeframe': converted_time
        }
    }
    # Call the Client function and get the raw response
    execution_id = client.start_xql_query(data)

    return CommandResults(
        outputs_prefix='PaloAltoNetworksXDR.XQL.Query',
        outputs_key_field='ExecutionID',
        outputs={
            'ExecutionID': execution_id
        },
    )


def get_xql_query_results_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    query_id = args.get('query_id')
    if not query_id:
        raise ValueError('query is not specified')
    results_limit = int(args.get('limit', 100))
    format_method = args.get('format', 'json')
    data = {
        'request_data': {
            'query_id': query_id,
            'pending_flag': True,
            'limit': results_limit,
            'format': format_method
        }
    }

    # Call the Client function and get the raw response
    response = client.get_xql_query_results(data)
    stream_id = response.get('results', {}).get('stream_id')
    if stream_id:
        return xdr_get_query_result_stream(client, stream_id)
    outputs = camelize(response, delim='_')
    outputs['ExecutionID'] = query_id
    return CommandResults(
        outputs_prefix='PaloAltoNetworksXDR.XQL.Query',
        outputs_key_field='ExecutionID',
        outputs=outputs,
    )


def get_xql_query_results_polling_command(client: Client, args: dict):
    ScheduledCommand.raise_error_if_not_supported()
    interval_in_secs = int(args.get('interval_in_seconds', 60))
    command_results = get_xql_query_results_command(client, args)
    outputs = command_results.outputs
    return_warning('STATUS :' + outputs.get('Status'))
    if outputs.get('Status') == 'PENDING':
        polling_args = {
            'interval_in_seconds': interval_in_secs,
            'polling': True,
            **args
        }
        scheduled_command = ScheduledCommand(
            command='xdr-get-xql-query-results',
            next_run_in_seconds=interval_in_secs,
            args=polling_args,
            timeout_in_seconds=600)
        command_results.scheduled_command = scheduled_command
    return command_results


def xdr_get_query_result_stream(client: Client, stream_id: str) -> CommandResults:

    if not stream_id:
        raise ValueError('stream_id is not specified')
    data = {
        'request_data': {
            'stream_id': stream_id,
            'is_gzip_compressed': True,
        }
    }
    # Call the Client function and get the raw response
    result = client.get_query_result_stream(data)

    return CommandResults(
        outputs_prefix='BaseIntegration',
        outputs_key_field='',
        outputs=result,
    )


def xdr_get_xql_quota_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    data = {
        'request_data': {
        }
    }
    # Call the Client function and get the raw response
    result = client.get_xql_quota(data)

    return CommandResults(
        outputs_prefix='BaseIntegration',
        outputs_key_field='',
        outputs=result,
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    api_key = params.get('apikey')
    api_key_id = params.get('apikey_id')
    base_url = urljoin(params['url'], '/public_api/v1')
    verify_cert = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        headers: Dict = {
            "x-xdr-auth-id": str(api_key_id),
            "Authorization": api_key
        }

        client = Client(
            base_url=base_url,
            verify=verify_cert,
            headers=headers,
            proxy=proxy)
        commands = init_commands()
        if command not in commands:
            raise DemistoException(f'Command {command} does not exist.')
        return_results(commands[command](client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
