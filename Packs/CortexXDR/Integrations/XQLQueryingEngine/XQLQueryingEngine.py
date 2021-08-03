import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any

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

    def get_xql_query_results(self, data: dict) -> str:
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

    def get_query_result_stream(self, data: dict) -> str:
        """Returns a simple python dict with the information provided
        in the input (dummy).

        :type data: ``dict``
        :param data: string to add in the dummy dict that is returned

        :return: dict as {"dummy": dummy}
        :rtype: ``str``
        """

        res = self._http_request(method='POST', url_suffix='/xql/get_query_results_stream', json_data=data)
        return res


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

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
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
        client._http_request(
            method='POST',
            url_suffix='/xql/get_quota',
            json_data={'request_data': {}}
        ),
        client.get_xql_quota({'request_data': {}})
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def start_xql_query_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    query = args.get('query')
    if not query:
        raise ValueError('query is not specified')
    time_frame = args.get('time_frame', '')
    tenant_ids = args.get('time_frame', [])
    converted_time = arg_to_datetime(time_frame)
    data = {
        'request_data': {
            'query': query,
            'tenants': tenant_ids
            'timeframe': converted_time
        }
    }
    # Call the Client function and get the raw response
    result = client.start_xql_query(data)

    return CommandResults(
        outputs_prefix='result',
        outputs_key_field='',
        outputs=result,
    )

def get_xql_query_results_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    query_id = args.get('query_id')
    if not query_id:
        raise ValueError('query is not specified')
    results_limit = args.get('Limit', 100)
    pending_flag = args.get('pending_flag', True)
    format_method = args.get('format', 'json')
    data = {
        'request_data': {
            'query_id': query_id,
            'pending_flag': pending_flag,
            'Limit': results_limit,
            'format': format_method
        }
    }
    # Call the Client function and get the raw response
    result = client.get_xql_query_results(data)

    return CommandResults(
        outputs_prefix='BaseIntegration',
        outputs_key_field='',
        outputs=result,
    )

def xdr_get_query_result_stream_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    stream_id = args.get('stream_id')
    if not stream_id:
        raise ValueError('query is not specified')
    is_gzip_compressed = args.get('gzip_compressed', False)
    data = {
        'request_data': {
            'stream_id': stream_id,
            'is_gzip_compressed': is_gzip_compressed,
        }
    }
    # Call the Client function and get the raw response
    result = client.get_get_query_result_stream(data)

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

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif command == 'xdr-start-xql-query':
            return_results(start_xql_query_command(client, demisto.args()))
        elif command == 'xdr-get-xql-query-results ':
            return_results(get-xql-query_command(client, demisto.args()))
        elif command == 'xdr-get-query-result-stream':
            return_results(get-query-result-stream_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
