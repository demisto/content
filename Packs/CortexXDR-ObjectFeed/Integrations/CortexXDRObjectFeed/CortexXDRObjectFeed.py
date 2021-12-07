import copy
import hashlib
import secrets
import string
import traceback
from gzip import decompress
from time import sleep
from typing import Any, Dict, Tuple

import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
DEFAULT_LIMIT = 100


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
        res = self._http_request(method='POST', url_suffix='/xql/start_xql_query', json_data=data)
        execution_id = res.get('reply', "")
        return execution_id

    def get_xql_query_results(self, data: dict) -> dict:
        res = self._http_request(method='POST', url_suffix='/xql/get_query_results', json_data=data)
        query_results = res.get('reply', "")
        return query_results

    def get_query_result_stream(self, data: dict) -> bytes:
        res = self._http_request(method='POST', url_suffix='/xql/get_query_results_stream', json_data=data,
                                 resp_type='response')
        return res.content

    def get_xql_quota(self, data: dict) -> dict:
        res = self._http_request(method='POST', url_suffix='/xql/get_quota', json_data=data)
        return res


# =========================================== Helper Functions ===========================================#


def start_xql_query(client: Client, args: Dict[str, Any]) -> str:
    """Execute an XQL query.

    Args:
        client (Client): The XDR Client.
        args (dict): The arguments to pass to the API call.

    Returns:
        str: The query execution ID.
    """
    query = args.get('query', '')
    if not query:
        raise ValueError('query is not specified')
    if '//' in query:
        raise DemistoException('Please remove notes (//) from query')

    if 'limit' not in query:  # if user did not provide a limit in the query, we will use the default one.
        query = f'{query} | limit {str(DEFAULT_LIMIT)}'
    data: Dict[str, Any] = {
        'request_data': {
            'query': query,
        }
    }
    tenant_ids = argToList(args.get('tenant_ids'))
    if tenant_ids:
        data['request_data']['tenants'] = tenant_ids
    # call the client function and get the raw response
    execution_id = client.start_xql_query(data)
    return execution_id


def get_xql_query_results(client: Client, args: dict) -> Tuple[dict, Optional[bytes]]:
    """Retrieve results of an executed XQL query API. returns the general response and
    a file data if the query has more than 1000 results.

    Args:
        client (Client): The XDR Client.
        args (dict): The arguments to pass to the API call.

    Returns:
        dict: The query results.
    """

    query_id = args.get('query_id')
    if not query_id:
        raise ValueError('query ID is not specified')
    data = {
        'request_data': {
            'query_id': query_id,
            'pending_flag': True,
            'format': 'json',
        }
    }

    # Call the Client function and get the raw response
    response = client.get_xql_query_results(data)
    response['execution_id'] = query_id
    results = response.get('results', {})
    stream_id = results.get('stream_id')
    if stream_id:
        file_data = get_query_result_stream(client, stream_id)
        return response, file_data
    response['results'] = results.get('data')
    return response, None


def get_query_result_stream(client: Client, stream_id: str) -> bytes:
    """Retrieve XQL query results with more than 1000 results.

    Args:
        client (Client): The XDR Client.
        stream_id (str): The stream ID of the query.

    Returns:
        bytes: The query results.
    """

    if not stream_id:
        raise ValueError('stream_id is not specified')
    data = {
        'request_data': {
            'stream_id': stream_id,
            'is_gzip_compressed': True,
        }
    }
    # Call the Client function and get the raw response
    return client.get_query_result_stream(data)


def get_nonce() -> str:
    """
    Generate a 64 bytes random string.

    Returns:
        str: The 64 bytes random string.
    """
    return "".join([secrets.choice(string.ascii_letters + string.digits) for _ in range(64)])


# ========================================== Generic Query ===============================================#


def test_module(client: Client, params: Dict[str, Any]) -> str:

    try:
        client.get_xql_quota({'request_data': {}})
        return_results('ok')
    except Exception as err:
        if any(error in str(err) for error in ['Forbidden', 'Authorization', 'Unauthorized']):
            raise DemistoException('Authorization failed, make sure API Key is correctly set')
        elif 'Not Found' in str(err):
            raise DemistoException('Authorization failed, make sure the URL is correct')
        else:
            raise err


def fetch_indicators_command(client, params):
    command = demisto.command()
    indicators = []
    object_type = params.get('object_type')
    xql_query = params.get('xql_query')
    field_value = params.get('field_value')

    args = {
        "query": xql_query,
        "query_name": "xdr-fetch-indicators"
    }

    execution_id = start_xql_query(client, args)

    execution_status, file_data = get_xql_query_results(client, args={"query_id": execution_id})
    counter = 0
    if not file_data:
        while execution_status.get('status') == 'PENDING' and counter < 100:
            sleep(10)
            execution_status, file_data = get_xql_query_results(client, args={"query_id": execution_id})
            counter += 1

    # We have more than 1000 results
    if file_data:
        execution_status['results'] = [json.loads(line) for line in decompress(file_data).decode().split("\n") if len(line) > 0]

    if execution_status:

        if "results" in execution_status:
            results = execution_status.get('results')

            # If this is the fetch-indicators command
            if command == 'fetch-indicators':
                indicators = []

                # Insert the new indicator and inject the object type
                for item in results:

                    item['object_type'] = object_type

                    indicators.append(
                        {
                            "value": item.get(field_value),
                            "rawJSON": item
                        })

                # Create the indicators in a batch, 2000 at a time
                for b in batch(indicators, batch_size=2000):
                    demisto.createIndicators(b)

            # If this is a manual commandline command
            else:

                # Inject the object type
                for item in results:
                    item['object_type'] = object_type

                command_results = CommandResults(
                    outputs_prefix=f'XDR.{object_type}',
                    outputs=results,
                    readable_output=tableToMarkdown("Indicators:", results)
                )
                return_results(command_results)


# =========================================== Built-In Queries ===========================================#

''' MAIN FUNCTION '''

# COMMAND CONSTANTS

GENERIC_QUERY_COMMANDS = {
    'test-module': test_module,
    'fetch-indicators': fetch_indicators_command,
    'xdr-get-indicators': fetch_indicators_command
}


def main() -> None:
    """main function, parses params and runs command functions
    """
    args = demisto.args()
    params = demisto.params()
    # using two different credentials object as they both fields need to be encrypted
    apikey = params.get('apikey', None)
    apikey_id = params.get('apikey_id', None)
    if not apikey:
        raise DemistoException('Missing API Key. Fill in a valid key in the integration configuration.')
    if not apikey_id:
        raise DemistoException('Missing API Key ID. Fill in a valid key ID in the integration configuration.')
    base_url = urljoin(params['url'], '/public_api/v1')
    tenant_ids = params.get('tenant_ids', [])
    object_type = params.get('object_type')
    verify_cert = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        # generate a 64 bytes random string
        nonce = get_nonce()
        # get the current timestamp as milliseconds.
        timestamp = str(int(datetime.now(timezone.utc).timestamp()) * 1000)
        # generate the auth key:
        auth_key = f'{apikey}{nonce}{timestamp}'.encode("utf-8")
        # convert to bytes object and calculate sha256
        api_key_hash = hashlib.sha256(auth_key).hexdigest()  # lgtm [py/weak-sensitive-data-hashing]

        # generate HTTP call headers
        headers = {
            "x-xdr-timestamp": timestamp,
            "x-xdr-nonce": nonce,
            "x-xdr-auth-id": apikey_id,
            "Authorization": api_key_hash,
        }

        client = Client(
            base_url=base_url,
            verify=verify_cert,
            headers=headers,
            proxy=proxy,
        )
        if command in GENERIC_QUERY_COMMANDS:
            GENERIC_QUERY_COMMANDS[command](client, params)
        else:
            raise NotImplementedError(f'Command {command} does not exist.')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError: {str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
