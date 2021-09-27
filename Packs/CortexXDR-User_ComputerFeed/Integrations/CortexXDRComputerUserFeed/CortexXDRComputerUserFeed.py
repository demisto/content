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
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): The XDR Client.
        args (dict): The arguments to pass to the API call.

    Returns:
        str: 'ok' if test passed, anything else will fail the test.
    """

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
    value_field = params.get('value_field', 'user')
    create_relationships = params.get('create_relationships', False)
    query = '''dataset = endpoints | filter endpoint_status = CONNECTED|
    arrayexpand network_interface | alter
    network_interface = split(network_interface, \"-\")|
    arrayexpand network_interface |
    filter network_interface not contains \":\"| sort desc last_seen | dedup user'''
    args = {
        "query": query,
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
        execution_status['results'] = json.loads(decompress(file_data).decode())

    if execution_status:

        if "results" in execution_status:
            results = execution_status.get('results')

            # If this is the fetch-indicators command
            if command == 'fetch-indicators':
                indicators = []

                # Populate all Host, IP and Account indicators separately
                for item in results:
                    user_item = item
                    host_item = item.copy()
                    ip_item = host_item.copy()
                    user_item['indicator_source_type'] = 'user'
                    host_item['indicator_source_type'] = 'host'
                    ip_item['indicator_source_type'] = 'ip'

                    # Prepend the domain name to the user
                    domain_name = item.get('domain') or "."
                    user_name = f"{domain_name}\\{item.get('user')}"

                    ######################
                    # Append the host item
                    ######################

                    if create_relationships:

                        # Create relationship between the host and the IP
                        for ip in ip_item.get('ip_address', []):

                            relationship_list = []

                            # Create relationship between the user and the IP
                            relationship_list.append(EntityRelationship(
                                name="hosted-on",
                                relationship_type='IndicatorToIndicator',
                                entity_a=ip,
                                entity_a_family='Indicator',
                                entity_a_type='IP',
                                entity_b=host_item.get('endpoint_name'),
                                entity_b_family='Indicator',
                                entity_b_type='Host',
                                reverse_name='hosts'
                            ).to_indicator())
                    else:
                        relationship_list = []

                    # Feed Related Indicators = [{"Value", "Type", "Description"}]
                    host_feed_related_indicators = []

                    # Add IP related information to the feed related indicators
                    for ip in ip_item.get('ip_address', []):
                        host_feed_related_indicators.append({
                            "value": ip,
                            "type": "IP",
                            "description": f"{ip} hosted on a network interface"
                        })

                    # Add Account related information to the feed related indicators
                    host_feed_related_indicators.append({
                        "value": user_name,
                        "type": "Account",
                        "description": "{user_name} activity see on host"
                    })

                    indicators.append(
                        {
                            "value": host_item.get('endpoint_name'),
                            "rawJSON": host_item,
                            "relationships": relationship_list,
                            "fields": {
                                "feedrelatedindicators": host_feed_related_indicators
                            }
                        })

                    #########################
                    # Append the Account item
                    #########################

                    # Create the relationship between the host and the Account
                    if create_relationships:
                        relationship_list = []
                        relationship_list.append(EntityRelationship(
                            name="used-on",
                            relationship_type='IndicatorToIndicator',
                            entity_a=user_name,
                            entity_a_family='Indicator',
                            entity_a_type='Account',
                            entity_b=user_item.get('endpoint_name'),
                            entity_b_family='Indicator',
                            entity_b_type='Host',
                            reverse_name='used-by'
                        ).to_indicator())
                    else:
                        relationship_list = []

                    # Feed Related Indicators = [{"Value", "Type", "Description"}]
                    account_feed_related_indicators = []

                    # Add IP related information to the feed related indicators
                    for ip in ip_item.get('ip_address', []):
                        account_feed_related_indicators.append({
                            "value": ip,
                            "type": "IP",
                            "description": f"{ip} traffic associated with {user_name}"
                        })

                    # Add host related information to the feed related indicators
                    account_feed_related_indicators.append({
                        "value": user_item.get('endpoint_name'),
                        "type": "Host",
                        "description": f"Account activity from {user_name} seen on {user_item.get('endpoint_name')}"
                    })

                    indicators.append(
                        {
                            "value": user_name,
                            "rawJSON": user_item,
                            "relationships": relationship_list,
                            "fields": {
                                "feedrelatedindicators": account_feed_related_indicators
                            }
                        })

                    #####################
                    # Append the IP item
                    #####################

                    for ip in ip_item.get('ip_address', []):
                        ip_index = ip_item.get('ip_address').index(ip)
                        mac_address = ip_item.get('mac_address', [])[ip_index] or None
                        ip_indicator = {k: v for k, v in ip_item.items()}
                        ip_indicator['mac_address'] = mac_address

                        # If create relationships
                        if create_relationships:
                            relationship_list = []

                            # Create relationship between the Account and the IP
                            relationship_list.append(EntityRelationship(
                                name="used-by",
                                relationship_type='IndicatorToIndicator',
                                entity_a=ip,
                                entity_a_family='Indicator',
                                entity_a_type='IP',
                                entity_b=user_name,
                                entity_b_family='Indicator',
                                entity_b_type='Account',
                                reverse_name='used-on'
                            ).to_indicator())

                        else:
                            relationship_list = []

                        # Feed Related Indicators = [{"Value", "Type", "Description"}]
                        ip_feed_related_indicators = []

                        # Add host related information to the feed related indicators
                        ip_feed_related_indicators.append({
                            "value": ip_item.get('endpoint_name'),
                            "type": "Host",
                            "description": f"{ip_item.get('endpoint_name')} hosted {ip} on a network interface"
                        })

                        # Add Account related information to the feed related indicators
                        ip_feed_related_indicators.append({
                            "value": user_name,
                            "type": "Account",
                            "description": f"{user_name} activity seen on {ip_item.get('endpoint_name')}"
                        })

                        indicators.append(
                            {
                                "value": ip,
                                "rawJSON": ip_indicator,
                                "relationships": relationship_list,
                                "fields": {
                                    "feedrelatedindicators": ip_feed_related_indicators
                                }
                            })

                # Create the indicators in a batch, 2000 at a time
                for b in batch(indicators, batch_size=2000):
                    demisto.createIndicators(b)

            # If this is a manual commandline command
            else:
                command_results = CommandResults(
                    outputs_prefix='XDR.UserMap',
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
    verify_cert = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
# try:
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
# except Exception as e:
    # demisto.error(traceback.format_exc())  # print the traceback
    #return_error(f'Failed to execute {command} command.\nError: {str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
