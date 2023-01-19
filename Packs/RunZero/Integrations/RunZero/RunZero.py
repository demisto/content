"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()


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

    def asset_search(self, search_str: str = None):
        url_suffix = f'/org/assets{search_str}' if search_str else '/org/assets'
        return self._http_request(method='GET',
                                  url_suffix=url_suffix,
                                  headers=self._headers)


''' HELPER FUNCTIONS '''


def asset_search(client: Client, args: dict):
    search_string = ''
    if args.get('ips'):
        search_string = ','.join(argToList(args.get('ips')))
        search_string = f'?search=address:{search_string}'
    elif args.get('hostnames'):
        search_string = ','.join(argToList(args.get('hostnames')))
        search_string = f'?search=name:{search_string}'
    elif args.get('asset_id'):
        search_string = ','.join(argToList(args.get('asset_id')))
        search_string = f'/{search_string}'
    elif args.get('search'):
        search_string = f'?search={args.get("search")}'
    raw = client.asset_search(search_string)
    message = []
    if type(raw) is list:
        for item_raw in raw:
            message.extend(parse_raw_response(item_raw))        
    if type(raw) is dict:
        message.extend(parse_raw_response(raw))
    human_readable = tableToMarkdown('runzero-asset-search',
                                     message,
                                     removeNull=True)
    return CommandResults(
        outputs_prefix='RunZero',
        outputs_key_field='Asset',
        outputs=message,
        raw_response=raw,
        readable_output=human_readable
    )


def parse_raw_response(raw: dict) -> list:
    message = {}
    message['Addresses'] = raw.get('addresses', [])
    message['Asset Status'] = raw.get('alive', '')
    message['Hostname'] = raw.get('names', [])
    message['OS'] = f'{raw.get("os", "")} {raw.get("os_version","")}'
    message['Type'] = raw.get('type', '')
    message['Hardware'] = raw.get('hw', '')
    message['Outlier'] = raw.get('outlier_score', '')
    message['MAC vendor'] = raw.get('mac_vendors', [])
    message['MAC age'] = raw.get('mag_age', '')
    message['MAC'] = raw.get('macs', [])
    message['OS EOL'] = raw.get('eol_os', '')
    message['Sources'] = raw.get('sources', [])
    message['Comments'] = raw.get('comments', '')
    message['Tags'] = raw.get('tags', {})
    message['Svcs'] = raw.get('service_count', '')
    message['TCP'] = raw.get('service_count_tcp', '')
    message['UDP'] = raw.get('service_count_udp', '')
    message['ICMP'] = raw.get('service_count_icmp', '')    
    return [message]


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
        client.asset_search()
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    api_key = params.get('api_key', {}).get('password')
    base_url = urljoin(params.get('url'), '/api/v1.0')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers = {'Authorization': f'Bearer {api_key}'}
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'runzero-asset-search':
            args = demisto.args()
            commandResult = asset_search(client, args)
            return_results(commandResult)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
