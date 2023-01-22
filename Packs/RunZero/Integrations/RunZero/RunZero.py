import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
# from typing import Dict, Any

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

    def comment_add(self, asset_id, comment):
        url_suffix = f'/org/assets/{asset_id}/comments'
        body = {}
        body['comments'] = comment
        return self._http_request(method='PATCH',
                                  url_suffix=url_suffix,
                                  json_data=body,
                                  headers=self._headers)

    def tags_add(self, asset_id, tags):
        url_suffix = f'/org/assets/{asset_id}/tags'
        body = {}
        body['tags'] = tags
        return self._http_request(method='PATCH',
                                  url_suffix=url_suffix,
                                  json_data=body,
                                  headers=self._headers)

    def service_search(self, service_str: str = None):
        url_suffix = f'/org/services{service_str}' if service_str else '/org/services'
        return self._http_request(method='GET',
                                  url_suffix=url_suffix,
                                  headers=self._headers)


''' HELPER FUNCTIONS '''


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


''' COMMAND FUNCTIONS '''


def asset_search(client: Client, args: dict) -> CommandResults:
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
    remove_attr = not args.get('display_attributes')
    remove_svc = not args.get('display_services')
    message = []
    if type(raw) is list:
        for item_raw in raw:
            if remove_attr:
                del item_raw['attributes']
            if remove_svc:
                del item_raw['services']
            message.extend(parse_raw_response(item_raw))
    if type(raw) is dict:
        if remove_attr:
            del raw['attributes']
        if remove_svc:
            del raw['services']
        message.extend(parse_raw_response(raw))
    human_readable = tableToMarkdown('Asset',
                                     message,
                                     removeNull=True)
    return CommandResults(
        outputs_prefix='RunZero',
        outputs_key_field='Asset',
        outputs=raw,
        raw_response=raw,
        readable_output=human_readable
    )


def comment_add(client: Client, args: dict) -> CommandResults:
    asset_id = args['asset_id']
    comment = args['comment']
    raw = client.comment_add(asset_id, comment)
    message = f'Comment added to {asset_id} successfully.'
    return CommandResults(
        outputs_prefix=None,
        outputs_key_field=None,
        outputs=None,
        raw_response=raw,
        readable_output=message
    )


def tags_add(client: Client, args: dict) -> CommandResults:
    asset_id = args['asset_id']
    tags = args['tags']
    raw = client.tags_add(asset_id, tags)
    message = f'Tags added to {asset_id} successfully.'
    return CommandResults(
        outputs_prefix=None,
        outputs_key_field=None,
        outputs=None,
        raw_response=raw,
        readable_output=message
    )


def service_search(client: Client, args: dict) -> CommandResults:
    service_string = ''
    if args.get('service_id'):
        service_string = f'/{args["service_id"]}'
    elif args.get('search'):
        service_string = f'?search={args["search"]}'
    elif args.get('service_addresses'):
        service_string = ' OR service_address:'.join(argToList(args.get('service_addresses')))
        service_string = f'?search=service_addresses:{service_string}'
    raw = client.service_search(service_string)
    remove_attr = not args.get('display_attributes')
    message = []
    if type(raw) is list:
        for item_raw in raw:
            if remove_attr:
                del item_raw['attributes']
            message.extend(parse_raw_response(item_raw))
    if type(raw) is dict:
        if remove_attr:
            del raw['attributes']
        message.extend(parse_raw_response(raw))
    human_readable = tableToMarkdown('Service',
                                     message,
                                     removeNull=True)
    return CommandResults(
        outputs_prefix='RunZero',
        outputs_key_field='Service',
        outputs=raw,
        raw_response=raw,
        readable_output=human_readable
    )


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

        args = demisto.args()
        if demisto.command() == 'test-module':
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'runzero-asset-search':
            commandResult = asset_search(client, args)
            return_results(commandResult)

        elif demisto.command() == 'runzero-comment-add':
            commandResult = comment_add(client, args)
            return_results(commandResult)

        elif demisto.command() == 'runzero-tag-add':
            commandResult = tags_add(client, args)
            return_results(commandResult)

        elif demisto.command() == 'runzero-service-search':
            commandResult = service_search(client, args)
            return_results(commandResult)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
