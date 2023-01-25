import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
# from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
MAX_RTT = 1_000_000
DEFAULT_LIMIT = 50

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

    def asset_delete(self, asset_ids: list):
        url_suffix = f'/org/assets/bulk/delete?asset_ids={asset_ids}'
        return self._http_request(method='DELETE',
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

    def service_delete(self, service_id: str):
        url_suffix = f'/org/services/{service_id}'
        return self._http_request(method='DELETE',
                                  url_suffix=url_suffix,
                                  headers=self._headers)

    def quota_get(self):
        url_suffix = '/org/key'
        return self._http_request(method='GET',
                                  url_suffix=url_suffix,
                                  headers=self._headers)

    def bulk_clear_tags(self, search_string: str):
        url_suffix = '/org/assets/bulk/clearTags'
        body = {'search': f'{search_string}'}
        return self._http_request(method='POST',
                                  url_suffix=url_suffix,
                                  headers=self._headers,
                                  json_data=body)

    def wireless_search(self, wireless_search_string: str):
        url_suffix = f'/org/wireless/{wireless_search_string}' if wireless_search_string else '/org/wireless'
        return self._http_request(method='GET',
                                  url_suffix=url_suffix,
                                  headers=self._headers)

    def wireless_delete(self, wireless_id: str):
        url_suffix = f'/org/wireless/{wireless_id}'
        return self._http_request(method='DELETE',
                                  url_suffix=url_suffix,
                                  headers=self._headers)


''' HELPER FUNCTIONS '''


def normalize_rtt(raw_rtt: float) -> float:
    # normalizing a number:
    # normalized = (x-min(x))/(max(x)-min(x))
    # min RTT = 0, MAX_RTT = 1_000_000
    if raw_rtt is None:
        return 0
    normalized_rtt = raw_rtt / MAX_RTT
    return round(normalized_rtt, 2)


def parse_raw_asset(raw: dict) -> list:
    message = {}
    message['ID'] = raw.get('id', '')
    message['Addresses'] = raw.get('addresses', [])
    message['Asset_Status'] = raw.get('alive', '')
    message['Hostname'] = raw.get('names', [])
    message['OS'] = f'{raw.get("os", "")} {raw.get("os_version","")}'
    message['Type'] = raw.get('type', '')
    message['Hardware'] = raw.get('hw', '')
    message['Outlier'] = raw.get('outlier_score', 0)
    message['MAC_Vendor'] = raw.get('mac_vendors', [])
    message['MAC_Age'] = raw.get('mag_age', '')
    message['MAC'] = raw.get('macs', [])
    message['OS_EOL'] = raw.get('eol_os', '')
    message['Sources'] = raw.get('sources', [])
    message['Comments'] = raw.get('comments', '')
    message['Tags'] = raw.get('tags', [])
    message['Svcs'] = raw.get('service_count', 0)
    message['TCP'] = raw.get('service_count_tcp', 0)
    message['UDP'] = raw.get('service_count_udp', 0)
    message['ICMP'] = raw.get('service_count_icmp', 0)
    message['ARP'] = raw.get('service_count_arp', 0)
    message['SW'] = raw.get('software_count', 0)
    message['Vulns'] = raw.get('vulnerability_count', 0)
    message['RTT/ms'] = normalize_rtt(raw.get('lowest_rtt', 0))
    message['Hops'] = raw.get('lowest_ttl', 0)
    message['Detected'] = raw.get('detected_by', '')
    message['First_Seen'] = timestamp_to_datestring(raw.get('first_seen', '') * 1000)
    message['Last_Seen'] = timestamp_to_datestring(raw.get('last_seen', '') * 1000)
    message['Explorer'] = raw.get('agent_name', '')
    message['Hosted_Zone'] = raw.get('hosted_zone_name', '')
    message['Site'] = raw.get('site_name', '')
    return [message]


def parse_raw_service(raw: dict) -> list:
    message = {}
    message['ID'] = raw.get('service_id', '')
    message['Asset_Status'] = raw.get('alive', '')
    message['Address'] = raw.get('service_address', '')
    message['Transport'] = raw.get('service_transport', '')
    message['Port'] = raw.get('service_port', 0)
    message['Protocol'] = raw.get('service_protocol', [])
    message['VHost'] = raw.get('service_vhost', '')
    message['Summary'] = raw.get('service_summary', '')
    message['Hostname'] = raw.get('names', [])
    message['OS'] = f"{raw.get('os', '')} {raw.get('os_version', '')}"
    message['Type'] = raw.get('type', '')
    message['Hardware'] = raw.get('hw', '')
    message['Outlier'] = raw.get('outlier_score', 0)
    message['MAC_Vendor'] = raw.get('mac_vendors', [])
    message['MAC_Age'] = raw.get('newest_mac_age', '')
    message['MAC'] = raw.get('macs', [])
    message['OS_EOL'] = raw.get('eol_os', 0)
    message['Comments'] = raw.get('comments', '')
    message['Tags'] = raw.get('tags', {})
    message['Svcs'] = raw.get('service_count', 0)
    message['TCP'] = raw.get('service_count_tcp', 0)
    message['UDP'] = raw.get('service_count_udp', 0)
    message['ICMP'] = raw.get('service_count_icmp', 0)
    message['ARP'] = raw.get('service_count_arp', 0)
    message['SW'] = raw.get('software_count', 0)
    message['Vulns'] = raw.get('vulnerability_count', 0)
    message['RTT/ms'] = normalize_rtt(raw.get('lowest_rtt', 0))
    message['Hops'] = raw.get('lowest_ttl', 0)
    message['Detected'] = raw.get('detected_by', 0)
    message['First_Seen'] = timestamp_to_datestring(raw.get('first_seen', '') * 1000)
    message['Last_Seen'] = timestamp_to_datestring(raw.get('last_seen', '') * 1000)
    message['Explorer'] = raw.get('agent_name', '')
    message['Hosted_Zone'] = raw.get('hosted_zone_name', '')
    message['Site'] = raw.get('site_name', '')
    return [message]


def parse_raw_quota_get(raw: dict) -> dict:
    message = {}
    message['usage_limit'] = raw.get('created_at', '')
    message['usage_today'] = raw.get('usage_today', '')
    message['counter'] = raw.get('counter', '')
    return message


def parse_raw_wireless(raw: dict) -> list:
    message = {}
    message['ID'] = raw.get('id', '')
    message['ESSID'] = raw.get('essid', '')
    message['BSSID'] = raw.get('bssid', '')
    message['Vendor'] = raw.get('vendor', '')
    message['Family'] = raw.get('family', '')
    message['Type'] = raw.get('type', '')
    message['Auth'] = raw.get('authentication', '')
    message['Enc'] = raw.get('encryption', '')
    message['Sig'] = raw.get('signal', 0)
    message['Int'] = raw.get('interface', '')
    message['Additional'] = raw.get('data', {})
    message['First_seen'] = timestamp_to_datestring(raw.get('created_at', ''))
    message['Last_seen'] = timestamp_to_datestring(raw.get('last_seen', ''))
    message['Site'] = raw.get('site_name', '')
    return [message]


''' COMMAND FUNCTIONS '''


def asset_search(client: Client, args: dict) -> CommandResults:
    search_string = ''
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
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
    remove_attr = not argToBoolean(args.get('display_attributes', 'False'))
    remove_svc = not argToBoolean(args.get('display_services', 'False'))
    message = []
    if type(raw) is list:
        raw = raw[:limit]
        for item_raw in raw:
            if remove_attr:
                del item_raw['attributes']
            if remove_svc:
                del item_raw['services']
            message.extend(parse_raw_asset(item_raw))
    if type(raw) is dict:
        if remove_attr:
            del raw['attributes']
        if remove_svc:
            del raw['services']
        message.extend(parse_raw_asset(raw))
    human_readable = tableToMarkdown('Asset',
                                     message,
                                     removeNull=True)
    return CommandResults(
        outputs_prefix='RunZero.Asset',
        outputs_key_field='id',
        outputs=raw,
        raw_response=raw,
        readable_output=human_readable
    )


def asset_delete(client: Client, args: dict) -> CommandResults:
    asset_list = argToList(args.get('asset_ids', []))
    raw = client.asset_delete(asset_list)
    message = f'Assets {asset_list} deleted successfully.'
    return CommandResults(
        outputs_prefix=None,
        outputs_key_field=None,
        outputs=None,
        raw_response=raw,
        readable_output=message
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
    tagsList = argToList(args['tags'])
    tags = " ".join(tagsList)
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
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    if args.get('service_id'):
        service_string = f'/{args["service_id"]}'
    elif args.get('search'):
        service_string = f'?search={args["search"]}'
    elif args.get('service_addresses'):
        service_string = ' OR service_address:'.join(argToList(args.get('service_addresses')))
        service_string = f'?search=service_addresses:{service_string}'
    raw = client.service_search(service_string)
    remove_attr = not argToBoolean(args.get('display_attributes', 'False'))
    message = []
    if type(raw) is list:
        raw = raw[:limit]
        for item_raw in raw:
            if remove_attr:
                del item_raw['attributes']
            message.extend(parse_raw_service(item_raw))
    if type(raw) is dict:
        if remove_attr:
            del raw['attributes']
        message.extend(parse_raw_service(raw))
    human_readable = tableToMarkdown('Service',
                                     message,
                                     removeNull=True)
    return CommandResults(
        outputs_prefix='RunZero.Service',
        outputs_key_field='service_id',
        outputs=raw,
        raw_response=raw,
        readable_output=human_readable
    )


def service_delete(client: Client, args: dict) -> CommandResults:
    service_id = args.get('service_id', '')
    raw = client.service_delete(service_id)
    message = f'Service {service_id} deleted successfully.'
    return CommandResults(
        outputs_prefix=None,
        outputs_key_field=None,
        outputs=None,
        raw_response=raw,
        readable_output=message
    )


def quota_get(client: Client) -> CommandResults:
    raw = client.quota_get()
    message = parse_raw_quota_get(raw)
    human_readable = tableToMarkdown('Quota',
                                     message,
                                     removeNull=False)
    return CommandResults(
        outputs_prefix='RunZero.Quota',
        outputs_key_field='id',
        outputs=raw,
        raw_response=raw,
        readable_output=human_readable
    )


def bulk_clear_tags(client: Client, args: dict) -> CommandResults:
    search_string = args['search']
    raw = client.bulk_clear_tags(search_string)
    human_readable = tableToMarkdown('Bulk_Clear_Tags',
                                     raw,
                                     removeNull=False)
    return CommandResults(
        outputs_prefix=None,
        outputs_key_field=None,
        outputs=None,
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
        client.quota_get()
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def wireless_lan_search(client: Client, args: dict) -> CommandResults:
    wireless_string = ''
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    if args.get('wireless_id'):
        wireless_string = f'/{args["wireless_id"]}'
    elif args.get('search'):
        wireless_string = f'?search={args["search"]}'
    raw = client.wireless_search(wireless_string)
    raw = raw[:limit]
    message = []
    if type(raw) is list:
        raw = raw[:limit]
        for item_raw in raw:
            message.extend(parse_raw_wireless(item_raw))
    if type(raw) is dict:
        message.extend(parse_raw_wireless(raw))
    human_readable = tableToMarkdown('Wireless',
                                     message,
                                     removeNull=True)
    return CommandResults(
        outputs_prefix='RunZero.WirelessLAN',
        outputs_key_field='id',
        outputs=raw,
        raw_response=raw,
        readable_output=human_readable
    )


def wireless_lan_delete(client: Client, args: dict) -> CommandResults:
    wireless_id = args.get('wireless_id', '')
    raw = client.wireless_delete(wireless_id)
    message = f'Wireless LAN {wireless_id} deleted successfully.'
    return CommandResults(
        outputs_prefix=None,
        outputs_key_field=None,
        outputs=None,
        raw_response=raw,
        readable_output=message
    )


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

        elif demisto.command() == 'runzero-quota-get':
            result = quota_get(client)
            return_results(result)

        elif demisto.command() == 'runzero-asset-search':
            commandResult = asset_search(client, args)
            return_results(commandResult)

        elif demisto.command() == 'runzero-asset-delete':
            commandResult = asset_delete(client, args)
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

        elif demisto.command() == 'runzero-service-delete':
            commandResult = service_delete(client, args)
            return_results(commandResult)

        elif demisto.command() == 'runzero-bulk-clear-tags':
            commandResult = bulk_clear_tags(client, args)
            return_results(commandResult)
        
        elif demisto.command() == 'runzero-wireless-lan-search':
            commandResult = wireless_lan_search(client, args)
            return_results(commandResult)
        
        elif demisto.command() == 'runzero-wireless-lan-delete':
            commandResult = wireless_lan_delete(client, args)
            return_results(commandResult)
        
    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
