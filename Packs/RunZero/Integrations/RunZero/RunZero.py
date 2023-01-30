import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

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

    def asset_search(self, params: dict = None):
        url_suffix = '/org/assets'
        return self._http_request(method='GET',
                                  url_suffix=url_suffix,
                                  params=params,
                                  headers=self._headers)

    def asset_delete(self, asset_ids: list):
        url_suffix = '/org/assets/bulk/delete'
        params_value = f"[{','.join(asset_ids)}]"
        return self._http_request(method='DELETE',
                                  url_suffix=url_suffix,
                                  params={'asset_ids': params_value},
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

    def tag_delete(self, asset_id: str, tags: str):
        url_suffix = f'/org/assets/{asset_id}/tags'
        tags_body = {'tags': tags}
        return self._http_request(method='PATCH',
                                  url_suffix=url_suffix,
                                  headers=self._headers,
                                  json_data=tags_body)

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
    """ normalizing a number:
    normalized = (x-min(x))/(max(x)-min(x))
    min RTT = 0, MAX_RTT = 1_000_000 """
    if raw_rtt is None:
        return 0
    normalized_rtt = raw_rtt / MAX_RTT
    return round(normalized_rtt, 2)


def parse_raw_asset(raw: dict) -> list:
    return [{
        'ID': raw.get('id', ''),
        'Addresses': raw.get('addresses', []),
        'Asset_Status': raw.get('alive', ''),
        'Hostname': raw.get('names', []),
        'OS': f'{raw.get("os", "")} {raw.get("os_version","")}',
        'Type': raw.get('type', ''),
        'Hardware': raw.get('hw', ''),
        'Outlier': raw.get('outlier_score', 0),
        'MAC_Vendor': raw.get('mac_vendors', []),
        'MAC_Age': raw.get('mag_age', ''),
        'MAC': raw.get('macs', []),
        'OS_EOL': raw.get('eol_os', ''),
        'Sources': raw.get('sources', []),
        'Comments': raw.get('comments', ''),
        'Tags': raw.get('tags', []),
        'Svcs': raw.get('service_count', 0),
        'TCP': raw.get('service_count_tcp', 0),
        'UDP': raw.get('service_count_udp', 0),
        'ICMP': raw.get('service_count_icmp', 0),
        'ARP': raw.get('service_count_arp', 0),
        'SW': raw.get('software_count', 0),
        'Vulns': raw.get('vulnerability_count', 0),
        'RTT/ms': normalize_rtt(raw.get('lowest_rtt', 0)),
        'Hops': raw.get('lowest_ttl', 0),
        'Detected': raw.get('detected_by', ''),
        'First_Seen': timestamp_to_datestring(raw.get('first_seen', '') * 1000),
        'Last_Seen': timestamp_to_datestring(raw.get('last_seen', '') * 1000),
        'Explorer': raw.get('agent_name', ''),
        'Hosted_Zone': raw.get('hosted_zone_name', ''),
        'Site': raw.get('site_name', ''),
    }]


def parse_raw_service(raw: dict) -> list:
    return [{
        'ID': raw.get('service_id', ''),
        'Asset_Status': raw.get('alive', ''),
        'Address': raw.get('service_address', ''),
        'Transport': raw.get('service_transport', ''),
        'Port': raw.get('service_port', 0),
        'Protocol': raw.get('service_protocol', []),
        'VHost': raw.get('service_vhost', ''),
        'Summary': raw.get('service_summary', ''),
        'Hostname': raw.get('names', []),
        'OS': f"{raw.get('os', '')} {raw.get('os_version', '')}",
        'Type': raw.get('type', ''),
        'Hardware': raw.get('hw', ''),
        'Outlier': raw.get('outlier_score', 0),
        'MAC_Vendor': raw.get('mac_vendors', []),
        'MAC_Age': raw.get('newest_mac_age', ''),
        'MAC': raw.get('macs', []),
        'OS_EOL': raw.get('eol_os', 0),
        'Comments': raw.get('comments', ''),
        'Tags': raw.get('tags', {}),
        'Svcs': raw.get('service_count', 0),
        'TCP': raw.get('service_count_tcp', 0),
        'UDP': raw.get('service_count_udp', 0),
        'ICMP': raw.get('service_count_icmp', 0),
        'ARP': raw.get('service_count_arp', 0),
        'SW': raw.get('software_count', 0),
        'Vulns': raw.get('vulnerability_count', 0),
        'RTT/ms': normalize_rtt(raw.get('lowest_rtt', 0)),
        'Hops': raw.get('lowest_ttl', 0),
        'Detected': raw.get('detected_by', 0),
        'First_Seen': timestamp_to_datestring(raw.get('first_seen', '') * 1000),
        'Last_Seen': timestamp_to_datestring(raw.get('last_seen', '') * 1000),
        'Explorer': raw.get('agent_name', ''),
        'Hosted_Zone': raw.get('hosted_zone_name', ''),
        'Site': raw.get('site_name', ''),
    }]


def parse_raw_quota_get(raw: dict) -> dict:
    return {
        'usage_limit': raw.get('created_at', ''),
        'usage_today': raw.get('usage_today', ''),
        'counter': raw.get('counter', ''),
    }


def parse_raw_wireless(raw: dict) -> list:
    return [{
        'ID': raw.get('id', ''),
        'ESSID': raw.get('essid', ''),
        'BSSID': raw.get('bssid', ''),
        'Vendor': raw.get('vendor', ''),
        'Family': raw.get('family', ''),
        'Type': raw.get('type', ''),
        'Auth': raw.get('authentication', ''),
        'Enc': raw.get('encryption', ''),
        'Sig': raw.get('signal', 0),
        'Int': raw.get('interface', ''),
        'Additional': raw.get('data', {}),
        'First_seen': timestamp_to_datestring(raw.get('created_at', '')),
        'Last_seen': timestamp_to_datestring(raw.get('last_seen', '')),
        'Site': raw.get('site_name', ''),
    }]


def check_if_valid_options(args: dict, valid_options: set):
    if len(valid_options.intersection(args.keys())) > 1:
        return_error(f'Please choose one option from the following: {valid_options}')


def parse_tags_from_list(tags_list: list):
    return ' -'.join(['', *tags_list])


''' COMMAND FUNCTIONS '''


def asset_search_command(client: Client, args: dict) -> CommandResults:
    search_params = {}
    check_if_valid_options(args, {'ips', 'hostnames', 'asset_ids', 'search'})
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    if args.get('ips'):
        search_list = ' or address:'.join(argToList(args.get('ips')))
        search_params = {'search': f'address:{search_list}'}
    elif args.get('hostnames'):
        search_list = ' or name:'.join(argToList(args.get('hostnames')))
        search_params = {'search': f'name:{search_list}'}
    elif args.get('asset_ids'):
        search_list = ' or id:'.join(argToList(args.get('asset_ids')))
        search_params = {'search': f'id:{search_list}'}
    elif args.get('search'):
        search_params = {'search': str(args.get('search'))}
    raw = client.asset_search(search_params)
    outputs = raw
    remove_attr = not argToBoolean(args.get('display_attributes', 'False'))
    remove_svc = not argToBoolean(args.get('display_services', 'False'))
    message = []
    if isinstance(outputs, list):
        raw = raw[:limit]
        outputs = outputs[:limit]
        for item in outputs:
            if remove_attr:
                item.pop('attributes', None)
            if remove_svc:
                item.pop('services', None)
            message.extend(parse_raw_asset(item))
    if isinstance(outputs, dict):
        if remove_attr:
            outputs.pop('attributes')
        if remove_svc:
            outputs.pop('services')
        message.extend(parse_raw_asset(outputs))
    human_readable = tableToMarkdown('Asset',
                                     message,
                                     removeNull=True)
    return CommandResults(
        outputs_prefix='RunZero.Asset',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=raw,
        readable_output=human_readable
    )


def asset_delete_command(client: Client, args: dict) -> CommandResults:
    asset_list = argToList(args.get('asset_ids', []))
    raw = client.asset_delete(asset_list)
    message = f'Assets {asset_list} deleted successfully.'
    return CommandResults(
        outputs_prefix='RunZero.Asset',
        raw_response=raw,
        readable_output=message
    )


def comment_add_command(client: Client, args: dict) -> CommandResults:
    asset_id = args.get('asset_id', '')
    comment = args.get('comment', '')
    raw = client.comment_add(asset_id, comment)
    message = f'Comment added to {asset_id} successfully.'
    return CommandResults(
        raw_response=raw,
        readable_output=message
    )


def tags_add_command(client: Client, args: dict) -> CommandResults:
    asset_id = args.get('asset_id', '')
    tags_list = argToList(args.get('tags', ''))
    tags = " ".join(tags_list)
    raw = client.tags_add(asset_id, tags)
    message = f'Tags added to {asset_id} successfully.'
    return CommandResults(
        outputs_prefix='RunZero.Tag',
        raw_response=raw,
        readable_output=message
    )


def service_search_command(client: Client, args: dict) -> CommandResults:
    check_if_valid_options(args, {'service_id', 'service_addresses', 'search'})
    service_string = ''
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    if args.get('service_id'):
        service_string = f'/{args.get("service_id", "")}'
    elif args.get('search'):
        service_string = f'?search={args.get("search", "")}'
    elif args.get('service_addresses'):
        service_string = ' or service_address:'.join(argToList(args.get('service_addresses')))
        service_string = f'?search=service_address:{service_string}'
    raw = client.service_search(service_string)
    outputs = raw
    remove_attr = not argToBoolean(args.get('display_attributes', 'False'))
    message = []
    if isinstance(outputs, list):
        raw = raw[:limit]
        outputs = outputs[:limit]
        for item in outputs:
            if remove_attr:
                item.pop('attributes', None)
            message.extend(parse_raw_service(item))
    if isinstance(outputs, dict):
        if remove_attr:
            outputs.pop('attributes', None)
        message.extend(parse_raw_service(raw))
    human_readable = tableToMarkdown('Service',
                                     message,
                                     removeNull=True)
    return CommandResults(
        outputs_prefix='RunZero.Service',
        outputs_key_field='service_id',
        outputs=outputs,
        raw_response=raw,
        readable_output=human_readable
    )


def service_delete_command(client: Client, args: dict) -> CommandResults:
    service_id = args.get('service_id', '')
    raw = client.service_delete(service_id)
    message = f'Service {service_id} deleted successfully.'
    return CommandResults(
        outputs_prefix='RunZero.Service',
        raw_response=raw,
        readable_output=message
    )


def quota_get_command(client: Client) -> CommandResults:
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


def tag_delete_command(client: Client, args: dict) -> CommandResults:
    asset_id = args.get('asset_id', '')
    tags_list = argToList(args.get('tags', []))
    tags = parse_tags_from_list(tags_list)
    raw = client.tag_delete(asset_id, tags)
    message = f'Tags {tags_list} from asset: {asset_id} deleted successfully.'
    return CommandResults(
        outputs_prefix='RunZero.Tag',
        raw_response=raw,
        readable_output=message
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
    client.quota_get()
    message = 'ok'
    return message


def wireless_lan_search_command(client: Client, args: dict) -> CommandResults:
    wireless_string = ''
    check_if_valid_options(args, {'wireless_id', 'search'})
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    if args.get('wireless_id'):
        wireless_string = f'/{args.get("wireless_id", "")}'
    elif args.get('search'):
        wireless_string = f'?search={args.get("search", "")}'
    raw = client.wireless_search(wireless_string)[:limit]
    message = []
    if isinstance(raw, list):
        raw = raw[:limit]
        for item_raw in raw:
            message.extend(parse_raw_wireless(item_raw))
    if isinstance(raw, dict):
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


def wireless_lan_delete_command(client: Client, args: dict) -> CommandResults:
    wireless_id = args.get('wireless_id', '')
    raw = client.wireless_delete(wireless_id)
    message = f'Wireless LAN {wireless_id} deleted successfully.'
    return CommandResults(
        outputs_prefix='RunZero.WirelessLAN',
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
            return_results(test_module(client))

        elif demisto.command() == 'runzero-quota-get':
            return_results(quota_get_command(client))

        elif demisto.command() == 'runzero-asset-search':
            return_results(asset_search_command(client, args))

        elif demisto.command() == 'runzero-asset-delete':
            return_results(asset_delete_command(client, args))

        elif demisto.command() == 'runzero-service-search':
            return_results(service_search_command(client, args))

        elif demisto.command() == 'runzero-service-delete':
            return_results(service_delete_command(client, args))

        elif demisto.command() == 'runzero-comment-add':
            return_results(comment_add_command(client, args))

        elif demisto.command() == 'runzero-tag-add':
            return_results(tags_add_command(client, args))

        elif demisto.command() == 'runzero-tag-delete':
            return_results(tag_delete_command(client, args))

        elif demisto.command() == 'runzero-wireless-lan-search':
            return_results(wireless_lan_search_command(client, args))

        elif demisto.command() == 'runzero-wireless-lan-delete':
            return_results(wireless_lan_delete_command(client, args))

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
