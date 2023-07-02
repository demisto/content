import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''


import urllib3
import re

urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """
    def __init__(self, url, api_token, verify, proxy):
        super().__init__(base_url=url, proxy=proxy, verify=verify)
        self.api_token = api_token
        if self.api_token:
            self._headers = {'Authorization': f'Bearer {self.api_token}'}

    def discovery_process_status(self):
        url_suffix = '/discovery'
        return self._http_request(method='GET', url_suffix=url_suffix, resp_type='json', ok_codes=(200,))

    def discovery_scan_status_list(self, **args):
        url_suffix = '/discovery/runs'
        run_id = args.get('run_id', '')
        if run_id:
            url_suffix += '/' + run_id
        return self._http_request(method='GET', url_suffix=url_suffix, resp_type='json', ok_codes=(200,))

    def discovery_search(self, **args):
        url_suffix = '/data/search?format=object'
        method = 'POST'
        kind = args.get('kind', 'Host')
        ip = args.get('ip', '')
        hostname = args.get('hostname', '')
        if not ip and not hostname:
            raise DemistoException('Please specify ip or hostname parameter')
        elif ip and hostname:
            raise DemistoException('ip and hostname are mutually exclusive. Please specify just one parameter')
        if ip:
            ipv4_match = re.match(ipv4Regex, ip)
            ipv6_match = re.match(ipv6Regex, ip)
            if not ipv4_match and not ipv6_match:
                raise DemistoException('Specified ip address doesn\'t look valid')
        query = 'SEARCH %s WHERE %s show *, __all_ip_addrs, __all_mac_addrs, __all_dns_names, #id'
        if ip:
            where = "__all_ip_addrs LIKE '%s'" % ip
        else:
            where = "__all_dns_names LIKE '%s'" % hostname
        query = query % (kind, where)
        data = {
            'query': query
        }
        return self._http_request(method=method, url_suffix=url_suffix, resp_type='json',
                                  json_data=data, ok_codes=(200,))

    def discovery_search_custom(self, **args):
        url_suffix = '/data/search?format=object'
        method = 'POST'
        query = args.get('query', '')
        if not query:
            raise DemistoException('Please specify query parameter')
        offset = args.get('offset', '')
        limit = args.get('limit', 50)
        results_id = args.get('results_id', '')
        if offset and not results_id:
            raise DemistoException('"offset" cannot be specified without "results_id"')
        params = dict()
        if offset:
            params['offset'] = offset
            params['results_id'] = results_id
        if limit:
            params['limit'] = limit
        data = {
            'query': query
        }
        return self._http_request(method=method, url_suffix=url_suffix, resp_type='json',
                                  params=params, json_data=data, ok_codes=(200,))

    def discovery_scan_create(self, **args):
        url_suffix = '/discovery/runs'
        label = args.get('label', '')
        ranges = argToList(args.get('ranges', ''))
        settings = {
            "scan_kind": "IP",
            "scope": "",
            "ranges": ranges,  # [ "xx.xx.xx.xx/xx" , "xx.xx.xx.xx/xx" ]
            "label": label,
            "scan_level": "Full Discovery"
        }
        return self._http_request(method='POST', url_suffix=url_suffix, resp_type='json', ok_codes=(200,),
                                  json_data=settings)

    def discovery_scan_stop(self, **args):
        run_id = args.get('run_id', '')
        url_suffix = '/discovery/runs/' + run_id
        data = {"cancelled": True}
        return self._http_request(method='PATCH', url_suffix=url_suffix, resp_type='text',
                                  json_data=data, ok_codes=(200,))

    def discovery_scan_summary(self, **args):
        run_id = args.get('run_id', '')
        url_suffix = '/discovery/runs/' + run_id + '/results'
        return self._http_request(method='GET', url_suffix=url_suffix, resp_type='json', ok_codes=(200,))

    def discovery_scan_results_list(self, **args):
        run_id = args.get('run_id', '')
        if not run_id:
            raise DemistoException('Please specify run_id parameter')
        result_type = args.get('result_type', 'Success')
        limit = args.get('limit', 50)
        offset = args.get('offset', '')
        results_id = args.get('results_id', '')
        if offset and not results_id:
            raise DemistoException('"offset" cannot be specified without "results_id"')
        params = dict()
        params['format'] = 'object'
        if offset:
            params['offset'] = offset
            params['results_id'] = results_id
        if limit:
            params['limit'] = limit
        url_suffix = '/discovery/runs/' + run_id + '/results/' + result_type
        return self._http_request(method='GET', url_suffix=url_suffix, params=params, resp_type='json', ok_codes=(200,))


def test_module(client):
    try:
        response = client.discovery_process_status()
        status = demisto.get(response, 'status')
        if not status:
            return f'Unexpected result from the service: status={status}'
        return 'ok'
    except Exception as e:
        exception_text = str(e).lower()
        if 'forbidden' in exception_text or 'authorization' in exception_text:
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise


def discovery_search_custom_command(client: Client, **args) -> CommandResults:
    response = client.discovery_search_custom(**args)
    if not response:
        raise DemistoException('Search command failed')

    user_output = list()
    for kind in response:
        row = dict()
        row['count'] = kind['count']
        row['offset'] = kind['offset']
        for key in ('kind', 'next_offset', 'results_id'):
            if key in kind:
                row[key] = kind[key]
        user_output.append(row)

    search_name = args.get('name', '')

    context_output = dict()
    context_output['data'] = response
    if search_name:
        context_output['name'] = search_name

    return CommandResults(outputs_prefix='BmcDiscovery.CustomSearch',
                          outputs=context_output,
                          raw_response=response,
                          readable_output=tableToMarkdown(name='BMC Discovery Custom Search Results '
                                                               '(see context for more details)', t=user_output))


def discovery_search_command(client: Client, **args) -> CommandResults:
    response = client.discovery_search(**args)

    if not response:
        raise DemistoException('Search command failed')

    output: Dict = {}
    output['data'] = list()
    search_name = args.get('name', '')
    if search_name:
        output['name'] = search_name
    count = 0
    for item in response:
        results = item['results']
        count += item.get('count', 0)
        for result in results:
            remove_nulls_from_dictionary(result)
            output['data'].append(result)
    output['count'] = count

    user_map_dict = {
        '#OwnedItem:Ownership:ITOwner:Person.name': 'IT Owner',
        'domain': 'Domain',
        'os': 'OS',
        '__all_ip_addrs': 'IP Addresses',
        'local_fqdn': 'Local FQDN',
        'name': 'Name',
        '#id': 'id',
        '#OwnedItem:Ownership:BusinessOwner:Person.name': 'Business Owner',
        'hostname': 'Hostname',
        '__all_dns_names': 'DNS Names',
        'type': 'Type',
        '#ElementInLocation:Location:Location:Location.name': 'Location',
        'os_class': 'OS Class'
    }

    user_output = list()
    for item in output['data']:  # type: ignore[not iterable]
        row = dict()
        for p in user_map_dict:
            if p in item:
                row[user_map_dict[p]] = item[p]
        user_output.append(row)

    return CommandResults(outputs_prefix='BmcDiscovery.Search',
                          outputs_key_field='data.#id',
                          outputs=output,
                          raw_response=response,
                          readable_output=tableToMarkdown(name='BMC Discovery Search Results', t=user_output))


def discovery_process_status_command(client: Client) -> CommandResults:
    response = client.discovery_process_status()
    status = demisto.get(response, 'status')

    if not status:
        raise DemistoException('Get status failed',
                               res=response)

    return CommandResults(outputs_prefix='BmcDiscovery.Process',
                          outputs=response,
                          raw_response=response,
                          readable_output=tableToMarkdown(name='BMC Discovery Status', t=response))


def discovery_scan_status_list_command(client: Client, **args) -> CommandResults:
    response = client.discovery_scan_status_list(**args)

    if isinstance(response, list):
        pass
    elif not response:
        raise DemistoException('Get runs failed')
    else:
        response = [response]

    user_map_dict = {
        'scan_level': 'Scan Level',
        'done': 'Done',
        'total': 'Total',
        'user': 'User',
        'starttime': 'Start Time',
        'finished': 'Finished',
        'label': 'Label',
        'scan_kind': 'Kind',
        'valid_ranges': 'Ranges',
        'scan_type': 'Type',
        'uuid': 'UUID'
    }

    user_output = list()
    for item in response:
        row = dict()
        for p in user_map_dict:
            if p in item:
                row[user_map_dict[p]] = item[p]
        user_output.append(row)

    return CommandResults(outputs_prefix='BmcDiscovery.Scan.Status',
                          outputs_key_field='uuid',
                          outputs=response,
                          raw_response=response,
                          readable_output=tableToMarkdown(name='BMC Discovery Scan Status', t=user_output))


def discovery_scan_create_command(client: Client, **args) -> CommandResults:
    response = client.discovery_scan_create(**args)
    return CommandResults(outputs_prefix='BmcDiscovery.Scan.Create',
                          outputs=response,
                          raw_response=response,
                          readable_output=tableToMarkdown(name='BMC Discovery New Scan', t=response))


def discovery_scan_stop_command(client: Client, **args) -> CommandResults:
    response = client.discovery_scan_stop(**args)
    return CommandResults(outputs_prefix='BmcDiscovery.Scan',
                          outputs=response, raw_response=response,
                          readable_output=tableToMarkdown(name='BMC Discovery Scan Status',
                          headers=['Stopped'], t=response))  # noqa: E128


def discovery_scan_summary_command(client: Client, **args) -> CommandResults:
    response = client.discovery_scan_summary(**args)
    if not response:
        raise DemistoException('Failed to get scan summary')

    output = dict()
    for key in response:
        if 'count' in response[key]:
            output[key] = response[key]['count']

    return CommandResults(outputs_prefix='BmcDiscovery.Scan.Summary',
                          outputs=output,
                          raw_response=response,
                          readable_output=tableToMarkdown(name='BMC Discovery Scan Summary', t=output))


def discovery_scan_results_list_command(client: Client, **args) -> CommandResults:
    response = client.discovery_scan_results_list(**args)
    if not response:
        raise DemistoException('Failed to get scan results')

    result_type = args.get('result_type', 'Success')

    user_output = list()
    for kind in response:
        row = dict()
        row['count'] = kind['count']
        row['offset'] = kind['offset']
        for key in ('kind', 'next_offset', 'results_id'):
            if key in kind:
                row[key] = kind[key]
        user_output.append(row)

    return CommandResults(outputs_prefix='BmcDiscovery.Scan.Result',
                          outputs=response,
                          raw_response=response,
                          readable_output=tableToMarkdown(name='BMC Discovery Scan Results for "%s" kind'
                                                               '(see context for more details)' % result_type,
                                                          t=user_output))


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_token = params.get('api_token', {}).get('password')
    url = params.get('url')
    verify = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {command}')

    try:
        client = Client(url=url, api_token=api_token, verify=verify, proxy=proxy)
        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'bmc-discovery-scan-status-list':
            return_results(discovery_scan_status_list_command(client, **args))
        elif command == 'bmc-discovery-search':
            return_results(discovery_search_command(client, **args))
        elif command == 'bmc-discovery-search-custom':
            return_results(discovery_search_custom_command(client, **args))
        elif command == 'bmc-discovery-scan-create':
            return_results(discovery_scan_create_command(client, **args))
        elif command == 'bmc-discovery-scan-stop':
            return_results(discovery_scan_stop_command(client, **args))
        elif command == 'bmc-discovery-scan-summary':
            return_results(discovery_scan_summary_command(client, **args))
        elif command == 'bmc-discovery-scan-results-list':
            return_results(discovery_scan_results_list_command(client, **args))
        else:
            raise NotImplementedError(f"command {command} is not implemented.")
    except Exception as e:
        demisto.error(fix_traceback_line_numbers(traceback.format_exc()))
        return_error("\n".join(("Failed to execute {command} command.",
                                "Error:",
                                str(e))))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
