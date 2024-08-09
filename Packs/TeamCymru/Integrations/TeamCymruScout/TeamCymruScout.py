""" IMPORTS """

from copy import deepcopy  # noqa E402
from datetime import datetime  # noqa E402
from typing import Any, Callable, Dict, List, Optional, Tuple  # noqa E402

import urllib3  # noqa E402

import demistomock as demisto  # noqa E402
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%d'
BASE_URL = 'https://scout.cymru.com/api/scout'
INDICATOR_SEARCH_URL = 'https://scout.cymru.com/scout/details?query={}'
MD_LINK = '[{}]({})'
VENDOR_NAME = 'Team Cymru Scout'
TOTAL_RETRIES = 4
STATUS_CODE_TO_RETRY = [429,
                        *(status_code for status_code in requests.status_codes._codes if status_code >= 500)]   # type: ignore
OK_CODES = [200, 201]
BACKOFF_FACTOR = 7.5  # Sleep for [0s, 15s, 30s, 60s] between retries.
DATE_FORMAT = '%Y-%m-%d'

DEFAULT_START_DATE = '30 days'
DEFAULT_END_DATE = 'now'
DEFAULT_PAGE_SIZE = 20

MINIMUM_PAGE_SIZE = 1
DEFAULT_PAGE_SIZE = 20
MINIMUM_DETAIL_IP_SIZE = 1
MAXIMUM_DETAIL_IP_SIZE = 1000
MINIMUM_DAY = 1
MAXIMUM_DAY = 30
MAXIMUM_START_DAY = 90
MAXIMUM_INDICATOR_SEARCH_SIZE = 5000
MAXIMUM_IP_LIST_SIZE = 10

DEFAULT_START_DATE = '30 days'
START_DATE_LIMIT = '90 days'
DEFAULT_END_DATE = 'now'

DBOT_SCORE_MAPPING = {
    'no_rating': 0,  # Unknown
    'informational': 1,  # Good
    'suspicious': 2,  # Suspicious
    'malicious': 3  # Bad
}
SEVERITY_MAPPING = {
    'no_rating': 'Unknown',
    'informational': 'Good',
    'suspicious': 'Suspicious',
    'malicious': 'Bad'
}

KEYS_TO_REMOVE_FROM_AN_IP_AND_ADD_TO_USAGE_CONTEXT = ['request_id', 'size', 'start_date', 'end_date']

API_KEY = 'API Key'
BASIC_AUTH = 'Basic Auth'

OUTPUT_PREFIX = {
    'IP': 'TeamCymruScout.IP',
    'QUERY_USAGE': 'TeamCymruScout.QueryUsage'
}

OUTPUT_KEY_FIELD = {
    'IP': 'ip',
    'QUERY_USAGE': 'command_name',
}

ENDPOINTS = {
    'LIST_IPS': '/ip/foundation',
    'IP_DETAILS': '/ip/{}/details',
    'QUERY_USAGE': '/usage',
    'SEARCH_INDICATORS': '/search',
}

ERROR_MESSAGES = {
    'NO_PARAM_PROVIDED': 'Please provide the {}.',
    'INVALID_PAGE_SIZE': '{} is invalid value for size. Value of size should be between {} and {}.',
    'START_DATE_GREATER_THAN_END_DATE': 'Please provide the start date less than the end date.',
    'END_DATE_GREATER_THAN_CURRENT_TIME': 'Please provide the end date less than current time.',
    'REACHED_MAXIMUM_DIFF_DAYS': f'Please provide the start date less than {MAXIMUM_DAY} days from the end date.',
    'REACHED_MAXIMUM_START_DAYS': f'Please provide the start date less than {MAXIMUM_START_DAY} days.',
    'INVALID_DAY': '{} is invalid value for days.'
                   f'Value of days should be between {MINIMUM_DAY} and {MAXIMUM_DAY}.',
    'NO_INDICATORS_FOUND': 'No indicators found for given query and filters.',
    'INVALID_IP_ADDRESSES': 'The following IP Addresses were found invalid: {}',
    'INVALID_IP_ADDRESS_SIZE': ('{} valid IP Addresses provided. '
                                'Please provide the list of IP Addresses less than or equal to {}.'),
}

''' CLIENT CLASS '''


class Client(BaseClient):
    '''
    Client class to interact with the Team Cymru Scout server API.

    This Client implements API calls, and does not contain any XSOAR logic.
    '''

    def __init__(self, server_url: str, verify: bool, proxy: bool, headers: Dict, auth: Optional[Tuple]):
        '''
        Initializes the Client class with the provided parameters.

        :type server_url: ``str``
        :param server_url: The URL of the Team Cymru Scout server.

        :type verify: ``bool``
        :param verify: Whether to verify the server's SSL certificate.

        :type proxy: ``bool``
        :param proxy: The proxy settings to be used.

        :type headers: ``Dict``
        :param headers: Additional headers to be included in the requests.

        :type auth: ``Optional[Tuple]``
        :param auth: The authentication tuple to be used.
        '''
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def http_request(self, *args, **kwargs):
        '''
        A wrapper for BaseClient.http_request method with the retries added.

        :type args: ``tuple``
        :param args: The tuple to send in a request.

        :type kwargs: ``Dict``
        :param kwargs: The dictionary to send in a request.

        :return: Depends on the resp_type parameter.
        :rtype: ``Dict`` or ``str`` or ``bytes`` or ``xml.etree.ElementTree.Element`` or ``requests.Response``
        '''
        return self._http_request(retries=TOTAL_RETRIES, status_list_to_retry=STATUS_CODE_TO_RETRY,
                                  backoff_factor=BACKOFF_FACTOR, raise_on_redirect=False, ok_codes=OK_CODES,
                                  raise_on_status=True, *args, **kwargs)  # type: ignore

    def scout_api_usage_request(self) -> Dict:
        '''
        A function to request the information for the API usage.

        :return: The response containing the api usage.
        :rtype: ``Dict``
        '''
        response = self.http_request('GET', ENDPOINTS['QUERY_USAGE'])

        return response

    def ip_request(self, ip: str, start_date: Optional[str], end_date: Optional[str], days: Optional[int],
                   size: Optional[int]) -> Dict:
        '''
        A function to request the information for the given IP.

        :type ip: ``str``
        :param ip: The IP to search for.

        :type start_date: ``Optional[str]``
        :param start_date: The start date for detailed information.

        :type end_date: ``Optional[str]``
        :param end_date: The end date for detailed information.

        :type days: ``Optional[int]``
        :param days: The number of days in past for detailed information.

        :type size: ``Optional[int]``
        :param size: The number of results to return.

        :return: The response containing information for the given IP.
        :rtype: ``Dict``
        '''
        params = assign_params(start_date=start_date, end_date=end_date, days=days, size=size)

        response = self.http_request('GET', ENDPOINTS['IP_DETAILS'].format(ip), params=params)

        return response

    def scout_indicator_search_request(self, query: str, start_date: Optional[str], end_date: Optional[str],
                                       days: Optional[int], size: Optional[int]) -> Dict:
        '''
        A function to search the indicators based on specified parameters.

        :type query: str
        :param query: The query to search for.

        :type start_date: Optional[str]
        :param start_date: The start date to filter indicators.

        :type end_date: Optional[str]
        :param end_date: The end date to filter indicators.

        :type days: Optional[int]
        :param days: The number of days in past to filter indicators.

        :type size: Optional[int]
        :param size: The number of results to return.

        :rtype: Dict[str, str]
        :return: The response containing the details for the queried indicators.
        '''
        params = assign_params(query=query, start_date=start_date, end_date=end_date, days=days, size=size)

        response = self.http_request('GET', ENDPOINTS['SEARCH_INDICATORS'], params=params)

        return response

    def scout_ip_list(self, params) -> Dict:
        '''
        A function to request the information for the IPs.

        :type params: Dict
        :param params: The parameters to send in the request.

        :rtype: Dict[str, str]
        :return: The response containing the ip's data.
        '''
        response = self.http_request('GET', ENDPOINTS['LIST_IPS'], params=params)

        return response


''' HELPER FUNCTIONS '''


def trim_spaces_from_args(args: Dict):
    '''Remove space from args.'''
    for key in args.keys():
        if isinstance(args[key], str):
            args[key] = args[key].strip()
    return args


def validate_params(params: Dict):
    '''
    Validate the parameters.

    :type params: ``Dict``
    :param params: Params to validate.
    '''
    authentication_type: str = params.get('authentication_type', '')

    if authentication_type == API_KEY:
        api_key = str(params.get('api_key', {}).get('password', '')).strip()
        if not api_key:
            raise DemistoException(ERROR_MESSAGES['NO_PARAM_PROVIDED'].format(API_KEY))
    elif authentication_type == BASIC_AUTH:
        basic_auth = params.get('basic_auth', {})
        username = str(basic_auth.get('identifier', '')).strip()
        if not username:
            raise DemistoException(ERROR_MESSAGES['NO_PARAM_PROVIDED'].format('Username'))
        password = str(basic_auth.get('password', '')).strip()
        if not password:
            raise DemistoException(ERROR_MESSAGES['NO_PARAM_PROVIDED'].format('Password'))


def header_transformer_for_ip(header: str) -> str:
    '''
    To transform the header for the markdown table.

    :type header: ``str``
    :param header: Header name.

    :return: The title cased header.
    :rtype: ``str``
    '''
    return header.replace('_', ' ').title().replace('Ip', 'IP')


def create_tag_list(tags: list) -> str:
    '''
    Create comma separated tag list.

    :type tags: ``list``
    :param tags: List of tags from response.

    :return: Comma separated tag list.
    :rtype: ``str``
    '''
    tag_list = []
    for tag_dict in tags:
        tag = tag_dict.get('name', '')
        sub_tags = []
        for child_tag in tag_dict.get('children', []):
            sub_tags.append(child_tag.get('name', ''))
        if sub_tags:
            tag += f': ({", ".join(sub_tags)})'
        tag_list.append(tag)
    return ', '.join(tag_list)


def remove_empty_elements_for_hr(d):
    """
    Recursively remove empty lists, empty dicts, or None elements from a dictionary.

    :type d: ``dict``
    :param d: Input dictionary.

    :return: Dictionary with all empty lists, and empty dictionaries removed.
    :rtype: ``dict``
    """

    def empty(x):
        return x is None or x == {} or x == [] or x == ''

    if not isinstance(d, (dict, list)):
        return d
    elif isinstance(d, list):
        return [v for v in (remove_empty_elements_for_hr(v) for v in d) if not empty(v)]
    else:
        return {k: v for k, v in ((k, remove_empty_elements_for_hr(v)) for k, v in d.items()) if not empty(v)}


def validate_common_search_command_args(args: Dict[str, str], required_arg: str,
                                        maximum_page_size: int = MAXIMUM_DETAIL_IP_SIZE) -> Tuple:
    '''
    To validate common arguments of all command.

    :type args: ``dict``
    :param args: Command arguments.

    :type required_arg: ``str``
    :param required_arg: Required argument.

    :type maximum_page_size: ``int``
    :param maximum_page_size: Maximum page size.

    :rtype: Tuple
    :return: The tuple containing the extracted arguments with pagination parameters.
    '''
    required_arg_val: str = args.get(required_arg, '')
    if not required_arg_val:
        raise DemistoException(ERROR_MESSAGES['NO_PARAM_PROVIDED'].format(required_arg))

    start_date_str = args.get('start_date', DEFAULT_START_DATE)
    end_date_str = args.get('end_date', DEFAULT_END_DATE)

    start_date_obj = arg_to_datetime(start_date_str, 'start_date')
    end_date_obj = arg_to_datetime(end_date_str, 'end_date')
    current_date_obj = arg_to_datetime(DEFAULT_END_DATE)

    start_date = start_date_obj.strftime(DATE_FORMAT) if isinstance(start_date_obj, datetime) else start_date_obj
    start_date_obj = arg_to_datetime(start_date)
    end_date = end_date_obj.strftime(DATE_FORMAT) if isinstance(end_date_obj, datetime) else end_date_obj
    end_date_obj = arg_to_datetime(end_date)

    if start_date_obj > end_date_obj:  # type: ignore
        raise DemistoException(ERROR_MESSAGES['START_DATE_GREATER_THAN_END_DATE'])
    if end_date_obj > current_date_obj:  # type: ignore
        raise DemistoException(ERROR_MESSAGES['END_DATE_GREATER_THAN_CURRENT_TIME'])

    if start_date_obj <= current_date_obj - timedelta(days=MAXIMUM_START_DAY):  # type: ignore
        raise DemistoException(ERROR_MESSAGES['REACHED_MAXIMUM_START_DAYS'])

    if end_date_obj - start_date_obj >= timedelta(days=MAXIMUM_DAY):  # type: ignore
        if start_date_str.lower() in DEFAULT_START_DATE:
            start_date_obj += timedelta(days=1)  # type: ignore
            start_date = start_date_obj.strftime(DATE_FORMAT)  # type: ignore
        else:
            raise DemistoException(ERROR_MESSAGES['REACHED_MAXIMUM_DIFF_DAYS'])

    days = arg_to_number(args.get('days'), 'days')
    if isinstance(days, int) and not (MINIMUM_DAY <= days <= MAXIMUM_DAY):
        raise DemistoException(ERROR_MESSAGES['INVALID_DAY'].format(days))

    size = arg_to_number(args.get('size', DEFAULT_PAGE_SIZE), 'size')
    if isinstance(size, int) and not (MINIMUM_PAGE_SIZE <= size <= maximum_page_size):
        raise DemistoException(ERROR_MESSAGES['INVALID_PAGE_SIZE'].format(
            size, MINIMUM_PAGE_SIZE, maximum_page_size))

    return required_arg_val, start_date, end_date, days, size


def validate_ip_addresses(ips_list: List[str]) -> Tuple[List[str], List[str]]:
    '''
    Given a list of IP addresses, returns the invalid and valid ips.

    :type ips_list: ``List[str]``
    :param ips_list: List of ip addresses.

    :return: invalid_ip_addresses and valid_ip_addresses.
    :rtype: ``Tuple[List[str], List[str]]``
    '''
    invalid_ip_addresses = []
    valid_ip_addresses = []
    for ip in ips_list:
        ip = ip.strip().strip('\"')
        if ip:
            if is_ip_valid(ip, accept_v6_ips=True):
                valid_ip_addresses.append(ip)
            else:
                invalid_ip_addresses.append(ip)
    return invalid_ip_addresses, valid_ip_addresses


def validate_ip_list_args(args: Dict) -> Dict:
    '''
    Validate the ip list arguments.

    :param args: Arguments to validate.
    :type args: Dict

    :return: Validated arguments.
    :rtype: Dict
    '''
    ip_addresses = argToList(args.get('ip_addresses'))

    invalid_ips, valid_ips = validate_ip_addresses(ip_addresses)

    if invalid_ips:
        return_warning(ERROR_MESSAGES['INVALID_IP_ADDRESSES'].format(', '.join(invalid_ips)),
                       exit=len(invalid_ips) == len(ip_addresses))

    if not valid_ips:
        raise DemistoException(ERROR_MESSAGES['NO_PARAM_PROVIDED'].format('ip_addresses'))

    if len(valid_ips) > 10:
        raise DemistoException(ERROR_MESSAGES['INVALID_IP_ADDRESS_SIZE'].format(len(valid_ips), MAXIMUM_IP_LIST_SIZE))

    return {'ips': ','.join(valid_ips)}


def remove_key_from_ip_and_add_to_usage(ip_response: dict, usage_response: dict) -> Tuple[Dict, Dict]:
    '''
    Prepare context ip command.

    :type ip_response: ``dict``
    :param ip_response: Response contain detailed information about ip.

    :type usage_response: ``dict``
    :param usage_response: Response contain information about api usage.

    :return: Modified ip_response and usage_response.
    :rtype: ``Tuple[Dict, Dict]``
    '''
    for key in KEYS_TO_REMOVE_FROM_AN_IP_AND_ADD_TO_USAGE_CONTEXT:
        usage_response[key] = ip_response.get(key)
        del ip_response[key]

    usage_response['command_name'] = 'ip'
    del ip_response['usage']

    return ip_response, usage_response


def find_description(ip: str, insights: list) -> str:
    '''
    Finding the description for ip from insights response.

    :type ip: ``str``
    :param ip: Used to find description.

    :type insights: ``list``
    :param insights: Insights related to ip.

    :return: Description related to ip.
    :rtype: ``str``
    '''
    description = ''

    for insight in insights:
        message = insight.get('message')
        if ip in message:
            return message
        description += message
        description += '\n'

    return description


def prepare_hr_for_ip(response: dict) -> str:
    '''
    Prepare Human Readable output for ip command.

    :type response: ``Dict``
    :param response: Response from API.

    :rtype: ``str``
    :return: Human readable output.
    '''
    data = response
    summary_hr = [{
        'Country Code': data.get('summary', {}).get('geo_ip_cc'),
        'Whois': remove_empty_elements_for_hr(data.get('summary', {}).get('whois')),
        'Tags': remove_empty_elements_for_hr(data.get('summary', {}).get('tags', [])),
        'Insights': remove_empty_elements_for_hr(data.get('summary', {}).get('insights', {}).get('insights'))
    }]

    severity = SEVERITY_MAPPING.get((response.get('summary', {}).get('insights', {}).get('overall_rating')).lower())
    ip_md_link = MD_LINK.format(data.get('ip'), INDICATOR_SEARCH_URL.format(data.get('ip')))

    for pdns_data in data.get('summary', {}).get('pdns', {}).get('top_pdns', []):
        del pdns_data['css_color']

    pdns_hr = data.get('summary', {}).get('pdns', {}).get('top_pdns', [])

    top_peers_hr = [{
        'Proto': peer.get('proto_text'),
        'Event Count': peer.get('event_count'),
        'Server IP': peer.get('local', {}).get('ip'),
        'Server Country Code(s)': peer.get('local', {}).get('country_codes'),
        'Server Tag(s)': create_tag_list(tags=peer.get('local', {}).get('tags', [])),
        'Server Services': remove_empty_elements_for_hr(peer.get('local', {}).get('top_services', [])[:5]),
        'Server AS Name': [as_info.get('as_name') for as_info in peer.get('local', {}).get('as_info', [])],
        'Client IP': peer.get('peer', {}).get('ip'),
        'Client Country Code(s)': peer.get('peer', {}).get('country_codes'),
        'Client Tag(s)': create_tag_list(tags=peer.get('peer', {}).get('tags', [])),
        'Client Services': remove_empty_elements_for_hr(peer.get('peer', {}).get('top_services', [])[:5]),
        'Client AS Name': [as_info.get('as_name') for as_info in peer.get('peer', {}).get('as_info', [])],
        'First Seen': peer.get('first_seen'),
        'Last Seen': peer.get('last_seen')
    } for peer in data.get('communications', {}).get('peers', [])[:5]]

    open_port_hr = [{
        'Event Count': port_data.get('event_count'),
        'Port': port_data.get('port'),
        'Protocol': port_data.get('protocol'),
        'Protocol Text': port_data.get('protocol_text'),
        'Service': port_data.get('service'),
        'First Seen': port_data.get('first_seen'),
        'Last Seen': port_data.get('last_seen')
    } for port_data in data.get('summary', {}).get('open_ports', {}).get('top_open_ports', [])]

    fingerprints_hr = data.get('summary', {}).get('fingerprints', {}).get('top_fingerprints', [])

    for certs_data in data.get('summary', {}).get('certs', {}).get('top_certs', []):
        del certs_data['css_color']

    certs_hr = data.get('summary', {}).get('certs', {}).get('top_certs', [])

    hr_list = [summary_hr, pdns_hr, top_peers_hr, open_port_hr, fingerprints_hr, certs_hr]
    new_hr_list = []
    for hr_data in hr_list:
        hr_data = remove_empty_elements_for_hr(hr_data)
        [remove_nulls_from_dictionary(data) for data in hr_data]
        new_hr_list.append(hr_data)

    (summary_hr, pdns_hr, top_peers_hr, open_port_hr, fingerprints_hr, certs_hr) = new_hr_list

    human_readable = tableToMarkdown(f'Summary Information For The Given {severity} IP: {ip_md_link}', summary_hr,
                                     json_transform_mapping={'Whois': JsonTransformer(), 'Insights': JsonTransformer(),
                                                             'Tags': JsonTransformer()},
                                     removeNull=True, headers=['Country Code', 'Whois', 'Tags', 'Insights']) + '\n'
    human_readable += tableToMarkdown(
        'Top PDNS', pdns_hr, headerTransform=header_transformer_for_ip, removeNull=True) + '\n' if pdns_hr else ''
    human_readable += tableToMarkdown('Top Peers', top_peers_hr, removeNull=True,
                                      json_transform_mapping={'Client Services': JsonTransformer(),
                                                              'Server Services': JsonTransformer()},
                                      headers=['Proto', 'Client IP', 'Client Country Code(s)', 'Client Tag(s)', 'Client Services',
                                               'Server IP', 'Server Country Code(s)', 'Server Tag(s)', 'Server Services',
                                               'Event Count', 'First Seen', 'Last Seen', 'Client AS Name',
                                               'Server AS Name']) + '\n' if top_peers_hr else ''
    human_readable += tableToMarkdown('Top Open Ports', open_port_hr, removeNull=True, headers=['Event Count', 'Port', 'Protocol',
                                      'Protocol Text', 'Service', 'First Seen', 'Last Seen']) + '\n' if open_port_hr else ''
    human_readable += tableToMarkdown('Top Fingerprints', fingerprints_hr, removeNull=True,
                                      headerTransform=header_transformer_for_ip) + '\n' if fingerprints_hr else ''
    human_readable += tableToMarkdown('Top Certificates', certs_hr, removeNull=True,
                                      headerTransform=header_transformer_for_ip) + '\n' if certs_hr else ''

    return human_readable


def create_relationship_for_indicator_search(response: dict) -> List:
    '''
    Create a list of relationships objects from the response.

    :type response: ``dict``
    :param response: Response of API.

    :return: List of EntityRelationship objects containing all the relationships.
    :rtype: ``List``
    '''
    relationships = []
    source_ip = response.get('ip', '')
    integration_reliability = demisto.params().get('integrationReliability')

    for peer in response.get('summary', {}).get('top_peers', []):
        client_ip = peer.get('ip')
        fields = {key: value for key, value in peer.items() if key != 'ip'}
        relationships.append(EntityRelationship(name=EntityRelationship.Relationships.COMMUNICATED_WITH,
                                                entity_a=source_ip,
                                                entity_a_type=FeedIndicatorType.IP,
                                                entity_b=client_ip,
                                                entity_b_type=FeedIndicatorType.IP,
                                                source_reliability=integration_reliability,
                                                brand=VENDOR_NAME, fields=fields))

    for pdns in response.get('summary', {}).get('pdns', []):
        ip = pdns.get('ip')
        domain = pdns.get('domain')
        fields = {key: value for key, value in pdns.items() if key not in ['ip', 'domain']}
        relationships.append(EntityRelationship(name=EntityRelationship.Relationships.RESOLVES_TO,
                                                entity_a=ip,
                                                entity_a_type=FeedIndicatorType.IP,
                                                entity_b=domain,
                                                entity_b_type=FeedIndicatorType.Domain,
                                                source_reliability=integration_reliability,
                                                brand=VENDOR_NAME, fields=fields))

    return relationships


def prepare_hr_and_context_for_indicator_search(response: Dict) -> Tuple[str, Dict, Common.IP, List]:
    '''
    A function to prepare the human readable and context output for the indicator search.

    :type response: Dict
    :param response: The response containing the list of indicators.

    :rtype: Tuple[str, Dict, Common.IP, List]
    :return: The human readable, context output, IP indicator and relationships.
    '''
    scout_ip_data = remove_empty_elements(response)
    remove_nulls_from_dictionary(scout_ip_data)

    ip_address = scout_ip_data.get('ip')

    dbot_score = Common.DBotScore(
        indicator=ip_address,
        indicator_type=DBotScoreType.IP,
        integration_name=VENDOR_NAME,
        score=Common.DBotScore.NONE,
        reliability=demisto.params().get('integrationReliability')
    )

    relationships = []
    create_relationships = demisto.params().get('create_relationships')
    if create_relationships:
        relationships = create_relationship_for_indicator_search(response)

    country_codes = scout_ip_data.get('country_codes', [])
    scout_ip_hr = [{
        'Country Code(s)': country_codes,
        'Whois': scout_ip_data.get('summary').get('whois'),
        'Event Count': scout_ip_data.get('event_count'),
        'Tags': scout_ip_data.get('tags', []),
        'Last Seen': scout_ip_data.get('summary', {}).get('last_seen'),
    }]
    pdns_hr = list(pdn for pdn in scout_ip_data.get('summary', {}).get('pdns', []))
    open_ports_hr = list(open_port for open_port in scout_ip_data.get('summary', {}).get('open_ports', []))
    top_peers_hr = list({'Source IP': ip_address, **top_peer} for top_peer in scout_ip_data.get(
        'summary', {}).get('top_peers', []))
    service_counts_hr = list({'Source IP': ip_address, **service_count} for service_count in scout_ip_data.get(
        'summary', {}).get('service_counts', []))
    fingerprints_hr = list(fingerprint for fingerprint in scout_ip_data.get('summary', {}).get('fingerprints', []))
    certs_hr = list(cert for cert in scout_ip_data.get('summary', {}).get('certs', []))

    hr_list = [scout_ip_hr, pdns_hr, open_ports_hr, top_peers_hr, service_counts_hr, fingerprints_hr, certs_hr]
    new_hr_list = []
    for hr_data in hr_list:
        hr_data = remove_empty_elements(hr_data)
        [remove_nulls_from_dictionary(data) for data in hr_data]
        new_hr_list.append(hr_data)

    (scout_ip_hr, pdns_hr, open_ports_hr, top_peers_hr, service_counts_hr, fingerprints_hr, certs_hr) = new_hr_list

    top_host_name = None
    top_host_event_count = 0
    for pdn in pdns_hr:
        if pdn.get('event_count') > top_host_event_count:
            top_host_event_count = pdn.get('event_count')
            top_host_name = pdn.get('domain')

    ip_indicator = Common.IP(
        ip=ip_address,
        dbot_score=dbot_score,
        asn=response.get('summary', {}).get('whois', {}).get('asn'),
        as_owner=response.get('summary', {}).get('whois', {}).get('as_name'),
        region=', '.join(country_codes),
        port=','.join([str(open_port.get('port', ''))
                      for open_port in response.get('summary', {}).get('open_ports', [])]),
        updated_date=response.get('summary', {}).get('last_seen'),
        organization_name=response.get('summary', {}).get('whois', {}).get('org_name'),
        hostname=top_host_name,
        geo_country=', '.join(country_codes),
        tags=create_tag_list(scout_ip_data.get('tags', [])),
        relationships=relationships,
    )

    ip_md_link = MD_LINK.format(ip_address, INDICATOR_SEARCH_URL.format(ip_address))
    human_readable = tableToMarkdown(f'Summary Information for the given indicator: {ip_md_link}', scout_ip_hr,
                                     json_transform_mapping={'Whois': JsonTransformer(), 'Tags': JsonTransformer()},
                                     removeNull=True, headerTransform=header_transformer_for_ip,
                                     headers=['IP', 'Country Code(s)', 'Whois', 'Event Count', 'Tags', 'Last Seen']) + '\n'
    human_readable += tableToMarkdown('PDNS Information', pdns_hr,
                                      headerTransform=header_transformer_for_ip) + '\n' if pdns_hr else ''
    human_readable += tableToMarkdown('Open Ports Information', open_ports_hr,
                                      headerTransform=header_transformer_for_ip) + '\n' if open_ports_hr else ''
    human_readable += tableToMarkdown(
        'Top Peers Information', top_peers_hr, headerTransform=header_transformer_for_ip) + '\n' if top_peers_hr else ''
    human_readable += tableToMarkdown('Service Counts Information', service_counts_hr,
                                      headerTransform=header_transformer_for_ip) + '\n' if service_counts_hr else ''
    human_readable += tableToMarkdown('Fingerprints Information', fingerprints_hr,
                                      headerTransform=header_transformer_for_ip) + '\n' if fingerprints_hr else ''
    human_readable += tableToMarkdown('Certs Information', certs_hr,
                                      headerTransform=header_transformer_for_ip) + '\n' if certs_hr else ''

    return human_readable, scout_ip_data, ip_indicator, relationships


def prepare_hr_and_context_for_ip_list(response: dict) -> Tuple[str, Dict, Common.IP]:
    '''
    A function to prepare the human readable and context output for the ip list command.

    :type response: dict
    :param response: The response from the server.

    :rtype: Tuple[str, Dict, Common.IP]
    :return: The human readable, context output and the indicator for the ip.
    '''
    scout_ip_data = remove_empty_elements(response)

    ip_address = scout_ip_data.get('ip')

    score = DBOT_SCORE_MAPPING[scout_ip_data.get('insights', {}).get('overall_rating') or 'no_rating']
    country_code = scout_ip_data.get('country_code', '')
    as_info = scout_ip_data.get('as_info', [])
    as_name = ''
    asn = ''
    if isinstance(as_info, list) and len(as_info) > 0:
        as_info_dict = as_info[0]
        as_name = as_info_dict.get('as_name', '')
        asn = as_info_dict.get('asn', '')

    dbot_score = Common.DBotScore(
        indicator=ip_address,
        indicator_type=DBotScoreType.IP,
        integration_name=VENDOR_NAME,
        score=score,
        reliability=demisto.params().get('integrationReliability')
    )

    tags = create_tag_list(scout_ip_data.get('tags', []))

    insight_message = find_description(ip_address, scout_ip_data.get('insights', {}).get('insights', []))

    ip_ioc = Common.IP(
        ip=ip_address,
        dbot_score=dbot_score,
        asn=asn,
        as_owner=as_name,
        region=country_code,
        geo_country=country_code,
        tags=tags,
        description=insight_message,
        organization_name=as_name,
    )

    ip_md_link = MD_LINK.format(ip_address, INDICATOR_SEARCH_URL.format(ip_address))

    hr_list = [{
        'Country Code': scout_ip_data.get('country_code', ''),
        'AS Info': scout_ip_data.get('as_info', ''),
        'Insights': scout_ip_data.get('insights', ''),
        'Tags': scout_ip_data.get('tags', '')
    }]

    table_title = f'Summary Information for the given {scoreToReputation(score)} IP: {ip_md_link}'
    table_headers = ['Country Code', 'AS Info', 'Insights', 'Tags']

    hr = tableToMarkdown(table_title, hr_list, removeNull=True, headers=table_headers,
                         json_transform_mapping={'AS Info': JsonTransformer(), 'Insights': JsonTransformer(),
                                                 'Tags': JsonTransformer()})

    return hr, scout_ip_data, ip_ioc


def prepare_hr_and_context_for_api_usage(response: dict, command_name: str) -> Tuple[str, Dict]:
    '''
    A function to prepare the human readable and context output for the api usage.

    :type response: dict
    :param response: The response containing the api usage.

    :type command_name: str
    :param command_name: The name of the command.

    :rtype: Tuple[str, Dict]
    :return: The human readable and context output for the api usage.
    '''
    hr_list = [{
        'Used Queries': response.get('used_queries'),
        'Remaining Queries': response.get('remaining_queries'),
        'Query Limit': response.get('query_limit'),
        'Foundation Used Queries': response.get('foundation_api_usage', {}).get('used_queries'),
        'Foundation Remaining Queries': response.get('foundation_api_usage', {}).get('remaining_queries'),
        'Foundation Query Limit': response.get('foundation_api_usage', {}).get('query_limit'),
    }]

    context = {'command_name': command_name, **response}

    table_headers = ['Used Queries', 'Remaining Queries', 'Query Limit', 'Foundation Used Queries',
                     'Foundation Remaining Queries', 'Foundation Query Limit']

    hr = tableToMarkdown('API Usage', hr_list, removeNull=True, headers=table_headers)

    return hr, context


def create_relationship(response: dict) -> List:
    '''
    Create a list of relationships objects from the response.

    :type response: ``dict``
    :param response: Response of API.

    :return: List of EntityRelationship objects containing all the relationships.
    :rtype: ``List``
    '''
    relationships = []

    for peer in response.get('communications', {}).get('peers', []):
        server_ip = peer.get('local', {}).get('ip')
        client_ip = peer.get('peer', {}).get('ip')
        relationships.append(EntityRelationship(name=EntityRelationship.Relationships.COMMUNICATED_WITH,
                                                entity_a=server_ip,
                                                entity_a_type=FeedIndicatorType.IP,
                                                entity_b=client_ip,
                                                entity_b_type=FeedIndicatorType.IP,
                                                source_reliability=demisto.params().get('integrationReliability'),
                                                brand=VENDOR_NAME))

    for pdns in response.get('pdns', {}).get('pdns', []):
        ip = pdns.get('ip')
        domain = pdns.get('domain')
        relationships.append(EntityRelationship(name=EntityRelationship.Relationships.RESOLVES_TO,
                                                entity_a=ip,
                                                entity_a_type=FeedIndicatorType.IP,
                                                entity_b=domain,
                                                entity_b_type=FeedIndicatorType.Domain,
                                                source_reliability=demisto.params().get('integrationReliability'),
                                                brand=VENDOR_NAME))

    return relationships


""" COMMAND FUNCTIONS """


def ip_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    '''
    Retrieve the detail information of ip that meet the specified filter criteria.

    :type client: ``Client``
    :param client: Object of Client class.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :rtype: ``List[CommandResults]``
    :return: List of standard command result.
    '''
    ips, start_date, end_date, days, size = validate_common_search_command_args(args=args, required_arg='ip')
    size = arg_to_number(args.get('size'), 'size')

    ips = argToList(args.get('ip'))
    invalid_ips, valid_ips = validate_ip_addresses(ips)
    if invalid_ips:
        return_warning('The following IP Addresses were found invalid: {}'.format(', '.join(invalid_ips)),
                       exit=len(invalid_ips) == len(ips))

    command_results = []

    for ip in valid_ips:
        response = client.ip_request(ip, start_date, end_date, days, size)
        response = remove_empty_elements(response)

        ip_response, hr_response = deepcopy(response), deepcopy(response)
        usage_response = deepcopy(response.get('usage', {}))

        ip_response, usage_response = remove_key_from_ip_and_add_to_usage(ip_response, usage_response)

        ip_hr_output = prepare_hr_for_ip(response=hr_response)
        hr, context = prepare_hr_and_context_for_api_usage(usage_response, 'ip')

        dbot_score = Common.DBotScore(
            indicator=ip,
            indicator_type=DBotScoreType.IP,
            integration_name=VENDOR_NAME,
            score=DBOT_SCORE_MAPPING.get(response.get('summary', {}).get('insights', {}).get('overall_rating') or 'no_rating'),
            malicious_description=find_description(ip, response.get('summary', {}).get('insights', {}).get('insights', [])),
            reliability=demisto.params().get('integrationReliability')
        )

        relationships = []
        create_relationships = demisto.params().get('create_relationships')
        if create_relationships:
            relationships = create_relationship(response)

        ip_indicator = Common.IP(
            ip=ip,
            asn=response.get('whois', {}).get('asn'),
            as_owner=response.get('whois', {}).get('as_name'),
            region=response.get('whois', {}).get('cc'),
            organization_name=response.get('whois', {}).get('org_name'),
            updated_date=response.get('whois', {}).get('modified'),
            description=find_description(ip, response.get('summary', {}).get('insights', {}).get('insights', [])),
            port=', '.join([str(data.get('port', '')) for data in response.get('open_ports', {}).get('open_ports', [])]),
            tags=create_tag_list(response.get('summary', {}).get('tags', [])),
            dbot_score=dbot_score,
            relationships=relationships
        )

        command_result = [CommandResults(
            outputs_prefix=OUTPUT_PREFIX['IP'],
            outputs_key_field=OUTPUT_KEY_FIELD['IP'],
            outputs=ip_response,
            raw_response=response,
            readable_output=ip_hr_output,
            indicator=ip_indicator,
            relationships=relationships
        ), CommandResults(
            outputs_prefix=OUTPUT_PREFIX['QUERY_USAGE'],
            outputs_key_field=OUTPUT_KEY_FIELD['QUERY_USAGE'],
            outputs=context,
            raw_response=response,
            readable_output=hr,
        )]

        command_results.extend(command_result)

    return command_results


def scout_api_usage_command(client: Client, *_) -> CommandResults:
    '''
    The command function to request the information for the API usage.

    :type client: Client
    :param client: The client object.

    :rtype: CommandResults
    :return: The command results containing the human readable and context output for the api usage.
    '''

    response = client.scout_api_usage_request()

    hr, context = prepare_hr_and_context_for_api_usage(response, 'scout-api-usage')

    command_results = CommandResults(
        outputs_prefix=OUTPUT_PREFIX['QUERY_USAGE'],
        outputs_key_field='command_name',
        outputs=context,
        raw_response=response,
        readable_output=hr,
    )

    return command_results


def scout_indicator_search_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    '''
    The command function to request the information for the API usage.

    :type client: Client
    :param client: The client object.

    :type args: Dict
    :param args: The arguments passed to the command.

    :rtype: CommandResults
    :return: The command results containing the human readable and context output for the api usage.
    '''
    validated_args = validate_common_search_command_args(args, 'query', MAXIMUM_INDICATOR_SEARCH_SIZE)

    response = client.scout_indicator_search_request(*validated_args)  # type: ignore

    ips_response = response.get('ips', [])
    ip_command_results = []
    if not ips_response:
        ip_command_results.append(CommandResults(
            readable_output=ERROR_MESSAGES['NO_INDICATORS_FOUND'],
        ))
    else:
        for ip_response in ips_response:
            raw_ip_response = deepcopy(ip_response)
            ip_response = remove_empty_elements(ip_response)
            ip_hr, ip_context, ip_indicator, relationships = prepare_hr_and_context_for_indicator_search(ip_response)
            ip_command_results.append(CommandResults(
                outputs_prefix=OUTPUT_PREFIX['IP'],
                outputs_key_field='ip',
                outputs=ip_context,
                raw_response=raw_ip_response,
                readable_output=ip_hr,
                indicator=ip_indicator,
                relationships=relationships,
            ))

    usage_response = {key: value for key, value in response.items() if key != 'ips'}

    usage_hr, usage_context = prepare_hr_and_context_for_api_usage(
        usage_response.get('usage', {}), 'scout-indicator-search')
    usage_context.update(usage_response)
    remove_empty_elements(usage_context)
    usage_context.pop('usage', None)

    usage_command_result = CommandResults(
        outputs_prefix=OUTPUT_PREFIX['QUERY_USAGE'],
        outputs_key_field='command_name',
        outputs=usage_context,
        raw_response=usage_response,
        readable_output=usage_hr,
    )

    return [*ip_command_results, usage_command_result]


def scout_ip_list_command(client: Client, args: Dict) -> List[CommandResults]:
    '''
    A function to get the ip list from the Team Cymru Scout server.

    :type client: Client
    :param client: The client object.

    :type args: Dict
    :param args: The arguments passed to the command.

    :rtype: List[CommandResults]
    :return: The command results containing the human readable and context output for the ip list and api usage.
    '''
    validated_args = validate_ip_list_args(args)
    response = client.scout_ip_list(params=validated_args)
    ips_data = deepcopy(response.get('data', []))
    ip_command_results = []

    if not ips_data:
        ip_command_results.append(CommandResults(
            readable_output=ERROR_MESSAGES['NO_INDICATORS_FOUND'],
        ))
    else:
        for ip_response in ips_data:
            ip_hr, ip_context, ip_indicator = prepare_hr_and_context_for_ip_list(ip_response)
            ip_command_results.append(CommandResults(
                outputs_prefix=OUTPUT_PREFIX['IP'],
                outputs_key_field=OUTPUT_KEY_FIELD['IP'],
                outputs=ip_context,
                raw_response=ip_response,
                readable_output=ip_hr,
                indicator=ip_indicator,
            ))

    usage_response = {key: value for key, value in response.items() if key != 'data'}

    usage_hr, usage_context = prepare_hr_and_context_for_api_usage(usage_response.get('usage', {}), 'scout-ip-list')
    usage_context.update(usage_response)
    remove_empty_elements(usage_context)
    usage_context.pop('usage', None)

    usage_command_result = CommandResults(
        outputs_prefix=OUTPUT_PREFIX['QUERY_USAGE'],
        outputs_key_field=OUTPUT_KEY_FIELD['QUERY_USAGE'],
        outputs=usage_context,
        raw_response=usage_response,
        readable_output=usage_hr,
    )
    return [*ip_command_results, usage_command_result]


def test_module(client: Client) -> str:
    '''
    Test the Team Cymru Scout instance configuration.

    :type client: ``Client``
    :param: client: Object of Client class.

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    '''
    client.scout_api_usage_request()
    return 'ok'


def main() -> None:
    '''main function, parses params and runs command functions.'''
    params = trim_spaces_from_args(demisto.params())
    remove_nulls_from_dictionary(params)

    args = trim_spaces_from_args(demisto.args())
    remove_nulls_from_dictionary(args)

    verify_certificate: bool = not argToBoolean(params.get('insecure', False))
    proxy: bool = argToBoolean(params.get('proxy', False))

    headers = {}
    authentication_type = params.get('authentication_type', '')

    if authentication_type == API_KEY:
        api_key = str(params.get('api_key', {}).get('password', '')).strip()
        headers['Authorization'] = f'Token {api_key}'
        auth_tuple = None
    elif authentication_type == BASIC_AUTH:
        basic_auth = params.get('basic_auth', {})
        username = str(basic_auth.get('identifier', '')).strip()
        password = str(basic_auth.get('password', '')).strip()
        auth_tuple = (username, password)

    command = demisto.command()
    demisto.debug(f'Command being called is {command}.')

    try:
        urllib3.disable_warnings()
        validate_params(params)

        client: Client = Client(BASE_URL, verify_certificate, proxy, headers=headers, auth=auth_tuple)

        commands: Dict[str, Callable] = {
            'ip': ip_command,
            'scout-api-usage': scout_api_usage_command,
            'scout-indicator-search': scout_indicator_search_command,
            'scout-ip-list': scout_ip_list_command,
        }

        if command == 'test-module':
            return_results(test_module(client))
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
