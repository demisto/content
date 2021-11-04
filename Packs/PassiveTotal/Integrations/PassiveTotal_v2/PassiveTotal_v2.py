from CommonServerPython import *

''' IMPORTS '''

from typing import Dict, Any, List, Union, Tuple, Optional
from requests import ConnectionError
from requests.exceptions import MissingSchema, InvalidSchema
import urllib3
import traceback
import re
from urllib import parse

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_TIME_FORMAT = '%Y-%m-%d %H:%M:%S'

DATE_FORMAT = '%Y-%m-%d'

INTEGRATION_NAME: str = 'PassiveTotal'

DEFAULT_REQUEST_TIMEOUT = '20'

PROFILE_TYPE = ["actor", "backdoor", "tool"]

SOURCE = ["osint", "riskiq"]

DEFAULT_PAGE_NUMBER = 0

DEFAULT_SIZE = 50

MESSAGES: Dict[str, str] = {
    'AUTHENTICATION_ERROR': 'Unauthenticated. Check the configured Username and API secret.',
    'PAGE_NOT_FOUND_ERROR': 'No record(s) found.',
    'INTERNAL_SERVER_ERROR': 'The server encountered an internal error for PassiveTotal and was unable to complete '
                             'your request.',
    'BAD_REQUEST_ERROR': 'An error occurred while fetching the data.',
    'REQUEST_TIMEOUT_VALIDATION': 'HTTP(S) Request timeout parameter must be a positive integer.',
    'REQUEST_TIMEOUT_EXCEED_ERROR': 'Value is too large for HTTP(S) Request Timeout.',
    'NO_RECORDS_FOUND': 'No {0} were found for the given argument(s).',
    'EMPTY_WHOIS_ARGUMENT': 'query or field argument should not be empty.',
    'EMPTY_DOMAIN_ARGUMENT': 'domain argument should not be empty.',
    'INVALID_DIRECTION_VALUE': 'The given value for direction is invalid. Supported values: children, parents.',
    'INVALID_QUERY_VALUE': 'The given value for query is invalid.',
    'MISSING_SCHEMA_ERROR': 'Invalid API URL. No schema supplied: http(s).',
    'INVALID_SCHEMA_ERROR': 'Invalid API URL. Supplied schema is invalid, supports http(s).',
    'CONNECTION_ERROR': 'Connectivity failed. Check your internet connection, the API URL or try increasing the HTTP(s)'
                        ' Request Timeout.',
    'PROXY_ERROR': 'Proxy Error - cannot connect to proxy. Either try clearing the \'Use system proxy\' check-box or '
                   'check the host, authentication details and connection details for the proxy.',
    'INVALID_VALUE_IN_FIELD_ARG': 'Invalid field type {}. Valid field types are domain, email, name, organization, '
                                  'address, phone, nameserver.',
    'INVALID_IP': 'IP is not valid. Please enter a valid IP address.',
    'EMPTY_GET_WHOIS_ARGUMENT': 'query argument should not be empty.',
    'INVALID_VALUE_IN_HISTORY_ARG': 'Invalid history value {}. Valid history values are true, false.',
    'INVALID_WHOLE_NUMBER': 'Argument {} should be 0 or a positive integer.',
    'INVALID_SINGLE_SELECT': 'Invalid argument {}. Valid values are {}.',
    'INVALID_QUERY_COOKIE_DOMAIN': 'Argument query should be a valid domain that '
                                   'does not contain any special characters other than hyphen (-) and full stop (.)',
    'INVALID_QUERY_COOKIE_NAME': 'Argument query should be a valid cookie name that does not contain '
                                 'spaces, separator character or tabs.',
    "REQUIRED_ARGUMENT": "Invalid argument value. {} is a required argument.",
    "EMPTY_IP_ARGUMENT": "IP(s) not specified",
    "INVALID_IP_ARGUMENT": "Invalid IP - {}",
    'INVALID_INDICATOR_TYPE': 'Invalid indicator type {}. Valid values are certficate_sha1, certificate_sha1, domain, '
                              'email, hash_md5, hash_sha256, ip, pdb_path, soa_email, url, whois_email.',
    'INVALID_SOURCE': 'Invalid indicator source {}. Valid values are osint, riskiq.',
    'INVALID_PAGE_SIZE': '{} is an invalid value for page size. Page size must be between 1 and int32.',
    'INVALID_PAGE_NUMBER': '{} is an invalid value for page number. Page number must be between 0 and int32.',
    "INVALID_PROFILE_TYPE": "Invalid profile type {}. Valid profile types are actor, backdoor, tool.",
    "REQUIRED_INDICATOR_VALUE": "'indicator_value' must be specified if the arguments 'source' or 'category' are used.",
    "INVALID_PRIORITY_LEVEL": "Invalid priority level {}. Valid priority level are low, medium, high.",
    "NOT_VALID_PAGE_SIZE": "{} is an invalid value for page size. Page size must be between 1 and 1000."
}

URL_SUFFIX: Dict[str, str] = {
    'TEST_MODULE': '/v2/account',
    'SSL_CERT_SEARCH': '/v2/ssl-certificate/search',
    'GET_PDNS_DETAILS': '/v2/dns/passive',
    'WHOIS_SEARCH': '/v2/whois/search',
    'WHOIS_GET': '/v2/whois',
    'GET_COMPONENTS': '/v2/host-attributes/components',
    'GET_TRACKERS': '/v2/host-attributes/trackers',
    'GET_ARTICLES': '/v2/articles/indicator',
    'GET_HOST_PAIRS': '/v2/host-attributes/pairs',
    'GET_SERVICES': '/v2/services',
    "GET_ADDRESSES_BY_COOKIE_NAME": "v2/cookies/name/{0}/addresses",
    "GET_ADDRESSES_BY_COOKIE_DOMAIN": "v2/cookies/domain/{0}/addresses",
    "GET_HOSTS_BY_COOKIE_NAME": "v2/cookies/name/{0}/hosts",
    "GET_HOSTS_BY_COOKIE_DOMAIN": "v2/cookies/domain/{0}/hosts",
    "GET_DATA_CARD_SUMMARY": "v2/cards/summary",
    "GET_REPUTATION": "v2/reputation",
    "LIST_INTEL_PROFILE_INDICATOR": "v2/intel-profiles/{}/indicators",
    "LIST_INTEL_PROFILE": "v2/intel-profiles",
    "LIST_INTEL_PROFILE_BY_INDICATOR": "v2/intel-profiles/indicator",
    "LIST_ASI_INSIGHTS": "/v2/attack-surface/priority",
    "LIST_ATTACK_SURFACE": "v2/attack-surface",
    "LIST_THIRD_PARTY_ASI": "v2/attack-surface/third-party",
    "LIST_ASI_ASSETS": "v2/attack-surface/insight",
    "THIRD_PARTY_ASI_INSIGHTS": "v2/attack-surface/third-party/{}/priority/{}",
    "LIST_ASI_VULNERABLE_COMPONENTS": "v2/attack-surface/vuln-intel/components",
    "LIST_ASI_VULNERABILITIES": "v2/attack-surface/vuln-intel/cves",
    "LIST_ASI_OBSERVATIONS": "v2/attack-surface/vuln-intel/cves/{}/observations",
    "LIST_THIRD_PARTY_ASI_ASSETS": "v2/attack-surface/third-party/{}/insight/{}",
    "LIST_THIRD_PARTY_ASI_VULNERABLE_COMPONENTS": "v2/attack-surface/vuln-intel/third-party/{}/components",
    "LIST_THIRD_PARTY_ASI_VULNERABILITIES": "v2/attack-surface/vuln-intel/third-party/{}/cves",
    "LIST_THIRD_PARTY_ASI_OBSERVATIONS": "v2/attack-surface/vuln-intel/third-party/{}/cves/{}/observations"
}

ISO_DATE: Dict[str, str] = {
    DATE_TIME_FORMAT: '"yyyy-mm-dd hh:mm:ss"',
    DATE_FORMAT: '"yyyy-mm-dd"'
}

VALID_DIRECTION_FOR_HOST_PAIRS = ['children', 'parents']

REQUEST_TIMEOUT_MAX_VALUE = 9223372036

COMPANY_NAME = "PaloAltoNetworks"

PRODUCT_NAME = "XSOAR"

INDICATOR_TYPE = ['certficate_sha1', 'certificate_sha1', 'domain', 'email', 'hash_md5', 'hash_sha256', 'ip',
                  'pdb_path', 'soa_email', 'url', 'whois_email']

PRIORITY = ["high", "medium", "low"]

UI_LINK = "https://community.riskiq.com/attack-surfaces/"


class Client(BaseClient):
    """
    Client to use in integration with powerful http_request.
    It extends the base client and uses the http_request method for the API request.
    Handle some exceptions externally.
    """

    def __init__(self, base_url, request_timeout, verify, proxy, auth):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, auth=auth)
        self.request_timeout = request_timeout

    def http_request(self, method: str, url_suffix: str, json_data=None, params=None, headers=None) -> Dict[str, Any]:
        """
            Override http_request method from BaseClient class. This method will print an error based on status code
            and exceptions.

        :type method: ``str``
        :param method: The HTTP method, for example: GET, POST, and so on.

        :type url_suffix: ``str``
        :param url_suffix: The API endpoint.

        :type json_data: ``dict``
        :param json_data: The dictionary to send in a 'POST' request.

        :type params: ``dict``
        :param params: URL parameters to specify the query.

        :type headers: ``dict``
        :param headers: Headers to send in the request. If None, will use self._headers.

        :return: Depends on the resp_type parameter
        :rtype: ``dict`` or ``str`` or ``requests.Response``
        """
        try:
            if not headers:
                headers = {}
            headers['X-RISKIQ'] = f"{COMPANY_NAME}-{PRODUCT_NAME}-{get_demisto_version_as_str()}"

            resp = self._http_request(method=method, url_suffix=url_suffix, json_data=json_data, params=params,
                                      headers=headers, timeout=self.request_timeout, resp_type='response',
                                      ok_codes=(200, 400, 401, 404, 407, 500), proxies=handle_proxy())
        except MissingSchema:
            raise ValueError(MESSAGES['MISSING_SCHEMA_ERROR'])
        except InvalidSchema:
            raise ValueError(MESSAGES['INVALID_SCHEMA_ERROR'])
        except DemistoException as e:
            if 'Proxy Error' in str(e):
                raise ConnectionError(MESSAGES['PROXY_ERROR'])
            elif 'ConnectionError' in str(e) or 'ConnectTimeout' in str(e):
                raise ConnectionError(MESSAGES['CONNECTION_ERROR'])
            else:
                raise e

        # Providing errors based on status code
        status_code = resp.status_code

        if status_code != 200:
            error_message = ''
            if resp.json().get('message', ''):
                error_message = 'Reason: {}'.format(resp.json().get('message', ''))
            status_code_message_map = {
                400: '{} {}'.format(MESSAGES['BAD_REQUEST_ERROR'], error_message),
                401: MESSAGES['AUTHENTICATION_ERROR'],
                404: MESSAGES['PAGE_NOT_FOUND_ERROR'],
                407: MESSAGES['PROXY_ERROR']
            }
            if status_code in status_code_message_map:
                demisto.info('Response code: {}. Reason: {}'.format(status_code, status_code_message_map[status_code]))
                raise ValueError(status_code_message_map[status_code])
            elif status_code >= 500:
                demisto.info('Response code: {}. Reason: {}'.format(status_code, MESSAGES['INTERNAL_SERVER_ERROR']))
                raise ValueError(MESSAGES['INTERNAL_SERVER_ERROR'])
            else:
                resp.raise_for_status()

        return resp.json()


''' HELPER FUNCTIONS '''


def get_request_timeout() -> Optional[Any]:
    """
    Validate and return the request timeout parameter.
    The parameter must be a positive integer.
    Default value is set to 20 seconds for API request timeout.

    :params req_timeout: Request timeout value.
    :return: boolean
    """
    try:
        request_timeout = demisto.params().get('request_timeout', DEFAULT_REQUEST_TIMEOUT)
        request_timeout = DEFAULT_REQUEST_TIMEOUT if not request_timeout else request_timeout
        request_timeout = int(request_timeout)
    except ValueError:
        raise ValueError(MESSAGES['REQUEST_TIMEOUT_VALIDATION'])

    if request_timeout <= 0:
        raise ValueError(MESSAGES['REQUEST_TIMEOUT_VALIDATION'])
    elif request_timeout > REQUEST_TIMEOUT_MAX_VALUE:
        raise ValueError(MESSAGES['REQUEST_TIMEOUT_EXCEED_ERROR'])

    return request_timeout


def remove_empty_elements_for_context(src):
    """
     Recursively remove empty lists, empty dicts, empty string or None elements from a dictionary.

    :type src: ``dict``
    :param src: Input dictionary.

    :return: Dictionary with all empty lists,empty string and empty dictionaries removed.
    :rtype: ``dict``
    """

    def empty(x):
        return x is None or x == '' or x == {} or x == []

    if not isinstance(src, (dict, list)):
        return src
    elif isinstance(src, list):
        return [v for v in (remove_empty_elements_for_context(v) for v in src) if not empty(v)]
    else:
        return {k: v for k, v in ((k, remove_empty_elements_for_context(v))
                                  for k, v in src.items()) if not empty(v)}


def get_host_attribute_context_data(records: List[Dict[str, Any]]) -> Tuple[list, list]:
    """
    Prepares context data for get components and get trackers command

    :param records: API response
    :return: standard entry command results list and custom entry context
    """
    custom_ec = createContext(data=records, removeNull=True)
    standard_results: List[CommandResults] = []
    for record in records:
        if record.get('hostname'):
            hostname = record.get('hostname')
            dbot_score = Common.DBotScore(indicator=hostname, indicator_type=DBotScoreType.DOMAIN,
                                          integration_name=INTEGRATION_NAME, score=Common.DBotScore.NONE)
            if auto_detect_indicator_type(hostname) == FeedIndicatorType.Domain:
                domain_ioc = Common.Domain(domain=hostname, dbot_score=dbot_score)
                # add standard output with standard readable output
                standard_results.append(CommandResults(
                    indicator=domain_ioc,
                    readable_output=tableToMarkdown('', domain_ioc.to_context().get(Common.Domain.CONTEXT_PATH))
                ))
        elif record.get('address'):
            address = record.get('address')
            dbot_score = Common.DBotScore(indicator=address, indicator_type=DBotScoreType.IP,
                                          integration_name=INTEGRATION_NAME, score=Common.DBotScore.NONE)
            if auto_detect_indicator_type(address) == FeedIndicatorType.IP:
                ip_ioc = Common.IP(ip=address, dbot_score=dbot_score)
                # add standard output with standard readable output
                standard_results.append(CommandResults(
                    indicator=ip_ioc,
                    readable_output=tableToMarkdown('', ip_ioc.to_context().get(Common.IP.CONTEXT_PATH))
                ))

    return standard_results, custom_ec


def get_components_hr(components: List[Dict[str, Any]]) -> str:
    """
    Prepares human readable text for get components command

    :param components: Components data response
    :return: Human readable output for components
    """

    hr_table: List[Dict[str, Any]] = []

    for component in components:
        hr_row = {
            'Hostname': component.get('hostname', ''),
            'Address': component.get('address', ''),
            'First (GMT)': component.get('firstSeen', ''),
            'Last (GMT)': component.get('lastSeen', ''),
            'Category': component.get('category', ''),
            'Value': component.get('label', ''),
            'Version': component.get('version', ''),
        }
        hr_table.append(hr_row)

    hr_headers = ['Hostname', 'Address', 'First (GMT)', 'Last (GMT)', 'Category', 'Value', 'Version']
    hr = '### Total Retrieved Record(s): {0}\n'.format(len(components))
    return hr + tableToMarkdown('COMPONENTS', hr_table, hr_headers, removeNull=True)


def get_trackers_hr(trackers: List[Dict[str, Any]]) -> str:
    """
    Prepares human readable text for get trackers command

    :param trackers: Trackers data response
    :return: Human readable output for trackers
    """

    hr_table: List[Dict[str, Any]] = []

    for tracker in trackers:
        hr_row = {
            'Hostname': tracker.get('hostname', ''),
            'Address': tracker.get('address', ''),
            'First (GMT)': tracker.get('firstSeen', ''),
            'Last (GMT)': tracker.get('lastSeen', ''),
            'Type': tracker.get('attributeType', ''),
            'Value': tracker.get('attributeValue', '')
        }
        hr_table.append(hr_row)

    hr_headers = ['Hostname', 'Address', 'First (GMT)', 'Last (GMT)', 'Type', 'Value']
    hr = '### Total Retrieved Record(s): {0}\n'.format(len(trackers))
    return hr + tableToMarkdown('TRACKERS', hr_table, hr_headers, removeNull=True)


def get_host_pairs_hr(host_pairs: List[Dict[str, Any]]) -> str:
    """
    Prepares human readable text for get host pairs command

    :param host_pairs: Host pairs data response
    :return: Human readable output for host pairs
    """

    hr_table: List[Dict[str, Any]] = []

    for pair in host_pairs:
        hr_row = {
            'Parent Hostname': pair.get('parent', ''),
            'Child Hostname': pair.get('child', ''),
            'First (GMT)': pair.get('firstSeen', ''),
            'Last (GMT)': pair.get('lastSeen', ''),
            'Cause': pair.get('cause', '')
        }
        hr_table.append(hr_row)

    hr_headers = ['Parent Hostname', 'Child Hostname', 'First (GMT)', 'Last (GMT)', 'Cause']
    hr = '### Total Retrieved Record(s): {0}\n'.format(len(host_pairs))
    return hr + tableToMarkdown('HOST PAIRS', hr_table, hr_headers, removeNull=True)


def get_common_arguments(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validates the common arguments and prepares parameter dictionary
    This method is used in commands "get-trackers", "get-components", "get-host-pairs"

    :param args: The general arguments
    :return: dict of params or message describing error in argument validation
    """
    params: Dict[str, Any] = {}

    if not args.get('query'):
        raise ValueError(MESSAGES['INVALID_QUERY_VALUE'])
    params['query'] = args.get('query')

    date_arguments = ['start', 'end']
    for argument in date_arguments:
        if args.get(argument):
            params[argument] = args.get(argument, '')

    return params


def get_valid_whois_search_arguments(args: Dict[str, Any]) -> Tuple[str, str]:
    """
    Get and Validate arguments for pt-whois-search command.

    :param args: it contain arguments of pt-whois-search command
    :return: validated arguments 'query' and 'field'
    """
    query = args.get('query', '')
    field = args.get('field', '')
    if query.strip() == '' or field.strip() == '':
        raise ValueError(MESSAGES['EMPTY_WHOIS_ARGUMENT'])
    if field not in ('domain', 'email', 'name', 'organization', 'address', 'phone', 'nameserver'):
        raise ValueError(MESSAGES['INVALID_VALUE_IN_FIELD_ARG'].format(field))
    return query, field


def get_valid_get_whois_arguments(args: Dict[str, Any]) -> Tuple[str, str]:
    """
    Get and Validate arguments for pt-get-whois command.

    :param args: it contain arguments of pt-get-whois command
    :return: validated arguments 'query' and 'history'
    """
    query = args.get('query', '').strip()
    arg_history = args.get('history', '').strip()
    history = arg_history.lower()
    if query == '':
        raise ValueError(MESSAGES['EMPTY_GET_WHOIS_ARGUMENT'])
    if history and history not in ('true', 'false'):
        raise ValueError(MESSAGES['INVALID_VALUE_IN_HISTORY_ARG'].format(arg_history))
    return query, history


def nested_to_flat(src: Dict[str, Any], key: str) -> Dict[str, Any]:
    """
    Convert nested dictionary to flat by contact the keys. Also converts keys in pascal string format.

    :param src: sub-dictionary that needs to convert from nested to flat. (e.g. "foo": {"bar": "some-value"})
    :param key: main key of sub-dictionary (e.g "foo")
    :return: flat dictionary with pascal formatted keys (e.g. {"FooBar": "some-value"})
    """

    flat_dict: Dict[str, str] = {}
    for sub_key, sub_value in src.items():
        pascal_key = '{}{}'.format(key, sub_key[0].upper() + sub_key[1:])
        flat_dict[pascal_key] = sub_value

    return flat_dict


def prepare_context_dict(response_dict: Dict[str, Any],
                         keys_with_hierarchy: tuple = (),
                         exclude_keys: tuple = ()) -> Dict[str, str]:
    """
    Prepare the context dictionary as per the standards.

    :param response_dict: dictionary getting from API response that contains sub-dictionaries
    :param keys_with_hierarchy: list of keys that contains sub-dictionary as its value.
    :param exclude_keys: keys need to exclude.
    :return: single level dictionary
    """
    simple_dict: Dict[str, str] = {}
    for key, value in response_dict.items():
        if key in keys_with_hierarchy:
            simple_dict.update(nested_to_flat(response_dict.get(key, {}), key))
        elif key not in exclude_keys:
            simple_dict[key] = value
    return simple_dict


def get_context_for_whois_commands(domains: List[Dict[str, Any]], score=0) -> Tuple[list, list]:
    """
    Prepare context for whois and domain reputation commands.

    :param domains: list of domains return from response
    :param score:
    :return: command results for standard context and custom context for whois and domain reputation command
    """
    command_results: List[CommandResults] = []
    custom_context: List[Dict[str, Any]] = []
    # set domain standard context
    for domain in domains:
        # set domain standard context
        if auto_detect_indicator_type(domain.get('domain', '')) == FeedIndicatorType.Domain:
            standard_context_domain = Common.Domain(
                domain=domain.get('domain', ''),
                creation_date=domain.get('registered', ''),
                updated_date=domain.get('registryUpdatedAt', ''),
                expiration_date=domain.get('expiresAt', ''),
                name_servers=domain.get('nameServers', ''),
                organization=domain.get('organization', ''),
                admin_name=domain.get('admin', {}).get('name', ''),
                admin_email=domain.get('admin', {}).get('email', ''),
                admin_phone=domain.get('admin', {}).get('telephone', ''),
                admin_country=domain.get('admin', {}).get('country', ''),
                registrar_name=domain.get('registrar', ''),
                registrant_email=domain.get('registrant', {}).get('email', ''),
                registrant_name=domain.get('registrant', {}).get('name', ''),
                registrant_phone=domain.get('registrant', {}).get('telephone', ''),
                registrant_country=domain.get('registrant', {}).get('country', ''),
                dbot_score=Common.DBotScore(
                    indicator=domain.get('domain', ''),
                    indicator_type=DBotScoreType.DOMAIN,
                    integration_name=INTEGRATION_NAME,
                    score=score
                )
            )
            # add standard output with standard readable output
            command_results.append(CommandResults(
                indicator=standard_context_domain,
                readable_output=tableToMarkdown('',
                                                standard_context_domain.to_context().get(Common.Domain.CONTEXT_PATH))
            ))

        # set custom context for whois commands
        custom_context.append(
            prepare_context_dict(
                response_dict=domain,
                keys_with_hierarchy=('registrant', 'admin', 'billing', 'tech'),
                exclude_keys=('zone', 'rawText')
            )
        )
    return command_results, createContext(custom_context, removeNull=True)


def get_context_for_get_whois_commands(domains: List[Dict[str, Any]]) -> list:
    """
    Prepare context for pt-get-whois command.

    :param domains: list of domains return from response
    :return: command results for custom context for whois command
    """
    custom_context: List[Dict[str, Any]] = []
    # set domain standard context
    for domain in domains:
        custom_context.append(
            prepare_context_dict(
                response_dict=domain,
                keys_with_hierarchy=('registrant', 'admin', 'billing', 'tech'),
                exclude_keys=('zone', 'rawText')
            )
        )
    return createContext(custom_context, removeNull=True)


def prepare_hr_cell_for_whois_info(domain_info: Dict[str, Any]) -> str:
    """
    Prepare cell information for Registrant, Admin, Billing and Tech columns.

    :param domain_info: domain information as a directory
    :return: domain information as a readable format
    """
    hr_cell_info: List[str] = []
    for key, value in domain_info.items():
        hr_cell_info.append('**{}:** {}'.format(key[0].upper() + key[1:], value))
    return ',\n'.join(hr_cell_info)


def get_human_readable_for_whois_commands(domains: List[Dict[str, Any]], is_reputation_command=False):
    """
    Prepare readable output for whois commands

    :param domains: list of domains return from response
    :param is_reputation_command: true if the command is execute for reputation command else false, default is false
    :return: markdown of whois commands based on domains passed
    """
    hr_table_content: List[Dict[str, Any]] = []
    table_name = 'Domain(s)'
    for domain in domains:
        hr_row = {
            'Domain': domain.get('domain', ''),
            'WHOIS Server': domain.get('whoisServer', ''),
            'Registrar': domain.get('registrar', ''),
            'Contact Email': domain.get('contactEmail', ''),
            'Name Servers': ', '.join(domain.get('nameServers', [])),
            'Creation Date (GMT)': domain.get('registered', ''),
            'Expire Date (GMT)': domain.get('expiresAt', ''),
            'Updated Date (GMT)': domain.get('registryUpdatedAt', ''),
            'Last Scanned (GMT)': domain.get('lastLoadedAt', ''),
            'Registrant': prepare_hr_cell_for_whois_info(domain.get('registrant', {})),
            'Admin': prepare_hr_cell_for_whois_info(domain.get('admin', {})),
            'Billing': prepare_hr_cell_for_whois_info(domain.get('billing', {})),
            'Tech': prepare_hr_cell_for_whois_info(domain.get('tech', {}))
        }
        hr_table_content.append(hr_row)

    hr = ''
    if not is_reputation_command:
        hr += '### Total Retrieved Record(s): ' + str(len(domains)) + '\n'
        table_name = 'Associated Domains'
    hr += tableToMarkdown(
        name=table_name,
        t=hr_table_content,
        headers=['Domain', 'WHOIS Server', 'Registrar', 'Contact Email', 'Name Servers', 'Registrant', 'Admin',
                 'Billing', 'Tech', 'Creation Date (GMT)', 'Expire Date (GMT)', 'Updated Date (GMT)',
                 'Last Scanned (GMT)'],
        removeNull=True
    )
    return hr


def get_human_readable_for_articles_commands(articles: List[Dict[str, Any]]):
    """
    Prepare readable output for pt-get-articles command

    :param articles: list of articles return from response
    :return: markdown of article command based on articles passed
    """
    hr_table_content: List[Dict[str, Any]] = []
    table_name = 'Article(s)'
    for article in articles:
        hr_row = {
            'GUID': article.get('guid', ''),
            'Title': article.get('title', ''),
            'Summary': article.get('summary', ''),
            'Type': article.get('type', ''),
            'Tags': ', '.join(article.get('tags', [])) if article.get('tags', []) else '',
            'Categories': ', '.join(article.get('categories', [])) if article.get('categories', []) else '',
            'Article Link': article.get('link', ''),
            'Published Date (GMT)': article.get('publishedDate', '')
        }
        hr_table_content.append(hr_row)

    hr = '### Total Retrieved Record(s): ' + str(len(articles)) + '\n'
    hr += tableToMarkdown(
        name=table_name,
        t=hr_table_content,
        headers=['GUID', 'Title', 'Summary', 'Type', 'Tags', 'Categories', 'Article Link', 'Published Date (GMT)'],
        removeNull=True
    )
    return hr


def get_human_readable_for_data_card_command(results: Dict[str, Any]) -> str:
    """
        Parse and convert the Data Card Summary in the response into human-readable markdown string.

        :type results: ``List[Dict[str, Any]]``
        :param results: Details of urls.

        :return: Human Readable string containing information of data card.
        :rtype: ``str``
        """
    hr_table_content: List[Dict[str, Any]] = []
    summary = results.get('data_summary', {})
    summary = {pascalToSpace(underscoreToCamelCase(k)): v for k, v in summary.items()}

    hr_row = {
        'Name': results.get('name', ''),
        'Type': results.get('type', ''),
        'Netblock': results.get('netblock', ''),
        'Autonomous System Number': results.get('asn', ''),
        'Host Provider': results.get('hosting_provider', ''),
        'Operating System': results.get('os', ''),
        'Data Card Summary': get_data_card_summary(summary)

    }
    hr_table_content.append(hr_row)

    return tableToMarkdown("Data Card Summary", hr_table_content,
                           headers=["Name", "Type", "Netblock", "Autonomous System Number", "Host Provider",
                                    "Operating System", "Data Card Summary"], removeNull=True)


def get_human_readable_for_reputation_command(results: Dict[str, Any], query: str) -> str:
    """
        Parse and convert the response into human-readable markdown string.

        :type results: ``List[Dict[str, Any]]``
        :param results: Details of urls.

        :type query: ``str``
        :param query: Value of the indicator.

        :return: Human Readable string containing information.
        :rtype: ``str``
        """
    classification = results.get('classification', '')

    reputation_score = results.get('score', '')

    reputation_message = f"The reputation score for '{query}' is {reputation_score} and is classified as '{classification}'.\n"

    hr_table_content: List[Dict[str, Any]] = []

    rules = results.get('rules', [])
    for rule in rules:
        link = rule.get('link')
        if link:
            name = f"[{rule.get('name', '')}]({rule.get('link')})"
        else:
            name = rule.get('name', '')
        hr_row = {
            'Name': name,
            'Description': rule.get('description', ''),
            'Severity': rule.get('severity', '')

        }
        hr_table_content.append(hr_row)
    hr_table = tableToMarkdown("Reputation Rules", hr_table_content, headers=['Name', 'Description', 'Severity'])

    return reputation_message + hr_table


def prepare_human_readable_dict_for_ssl(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Preparing human-readable dictionary for ssl certificate command.

    :param results: ssl certificates details
    :return: human-readable dict
    """
    return [{
        'First (GMT)': epochToTimestamp(result.get('firstSeen', '')) if result.get('firstSeen') else None,
        'Last (GMT)': epochToTimestamp(result.get('lastSeen', '')) if result.get('lastSeen') else None,
        'SSL Version': result.get('sslVersion', 0),
        'Expires (GMT)': result.get('expirationDate', ''),
        'Issued (GMT)': result.get('issueDate', ''),
        'Sha1': result.get('sha1', ''),
        'Serial Number': result.get('serialNumber', ''),
        'Subject Country': result.get('subjectCountry', ''),
        'Issuer Common Name': result.get('issuerCommonName', ''),
        'Issuer Province': result.get('issuerProvince', ''),
        'Subject State/Province Name': result.get('subjectStateOrProvinceName', ''),
        'Subject Street Address': result.get('subjectStreetAddress', ''),
        'Issuer State/Province Name': result.get('issuerStateOrProvinceName', ''),
        'Issuer Country': result.get('issuerCountry', ''),
        'Subject Locality Name': result.get('subjectLocalityName', ''),
        'Subject Alternative Names': ', '.join(result.get('subjectAlternativeNames', [])),
        'Issuer Organization Unit Name': result.get('issuerOrganizationUnitName', ''),
        'Issuer Organization Name': result.get('issuerOrganizationName', ''),
        'Subject Organization Name': result.get('subjectOrganizationName', ''),
        'Issuer Locality Name': result.get('issuerLocalityName', ''),
        'Subject Common Name': result.get('subjectCommonName', ''),
        'Subject Province': result.get('subjectProvince', ''),
        'Subject Organization Unit Name': result.get('subjectOrganizationUnitName', ''),
        'Issuer Street Address': result.get('issuerStreetAddress', '')
    } for result in results]


def prepare_human_readable_dict_for_pdns(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Prepare human-readable dictionary for passive DNS command.

    :param results: passive DNS details.
    :return: human-readable dict
    """
    return [{
        'First (GMT)': result.get('firstSeen', ''),
        'Last (GMT)': result.get('lastSeen', ''),
        'Source': ', '.join(result.get('source', [])),
        'Value': result.get('value', ''),
        'Collected (GMT)': result.get('collected', ''),
        'Record Type': result.get('recordType', ''),
        'Resolve': result.get('resolve', ''),
        'Resolve Type': result.get('resolveType', ''),
        'Record Hash': result.get('recordHash', '')
    } for result in results]


def get_ssl_cert_search_hr(results: List[Dict[str, Any]]) -> str:
    """
    Retrieved information of ssl certificates and convert it into human-readable markdown string.

    :param results: ssl certificates details
    :return: human-readable string
    """
    ssl_cert_search_hr: List[Dict[str, Any]] = prepare_human_readable_dict_for_ssl(results)

    hr = '### Total Retrieved Record(s): ' + str(len(results)) + '\n'
    hr += tableToMarkdown('SSL certificate(s)', ssl_cert_search_hr,
                          ['Sha1', 'Serial Number', 'Issued (GMT)', 'Expires (GMT)', 'SSL Version', 'First (GMT)',
                           'Last (GMT)', 'Issuer Common Name', 'Subject Common Name', 'Subject Alternative Names',
                           'Issuer Organization Name', 'Subject Organization Name', 'Issuer Locality Name',
                           'Subject Locality Name', 'Issuer State/Province Name', 'Subject State/Province Name',
                           'Issuer Country', 'Subject Country', 'Issuer Street Address', 'Subject Street Address',
                           'Issuer Organization Unit Name', 'Subject Organization Unit Name'], removeNull=True)

    return hr


def get_pdns_details_hr(results: List[Dict[str, Any]], total_record: int) -> str:
    """
    Retrieved information of passive DNS and convert it into human-readable markdown string.

    :param results: passive DNS details
    :param total_record: number of record retrieved from response
    :return: human-readable string
    """
    pdns_details_hr: List[Dict[str, Any]] = prepare_human_readable_dict_for_pdns(results)

    table_headers = ['Resolve', 'Resolve Type', 'Record Type', 'Collected (GMT)', 'First (GMT)', 'Last (GMT)',
                     'Source', 'Record Hash']
    hr = '### Total Retrieved Record(s): ' + str(total_record) + '\n'
    hr += tableToMarkdown('PDNS detail(s)', pdns_details_hr, table_headers, removeNull=True)
    return hr


def create_pdns_standard_context(results: List[Dict[str, Any]]) -> List[CommandResults]:
    """
    Preparing standard context and dbotScore for pdns command.
    here, standard context includes ip and domain model.

    :param results: pdns details from response
    :return: list of CommandResults of standard context
    """
    standard_results: List[CommandResults] = []
    for result in results:
        resolve_type = result.get('resolveType', '')
        resolve = result.get('resolve', '')

        if 'domain' == resolve_type:
            dbot_score = Common.DBotScore(resolve, resolve_type, INTEGRATION_NAME, Common.DBotScore.NONE)
            if auto_detect_indicator_type(resolve) == FeedIndicatorType.Domain:
                domain_ioc = Common.Domain(resolve, dbot_score)
                # add standard output with standard readable output
                standard_results.append(CommandResults(
                    indicator=domain_ioc,
                    readable_output=tableToMarkdown('', domain_ioc.to_context().get(Common.Domain.CONTEXT_PATH))
                ))
        elif 'ip' == resolve_type:
            dbot_score = Common.DBotScore(resolve, resolve_type, INTEGRATION_NAME, Common.DBotScore.NONE)
            if auto_detect_indicator_type(resolve) == FeedIndicatorType.IP:
                ip_ioc = Common.IP(resolve, dbot_score)
                # add standard output with standard readable output
                standard_results.append(CommandResults(
                    indicator=ip_ioc,
                    readable_output=tableToMarkdown('', ip_ioc.to_context().get(Common.IP.CONTEXT_PATH))
                ))

    return standard_results


def get_services_hr(total_records: int, results: list) -> str:
    services_hr = []
    for result in results:
        current_services = result.get("currentServices", [])
        labels = []
        for services in current_services:
            if services.get("label"):
                labels.append(services.get("label"))

        services_hr.append({
            "Port Number": result.get("portNumber"),
            "Protocol": result.get("protocol"),
            "Status": result.get("status"),
            "Current Service Labels": ", ".join(labels),
            "First Seen Date (GMT)": result.get("firstSeen"),
            "Last Seen Date (GMT)": result.get("lastSeen"),
            "Last Scanned Date (GMT)": result.get("lastScan")
        })

    table_output = tableToMarkdown("Services", services_hr,
                                   headers=["Port Number", "Protocol", "Status", "Current Service Labels",
                                            "First Seen Date (GMT)", "Last Seen Date (GMT)", "Last Scanned Date (GMT)"],
                                   removeNull=True)

    return f"### Total Retrieved Record(s) {total_records} \n {table_output}"


def validate_get_cookies_arguments(args: Dict[str, Any]) -> None:
    """
    Validate arguments for get cookies command, raise ValueError on invalid arguments.

    :param args: stripped arguments provided by user
    """

    # check if page is a valid whole number
    try:
        if int(args.get("page", "0")) < 0:
            raise ValueError
    except ValueError:
        raise ValueError(MESSAGES['INVALID_WHOLE_NUMBER'].format('page'))

    # check if the single-select values of arguments are valid or not
    valid_values = {
        'search_by': [
            'get addresses by cookie domain',
            'get addresses by cookie name',
            'get hosts by cookie domain',
            'get hosts by cookie name'
        ],
        'order': [
            'desc',
            'asc'
        ],
        'sort': [
            'first seen',
            'last seen'
        ]
    }
    for argument_name, valid_value in valid_values.items():
        if args.get(argument_name) not in valid_value:
            raise ValueError(MESSAGES['INVALID_SINGLE_SELECT'].format(argument_name, ",".join(valid_value)))

    # validate query param based on search_by
    if "domain" in args['search_by']:
        # The domain should only contain the characters a-z, A-Z, hyphen (-) and fullstops (.).
        if not args["query"] or re.search("[^a-zA-Z0-9.-]", args['query']):
            raise ValueError(MESSAGES['INVALID_QUERY_COOKIE_DOMAIN'])
    else:
        """ Valid cookie name can be any US-ASCII characters,
            except control characters, spaces, separator character or tabs."""
        if not args["query"] or re.search(r'[?^()<>@,;:/="\[\]{}\\\t\n\s]', args["query"]):
            raise ValueError(MESSAGES['INVALID_QUERY_COOKIE_NAME'])


def get_cookies_hr(results: List[Dict[str, Any]], hostname_header: str, total_records: int):
    """
    Retrieved information of cookies and convert it into human-readable markdown string.

    :param results: cookie details
    :param hostname_header: The header for the hostname column, should be either 'Hostname' or 'IP Address'
    :param total_records: Total number of available records
    :return: human-readable string
    """
    hr_results = [{
        hostname_header: result.get("hostname", ''),
        'Cookie Name': result.get("cookieName", ''),
        'Cookie Domain': result.get("cookieDomain", ''),
        'First Seen Date (GMT)': result.get("firstSeen", ''),
        'Last Seen Date (GMT)': result.get("lastSeen", '')
    } for result in results]

    table_headers = [hostname_header, 'Cookie Name', 'Cookie Domain', 'First Seen Date (GMT)', 'Last Seen Date (GMT)']

    hr = '### Total Record(s): ' + str(total_records) + '\n'
    hr += '### Total Retrieved Record(s): ' + str(len(hr_results)) + '\n'
    hr += tableToMarkdown('Cookies', hr_results, table_headers, removeNull=True)
    return hr


def calculate_dbot_score(classification: str) -> int:
    """
    Calculate te dbot score according to the classification provided
    :param classification: The classification received from he api response
    :return: Dbot Score
    """
    if classification == "UNKNOWN":
        score = Common.DBotScore.NONE  # unknown
    elif classification == "MALICIOUS":
        score = Common.DBotScore.BAD  # bad
    elif classification == "SUSPICIOUS":
        score = Common.DBotScore.SUSPICIOUS  # suspicious
    else:
        score = Common.DBotScore.GOOD  # good
    return score


def get_standard_context(score: int, ip: str) -> Common.IP:
    """
    Prepare standard context for ip reputation command
    :param score: The Dbot score
    :param ip: IP Address
    :return: IP indicator object
    """
    dbot_score = Common.DBotScore(
        indicator=ip,
        integration_name='PassiveTotal',
        indicator_type=DBotScoreType.IP,
        score=score
    )
    return Common.IP(
        ip=ip,
        dbot_score=dbot_score
    )


def get_data_card_summary(summary: dict) -> str:
    """
    Prepare data card summary
    :param summary: data card summary response
    :return: human readable string
    """
    data_card_summary = ""
    for key, value in summary.items():
        if value.get("count") == 0:
            data_card_summary += "{}: {}, ".format(key, value.get("count"))
        else:
            data_card_summary += "{}: [{}]({}), ".format(key, value.get("count"), value.get("link"))

    return data_card_summary[:-2]


def validate_list_intel_profile_args(args: Dict[str, str]) -> Tuple[Dict[str, Any], int]:
    """
    Validate arguments for pt-list-intel-profiles, raise ValueError on invalid arguments.

    :param args: The command arguments provided by the user.
    :return: Parameters to send in request

    """
    params: Dict[str, Any] = {}
    query = args.get('query', '')
    if query:
        params["query"] = query

    profile_type = args.get('type', '').lower()
    if profile_type:
        if profile_type not in PROFILE_TYPE:
            raise ValueError(MESSAGES["INVALID_PROFILE_TYPE"].format(profile_type))
        params["type"] = profile_type

    indicator_value = args.get("indicator_value", "")
    if indicator_value:
        params["query"] = indicator_value

    source = args.get('source', '').lower()
    if source:
        if not indicator_value:
            raise ValueError(MESSAGES["REQUIRED_INDICATOR_VALUE"])
        if source not in SOURCE:
            raise ValueError(MESSAGES["INVALID_SOURCE"].format(source))
        params["sources"] = source

    category = args.get('category', '').lower()
    if category:
        if not indicator_value:
            raise ValueError(MESSAGES["REQUIRED_INDICATOR_VALUE"])
        params["categories"] = category

    page_size = validate_page_size_args(args)

    return params, page_size


def get_human_readable_for_intel_profile_command(results: List[Dict[str, Any]]) -> str:
    """
    Parse and convert the response into human-readable markdown string.

    :param results: Details of profiles.
    :return: Human Readable string containing information.
    """
    hr_list = []
    for profile in results:
        hr_record = {
            'ID': profile.get('id', ''),
            'Title': profile.get('title', ''),
            'Aliases': ", ".join("{}".format(i) for i in profile.get("aliases", [])),
            'Public Indicators': profile.get('osintIndicatorsCount', ''),
            'RiskIQ Indicators': profile.get('riskIqIndicatorsCount', '')
        }

        hr_list.append(hr_record)

    return tableToMarkdown('Profile(s)', hr_list, ['ID', 'Title', 'Aliases', 'Public Indicators', 'RiskIQ Indicators'],
                           removeNull=True)


def validate_page_and_size_args(args: Dict[str, str]) -> dict:
    """
    Validate page and size arguments for all commands, raise ValueError on invalid arguments.
    :param args: The command arguments provided by the user.
    :return: Parameters to send in request
    """

    params: Dict[str, Any] = {}

    page_size = arg_to_number(args.get('page_size', DEFAULT_SIZE))

    if page_size is not None:
        if page_size < 1 or page_size > 2147483647:
            raise ValueError(MESSAGES["INVALID_PAGE_SIZE"].format(page_size))
    else:
        page_size = int(DEFAULT_SIZE)
    params["size"] = page_size

    page_number = arg_to_number(args.get('page_number', DEFAULT_PAGE_NUMBER))
    if page_number:
        if page_number < 0 or page_number > 2147483647:
            raise ValueError(MESSAGES["INVALID_PAGE_NUMBER"].format(page_number))
    else:
        page_number = int(DEFAULT_PAGE_NUMBER)
    params["page"] = page_number

    return params


def validate_list_intel_profile_indicators_args(args: Dict[str, Any]) -> Tuple[str, dict]:
    """
    Validate arguments of list_intel_profile_indicators commands, raise ValueError on invalid arguments.
    :param args: The command arguments provided by the user.
    :return: Parameters to send in request
    """
    profile_id = args.get('id', '')
    if not profile_id:
        raise ValueError(MESSAGES['REQUIRED_ARGUMENT'].format('id'))

    params = validate_page_and_size_args(args)

    indicator_type = args.get('type', '').lower()
    if indicator_type:
        if indicator_type not in INDICATOR_TYPE:
            raise ValueError(MESSAGES["INVALID_INDICATOR_TYPE"].format(indicator_type))
        params['types'] = indicator_type

    indicator_value = args.get('indicator_value', '')
    if indicator_value:
        params['query'] = indicator_value

    source = args.get('source', '').lower()
    if source:
        if source not in SOURCE:
            raise ValueError(MESSAGES['INVALID_SOURCE'].format(source))
        params['sources'] = source

    category = args.get('category', '').lower()
    if category:
        params['categories'] = category

    return profile_id, params


def get_human_readable_for_intel_profile_indicator_command(indicators: Dict[str, Any]) -> str:
    """
    Parse and convert the intel profile indicator list into human-readable markdown string.
    :param indicators: Details of indicators.
    :return: Human Readable string containing information of intel profile indicators.
    """
    hr_table_content: List[Dict[str, Any]] = []
    total_records = indicators.get('totalCount', 0)

    for indicator in indicators.get('results', []):
        hr_row = {
            'ID': indicator.get('id', ''),
            'Artifact Value': indicator.get('value', ''),
            'Type': indicator.get('type', ''),
            'First Seen (GMT)': indicator.get('firstSeen', ''),
            'Last Seen (GMT)': indicator.get('lastSeen', ''),
            'Source': 'OSINT' if indicator.get('osint', True) else 'RiskIQ',
        }
        hr_table_content.append(hr_row)

    hr = f"### Total Retrieved Indicator(s) {total_records}\n"
    hr += tableToMarkdown("Indicator(s)", hr_table_content,
                          headers=["ID", "Artifact Value", "Type", "First Seen (GMT)", "Last Seen (GMT)", "Source"],
                          removeNull=True)
    return hr


def validate_list_my_asi_insights_args(args: Dict[str, Any]) -> Tuple[str, int]:
    """
    Validate arguments of pt-list-my-attack-surface-insights, pt-list-third-party-asi-insights command, raise ValueError
    on invalid arguments.

    :param args: The command arguments provided by the user.
    :return: Parameters to send in request
    """

    priority = args.get('priority', '').lower()

    if priority:
        if priority not in PRIORITY:
            raise ValueError(MESSAGES["INVALID_PRIORITY_LEVEL"].format(priority))
    else:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("priority"))

    page_size = validate_page_size_args(args)

    return priority, page_size


def prepare_context_for_my_asi_insights(response, priority_level) -> Dict[str, Any]:
    """
    Prepare context data for pt-list-my-attack-surface-insights, pt-list-third-party-asi-insights command
    :param response: API response.
    :param priority_level: The priority level provided by the user.
    :return: context data
    """
    context_data = {"priorityLevel": priority_level}

    insights = response.get("insights", [])

    for insight in insights:
        link = insight.get("link", '')
        if link:
            # retrieve segment_by and insight_id from the link received from api response
            link_split = link.split('?')
            insight['insightId'] = link_split[0].split('/')[-1]
            query_parameters = parse.parse_qs(link_split[1])
            insight['segmentBy'] = query_parameters.get("segmentBy", '')[0]

    context_data["insight"] = insights

    return context_data


def get_human_readable_for_my_asi_insights_command(results: Dict[str, Any], priority: str, active_insights: int,
                                                   total_insights: int, total_observations: int) -> str:
    """
    Parse and convert the asi insight list into human-readable markdown string.
    :param results: Details of insights.
    :param priority: Priority of insights.
    :param active_insights: Total active insights
    :param total_insights: Total number of insights
    :param total_observations: Total observations
    :return: Human Readable string containing information.
    """
    hr_table_content: List[Dict[str, Any]] = []

    insights = results.get('insight', {})
    for insight in insights:
        hr_row = {
            'Name': insight.get('name', ''),
            'Description': insight.get('description', ''),
            'Observations': insight.get('observationCount', ''),
            'Insight ID': insight.get('insightId', ''),
            'Segment By': insight.get('segmentBy', ''),
        }
        hr_table_content.append(hr_row)

    # sort on the basis of observation count
    sorted_hr_table = sorted(hr_table_content, key=lambda item: item['Observations'], reverse=True)

    table_heading = f"{priority.capitalize()} Severity Insights\n{active_insights} Active of {total_insights} " \
                    f"Insights - {total_observations} Observations\n"
    hr = tableToMarkdown(table_heading, sorted_hr_table,
                         headers=["Name", "Description", "Observations", "Insight ID", "Segment By"],
                         removeNull=True)
    return hr


def get_human_readable_for_attack_surface_command(response: List[Dict[str, Any]]) -> str:
    """
    Parse and convert the attack surface list into human-readable markdown string.
    :param response: Details of attack surface.
    :return: Human Readable string containing information of attack surface.
    """
    hr_table_content: List[Dict[str, Any]] = []

    for result in response:
        hr_row = {
            'ID': result.get('id', ''),
            'Name': f"[{result.get('name', '')}]({UI_LINK}{result.get('id', '')})",
            'High Severity': f"{result.get('priorities', {}).get('high', {}).get('observationCount', 0)} observations",
            'Medium Severity': f"{result.get('priorities', {}).get('medium', {}).get('observationCount', 0)} observations",
            'Low Severity': f"{result.get('priorities', {}).get('low', {}).get('observationCount', 0)} observations",
        }
        hr_table_content.append(hr_row)

    return tableToMarkdown("Attack Surface(s)", hr_table_content,
                           headers=["ID", "Name", "High Severity", "Medium Severity", "Low Severity"], removeNull=True)


def validate_list_my_asi_assets_args(args: Dict[str, Any]) -> Tuple[str, dict]:
    """
    Validate arguments of list_my_asi_assets_command commands, raise ValueError on invalid arguments.
    :param args: The command arguments provided by the user.
    :return: Parameters to send in request
    """
    insight_id = args.get('id', '')
    if not insight_id:
        raise ValueError(MESSAGES['REQUIRED_ARGUMENT'].format('id'))

    segment_by = args.get('segment_by', '')
    if not segment_by:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("segment_by"))

    params = validate_page_and_size_args(args)
    params["segmentBy"] = segment_by

    return insight_id, params


def get_human_readable_for_my_asi_assets_command(results: Dict[str, Any]) -> str:
    """
    Parse and convert the asi asset list into human-readable markdown string.
    :param results: Details of assets.
    :return: Human Readable string containing information.
    """
    hr_table_content: List[Dict[str, Any]] = []
    assets = results.get('assets', [])
    for asset in assets:
        hr_row = {
            'Name': asset.get('name', ''),
            'Type': asset.get('type', ''),
            'First Seen (GMT)': asset.get('firstSeen', ''),
            'Last Seen (GMT)': asset.get('lastSeen', ''),
        }
        hr_table_content.append(hr_row)

    hr = tableToMarkdown("Asset(s)", hr_table_content,
                         headers=["Name", "Type", "First Seen (GMT)", "Last Seen (GMT)"],
                         removeNull=True)
    return hr


def get_human_readable_for_my_asi_vulnerable_components_command(results: List[Dict[str, Any]]) -> str:
    """
    Parse and convert the asi vulnerable component list into human-readable markdown string.
    :param results: Details of vulnerable component.
    :return: Human Readable string containing information.
    """
    hr_table_content: List[Dict[str, Any]] = []
    for component in results:
        hr_row = {
            'Name': component.get('name', ''),
            'Type': component.get('type', ''),
            'Severity': component.get('severity', ''),
            'Asset Count': component.get('count', ''),
        }
        hr_table_content.append(hr_row)

    hr = tableToMarkdown("Vulnerable Component(s)", hr_table_content,
                         headers=["Name", "Type", "Severity", "Asset Count"],
                         removeNull=True)
    return hr


def get_human_readable_for_my_asi_vulnerabilities_command(results: List[Dict[str, Any]]) -> str:
    """
    Parse and convert the asi vulnerabilities list into human-readable markdown string.
    :param results: Details of vulnerability.
    :return: Human Readable string containing information.
    """
    hr_table_content: List[Dict[str, Any]] = []
    for component in results:
        hr_row = {
            'CVE ID': component.get('cveId', ''),
            'CWE ID': f'{", ".join("{}".format(i.get("cweId")) for i in component.get("cwes", []))} ',
            'RiskIQ Priority Score': component.get('priorityScore', ''),
            'Asset Count': component.get('observationCount', ''),
        }
        hr_table_content.append(hr_row)

    hr = tableToMarkdown("Vulnerabilities", hr_table_content,
                         headers=["CVE ID", "CWE ID", "RiskIQ Priority Score", "Asset Count"],
                         removeNull=True)
    return hr


def get_human_readable_for_my_asi_observations_command(results: Dict[str, Any]) -> str:
    """
    Parse and convert the asi observations list into human-readable markdown string.
    :param results: Details of observations.
    :return: Human Readable string containing information.
    """
    hr_table_content: List[Dict[str, Any]] = []
    assets = results.get('assets', [])
    for asset in assets:
        hr_row = {
            'Name': asset.get('name', ''),
            'Type': asset.get('type', ''),
            'First Seen (GMT)': asset.get('firstSeen', ''),
            'Last Seen (GMT)': asset.get('lastSeen', ''),
        }
        hr_table_content.append(hr_row)

    hr = tableToMarkdown("Observation(s)", hr_table_content,
                         headers=["Name", "Type", "First Seen (GMT)", "Last Seen (GMT)"],
                         removeNull=True)
    return hr


def validate_page_size_args(args: Dict[str, str]) -> int:
    """
    Validate page_size argument for all command which does not supports pagination, raise ValueError on invalid
    arguments.
    :param args: The command arguments provided by the user.
    :return: Validated page_size argument
    """

    page_size = arg_to_number(args.get('page_size', DEFAULT_SIZE))

    if page_size is not None:
        if page_size < 1 or page_size > 1000:
            raise ValueError(MESSAGES["NOT_VALID_PAGE_SIZE"].format(page_size))
    else:
        page_size = int(DEFAULT_SIZE)

    return page_size


''' REQUESTS FUNCTIONS '''


def test_function(client: Client) -> str:
    """
    Performs test connectivity by valid http response

    :param client: client object which is used to get response from api
    :return: raise ValueError if any error occurred during connection
    """
    client.http_request(method='GET', url_suffix=URL_SUFFIX['TEST_MODULE'])

    return 'ok'


@logger
def get_components_command(client: Client, args: Dict[str, Any]) -> Union[str, List[CommandResults]]:
    """
    Retrieves the host attribute components for a domain or IP address.

    :param client: Client object
    :param args: The command arguments provided by user
    :return: Standard command result or no records found message
    """
    # Trim the arguments
    for argument in args:
        args[argument] = args[argument].strip()

    # Retrieve arguments and prepare query data
    params = get_common_arguments(args)

    # http call
    resp = client.http_request(method="GET", url_suffix=URL_SUFFIX['GET_COMPONENTS'], params=params)

    total_records = resp.get('totalRecords', 0)
    if total_records == 0:
        return MESSAGES['NO_RECORDS_FOUND'].format('component(s)')

    results = resp.get('results', [])

    # Creating entry context
    command_results, custom_ec = get_host_attribute_context_data(results)

    # Creating human-readable
    hr = get_components_hr(results)

    command_results.insert(0, CommandResults(
        outputs_prefix='PassiveTotal.Component',
        outputs_key_field='',
        outputs=custom_ec,
        readable_output=hr,
        raw_response=resp,
    ))

    return command_results


@logger
def pt_whois_search_command(client_obj: Client, args: Dict[str, Any]) -> Union[List[CommandResults], str]:
    """
    Gets WHOIS information records based on field matching queries

    :param client_obj: client object which is used to get response from API
    :param args: it contain arguments of pt-whois-search
    :return: command output
    """
    # Retrieve arguments
    query, field = get_valid_whois_search_arguments(args)
    params = {
        'query': query,
        'field': field
    }

    # http call
    response = client_obj.http_request(method='GET', url_suffix=URL_SUFFIX['WHOIS_SEARCH'], params=params)

    domains = response.get('results', [])
    if len(domains) <= 0:
        return MESSAGES['NO_RECORDS_FOUND'].format('domain information')

    # Creating entry context
    command_results, custom_ec = get_context_for_whois_commands(domains)

    # Creating human-readable
    hr = get_human_readable_for_whois_commands(domains)

    command_results.insert(0, CommandResults(
        outputs_prefix='PassiveTotal.WHOIS',
        outputs_key_field=['domain', 'lastLoadedAt'],
        outputs=custom_ec,
        readable_output=hr,
        raw_response=response
    ))

    return command_results


@logger
def get_trackers_command(client: Client, args: Dict[str, Any]) -> Union[str, List[CommandResults]]:
    """
    Retrieves the host attribute trackers for a domain or IP address.

    :param client: Client object
    :param args: The command arguments provided by user
    :return: Standard command result or no records found message
    """
    # Trim the arguments
    for argument in args:
        args[argument] = args[argument].strip()

    # Retrieve arguments and prepare query data
    params = get_common_arguments(args)

    # http call
    resp = client.http_request(method="GET", url_suffix=URL_SUFFIX['GET_TRACKERS'], params=params)

    total_records = resp.get('totalRecords', 0)
    if total_records == 0:
        return MESSAGES['NO_RECORDS_FOUND'].format('tracker(s)')

    results = resp.get('results', [])

    # Creating entry context
    command_results, custom_ec = get_host_attribute_context_data(results)

    # Creating human-readable
    hr = get_trackers_hr(results)

    command_results.insert(0, CommandResults(
        outputs_prefix='PassiveTotal.Tracker',
        outputs_key_field='',
        outputs=custom_ec,
        readable_output=hr,
        raw_response=resp,
    ))

    return command_results


@logger
def ssl_cert_search_command(client: Client, args: Dict[str, Any]) -> Union[str, CommandResults]:
    """
    Retrieve SSL certificates based on various field and its value.

    :param client: client object.
    :param args: Demisto argument(s) provided by the user.
    :return: standard command result
    """
    # Retrieve arguments
    field: str = args.get('field', '')
    query: str = args.get('query', '')

    # Building url
    url_suffix: str = URL_SUFFIX['SSL_CERT_SEARCH']

    # Prepare query data
    request_data: Dict[str, Any] = {
        'field': field,
        'query': query
    }

    # http call
    resp: Dict[str, Any] = client.http_request("GET", url_suffix, request_data)

    results: List[Dict[str, Any]] = resp.get('results', [])
    if len(results) <= 0:
        return MESSAGES['NO_RECORDS_FOUND'].format('SSL certificate(s)')

    # Creating entry context
    custom_ec = createContext(results, removeNull=True)

    # Creating human-readable
    hr = get_ssl_cert_search_hr(results)

    return CommandResults(
        outputs_prefix='PassiveTotal.SSL',
        outputs_key_field='sha1',
        outputs=custom_ec,
        readable_output=hr,
        raw_response=resp
    )


@logger
def get_pdns_details_command(client: Client, args: Dict[str, Any]) -> Union[str, List[CommandResults]]:
    """
    Retrieve passive DNS details based on ip or host.

    :param client: client object.
    :param args: Demisto argument(s) provided by the user.
    :return: standard command result
    """
    # Retrieve arguments
    params = get_common_arguments(args)
    params['timeout'] = args.get('timeout', 7)

    # http call
    resp = client.http_request("GET", url_suffix=URL_SUFFIX['GET_PDNS_DETAILS'], params=params)
    total_record = resp.get('totalRecords', 0)
    if total_record <= 0:
        return MESSAGES['NO_RECORDS_FOUND'].format('PDNS Record(s)')

    # Creating entry context
    results = resp.get('results', [])
    custom_ec = createContext(results, removeNull=True)
    command_results = create_pdns_standard_context(results)

    # Creating human-readable
    hr = get_pdns_details_hr(results, total_record)

    # Building custom output path
    output_path = 'PassiveTotal.PDNS(val.{0} == obj.{0} && val.{1} == obj.{1} && val.{2} == obj.{2})' \
        .format('resolve', 'recordType', 'resolveType')

    command_results.insert(0, CommandResults(
        outputs_prefix=output_path,
        outputs_key_field='',
        outputs=custom_ec,
        readable_output=hr,
        raw_response=resp
    ))

    return command_results


@logger
def get_host_pairs_command(client: Client, args: Dict[str, Any]) -> Union[str, CommandResults]:
    """
    Retrieves the host attribute pairs related to a domain or IP address.

    :param client: Client object
    :param args: The command arguments provided by user
    :return: Standard command result or no records found message
    """
    # Trim the arguments
    for argument in args:
        args[argument] = args[argument].strip()

    # Retrieve arguments and prepare query data
    params = get_common_arguments(args)

    if args.get('direction') not in VALID_DIRECTION_FOR_HOST_PAIRS:
        raise ValueError(MESSAGES['INVALID_DIRECTION_VALUE'])
    params['direction'] = args.get('direction')

    # http call
    resp = client.http_request(method="GET", url_suffix=URL_SUFFIX['GET_HOST_PAIRS'], params=params)

    total_records = resp.get('totalRecords', 0)
    if total_records == 0:
        return MESSAGES['NO_RECORDS_FOUND'].format('host pair(s)')

    results = resp.get('results', [])

    # Creating entry context
    custom_ec = createContext(data=results, removeNull=True)

    # Creating human-readable
    hr = get_host_pairs_hr(results)

    return CommandResults(
        outputs_prefix='PassiveTotal.HostPair',
        outputs_key_field='',
        outputs=custom_ec,
        readable_output=hr,
        raw_response=resp
    )


@logger
def domain_reputation_command(client_obj: Client, args: Dict[str, Any]) -> Union[str, List[CommandResults]]:
    """
    Reputation command for domain.

    :param client_obj: Client object
    :param args: The command arguments provided by user
    :return: Standard command result or no records found message
    """
    # Retrieve arguments
    domains = argToList(args.get('domain', ''))

    # argument validation
    if len(domains) == 0:
        raise ValueError('domain(s) not specified')

    command_results: List[CommandResults] = []
    custom_domain_context: List[Dict[str, Any]] = []
    domain_responses: List[Dict[str, Any]] = []
    custom_reputation_response = []
    for domain in domains:
        # argument validation
        if domain.strip() == '':
            raise ValueError(MESSAGES['EMPTY_DOMAIN_ARGUMENT'])

        params = {
            'query': domain,
            'field': 'domain'
        }

        # http call
        response = client_obj.http_request(method='GET', url_suffix=URL_SUFFIX['WHOIS_SEARCH'], params=params)
        reputation_response = client_obj.http_request(method='GET', url_suffix=URL_SUFFIX["GET_REPUTATION"],
                                                      params=params)
        hr_response = get_human_readable_for_reputation_command(reputation_response, domain)
        custom_reputation_response.append(hr_response)
        custom_reputation_context = remove_empty_elements(reputation_response)

        domains_response = response.get('results', [])
        if len(domains_response) <= 0:
            continue

        classification = reputation_response.get('classification', '')
        dbot_score = calculate_dbot_score(classification)
        # Creating entry context
        standard_results, custom_context = get_context_for_whois_commands(domains_response, dbot_score)

        # Preparing context data
        command_results.extend(standard_results)
        custom_context.append(custom_reputation_context)
        final_context = {k: v for x in custom_context for k, v in x.items()}
        custom_domain_context.append(final_context)

        domain_responses += domains_response

    # Creating human-readable
    domain_standard_hr = get_human_readable_for_whois_commands(
        domain_responses,
        is_reputation_command=True
    )

    final_hr = domain_standard_hr
    for x in custom_reputation_response:
        final_hr += x

    command_results.insert(0, CommandResults(
        readable_output=final_hr,
        outputs_prefix='PassiveTotal.Domain',
        outputs_key_field='domain',
        outputs=custom_domain_context
    ))

    return command_results


@logger
def get_services_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieves the services for the specified IP address.

    :param client: Client object.
    :param args: The command arguments provided by user.
    :return: Standard command result or no records found message.
    """

    # Trim the argument and remove ' quotes surrounding ip
    ip = args['ip'].strip().strip("'")

    # Checking whether ip is valid or not
    if not is_ip_valid(ip, accept_v6_ips=True):
        raise ValueError(MESSAGES['INVALID_IP'])

    # http call
    resp = client.http_request(method="GET", url_suffix=URL_SUFFIX['GET_SERVICES'], params={'query': ip})

    total_records = resp.get('totalRecords', 0)

    if total_records == 0:
        return CommandResults(readable_output=MESSAGES['NO_RECORDS_FOUND'].format('services'))

    results = [{**response, 'ip': ip} for response in resp.get('results', [])]

    # Creating context
    context_output = remove_empty_elements(results)

    # Creating human-readable
    hr = get_services_hr(total_records, results)

    return CommandResults(
        outputs_prefix='PassiveTotal.Service',
        outputs_key_field=['ip', 'portNumber'],
        outputs=context_output,
        readable_output=hr,
        raw_response=resp,
    )


@logger
def pt_get_whois_command(client_obj: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Gets WHOIS information records based on queries

    :param client_obj: client object which is used to get response from API
    :param args: it contain arguments of pt-get-whois
    :return: command output
    """
    # Retrieve arguments
    query, history = get_valid_get_whois_arguments(args)
    params = {
        'query': query,
        'history': history
    }

    # http call
    response = client_obj.http_request(method='GET', url_suffix=URL_SUFFIX['WHOIS_GET'], params=params)

    domains = response.get('results', [])
    if len(domains) <= 0 and 'domain' in response:
        domains = [response]

    if len(domains) <= 0:
        return CommandResults(readable_output=MESSAGES['NO_RECORDS_FOUND'].format('domain information'))

    # Creating entry context
    custom_context = get_context_for_get_whois_commands(domains)

    # Creating human-readable
    hr = get_human_readable_for_whois_commands(domains)

    return CommandResults(
        outputs_prefix='PassiveTotal.WHOIS',
        outputs_key_field=['domain', 'lastLoadedAt'],
        outputs=custom_context,
        readable_output=hr,
        raw_response=response
    )


@logger
def get_cookies_command(client: Client, args: Dict[str, str]) -> Union[str, CommandResults]:
    """
    Retrieve cookies with hostnames or addresses based on cookie name or cookie domain.

    :param client: Client object
    :param args: The command arguments provided by user

    :return: Standard command result or no records found message
    """

    default_values = {
        'page': "0",
        'sort': "last seen",
        'order': 'desc'
    }
    # Trim the arguments and fill empty optional args with default values
    for argument in args:
        args[argument] = args[argument].strip()
        if not args[argument] and argument in list(default_values.keys()):
            args[argument] = default_values[argument]

    # Validate arguments
    validate_get_cookies_arguments(args)

    # Prepare params for http request
    params = {
        "page": args.get("page"),
        "sort": 'lastSeen' if args.get("sort") == "last seen" else 'firstSeen',
        "order": args.get("order")
    }

    # Prepare the url suffix as per search_by and query argument
    url_suffix = URL_SUFFIX["_".join(args["search_by"].upper().split())].format(args["query"])

    # Make the http request
    resp = client.http_request(method="GET", url_suffix=url_suffix, params=params)

    # Get results from response
    results = resp.get("results", [])

    # Get total records from response
    total_records = resp.get("totalRecords", 0)
    # return standard no records found message on empty results
    if len(results) <= 0:
        return 'Total Record(s): ' + str(total_records) + '\n' + MESSAGES['NO_RECORDS_FOUND'].format('cookies')

    # creating entry context
    entry_context = createContext(results, removeNull=True)

    # create human readable by providing it results and the first column header name
    human_readable = get_cookies_hr(results, "Hostname" if "hosts" in url_suffix else "IP Address", total_records)

    # return CommandResults objects
    return CommandResults(
        outputs_prefix="PassiveTotal.Cookie",
        outputs_key_field=['hostname', 'cookieName', 'cookieDomain'],
        outputs=entry_context,
        readable_output=human_readable,
        raw_response=resp
    )


@logger
def pt_get_articles_command(client_obj: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Gets an article information based on queries

    :param client_obj: client object which is used to get response from API
    :param args: it contain arguments of pt-get-articles
    :return: command output
    """
    # Retrieve arguments
    query = args.get('query', '').strip()
    article_type = args.get('type', '').strip()
    if query == '':
        raise ValueError(MESSAGES['EMPTY_GET_WHOIS_ARGUMENT'])

    params = {
        'query': query
    }

    if article_type != '':
        params['type'] = article_type

    # http call
    response = client_obj.http_request(method='GET', url_suffix=URL_SUFFIX['GET_ARTICLES'], params=params)

    articles = response.get('articles', [])

    if not articles or len(articles) <= 0:
        return CommandResults(readable_output=MESSAGES['NO_RECORDS_FOUND'].format('articles'))

    # Creating entry context
    custom_ec_for_articles = remove_empty_elements(articles)

    # Creating human-readable
    hr = get_human_readable_for_articles_commands(articles)

    return CommandResults(
        outputs_prefix='PassiveTotal.Article',
        outputs_key_field='guid',
        outputs=custom_ec_for_articles,
        readable_output=hr,
        raw_response=response
    )


@logger
def get_data_card_summary_command(client_obj: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieves a summary data card associated with the given query.

    :param client_obj: client object which is used to get response from API
    :param args: it contain arguments of pt-data-card-get
    :return: command output
    """
    # Retrieve arguments
    query = args.get('query', '').strip()
    if not query:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("query"))

    params = {
        'query': query
    }

    # http call
    response = client_obj.http_request(method='GET', url_suffix=URL_SUFFIX['GET_DATA_CARD_SUMMARY'], params=params)
    context_data = remove_empty_elements(response)
    hr_response = get_human_readable_for_data_card_command(response)

    return CommandResults(
        outputs_prefix='PassiveTotal.DataCard',
        outputs_key_field='name',
        outputs=context_data,
        readable_output=hr_response,
        raw_response=response
    )


@logger
def get_reputation_command(client_obj: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Gets reputation for a given domain, host or IP.

    :param client_obj: client object which is used to get response from API
    :param args: it contain arguments of pt-reputation-get
    :return: command output
    """
    # Retrieve arguments
    query = args.get('query', '').strip()

    if not query:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("query"))

    params = {
        'query': query
    }

    # http call
    response = client_obj.http_request(method='GET', url_suffix=URL_SUFFIX["GET_REPUTATION"], params=params)
    context_data = remove_empty_elements(response)
    context_data['query'] = query
    hr_response = get_human_readable_for_reputation_command(response, query)

    return CommandResults(
        outputs_prefix='PassiveTotal.Reputation',
        outputs_key_field='query',
        outputs=context_data,
        readable_output=hr_response,
        raw_response=response
    )


@logger
def ip_reputation_command(client_obj: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """
    Reputation command for IP.

    :param client_obj: Client object
    :param args: The command arguments provided by user
    :return: Standard command result
    """
    # Retrieve arguments
    ips = args.get('ip', '')
    ips = argToList(",".join([x.strip() for x in ips.split(",") if x.strip()]))

    # argument validation
    if len(ips) == 0:
        raise ValueError(MESSAGES["EMPTY_IP_ARGUMENT"])

    command_results: List[CommandResults] = []

    for ip in ips:
        if not is_ip_valid(ip, True):
            raise ValueError(MESSAGES["INVALID_IP_ARGUMENT"].format(ip))
        params = {
            'query': ip,
        }
        # http call
        response = client_obj.http_request(method='GET', url_suffix=URL_SUFFIX["GET_REPUTATION"], params=params)

        classification = response.get('classification', '')
        dbot_score = calculate_dbot_score(classification)
        standard_context = get_standard_context(dbot_score, ip)

        context_data = remove_empty_elements(response)
        context_data['query'] = ip

        human_readable = get_human_readable_for_reputation_command(response, ip)

        command_results.append(CommandResults(
            readable_output=human_readable,
            outputs_prefix='PassiveTotal.IP',
            outputs_key_field='query',
            outputs=context_data,
            indicator=standard_context
        ))
    return command_results


@logger
def get_intel_profile_command(client_obj: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieves the list of all profiles.

    :param client_obj: client object which is used to get response from API
    :param args: it contain arguments of pt-list-intel-profiles
    :return: command output
    """
    # Retrieve arguments
    params, page_size = validate_list_intel_profile_args(args)

    profile_id = args.get("id")

    if profile_id:
        url_suffix = f'{URL_SUFFIX["LIST_INTEL_PROFILE"]}/{profile_id}'

    elif args.get("indicator_value"):
        url_suffix = URL_SUFFIX["LIST_INTEL_PROFILE_BY_INDICATOR"]

    else:
        url_suffix = URL_SUFFIX["LIST_INTEL_PROFILE"]

    # http call
    response = client_obj.http_request(method='GET', url_suffix=url_suffix, params=params)

    if profile_id:
        profiles = [response]
    else:
        profiles = response.get("results", [])

    if not profiles:
        return CommandResults(readable_output=MESSAGES['NO_RECORDS_FOUND'].format("profiles"))

    profiles = profiles[:page_size]
    context_data = remove_empty_elements_for_context(profiles)

    hr_response = get_human_readable_for_intel_profile_command(profiles)

    return CommandResults(
        outputs_prefix='PassiveTotal.IntelProfile',
        outputs_key_field='id',
        outputs=context_data,
        readable_output=hr_response,
        raw_response=response
    )


@logger
def list_intel_profile_indicators_command(client_obj: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieves the indicators for the given profile.

    :param client_obj: client object which is used to get response from API
    :param args: it contain arguments of pt-list-intel-profile-indicator
    :return: command output
    """
    profile_id, params = validate_list_intel_profile_indicators_args(args)

    response = client_obj.http_request(method='GET',
                                       url_suffix=URL_SUFFIX['LIST_INTEL_PROFILE_INDICATOR'].format(profile_id),
                                       params=params)
    indicators = response.get('results', [])
    if not indicators or len(indicators) <= 0:
        return CommandResults(readable_output=MESSAGES['NO_RECORDS_FOUND'].format('indicators'))

    for indicator in indicators:
        del indicator['profileId']

    context_data = {'indicator': remove_empty_elements(indicators), 'id': profile_id}
    hr_response = get_human_readable_for_intel_profile_indicator_command(response)

    return CommandResults(
        outputs_prefix='PassiveTotal.IntelProfile',
        outputs_key_field='id',
        outputs=context_data,
        readable_output=hr_response,
        raw_response=response
    )


@logger
def list_my_asi_insights_command(client_obj: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieves the attack surface insight information of the individual's account.

    :param client_obj: client object which is used to get response from API
    :param args: it contain arguments of pt-list-my-attack-surface-insights
    :return: command output
    """
    priority_level, page_size = validate_list_my_asi_insights_args(args)

    url_suffix = f'{URL_SUFFIX["LIST_ASI_INSIGHTS"]}/{priority_level}'

    response = client_obj.http_request(method='GET', url_suffix=url_suffix)

    insights = response.get('insights', [])
    response['insights'] = insights[:page_size]
    context_data = prepare_context_for_my_asi_insights(response, priority_level)
    summary = {
        "name": "pt-list-my-attack-surface-insights",
        "activeInsightCount": response.get("activeInsightCount", ''),
        "totalInsightCount": response.get("totalInsightCount", ''),
        "totalObservations": response.get("totalObservations", '')

    }
    outputs = {
        "PassiveTotal.Insight(val.priorityLevel == obj.priorityLevel)": context_data,
        "PassiveTotal.Summary.Insight(val.name == obj.name)": summary
    }

    hr_response = get_human_readable_for_my_asi_insights_command(context_data, priority_level,
                                                                 summary['activeInsightCount'],
                                                                 summary['totalInsightCount'],
                                                                 summary['totalObservations'])
    outputs = remove_empty_elements_for_context(outputs)

    return CommandResults(
        outputs=outputs,
        readable_output=hr_response,
        raw_response=response
    )


@logger
def list_third_party_asi_command(client_obj: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieves the attack surface observations by severity level for the given third-party account.

    :param client_obj: client object which is used to get response from API
    :param args: it contain arguments of pt-list-third-party-attack-surface
    :return: command output
    """
    params = validate_page_and_size_args(args)

    vendor_id = arg_to_number(args.get('id'))

    url_suffix = URL_SUFFIX['LIST_THIRD_PARTY_ASI']
    if vendor_id:
        url_suffix = f"{URL_SUFFIX['LIST_THIRD_PARTY_ASI']}/{vendor_id}"
        params = {}

    response = client_obj.http_request(method='GET', url_suffix=url_suffix, params=params)

    if vendor_id:
        context_data = [remove_empty_elements(response)]
    else:
        context_data = remove_empty_elements(response.get('vendors', []))

    hr_response = get_human_readable_for_attack_surface_command(context_data)

    for data in context_data:
        data['priority'] = data.pop('priorities')

    summary = {
        "name": "pt-list-third-party-attack-surface",
        "totalCount": response.get("totalCount", ''),
        "totalPages": response.get("totalPages", ''),
        "nextPage": response.get("nextPage", '')

    }
    outputs = {
        "PassiveTotal.ThirdParty(val.id == obj.id)": context_data,
        "PassiveTotal.Summary.ThirdPartyASI(val.name == obj.name)": summary
    }
    outputs = remove_empty_elements_for_context(outputs)

    return CommandResults(
        outputs=outputs,
        readable_output=hr_response,
        raw_response=response
    )


@logger
def list_my_attack_surfaces_command(client_obj: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieves the attack surface information of the individual's account.

    :param client_obj: client object which is used to get response from API
    :param args: It contain arguments of pt-list-my-attack-surfaces
    :return: command output
    """
    page_size = validate_page_size_args(args)

    response = client_obj.http_request(method='GET', url_suffix=URL_SUFFIX['LIST_ATTACK_SURFACE'])
    if isinstance(response, dict):
        response = [response]  # type: ignore

    response = response[:page_size]  # type: ignore
    context_data = remove_empty_elements_for_context(response)
    for data in context_data:
        data['priority'] = data.pop('priorities')

    hr_response = get_human_readable_for_attack_surface_command(response)  # type: ignore

    return CommandResults(
        outputs_prefix='PassiveTotal.AttackSurface',
        outputs_key_field='id',
        outputs=context_data,
        readable_output=hr_response,
        raw_response=response
    )


@logger
def list_third_party_asi_insights_command(client_obj: Client, args: Dict[str, Any]):
    """
    Retrieves the attack surface insight information of the given third-party account.

    :param client_obj: client object which is used to get response from API
    :param args: It contain arguments of pt-list-third-party-attack-surface-insights
    :return: command output
    """
    vendor_id = arg_to_number(args.get("id", ''))
    if not vendor_id:
        raise ValueError(MESSAGES['REQUIRED_ARGUMENT'].format('id'))

    priority, page_size = validate_list_my_asi_insights_args(args)

    url_suffix = URL_SUFFIX['THIRD_PARTY_ASI_INSIGHTS'].format(vendor_id, priority)
    response = client_obj.http_request(method='GET', url_suffix=url_suffix)

    insights = response.get('insights', [])
    response['insights'] = insights[:page_size]

    context_data_out = prepare_context_for_my_asi_insights(response, priority)
    context_data_out.pop("priorityLevel")
    context_data = {
        "Insight": context_data_out,
        "id": vendor_id,
        "priorityLevel": priority
    }

    summary = {
        "name": "pt-list-third-party-attack-surface-insights",
        "activeInsightCount": response.get("activeInsightCount", ''),
        "totalInsightCount": response.get("totalInsightCount", ''),
        "totalObservations": response.get("totalObservations", '')
    }
    outputs = {
        "PassiveTotal.ThirdParty(val.id == obj.id)": context_data,
        "PassiveTotal.Summary.ThirdPartyInsight(val.name == obj.name)": summary
    }
    outputs = remove_empty_elements_for_context(outputs)

    hr_response = get_human_readable_for_my_asi_insights_command(context_data["Insight"], priority,  # type:ignore
                                                                 summary['activeInsightCount'],
                                                                 summary['totalInsightCount'],
                                                                 summary['totalObservations'])

    return CommandResults(
        outputs=outputs,
        raw_response=response,
        readable_output=hr_response
    )


@logger
def list_my_asi_assets_command(client_obj: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieves the attack surface asset information of the individual's account.

    :param client_obj: client object which is used to get response from API
    :param args: it contain arguments of pt-list-attack-surface-assets
    :return: command output
    """
    insight_id, params = validate_list_my_asi_assets_args(args)

    url_suffix = f'{URL_SUFFIX["LIST_ASI_ASSETS"]}/{insight_id}'

    response = client_obj.http_request(method='GET', url_suffix=url_suffix, params=params)

    context_data = {
        "asset": response.get("assets", []),
        "insightId": insight_id,
        "segmentBy": params["segmentBy"]}

    summary = {
        "name": "pt-list-my-attack-surface-assets",
        "totalCount": response.get("totalCount", ''),
        "totalPages": response.get("totalPages", ''),
        "nextPage": response.get("nextPage", '')

    }
    outputs = {
        "PassiveTotal.Asset(val.insightId == obj.insightId && val.segmentBy == obj.segmentBy)": context_data,
        "PassiveTotal.Summary.Asset(val.name == obj.name)": summary
    }
    outputs = remove_empty_elements_for_context(outputs)

    hr_response = get_human_readable_for_my_asi_assets_command(response)

    return CommandResults(
        outputs=outputs,
        readable_output=hr_response,
        raw_response=response
    )


@logger
def list_my_asi_vulnerable_components_command(client_obj: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieves the attack surface vulnerable component information of the individual's account.

    :param client_obj: client object which is used to get response from API
    :param args: it contain arguments of pt-list-my-attack-surface-vulnerable-components
    :return: command output
    """
    params = validate_page_and_size_args(args)

    response = client_obj.http_request(method='GET', url_suffix=URL_SUFFIX["LIST_ASI_VULNERABLE_COMPONENTS"],
                                       params=params)

    result = response.get("vulnerableComponents")
    if not result:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("vulnerable components"))

    summary = {
        "name": "pt-list-my-attack-surface-vulnerable-components",
        "totalCount": response.get("totalCount", ''),
        "totalPages": response.get("totalPages", ''),
        "nextPage": response.get("nextPage", '')

    }
    outputs = {
        "PassiveTotal.VulnerableComponent(val.name == obj.name && val.type == obj.type)": result,
        "PassiveTotal.Summary.VulnerableComponent(val.name == obj.name)": summary
    }
    outputs = remove_empty_elements_for_context(outputs)
    hr_response = get_human_readable_for_my_asi_vulnerable_components_command(result)

    return CommandResults(
        outputs=outputs,
        readable_output=hr_response,
        raw_response=response
    )


@logger
def list_my_asi_vulnerabilities_command(client_obj: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieves the attack surface vulnerable component information of the individual's account.

    :param client_obj: client object which is used to get response from API
    :param args: it contain arguments of pt-list-my-attack-surface-vulnerabilities
    :return: command output
    """
    params = validate_page_and_size_args(args)

    response = client_obj.http_request(method='GET', url_suffix=URL_SUFFIX["LIST_ASI_VULNERABILITIES"],
                                       params=params)

    result = response.get("cves")
    if not result:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("vulnerabilities"))

    summary = {
        "name": "pt-list-my-attack-surface-vulnerabilities",
        "totalCount": response.get("totalCount", ''),
        "totalPages": response.get("totalPages", ''),
        "nextPage": response.get("nextPage", '')

    }
    outputs = {
        "PassiveTotal.Vulnerability(val.cveId == obj.cveId)": result,
        "PassiveTotal.Summary.Vulnerability(val.name == obj.name)": summary
    }
    outputs = remove_empty_elements_for_context(outputs)
    hr_response = get_human_readable_for_my_asi_vulnerabilities_command(result)

    return CommandResults(
        outputs=outputs,
        readable_output=hr_response,
        raw_response=response
    )


@logger
def list_third_party_asi_vulnerable_components_command(client_obj: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieves the attack surface vulnerable component information of the given third-party account.

    :param client_obj: client object which is used to get response from API
    :param args: it contain arguments of pt-list-third-party-attack-surface-vulnerable-components
    :return: command output
    """
    vendor_id = arg_to_number(args.get("id", ''))
    if not vendor_id:
        raise ValueError(MESSAGES['REQUIRED_ARGUMENT'].format('id'))

    params = validate_page_and_size_args(args)

    response = client_obj.http_request(method='GET',
                                       url_suffix=URL_SUFFIX["LIST_THIRD_PARTY_ASI_VULNERABLE_COMPONENTS"].format(
                                           vendor_id),
                                       params=params)

    result = response.get("vulnerableComponents")
    if not result:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("third party vulnerable components"))

    context_data = {
        "id": vendor_id,
        "VulnerableComponent": result
    }

    summary = {
        "name": "pt-list-third-party-attack-surface-vulnerable-components",
        "totalCount": response.get("totalCount", ''),
        "totalPages": response.get("totalPages", ''),
        "nextPage": response.get("nextPage", '')

    }
    outputs = {
        "PassiveTotal.ThirdParty(val.id == obj.id)": context_data,
        "PassiveTotal.Summary.ThirdPartyVulnerableComponent(val.name == obj.name)": summary
    }
    outputs = remove_empty_elements_for_context(outputs)

    hr_response = get_human_readable_for_my_asi_vulnerable_components_command(result)

    return CommandResults(
        outputs=outputs,
        readable_output=hr_response,
        raw_response=response
    )


@logger
def list_my_asi_observations_command(client_obj: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieves the attack surface vulnerability observation information of the individual's account.

    :param client_obj: client object which is used to get response from API
    :param args: it contain arguments of pt-list-my-attack-surface-observations
    :return: command output
    """
    cve_id = args.get("cve_id")
    if not cve_id:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("cve_id"))

    params = validate_page_and_size_args(args)

    response = client_obj.http_request(method='GET', url_suffix=URL_SUFFIX["LIST_ASI_OBSERVATIONS"].format(cve_id),
                                       params=params)
    result = response.get("assets")
    if not result:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("observations"))

    summary = {
        "name": "pt-list-my-attack-surface-observations",
        "totalCount": response.get("totalCount", ''),
        "totalPages": response.get("totalPages", ''),
        "nextPage": response.get("nextPage", '')

    }
    result = {
        "cveId": response.get("cveId", ''),
        "cwe": response.get("cwes", []),
        "asset": response.get("assets", [])
    }
    outputs = {
        "PassiveTotal.Observation(val.cveId == obj.cveId)": result,
        "PassiveTotal.Summary.Observation(val.name == obj.name)": summary
    }
    outputs = remove_empty_elements_for_context(outputs)
    hr_response = get_human_readable_for_my_asi_observations_command(response)

    return CommandResults(
        outputs=outputs,
        readable_output=hr_response,
        raw_response=response
    )


@logger
def list_third_party_asi_assets_command(client_obj: Client, args: Dict[str, Any]):
    """
    Retrieves the attack surface asset information of the given third-party account.

    :param client_obj: client object which is used to get response from API
    :param args: it contain arguments of pt-list-third-party-attack-surface-assets
    :return: command output
    """
    vendor_id = arg_to_number(args.get("vendor_id", ''))
    if not vendor_id:
        raise ValueError(MESSAGES['REQUIRED_ARGUMENT'].format('vendor_id'))

    insight_id, params = validate_list_my_asi_assets_args(args)

    response = client_obj.http_request(method='GET',
                                       url_suffix=URL_SUFFIX["LIST_THIRD_PARTY_ASI_ASSETS"].format(vendor_id,
                                                                                                   insight_id),
                                       params=params)

    context_data = {
        "id": vendor_id,
        "InsightAsset": {
            "asset": response.get("assets", []),
            "insightId": insight_id,
            "segmentBy": params["segmentBy"]
        }
    }

    summary = {
        "name": "pt-list-third-party-attack-surface-assets",
        "totalCount": response.get("totalCount", ''),
        "totalPages": response.get("totalPages", ''),
        "nextPage": response.get("nextPage", '')

    }
    outputs = {
        "PassiveTotal.ThirdParty(val.id == obj.id)": context_data,
        "PassiveTotal.Summary.ThirdPartyInsightAsset(val.name == obj.name)": summary
    }
    outputs = remove_empty_elements_for_context(outputs)

    hr_response = get_human_readable_for_my_asi_assets_command(response)

    return CommandResults(
        outputs=outputs,
        raw_response=response,
        readable_output=hr_response
    )


@logger
def list_third_party_asi_observations_command(client_obj: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieves the attack surface vulnerability observation information of the given third-party account.

    :param client_obj: client object which is used to get response from API
    :param args: it contain arguments of pt-list-third-party-attack-surface-observations
    :return: command output
    """
    vendor_id = arg_to_number(args.get("id", ''))
    if not vendor_id:
        raise ValueError(MESSAGES['REQUIRED_ARGUMENT'].format('id'))

    cve_id = args.get("cve_id")
    if not cve_id:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("cve_id"))

    params = validate_page_and_size_args(args)

    response = client_obj.http_request(method='GET',
                                       url_suffix=URL_SUFFIX["LIST_THIRD_PARTY_ASI_OBSERVATIONS"].format(vendor_id,
                                                                                                         cve_id),
                                       params=params)

    result = response.get("assets")
    if not result:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("third party observations"))

    # prepare context
    summary = {
        "name": "pt-list-third-party-attack-surface-observations",
        "totalCount": response.get("totalCount", ''),
        "totalPages": response.get("totalPages", ''),
        "nextPage": response.get("nextPage", '')

    }
    result = {
        "id": vendor_id,
        "Observation": {
            "cveId": response.get("cveId", ''),
            "cwe": response.get("cwes", []),
            "asset": response.get("assets", [])
        }
    }
    outputs = {
        "PassiveTotal.ThirdParty(val.id == obj.id)": result,
        "PassiveTotal.Summary.ThirdPartyObservation(val.name == obj.name)": summary
    }
    outputs = remove_empty_elements_for_context(outputs)

    hr_response = get_human_readable_for_my_asi_observations_command(response)

    return CommandResults(
        outputs=outputs,
        readable_output=hr_response,
        raw_response=response
    )


@logger
def list_third_party_attack_surface_vulnerabilities_command(client_obj: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieves the attack surface vulnerability information of the given third party account.

    :param client_obj: client object which is used to get response from API
    :param args: it contain arguments of pt-list-third-party-attack-surface-vulnerabilities
    :return: command output
    """
    vendor_id = arg_to_number(args.get("id", ''))
    if not vendor_id:
        raise ValueError(MESSAGES['REQUIRED_ARGUMENT'].format('id'))

    params = validate_page_and_size_args(args)

    response = client_obj.http_request(method='GET',
                                       url_suffix=URL_SUFFIX["LIST_THIRD_PARTY_ASI_VULNERABILITIES"].format(
                                           vendor_id),
                                       params=params)

    result = response.get("cves")
    if not result:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("third party vulnerabilities"))

    context_data = {
        "id": vendor_id,
        "Vulnerability": result
    }

    summary = {
        "name": "pt-list-third-party-attack-surface-vulnerabilities",
        "totalCount": response.get("totalCount", ''),
        "totalPages": response.get("totalPages", ''),
        "nextPage": response.get("nextPage", '')

    }
    outputs = {
        "PassiveTotal.ThirdParty(val.id == obj.id)": context_data,
        "PassiveTotal.Summary.ThirdPartyVulnerability(val.name == obj.name)": summary
    }
    outputs = remove_empty_elements_for_context(outputs)

    hr_response = get_human_readable_for_my_asi_vulnerabilities_command(result)

    return CommandResults(
        outputs=outputs,
        readable_output=hr_response,
        raw_response=response
    )


def main() -> None:
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    # Commands dict
    commands = {
        'pt-ssl-cert-search': ssl_cert_search_command,
        'pt-get-pdns-details': get_pdns_details_command,
        'pt-whois-search': pt_whois_search_command,
        'pt-get-components': get_components_command,
        'pt-get-trackers': get_trackers_command,
        'pt-get-host-pairs': get_host_pairs_command,
        'pt-get-services': get_services_command,
        'domain': domain_reputation_command,
        'pt-get-whois': pt_get_whois_command,
        'pt-get-cookies': get_cookies_command,
        'pt-get-articles': pt_get_articles_command,
        'pt-get-data-card': get_data_card_summary_command,
        'pt-get-reputation': get_reputation_command,
        'ip': ip_reputation_command,
        'pt-list-intel-profiles': get_intel_profile_command,
        'pt-list-intel-profile-indicators': list_intel_profile_indicators_command,
        'pt-list-third-party-attack-surface': list_third_party_asi_command,
        'pt-list-my-attack-surface-insights': list_my_asi_insights_command,
        'pt-list-third-party-attack-surface-insights': list_third_party_asi_insights_command,
        'pt-list-my-attack-surface-assets': list_my_asi_assets_command,
        'pt-list-my-attack-surface-vulnerable-components': list_my_asi_vulnerable_components_command,
        'pt-list-my-attack-surface-vulnerabilities': list_my_asi_vulnerabilities_command,
        'pt-list-my-attack-surface-observations': list_my_asi_observations_command,
        'pt-list-third-party-attack-surface-assets': list_third_party_asi_assets_command,
        'pt-list-third-party-attack-surface-vulnerable-components': list_third_party_asi_vulnerable_components_command,
        'pt-list-third-party-attack-surface-vulnerabilities': list_third_party_attack_surface_vulnerabilities_command,
        'pt-list-third-party-attack-surface-observations': list_third_party_asi_observations_command,
        'pt-list-my-attack-surfaces': list_my_attack_surfaces_command
    }

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        # Retrieve XSOAR params
        base_url = demisto.params().get('url')
        username = demisto.params().get('username')
        secret = demisto.params().get('secret')
        verify_certificate = not demisto.params().get('insecure', False)
        proxy = demisto.params().get('proxy', False)
        request_timeout = get_request_timeout()

        # prepare client class object
        client = Client(base_url=base_url, request_timeout=request_timeout, verify=verify_certificate, proxy=proxy,
                        auth=(username, secret))

        # This is the call made when pressing the integration Test button.
        if demisto.command() == 'test-module':
            result = test_function(client)
            demisto.results(result)

        elif command in commands:
            args = {key: value.strip() for key, value in demisto.args().items()}
            return_results(commands[command](client, args))

    # Log exceptions
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Error: {str(e)}')


def init():
    if __name__ in ('__main__', '__builtin__', 'builtins'):
        main()


init()
