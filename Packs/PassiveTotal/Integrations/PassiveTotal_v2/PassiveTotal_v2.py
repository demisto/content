from CommonServerPython import *

''' IMPORTS '''

from typing import Dict, Any, List, Union, Tuple, Optional
from requests import ConnectionError
from requests.exceptions import MissingSchema, InvalidSchema
import urllib3
import traceback

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_TIME_FORMAT = '%Y-%m-%d %H:%M:%S'

DATE_FORMAT = '%Y-%m-%d'

INTEGRATION_NAME: str = 'PassiveTotal'

DEFAULT_REQUEST_TIMEOUT = '20'

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
                                  'address, phone, nameserver.'
}

URL_SUFFIX: Dict[str, str] = {
    'TEST_MODULE': '/v2/account',
    'SSL_CERT_SEARCH': '/v2/ssl-certificate/search',
    'GET_PDNS_DETAILS': '/v2/dns/passive',
    'WHOIS_SEARCH': '/v2/whois/search',
    'GET_COMPONENTS': '/v2/host-attributes/components',
    'GET_TRACKERS': '/v2/host-attributes/trackers',
    'GET_HOST_PAIRS': '/v2/host-attributes/pairs'
}

ISO_DATE: Dict[str, str] = {
    DATE_TIME_FORMAT: '"yyyy-mm-dd hh:mm:ss"',
    DATE_FORMAT: '"yyyy-mm-dd"'
}

VALID_DIRECTION_FOR_HOST_PAIRS = ['children', 'parents']

REQUEST_TIMEOUT_MAX_VALUE = 9223372036


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


def get_context_for_whois_commands(domains: List[Dict[str, Any]]) -> Tuple[list, list]:
    """
    Prepare context for whois and domain reputation commands.

    :param domains: list of domains return from response
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
                    score=Common.DBotScore.NONE
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
        outputs_key_field='domain',
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

        domains_response = response.get('results', [])
        if len(domains_response) <= 0:
            continue

        # Creating entry context
        standard_results, custom_context = get_context_for_whois_commands(domains_response)
        command_results.extend(standard_results)
        custom_domain_context += custom_context
        domain_responses += domains_response

    # Creating human-readable
    domain_standard_hr = get_human_readable_for_whois_commands(
        domain_responses,
        is_reputation_command=True
    )

    command_results.insert(0, CommandResults(
        readable_output=domain_standard_hr,
        outputs_prefix='PassiveTotal.Domain',
        outputs_key_field='domain',
        outputs=custom_domain_context,
    ))

    return command_results


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
        'domain': domain_reputation_command
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
            return_results(commands[command](client, demisto.args()))

    # Log exceptions
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Error: {str(e)}')


def init():
    if __name__ in ('__main__', '__builtin__', 'builtins'):
        main()


init()
