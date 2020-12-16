from CommonServerPython import *

''' IMPORTS '''
import urllib3
import traceback
from typing import List, Dict, Any, Tuple, Union
from requests.exceptions import MissingSchema, InvalidSchema

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

INTEGRATION_NAME = 'RiskIQ Digital Footprint'

COMMAND_URL_SUFFIX = {
    'TEST_MODULE': '/v1/whois/riskiq.net',
    'ASSET_CONNECTIONS': 'v1/globalinventory/assets/{}/connected',
    'ASSET_CHANGES_SUMMARY': 'v1/globalinventory/deltas/summary',
    'ASSET_CHANGES': '/v1/globalinventory/deltas',
    'GET_ASSET_BY_UUID': 'v1/globalinventory/assets/id/{}',
    'GET_ASSET_BY_NAME_AND_TYPE': 'v1/globalinventory/assets/{}',
    'ADD_ASSET': '/v1/globalinventory/assets/add',
    'UPDATE_ASSET': '/v1/globalinventory/update',
    'TASK_STATUS': '/v1/globalinventory/task/{}'
}

MESSAGES = {
    'MISSING_SCHEMA_ERROR': 'Invalid API URL. No schema supplied: http(s).',
    'INVALID_SCHEMA_ERROR': 'Invalid API URL. Supplied schema is invalid, supports http(s).',
    'CONNECTION_ERROR': 'Connectivity failed. Check your internet connection or the API URL.',
    'TIMEOUT_ERROR': 'Connection timed out. Check your internet connection or try decreasing the value of the'
                     ' size argument if specified.',
    'PROXY_ERROR': 'Proxy Error - cannot connect to proxy. Either try clearing the \'Use system proxy\' check-box or '
                   'check the host, authentication details and connection details for the proxy.',
    'AUTHENTICATION_ERROR': 'Unauthenticated. Check the configured API token and API secret.',
    'PAGE_NOT_FOUND_ERROR': 'No record(s) found.',
    'INTERNAL_SERVER_ERROR': 'The server encountered an internal error for RiskIQ Digital Footprint and was unable to '
                             'complete your request.',
    'BAD_REQUEST_ERROR': 'An error occurred while fetching the data.',
    'NO_RESPONSE_BODY': 'An unexpected error occurred. Failed to parse json object from response.',
    'SIZE_VALIDATION': 'Size argument must be a positive integer. The value of this argument'
                       ' should be between 1 and 1000.',
    'PAGE_VALIDATION': 'Page argument must be 0 or a positive integer. The index is zero based so the first page'
                       ' is page 0.',
    'INVALID_ASSET_TYPE_ERROR': 'The given value for type is invalid. Valid Types: Domain, Host, IP Address, IP Block,'
                                ' ASN, Page, SSL Cert, Contact. This argument supports a single value only.',
    'INVALID_ASSET_TYPE_AND_ASSET_DETAIL_TYPE_ERROR': 'The given value for type is invalid. '
                                                      'Valid asset types: Domain, Host, IP Address, '
                                                      'IP Block, ASN, Page, SSL Cert, Contact. '
                                                      'Valid asset detail types: '
                                                      'Self Hosted Resource, ThirdParty Hosted Resource.'
                                                      ' This argument supports a single value only.',
    'INVALID_BOOLEAN_VALUE_ERROR': 'The given value for {0} argument is invalid. Valid values: true, false.'
                                   ' This argument supports a single value only.',
    'NO_RECORDS_FOUND': 'No {0} were found for the given argument(s).',
    'INVALID_DATE_FORMAT_ERROR': 'The given value for date is invalid. The accepted format for date is YYYY-MM-DD.'
                                 ' This argument supports a single value only.',
    'INVALID_RANGE_ERROR': 'The given value for range is invalid. Valid values: 1, 7, 30.'
                           ' This argument supports a single value only.',
    'INVALID_RANGE_ERROR_FOR_ASSET_DETAIL_TYPE': 'The given value for range is invalid. '
                                                 'Only single day changes can be shown for {0} type. Valid value: 1.'
                                                 ' This argument supports a single value only.',
    'INVALID_ASSET_TYPE_MEASURE': 'The given value for measure(type of change) is invalid.'
                                  ' Valid options are Added or Removed. This argument supports a single value only.',
    'INVALID_ASSET_DETAIL_TYPE_MEASURE': 'The given value for measure(type of change) is invalid.'
                                         ' Valid options are Added or Changed.'
                                         ' This argument supports a single value only.',
    'ASSET_PAYLOAD_MISSING_KEYS_ERROR': 'Required keys for {} asset(s) are {}. One or more of them are not present'
                                        ' in the asset JSON.',
    'INVALID_ARGUMENTS_ADD_ASSET': 'Argument asset_json cannot be used with other arguments except fail_on_error.',
    'INVALID_ARGUMENTS_UPDATE_ASSET': 'At least one property argument should have a value in order to update the'
                                      ' asset. The property arguments are: state, priority, removed_state, '
                                      'brand, organization, tag and enterprise.',
    'REQUIRED_ARGUMENTS_FOR_ASSET': 'Argument asset_json or arguments name and type are required to {0} an asset.',
    'INVALID_ASSET_STATE_ERROR': 'The given value for state is invalid. '
                                 'Valid States: Candidate, Approved Inventory, Requires Investigation, '
                                 'Dependencies, Monitor Only. This argument supports a single value only.',
    'INVALID_ASSET_PRIORITY_ERROR': 'The given value for priority is invalid. Valid Priority levels: High, Medium,'
                                    ' Low, None. This argument supports a single value only.',
    'INVALID_REMOVED_STATE_ERROR': 'The given value for removed state is invalid. Valid value: Dismissed.'
                                   ' This argument supports a single value only.',
    'INVALID_ACTION_ERROR': 'The given value for action is invalid. Valid values: Add, Remove, Update.'
                            ' This argument supports a single value only.',
    'INVALID_ARGUMENTS_GET_ASSET': 'Argument uuid cannot be used with other arguments except global and recent.',
    'MISSING_REQUIRED_KEYS_FOR_GET_ASSET': 'Required argument(s) uuid or [name, type] to get asset details. One or more'
                                           ' of them are not present.'
}
VALID_ASSET_TYPES = ['DOMAIN', 'HOST', 'IP_ADDRESS', 'IP_BLOCK', 'ASN', 'PAGE', 'SSL_CERT', 'CONTACT']
VALID_ASSET_DETAIL_TYPES = ['SELF_HOSTED_RESOURCE', 'THIRDPARTY_HOSTED_RESOURCE']
VALID_ASSET_TYPE_MEASURES = ['Added', 'Removed']
VALID_ASSET_DETAIL_TYPE_MEASURES = ['Added', 'Changed']
ASSET_TYPE_PLURAL_HR = {
    'DOMAIN': 'Domains',
    'HOST': 'Hosts',
    'IP_ADDRESS': 'IP Addresses',
    'IP_BLOCK': 'IP Blocks',
    'AS': 'ASNs',
    'PAGE': 'Pages',
    'SSL_CERT': 'SSL Certs',
    'CONTACT': 'Contacts'
}
VALID_RANGES = ['1', '7', '30']
ASSET_TYPE_HR = {
    'DOMAIN': 'Domain',
    'HOST': 'Host',
    'IP_ADDRESS': 'IP Address',
    'IP_BLOCK': 'IP Block',
    'AS': 'ASN',
    'PAGE': 'Page',
    'SSL_CERT': 'SSL Cert',
    'CONTACT': 'Contact',
    'SELF_HOSTED_RESOURCE': 'Self Hosted Resource',
    'THIRDPARTY_HOSTED_RESOURCE': 'ThirdParty Hosted Resource'
}
DEEP_LINK_PREFIX = {
    'ASSET_CHANGES_SUMMARY': 'https://app.riskiq.net/a/main/index#/dashboard/inventorychanges',
    'ASSET_CHANGES': 'https://app.riskiq.net/a/main/index#/dashboard/inventorychanges/details'
}
INCOMPLETE_TASK_STATES = ['PENDING', 'RUNNING']
COMPLETE_TASK_STATES = ['COMPLETE', 'INCOMPLETE', 'FAILED', 'WARNING']
VALID_ASSET_STATES = ['Candidate', 'Approved Inventory', 'Requires Investigation', 'Dependencies', 'Monitor Only']
VALID_ASSET_PRIORITY = ['High', 'Medium', 'Low', 'None']
VALID_ACTIONS = ['ADD', 'REMOVE', 'UPDATE']


class Client(BaseClient):
    """
    Client to use in integration with powerful http_request.
    It extends the base client and uses the http_request method for the API request.
    Handle some exceptions externally.
    """

    def __init__(self, base_url: str, verify: bool, proxy: bool, auth: Tuple[str, str], request_timeout: int):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, auth=auth)
        self.request_timeout = request_timeout

    @staticmethod
    def raise_error_according_to_status_code(resp, status_code):
        if status_code == 407:
            demisto.info(f'Response code: {status_code}. {MESSAGES["PROXY_ERROR"]}')
            raise ValueError(MESSAGES['PROXY_ERROR'])

        error_message = ''
        try:
            if resp.json().get('error', ''):
                error_message = f'Reason: {resp.json().get("error", "")}'
        except ValueError:
            raise ValueError(MESSAGES['NO_RESPONSE_BODY'])
        status_code_message_map = {
            400: f'{MESSAGES["BAD_REQUEST_ERROR"]} {error_message}',
            401: MESSAGES['AUTHENTICATION_ERROR'],
            404: f'{MESSAGES["PAGE_NOT_FOUND_ERROR"]} {error_message}'
        }
        if status_code in status_code_message_map:
            demisto.info(f'Response code: {status_code}. {status_code_message_map[status_code]}')
            raise ValueError(status_code_message_map[status_code])
        elif status_code >= 500:
            demisto.info(f'Response code: {status_code}. {MESSAGES["INTERNAL_SERVER_ERROR"]} {error_message}')
            raise ValueError(MESSAGES['INTERNAL_SERVER_ERROR'])
        else:
            resp.raise_for_status()

    def http_request(self, method: str, url_suffix: str, params=None, headers=None, json_data=None):
        """
        Override http_request method from BaseClient class. This method will print an error based on status code
        and exceptions.

        :param method: The HTTP method, for example: GET, POST, and so on.
        :param url_suffix: The API endpoint.
        :param params: URL parameters to specify the query.
        :param headers: Headers to send in the request. If None, will use self._headers.
        :param json_data: The dictionary to send in a 'POST' request.
        :return: List of dictionaries, a Dictionary or an error message fetched as
         response of the API call made.
        """

        try:
            resp = self._http_request(method=method, url_suffix=url_suffix, headers=headers, params=params,
                                      json_data=json_data, timeout=self.request_timeout, resp_type='response',
                                      ok_codes=(200, 400, 401, 404, 407, 500), proxies=handle_proxy())
        except MissingSchema:
            raise ValueError(MESSAGES['MISSING_SCHEMA_ERROR'])

        except InvalidSchema:
            raise ValueError(MESSAGES['INVALID_SCHEMA_ERROR'])

        except DemistoException as e:
            if 'ProxyError' in str(e):
                raise ConnectionError(MESSAGES['PROXY_ERROR'])
            elif 'ConnectTimeout' in str(e) or 'ReadTimeoutError' in str(e):
                raise ConnectionError(MESSAGES['TIMEOUT_ERROR'])
            elif 'ConnectionError' in str(e):
                raise ConnectionError(MESSAGES['CONNECTION_ERROR'])
            else:
                raise e

        status_code = resp.status_code

        if status_code != 200:
            self.raise_error_according_to_status_code(resp, status_code)

        return resp.json()


''' HELPER FUNCTIONS '''


def remove_empty_entities(d):
    """
    Recursively remove empty lists, empty dicts, or None elements from a dictionary.

    :param d: Input dictionary.
    :return: Dictionary with all empty lists, and empty dictionaries removed.
    """

    def empty(x):
        return x is None or x == {} or x == [] or x == ''

    if not isinstance(d, (dict, list)):
        return d
    elif isinstance(d, list):
        return [value for value in (remove_empty_entities(value) for value in d) if not empty(value)]
    else:
        return {key: value for key, value in ((key, remove_empty_entities(value))
                                              for key, value in d.items()) if not empty(value)}


def get_timeout_and_size(size) -> Tuple[int, int]:
    """
    Validate and return the request_timeout and size parameters.
    The parameters must be a positive integer.
    Default value is set to 40 seconds for API request timeout and 2000 for size.
    :param size: Value of size argument passed by the user
    :return: request_timeout & size values or message describing error that occurred in while validating
    """

    try:
        size = int(size)
        if size <= 0 or size > 1000:
            raise ValueError(MESSAGES['SIZE_VALIDATION'])
    except ValueError:
        raise ValueError(MESSAGES['SIZE_VALIDATION'])

    request_timeout = 10
    if 50 < size <= 500:
        request_timeout = 30
    elif size > 500:
        request_timeout = 60
    return request_timeout, size


def nested_to_flat(src: Dict[str, Any], key: str) -> Dict[str, Any]:
    """
    Convert nested dictionary to flat by contact the keys. Also converts keys in pascal string format.

    :param src: sub-dictionary that needs to convert from nested to flat. (e.g. "foo": {"bar": "some-value"})
    :param key: main key of sub-dictionary (e.g "foo")
    :return: flat dictionary with pascal formatted keys (e.g. {"FooBar": "some-value"})
    """

    flat_dict: Dict[str, str] = {}
    for sub_key, sub_value in src.items():
        parent_key = key
        if ' ' in sub_key:
            sub_key = ''.join(sub_key.split(' '))
        pascal_key = f'{parent_key}{sub_key[0].upper() + sub_key[1:]}'
        if parent_key in sub_key:
            pascal_key = sub_key
        flat_dict[pascal_key] = sub_value

    return flat_dict


def prepare_context_dict(response_dict: Dict[str, Any],
                         keys_with_hierarchy: Union[tuple, str] = (),
                         exclude_keys: Union[tuple, str] = ()) -> Dict[str, str]:
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


def validate_asset_connections_args_and_get_params(args: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """
    Validate the arguments passed by the user and prepare params

    :param args: arguments passed by the user
    :return: type_args, params: type of asset and params dictionary to be passed in the API Call
    """
    type_arg = str(args.get('type')).replace(' ', '_').upper()
    if type_arg not in VALID_ASSET_TYPES:
        raise ValueError(MESSAGES['INVALID_ASSET_TYPE_ERROR'])
    if type_arg == 'ASN':
        type_arg = 'AS'

    # prepare params
    params: Dict[str, Any] = {'name': args.get('name')}
    global_arg = args.get('global', '').lower()
    if global_arg:
        try:
            params['global'] = argToBoolean(global_arg)
        except ValueError:
            raise ValueError(MESSAGES['INVALID_BOOLEAN_VALUE_ERROR'].format('global'))

    page = args.get('page')
    if page:
        try:
            page = int(page)
            if page < 0:
                raise ValueError(MESSAGES['PAGE_VALIDATION'])
            params['page'] = page
        except ValueError:
            raise ValueError(MESSAGES['PAGE_VALIDATION'])

    size = args.get('size')
    if size:
        params['size'] = size

    return type_arg, params


def convert_list_to_comma_separated_string(values: List[Dict[str, Any]], key: str) -> str:
    """
    Retrieve values of an attribute in comma separated manner from response to populate human readable output

    :param: values: list of attributes fetched from response
    :param: key: key to consider the value for
    :return: a string containing values of passed attribute in comma separated manner
    """
    value_list = set()
    for value in values:
        value_list.add(value.get(key, ''))
    return ', '.join(value_list)


def get_comma_separated_values_only_current(values: List[Dict[str, Any]], key: str) -> str:
    """
    Retrieve values of an attribute in comma separated manner from response to populate human readable output

    :param: values: list of attributes fetched from response
    :param: key: the key to fetch the value of
    :return: a string containing values of passed attribute in comma separated manner
    """
    value_list = set()
    for value in values:
        if value.get('current'):
            value_list.add(str(value.get(key, '')))
    return ', '.join(value_list)


def get_attribute_details_hr(attributes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Retrieve nested properties from list of a specific attribute fetched in response to populate human readable

    :param attributes: list of properties associated with an attribute of an asset
    :return: list of dictionary containing attributes to be populated in Context Data on XSOAR
    """
    return [{
        'Name': attribute.get('value', ''),
        'First Seen (GMT)': epochToTimestamp(attribute.get('firstSeen', '')) if attribute.get('firstSeen') else None,
        'Last Seen (GMT)': epochToTimestamp(attribute.get('lastSeen', '')) if attribute.get('lastSeen') else None,
        'Current': attribute.get('current'),
        'Recent': attribute.get('recent')
    } for attribute in attributes]


def get_asset_connections_hr(asset_details: Dict[str, Any]) -> Dict[str, Any]:
    """
    Retrieve attributes from response to populate human readable output

    :param asset_details: attributes of all the assets fetched from response
    :return: dictionary containing attributes to be shown in Human Readable format on XSOAR
    """
    return {
        'Name': asset_details.get('name', ''),
        'State': asset_details.get('state', ''),
        'First Seen (GMT)': epochToTimestamp(asset_details.get('firstSeen', '')) if asset_details.get(
            'firstSeen') else None,
        'Last Seen (GMT)': epochToTimestamp(asset_details.get('lastSeen', '')) if asset_details.get(
            'lastSeen') else None,
        'Tag(s)': convert_list_to_comma_separated_string(asset_details.get('tags', []), 'name')
    }


def get_asset_connections_outputs(resp: Dict[str, Any],
                                  total_elements: Dict[str, Any]) -> Tuple[str, List[CommandResults]]:
    """
    Generates all outputs for asset_connections_command

    :param resp: response that is fetched by making the API call using the acquired arguments
    :param total_elements: Dictionary of total_elements fetched for each asset type
    :return: hr, standard_ec, custom_ec: Human readable, Standard Context and Custom Context outputs
    """
    hr = ''
    asset_type_standard_context_map = {
        'DOMAIN': get_standard_context_domain,
        'IP_ADDRESS': get_standard_context_ip,
        'PAGE': get_standard_context_url
    }
    command_results: List[CommandResults] = []

    hr += '### CONNECTED ASSETS\n'
    for asset_type in total_elements:
        if total_elements.get(asset_type) and total_elements.get(asset_type) != 0:
            for asset_details in resp.get(asset_type, {}).get('content', []):
                asset_connections_standard_context = None
                asset_connections_custom_context = asset_details
                if asset_type in asset_type_standard_context_map:
                    asset_connections_standard_context = asset_type_standard_context_map[asset_type](asset_details)
                asset_connections_hr = tableToMarkdown(f'{asset_type.replace("_", " ").capitalize()} Details',
                                                       get_asset_connections_hr(asset_details),
                                                       ['Name', 'State', 'First Seen (GMT)', 'Last Seen (GMT)',
                                                        'Tag(s)'], removeNull=True)
                custom_ec = createContext(remove_empty_entities(asset_connections_custom_context), removeNull=True)
                command_results.append(CommandResults(
                    outputs_prefix='RiskIQDigitalFootprint.Asset',
                    outputs_key_field='uuid',
                    outputs=custom_ec,
                    indicator=asset_connections_standard_context,
                    readable_output=asset_connections_hr,
                    raw_response=resp
                ))
            hr += f'### Total {ASSET_TYPE_PLURAL_HR.get(asset_type)}:' \
                  f' {resp.get(asset_type, {}).get("totalElements")}\n'
            hr += f'### Fetched {ASSET_TYPE_PLURAL_HR.get(asset_type)}: {len(asset_connections_hr)}\n'
    return hr, command_results


def validate_asset_changes_summary_args(date_arg: str, range_arg: str) -> Tuple[str, Any]:
    """
    Validate the arguments passed by the user

    :param date_arg: run date when the changes were identified
    :param range_arg: the time period for which the changes summary is to be fetched
    :return: date_arg, range_arg: date and range arguments or message describing error that occurred
     in parameter validation
    """
    try:
        if date_arg and date_arg != datetime.strptime(date_arg, '%Y-%m-%d').strftime('%Y-%m-%d'):
            raise ValueError(MESSAGES['INVALID_DATE_FORMAT_ERROR'])
    except ValueError:
        raise ValueError(MESSAGES['INVALID_DATE_FORMAT_ERROR'])
    if range_arg and range_arg not in VALID_RANGES:
        raise ValueError(MESSAGES['INVALID_RANGE_ERROR'])
    return date_arg, range_arg


def prepare_hr_cell_for_changes_summary(attribute: List[Dict[str, Any]], order: int) -> str:
    """
    Prepare cell information for each range respectively

    :param order: order of that range in attribute list
    :param attribute: attribute for which hr is to be prepared
    :return: attribute information in human readable format
    """
    hr_cell_info = []

    # Fetch all keys
    added = attribute[order].get('added')
    changed = attribute[order].get('changed')
    removed = attribute[order].get('removed')
    count = attribute[order].get('count')
    difference = attribute[order].get('difference')
    if added:
        hr_cell_info.append(f'**Added:** {added}')
    if changed:
        hr_cell_info.append(f'**Changed:** {changed}')
    if removed:
        hr_cell_info.append(f'**Removed:** {removed}')
    if count:
        hr_cell_info.append(f'**Count:** {count}')
    if difference:
        hr_cell_info.append(f'**Difference:** {difference}')
    return '\n'.join(hr_cell_info)


def get_asset_changes_summary_hr(summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Retrieves all attributes of summary and populates human_readable for asset_changes_summary

    :param summary: nested dictionary containing all attributes of summary
    :return: human_readable: human readable for asset_changes_summary
    """
    human_readable = []
    for delta in summary.get('deltas', []):
        result = {
            'range_1': prepare_hr_cell_for_changes_summary(delta.get('aggregations', []), 0)
            if delta.get('aggregations') else '',
            'range_7': prepare_hr_cell_for_changes_summary(delta.get('aggregations', []), 1)
            if delta.get('aggregations') else '',
            'range_30': prepare_hr_cell_for_changes_summary(delta.get('aggregations', []), 2)
            if delta.get('aggregations') else ''
        }
        if not all(value == '' for value in result.values()):
            human_readable_dict = {'Asset Type': f'**{ASSET_TYPE_HR.get(delta.get("type", ""), "")}**',
                                   '1 Day': result['range_1'],
                                   '7 Days': result['range_7'],
                                   '30 Days': result['range_30']
                                   }
            human_readable.append(human_readable_dict)
    return human_readable


def prepare_deep_link_for_asset_changes_summary(resp: List[Dict[str, Any]], date_arg: str, range_arg: str) -> str:
    """
    Generates deep link for asset-changes-summary command to redirect to RiskIQ Platform.

    :param resp: response that is fetched by making the API call using the acquired arguments
    :param date_arg: date argument passed by user to build redirect URL to RiskIQ platform.
    :param range_arg: range argument passed by user to build redirect URL to RiskIQ platform.
    :return: deep_link: Deep link to RiskIQ platform
    """
    last_run_date = resp[0].get('runDate', '')
    deep_link = f'{DEEP_LINK_PREFIX["ASSET_CHANGES_SUMMARY"]}/{last_run_date}'
    if date_arg and range_arg:
        deep_link = f'{DEEP_LINK_PREFIX["ASSET_CHANGES_SUMMARY"]}/{date_arg}/{range_arg}'
    elif date_arg:
        deep_link = f'{DEEP_LINK_PREFIX["ASSET_CHANGES_SUMMARY"]}/{date_arg}'
    elif range_arg:
        deep_link += f'/{range_arg}'
    return deep_link


def get_asset_changes_summary_outputs(resp: List[Dict[str, Any]], date_arg: str, range_arg: str) \
        -> Tuple[str, List[Dict[str, Any]]]:
    """
    Generates all outputs for asset_changes_summary_command

    :param resp: response that is fetched by making the API call using the acquired arguments
    :param date_arg: date argument passed by user to build redirect URL to RiskIQ platform.
    :param range_arg: range argument passed by user to build redirect URL to RiskIQ platform.
    :return: hr, custom_ec: Human readable and Custom Context outputs
    """
    hr = ''
    custom_ec: List[Dict[str, Any]] = []
    if resp:
        deep_link = encode_string_results(prepare_deep_link_for_asset_changes_summary(resp, date_arg, range_arg))
        hr += f'### [INVENTORY CHANGES]({deep_link})\n#### Note: If the range argument is specified, a list of' \
              f' table(s) containing a daily, weekly and monthly changes summary identified over the given period of' \
              f' time will be presented. For example, there will be an individual table for all the dates from the' \
              f' last run date to the date provided in the range value representing a daily, weekly and monthly' \
              f' changes summary.\n'
        for summary in resp:
            asset_changes_summary_hr = get_asset_changes_summary_hr(summary)
            hr += tableToMarkdown(f'Date of the run in which following changes were identified:'
                                  f' {summary.get("runDate", "")}', asset_changes_summary_hr,
                                  ['Asset Type', '1 Day', '7 Days', '30 Days'], removeNull=True)
        custom_ec = createContext(remove_empty_entities(resp), removeNull=True)
    return hr, custom_ec


def get_standard_context_domain(record: Dict[str, Any]) -> Common.Domain:
    """
    Prepare standard context for Domain
    :param record: The record for which context is to be prepared
    :return: Common.Domain
    """
    return Common.Domain(
        domain=record.get('name', ''),
        organization=convert_list_to_comma_separated_string(record.get('organizations', []), 'name')
        if record.get('organizations') else None,
        dbot_score=Common.DBotScore(
            indicator=record.get('name', ''),
            indicator_type=DBotScoreType.DOMAIN,
            integration_name=INTEGRATION_NAME,
            score=Common.DBotScore.NONE
        )
    )


def get_standard_context_domain_for_get_asset(record: Dict[str, Any]) -> list:
    """
    Prepare standard context for domain for get asset command
    :param record: The record for which context is to be prepared
    :return: List[Common.Domain]
    """
    whois = record.get('asset', {}).get('whois', {})
    return [Common.Domain(
        domain=record.get('name', ''),
        organization=convert_list_to_comma_separated_string(record.get('organizations', []), 'name')
        if record.get('organizations') else None,
        domain_status=whois.get('domainStatus', ''),
        name_servers=', '.join(whois.get('nameservers', [])),
        registrant_email=whois.get('registrant', {}).get('email', ''),
        registrant_name=whois.get('registrant', {}).get('organization', ''),
        registrant_country=whois.get('registrant', {}).get('country', ''),
        registrant_phone=whois.get('registrant', {}).get('phone', ''),
        registrar_name=whois.get('registrarName', ''),
        registrar_abuse_email=whois.get('registrarEmail', ''),
        registrar_abuse_phone=whois.get('registrarPhone', ''),
        admin_name=whois.get('admin', {}).get('organization', ''),
        admin_email=whois.get('admin', {}).get('email', ''),
        admin_country=whois.get('admin', {}).get('country', ''),
        admin_phone=whois.get('admin', {}).get('phone', ''),
        dbot_score=Common.DBotScore(
            indicator=record.get('name', ''),
            indicator_type=DBotScoreType.DOMAIN,
            integration_name=INTEGRATION_NAME,
            score=Common.DBotScore.NONE
        )
    )]


def get_standard_context_host_for_get_asset(record: Dict[str, Any]) -> list:
    """
    Prepare standard context for host for get asset command
    :param record: The record for which context is to be prepared
    :return: List[Common.CVE]
    """
    standard_context_host = []
    for web_component in record.get('asset', {}).get('webComponents', []):
        for cve in web_component.get('cves', []):
            standard_context_host.append(
                Common.CVE(
                    id=cve.get('name', ''),
                    cvss=cve.get('cvssScore', ''),
                    published='',
                    modified='',
                    description=''
                )
            )
    return standard_context_host


def get_standard_context_ip(record: Dict[str, Any]) -> Common.IP:
    """
    Prepare standard context for ip
    :param record: The record for which context is to be prepared
    :return: Common.IP
    """
    return Common.IP(
        ip=record.get('name'),
        dbot_score=Common.DBotScore(
            indicator=record.get('name', ''),
            indicator_type=DBotScoreType.IP,
            integration_name=INTEGRATION_NAME,
            score=Common.DBotScore.NONE
        )
    )


def get_standard_context_ip_for_get_asset(record: Dict[str, Any]) -> list:
    """
    Prepare standard context for ip for get asset command
    :param record: The record for which context is to be prepared
    :return: List[Union[Common.IP, Common.CVE]]
    """
    standard_context_ip: List[Union[Common.IP, Common.CVE]] = [Common.IP(
        ip=record.get('name'),
        asn=convert_list_to_comma_separated_string(record.get('asset', {}).get('asns', []), 'name'),
        dbot_score=Common.DBotScore(
            indicator=record.get('name', ''),
            indicator_type=DBotScoreType.IP,
            integration_name=INTEGRATION_NAME,
            score=Common.DBotScore.NONE
        )
    )]

    for web_component in record.get('asset', {}).get('webComponents', []):
        for cve in web_component.get('cves', []):
            standard_context_ip.append(
                Common.CVE(
                    id=cve.get('name', ''),
                    cvss=cve.get('cvssScore', ''),
                    published='',
                    modified='',
                    description=''
                )
            )

    return standard_context_ip


def get_standard_context_url(record: Dict[str, Any]) -> Common.URL:
    """
    Prepare standard context for url
    :param record: The record for which context is to be prepared
    :return: Common.URL
    """
    return Common.URL(
        url=record.get('name'),
        dbot_score=Common.DBotScore(
            indicator=record.get('name', ''),
            indicator_type=DBotScoreType.URL,
            integration_name=INTEGRATION_NAME,
            score=Common.DBotScore.NONE
        )
    )


def get_standard_context_url_for_get_asset(record: Dict[str, Any]) -> list:
    """
    Prepare standard context for url for get asset command
    :param record: The record for which context is to be prepared
    :return: List[Union[Common.URL, Common.CVE]]
    """
    standard_context_url: List[Union[Common.URL, Common.CVE]] = [Common.URL(
        url=record.get('name'),
        dbot_score=Common.DBotScore(
            indicator=record.get('name', ''),
            indicator_type=DBotScoreType.URL,
            integration_name=INTEGRATION_NAME,
            score=Common.DBotScore.NONE
        )
    )]

    for web_component in record.get('asset', {}).get('webComponents', []):
        for cve in web_component.get('cves', []):
            standard_context_url.append(
                Common.CVE(
                    id=cve.get('name', ''),
                    cvss=cve.get('cvssScore', ''),
                    published='',
                    modified='',
                    description=''
                )
            )

    return standard_context_url


def get_standard_context_file(record: Dict[str, Any]) -> Common.File:
    """
    Prepare standard context for file
    :param record: The record for which context is to be prepared
    :return: Common.File
    """
    return Common.File(
        name=record.get('resource', ''),
        size=int(record.get('responseBodySize', '')),
        md5=record.get('md5', ''),
        file_type=record.get('contentType', ''),
        hostname=record.get('resourceHost', ''),
        dbot_score=Common.DBotScore(
            indicator=record.get('resource', ''),
            indicator_type=DBotScoreType.URL,
            integration_name=INTEGRATION_NAME,
            score=Common.DBotScore.NONE
        )
    )


def get_asset_changes_context_data(asset_changes_records: List[Dict[str, Any]], asset_type: str) \
        -> Tuple[List[CommandResults], List[Dict[str, Any]]]:
    """
    Prepare context data for asset changes command
    :param asset_changes_records: Asset changes response
    :param asset_type: The type of asset for which changes are fetched
    :return: Standard entry context and Custom entry context
    """
    ioc_command_results: List[CommandResults] = []
    asset_type_standard_context_map = {
        'DOMAIN': get_standard_context_domain,
        'IP_ADDRESS': get_standard_context_ip,
        'PAGE': get_standard_context_url,
        'SELF_HOSTED_RESOURCE': get_standard_context_file,
        'THIRDPARTY_HOSTED_RESOURCE': get_standard_context_file
    }
    for record in asset_changes_records:

        # Create standard context
        if asset_type in asset_type_standard_context_map:
            indicator = asset_type_standard_context_map[asset_type](record)
            ioc_command_results.append(CommandResults(
                indicator=indicator
            ))

    custom_ec = createContext(data=remove_empty_entities(asset_changes_records), removeNull=True)
    return ioc_command_results, custom_ec


def prepare_deep_link_for_asset_changes(last_run_date: str, asset_type: str, measure: str,
                                        date_arg: str, range_arg: str) -> str:
    """
    Generates deep link for asset-changes command to redirect to RiskIQ Platform.
    :param last_run_date: last run date fetched from the response.
    :param asset_type: The type of asset for which changes are to be fetched
    :param measure: The type operation which captured change in asset. Eg. Added, Removed, Changed
    :param date_arg: run date when the changes were identified
    :param range_arg: the time period for which the changes summary is to be fetched
    :return: deep_link: Deep link to RiskIQ platform
    """
    measure = measure.upper()
    deep_link = f'{DEEP_LINK_PREFIX["ASSET_CHANGES"]}/date={last_run_date}&measure={measure}&range=1&type={asset_type}'

    if date_arg and range_arg:
        deep_link = f'{DEEP_LINK_PREFIX["ASSET_CHANGES"]}/date={date_arg}&measure={measure}&range={range_arg}' \
                    f'&type={asset_type}'
    elif date_arg:
        deep_link = f'{DEEP_LINK_PREFIX["ASSET_CHANGES"]}/date={date_arg}&measure={measure}&range=1&type={asset_type}'
    elif range_arg:
        deep_link = f'{DEEP_LINK_PREFIX["ASSET_CHANGES"]}/date={last_run_date}&measure={measure}&range={range_arg}' \
                    f'&type={asset_type}'

    if asset_type in VALID_ASSET_DETAIL_TYPES:
        deep_link += '&deltaType=micro'

    return deep_link


def get_asset_changes_hr(asset_changes_records: List[Dict[str, Any]], asset_type: str, measure: str) -> str:
    """
    Prepares human readable text for asset changes command
    :param asset_changes_records: Asset changes response
    :param asset_type: The type of asset for which changes are to be fetched
    :param measure: The type operation which captured change in asset. Eg. Added, Removed, Changed
    :return: Human readable for asset changes command
    """
    hr_title = f'Fetched: {len(asset_changes_records)}'
    hr_headers = []
    hr_table = []

    if asset_type in VALID_ASSET_TYPES:
        for record in asset_changes_records:
            hr_row = {
                'Name': record.get('name', ''),
                'Description': record.get('description', ''),
                'State': record.get('state', ''),
                'Priority': record.get('priority', ''),
                'Measure': record.get('measure', ''),
                'RunDate': record.get('runDate', '')
            }
            hr_table.append(hr_row)
        hr_headers = ['Name', 'Description', 'State', 'Priority', 'Measure', 'RunDate']

    elif asset_type in VALID_ASSET_DETAIL_TYPES:
        for record in asset_changes_records:
            hr_row = {
                'Type': record.get('type', ''),
                'Parent Host': record.get('name', ''),
                'Resource Host': record.get('resourceHost', ''),
                'Resource': record.get('resource', ''),
                'MD5': record.get('md5', ''),
                'Description': record.get('description', ''),
                'RunDate': record.get('runDate', '')
            }
            hr_table.append(hr_row)
        hr_headers = ['Type', 'Parent Host', 'Resource Host', 'Resource',
                      'MD5', 'Description', 'RunDate']
    return tableToMarkdown(hr_title, hr_table, hr_headers, removeNull=True)


def validate_date_for_asset_changes(date_arg: str) -> str:
    """
    Validates the date argument for asset changes command
    :param date_arg: date argument passed by the user
    :return: date if valid else raise ValueError
    """
    date_text = date_arg
    try:
        if date_text != datetime.strptime(date_text, '%Y-%m-%d').strftime('%Y-%m-%d'):
            raise ValueError(MESSAGES['INVALID_DATE_FORMAT_ERROR'])
    except ValueError:
        raise ValueError(MESSAGES['INVALID_DATE_FORMAT_ERROR'])
    return date_text


def validate_range_for_asset_changes(asset_type: str, range_arg: str) -> int:
    """
    Validates the range argument for asset changes command
    :param asset_type: asset type argument passed by the user
    :param range_arg: range argument passed by the user
    :return: range if valid else raise ValueError
    """
    valid_range_arg = 0
    if asset_type in VALID_ASSET_TYPES:
        if range_arg not in VALID_RANGES:
            raise ValueError(MESSAGES['INVALID_RANGE_ERROR'])
        valid_range_arg = int(range_arg)
    elif asset_type in VALID_ASSET_DETAIL_TYPES:
        if range_arg != '1':
            raise ValueError(MESSAGES['INVALID_RANGE_ERROR_FOR_ASSET_DETAIL_TYPE'].format(ASSET_TYPE_HR[asset_type]))
        valid_range_arg = int(range_arg)
    return valid_range_arg


def validate_measure_for_asset_changes(asset_type: str, measure: str) -> str:
    """
    Validates the range argument for asset changes command
    :param asset_type: asset type argument passed by the user
    :param measure: measure argument passed by the user
    :return: measure if valid else raise ValueError
    """
    valid_measure = ''
    if asset_type in VALID_ASSET_TYPES:
        if measure not in VALID_ASSET_TYPE_MEASURES:
            raise ValueError(MESSAGES['INVALID_ASSET_TYPE_MEASURE'])
        valid_measure = measure
    elif asset_type in VALID_ASSET_DETAIL_TYPES:
        if measure not in VALID_ASSET_DETAIL_TYPE_MEASURES:
            raise ValueError(MESSAGES['INVALID_ASSET_DETAIL_TYPE_MEASURE'])
        valid_measure = measure

    return valid_measure


def validate_page_for_asset_changes(page: str) -> int:
    try:
        valid_page = int(page)
        if valid_page < 0:
            raise ValueError(MESSAGES['PAGE_VALIDATION'])
        return valid_page
    except ValueError:
        raise ValueError(MESSAGES['PAGE_VALIDATION'])


def get_asset_changes_params(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validates the command arguments and creates parameter dictionary
    :param args: The command arguments
    :return: parameters for API call or message describing error that occurred in parameter validation
    """
    params: Dict[str, Any] = {}

    asset_type = args.get('type', '').replace(' ', '_').upper()
    if asset_type not in VALID_ASSET_DETAIL_TYPES and asset_type not in VALID_ASSET_TYPES:
        raise ValueError(MESSAGES['INVALID_ASSET_TYPE_AND_ASSET_DETAIL_TYPE_ERROR'])
    else:
        if asset_type == 'ASN':
            params['type'] = 'AS'
        else:
            params['type'] = asset_type

    if args.get('date'):
        params['date'] = validate_date_for_asset_changes(args.get('date', ''))

    if args.get('range'):
        params['range'] = validate_range_for_asset_changes(asset_type, args.get('range', ''))

    if args.get('measure'):
        params['measure'] = validate_measure_for_asset_changes(asset_type, args.get('measure', ''))

    for argument in ['brand', 'organization', 'tag', 'size']:
        if args.get(argument):
            params[argument] = args.get(argument, '')

    page = args.get('page')
    if page:
        params['page'] = validate_page_for_asset_changes(page)

    return params


def validate_and_fetch_get_asset_arguments(args: Dict[str, Any]) -> Tuple[str, str]:
    """
    Validates the command arguments and returns asset_type
    :param args: The command arguments
    :return asset_type: asset_type fetched from the arguments
    """
    if 'uuid' in args.keys() and args.keys() - {'uuid', 'global', 'recent'} != set():
        raise ValueError(MESSAGES['INVALID_ARGUMENTS_GET_ASSET'])

    uuid = args.get('uuid', '')
    asset_type = args.get('type', '').replace(' ', '_').upper()
    name = args.get('name', '')
    if not (uuid or (asset_type and name)):
        raise ValueError(MESSAGES['MISSING_REQUIRED_KEYS_FOR_GET_ASSET'])

    if asset_type:
        if asset_type not in VALID_ASSET_TYPES:
            raise ValueError(MESSAGES['INVALID_ASSET_TYPE_ERROR'])
        if asset_type == 'ASN':
            asset_type = 'AS'

    return uuid, asset_type


def get_asset_params(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validates the command arguments and creates parameter dictionary
    :param args: The command arguments
    :return: parameters for API call or message describing error that occurred in parameter validation
    """
    params: Dict[str, Any] = {}
    name = args.get('name', '')
    global_arg = args.get('global', '')
    recent = args.get('recent', '')
    size = args.get('size')

    if name:
        params['name'] = name
        if size:
            params['size'] = size
    if global_arg:
        global_arg = global_arg.lower()
        try:
            global_arg = argToBoolean(global_arg)
            params['global'] = global_arg
        except ValueError:
            raise ValueError(MESSAGES['INVALID_BOOLEAN_VALUE_ERROR'].format('global'))

    if recent:
        recent = recent.lower()
        try:
            recent = argToBoolean(recent)
            params['recent'] = recent
        except ValueError:
            raise ValueError(MESSAGES['INVALID_BOOLEAN_VALUE_ERROR'].format('recent'))

    return params


def get_attribute_details_from_given_lists(source_dict: Dict[str, Any], key: str, lists: List[str]) -> str:
    """
    Retrieve attribute details from given lists of various properties

    :param source_dict: The source dictionary from which attributes are to be fetched
    :param key: The attribute to be fetched from the lists
    :param lists: The lists from which the attribute value is to be fetched
    :return: value: value of the requested attribute
    """
    value = ''
    for single_list in source_dict and lists:
        if key in source_dict.get(single_list, []):
            value += f'{single_list.capitalize()}: {source_dict.get(single_list, []).get(key, "")}\n'
    return value


def get_whois_hr(whois_details: Dict[str, Any]) -> str:
    """
    Retrieves the human readable for whois details of the asset

    :param whois_details: Dictionary containing whois details of the asset
    :return: Human readable of whois details
    """
    whois_details_hr = {
        'Whois Server': whois_details.get('whoisServer', ''),
        'Registrar': whois_details.get('registrarName', ''),
        'Email': get_attribute_details_from_given_lists(whois_details, 'email',
                                                        ['registrant', 'admin', 'technical', 'billing']),
        'Name': get_attribute_details_from_given_lists(whois_details, 'name',
                                                       ['registrant', 'admin', 'technical', 'billing']),
        'Organization': get_attribute_details_from_given_lists(whois_details, 'organization',
                                                               ['registrant', 'admin', 'technical', 'billing']),
        'Street': get_attribute_details_from_given_lists(whois_details, 'street',
                                                         ['registrant', 'admin', 'technical', 'billing']),
        'City': get_attribute_details_from_given_lists(whois_details, 'city',
                                                       ['registrant', 'admin', 'technical', 'billing']),
        'State': get_attribute_details_from_given_lists(whois_details, 'state',
                                                        ['registrant', 'admin', 'technical', 'billing']),
        'Postal Code': get_attribute_details_from_given_lists(whois_details, 'zip',
                                                              ['registrant', 'admin', 'technical', 'billing']),
        'Country': get_attribute_details_from_given_lists(whois_details, 'country',
                                                          ['registrant', 'admin', 'technical', 'billing']),
        'Phone': get_attribute_details_from_given_lists(whois_details, 'phone',
                                                        ['registrant', 'admin', 'technical', 'billing']),
        'Name Servers': ', '.join(whois_details.get('nameservers', []))
    }
    return tableToMarkdown('WHOIS', whois_details_hr, ['Whois Server', 'Registrar', 'Email', 'Name',
                                                       'Organization', 'Street', 'City', 'State', 'Postal Code',
                                                       'Country', 'Phone', 'Name Servers'], removeNull=True)


def get_name_and_mail_server_hr(asset_details: Dict[str, Any]) -> str:
    """
    Retrieves the human readable for name and mail server details of the asset

    :param asset_details: Dictionary containing name and mail server details of the asset
    :return: Human readable of name and mail server details
    """
    name_and_mail_server_hr = ''
    for attribute in ['nameServers', 'mailServers']:
        attribute_details = asset_details.get(attribute, [])
        if attribute_details:
            name_and_mail_server_hr += tableToMarkdown(pascalToSpace(attribute),
                                                       get_attribute_details_hr(attribute_details),
                                                       ['Name', 'First Seen (GMT)', 'Last Seen (GMT)', 'Recent',
                                                        'Current'],
                                                       removeNull=True)
    return name_and_mail_server_hr


def get_asset_domain_hr(asset_details: Dict[str, Any]) -> str:
    """
    Retrieves the human readable for Domain

    :param asset_details: Dictionary containing asset details of the domain
    :return: Human readable of all the domain details
    """
    asset_specific_hr = ''
    asset_specific_details = {
        'Domain Name': asset_details.get('domain', ''),
        'Parked': get_comma_separated_values_only_current(asset_details.get('parkedDomain', []), 'value'),
        'Alexa Rank': asset_details.get('alexaRank', ''),
        'Domain Status': convert_list_to_comma_separated_string(asset_details.get('domainStatuses', []), 'value')
    }

    if not all(value == '' or value == [] for value in asset_specific_details.values()):
        asset_specific_hr += tableToMarkdown('Domain Details', asset_specific_details,
                                             ['Domain Name', 'Parked', 'Alexa Rank', 'Domain Status'],
                                             removeNull=True)

    if asset_details.get('nameServers') or asset_details.get('mailServers'):
        asset_specific_hr += get_name_and_mail_server_hr(asset_details)

    who_is_details = asset_details.get('whois', {})
    if who_is_details:
        asset_specific_hr += get_whois_hr(who_is_details)

    return asset_specific_hr


def get_ip_hr(ip_details: List[Dict[str, Any]]) -> str:
    """
    Retrieve nested properties from list of ipAddresses fetched in response to populate human readable

    :param ip_details: list of properties associated with ipAddresses of an asset
    :return: Human Readable of ipAddresses to be populated on XSOAR
    """
    ip_hr = [{
        'Value': ip_info.get('value', ''),
        'First Seen (GMT)': epochToTimestamp(ip_info.get('firstSeen', '')) if ip_info.get('firstSeen') else None,
        'Last Seen (GMT)': epochToTimestamp(ip_info.get('lastSeen', '')) if ip_info.get('lastSeen') else None,
        'Recent': ip_info.get('recent')
    } for ip_info in ip_details]

    return tableToMarkdown('Observed IPs', ip_hr, ['Value', 'First Seen (GMT)', 'Last Seen (GMT)', 'Recent'],
                           removeNull=True)


def get_trackers_hr(trackers: List[Dict[str, Any]]) -> str:
    """
    Retrieve nested properties from list of attributes/trackers fetched in response to populate human readable

    :param trackers: list of properties associated with attributes/trackers of an asset
    :return: Human Readable of attributes/trackers to be populated on XSOAR
    """
    trackers_hr = [{
        'Type': tracker.get('attributeType', ''),
        'Value': tracker.get('attributeValue', ''),
        'First Seen (GMT)': epochToTimestamp(tracker.get('firstSeen', '')) if tracker.get('firstSeen') else None,
        'Last Seen (GMT)': epochToTimestamp(tracker.get('lastSeen', '')) if tracker.get('lastSeen') else None
    } for tracker in trackers]

    return tableToMarkdown('Trackers', trackers_hr, ['Type', 'Value', 'First Seen (GMT)', 'Last Seen (GMT)'],
                           removeNull=True)


def get_web_components_hr(web_components: List[Dict[str, Any]]) -> str:
    """
    Retrieve nested properties from list of web components fetched in response to populate human readable

    :param web_components: list of properties associated with web_components of an asset
    :return: Human Readable of web_components to be populated on XSOAR
    """
    web_components_hr = [{
        'Category': web_component.get('webComponentCategory', ''),
        'Name': web_component.get('webComponentName', ''),
        'Version': web_component.get('webComponentVersion', ''),
        'CVEs': convert_list_to_comma_separated_string(web_component.get('cves', []), 'name'),
        'First Seen (GMT)': epochToTimestamp(web_component.get('firstSeen', '')) if web_component.get(
            'firstSeen') else None,
        'Last Seen (GMT)': epochToTimestamp(web_component.get('lastSeen', '')) if web_component.get(
            'lastSeen') else None,
        'Recent': web_component.get('recent')
    } for web_component in web_components]

    return tableToMarkdown('Web Components', web_components_hr,
                           ['Category', 'Name', 'Version', 'CVEs', 'First Seen (GMT)',
                            'Last Seen (GMT)', 'Recent'], removeNull=True)


def get_resources_hr(resources: List[Dict[str, Any]]) -> str:
    """
    Retrieve nested properties from list of resources fetched in response to populate human readable

    :param resources: list of properties associated with web_components of an asset
    :return: Human Readable of web_components to be populated on XSOAR
    """
    resources_hr = [{
        'Resource': resource.get('url', ''),
        'Resource Host': resource.get('resources', [])[0].get('host', '') if resource.get('resources', []) else '',
        'MD5': resource.get('resources', [])[0].get('md5', '') if resource.get('resources', []) else '',
        'First Seen (GMT)': epochToTimestamp(resource.get('resources', [])[0].get('firstSeen', ''))
        if resource.get('resources', []) and resource.get('resources', [])[0].get('firstSeen') else None,
        'Last Seen (GMT)': epochToTimestamp(resource.get('resources', [])[0].get('lastSeen', ''))
        if resource.get('resources', []) and resource.get('resources', [])[0].get('lastSeen') else None,
        'Size (in bytes)': resource.get('resources', [])[0].get('responseBodySize', '')
        if resource.get('resources', []) else None,
        'Observed': resource.get('resources', [])[0].get('count', '') if resource.get('resources', []) else None,
        'Recent': resource.get('recent')
    } for resource in resources]

    return tableToMarkdown('Resources (observed within last month)', resources_hr,
                           ['Resource', 'Resource Host', 'MD5', 'First Seen (GMT)', 'Last Seen (GMT)',
                            'Size (in bytes)', 'Observed', 'Recent'], removeNull=True)


def get_ssl_certs_associated_with_other_asset_hr(ssl_certs: List[Dict[str, Any]]) -> str:
    """
    Retrieve nested properties from list of ssl certs fetched in response to populate human readable

    :param ssl_certs: list of properties associated with ssl certs of an asset
    :return: Human Readable of ssl certs to be populated on XSOAR
    """
    ssl_certs_hr = [{
        'SHA1': ssl_cert.get('sha1', ''),
        'Issued': epochToTimestamp(ssl_cert.get('notBefore', '')) if ssl_cert.get('notBefore') else None,
        'Expires': epochToTimestamp(ssl_cert.get('notAfter', '')) if ssl_cert.get('notAfter') else None,
        'First Seen (GMT)': epochToTimestamp(ssl_cert.get('firstSeen', '')) if ssl_cert.get('firstSeen') else None,
        'Last Seen (GMT)': epochToTimestamp(ssl_cert.get('lastSeen', '')) if ssl_cert.get('lastSeen') else None,
        'Recent': ssl_cert.get('recent')
    } for ssl_cert in ssl_certs]

    return tableToMarkdown('SSL Certificates', ssl_certs_hr,
                           ['SHA1', 'Issued', 'Expires', 'First Seen (GMT)', 'Last Seen (GMT)', 'Recent'],
                           removeNull=True)


def get_asset_host_hr(asset_details: Dict[str, Any]) -> str:
    """
    Retrieves the human readable for Host

    :param asset_details: Dictionary containing asset details of the host
    :return: Human readable of all the host details
    """
    asset_specific_hr = ''
    asset_specific_details = {
        'Domain': asset_details.get('domain', ''),
        'IP Address': asset_details.get('ipAddresses', [])[0].get('value', '')
        if asset_details.get('ipAddresses', []) and asset_details.get('ipAddresses', [])[0].get('current', '') else '',
        'CName': asset_details.get('cnames', [])[0].get('value', '')
        if asset_details.get('cnames', []) and asset_details.get('cnames', [])[0].get('current', '') else '',
        'Alexa Rank': asset_details.get('alexaRank', '')
    }

    if not all(value == '' or value == [] for value in asset_specific_details.values()):
        asset_specific_hr += tableToMarkdown('Host Details', asset_specific_details,
                                             ['Domain', 'IP Address', 'CName', 'Alexa Rank'],
                                             removeNull=True)
    if asset_details.get('ipAddresses'):
        asset_specific_hr += get_ip_hr(asset_details.get('ipAddresses', []))

    if asset_details.get('nameServers') or asset_details.get('mailServers'):
        asset_specific_hr += get_name_and_mail_server_hr(asset_details)

    if asset_details.get('attributes'):
        asset_specific_hr += get_trackers_hr(asset_details.get('attributes', []))

    if asset_details.get('webComponents'):
        asset_specific_hr += get_web_components_hr(asset_details.get('webComponents', []))

    if asset_details.get('resourceUrls'):
        asset_specific_hr += get_resources_hr(asset_details.get('resourceUrls', []))

    if asset_details.get('sslCerts'):
        asset_specific_hr += get_ssl_certs_associated_with_other_asset_hr(asset_details.get('sslCerts', []))

    who_is_details = asset_details.get('whois', {})
    if who_is_details:
        asset_specific_hr += get_whois_hr(who_is_details)

    return asset_specific_hr


def get_ip_reputation_hr(ip_reputations: List[Dict[str, Any]]) -> str:
    """
    Retrieve nested properties from list of ip reputations fetched in response to populate human readable

    :param ip_reputations: list of properties associated with ip reputations of an asset
    :return: Human Readable of ssl certs to be populated on XSOAR
    """
    reputation_hr = [{
        'List': ip_reputation.get('listName', ''),
        'Threat Type': ip_reputation.get('threatType', ''),
        'List Last Updated': epochToTimestamp(ip_reputation.get('listUpdatedAt', ''))
        if ip_reputation.get('listUpdatedAt') else None,
        'First Seen (GMT)': epochToTimestamp(ip_reputation.get('firstSeen', ''))
        if ip_reputation.get('firstSeen') else None,
        'Last Seen (GMT)': epochToTimestamp(ip_reputation.get('lastSeen', ''))
        if ip_reputation.get('lastSeen') else None,
        'Recent': ip_reputation.get('recent')
    } for ip_reputation in ip_reputations]

    return tableToMarkdown('IP Reputation', reputation_hr,
                           ['List', 'Threat Type', 'List Last Updated', 'First Seen (GMT)',
                            'Last Seen (GMT)', 'Recent'], removeNull=True)


def get_ports_hr(ports: List[Dict[str, Any]]) -> str:
    """
    Retrieve nested properties from list of ports fetched in response to populate human readable

    :param ports: list of properties associated with ports of an asset
    :return: Human Readable of ports to be populated on XSOAR
    """
    port_hr = [{
        'Port': port.get('port', ''),
        'First Seen (GMT)': epochToTimestamp(port.get('firstSeen', '')) if port.get('firstSeen', '') else None
        if port.get('firstSeen') else None,
        'Last Seen (GMT)': epochToTimestamp(port.get('lastSeen', '')) if port.get('lastSeen', '') else None
        if port.get('lastSeen') else None,
        'Last Scanned': epochToTimestamp(port.get('lastSeen', '')) if port.get('lastSeen') else None,
        'Scan Type': port.get('banners', [])[0].get('scanType', '') if port.get('banners', []) else '',
        'Recent': port.get('recent'),
        'Banner': port.get('banners', [])[0].get('banner', '') if port.get('banners', []) else '',
    } for port in ports]

    return tableToMarkdown('Open Ports', port_hr,
                           ['Port', 'First Seen (GMT)', 'Last Seen (GMT)', 'Last Scanned', 'Scan Type',
                            'Recent', 'Banner'], removeNull=True)


def get_asset_ip_address_hr(asset_details: Dict[str, Any]) -> str:
    """
    Retrieves the human readable for IP Address

    :param asset_details: Dictionary containing asset details of the IP Address
    :return: Human readable of all the IP Address details
    """
    asset_specific_hr = ''
    asset_specific_details = {
        'IP Blocks': get_comma_separated_values_only_current(asset_details.get('ipBlocks', []), 'ipBlock'),
        'ASNs': convert_list_to_comma_separated_string(asset_details.get('asns', []), 'fullName')
    }

    if not all(value == '' or value == [] for value in asset_specific_details.values()):
        asset_specific_hr += tableToMarkdown('IP Address Details', asset_specific_details,
                                             ['IP Blocks', 'ASNs'],
                                             removeNull=True)

    if asset_details.get('reputations'):
        asset_specific_hr += get_ip_reputation_hr(asset_details.get('reputations', []))

    if asset_details.get('nameServers') or asset_details.get('mailServers'):
        asset_specific_hr += get_name_and_mail_server_hr(asset_details)

    if asset_details.get('services'):
        asset_specific_hr += get_ports_hr(asset_details.get('services', []))

    if asset_details.get('attributes'):
        asset_specific_hr += get_trackers_hr(asset_details.get('attributes', []))

    if asset_details.get('webComponents'):
        asset_specific_hr += get_web_components_hr(asset_details.get('webComponents', []))

    if asset_details.get('sslCerts'):
        asset_specific_hr += get_ssl_certs_associated_with_other_asset_hr(asset_details.get('sslCerts', []))

    who_is_details = asset_details.get('whois', {})
    if who_is_details:
        asset_specific_hr += get_whois_hr(who_is_details)

    return asset_specific_hr


def get_asset_ip_block_hr(asset_details: Dict[str, Any]) -> str:
    """
    Retrieves the human readable for IP Block

    :param asset_details: Dictionary containing asset details of the IP Block
    :return: Human readable of all the IP Block details
    """
    asset_specific_hr = ''
    asset_specific_details = {
        'CIDR': asset_details.get('ipBlock', '').split('/')[-1],
        'Network Name': get_comma_separated_values_only_current(asset_details.get('netNames', []), 'value'),
        'Organisation Name': get_comma_separated_values_only_current(asset_details.get('registrantOrgs', []), 'value'),
        'ASN': convert_list_to_comma_separated_string(asset_details.get('asns', []), 'fullName'),
        'Country': convert_list_to_comma_separated_string(asset_details.get('asns', []), 'countryCode'),
        'Net Range': get_comma_separated_values_only_current(asset_details.get('netRanges', []), 'value')
    }

    if not all(value == '' or value == [] for value in asset_specific_details.values()):
        asset_specific_hr += tableToMarkdown('IP Block Details', asset_specific_details,
                                             ['CIDR', 'Network Name', 'Organisation Name',
                                              'ASN', 'Country', 'Net Range'], removeNull=True)

    if asset_details.get('nameServers') or asset_details.get('mailServers'):
        asset_specific_hr += get_name_and_mail_server_hr(asset_details)

    who_is_details = asset_details.get('whois', {})
    if who_is_details:
        asset_specific_hr += get_whois_hr(who_is_details)

    return asset_specific_hr


def get_asset_as_hr(asset_details: Dict[str, Any]) -> str:
    """
    Retrieves the human readable for AS

    :param asset_details: Dictionary containing asset details of the AS
    :return: Human readable of all the AS details
    """
    asset_specific_hr = ''
    asset_asn_details = asset_details.get('asn', {})
    asset_specific_details = {
        'AS Number': asset_details.get('asnNumber', ''),
        'Full Name': asset_asn_details.get('fullName', ''),
        'Description': asset_asn_details.get('description', ''),
        'Organizations': get_comma_separated_values_only_current(asset_details.get('orgNames', []), 'value'),
        'Countries': get_comma_separated_values_only_current(asset_details.get('countries', []), 'value'),
        'Registries': get_comma_separated_values_only_current(asset_details.get('registries', []), 'value')
    }

    if not all(value == '' or value == [] for value in asset_specific_details.values()):
        asset_specific_hr += tableToMarkdown('ASN Details', asset_specific_details,
                                             ['AS Number', 'Full Name', 'Description', 'Organizations', 'Countries',
                                              'Registries'], removeNull=True)

    if asset_details.get('nameServers') or asset_details.get('mailServers'):
        asset_specific_hr += get_name_and_mail_server_hr(asset_details)

    who_is_details = asset_details.get('whois', {})
    if who_is_details:
        asset_specific_hr += get_whois_hr(who_is_details)

    return asset_specific_hr


def check_first_element_and_populate_current(attribute_details: Dict[str, Any], key: str) -> str:
    """
    Retrieve the value of requested key from the first element of the list

    :param attribute_details: list of properties from which the value is the be retrieved
    :param key: the key whose value is to be fetched
    :return: attribute_value: value of the requested key
    """
    attribute_value = ''
    if attribute_details.get(key, []) and attribute_details.get(key, [])[0].get('current', ''):
        attribute_value = attribute_details.get(key, [])[0].get('value', '')
    return attribute_value


def get_security_policies_hr(security_policies: List[Dict[str, Any]]) -> str:
    """
    Retrieve nested properties from list of security policies fetched in response to populate human readable

    :param security_policies: list of properties associated with security_policies of an asset
    :return: Human Readable of security_policies to be populated on XSOAR
    """
    security_policies_hr = [{
        'Policy': security_policy.get('policyName', ''),
        'Description': security_policy.get('description', ''),
        'First Seen (GMT)': epochToTimestamp(security_policy.get('firstSeen', ''))
        if security_policy.get('firstSeen') else None,
        'Last Seen (GMT)': epochToTimestamp(security_policy.get('lastSeen', '')) if security_policy.get(
            'lastSeen') else None,
        'Recent': security_policy.get('recent')
    } for security_policy in security_policies if security_policy.get('isAffected')]

    return tableToMarkdown('Affected Security Policies', security_policies_hr,
                           ['Policy', 'Description', 'First Seen (GMT)', 'Last Seen (GMT)', 'Recent'], removeNull=True)


def get_asset_page_hr(asset_details: Dict[str, Any]) -> str:
    """
    Retrieves the human readable for Page

    :param asset_details: Dictionary containing asset details of the Page
    :return: Human readable of all the Page details
    """
    asset_specific_hr = ''

    asset_specific_details = {
        'Title': check_first_element_and_populate_current(asset_details, 'titles'),
        'Initial URL': asset_details.get('url', ''),
        'Initial Response Code': check_first_element_and_populate_current(asset_details, 'httpResponseCodes'),
        'Final URL': check_first_element_and_populate_current(asset_details, 'finalUrls'),
        'Final Response Code': check_first_element_and_populate_current(asset_details, 'finalResponseCodes'),
        'Response Time (in milliseconds)': check_first_element_and_populate_current(asset_details, 'responseTimes'),
        'Latest Final IP Address': check_first_element_and_populate_current(asset_details, 'finalIpAddresses'),
        'Cause': asset_details.get('cause', {}).get('cause', ''),
        'Error': check_first_element_and_populate_current(asset_details, 'errors'),
        'Content Type': check_first_element_and_populate_current(asset_details, 'contentTypes'),
        'Charset': check_first_element_and_populate_current(asset_details, 'charsets'),
        'Language': check_first_element_and_populate_current(asset_details, 'languages'),
        'Parked': asset_details.get('parkedPage', [])[0].get('value', '')
        if asset_details.get('parkedPage', []) and asset_details.get('parkedPage', [])[0].get('current', '') else None
    }

    if any(value != "" and value is not None for value in asset_specific_details.values()):
        asset_specific_hr += tableToMarkdown('Page Details', asset_specific_details,
                                             ['Title', 'Initial URL', 'Initial Response Code', 'Final URL',
                                              'Final Response Code', 'Response Time (in milliseconds)',
                                              'Latest Final IP Address',
                                              'Cause', 'Error', 'Content Type', 'Charset', 'Language', 'Parked'],
                                             removeNull=True)

    if asset_details.get('nameServers') or asset_details.get('mailServers'):
        asset_specific_hr += get_name_and_mail_server_hr(asset_details)

    if asset_details.get('attributes'):
        asset_specific_hr += get_trackers_hr(asset_details.get('attributes', []))

    if asset_details.get('webComponents'):
        asset_specific_hr += get_web_components_hr(asset_details.get('webComponents', []))

    if asset_details.get('resourceUrls'):
        asset_specific_hr += get_resources_hr(asset_details.get('resourceUrls', []))

    if asset_details.get('sslCerts'):
        asset_specific_hr += get_ssl_certs_associated_with_other_asset_hr(asset_details.get('sslCerts', []))

    if asset_details.get('assetSecurityPolicies'):
        asset_specific_hr += get_security_policies_hr(asset_details.get('assetSecurityPolicies', []))

    who_is_details = asset_details.get('whois', {})
    if who_is_details:
        asset_specific_hr += get_whois_hr(who_is_details)

    return asset_specific_hr


def prepare_issuer_subject_cell(asset_details: Dict[str, Any], key: str) -> str:
    """
    Retrieve nested properties of a key from asset details fetched in response to populate human readable

    :param asset_details: dictionary from which the properties are to be fetched
    :param key: the key whose nested properties and values are to be fetched
    :return: Human Readable of nested properties of the requested key to be populated on XSOAR
    """
    hr_cell_info = []

    # Fetch all keys
    common_name = asset_details.get(key, {}).get('common name', '')
    alternative_names = ', '.join(asset_details.get(f'{key}AlternativeNames', []))
    organization_name = asset_details.get(key, {}).get('organization', '')
    organization_unit = asset_details.get(key, {}).get('unit', '')
    locality = asset_details.get(key, {}).get('locale', '')
    state = asset_details.get(key, {}).get('state', '')
    country = asset_details.get(key, {}).get('country', '')
    if common_name:
        hr_cell_info.append(f'Common Name: {common_name}')
    if alternative_names:
        hr_cell_info.append(f'Alternate Names: {alternative_names}')
    if organization_name:
        hr_cell_info.append(f'Organization Name: {organization_name}')
    if organization_unit:
        hr_cell_info.append(f'Organization Unit: {organization_unit}')
    if locality:
        hr_cell_info.append(f'Locality: {locality}')
    if state:
        hr_cell_info.append(f'State: {state}')
    if country:
        hr_cell_info.append(f'Country: {country}')
    return '\n'.join(hr_cell_info)


def get_asset_ssl_hr(asset_details: Dict[str, Any]) -> str:
    """
    Retrieves the human readable for SSL Cert

    :param asset_details: Dictionary containing asset details of the SSL Cert
    :return: Human readable of all the SSL Cert details
    """
    asset_specific_hr = ''
    asset_specific_details = {
        'Certificate Issued': epochToTimestamp(asset_details.get('notBefore', ''))
        if asset_details.get('notBefore') else None,
        'Certificate Expires': epochToTimestamp(asset_details.get('notAfter', ''))
        if asset_details.get('notAfter') else None,
        'Serial Number': asset_details.get('serialNumber', ''),
        'SSL Version': asset_details.get('version'),
        'Certificate Key Algorithm': asset_details.get('publicKeyAlgorithm', ''),
        'Certificate Key Size': asset_details.get('keySize'),
        'Signature Algorithm': asset_details.get('signatureAlgorithm', ''),
        'Signature Algorithm Oid': asset_details.get('signatureAlgorithmOid', ''),
        'Self Signed': asset_details.get('selfSigned'),
        'Subject': prepare_issuer_subject_cell(asset_details, 'subject') if asset_details.get('subject') else '',
        'Issuer': prepare_issuer_subject_cell(asset_details, 'issuer') if asset_details.get('issuer') else ''
    }

    if any(value != "" or value is not None for value in asset_specific_details.values()):
        asset_specific_hr += tableToMarkdown('SSL Cert Details', asset_specific_details,
                                             ['Certificate Issued', 'Certificate Expires', 'Serial Number',
                                              'SSL Version', 'Certificate Key Algorithm', 'Certificate Key Size',
                                              'Signature Algorithm', 'Signature Algorithm Oid', 'Self Signed',
                                              'Subject', 'Issuer'], removeNull=True)

    if asset_details.get('nameServers') or asset_details.get('mailServers'):
        asset_specific_hr += get_name_and_mail_server_hr(asset_details)

    return asset_specific_hr


def get_asset_contact_hr(asset_details: Dict[str, Any]) -> str:
    """
    Retrieves the human readable for Contact

    :param asset_details: Dictionary containing asset details of the Contact
    :return: Human readable of all the Contact details
    """
    asset_specific_hr = ''

    if asset_details.get('nameServers') or asset_details.get('mailServers'):
        asset_specific_hr += get_name_and_mail_server_hr(asset_details)

    return asset_specific_hr


def get_asset_custom_context_for_services_and_web_components(resp: Dict[str, Any], key: str,
                                                             exclude_keys: Union[tuple, str]) -> List[Dict[str, Any]]:
    """
    Fetching the custom context for specific keys and excluding unnecessary sub keys from it.

    :param resp: Response fetched from the API call
    :param key: Key for which the custom context is to be fetched.
    :param exclude_keys: List of sub keys to be excluded from the given key.
    :return: attribute_content: Custom context prepared for the requested key
    """

    attribute_content = []
    for attribute in resp.get('asset', {}).get(key, []):
        attribute_content.append(
            prepare_context_dict(attribute, exclude_keys=exclude_keys))

    return attribute_content


def get_asset_custom_context_for_ssl_cert(resp: Dict[str, Any], simple_context: Dict[str, Any],
                                          keys_with_hierarchy: List[str]) -> Tuple[Dict[str, Any], List[str]]:
    """
    Modifying the lists and reducing the levels of keys for SSL Cert asset type from the fetched response.

    :param resp: Response fetched from the API call
    :param simple_context: Simplified context after reducing heirarchy and excluding keys.
    :param keys_with_hierarchy: List of keys to be reduced from the main asset key.
    :return: simple_context, keys_with_hierarchy: Custom context prepared for the SSL Cert details
     from the fetched response and appended list of keys that can be used to reduce the level of context.
    """

    if resp.get('asset', {}).get('issuer'):
        simple_context['issuer'] = resp.get('asset', {}).get('issuer', '')
        keys_with_hierarchy.append('issuer')

    if resp.get('asset', {}).get('subject'):
        simple_context['subject'] = resp.get('asset', {}).get('subject', '')
        keys_with_hierarchy.append('subject')

    if resp.get('asset', {}).get('issuerAlternativeNames'):
        simple_context['issuerAlternativeNames'] = \
            ', '.join(resp.get('asset', {}).get('issuerAlternativeNames', []))

    if resp.get('asset', {}).get('subjectAlternativeNames'):
        simple_context['subjectAlternativeNames'] = \
            ', '.join(resp.get('asset', {}).get('subjectAlternativeNames', []))

    return simple_context, keys_with_hierarchy


def get_asset_custom_context_for_whois(resp: Dict[str, Any], whois_content: Dict[str, Any]) -> Dict[str, Any]:
    """
    Modifying the lists fetched from whois details of response to comma separated strings.

    :param resp: Response fetched from the API call
    :param whois_content: Whois content after reducing heirarchy and excluding keys.
    :return: whois_content: Custom context prepared for the whois details for the fetched response
    """

    asset = resp.get('asset', {}).get('whois', {})
    if asset.get('contactCountries'):
        whois_content['contactCountries'] = \
            ', '.join(asset.get('contactCountries', []))

    if asset.get('contactOrganizations'):
        whois_content['contactOrganizations'] = \
            ', '.join(asset.get('contactOrganizations', []))

    if asset.get('contactEmails'):
        whois_content['contactEmails'] = \
            ', '.join(asset.get('contactEmails', []))

    if asset.get('contactNames'):
        whois_content['contactNames'] = \
            ', '.join(asset.get('contactNames', []))

    if asset.get('nameservers'):
        whois_content['nameservers'] = \
            ', '.join(asset.get('nameservers', []))

    return whois_content


def get_asset_custom_context_for_data(resp: Dict[str, Any]) -> Dict[str, Any]:
    """
    Fetching all the details inside data key fetched from the response.

    :param resp: Response fetched from the API call
    :return: data_content: Custom context prepared for the data details for the fetched response
    """
    data = resp.get('data', {})
    data_content: Dict[str, Any] = {}

    if data.get('hostPairs', {}).get('content', []):
        data_content['hostPairs'] = data.get('hostPairs', {}).get('content', [])

    if data.get('attributes', {}).get('content', []):
        data_content['attributes'] = data.get('attributes', {}).get('content', [])

    if data.get('webComponents', {}).get('content', []):
        data_content['webComponents'] = data.get('webComponents', {}).get('content', [])

    if data.get('sslCerts', {}).get('content', []):
        ssl_cert_data_content = []
        for ssl_cert in data.get('sslCerts', {}).get('content', []):
            if ssl_cert.get('issuerAlternativeNames'):
                ssl_cert['issuerAlternativeNames'] = \
                    ', '.join(ssl_cert.get('issuerAlternativeNames', []))

            if ssl_cert.get('subjectAlternativeNames'):
                ssl_cert['subjectAlternativeNames'] = \
                    ', '.join(ssl_cert.get('subjectAlternativeNames', []))
            ssl_cert_data_content.append(ssl_cert)
        data_content['sslCerts'] = ssl_cert_data_content

    if data.get('cookies', {}).get('content', []):
        data_content['cookies'] = data.get('cookies', {}).get('content', [])

    return data_content


def get_asset_custom_context(resp: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prepare the custom context from fetched response by reducing
    the context heirarchy levels and removing unnecessary keys

    :param resp: Response fetched from the API call
    :return: final_context: Custom context prepared from the fetched response
    """
    # Removing unnecessary keys or keys which can be reduced from the response
    simple_context: Dict[str, Any] = prepare_context_dict(resp, exclude_keys=('asset', 'data', 'discoveryRun', '_meta'))

    # Removing unnecessary keys or keys which can be reduced from the asset key of response
    assets_content = prepare_context_dict(resp.get('asset', {}), exclude_keys=('whois', 'services', 'issuer', 'subject',
                                                                               'issuerAlternativeNames',
                                                                               'subjectAlternativeNames',
                                                                               'responseBodies', 'nxdomain',
                                                                               'responseBodyMinhashSignatures',
                                                                               'fullDomMinhashSignatures',
                                                                               'nonHtmlFrames', 'undirectedContent',
                                                                               'redirectUrls', 'webComponents'))
    simple_context['asset'] = assets_content

    # Removing unnecessary keys or keys which can be reduced from the whois key of the response
    if resp.get('asset', {}).get('whois', {}):
        whois_content = prepare_context_dict(resp.get('asset', {}).get('whois', {}),
                                             ('registrant', 'admin', 'technical', 'billing'),
                                             ('raw', 'contactCountries', 'contactOrganizations', 'contactEmails',
                                              'contactNames', 'nameservers', 'zone'))

        whois_content = get_asset_custom_context_for_whois(resp, whois_content)

        simple_context['whois'] = whois_content

    if resp.get('asset', {}).get('services', []):
        services_content = get_asset_custom_context_for_services_and_web_components(resp, key='services',
                                                                                    exclude_keys=('webComponents',
                                                                                                  'sslCerts',
                                                                                                  'exceptions'))
        simple_context['asset']['services'] = services_content

    if resp.get('asset', {}).get('webComponents', []):
        web_component_content = get_asset_custom_context_for_services_and_web_components(resp, key='webComponents',
                                                                                         exclude_keys='ruleid')

        simple_context['asset']['webComponents'] = web_component_content

    # Removing unnecessary keys or keys which can be reduced from the discoveryRun key of the response
    if resp.get('discoveryRun', {}):
        if resp.get('discoveryRun', {}).get('search', {}):
            discovery_run_result = prepare_context_dict(resp.get('discoveryRun', {}), 'search')
            simple_context['discoveryRun'] = discovery_run_result
        else:
            simple_context['discoveryRun'] = resp.get('discoveryRun')

    if resp.get('data', {}):
        simple_context['data'] = get_asset_custom_context_for_data(resp)

    # Setting the keys which are to be reduced in the response
    keys_with_hierarchy = ['whois', 'discoveryRun', 'asset']

    # Removing unnecessary keys or keys which can be reduced from of the response fetched for SSL_Cert asset type
    if resp.get('type', '') == 'SSL_CERT':
        simple_context, keys_with_hierarchy = get_asset_custom_context_for_ssl_cert(resp, simple_context,
                                                                                    keys_with_hierarchy)

    # Setting the final context fetched from the response after reducing it to minimal hierarchy level
    final_context = prepare_context_dict(simple_context, tuple(keys_with_hierarchy))
    return remove_empty_entities(final_context)


def get_asset_basic_hr(resp: Dict[str, Any]) -> Dict[str, Any]:
    """
    Retrieve attributes from response to populate human readable output

    :param resp: attribute details of the asset fetched from response
    :return: dictionary containing attributes to be shown in Human Readable format on XSOAR
    """
    return {
        'Name': resp.get('name', ''),
        'Type': resp.get('type', ''),
        'Inventory Status': resp.get('state', ''),
        'UUID': resp.get('uuid', ''),
        'First Seen (GMT)': epochToTimestamp(resp.get('firstSeen', '')) if resp.get('firstSeen') else None,
        'Last Seen (GMT)': epochToTimestamp(resp.get('lastSeen', '')) if resp.get('lastSeen') else None,
        'Added To Inventory (GMT)': epochToTimestamp(resp.get('createdAt', '')) if resp.get('createdAt') else None,
        'Last Updated (GMT)': epochToTimestamp(resp.get('updatedAt', '')) if resp.get('updatedAt') else None,
        'Confidence': resp.get('confidence', ''),
        'Enterprise Asset': resp.get('enterprise'),
        'Priority': resp.get('priority', ''),
        'Organization(s)': convert_list_to_comma_separated_string(resp.get('organizations', []), 'name'),
        'Tag(s)': convert_list_to_comma_separated_string(resp.get('tags', []), 'name'),
        'Brand(s)': convert_list_to_comma_separated_string(resp.get('brands', []), 'name')
    }


def get_asset_outputs(resp: Dict[str, Any]) -> List[CommandResults]:
    """
    Generates all outputs for df-get-asset command

    :param resp:  API Response
    :return: Human Readable, Standard Context, Custom Context
    """
    hr = ''
    custom_ec = {}
    standard_ec: list = []
    command_results: List[CommandResults] = []

    asset_type_hr_map = {
        'DOMAIN': get_asset_domain_hr,
        'HOST': get_asset_host_hr,
        'IP_ADDRESS': get_asset_ip_address_hr,
        'IP_BLOCK': get_asset_ip_block_hr,
        'AS': get_asset_as_hr,
        'PAGE': get_asset_page_hr,
        'SSL_CERT': get_asset_ssl_hr,
        'CONTACT': get_asset_contact_hr
    }
    asset_type_standard_context_map = {
        'DOMAIN': get_standard_context_domain_for_get_asset,
        'HOST': get_standard_context_host_for_get_asset,
        'IP_ADDRESS': get_standard_context_ip_for_get_asset,
        'PAGE': get_standard_context_url_for_get_asset
    }
    if resp:
        asset_type = resp.get('type', '')
        asset_details = resp.get('asset', {})

        custom_ec = get_asset_custom_context(resp)
        hr += '### ASSET DETAILS\n'
        asset_basic_hr = get_asset_basic_hr(resp)
        hr += tableToMarkdown('Basic Details', asset_basic_hr,
                              ['Name', 'Type', 'Inventory Status', 'UUID', 'First Seen (GMT)', 'Last Seen (GMT)',
                               'Added To Inventory (GMT)', 'Last Updated (GMT)', 'Confidence', 'Enterprise Asset',
                               'Priority', 'Organization(s)', 'Tag(s)', 'Brand(s)'],
                              removeNull=True)

        if asset_type in asset_type_hr_map:
            hr += asset_type_hr_map[asset_type](asset_details)
        if asset_type in asset_type_standard_context_map:
            standard_ec = asset_type_standard_context_map[asset_type](resp)
        custom_ec = createContext(custom_ec, removeNull=True)

    if custom_ec:
        command_results.append(CommandResults(
            outputs_prefix='RiskIQDigitalFootprint.Asset',
            outputs_key_field='uuid',
            readable_output=hr,
            outputs=custom_ec,
            raw_response=resp
        ))
    if standard_ec:
        for indicator in standard_ec:
            command_results.append(CommandResults(
                indicator=indicator
            ))

    return command_results


def get_add_and_update_assets_params(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Fetch and validate parameters to be passed for df-add-assets or df-update-assets command
    and prepare params dictionary.

    :param args: args passed by the user
    :return: params dictionary
    """
    params: Dict[str, Any] = {}

    if args.get('fail_on_error'):
        try:
            fail_on_error = argToBoolean(args.get('fail_on_error'))
        except ValueError:
            raise ValueError(MESSAGES['INVALID_BOOLEAN_VALUE_ERROR'].format('fail_on_error'))
        params['failOnError'] = fail_on_error
    return params


def prepare_add_and_update_asset_hr(task_resp: Dict[str, Any], operation_bool: bool) -> str:
    """
    Prepare human readable for df-add-assets and df-update-assets commands.

    :param task_resp: Response fetched from task status API call.
    :param operation_bool: operation that is being performed. i.e. True(add) or False(update)
    :return: human readable output for df-add-assets and df-update-assets commands.
    """
    task_state = task_resp.get('state', '')
    task_reason = task_resp.get('reason') if task_resp.get('reason') is not None else 'An unexpected error occurred.'
    operation = 'add' if operation_bool else 'updat'
    state_hr_map = {
        'COMPLETE': f'### The requested asset(s) have been successfully {operation}ed.',
        'FAILED': f'### The request for {operation}ing asset(s) failed. Reason: {task_reason}',
        'INCOMPLETE': f'### The request for {operation}ing asset(s) is incomplete. Reason: {task_reason}',
        'WARNING': f'### The request for {operation}ing asset(s) is completed with a warning. Reason: {task_reason}',
        'RUNNING': f'### The request for {operation}ing asset(s) has been successfully submitted. '
                   f'You can check its status using this task identifier/reference: {task_resp["key"]["uuid"]} '
                   f'in RiskIQ Digital Footprint.',
        'PENDING': f'### The request for {operation}ing asset(s) has been successfully submitted. '
                   f'You can check its status using this task identifier/reference: {task_resp["key"]["uuid"]} '
                   f'in RiskIQ Digital Footprint.'
    }
    return state_hr_map.get(task_state, '')


def prepare_add_and_update_asset_context(task_resp: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Prepare custom context for df-add-assets and df-update-assets commands.

    :param task_resp: Response fetched from task status API call.
    :return: custom context output for df-add-assets and df-update-assets commands.
    """
    custom_ec = {
        'uuid': task_resp.get('key', '').get('uuid', ''),
        'state': task_resp.get('state', ''),
        'reason': task_resp.get('reason', ''),
        'estimated': task_resp.get('data', {}).get('estimated'),
        'totalUpdates': task_resp.get('data', {}).get('totalUpdates')
    }
    return createContext(data=custom_ec, removeNull=True)


def validate_properties_and_prepare_payload(args: Dict[str, Any], operation: str,
                                            valid_json: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prepare payload for post data in case user wants to add or update single asset.

    :param args: args passed by the user
    :param operation: operation being performed i.e. add or update
    :param valid_json: The validated input asset JSON
    :return: payload to be passed as request body for adding or updating the requested asset.
    """
    action = operation.upper() if operation == 'add' else args.get('action', 'Update').upper()
    if action not in VALID_ACTIONS:
        raise ValueError(MESSAGES['INVALID_ACTION_ERROR'])

    state = args.get('state', '')
    if state and state not in VALID_ASSET_STATES:
        raise ValueError(MESSAGES['INVALID_ASSET_STATE_ERROR'])
    elif state:
        valid_json['properties'].append({
            'name': 'state',
            'value': state,
            'action': action
        })

    priority = args.get('priority', '')
    if priority and priority not in VALID_ASSET_PRIORITY:
        raise ValueError(MESSAGES['INVALID_ASSET_PRIORITY_ERROR'])
    elif priority:
        valid_json['properties'].append({
            'name': 'priority',
            'value': priority,
            'action': action
        })

    enterprise = args.get('enterprise', '')
    if enterprise and enterprise not in ['true', 'false']:
        raise ValueError(MESSAGES['INVALID_BOOLEAN_VALUE_ERROR'].format('enterprise'))
    elif enterprise:
        valid_json['properties'].append({
            'name': 'enterprise',
            'value': argToBoolean(enterprise),
            'action': action
        })

    for key in ['brand', 'organization', 'tag']:
        if args.get(key, ''):
            valid_json['properties'].append({
                'name': key,
                'value': args.get(key, '').split(','),
                'action': action
            })

    return valid_json


def prepare_single_asset_payload(args: Dict[str, Any], operation: str) -> Dict[str, Any]:
    """
    Prepare payload for post data in case user wants to add or update single asset. Throws error if valid values
    are not provided in arguments.

    :param args: args passed by the user
    :param operation: operation being performed i.e. add or update
    :return: payload to be passed as request body for adding or updating the requested asset.
    """
    valid_json: Dict[str, Any] = {}

    # Throw error if for updating a workload none of the property arguments are mentioned
    if operation == 'update' and args.keys() - {'name', 'type', 'action', 'target_asset_types'} == set():
        raise ValueError(MESSAGES['INVALID_ARGUMENTS_UPDATE_ASSET'])

    asset_type = args.get('type', '').replace(' ', '_').upper()
    if asset_type not in VALID_ASSET_TYPES:
        raise ValueError(MESSAGES['INVALID_ASSET_TYPE_ERROR'])
    else:
        valid_json['assets'] = [{
            'name': args.get('name'),
            'type': asset_type if asset_type != 'ASN' else 'AS'
        }]
        valid_json['properties'] = []

    # Prepare payload for general properties
    valid_json = validate_properties_and_prepare_payload(args, operation, valid_json)

    removed_state = args.get('removed_state', '')
    if removed_state and removed_state != 'Dismissed':
        raise ValueError(MESSAGES['INVALID_REMOVED_STATE_ERROR'])
    elif removed_state:
        valid_json['properties'].append({
            'name': 'removedState',
            'value': removed_state
        })

    confirm = args.get('confirm', '')
    if confirm and confirm not in ['true', 'false']:
        raise ValueError(MESSAGES['INVALID_BOOLEAN_VALUE_ERROR'].format('confirm'))
    elif confirm:
        valid_json['confirm'] = argToBoolean(confirm)

    target_asset_types = args.get('target_asset_types', '')
    if target_asset_types:
        valid_json['targetAssetTypes'] = target_asset_types.split(',')

    return valid_json


def check_task_status(client: Client, resp: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check if the task of adding or updating asset(s) has been completed or not and return the response obtained.
    This function will return the last status of task if it is not completed after 3 retries.

    :param client: The Client object used for request
    :param resp: response obtained from add or update API call
    :return: response obtained from task status API call.
    """
    # Check the task status of assets to be added
    url_suffix = COMMAND_URL_SUFFIX['TASK_STATUS'].format(resp.get('identifier', ''))
    retries = 1
    task_resp = {}
    while retries <= 3:
        task_resp = client.http_request(method='GET', url_suffix=url_suffix)
        if task_resp.get('state', '') in COMPLETE_TASK_STATES:
            break
        else:
            demisto.debug(f'Fetching the task status. Retry number: {retries}')
            wait = retries * 30
            time.sleep(wait)  # pylint: disable=sleep-exists
            retries += 1
    return task_resp


def validate_required_keys_for_add_asset(valid_json: Dict[str, Any], required_keys: List[str]) -> bool:
    """
    Check if the required keys for adding an asset are present or not

    :param valid_json: The valid input asset JSON
    :param required_keys: The required keys for creating an asset
    :return: True if the required values are present else false
    """
    return all(key in valid_json.keys() for key in required_keys)


def validate_required_keys_for_update_asset(valid_json: Dict[str, Any], required_keys: List[str],
                                            required_keys_for_bulk_update: List[str]) -> bool:
    """
    Check if the required keys for updating an asset or required keys for bulk updating assets are present or not

    :param valid_json: The valid input asset JSON
    :param required_keys: The required keys for updating an asset
    :param required_keys_for_bulk_update: The required keys for bulk updating assets
    :return: True if the required values are present else false
    """
    return (all(key in valid_json.keys() for key in required_keys) or all(key in valid_json.keys()
                                                                          for key in required_keys_for_bulk_update))


def validate_required_keys_for_assets_key(assets: List[Dict[str, Any]], asset_required_keys: set) -> bool:
    """
    Check if the required keys in list of assets to be added or updated are present or not

    :param assets: List of assets
    :param asset_required_keys: The required keys for adding or updating an asset
    :return: True if the required values are present else false
    """
    return all(asset.keys() >= asset_required_keys for asset in assets)


def validate_asset_json(args: Dict[str, Any], operation: str) -> Dict[str, Any]:
    """
        Validates the value in asset_json argument in add and update asset command.
    :param args: The input arguments
    :param operation: operation being performed i.e. add or update
    :return: payload to be passed as request body for adding or updating the requested asset.
    """
    asset_json = args.get('asset_json')
    # Validate the input JSON is valid or not
    try:
        valid_json = safe_load_json(asset_json)
    except ValueError:
        raise ValueError('Unable to parse JSON file. Please verify the JSON is valid or the Entry ID is correct.')

    # Check if the required keys are present in the JSON payload
    required_keys = ['assets', 'properties']
    required_keys_for_bulk_update = ['query', 'properties']

    if operation == 'add' and not validate_required_keys_for_add_asset(valid_json, required_keys):
        raise ValueError(MESSAGES['ASSET_PAYLOAD_MISSING_KEYS_ERROR'].format(operation, required_keys))
    elif operation == 'update' and not validate_required_keys_for_update_asset(valid_json, required_keys,
                                                                               required_keys_for_bulk_update):
        raise ValueError(MESSAGES['ASSET_PAYLOAD_MISSING_KEYS_ERROR']
                         .format(operation, f'{required_keys} or {required_keys_for_bulk_update}'))

    asset_required_keys = {'name', 'type'}
    if 'assets' in valid_json.keys() and not validate_required_keys_for_assets_key(valid_json['assets'],
                                                                                   asset_required_keys):
        raise ValueError(MESSAGES['ASSET_PAYLOAD_MISSING_KEYS_ERROR']
                         .format(operation, '[\'name\', \'type\'] in assets key'))

    return valid_json


def validate_asset_payload(args: Dict[str, Any], operation: str) -> Dict[str, Any]:
    """
    Validates the arguments and creates an asset payload. Throws error if the required arguments for
    adding/updating a payload are not present.

    :param args: args passed by the user
    :param operation: operation being performed i.e. add or update
    :return: payload to be passed as request body for adding or updating the requested asset(s).
    """
    # Throw error if both asset_json and other arguments for creating asset manually are specified
    if 'asset_json' in args.keys() and args.keys() - {'asset_json', 'fail_on_error'} != set():
        raise ValueError(MESSAGES['INVALID_ARGUMENTS_ADD_ASSET'])

    asset_json = args.get('asset_json')
    if asset_json:
        valid_json = validate_asset_json(args, operation)
    elif args.get('name') and args.get('type'):
        valid_json = prepare_single_asset_payload(args, operation)
    else:
        raise ValueError(MESSAGES['REQUIRED_ARGUMENTS_FOR_ASSET'].format(operation))
    return valid_json


''' REQUESTS FUNCTIONS '''


def test_function(client: Client) -> str:
    """
    Performs test connectivity by valid http response

    :param client: client object which is used to get response from api
    :return: raise ValueError if any error occurred during connection
    """
    client.http_request(method='GET', url_suffix=COMMAND_URL_SUFFIX['TEST_MODULE'])
    return 'ok'


@logger
def asset_connections_command(client: Client, args: Dict[str, Any]) -> Union[str, List[CommandResults]]:
    """
    Retrieve the set of assets that are connected to the requested asset.

    :param client: client object which is used to get response from api
    :param args: parameters required to generate the api request
    :return: standard output: standard output required for XSOAR platform
    """

    # fetch and validate command arguments and params
    type_arg, params = validate_asset_connections_args_and_get_params(args)

    resp = client.http_request('GET',
                               url_suffix=COMMAND_URL_SUFFIX['ASSET_CONNECTIONS'].format(type_arg),
                               params=params)

    total_elements, content = {}, {}
    for asset_type in VALID_ASSET_TYPES and resp:
        total_elements[asset_type] = resp.get(asset_type).get('totalElements', 0)
        content[asset_type] = resp.get(asset_type).get('content', [])
    if all(value == 0 for value in total_elements.values()) or all(value == [] for value in content.values()):
        return f'{MESSAGES["NO_RECORDS_FOUND"].format("connected assets")} If the page argument is specified,' \
               f' try decreasing its value.'

    hr, command_results = get_asset_connections_outputs(resp, total_elements)
    # add hr to the begining of result
    command_results.insert(0, CommandResults(readable_output=hr))
    return command_results


@logger
def asset_changes_summary_command(client: Client, args: Dict[str, Any]) -> Union[str, CommandResults]:
    """
    Retrieve summary information describing counts of confirmed assets that have been added, removed or changed in
    inventory over the given time period.

    :param client: client object which is used to get response from api
    :param args: parameters required to generate the api request
    :return: standard output: standard output required for XSOAR platform
    """

    # fetch and validate command arguments
    date_arg, range_arg = validate_asset_changes_summary_args(args.get('date', ''), args.get('range', ''))

    # prepare params
    params: Dict[str, Any] = {}
    if date_arg:
        params['date'] = date_arg
    if range_arg:
        params['range'] = int(range_arg)
    for param in ['tag', 'brand', 'organization']:
        if args.get(param, ''):
            params[param] = args.get(param, '')

    resp = client.http_request('GET',
                               url_suffix=COMMAND_URL_SUFFIX['ASSET_CHANGES_SUMMARY'],
                               params=params)

    hr, custom_ec = get_asset_changes_summary_outputs(resp, date_arg, range_arg)
    return CommandResults(
        outputs_prefix='RiskIQDigitalFootprint.AssetSummary',
        outputs_key_field='runDate',
        outputs=custom_ec,
        readable_output=hr,
        raw_response=resp
    )


@logger
def asset_changes_command(client: Client, args: Dict[str, Any]) -> Union[str, List[CommandResults]]:
    """
    Retrieve the list of confirmed assets that have been added,
    removed or changes in asset properties in the inventory over the given time period.

    :param client: The Client object used for request
    :param args: The command arguments
    :return: CommandResults
    """

    params: Dict[str, Any] = get_asset_changes_params(args)

    resp = client.http_request(method='GET', url_suffix=COMMAND_URL_SUFFIX['ASSET_CHANGES'], params=params)

    total_elements = resp.get('totalElements', 0)
    if total_elements <= 0:
        return MESSAGES['NO_RECORDS_FOUND'].format('inventory change(s)')

    asset_changes_records = resp.get('content', [])

    # Prepare entry context
    ioc_command_results, custom_ec = get_asset_changes_context_data(asset_changes_records, params['type'])

    # Prepare human readable
    deep_link = encode_string_results(prepare_deep_link_for_asset_changes(asset_changes_records[0].get('runDate', ''),
                                                                          params['type'],
                                                                          params.get('measure', 'Added'),
                                                                          params.get('date', ''),
                                                                          params.get('range', '')))

    asset_type = args.get('type', '').replace(' ', '_').upper()
    measure = params.get('measure', 'Added')

    output_key_fields = ['name', 'type']
    changed_entity = 'Assets'
    if asset_type in VALID_ASSET_DETAIL_TYPES:
        output_key_fields = ['id', 'resource']
        changed_entity = 'Resources'

    hr = f'### [INVENTORY CHANGES: DETAILS]({deep_link})\n### {measure} Inventory {changed_entity}\n' \
         f'### Total: {resp.get("totalElements")}\n'
    hr += get_asset_changes_hr(asset_changes_records, asset_type, measure)

    ioc_command_results.insert(0, CommandResults(
        outputs_prefix="RiskIQDigitalFootprint.AssetChanges",
        outputs_key_field=output_key_fields,
        outputs=custom_ec,
        readable_output=hr,
        raw_response=resp
    ))

    return ioc_command_results


@logger
def get_asset_command(client: Client, args: Dict[str, Any]) -> Union[str, List[CommandResults]]:
    """
    Retrieve the asset of the specified UUID from Global Inventory.

    :param client: The Client object used for request
    :param args: The command arguments
    :return: CommandResults
    :return: CommandResults
    """

    uuid, asset_type = validate_and_fetch_get_asset_arguments(args)
    params = get_asset_params(args)

    if uuid:
        resp = client.http_request(method='GET', url_suffix=COMMAND_URL_SUFFIX['GET_ASSET_BY_UUID'].format(uuid),
                                   params=params)
    else:
        resp = client.http_request(method='GET', url_suffix=COMMAND_URL_SUFFIX['GET_ASSET_BY_NAME_AND_TYPE']
                                   .format(asset_type), params=params)

    command_results = get_asset_outputs(resp)
    return command_results


@logger
def add_assets_command(client: Client, args: Dict[str, Any]) -> Union[str, CommandResults]:
    """
    Adds one or more assets to Global Inventory with a provided set of properties to apply to all assets.

    :param client: The Client object used for request
    :param args: The command arguments
    :return: CommandResults
    """

    # Validate arguments
    valid_json = validate_asset_payload(args, 'add')
    params: Dict[str, Any] = get_add_and_update_assets_params(args)

    # API call
    resp = client.http_request(method='POST', url_suffix=COMMAND_URL_SUFFIX['ADD_ASSET'], json_data=valid_json,
                               params=params)

    task_resp = check_task_status(client, resp)

    # Create HR
    hr = prepare_add_and_update_asset_hr(task_resp, True)

    # Create entry context
    custom_ec = prepare_add_and_update_asset_context(task_resp)
    return CommandResults(
        outputs_prefix='RiskIQDigitalFootprint.Task',
        outputs_key_field='uuid',
        outputs=custom_ec,
        readable_output=hr,
        raw_response=task_resp
    )


@logger
def update_assets_command(client: Client, args: Dict[str, Any]) -> Union[str, CommandResults]:
    """
    Updates one or more assets in Global Inventory with provided set of properties

    :param client: The Client object used for request
    :param args: The command arguments
    :return: CommandResults
    """

    # Validate arguments
    valid_json = validate_asset_payload(args, 'update')
    params: Dict[str, Any] = get_add_and_update_assets_params(args)

    # API call
    resp = client.http_request(method='POST', url_suffix=COMMAND_URL_SUFFIX['UPDATE_ASSET'], json_data=valid_json,
                               params=params)

    task_resp = check_task_status(client, resp)

    # Create HR
    hr = prepare_add_and_update_asset_hr(task_resp, False)

    # Create entry context
    custom_ec = prepare_add_and_update_asset_context(task_resp)
    return CommandResults(
        outputs_prefix='RiskIQDigitalFootprint.Task',
        outputs_key_field='uuid',
        outputs=custom_ec,
        readable_output=hr,
        raw_response=task_resp
    )


def main() -> None:
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """

    # Commands dict
    commands = {
        'df-asset-changes-summary': asset_changes_summary_command,
        'df-add-assets': add_assets_command,
        'df-update-assets': update_assets_command,
        'df-asset-connections': asset_connections_command,
        'df-asset-changes': asset_changes_command,
        'df-get-asset': get_asset_command,
    }

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        # Retrieve XSOAR params
        url = demisto.params().get('url')
        token = demisto.params().get('token')
        secret = demisto.params().get('secret')
        verify_certificate = not demisto.params().get('insecure', False)
        proxy = demisto.params().get('proxy', False)

        # Trim the arguments
        args = demisto.args()
        for argument in args:
            if isinstance(args[argument], str):
                args[argument] = args[argument].strip()

        # Fetch the request_timeout according to the value of size argument
        request_timeout = 10
        size = args.get('size')
        if size:
            request_timeout, size = get_timeout_and_size(size)
            args['size'] = size

        client = Client(base_url=url, request_timeout=request_timeout, verify=verify_certificate, proxy=proxy,
                        auth=(token, secret))

        command = demisto.command()

        # This is the call made when pressing the integration Test button.
        if command == 'test-module':
            result = test_function(client)
            demisto.results(result)
        elif command in commands:
            return_results(commands[command](client, args))

    # Log exceptions
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Error: {str(e)}')


def init():
    if __name__ in ('__main__', '__builtin__', 'builtins'):
        main()


init()
