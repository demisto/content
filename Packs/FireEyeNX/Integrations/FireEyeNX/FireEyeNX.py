from CommonServerPython import *

''' IMPORTS '''

from requests import Response
from typing import Dict, Any, Union, Tuple, List
from datetime import timezone
from requests.exceptions import MissingSchema, InvalidSchema, InvalidURL, SSLError
import urllib3
from re import split

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DEFAULT_REQUEST_TIMEOUT = 120
REQUEST_TIMEOUT_MAX_VALUE = 9223372036

API_VERSION = 'v2.0.0'

DEFAULT_SESSION_TIMEOUT = 15 * 60  # In Seconds
DEFAULT_FETCH_LIMIT = '10'
CONTENT_TYPE_JSON = 'application/json'
CONTENT_TYPE_ZIP = 'application/zip'
DATE_FORMAT_OF_YEAR_MONTH_DAY = '%Y-%m-%d'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
ALERT_DETAILS_REPORT = 'Alert Details Report'
VICTIM_IP = 'Victim IP'
TIME_UTC = 'Time (UTC)'

MESSAGES: Dict[str, str] = {
    'BAD_REQUEST_ERROR': 'An error occurred while fetching the data.',
    'AUTHENTICATION_ERROR': 'Unauthenticated. Check the configured Username and Password.',
    'PROXY_ERROR': 'Proxy Error - cannot connect to proxy. Either try clearing the \'Use system proxy\' check-box or '
                   'check the host, authentication details and connection details for the proxy.',
    'BLANK_PROXY_ERROR': 'https proxy value is empty. Check XSOAR server configuration ',
    'SSL_CERT_ERROR': 'SSL Certificate Verification Failed - try selecting \'Trust any certificate\' checkbox in the '
                      'integration configuration.',
    'INTERNAL_SERVER_ERROR': 'The server encountered an internal error for FireEye NX and was unable to complete '
                             'your request.',
    'MISSING_SCHEMA_ERROR': 'Invalid API URL. No schema supplied: http(s).',
    'INVALID_SCHEMA_ERROR': 'Invalid API URL. Supplied schema is invalid, supports http(s).',
    'INVALID_API_URL': 'Invalid API URL.',
    'CONNECTION_ERROR': 'Connectivity failed. Check your internet connection or the API URL.',
    'INVALID_ALERT_DETAILS': 'For fetching Alert Details Report, "infection_id" and "infection_type" '
                             'arguments are required.',
    'INVALID_REPORT_TYPE': 'The given value for report_type is invalid.',
    'INVALID_REPORT_OUTPUT_TYPE': 'The given value for the argument type (report\'s format) is invalid. Valid value('
                                  's): {}.',
    'NO_RECORDS_FOUND': 'No {} were found for the given argument(s).',
    'INVALID_INT_VALUE': 'The given value for {} is invalid. Expected integer value.',
    'FETCH_LIMIT_VALIDATION': 'Value of Fetch Limit should be an integer and between range 1 to 200.',
    'INVALID_BOOLEAN_VALUE_ERROR': 'The given value for {0} argument is invalid. Valid values: true, false.',
    'REQUEST_TIMEOUT_VALIDATION': 'HTTP(S) Request timeout parameter must be a positive integer.',
    'REQUEST_TIMEOUT_EXCEED_ERROR': 'Value is too large for HTTP(S) Request Timeout.',
    'REQUEST_TIMEOUT': 'Request timed out. Check the configured HTTP(S) Request Timeout (in seconds) value.'
}

URL_SUFFIX: Dict[str, str] = {
    'TEST_MODULE': '/auth/login',
    'GET_ARTIFACTS_METADATA': '/artifacts/{}/meta',
    'GET_ARTIFACTS': '/artifacts/{}',
    'GET_REPORTS': '/reports/report',
    'GET_ALERTS': '/alerts',
    'GET_EVENTS': '/events'
}

REPORT_TYPE_LABEL_NAME = {
    'Website Callback Server Report': 'mpsCallBackServer',
    'Website Executive Summary': 'mpsExecutiveSummary',
    'Website Infected Host Trends': 'mpsInfectedHostsTrend',
    'Website Malware Activity': 'mpsMalwareActivity',
    'Website Antivirus Report': 'mpsWebAVReport',
    'IPS Executive Summary Report': 'ipsExecutiveSummary',
    'IPS Top N Attacks Report': 'ipsTopNAttack',
    'IPS Top N Attackers Report': 'ipsTopNAttacker',
    'IPS Top N Victims Report': 'ipsTopNVictim',
    'IPS Top N MVX-Correlated Report': 'ipsTopNMvxVerified',
    ALERT_DETAILS_REPORT: 'alertDetailsReport'
}
REPORT_TYPE_ALLOWED_FORMAT = {
    'Website Callback Server Report': ['csv'],
    'Website Executive Summary': ['pdf'],
    'Website Infected Host Trends': ['csv'],
    'Website Malware Activity': ['pdf', 'csv'],
    'Website Antivirus Report': ['csv'],
    'IPS Executive Summary Report': ['pdf', 'csv'],
    'IPS Top N Attacks Report': ['pdf', 'csv'],
    'IPS Top N Attackers Report': ['pdf', 'csv'],
    'IPS Top N Victims Report': ['pdf', 'csv'],
    'IPS Top N MVX-Correlated Report': ['pdf', 'csv'],
    ALERT_DETAILS_REPORT: ['pdf']
}


class Client(BaseClient):
    """
    Client to use in integration with powerful http_request.
    It extends the base client and uses the http_request method for the API request.
    Handle some exceptions externally.
    """

    def __init__(self, base_url: str, verify: bool, proxy: bool, auth: Tuple[str, str], request_timeout: int):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, auth=auth)
        self.request_timeout = request_timeout
        # Set proxy
        self.proxies = handle_proxy()
        # Throws a ValueError if Proxy is empty in configuration.
        if proxy and not self.proxies.get('https', True):
            raise ValueError(MESSAGES['BLANK_PROXY_ERROR'] + str(self.proxies))

    def http_request(self, method: str, url_suffix: str, json_data=None, params=None,
                     headers=None):
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
        resp = Response()
        try:
            resp = self._http_request(method=method, url_suffix=url_suffix, json_data=json_data, params=params,
                                      headers=headers, resp_type='response',
                                      timeout=self.request_timeout,
                                      ok_codes=(200, 201, 400, 401, 403, 404, 406, 407, 500, 503),
                                      proxies=self.proxies)
        except MissingSchema:
            raise ValueError(MESSAGES['MISSING_SCHEMA_ERROR'])
        except InvalidSchema:
            raise ValueError(MESSAGES['INVALID_SCHEMA_ERROR'])
        except InvalidURL:
            raise ValueError(MESSAGES['INVALID_API_URL'])
        except DemistoException as e:
            self.handle_demisto_exception(e)

        if resp.ok:
            content_type = resp.headers.get('Content-Type', '')
            if content_type == CONTENT_TYPE_JSON:
                # Handle empty response
                if resp.text == '':
                    return resp
                else:
                    return resp.json()
            elif self.is_supported_context_type(content_type):
                return resp
        else:
            self.handle_error_response(resp)

    @staticmethod
    def is_supported_context_type(content_type: str):
        """
        Check whether content type is supported or not.
        :param content_type: content type of header.
        :return: boolean flag, whether content type is supported or not.
        """
        if content_type == 'application/pdf' or content_type == 'text/csv' or content_type == CONTENT_TYPE_ZIP:
            return True
        return False

    @staticmethod
    def handle_demisto_exception(e):
        """
        Handle Demisto exception based on string.

        :param e: Demisto Exception
        :return: Error message
        """
        if 'Proxy Error' in str(e):
            raise ConnectionError(MESSAGES['PROXY_ERROR'])
        elif 'ReadTimeoutError' in str(e):
            raise ConnectionError(MESSAGES['REQUEST_TIMEOUT'])
        elif 'ConnectionError' in str(e) or 'ConnectTimeoutError' in str(e):
            raise ConnectionError(MESSAGES['CONNECTION_ERROR'])
        elif 'SSLError' in str(e):
            raise SSLError(MESSAGES['SSL_CERT_ERROR'])
        else:
            raise e

    @staticmethod
    def handle_error_response(resp):
        """
        Handle error response and display user specific error message based on status code.

        :param resp: response from API.
        :return: raise DemistoException based on status code.
        """
        error_message = ''
        error_message_with_reason = ''
        try:
            error_message = resp.json().get('fireeyeapis', {}).get('description', '').strip()
            error_message = error_message.replace('\n', '')
            if error_message:
                error_message_with_reason = f"Reason: {error_message}"
        except ValueError:  # ignoring json parsing errors
            pass
        if resp.headers.get('Content-Type', '') == CONTENT_TYPE_ZIP:
            error_message = error_message_with_reason = resp.text

        status_code_messages = {
            400: f"{MESSAGES['BAD_REQUEST_ERROR']} {error_message_with_reason}",
            401: MESSAGES['AUTHENTICATION_ERROR'],
            403: error_message,
            404: error_message,
            406: error_message,
            407: MESSAGES['PROXY_ERROR'],
            500: MESSAGES['INTERNAL_SERVER_ERROR'],
            503: MESSAGES['INTERNAL_SERVER_ERROR']
        }

        if resp.status_code in status_code_messages:
            demisto.debug(f'Response Code: {resp.status_code}, Reason: {status_code_messages[resp.status_code]}')
            raise DemistoException(status_code_messages[resp.status_code])
        else:
            resp.raise_for_status()

    def get_api_token(self):
        """
        Retrieve new api token and set it to integration context.
        if api token is not not found or expired, making api call to retrieve api token and set it to integration
        context.

        :return: api-token
        """
        integration_context = demisto.getIntegrationContext()
        api_token = integration_context.get('api_token')
        valid_until = integration_context.get('valid_until')

        # Return api token from integration context, if found and not expired
        if api_token and valid_until and time.time() < valid_until:
            demisto.debug('Retrieved api-token from integration cache.')
            return api_token

        headers = {
            'Accept': CONTENT_TYPE_JSON
        }

        demisto.debug('Calling authentication API for retrieve api-token')
        resp = self.http_request(method='POST', url_suffix=URL_SUFFIX['TEST_MODULE'], headers=headers)
        integration_context = self.set_integration_context(resp)

        return integration_context.get('api_token')

    @staticmethod
    def set_integration_context(resp):
        """
        set api token and expiry time in integration configuration context.
        Will raise value error if api-token is not found.

        :param resp: resp from API.
        :return: integration context
        """
        integration_context = demisto.getIntegrationContext()
        api_token = resp.headers.get('X-FeApi-Token')
        if api_token:
            shorten_by = 5  # Shorten token validity period by 5 seconds for safety
            integration_context['api_token'] = api_token
            integration_context['valid_until'] = time.time() + DEFAULT_SESSION_TIMEOUT - shorten_by
        else:
            raise ValueError('No api token found. Please try again')
        demisto.setIntegrationContext(integration_context)
        return integration_context


''' HELPER FUNCTION'''


def get_request_timeout() -> int:
    """
    Validate and return the request timeout parameter.
    The parameter must be a positive integer.
    Default value is set to 60 seconds for API request timeout.
    Will raise ValueError if inappropriate input given.

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


def get_fetch_limit():
    """
    Retrieve fetch limit from demisto arguments and validate it.
    Will raise ValueError if inappropriate input given.

    :return: fetch limit
    """
    fetch_limit = demisto.params().get('fetch_limit', DEFAULT_FETCH_LIMIT)
    fetch_limit = DEFAULT_FETCH_LIMIT if not fetch_limit else fetch_limit

    try:
        if not 1 <= int(fetch_limit) <= 200:
            raise ValueError(MESSAGES['FETCH_LIMIT_VALIDATION'])
    except ValueError:
        raise ValueError(MESSAGES['FETCH_LIMIT_VALIDATION'])

    return fetch_limit


def generate_report_file_name(args: Dict[str, Any]) -> str:
    """
    Create the filename of the info file of report.

    :param args: Input arguments
    :return: The report file name
    """
    return f"{args.get('report_type', '').lower().replace(' ', '_')}_fireeye_" \
           f"{datetime.now().strftime('%Y-%m-%d_%H:%M:%S')}." \
           f"{args.get('type', REPORT_TYPE_ALLOWED_FORMAT[args.get('report_type', '')][0])}"


def validate_alert_report_type_arguments(args: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validates the arguments required for alert details report type from input arguments of reports command.
    Will raise ValueError if inappropriate input given.

    :param args: Input arguments
    :param params: Params to be passed in API call
    :return: Params to be passed in API call
    """
    arg_keys = args.keys()

    if 'infection_id' in arg_keys and 'infection_type' in arg_keys:
        params['infection_id'] = args.get('infection_id', '')
        params['infection_type'] = args.get('infection_type', '')
    else:
        raise ValueError(MESSAGES['INVALID_ALERT_DETAILS'])
    return params


def validate_ips_report_type_arguments(args: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validates the arguments required for IPS report types from input arguments of reports command.
    Will raise ValueError if inappropriate input given.

    :param args: Input arguments
    :param params: Params to be passed in API call
    :return: Params to be passed in API call
    """
    arg_keys = args.keys()

    if 'limit' in arg_keys:
        limit = args.get('limit', '')
        try:
            params['limit'] = int(limit)
        except ValueError:
            raise ValueError(MESSAGES['INVALID_INT_VALUE'].format('limit'))
    if 'interface' in arg_keys:
        params['interface'] = args.get('interface', '') if args.get('interface', '') != 'All' else 'all'
    return params


def validate_date(date: str, date_format: str) -> str:
    """
    Validate and add date suffix into date.
    Will raise ValueError if error occur.

    :param date: The date value.
    :param date_format: The format of date.
    :return: return formated date.
    """
    datetime.strptime(date, date_format).strftime(date_format)
    return f"{date}T00:00:00.000+00:00"


def validate_time_parameters(args: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validates the time arguments from input arguments of reports command.

    :param args: Input arguments
    :param params: Params to be passed in API call
    :return: Params to be passed in API call
    """
    arg_keys = args.keys()

    if 'time_frame' in arg_keys:
        params['time_frame'] = args.get('time_frame', '')

    if 'start_time' in arg_keys:
        start_time = args.get('start_time', '')
        try:
            params['start_time'] = validate_date(start_time, DATE_FORMAT_OF_YEAR_MONTH_DAY)
        except ValueError:
            params['start_time'] = start_time

    if 'end_time' in arg_keys:
        end_time = args.get('end_time', '')
        try:
            params['end_time'] = validate_date(end_time, DATE_FORMAT_OF_YEAR_MONTH_DAY)
        except ValueError:
            params['end_time'] = end_time

    return params


def get_reports_params(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validates the input arguments of command and returns parameter dictionary. This function validates the
    report_type, output format(type), time arguments.
    Will raise ValueError if inappropriate input given.

    :param args: Input arguments of command
    :return: Params dict or error message
    """
    params: Dict[str, Any] = {}
    arg_keys = args.keys()

    report_type = args.get('report_type', '')
    if report_type not in REPORT_TYPE_LABEL_NAME:
        raise ValueError(MESSAGES['INVALID_REPORT_TYPE'])
    params['report_type'] = REPORT_TYPE_LABEL_NAME[report_type]

    if 'type' in arg_keys:
        output_type = args.get('type', '')
        if output_type not in REPORT_TYPE_ALLOWED_FORMAT[report_type]:
            raise ValueError(MESSAGES['INVALID_REPORT_OUTPUT_TYPE']
                             .format(', '.join(REPORT_TYPE_ALLOWED_FORMAT[report_type])))
        params['type'] = output_type

    params = validate_time_parameters(args, params)

    params = validate_ips_report_type_arguments(args, params)

    if report_type == ALERT_DETAILS_REPORT:
        params = validate_alert_report_type_arguments(args, params)

    return params


def add_time_suffix_into_arguments(args):
    """
    Add time suffix into arguments.

    :param args: arguments of alerts.
    :return: Add suffix to date format if full format is not given.
    """
    arg_keys = args.keys()
    if 'start_time' in arg_keys:
        start_time = args.get('start_time', '')
        try:
            args['start_time'] = validate_date(start_time, DATE_FORMAT_OF_YEAR_MONTH_DAY)
        except ValueError:
            args['start_time'] = start_time
    if 'end_time' in arg_keys:
        end_time = args.get('end_time', '')
        try:
            args['end_time'] = validate_date(end_time, DATE_FORMAT_OF_YEAR_MONTH_DAY)
        except ValueError:
            args['end_time'] = end_time


def get_events_params(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validates the input arguments of command and returns parameter dictionary
    or raises ValueError in case of validation failed.

    :param args: Input arguments of command
    :return: Params dict or error message
    """
    params: Dict[str, Any] = {
        'event_type': 'Ips Event'
    }
    arg_keys = args.keys()

    if 'duration' in arg_keys:
        params['duration'] = args.get('duration', '')
    if 'end_time' in arg_keys:
        params['end_time'] = args.get('end_time', '')
    if 'mvx_correlated_only' in arg_keys:
        mvx_correlated_only = args.get('mvx_correlated_only', '').lower()
        try:
            mvx_correlated_only = argToBoolean(mvx_correlated_only)
            params['mvx_correlated_only'] = mvx_correlated_only
        except ValueError:
            raise ValueError(MESSAGES['INVALID_BOOLEAN_VALUE_ERROR'].format('mvx_correlated_only'))

    return params


def prepare_hr_for_artifact_metadata(artifacts_info) -> str:
    """
    Prepare Human readable for get artifact metadata.

    :param artifacts_info: List contain artifact metadata information.
    :return: Markdown format in string.
    """
    artifacts_info_hr_list = []

    for artifact in artifacts_info:
        artifacts_dict = {
            'Artifact Type': artifact.get('artifactType', ''),
            'Artifact Name': artifact.get('artifactName', ''),
            'Artifact Size (Bytes)': artifact.get('artifactSize', ''),
        }
        artifacts_info_hr_list.append(artifacts_dict)

    return tableToMarkdown('Artifacts Metadata', artifacts_info_hr_list,
                           headers=['Artifact Type', 'Artifact Name', 'Artifact Size (Bytes)'], removeNull=True)


def nested_to_flat(src: Dict[str, Any], key: str) -> Dict[str, Any]:
    """
    Convert nested dictionary to flat by contact the keys. Also converts keys in pascal string format.

    :param src: sub-dictionary that needs to convert from nested to flat. (e.g. "foo": {"bar": "some-value"})
    :param key: main key of sub-dictionary (e.g "foo")
    :return: flat dictionary with pascal formatted keys (e.g. {"FooBar": "some-value"})
    """
    flat_dict: Dict[str, str] = {}
    for sub_key, sub_value in src.items():
        pascal_key = '{}{}'.format(key[0].upper() + key[1:], sub_key[0].upper() + sub_key[1:])
        flat_dict[pascal_key] = sub_value

    return flat_dict


def prepare_context_dict(response_dict: Dict[str, Any],
                         keys_with_hierarchy: tuple = (),
                         exclude_keys: tuple = ()) -> Dict[str, Any]:
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
            if type(response_dict.get(key, {})) is not str:
                simple_dict.update(nested_to_flat(response_dict.get(key, {}), key))
        elif key not in exclude_keys:
            simple_dict[key] = value
    return simple_dict


def pascal_case(st) -> str:
    """
    Covert string to pascal case.

    :param st: string
    :return: pascal case string.
    """
    return ''.join(a.capitalize() for a in split('([^a-zA-Z])', st) if a.isalnum())


def convert_dict_key_into_pascal_case(dictionary: Dict[str, Any]) -> Dict:
    """
    Convert dictionary into pascal case dictionary.

    :param dictionary: dictionary contain keys and values.
    :return: pascal case string.
    """
    pascal_dict: Dict[str, Any] = {}
    for key in dictionary:
        new_key = pascal_case(key)
        pascal_dict.update({new_key: dictionary[key]})

    return pascal_dict


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


def prepare_heapspraying_context(heapspraying_list: list) -> Dict:
    """
    Prepare context for heapspraying key in os changes response.

    :param heapspraying_list: List of heapspraying.
    :return: Dictionary of context output for heapspraying.
    """
    heapspraying_context_list = []
    for heapspraying in heapspraying_list:
        heapspraying_context_dict = prepare_context_dict(heapspraying, keys_with_hierarchy=('processinfo', ''),
                                                         exclude_keys=('BytesList', ''))
        heapspraying_context_dict.update(
            nested_to_flat(
                prepare_context_dict(response_dict=heapspraying.get('BytesList', {}), exclude_keys=('Entry', '')),
                key='BytesList'))
        heapspraying_context_dict.update({'BytesListEntry': heapspraying.get('BytesList', {}).get('Entry', {})})

        heapspraying_context_list.append(heapspraying_context_dict)
    return {'heapspraying': heapspraying_context_list}


def prepare_process_context(process_list: list) -> Dict:
    """
    Prepare context for process key in os changes response.

    :param process_list: List of process.
    :return: Dictionary of context output for process.
    """
    process_context_list = []
    for process in process_list:
        process_context_dict = prepare_context_dict(process,
                                                    keys_with_hierarchy=('fid', 'ParentUserAccount', 'UserAccount'),
                                                    exclude_keys=('telemetry_data', ''))
        process_context_dict.update(
            nested_to_flat(convert_dict_key_into_pascal_case(process.get('telemetry_data', {})), key='TelemetryData'))
        process_context_list.append(process_context_dict)
    return {'process': process_context_list}


def prepare_regkey_context(regkey_list: list) -> Dict:
    """
    Prepare context for regkey key in os changes response.

    :param regkey_list: List of regkey.
    :return: Dictionary of context output for regkey.
    """
    regkey_context_list = []
    for regkey in regkey_list:
        regkey_context_list.append(prepare_context_dict(regkey, keys_with_hierarchy=('processinfo', '')))
    return {'regkey': regkey_context_list}


def prepare_network_context(network: Union[Dict[str, Any], List[Dict[str, Any]]]) -> Dict[str, Any]:
    """
    Prepare context for network key in os changes response.

    :param network: List or dictionary of network.
    :return: Dictionary of context output for network.
    """
    network_context_dict: Dict[str, Any] = {}
    if type(network) is dict:
        network_context_dict = {
            'network': prepare_context_dict(network, keys_with_hierarchy=('processinfo', ''))}  # type: ignore
    elif type(network) is list:
        network_context_list = []
        for network_dict in network:
            network_context_list.append(
                prepare_context_dict(network_dict, keys_with_hierarchy=('processinfo', '')))  # type: ignore
        network_context_dict = {'network': network_context_list}
    return network_context_dict


def prepare_exploitcode_context(exploitcode_list: list) -> Dict:
    """
    Prepare context for exploitcode key in os changes response.

    :param exploitcode_list: List of exploitcode.
    :return: Dictionary of context output for exploitcode.
    """
    exploitcode_context_list = []
    for exploitcode in exploitcode_list:
        exploitcode_context_dict = prepare_context_dict(exploitcode, keys_with_hierarchy=('processinfo', ''),
                                                        exclude_keys=('callstack', 'params'))
        callstack_entry_context_list = []
        for callstack_entry in exploitcode.get('callstack', {}).get('callstack-entry', []):
            callstack_entry_context_list.append(
                convert_dict_key_into_pascal_case(callstack_entry))
        exploitcode_context_dict.update({'CallstackEntry': callstack_entry_context_list})
        exploitcode_context_dict.update({'param': exploitcode.get('params', {}).get('param', {})})
        exploitcode_context_list.append(exploitcode_context_dict)
    return {'exploitcode': exploitcode_context_list}


def prepare_folder_context(folder_list: list) -> Dict:
    """
    Prepare context for folder key in os changes response.

    :param folder_list: List of folder.
    :return: Dictionary of context output for folder.
    """
    folder_context_list = []
    for folder in folder_list:
        folder_context_list.append(prepare_context_dict(folder, keys_with_hierarchy=('processinfo', '')))
    return {'folder': folder_context_list}


def prepare_file_context(file_list: list) -> Dict:
    """
    Prepare context for file key in os changes response.

    :param file_list: List of file.
    :return: Dictionary of context output for file.
    """
    file_context_list = []
    for file in file_list:
        file_context_dict = prepare_context_dict(file, keys_with_hierarchy=('fid', 'processinfo'),
                                                 exclude_keys=('PE', ''))

        file_context_dict.update(nested_to_flat(prepare_context_dict(file.get('PE', {}),
                                                                     exclude_keys=('Characteristics',
                                                                                   'DllCharacteristics')), key='PE'))
        file_context_dict.update(
            nested_to_flat(file.get('PE', {}).get('DllCharacteristics', {}),
                           key='PEDllCharacteristics'))
        file_context_dict.update(
            nested_to_flat(file.get('PE', {}).get('Characteristics', {}).get('names', {}), key='PECharacteristics'))
        file_context_dict.update(
            {'PECharacteristicsValue': file.get('PE', {}).get('Characteristics', {}).get('value', {})})
        file_context_list.append(file_context_dict)
    return {'file': file_context_list}


def prepare_malicious_alert_context(malicious_alert_list: list) -> Dict:
    """
    Prepare context for malicious alert key in os changes response.

    :param malicious_alert_list: List of malicious alert.
    :return: Dictionary of context output for malicious alert.
    """
    malicious_alert_context_list = []
    for malicious_alert in malicious_alert_list:
        malicious_alert_context_list.append(convert_dict_key_into_pascal_case(malicious_alert))
    return {'MaliciousAlert': malicious_alert_context_list}


def prepare_dialog_detected_context(dialog_detected_list: list) -> Dict:
    """
    Prepare context for dialog detected key in os changes response.

    :param dialog_detected_list: List of dialog detected.
    :return: Dictionary of context output for dialog detected.
    """
    dialog_detected_context_list = []
    for dialog_detected in dialog_detected_list:
        dialog_detected_context_list.append(
            prepare_context_dict(convert_dict_key_into_pascal_case(dialog_detected),
                                 keys_with_hierarchy=('Processinfo', '')))
    return {'DialogDetected': dialog_detected_context_list}


def prepare_dialog_dismissed_context(dialog_dismissed_list: list) -> Dict:
    """
    Prepare context for dialog dismissed key in os changes response.

    :param dialog_dismissed_list: List of dialog dismissed.
    :return: Dictionary of context output for dialog dismissed.
    """
    dialog_dismissed_context_list = []
    for dialog_dismissed in dialog_dismissed_list:
        dialog_dismissed_context_list.append(
            prepare_context_dict(convert_dict_key_into_pascal_case(dialog_dismissed),
                                 keys_with_hierarchy=('Processinfo', '')))
    return {'DialogDismissed': dialog_dismissed_context_list}


def prepare_os_changes_context_output(os_changes: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prepare context for os changes key in alert response.

    :param os_changes: Dictionary of os changes.
    :return: Dictionary of context output for os changes.
    """
    os_changes_context = {}
    os_changes_context.update(nested_to_flat(os_changes.get('os', {}), key='os'))
    os_changes_context.update(nested_to_flat(os_changes.get('os_monitor', {}), key='OsMonitor'))
    os_changes_context.update(nested_to_flat(os_changes.get('analysis', {}), key='Analysis'))
    os_changes_context.update(
        convert_dict_key_into_pascal_case(nested_to_flat(os_changes.get('action_fopen', {}), key='action_fopen_')))
    os_changes_context.update(
        convert_dict_key_into_pascal_case(nested_to_flat(os_changes.get('application', {}), key='application_')))
    os_changes_context.update(nested_to_flat(prepare_context_dict(response_dict=os_changes.get('QuerySystemTime', {}),
                                                                  keys_with_hierarchy=('processinfo', 'SystemTime')),
                                             key='QuerySystemTime'))
    os_changes_context.update({'EndOfReport': os_changes.get('end-of-report', '')})
    os_changes_context.update(nested_to_flat(
        prepare_context_dict(convert_dict_key_into_pascal_case(os_changes.get('wmiquery', {})),
                             exclude_keys=('Wmicontents', ''),
                             keys_with_hierarchy=('Processinfo', '')), key='Wmiquery'))
    os_changes_context.update(
        nested_to_flat(os_changes.get('wmiquery', {}).get('wmicontents', {}).get('wmicontent', {}),
                       key='WmiqueryWmicontent'))

    os_changes_context.update(prepare_heapspraying_context(os_changes.get('heapspraying', [])))

    os_changes_context.update(prepare_process_context(os_changes.get('process', [])))

    os_changes_context.update(prepare_regkey_context(os_changes.get('regkey', [])))

    os_changes_context.update(prepare_network_context(os_changes.get('network', [])))

    os_changes_context.update(prepare_exploitcode_context(os_changes.get('exploitcode', [])))

    os_changes_context.update(prepare_folder_context(os_changes.get('folder', [])))

    os_changes_context.update(prepare_file_context(os_changes.get('file', [])))

    os_changes_context.update(prepare_malicious_alert_context(os_changes.get('malicious-alert', [])))

    os_changes_context.update(prepare_dialog_detected_context(os_changes.get('dialog-detected', [])))

    os_changes_context.update(prepare_dialog_dismissed_context(os_changes.get('dialog-dismissed', [])))

    os_changes_context.update({'uac': os_changes.get('uac', [])})
    return os_changes_context


def get_alert_context_output(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prepare context for alert response.

    :param alert: Dictionary of response.
    :return: Dictionary of context output for alert.
    """
    alert_context = prepare_context_dict(response_dict=alert, keys_with_hierarchy=(
        'src', 'dst', 'staticAnalysis', 'stolenData'), exclude_keys=('explanation', 'cncServices', 'osChanges'))
    alert_context.update(nested_to_flat(prepare_context_dict(
        response_dict=alert.get('explanation', {}).get('stolenData', {}),
        keys_with_hierarchy=('info', '')), 'StolenData')
    )
    alert_context.update(nested_to_flat(alert.get('explanation', {}).get('staticAnalysis', {}),
                                        key='StaticAnalysis'))

    alert_context.update(alert.get('explanation', {}).get('malwareDetected', {}))

    alert_context.update(alert.get('explanation', {}).get('cncServices', {}))

    os_changes_context = []
    for os_changes in alert.get('explanation', {}).get('osChanges', []):
        os_changes_context.append(prepare_os_changes_context_output(os_changes))
    alert_context.update({'osChanges': os_changes_context})
    return alert_context


def prepare_hr_for_alert_response(resp: Dict) -> str:
    """
    Prepare human readable for alert response.

    :param resp: Dictionary of API response
    :return: Markdown format for human readable.
    """
    alert_hr_list = []

    for alert in resp.get('alert', []):
        artifacts_dict = {
            'ID': alert.get('id', ''),
            'Distinguisher(UUID)': alert.get('uuid', ''),
            'Malware Name': alert.get('explanation',
                                      {}).get('malwareDetected', {}).get('malware', [{}])[0].get('name', ''),
            'Alert Type': alert.get('name', ''),
            VICTIM_IP: alert.get('src', {}).get('ip', ''),
            TIME_UTC: alert.get('occurred', ''),
            'Severity': alert.get('severity', ''),
            'Malicious': alert.get('malicious', ''),
            'SC Version': alert.get('scVersion', ''),
            'Victim Port': alert.get('src', {}).get('port', ''),
            'Victim MAC Address': alert.get('src', {}).get('mac', ''),
            'Target IP': alert.get('dst', {}).get('ip', ''),
            'Target Port': alert.get('dst', {}).get('port', ''),
            'Target MAC Address': alert.get('dst', {}).get('mac', '')
        }
        alert_hr_list.append(artifacts_dict)
    headers = ['ID', 'Distinguisher(UUID)', 'Malware Name', 'Alert Type', VICTIM_IP, TIME_UTC, 'Severity',
               'Malicious',
               'SC Version', 'Victim Port', 'Victim MAC Address', 'Target IP', 'Target Port', 'Target MAC Address']
    return tableToMarkdown("Alert(s) Information", alert_hr_list,
                           headers=headers, removeNull=True)


def prepare_hr_for_events(events_info) -> str:
    """
    Prepare the Human readable info for events command.

    :param events_info: The events data.
    :return: Human readable.
    """
    hr_list = []
    for record in events_info:
        hr_record = {
            'Event ID': record.get('eventId', None),
            TIME_UTC: record.get('occurred', ''),
            VICTIM_IP: record.get('srcIp', ''),
            'Attacker IP': record.get('dstIp', ''),
            'CVE ID': record.get('cveId', ''),
            'Severity': record.get('severity', None),
            'Rule': record.get('ruleName', ''),
            'Protocol': record.get('protocol', None)
        }
        hr_list.append(hr_record)

    return tableToMarkdown('IPS Events', hr_list,
                           ['Event ID', TIME_UTC, VICTIM_IP, 'Attacker IP', 'CVE ID',
                            'Severity', 'Rule', 'Protocol'], removeNull=True)


''' REQUESTS FUNCTIONS '''


def test_function(client: Client) -> str:
    """
    Performs test connectivity by valid http response

    :param client: client object which is used to get response from api
    :return: raise ValueError if any error occurred during connection
    """
    headers = {
        'Accept': CONTENT_TYPE_JSON
    }
    client.http_request(method='POST', url_suffix=URL_SUFFIX['TEST_MODULE'], headers=headers)

    return 'ok'


@logger
def get_artifacts_metadata_by_alert_command(client: Client, args: Dict[str, Any]) -> Union[str, CommandResults]:
    """
    Gets malware artifacts metadata for the specified UUID.

    :param client: The Client object used for request
    :param args: The command arguments
    :return: CommandResults
    """
    uuid = args.get('uuid', '')
    if not uuid.islower():
        uuid = uuid.lower()

    # Preparing header
    headers = {
        'Accept': CONTENT_TYPE_JSON,
        'X-FeApi-Token': client.get_api_token()
    }

    # Call get artifacts metadata api
    resp = client.http_request('GET', url_suffix=URL_SUFFIX['GET_ARTIFACTS_METADATA'].format(uuid), headers=headers)

    artifacts_info = resp.get('artifactsInfoList', [])
    if len(artifacts_info) == 0:
        return MESSAGES['NO_RECORDS_FOUND'].format('artifacts metadata')

    # Create entry context
    artifacts_metadata_custom_ec = createContext(artifacts_info, removeNull=True)

    # Prepare human readable
    hr = prepare_hr_for_artifact_metadata(artifacts_info)

    custom_ec = {
        'ArtifactsMetadata': artifacts_metadata_custom_ec,
        'uuid': uuid
    }
    return CommandResults(
        outputs_prefix='FireEyeNX.Alert',
        outputs_key_field='uuid',
        outputs=custom_ec,
        readable_output=hr,
        raw_response=resp
    )


@logger
def get_artifacts_by_alert_command(client: Client, args: Dict[str, Any]) -> Union[str, Dict[str, Any]]:
    """
    Downloads malware artifacts data for the specified UUID as a zip file.

    :param client: The Client object used for request
    :param args: The command arguments
    :return: Dictionary of file info or empty result message
    """
    uuid = args.get('uuid', '')

    if not uuid.islower():
        uuid = uuid.lower()

    # Preparing header
    headers = {
        'accept': CONTENT_TYPE_ZIP,
        'X-FeApi-Token': client.get_api_token()
    }

    # Call get artifacts data api
    artifacts_resp = client.http_request('GET', url_suffix=URL_SUFFIX[
        'GET_ARTIFACTS'].format(uuid), headers=headers)

    # Create file from Content
    if int(artifacts_resp.headers.get('Content-Length', '0')) > 0:
        file_name = uuid + '.zip'
        file_entry = fileResult(filename=file_name, data=artifacts_resp.content)
        return file_entry
    else:
        return MESSAGES['NO_RECORDS_FOUND'].format('artifacts data')


@logger
def get_reports_command(client: Client, args: Dict[str, Any]) -> Union[str, Dict[str, Any]]:
    """
    Returns reports on selected alerts by specifying a time_frame value or a start_time and end_time
    of the search range.
    Will raise ValueError if inappropriate input given.

    :param client: client object which is used to get response from api
    :param args:The command arguments
    :return: Dictionary of file info or empty result message
    """
    # Validate arguments
    params = get_reports_params(args)

    # Preparing header
    headers = {
        'X-FeApi-Token': client.get_api_token(),
        'Accept': CONTENT_TYPE_JSON
    }

    # API call
    resp: Response = client.http_request(method='GET', url_suffix=URL_SUFFIX['GET_REPORTS'], params=params,
                                         headers=headers)

    # Create file from Content
    if int(resp.headers.get('Content-Length', '')) > 0:
        file_entry = fileResult(filename=generate_report_file_name(args), data=resp.content,
                                file_type=EntryType.ENTRY_INFO_FILE)
        return file_entry
    else:
        return MESSAGES['NO_RECORDS_FOUND'].format('report contents')


@logger
def get_alerts_command(client: Client, args: Dict[str, Any]) -> Union[str, CommandResults]:
    """
    Retrieve list of alerts based on various argument(s).

    :param client: Client object
    :param args: The command arguments provided by user.
    :return: Standard command result or no records found message
    """
    add_time_suffix_into_arguments(args)

    # Preparing header
    headers = {
        'X-FeApi-Token': client.get_api_token(),
        'Accept': CONTENT_TYPE_JSON
    }

    # http call
    resp = client.http_request(method="GET", url_suffix=URL_SUFFIX['GET_ALERTS'], params=args, headers=headers)

    total_records = resp.get('alertsCount', 0)
    if total_records <= 0:
        return MESSAGES['NO_RECORDS_FOUND'].format('alert(s)')

    # Creating entry context
    alerts_context_list = []
    for alert in resp.get('alert', []):
        alerts_context_list.append(get_alert_context_output(alert))
    custom_ec = remove_empty_entities(alerts_context_list)

    # Creating human-readable
    hr = prepare_hr_for_alert_response(resp)

    return CommandResults(
        outputs_prefix='FireEyeNX.Alert',
        outputs_key_field='uuid',
        outputs=custom_ec,
        readable_output=hr,
        raw_response=resp
    )


@logger
def fetch_incidents(
        client: Client,
        malware_type: str,
        last_run: Dict[str, Any],
        first_fetch: int,
        fetch_limit: int,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    This function retrieves new incidents every interval.

    :param client: Client object
    :param malware_type: type of malware specified in integration configuration
    :param last_run: A dictionary with a key containing the latest incident modified time which we got from last run.
    :param first_fetch: It contains the timestamp in milliseconds on when to start fetching
                        incidents, if last_run is not provided.
    :param fetch_limit: limit for number of fetch incidents per fetch.
    :return: Tuple containing two elements. incidents list and timestamp.
    """
    # Retrieving last run time if not none, otherwise first_fetch will be considered.
    start_time = last_run.get('start_time', None)
    start_time = int(start_time) if start_time else first_fetch

    next_run = {'start_time': datetime.now().replace(tzinfo=timezone.utc).timestamp()}

    incidents: List[Dict[str, Any]] = []

    # Preparing header and parameters
    headers = {
        'X-FeApi-Token': client.get_api_token(),
        'Accept': CONTENT_TYPE_JSON
    }
    params = {
        'start_time': time.strftime('%Y-%m-%dT%H:%M:%S.000-00:00', time.localtime(start_time))
    }
    if malware_type:
        params['malware_type'] = malware_type

    # http call
    resp = client.http_request(method="GET", url_suffix=URL_SUFFIX['GET_ALERTS'], params=params, headers=headers)

    total_records = resp.get('alertsCount', 0)
    if total_records > 0:
        count = 0
        for alert in resp.get('alert', []):
            # set incident
            context_alert = remove_empty_entities(get_alert_context_output(alert))
            if count >= fetch_limit:
                break

            incident = {
                'name': context_alert.get('name', ''),
                'rawJSON': json.dumps(context_alert),
                'details': json.dumps(context_alert)
            }
            remove_nulls_from_dictionary(incident)
            incidents.append(incident)
            count += 1

    return next_run, incidents


@logger
def get_events_command(client: Client, args: Dict[str, Any]) -> Union[str, CommandResults]:
    """
    Retrieve list of events based on various argument(s).
    Will raise an exception if validation fails.

    :param client: Client object
    :param args: The command arguments provided by user.
    :return: Standard command result or no records found message
    """

    # Validate arguments
    params = get_events_params(args)

    # Preparing header
    headers = {
        'X-FeApi-Token': client.get_api_token(),
        'Accept': CONTENT_TYPE_JSON
    }

    # http call
    resp = client.http_request(method="GET", url_suffix=URL_SUFFIX['GET_EVENTS'], params=params, headers=headers)

    total_records = resp.get('events', [])
    if not total_records:
        return MESSAGES['NO_RECORDS_FOUND'].format('event(s)')

    # Creating entry context
    custom_ec = createContext(total_records, removeNull=True)

    # Creating human-readable
    hr = prepare_hr_for_events(total_records)

    return CommandResults(
        outputs_prefix='FireEyeNX.Event',
        outputs_key_field='eventId',
        outputs=custom_ec,
        readable_output=hr,
        raw_response=resp
    )


def main() -> None:
    """
         PARSE AND VALIDATE INTEGRATION PARAMS
    """
    # Commands dict
    commands = {
        'fireeye-nx-get-artifacts-metadata-by-alert': get_artifacts_metadata_by_alert_command,
        'fireeye-nx-get-reports': get_reports_command,
        'fireeye-nx-get-alerts': get_alerts_command,
        'fireeye-nx-get-artifacts-by-alert': get_artifacts_by_alert_command,
        'fireeye-nx-get-events': get_events_command
    }

    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:
        url = demisto.params().get('url')
        username = demisto.params().get('username')
        password = demisto.params().get('password')
        verify_certificate = not demisto.params().get('insecure', False)
        proxy = demisto.params().get('proxy', False)
        fetch_limit = get_fetch_limit()
        demisto.debug(f"Fetch Limit {fetch_limit}")
        request_timeout = get_request_timeout()
        malware_type = demisto.params().get('malware_type', '')

        base_url = f"{url}/wsapis/{API_VERSION}"

        # Get first fetch time from integration params.
        first_fetch_time = demisto.params().get('firstFetchTimestamp', '48 hours')

        # getting numeric value from string representation
        start_time, _ = parse_date_range(first_fetch_time, date_format=DATE_FORMAT, utc=True)

        # prepare client class object
        client = Client(base_url=base_url, verify=verify_certificate, proxy=proxy, auth=(username, password),
                        request_timeout=request_timeout)

        # Trim the arguments
        args = demisto.args()
        for argument in args:
            if isinstance(args[argument], str):
                args[argument] = args[argument].strip()

        # This is the call made when pressing the integration Test button.
        if demisto.command() == 'test-module':
            result = test_function(client)
            demisto.results(result)

        elif demisto.command() == 'fetch-incidents':
            next_run, incidents = fetch_incidents(
                client=client,
                malware_type=malware_type,
                last_run=demisto.getLastRun(),
                fetch_limit=int(fetch_limit),
                first_fetch=date_to_timestamp(start_time, date_format=DATE_FORMAT) / 1000
            )
            # saves next_run for the time fetch-incidents is invoked.
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

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
