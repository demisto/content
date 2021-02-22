from CommonServerPython import *

''' IMPORTS '''

import dateparser
from requests import Response
from typing import Dict, Any, Union, Tuple, List
from datetime import timezone
from requests.exceptions import MissingSchema, InvalidSchema, InvalidURL, SSLError
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DEFAULT_REQUEST_TIMEOUT = 120
REQUEST_TIMEOUT_MAX_VALUE = 9223372036

API_VERSION = 'v2.0.0'

DEFAULT_SESSION_TIMEOUT = 15 * 60  # In Seconds
DEFAULT_FETCH_LIMIT = '50'
CONTENT_TYPE_JSON = 'application/json'
CONTENT_TYPE_ZIP = 'application/zip'
DATE_FORMAT_OF_YEAR_MONTH_DAY = '%Y-%m-%d'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
DATE_FORMAT_WITH_MICROSECOND = '%Y-%m-%dT%H:%M:%S.%fZ'
API_SUPPORT_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.000-00:00'
ALERT_DETAILS_REPORT = 'Alert Details Report'
VICTIM_IP = 'Victim IP'
TIME_UTC = 'Time (UTC)'
DEFAULT_FIRST_FETCH = '12 hours'
ALERT_INCIDENT_TYPE = 'FireEye NX Alert'
IPS_EVENT_INCIDENT_TYPE = 'FireEye NX IPS Event'

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
    'REQUEST_TIMEOUT': 'Request timed out. Check the configured HTTP(S) Request Timeout (in seconds) value.',
    'FIRST_FETCH_ARG_VALIDATION': 'The First fetch time interval should be up to 48 hour as per API limitation.',
    'INVALID_TIME_VALIDATION': 'The given value for {0} argument is invalid.',
    'INVALID_FETCH_TYPE': 'The given value for Fetch Types is invalid. Expected Alerts or/and IPS Events '
}

URL_SUFFIX: Dict[str, str] = {
    'GET_TOKEN': '/auth/login',
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

PLATFORM_SEVERITY_TO_SEVERITY_MAP = {
    '10': 4,
    '9': 4,
    '8': 3,
    '7': 3,
    '6': 2,
    '5': 2,
    '4': 2,
    '3': 1,
    '2': 1,
    '1': 1,
    '0': 0
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
            resp = super()._http_request(method=method, url_suffix=url_suffix, json_data=json_data, params=params,
                                         headers=headers, resp_type='response',
                                         timeout=self.request_timeout,
                                         ok_codes=(200, 201), error_handler=self.handle_error_response)
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
            raise DemistoException(resp.raise_for_status())

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
        resp = self.http_request(method='POST', url_suffix=URL_SUFFIX['GET_TOKEN'], headers=headers)
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
            integration_context['api_token'] = api_token
            integration_context['valid_until'] = time.time() + DEFAULT_SESSION_TIMEOUT
        else:
            raise ValueError('No api token found. Please try again')
        demisto.setIntegrationContext(integration_context)
        return integration_context


''' HELPER FUNCTION'''


def set_attachment_file(client, incident: dict, uuid: str, headers: dict):
    """
    Set attachment in incident entry.

    :param client: Client object.
    :param incident: Incident entry.
    :param uuid: uuid of alert.
    :param headers: Header of API which will pass to get artifact API.
    """

    # Call get artifacts data api
    headers['Accept'] = CONTENT_TYPE_ZIP
    artifacts_resp = client.http_request('GET', url_suffix=URL_SUFFIX[
        'GET_ARTIFACTS'].format(uuid), headers=headers)

    # Create file from Content
    if int(artifacts_resp.headers.get('Content-Length', '0')) > 0:
        file_name = f'{uuid}.zip'

        attachment_file = fileResult(filename=file_name, data=artifacts_resp.content)

        incident['attachment'] = [{
            'path': attachment_file['FileID'],
            'name': file_name
        }]


def get_incidents_for_alert(**kwargs) -> list:
    """
    Return List of incidents for alert.

    :param kwargs: Contains all required arguments.
    :return: Incident List for alert.
    """
    incidents: List[Dict[str, Any]] = []

    headers = {
        'X-FeApi-Token': kwargs['client'].get_api_token(),
        'Accept': CONTENT_TYPE_JSON
    }

    params = {
        'start_time': time.strftime(API_SUPPORT_DATE_FORMAT, time.localtime(kwargs['start_time'])),
        'duration': '48_hours'
    }

    if kwargs['malware_type']:
        params['malware_type'] = kwargs['malware_type']

    # http call
    resp = kwargs['client'].http_request(method="GET", url_suffix=URL_SUFFIX['GET_ALERTS'], params=params,
                                         headers=headers)

    total_records = resp.get('alertsCount', 0)
    if total_records > 0:

        if kwargs['replace_alert_url']:
            replace_alert_url_key_domain_to_instance_url(resp.get('alert', []), kwargs['instance_url'])

        count = kwargs['fetch_count']
        for alert in resp.get('alert', []):
            # set incident
            context_alert = remove_empty_entities(alert)
            context_alert['incidentType'] = ALERT_INCIDENT_TYPE
            if count >= kwargs['fetch_limit']:
                break

            incident = {
                'name': context_alert.get('name', ''),
                'occurred': dateparser.parse(context_alert.get('occurred', '')).strftime(
                    DATE_FORMAT_WITH_MICROSECOND),
                'rawJSON': json.dumps(context_alert)
            }

            if not kwargs['is_test'] and alert.get('uuid', '') and kwargs['fetch_artifacts']:
                set_attachment_file(client=kwargs['client'], incident=incident, uuid=alert.get('uuid', ''),
                                    headers=headers)

            remove_nulls_from_dictionary(incident)
            incidents.append(incident)
            count += 1
    return incidents


def get_incidents_for_event(client: Client, start_time: int, fetch_limit: int, mvx_correlated: bool):
    """
    Return List of incidents for event.

    :param client: Client object.
    :param start_time: It contains the timestamp in milliseconds on when to start fetching incidents.
    :param fetch_limit: limit for number of fetch incidents per fetch.
    :param mvx_correlated: The boolean flag that tell us to fetch events which only mvx correlated.
    :return: Incident List for event.
    """
    incidents: List[Dict[str, Any]] = []

    # Preparing header and parameters
    headers = {
        'X-FeApi-Token': client.get_api_token(),
        'Accept': CONTENT_TYPE_JSON
    }

    params = {
        'start_time': time.strftime(API_SUPPORT_DATE_FORMAT, time.localtime(start_time)),
        'duration': '48_hours',
        'event_type': 'Ips Event'
    }

    if mvx_correlated:
        params['mvx_correlated_only'] = 'true'

    # http call
    resp = client.http_request(method="GET", url_suffix=URL_SUFFIX['GET_EVENTS'], params=params, headers=headers)

    total_records = len(resp.get('events', []))
    count = 0
    if total_records > 0:
        for event in resp.get('events', []):
            # set incident
            context_event = remove_empty_entities(event)
            context_event['incidentType'] = IPS_EVENT_INCIDENT_TYPE
            if count >= fetch_limit:
                break

            incident = {
                'name': context_event.get('ruleName', ''),
                'occurred': context_event.get('occurred', ''),
                'severity': PLATFORM_SEVERITY_TO_SEVERITY_MAP.get(str(context_event.get('severity', 0)), 0),
                'rawJSON': json.dumps(context_event)
            }
            remove_nulls_from_dictionary(incident)
            incidents.append(incident)
            count += 1
    return incidents, count


def validate_fetch_type(fetch_type):
    """
    Validate fetch type.

    :param fetch_type: A list contain types which user want to fetch.
    :return:
    """
    if type(fetch_type) == list:
        if len(fetch_type) == 0:
            raise ValueError(MESSAGES['INVALID_FETCH_TYPE'])

        if not ('Alerts' in fetch_type) and not ('IPS Events' in fetch_type):
            raise ValueError(MESSAGES['INVALID_FETCH_TYPE'])


def validate_date_range(fetch_time: str):
    """
    Validate date range and it should be up to 2 days as per API limitation.
    Will raise ValueError() if date is not in range.

    :param fetch_time: A time in format of (<number> <unit>). eg. 1 hour.
    """
    two_days_before_time = datetime.utcnow() - timedelta(hours=48)

    start_time, _ = parse_date_range(fetch_time, utc=True)

    if start_time < two_days_before_time:
        raise ValueError(MESSAGES['FIRST_FETCH_ARG_VALIDATION'])


def pascal_case(st) -> str:
    """
    Covert string to pascal case.

    :param st: string
    :return: pascal case string.
    """
    if st.find('-') != -1 or st.find('_') != -1:
        st = ''.join(a.capitalize() for a in re.split('-|_', st))
    return st[:1].upper() + st[1:len(st)]


def remove_dash_and_underscore_from_key(d):  # type: ignore
    """
    Recursively traverse dict and change keys into pascal case.

    :param d: Input dictionary.
    :return: Dictionary with pascal case key.
    """

    if not isinstance(d, (dict, list)):
        return d
    elif isinstance(d, list):
        return [value for value in (remove_dash_and_underscore_from_key(value) for value in d)]
    else:
        return {pascal_case(key): remove_dash_and_underscore_from_key(value) for key, value in d.items()}


def get_request_timeout(request_timeout: str) -> int:
    """
    Validate and return the request timeout parameter.
    The parameter must be a positive integer.
    Default value is set to 60 seconds for API request timeout.
    Will raise ValueError if inappropriate input given.

    :params req_timeout: Request timeout value.
    :return: boolean
    """
    try:
        request_timeout_str = str(DEFAULT_REQUEST_TIMEOUT) if not request_timeout else request_timeout
        request_timeout_int = int(request_timeout_str)
    except ValueError:
        raise ValueError(MESSAGES['REQUEST_TIMEOUT_VALIDATION'])

    if request_timeout_int <= 0:
        raise ValueError(MESSAGES['REQUEST_TIMEOUT_VALIDATION'])
    elif request_timeout_int > REQUEST_TIMEOUT_MAX_VALUE:
        raise ValueError(MESSAGES['REQUEST_TIMEOUT_EXCEED_ERROR'])

    return request_timeout_int


def get_fetch_limit(fetch_limit):
    """
    Retrieve fetch limit from demisto arguments and validate it.
    Will raise ValueError if inappropriate input given.

    :param fetch_limit: The maximum number of incident want to fetch.
    :return: fetch limit
    """
    fetch_limit = DEFAULT_FETCH_LIMIT if not fetch_limit else fetch_limit
    try:
        fetch_limit_int = int(fetch_limit)
        if not 1 <= fetch_limit_int <= 200:
            raise ValueError
    except ValueError:
        raise ValueError(MESSAGES['FETCH_LIMIT_VALIDATION'])

    return fetch_limit_int


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
        date_time = dateparser.parse(start_time)
        if date_time:
            params['start_time'] = str(date_time.strftime(API_SUPPORT_DATE_FORMAT))
        else:
            params['start_time'] = start_time

    if 'end_time' in arg_keys:
        end_time = args.get('end_time', '')
        date_time = dateparser.parse(end_time)
        if date_time:
            params['end_time'] = str(date_time.strftime(API_SUPPORT_DATE_FORMAT))
        else:
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


def add_time_suffix_into_arguments(args: Dict[str, Any]):
    """
    Add time suffix into arguments.

    :param args: arguments of alerts.
    :return: Add suffix to date format if full format is not given.
    """
    arg_keys = args.keys()
    if 'start_time' in arg_keys:
        start_time = args.get('start_time', '')
        date_time = dateparser.parse(start_time)
        if date_time:
            args['start_time'] = str(date_time.strftime(API_SUPPORT_DATE_FORMAT))
        else:
            raise ValueError(MESSAGES['INVALID_TIME_VALIDATION'].format('start_time'))

    if 'end_time' in arg_keys:
        end_time = args.get('end_time', '')
        date_time = dateparser.parse(end_time)
        if date_time:
            args['end_time'] = str(date_time.strftime(API_SUPPORT_DATE_FORMAT))
        else:
            raise ValueError(MESSAGES['INVALID_TIME_VALIDATION'].format('end_time'))


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

    if 'start_time' in arg_keys:
        start_time = args.get('start_time', '')
        date_time = dateparser.parse(start_time)
        if date_time:
            params['start_time'] = str(date_time.strftime(API_SUPPORT_DATE_FORMAT))
        else:
            raise ValueError(MESSAGES['INVALID_TIME_VALIDATION'].format('start_time'))

    if 'end_time' in arg_keys:
        end_time = args.get('end_time', '')
        date_time = dateparser.parse(end_time)
        if date_time:
            params['end_time'] = str(date_time.strftime(API_SUPPORT_DATE_FORMAT))
        else:
            raise ValueError(MESSAGES['INVALID_TIME_VALIDATION'].format('end_time'))

    if 'mvx_correlated_only' in arg_keys:
        mvx_correlated_only = args.get('mvx_correlated_only', '').lower()
        try:
            mvx_correlated_only = argToBoolean(mvx_correlated_only)
            params['mvx_correlated_only'] = mvx_correlated_only
        except ValueError:
            raise ValueError(MESSAGES['INVALID_BOOLEAN_VALUE_ERROR'].format('mvx_correlated_only'))

    return params


def prepare_hr_for_artifact_metadata(artifacts_info: List[Dict[str, Any]]) -> str:
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


def remove_empty_entities(d):
    """
    Recursively remove empty lists, empty dicts, or None elements from a dictionary.
    Note. This is extended feature of CommonServerPython.py remove_empty_elements() method as it was not removing
    empty character x == ''.

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


def replace_alert_url_key_domain_to_instance_url(alerts_resp: list, instance_url: str):
    """
    Change domain of 'alertUrl' to the instance URL.

    :param alerts_resp: List contain dictionary of alerts.
    :param instance_url: URL to connect to the FireEye NX.
    """

    def replace_url(alert_url: str, prefix_url: str) -> str:
        """
        Replace alert url domain to prefix url.

        :param alert_url: Actual url that getting from response.
        :param prefix_url: URL to connect to the FireEye NX.
        :return:
        """
        if alert_url.startswith('http://'):  # NOSONAR
            alert_url = alert_url.replace('http://', '')  # NOSONAR

        elif alert_url.startswith('https://'):
            alert_url = alert_url.replace('https://', '')

        if alert_url.startswith('www.'):
            alert_url = alert_url.replace('www.', '')

        elif alert_url.startswith('WWW.'):
            alert_url = alert_url.replace('WWW.', '')

        if not prefix_url.endswith('/'):
            prefix_url = f"{prefix_url + '/'}"

        alert_url_split = alert_url.split('/', 1)

        suffix_url = ''.join(alert_url_split[count] for count in range(len(alert_url_split)) if count != 0)

        return f"{prefix_url + suffix_url}"

    for alert_index in range(len(alerts_resp)):
        if alerts_resp[alert_index].get('alertUrl'):
            alerts_resp[alert_index]['alertUrl'] = replace_url(alerts_resp[alert_index]['alertUrl'], instance_url)


''' REQUESTS FUNCTIONS '''


def test_function(**kwargs) -> str:
    """
    Performs test connectivity by valid http response.

    :param kwargs: Contains all required parameters.
    :return: raise ValueError if any error occurred during connection
    """
    if kwargs['is_fetch']:
        fetch_limit = get_fetch_limit(kwargs['fetch_limit'])

        # getting numeric value from string representation
        start_time, _ = parse_date_range(kwargs['first_fetch_time'], date_format=DATE_FORMAT, utc=True)

        # validate start_time should be less then 48 hour as per API limitation
        validate_date_range(kwargs['first_fetch_time'])
        validate_fetch_type(kwargs['fetch_type'])

        first_fetch = date_to_timestamp(start_time, date_format=DATE_FORMAT) / 1000
        fetch_incidents(client=kwargs['client'], last_run=demisto.getLastRun(), first_fetch=first_fetch,
                        fetch_limit=fetch_limit, malware_type=kwargs['malware_type'],
                        is_test=True, fetch_type=kwargs['fetch_type'], mvx_correlated=kwargs['mvx_correlated'],
                        replace_alert_url=kwargs['replace_alert_url'], instance_url=kwargs['instance_url'],
                        fetch_artifacts=kwargs['fetch_artifacts'])
    else:
        headers = {
            'Accept': CONTENT_TYPE_JSON
        }
        kwargs['client'].http_request(method='POST', url_suffix=URL_SUFFIX['GET_TOKEN'], headers=headers)

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

    custom_ec_for_artifact_metadata = {
        'ArtifactsMetadata': artifacts_metadata_custom_ec,
        'Uuid': uuid
    }

    # Remove dash, underscore from key and make it pascal case.
    custom_ec = remove_dash_and_underscore_from_key(custom_ec_for_artifact_metadata)

    return CommandResults(
        outputs_prefix='FireEyeNX.Alert',
        outputs_key_field='Uuid',
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
        file_name = f'{uuid}.zip'
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
def get_alerts_command(client: Client, args: Dict[str, Any], replace_alert_url: bool, instance_url: str) -> \
        Union[str, CommandResults]:
    """
    Retrieve list of alerts based on various argument(s).

    :param client: Client object
    :param args: The command arguments provided by user.
    :param replace_alert_url: Replace the domain of the alert URL key to the Instance URL.
    :param instance_url: URL to connect to the FireEye NX.
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

    alerts_resp = resp.get('alert', [])

    # Replace the domain of the alertUrl key to Instance URL if it is true.
    if replace_alert_url:
        replace_alert_url_key_domain_to_instance_url(alerts_resp, instance_url)

    # Creating human-readable
    hr = prepare_hr_for_alert_response(resp)

    # Creating entry context
    custom_ec_for_alerts = remove_empty_entities(alerts_resp)

    # Remove dash, underscore from key and make it pascal case.
    custom_ec = remove_dash_and_underscore_from_key(custom_ec_for_alerts)

    return CommandResults(
        outputs_prefix='FireEyeNX.Alert',
        outputs_key_field='Uuid',
        outputs=custom_ec,
        readable_output=hr,
        raw_response=resp
    )


@logger
def fetch_incidents(
        **kwargs
) -> Tuple[Union[Dict[str, Any], None], Union[List[Dict[str, Any]], None]]:
    """
    This function retrieves new incidents every interval.

    :param kwargs : Dictionary contain all required arguments.
    :return: Tuple containing two elements. incidents list and timestamp.
    """
    # Retrieving last run time if not none, otherwise first_fetch will be considered.
    start_time = kwargs['last_run'].get('start_time')
    start_time = int(start_time) if start_time else kwargs['first_fetch']

    next_run = {'start_time': datetime.now(timezone.utc).timestamp()}

    incidents = []
    fetch_count = 0
    if 'IPS Events' in kwargs['fetch_type']:
        incidents, fetch_count = get_incidents_for_event(kwargs['client'], start_time,
                                                         kwargs['fetch_limit'], kwargs['mvx_correlated'])

    if 'Alerts' in kwargs['fetch_type'] and (fetch_count < kwargs['fetch_limit']):
        incidents.extend(
            get_incidents_for_alert(client=kwargs['client'], malware_type=kwargs['malware_type'],
                                    start_time=start_time, fetch_limit=kwargs['fetch_limit'],
                                    replace_alert_url=kwargs['replace_alert_url'],
                                    instance_url=kwargs['instance_url'], is_test=kwargs['is_test'],
                                    fetch_artifacts=kwargs['fetch_artifacts'], fetch_count=fetch_count)
        )

    if kwargs['is_test']:
        return None, None
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
    custom_ec_for_event = createContext(total_records, removeNull=True)
    custom_ec = remove_dash_and_underscore_from_key(custom_ec_for_event)

    # Creating human-readable
    hr = prepare_hr_for_events(total_records)

    return CommandResults(
        outputs_prefix='FireEyeNX.Event',
        outputs_key_field='EventId',
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
        'fireeye-nx-get-artifacts-by-alert': get_artifacts_by_alert_command,
        'fireeye-nx-get-events': get_events_command
    }
    commands_with_params = {
        'fireeye-nx-get-alerts': get_alerts_command
    }

    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:
        url = demisto.params().get('url')
        username = demisto.params().get('credentials', {}).get('identifier')
        password = demisto.params().get('credentials', {}).get('password')
        if password:
            password = password.encode('utf-8')

        verify_certificate = not demisto.params().get('insecure', False)
        proxy = demisto.params().get('proxy', False)
        request_timeout = demisto.params().get('request_timeout')
        request_timeout = get_request_timeout(request_timeout)

        base_url = f"{url}/wsapis/{API_VERSION}"

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
            is_fetch = demisto.params().get('isFetch')
            first_fetch_time = demisto.params().get('first_fetch')

            # Set first fetch time as default if user leave empty
            first_fetch_time = DEFAULT_FIRST_FETCH if not first_fetch_time else first_fetch_time

            malware_type = demisto.params().get('malware_type')

            fetch_limit = demisto.params().get('max_fetch')

            fetch_type = demisto.params().get('fetch_type')

            mvx_correlated = demisto.params().get('fetch_mvx_correlated_events', False)

            replace_alert_url = demisto.params().get('replace_alert_url', False)

            fetch_artifacts = demisto.params().get('fetch_artifacts', False)

            result = test_function(client=client, first_fetch_time=first_fetch_time, fetch_limit=fetch_limit,
                                   malware_type=malware_type, is_fetch=is_fetch, fetch_type=fetch_type,
                                   mvx_correlated=mvx_correlated, replace_alert_url=replace_alert_url, instance_url=url,
                                   fetch_artifacts=fetch_artifacts)
            demisto.results(result)

        elif demisto.command() == 'fetch-incidents':
            malware_type = demisto.params().get('malware_type', '')

            first_fetch_time = demisto.params().get('first_fetch')

            # Set first fetch time as default if user leave empty
            first_fetch_time = DEFAULT_FIRST_FETCH if not first_fetch_time else first_fetch_time

            fetch_limit = demisto.params().get('max_fetch')

            fetch_limit = get_fetch_limit(fetch_limit)
            demisto.debug(f"Fetch Limit {fetch_limit}")

            fetch_type = demisto.params().get('fetch_type')

            mvx_correlated = demisto.params().get('fetch_mvx_correlated_events', False)

            # Getting numeric value from string representation
            start_time, _ = parse_date_range(first_fetch_time, date_format=DATE_FORMAT, utc=True)

            # Validate start_time should be less then 48 hour as per API limitation
            validate_date_range(first_fetch_time)

            validate_fetch_type(fetch_type)
            # Flag indicate to replace the 'alertUrl' domain to Integration URL or not.
            replace_alert_url = demisto.params().get('replace_alert_url', False)

            fetch_artifacts = demisto.params().get('fetch_artifacts', False)

            next_run, incidents = fetch_incidents(
                client=client,
                malware_type=malware_type,
                last_run=demisto.getLastRun(),
                fetch_limit=fetch_limit,
                first_fetch=date_to_timestamp(start_time, date_format=DATE_FORMAT) / 1000,
                fetch_type=fetch_type,
                mvx_correlated=mvx_correlated,
                replace_alert_url=replace_alert_url,
                instance_url=url,
                fetch_artifacts=fetch_artifacts,
                is_test=False
            )
            # saves next_run for the time fetch-incidents is invoked.
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command in commands:
            return_results(commands[command](client, args))

        elif command in commands_with_params:
            # Flag indicate to replace alertUrl domain to Integration URL or not.
            replace_alert_url = demisto.params().get('replace_alert_url', False)

            return_results(commands_with_params[command](client, args, replace_alert_url, url))

    # Log exceptions
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
