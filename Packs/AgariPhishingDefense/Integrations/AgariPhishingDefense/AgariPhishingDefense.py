import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import dateparser
import requests
from requests import Response
from typing import Dict, Any, Union, Tuple
from requests.exceptions import MissingSchema, InvalidSchema, InvalidURL, SSLError
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''

MAX_LIMIT_FOR_EVENT = 200
MAX_LIMIT_FOR_MESSAGE = 1000
DEFAULT_FETCH_LIMIT = '50'
DEFAULT_FIRST_FETCH = '12 hours'
DEFAULT_SESSION_TIMEOUT = 30
TOKEN_EXPIRY_TIMEOUT = 60 * 60 * 4
CONTENT_TYPE_JSON = 'application/json'
DATE_FORMAT_OF_YEAR_MONTH_DAY = '%Y-%m-%d'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
DATE_FORMAT_WITH_MICROSECOND = '%Y-%m-%dT%H:%M:%S.%fZ'
API_SUPPORT_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.000-00:00'
API_VERSION = 'v1'
MAX_WORKERS = 5
TOKEN_TIME_DIFF = 60


URL_SUFFIX: Dict[str, str] = {
    'GET_TOKEN': '/token',
    'GET_EVENTS': '/policy_events',
    'REMEDIATE_MSG': '/messages/{}/remediate',
    'GET_MESSAGES': '/messages'
}

MESSAGES: Dict[str, str] = {
    'BAD_REQUEST_ERROR': 'An error occurred while fetching the data.',
    'AUTHENTICATION_ERROR': 'Unauthenticated. Check the configured API Key and Secret Key.',
    'PROXY_ERROR': 'Proxy Error - cannot connect to proxy. Either try clearing the \'Use system proxy\' check-box or '
                   'check the host, authentication details and connection details for the proxy.',
    'SSL_CERT_ERROR': 'SSL Certificate Verification Failed - try selecting \'Trust any certificate\' checkbox in the '
                      'integration configuration.',
    'INTERNAL_SERVER_ERROR': 'The server encountered an internal error for Agari and was unable to complete '
                             'your request.',
    'MISSING_SCHEMA_ERROR': 'Invalid API URL. No schema supplied: http(s).',
    'INVALID_SCHEMA_ERROR': 'Invalid API URL. Supplied schema is invalid, supports http(s).',
    'INVALID_API_URL': 'Invalid API URL.',
    'CONNECTION_ERROR': 'Connectivity failed. Check your internet connection or the API URL.',
    'NO_RECORDS_FOUND': 'No {} were found for the given argument(s).',
    'FETCH_LIMIT_VALIDATION': 'Value of Fetch Limit must be a positive integer between 1 to 200.',
    'REQUEST_TIMEOUT': 'Request timed out. Check the configured HTTP(S) Request Timeout (in seconds) value.',
    'INVALID_TIME_VALIDATION': 'The given value for {0} argument is invalid.',
    'INVALID_POLICY_ACTION_TYPE': 'The given value for Policy Actions is invalid. Expected "deliver", "mark-spam", '
                                  '"move", "inbox", "delete" or "none". ',
    'INVALID_LIMIT': 'Argument limit must be a positive integer between 1 to {}.',
    'INVALID_PAGE_ID': 'Argument page_id must be a positive integer.',
    'INVALID_REM_FIELDS': 'Cannot pass "id" in rem_fields argument.',
    'MISSING_REMEDIATE_ARGS': 'Invalid argument value. Requires both "id" and "operation" argument.',
    'INVALID_EXCLUDE_ALERT_TYPE': 'The given value for Exclude Alerts is invalid. Expected "System Alert" or '
                                  '"Message Alert". '
}

HR_MESSAGES: Dict[str, str] = {
    'REMEDIATE_MSG_SUCCESS': "Message ID - {} remediated successfully with operation '{}'."
}

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, base_url: str, verify: bool, proxy: bool, request_timeout: int, payload):
        """
        Initialization of HTTP request timeout, payload(i.e client id and client secret)
        Initialization of lock object and create a token for the first time if not available in context

        :param base_url: Base url of Endpoint
        :param verify: Whether the request should verify the SSL certificate.
        :param proxy: Whether to run the integration using the system proxy.
        :param request_timeout: Time of Request Timeout
        :param payload: Payload data (i.e client id and client secret)
        """
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.request_timeout = request_timeout
        self.payload = payload
        self.lock = threading.Lock()
        self.api_token, self.api_token_valid_until = self.get_api_token()

    def http_request(self, method: str, url_suffix: str, json_data=None, params=None,
                     headers=None, data=None):
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
            if url_suffix != URL_SUFFIX['GET_TOKEN']:
                with self.lock:
                    if int(time.time() + TOKEN_TIME_DIFF) >= self.api_token_valid_until:
                        self.api_token, self.api_token_valid_until = self.get_api_token()
            resp = super()._http_request(method=method, url_suffix=url_suffix, json_data=json_data, params=params,
                                         headers=headers, resp_type='response',
                                         timeout=self.request_timeout,
                                         ok_codes=(200, 201), error_handler=self.handle_error_response, data=data)
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
            if content_type.__contains__(CONTENT_TYPE_JSON):
                # Handle empty response
                if resp.text == '':
                    return resp
                else:
                    return resp.json()
            else:
                return resp

    @staticmethod
    def handle_demisto_exception(e) -> None:
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
    def handle_error_response(resp) -> None:
        """
        Handle error response and display user specific error message based on status code.

        :param resp: response from API.
        :return: raise DemistoException based on status code.
        """

        error_message = ''
        error_message_with_reason = ''
        try:
            json_resp = resp.json()
            error_message = json_resp['error']
            error_message_with_reason = json_resp['error_description']
        except Exception:  # ignoring json parsing errors
            pass

        status_code_messages = {
            400: f"{MESSAGES['BAD_REQUEST_ERROR']} {error_message_with_reason}",
            401: MESSAGES['AUTHENTICATION_ERROR'],
            403: error_message,
            404: f"{MESSAGES['BAD_REQUEST_ERROR']} {error_message_with_reason}",
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

    @staticmethod
    def set_integration_context(resp) -> dict:
        """
        set api token and expiry time in integration configuration context.
        Will raise value error if api-token is not found.

        :param resp: resp from API.
        :return: integration context
        """

        integration_context = demisto.getIntegrationContext()
        api_token = resp['access_token']
        if api_token:
            integration_context['api_token'] = "Bearer " + api_token
            integration_context['valid_until'] = int(time.time() + TOKEN_EXPIRY_TIMEOUT)
        else:
            raise ValueError('No api token found. Please try again')
        demisto.setIntegrationContext(integration_context)
        return integration_context

    def get_api_token(self):
        """
        Retrieve new api token and set it to integration context.
        if api token is not not found or expired, making api call to retrieve api token and set it to integration
        context.

        :return: api-token, validity of token
        """
        integration_context = demisto.getIntegrationContext()
        api_token = integration_context.get('api_token')
        valid_until = integration_context.get('valid_until')

        # Return api token from integration context, if found and not expired
        if api_token and valid_until and time.time() + TOKEN_TIME_DIFF < valid_until:
            demisto.debug('Retrieved api-token from integration cache.')
            return api_token, valid_until

        headers = {
            "Accept": CONTENT_TYPE_JSON,
            "Content-Type": "application/x-www-form-urlencoded"
        }

        demisto.debug('Calling authentication API for retrieve api-token')
        resp = self.http_request(method='POST', url_suffix=URL_SUFFIX['GET_TOKEN'], headers=headers, data=self.payload)

        integration_context = self.set_integration_context(resp)

        return integration_context.get('api_token'), int(integration_context.get('valid_until', 0))


def get_fetch_limit(fetch_limit) -> int:
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


def validate_fetch_policy_action(fetch_policy_action) -> bool:
    """
    Validate fetch policy action.

    :param fetch_policy_action: A list contain policy actions which user want to fetch.
    :return: True if it is valid
    """
    policy_actions = ["deliver", "mark-spam", "move", "inbox", "delete", "none"]
    if fetch_policy_action == "" or fetch_policy_action is None:
        return True

    if not (fetch_policy_action in policy_actions):
        raise ValueError(MESSAGES['INVALID_POLICY_ACTION_TYPE'])
    return False


def validate_exclude_alert_type(exclude_alert_type) -> bool:
    """
    Validate exclude alert type.

    :param exclude_alert_type: A list contain exclude alert types which user want to exclude.
    :return: True if it is valid
    """

    exclude_alert_types = ["System Alert", "Message Alert"]
    if exclude_alert_type == "" or exclude_alert_type is None:
        return True

    if not (exclude_alert_type in exclude_alert_types):
        raise ValueError(MESSAGES['INVALID_EXCLUDE_ALERT_TYPE'])
    return False


def prepare_hr_for_events(events_info) -> str:
    """
    Prepare the Human readable info for events command.

    :param events_info: The events data.
    :return: Human readable.
    """
    hr_list = []
    for record in events_info:
        hr_record = {
            'Event ID': record.get('id', None),
            'Alert Definition Name': record.get('alert_definition_name', ''),
            'Created': record.get('created_at', ''),
            'Updated': record.get('updated_at', ''),
            'Policy Action': record.get('policy_action', ''),
            'Notified Original Recipients': record.get('notified_original_recipients', ''),
            'Admin Recipients': record.get('admin_recipients', '')
        }
        hr_list.append(hr_record)

    return tableToMarkdown('Policy Events', hr_list,
                           ['Event ID', 'Alert Definition Name', 'Policy Action',
                            'Notified Original Recipients', 'Admin Recipients', 'Created', 'Updated'],
                           removeNull=True)


def prepare_hr_for_messages(messages_info) -> str:
    """
    Prepare the Human readable info for messages data command.

    :param messages_info: The messages data.
    :return: Human readable.
    """
    hr_list = []
    for record in messages_info:
        hr_record = {
            'ID': record.get('id', ''),
            'From': record.get('from', ''),
            'To': record.get('to', ''),
            'Subject': record.get('subject', ''),
            'Message Trust Score': record.get('message_trust_score', ''),
            'Domain Reputation': record.get('domain_reputation', ''),
            'IP': record.get('ip', ''),
            'Authenticity': record.get('authenticity', ''),
            'Attachment Filenames': record.get('attachment_filenames', ''),
            'Attachment sha256': record.get('attachment_sha256', ''),
            'Attack Types': record.get('attack_types', ''),
            'Date': record.get('date', '')
        }
        hr_list.append(hr_record)

    return tableToMarkdown('Messages', hr_list,
                           ['ID', 'From', 'To', 'Subject', 'Message Trust Score',
                            'Domain Reputation', 'IP', 'Authenticity', 'Attachment Filenames', 'Attachment sha256',
                            'Attack Types', 'Date'],
                           removeNull=True)


def test_function(**kwargs) -> str:
    """
    Performs test connectivity by valid http response.

    :param kwargs: Contains all required parameters.
    :return: raise ValueError if any error occurred during connection
    """
    headers = {
        "Accept": CONTENT_TYPE_JSON,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    client = kwargs['client']
    res = client.http_request(method='POST', url_suffix=URL_SUFFIX['GET_TOKEN'], headers=headers, data=client.payload)
    if not res['access_token']:
        return 'Invalid API Key, Secret Key or URL'

    if kwargs['is_fetch']:
        get_fetch_limit(kwargs['fetch_limit'])

        # getting numeric value from string representation
        start_time, _ = parse_date_range(kwargs['first_fetch_time'], date_format=DATE_FORMAT, utc=True)

        # validate policy actions

        validate_fetch_policy_action(kwargs['fetch_policy_actions'])

        # validate exclude alerts

        validate_exclude_alert_type(kwargs['exclude_alert_type'])
        kwargs['exclude_alert_type'] = kwargs['exclude_alert_type'].replace(" ", "")
        fetch_incidents(client, {}, {}, True)

    return "ok"


def get_events_params(args: Dict[str, Any], max_record=MAX_LIMIT_FOR_EVENT) -> Dict[str, Any]:
    """
        Validates the input arguments of command and returns parameter dictionary
        or raises ValueError in case of validation failed.

        :param args: Input arguments of command
        :param max_record: Maximum fetch limit
        :return: Params dict or error message
        """

    arg_keys = args.keys()

    if 'rem_fields' in arg_keys:
        values = args.get('rem_fields', '').split(',')
        if 'id' in values:
            raise ValueError(MESSAGES['INVALID_REM_FIELDS'])

    if 'start_date' in arg_keys:
        start_date = args.get('start_date', '')
        if start_date.isdigit():
            raise ValueError(MESSAGES['INVALID_TIME_VALIDATION'].format('start_date'))
        date_time = dateparser.parse(start_date, settings={'STRICT_PARSING': True})
        if date_time:
            args['start_date'] = str(date_time.strftime(API_SUPPORT_DATE_FORMAT))
        else:
            raise ValueError(MESSAGES['INVALID_TIME_VALIDATION'].format('start_date'))

    if 'end_date' in arg_keys:
        end_date = args.get('end_date', '')
        if end_date.isdigit():
            raise ValueError(MESSAGES['INVALID_TIME_VALIDATION'].format('end_date'))
        date_time = dateparser.parse(end_date, settings={'STRICT_PARSING': True})
        if date_time:
            args['end_date'] = str(date_time.strftime(API_SUPPORT_DATE_FORMAT))
        else:
            raise ValueError(MESSAGES['INVALID_TIME_VALIDATION'].format('end_date'))

    limit = 25
    if 'limit' in arg_keys:
        try:
            limit = int(args.get('limit', 25))
            if not (1 <= limit <= max_record):
                raise ValueError(MESSAGES['INVALID_LIMIT'].format(max_record))
        except ValueError:
            raise ValueError(MESSAGES['INVALID_LIMIT'].format(max_record))

    if 'page_id' in arg_keys:
        try:
            page_id = int(args.get('page_id', 1))
            page_id -= 1
            if page_id < 0:
                raise ValueError(MESSAGES['INVALID_PAGE_ID'])
        except ValueError:
            raise ValueError(MESSAGES['INVALID_PAGE_ID'])

        offset = page_id * limit
        args['offset'] = offset
        args.__delitem__('page_id')

    return args


def list_policy_events_command(client: Client, args: Dict[str, Any]) -> Union[str, CommandResults]:
    """
        Retrieve list of events based on various argument(s).
        Will raise an exception if validation fails.

        :param client: Client object
        :param args: The command arguments provided by user.
        :return: Standard command result or no records found message
    """

    # Validate arguments
    params = get_events_params(args, MAX_LIMIT_FOR_EVENT)

    resp = get_list_policies_api_endpoint(client, params)

    total_records = resp['alert_events']
    if not total_records:
        return MESSAGES['NO_RECORDS_FOUND'].format('event(s)')

    # Creating entry context
    custom_ec_for_event = remove_empty_elements(total_records)

    # Creating human-readable
    hr = prepare_hr_for_events(total_records)

    return CommandResults(
        outputs_prefix='AgariPhishingDefense.Alert',
        outputs_key_field='id',
        outputs=custom_ec_for_event,
        readable_output=hr,
        raw_response=resp
    )


def list_message_data_command(client: Client, args: Dict[str, Any]) -> Union[str, CommandResults]:
    """
        Retrieve list of messages based on various argument(s).
        Will raise an exception if validation fails.

        :param client: Client object
        :param args: The command arguments provided by user.
        :return: Standard command result or no records found message
    """

    # Validate arguments
    params = get_events_params(args, MAX_LIMIT_FOR_MESSAGE)

    # Preparing header

    headers = {
        'Authorization': client.api_token,
        'Accept': CONTENT_TYPE_JSON
    }

    # http call
    resp = client.http_request(method='GET', url_suffix=URL_SUFFIX['GET_MESSAGES'], params=params, headers=headers)

    total_records = resp['messages']
    if not total_records:
        return MESSAGES['NO_RECORDS_FOUND'].format('event(s)')

    # Creating entry context
    custom_ec_for_message = remove_empty_elements(total_records)

    # Creating human-readable
    hr = prepare_hr_for_messages(total_records)

    return CommandResults(
        outputs_prefix='AgariPhishingDefense.Message',
        outputs_key_field='id',
        outputs=custom_ec_for_message,
        readable_output=hr,
        raw_response=resp
    )


def remediate_message_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
        Remediate a message by applying a remediation operation 'move' or 'delete'.

        :param client: Client object
        :param args: The command arguments provided by user.
        :return: Standard command result or raise Exception
    """
    # Validate arguments
    message_id, action = args.get('id', '').strip(), args.get('operation', '').strip()

    if not message_id or not action:
        raise ValueError(MESSAGES['MISSING_REMEDIATE_ARGS'])

    body = {
        "operation": action.lower()
    }

    headers = {
        'Authorization': client.api_token,
        'Accept': CONTENT_TYPE_JSON
    }

    # http call
    client.http_request(method='POST', url_suffix=URL_SUFFIX['REMEDIATE_MSG'].format(message_id), json_data=body,
                        headers=headers)

    return CommandResults(readable_output=HR_MESSAGES['REMEDIATE_MSG_SUCCESS'].format(message_id, action))


def get_list_policies_api_endpoint(client: Client, params: Dict[str, Any]) -> Any:
    """
        This function gets list of policies

        :param client: Client object
        :param params: Parameters to be passed in API call

        :return response: Response of API call of list all policies
    """
    # Preparing header
    headers = {
        'Authorization': client.api_token,
        'Accept': CONTENT_TYPE_JSON
    }

    # http call
    return client.http_request(method='GET', url_suffix=URL_SUFFIX['GET_EVENTS'], params=params, headers=headers)


def fetch_incidents_params(**kwargs) -> Dict[str, Any]:
    """
        Validates the input arguments of integration for fetching incidents and returns parameter dictionary
        or raises ValueError in case of validation failed.

        :param kwargs: Input arguments of integration to fetch incidents
        :return: params dict or error message
    """
    params = {'start_date': kwargs['start_date'], "sort": "created_at ASC,id ASC"}

    if kwargs['id'] is not None and kwargs['id'] != '':
        params['filter'] = 'id.gt(+' + str(kwargs['id']) + ')'
        if kwargs['policy_filter'] is not None and kwargs['policy_filter'] != '':
            params['filter'] = kwargs['policy_filter'] + ' and ' + params['filter']
    elif kwargs['policy_filter'] is not None and kwargs['policy_filter'] != '':
        params['filter'] = kwargs['policy_filter']

    if kwargs['fetch_limit'] is not None and kwargs['fetch_limit'] != '':
        params['limit'] = get_fetch_limit(kwargs['fetch_limit'])

    if kwargs['fetch_policy_actions'] is not None and kwargs['fetch_policy_actions'] != '':
        params['policy_action'] = kwargs['fetch_policy_actions']
    if kwargs['exclude_alert_type'] is not None and kwargs['exclude_alert_type'] != '':
        params['exclude_alert_types'] = kwargs['exclude_alert_type'].replace(" ", "")
    return params


def get_message(client: Client, policy_id: str) -> Any:
    """
        This function is called for getting message for each policy_id
        :param client: Client object
        :param policy_id: Policy id of policy

        :return message_response: Response of message of given policy_id
    """

    headers = {
        'Authorization': client.api_token,
        'Accept': CONTENT_TYPE_JSON
    }

    try:
        policy_response = client.http_request(method='GET', url_suffix=URL_SUFFIX['GET_EVENTS'] + f'/{policy_id}',
                                              headers=headers)
        url = policy_response['alert_event']['collector_message_id']
        message_response = client.http_request(method='GET', url_suffix=URL_SUFFIX['GET_MESSAGES'] + f'/{url}', headers=headers)
        # attack_class_types Key is added to separate out the attack_class' keys in Dashboard
        message_response['message']['attack_class_types'] = []
        for attack_class in list(message_response['message']['attack_class'].keys()):
            message_response['message']['attack_class_types'].append({"Types": attack_class})
        return message_response['message']
    except Exception as ex:
        demisto.debug(str(ex))


def fetch_incidents(client: Client, last_run: Dict[str, Any], args: Dict[str, Any],
                    call_from_test=False) -> Tuple[dict, list]:
    """
        This function is called for fetching incidents.
        This function gets all policies, then after using ThreadPoolExecutor, for each policy in all policies, get each
        policy and get message from message id obtained from each policy
        This function will execute each interval (default is 1 minute).

        :param client: Client object
        :param last_run: The greatest incident created_time we fetched from last fetch
        :param args: The command arguments provided by user.
        :param call_from_test: Whether calling from test module

        :return next_run: This will be last_run in the next fetch-incidents
        :return incidents: Incidents that will be created in Cortex XSOAR
    """

    # Get the last fetch time and id, if exists
    last_fetch = last_run.get('last_fetch')
    id = last_run.get('id', '')

    first_fetch = args.get('first_fetch')
    # Set first fetch time as default if user leave empty
    first_fetch = DEFAULT_FIRST_FETCH if not first_fetch else first_fetch

    fetch_limit = args.get('max_fetch', DEFAULT_FETCH_LIMIT)

    fetch_policy_actions = args.get('fetch_policy_actions', '')

    exclude_alert_type = args.get('exclude_alert_type', '')

    policy_filter = args.get('policy_filter', '')

    # Handle first time fetch
    if last_fetch is None:
        latest_created_time = dateparser.parse(first_fetch)
    else:
        latest_created_time = dateparser.parse(last_fetch)
    latest_created_time = latest_created_time.strftime(DATE_FORMAT)

    params = fetch_incidents_params(start_date=latest_created_time, fetch_limit=fetch_limit,
                                    fetch_policy_actions=fetch_policy_actions, exclude_alert_type=exclude_alert_type,
                                    policy_filter=policy_filter, id=id)

    resp = get_list_policies_api_endpoint(client, params)

    total_records = resp['alert_events']
    if not total_records:
        return last_run, []

    policy_ids = []
    policy_data = {}
    for alert_event in total_records:
        policy_data[alert_event['id']] = alert_event
        policy_ids.append(alert_event['id'])

    items = []
    incidents = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(get_message, client, policy_id): policy_id for policy_id in policy_ids}
        for future in as_completed(future_to_url):
            try:
                items.append([future.result(), future_to_url[future]])
            except Exception as ex:
                demisto.debug(str(ex))
    for item in items:
        if item[0] is None:
            continue
        result = {'message': item[0], 'policy': policy_data[item[1]]}
        incident = {
            'name': str(item[1]),
            'rawJSON': json.dumps(result)
        }
        incidents.append(incident)

    # Update last run and add incident if the incident is newer than last fetch
    latest_created_time = dateparser.parse(total_records[-1]['created_at'])
    latest_created_time = latest_created_time.strftime(DATE_FORMAT)
    next_run = {'last_fetch': latest_created_time, 'id': total_records[-1]['id']}
    if call_from_test:
        # Returning None
        return {}, []
    return next_run, incidents


''' MAIN FUNCTION '''


def main() -> None:
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """

    command = demisto.command()
    demisto.info(f'[Agari] Command being called is {command}')

    try:
        url = demisto.params().get('url')
        client_id = demisto.params().get('apikey')
        client_secret = demisto.params().get('apisecret')

        verify_certificate = not demisto.params().get('insecure', False)
        proxy = demisto.params().get('proxy', False)

        # prepare payload
        payload = "client_id=" + client_id + "&client_secret=" + client_secret

        # prepare client class object
        client = Client(base_url=url, verify=verify_certificate, proxy=proxy,
                        request_timeout=DEFAULT_SESSION_TIMEOUT, payload=payload)

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

            incident_type = demisto.params().get('incidentType')

            fetch_limit = demisto.params().get('max_fetch')

            fetch_policy_actions = demisto.params().get('fetch_policy_actions')

            policy_filter = demisto.params().get('policy_filter')

            exclude_alert_type = demisto.params().get('exclude_alert_type')

            result = test_function(client=client, first_fetch_time=first_fetch_time, fetch_limit=fetch_limit,
                                   is_fetch=is_fetch, incident_type=incident_type,
                                   fetch_policy_actions=fetch_policy_actions, policy_filter=policy_filter,
                                   exclude_alert_type=exclude_alert_type)
            demisto.results(result)
        elif demisto.command() == 'apd-list-policy-events':
            return_results(list_policy_events_command(client, args))
        elif demisto.command() == 'apd-list-message-data':
            return_results(list_message_data_command(client, args))
        elif demisto.command() == 'fetch-incidents':
            next_run, incidents = fetch_incidents(
                client,
                demisto.getLastRun(),
                demisto.params())

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif demisto.command() == 'apd-remediate-message':
            return_results(remediate_message_command(client, args))

    # Log exceptions
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
