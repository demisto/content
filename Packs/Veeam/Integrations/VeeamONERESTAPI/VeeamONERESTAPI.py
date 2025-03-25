import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''
from http import HTTPStatus
from typing import Any
from collections.abc import Callable
from dateutil import parser
from datetime import datetime
from packaging.version import Version
import json
import ast
from enum import Enum
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
MAX_ATTEMPTS = 3
MAX_ALARMS_FOR_FETCH = 200
GRANT_TYPE = 'password'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
CONTENT_TYPE = 'application/json'
ERROR_IN_TRIGGERED_ALARMS = 'error_in_triggered_alarms'
SUPPORTED_VONE_VERSION = '12.2.0.0'
NOT_APPLICABLE = 'N/A'
DEFAULT_PAGE_SIZE = 100
DEFAULT_SIZE_LIMIT = 0  # Unlimited

DESIRED_TYPES = {
    395: 'Backup Server Security Status',
    364: 'Incremental Backup Size',
    369: 'Job Duration',
    391: 'Enterprise Application Backup',
    365: 'Backup Copy Creation Time',
    370: 'Physical Machine Backup',
    314: 'Virtual Machine Backup',
    331: 'Virtual Machine Replica',
    376: 'Immutability State',
    377: 'Immutability Change Tracking',
    403: 'Malware Detection Change Tracking',
    316: 'Job Disabling',
    342: 'Possible Malware Activity',
    381: 'Job Duration Deviation (Veeam Backup for Microsoft 365)',
}

SEVERITY_MAP = {
    395: IncidentSeverity.MEDIUM,
    364: IncidentSeverity.CRITICAL,
    369: IncidentSeverity.MEDIUM,
    391: IncidentSeverity.CRITICAL,
    365: IncidentSeverity.CRITICAL,
    370: IncidentSeverity.CRITICAL,
    314: IncidentSeverity.CRITICAL,
    331: IncidentSeverity.CRITICAL,
    376: IncidentSeverity.MEDIUM,
    377: IncidentSeverity.MEDIUM,
    403: IncidentSeverity.CRITICAL,
    316: IncidentSeverity.MEDIUM,
    342: IncidentSeverity.CRITICAL,
    381: IncidentSeverity.MEDIUM,
}

ERROR_COUNT_MAP = {
    2: IncidentSeverity.LOW,
    6: IncidentSeverity.MEDIUM,
    48: IncidentSeverity.CRITICAL,

}

DESIRED_STATUSES = ['Warning', 'Error']


class Operation(Enum):
    EQUALS = 'equals'
    NOT_EQUALS = 'notEquals'
    GREATER_THAN = 'greaterThan'
    GREATER_THAN_OR_EQUAL = 'greaterThanOrEqual'
    LESS_THAN = 'lessThan'
    LESS_THAN_OR_EQUAL = 'lessThanOrEqual'
    IN = 'in'
    CONTAINS = 'contains'
    SUBSET = 'subset'
    SUPERSET = 'superset'
    OR = 'or'
    AND = 'and'
    EXCLUSIVE_OR = 'exclusiveOr'
    NOT = 'not'


class FilterBuilder:
    def __init__(self, operation=None, items=None):
        self.operation = operation
        self.items = items or []

    def add_property(self, property, operation, value, collation=None):
        item = {'property': property, 'operation': operation.value, 'value': value}
        if collation:
            item['collation'] = collation
        self.items.append(item)

    def add_node(self, node):
        if isinstance(node, FilterBuilder):
            self.items.append(json.loads(str(node)))

    def __str__(self):
        result = {}
        if len(self.items) == 1:
            result = self.items[0]
        elif len(self.items) > 1:
            result = {
                'operation': self.operation.value if self.operation else None,
                'items': self.items}
        return json.dumps(result)


''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth, timeout):
        super().__init__(
            base_url=server_url,
            verify=verify,
            proxy=proxy,
            headers=headers,
            auth=auth,
            timeout=timeout
        )

    def get_headers(self):
        """
        Gets headers required for requests.

        Returns:
            dict: The header dictionary.
        """
        return self._headers

    def set_headers(self, headers):
        """
        Sets headers required for requests.

        Args:
            headers (dict): The header dictionary to set.
        """
        self._headers = headers

    def get_about_request(self):
        """
        Retrieves information about the Veeam ONE server.

        Returns:
            dict: The response data.
        """
        headers = self._headers.copy()

        response = self._http_request('get', 'api/v2.2/about', headers=headers)

        return response

    def authentication_create_token_request(self, grant_type, username=None, password=None, refresh_token=None):
        """
        Creates an authentication token.

        Args:
            grant_type (str): The grant type (e.g., 'password' or 'refresh_token').
            username (str): The username for the password grant type.
            password (str): The password for the password grant type.
            refresh_token (str): The refresh token for the refresh token grant type.

        Returns:
            dict: The response data.
        """
        data = assign_params(grant_type=grant_type, username=username, password=password, refresh_token=refresh_token)
        headers = self._headers.copy()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'

        response = self._http_request('post', 'api/token', data=data, headers=headers)

        return response

    def get_triggered_alarms_request(self, Offset=None, Limit=None, Filter=None, Sort=None, Select=None):
        """
        Retrieves triggered alarms.

        Args:
            Offset (int): The number of records to skip.
            Limit (int): The maximum number of records to retrieve.
            Filter (str): The filter to apply to the results.
            Sort (str): The order in which to sort the results.
            Select (str): Property that must be explicitly returned in a response.

        Returns:
            dict: The response data.
        """
        params = assign_params(Offset=Offset, Limit=Limit, Filter=Filter, Sort=Sort, Select=Select)
        headers = self._headers.copy()

        response = self._http_request(
            'get',
            'api/v2.2/alarms/triggeredAlarms',
            params=params,
            headers=headers
        )

        return response

    def resolve_triggered_alarms_request(self, triggeredAlarmIds, comment, resolveType):
        """
        Resolves triggered alarms.

        Args:
            triggeredAlarmIds (List[str]): The IDs of the triggered alarms to resolve.
            comment (str): The comment for resolving the alarms.
            resolveType (str): The type of resolution.

        Returns:
            str: The response result as a string.
        """

        data = assign_params(triggeredAlarmIds=triggeredAlarmIds, comment=comment, resolveType=resolveType)
        headers = self._headers.copy()

        response = self._http_request(
            'post',
            'api/v2.2/alarms/triggeredAlarms/resolve',
            json_data=data,
            headers=headers,
            resp_type='response'
        )

        result = str(response)
        return result


''' HELPER FUNCTIONS '''


def get_triggered_alarms_command(client: Client, args: dict[str, Any]) -> CommandResults:
    Offset = args.get('Offset', None)
    try_cast_to_int(Offset)
    Limit = args.get('Limit', None)
    try_cast_to_int(Limit)
    Filter = str(args.get('Filter', ''))
    Sort = str(args.get('Sort', ''))
    Select = str(args.get('Select', ''))

    response = client.get_triggered_alarms_request(Offset, Limit, Filter, Sort, Select)

    command_results = CommandResults(
        outputs_prefix='Veeam.VONE.TriggeredAlarmInfoPage',
        outputs_key_field='',
        outputs=response['items'],
        raw_response=response['items']
    )

    return command_results


def resolve_triggered_alarms_command(client: Client, args: dict[str, Any]) -> CommandResults:
    triggeredAlarmIds_str = args.get('triggeredAlarmIds', '')
    triggeredAlarmIds = convert_to_list(triggeredAlarmIds_str)
    comment = str(args.get('comment', ''))

    resolveType = str(args.get('resolveType', ''))

    response = client.resolve_triggered_alarms_request(triggeredAlarmIds, comment, resolveType)
    command_results = CommandResults(
        outputs_prefix='Veeam.VONE',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def convert_to_list(string: str) -> list:
    try:
        result = ast.literal_eval(string)
        if isinstance(result, list):
            return result
        else:
            return []
    except Exception as e:
        raise Exception(f"Failed to convert '{string}' to list. Exception: {str(e)}")


def try_cast_to_int(value: str) -> None:
    if value:
        try:
            int(value)
        except ValueError as e:
            raise ValueError(f"Failed to convert '{value}' to integer. Exception: {str(e)}")


def check_version(version_: str) -> None:
    parsed_version = Version(version_)
    parsed_supported_version = Version(SUPPORTED_VONE_VERSION)

    if parsed_version < parsed_supported_version:
        raise ValueError(f"Minimum supported version is {SUPPORTED_VONE_VERSION}. Current version is {version_}")


def test_module(client: Client) -> str:
    """
    Tests the integration by making a request to the Veeam ONE server and checking the version.

    Args:
        client (Client): The Veeam ONE API client.

    Returns:
        str: The result of the test. Returns 'ok' if the test is successful.

    Raises:
        Exception: If an error occurred during the test.
    """
    try:
        response = client.get_about_request()
        version = response.get('version', '')
        check_version(version)
    except Exception as e:
        exception_text = str(e).lower()
        if 'forbidden' in exception_text or 'authorization' in exception_text:
            return 'Authentication Error: Invalid API Key'
        else:
            raise e
    return 'ok'


def update_token(client: Client, username: str, password: str) -> str:
    response = client.authentication_create_token_request(GRANT_TYPE, username, password)
    token = response.get('access_token')
    return token


def search_with_paging(
    method: Callable[..., Any],
    args: dict[str, Any] = {},
    page_size=DEFAULT_PAGE_SIZE,
    size_limit=DEFAULT_SIZE_LIMIT
) -> list[dict]:

    skip_items = 0
    args['Offset'] = 0
    items_to_fetch = size_limit
    items: list[dict] = []

    while True:
        if 0 < items_to_fetch < page_size:
            page_size = items_to_fetch
        args['Limit'] = page_size

        response = method(**args)
        items = items + response['items']
        response_len = len(response['items'])

        if response_len < page_size:
            break

        items_to_fetch -= response_len
        skip_items += page_size

        if (size_limit and items_to_fetch <= 0):
            items = items[:size_limit]
            break

        args['Offset'] = skip_items

    return items


def overwrite_last_fetch_time(last_fetch_time: str, alarm: dict) -> str:
    last_fetch_datetime = parser.isoparse(last_fetch_time)
    alarm_datetime = parser.isoparse(alarm['triggeredTime'])

    if alarm_datetime > last_fetch_datetime:
        last_fetch_time = alarm['triggeredTime']

    return last_fetch_time


def process_error(error_count: int, error_message: str) -> tuple[dict, int]:
    error_count += 1
    incident = {}
    if error_count in ERROR_COUNT_MAP:
        integration_instance = demisto.callingContext.get('context', {}).get('IntegrationInstance', '')
        incident_name = f"Veeam - Fetch incident error has occurred on {integration_instance}"
        incident = {
            'name': incident_name,
            'occurred': datetime.now().strftime(DATE_FORMAT),
            'rawJSON': json.dumps({'incident_type': 'Incident Fetch Error', 'details': error_message}),
            'severity': ERROR_COUNT_MAP[error_count]
        }

    return incident, error_count


def convert_triggered_alarms_to_incidents(
    client: Client, start_time: datetime, existed_ids: set, max_results: int
) -> tuple[list[dict], set[str], str]:

    last_fetch_time = start_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

    sorting = '{"property": "triggeredTime", "direction": "ascending"}'
    filter_builder = FilterBuilder(operation=Operation.AND)
    filter_builder.add_property('triggeredTime', Operation.GREATER_THAN_OR_EQUAL, last_fetch_time)
    filter_builder.add_property('predefinedAlarmId', Operation.IN, list(DESIRED_TYPES.keys()))
    filter_builder.add_property('status', Operation.IN, DESIRED_STATUSES)
    Filter = str(filter_builder)

    response = search_with_paging(
        method=client.get_triggered_alarms_request,
        args={'Filter': Filter, 'Sort': sorting},
        size_limit=max_results
    )
    incidents: list[dict] = []
    new_ids = set()

    for alarm in response:
        if len(incidents) >= max_results:
            break

        alarm_id = str(alarm.get('triggeredAlarmId'))

        if alarm_id not in existed_ids:
            object_name = alarm.get('alarmAssignment', {}).get('objectName', NOT_APPLICABLE)
            incident_name = f"Veeam - {alarm['name']} ({object_name})"
            alarm['incident_type'] = alarm['predefinedAlarmId']
            incident = {
                'name': incident_name,
                'occurred': alarm['triggeredTime'],
                'rawJSON': json.dumps(alarm),
                'severity': SEVERITY_MAP.get(alarm['predefinedAlarmId'])
            }
            new_ids.add(alarm_id)
            incidents.append(incident)
            last_fetch_time = overwrite_last_fetch_time(last_fetch_time, alarm)

    if not new_ids:
        new_ids = existed_ids

    return incidents, new_ids, last_fetch_time


def fetch_converted_incidents(
    client: Client, last_run: dict, last_fetch: str, max_results: int, errors_by_command: dict
) -> tuple[list[dict], set[str], str]:

    last_fetch_time = last_fetch
    incidents: list[dict] = []
    error_count: int = errors_by_command.get(ERROR_IN_TRIGGERED_ALARMS, 0)
    try:
        alarms_ids = set(last_run.get('alarms_ids', []))
        incidents, alarms_ids, last_fetch_time = handle_command_with_token_refresh(
            convert_triggered_alarms_to_incidents,
            {'client': client, 'start_time': parser.parse(last_fetch), 'existed_ids': alarms_ids, 'max_results': max_results},
            client
        )
        error_count = 0
    except Exception as e:
        error_message = str(e)
        demisto.debug(error_message)
        incident, error_count = process_error(error_count, error_message)
        if incident:
            incidents.append(incident)
    finally:
        errors_by_command[ERROR_IN_TRIGGERED_ALARMS] = error_count
        return incidents, alarms_ids, last_fetch_time


def fetch_incidents(
    client: Client, last_run: dict, first_fetch_time: str, max_triggered_alarms_for_fetch: int
) -> tuple[dict, list[dict]]:

    demisto.debug(f'Last run: {json.dumps(last_run)}')
    last_fetch = last_run.get('last_fetch', None)

    # Handle first fetch time
    if last_fetch is None:
        # if missing, use what provided via first_fetch_time
        last_fetch = first_fetch_time
    else:
        # otherwise use the stored last fetch
        last_fetch = last_fetch

    assert last_fetch

    incidents: list[dict[str, Any]] = []
    errors_by_command: dict = last_run.get('errors_by_command', {})

    alarmIds: set[str] = set()
    last_fetch_time: str = datetime.now().strftime(DATE_FORMAT)
    if max_triggered_alarms_for_fetch > 0:
        incidents, alarmIds, last_fetch_time = fetch_converted_incidents(
            client=client, last_run=last_run, last_fetch=last_fetch,
            max_results=max_triggered_alarms_for_fetch, errors_by_command=errors_by_command
        )

    next_run = {'last_fetch': last_fetch_time, 'alarms_ids': list(alarmIds), 'errors_by_command': errors_by_command}
    demisto.debug(f'Number of incidents: {len(incidents)}')
    demisto.debug(f'Next run after incident fetching: {json.dumps(next_run)}')
    return next_run, incidents


def process_command(command: Any, client: Client, first_fetch_time: datetime,
                    params: dict, args: dict, max_attempts: int = MAX_ATTEMPTS):
    commands = {
        'veeam-vone-get-triggered-alarms': get_triggered_alarms_command,

        'veeam-vone-resolve-triggered-alarms': resolve_triggered_alarms_command
    }

    if command == 'test-module':
        result = handle_command_with_token_refresh(test_module, {'client': client}, client, max_attempts)
        return result

    elif command == 'fetch-incidents':
        max_triggered_alarms_for_fetch = int(params.get('max_fetch', MAX_ALARMS_FOR_FETCH))

        next_run, incidents = fetch_incidents(
            client=client,
            last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
            first_fetch_time=datetime.strftime(first_fetch_time, DATE_FORMAT),
            max_triggered_alarms_for_fetch=max_triggered_alarms_for_fetch)

        demisto.setLastRun(next_run)
        demisto.incidents(incidents)
        return None

    elif command in commands:
        result = handle_command_with_token_refresh(commands[command], {'client': client, 'args': args}, client, max_attempts)
        return result
    else:
        raise NotImplementedError(f'Command {command} is not implemented.')


def get_api_key(client: Client) -> str:
    credentials: dict[str, str] = demisto.params().get('credentials')
    username: str = credentials.get('identifier', '')
    password: str = credentials.get('password', '')
    token = update_token(client, username, password)
    api_key = f'Bearer {token}'
    return api_key


def set_api_key(client: Client, api_key: str) -> None:
    headers = client.get_headers()
    headers['Authorization'] = api_key
    client.set_headers(headers)


def handle_command_with_token_refresh(command: Callable, command_params: dict, client: Client, max_attempts: int = MAX_ATTEMPTS):
    attempts = 0

    while attempts < max_attempts:
        try:
            context = demisto.getIntegrationContext()
            api_key = context.get('token')
            if not api_key:
                api_key = get_api_key(client)
                demisto.setIntegrationContext({'token': api_key})

            set_api_key(client, api_key)

            response = client.get_about_request()
            version = response.get('version', '')
            check_version(version)

            res = command(**command_params)
            return res
        except Exception as e:
            status_code = getattr(getattr(e, 'res', None), 'status_code', None)
            if status_code == HTTPStatus.UNAUTHORIZED:
                attempts += 1
                context = demisto.getIntegrationContext()
                context['token'] = None
                demisto.setIntegrationContext(context)
            else:
                raise e

    raise ValueError('Failed to obtain a valid API Key after 3 attempts')


def main() -> None:

    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()
    url: str = params.get('url', '')
    verify_certificate: bool = not params.get('insecure', False)
    proxy: bool = params.get('proxy', False)

    first_fetch_time = arg_to_datetime(
        arg=params.get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=False
    )

    if not first_fetch_time:
        first_fetch_time = datetime.now()

    http_request_timeout_sec = int(params.get('http_request_timeout_sec', 120))

    headers = {}
    headers['Content-Type'] = CONTENT_TYPE

    command = demisto.command()
    demisto.debug(f'Command {command} has been run with the following arguments: {args}')

    try:
        client: Client = Client(
            urljoin(url, '/'),
            verify_certificate,
            proxy,
            headers=headers,
            auth=None,
            timeout=http_request_timeout_sec
        )
        result = process_command(command, client, first_fetch_time, params, args)
        return_results(result)

    except Exception as e:
        error_message: Union[str, dict[str, Any]] = str(e)
        res = getattr(e, 'res', None)
        status_code = getattr(res, 'status_code', None)
        if res is not None and status_code:
            error_message = {'status_code': status_code, 'message': str(e)}

        return_error(error_message)


''' ENTRY POINT '''

if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
