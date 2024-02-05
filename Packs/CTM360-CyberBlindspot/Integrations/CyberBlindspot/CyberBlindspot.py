import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa

import urllib3
from typing import Any

''' IMPORTS '''

from hashlib import sha256
from inspect import getfullargspec

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

INFO = 'info'
ERROR = 'error'
DEBUG = 'debug'
MAX_RETRIES = 5
MIRROR_LIMIT = 1000
ABSOLUTE_MAX_FETCH = 200
MAX_FETCH = arg_to_number(demisto.params().get('max_fetch')) or 25
MAX_FETCH = min(MAX_FETCH, ABSOLUTE_MAX_FETCH)
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
CBS_OUTGOING_DATE_FORMAT = '%d-%m-%Y %H:%M'
CBS_INCOMING_DATE_FORMAT = '%d-%m-%Y %I:%M:%S %p'
CBS_BASE_URL = 'https://cbs.ctm360.com'
CBS_API_ENDPOINT = '/api/v2/incidents'
API = {
    'CLOSE_INCIDENT': '/close_incident/',
    'REQUEST_TAKEDOWN': '/request_takedown/',
}
LOGGING_PREFIX = '[CYBER-BLINDSPOT]'

CBS_INCIDENT_FIELDS = [
    {'name': 'id', 'description': 'Unique ID for the incident record'},
    {'name': 'subject', 'description': 'Asset or title of incident'},
    {'name': 'severity', 'description': 'The severity of the incident'},
    {'name': 'type', 'description': 'Incident type'},
    {'name': 'class', 'description': 'Subject class'},
    {'name': 'status', 'description': 'Incident\'s current state of affairs'},
    {'name': 'coa', 'description': 'The possible course of action'},
    {'name': 'remarks', 'description': 'Remarks about the incident'},
    {'name': 'created_date', 'description': 'The creation date of the incident'},
    {'name': 'updated_date', 'description': 'The date the incident got last updated'},
    {'name': 'brand', 'description': 'The organization the incident belongs to'},
    {'name': 'timestamp', 'description': 'The timestamp of when the record was created'},
]

MIRROR_DIRECTION = {
    'None': None,
    'Incoming': 'In',
    'Outgoing': 'Out',
    'Incoming And Outgoing': 'Both'
}.get(demisto.params().get('mirror_direction'))

INTEGRATION_INSTANCE = demisto.integrationInstance()


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def test_configuration(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        """Send request to test

        :param params: Parameters to be sent in the request
        :type params: dict[str, Any]
        :return: List containing the incidents
        :rtype: List[dict[str, Any]]
        """

        response = self._http_request(
            method='GET',
            url_suffix=f'{CBS_API_ENDPOINT}/xsoar',
            params=params
        )
        log(DEBUG, 'at client\'s test function')
        if response.get('statusCode') != 200:
            raise DemistoException(f'Error received: {response.get("errors")}')
        return response

    def fetch_incidents(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        """Send request to fetch list of incidents

        :param params: Parameters to be sent in the request
        :type params: dict[str, Any]
        :return: List containing the incidents
        :rtype: List[dict[str, Any]]
        """

        response = self._http_request(
            method='GET',
            retries=MAX_RETRIES,
            backoff_factor=10,
            status_list_to_retry=[400, 429, 500],
            url_suffix=f'{CBS_API_ENDPOINT}/xsoar',
            params=params
        )
        log(DEBUG, 'at client\'s fetch function')
        if response.get('statusCode') != 200:
            raise DemistoException(f'Error received: {response.get("message")}')

        incident_list = response.get('incident_list', [])
        return incident_list

    def fetch_incident(self, params: dict[str, Any]) -> dict[str, Any]:
        """Send a request to fetch a certain incident

        :param params: Parameters to be sent in the request
        :type params: dict[str, Any]
        :return: Dictionary containing the incident data
        :rtype: dict[str, Any]
        """
        response = self._http_request(
            method='GET',
            retries=MAX_RETRIES,
            backoff_factor=10,
            status_list_to_retry=[400, 429, 500],
            url_suffix=f'{CBS_API_ENDPOINT}/xsoar',
            params=params
        )
        log(DEBUG, 'at client\'s fetch function')

        incident_list = response.get('incident_list', [])
        if not incident_list:
            return {}

        return incident_list[0]

    def close_incident(self, args: dict[str, Any]) -> dict[str, Any]:
        """Send incident close request for a certain incident

        :param args: Arguments to be sent in the request
        :type args: dict[str, Any]
        :return: Response from the remote server carrying the result of the request
        :rtype: dict[str, Any]
        """
        response = self._http_request(
            method='POST',
            retries=MAX_RETRIES,
            backoff_factor=10,
            status_list_to_retry=[400, 429, 500],
            url_suffix=CBS_API_ENDPOINT + API['CLOSE_INCIDENT'],
            data=args,
            params={'t': datetime.now().timestamp()}
        )
        log(DEBUG, f'Closing returned status {response.get("statusCode")}')

        if response.get('statusCode') != 200:
            log(ERROR, f'Incident could not be closed: Error Code {response.get("statusCode")}')
        else:
            log(INFO, response.get('message', ''))
        return response

    def request_takedown(self, args: dict[str, Any]) -> dict[str, Any]:
        """Send incident takedown request for a certain incident

        :param args: Arguments to be sent in the request
        :type args: dict[str, Any]
        :return: Response from the remote server carrying the result of the request
        :rtype: dict[str, Any]
        """

        response = self._http_request(
            method='POST',
            retries=MAX_RETRIES,
            backoff_factor=10,
            status_list_to_retry=[400, 429, 500],
            url_suffix=CBS_API_ENDPOINT + API['REQUEST_TAKEDOWN'],
            data=args,
            params={'t': datetime.now().timestamp()}
        )
        log(DEBUG, f'Takedown request returned status {response.get("statusCode")}')

        if response.get('statusCode') != 200:
            log(ERROR, f'Takedown Request Failed: Error Code {response.get("statusCode")}')
        else:
            log(INFO, response.get('message', ''))
        return response


''' HELPER FUNCTIONS '''


def log(level: str, msg: str):
    {
        'info': demisto.info,
        'error': demisto.error,
        'debug': demisto.debug,
    }[level.lower()](f'{LOGGING_PREFIX} {msg}')


def convert_to_demisto_severity(severity: str) -> int | float:
    """Converts the CyberBlindspot incident severity level ('Unknown', 'Info', 'Low', 'Medium', 'High', 'Critical') to XSOAR
    incident severity (0 to 4).

    :param severity: severity as returned from the CyberBlindspot API
    :type severity: ``str``
    :return: _description_
    :rtype: ``int | float``
    """

    return {
        'informational': IncidentSeverity.INFO,
        'info': IncidentSeverity.INFO,
        'low': IncidentSeverity.LOW,
        'medium': IncidentSeverity.MEDIUM,
        'high': IncidentSeverity.HIGH,
        'critical': IncidentSeverity.CRITICAL,
        'fyi': IncidentSeverity.UNKNOWN
    }[severity.lower()]


def convert_time_string(
        time_string: str,
        input_format_string: str,
        output_format: str = '',
        timestamp: bool = False,
        is_utc=False,
        in_iso_format=False,
        **parser_args) -> datetime | str | int:
    """helper function to convert a time string into another format or get the timestamp from it

    :param time_string: Input time string
    :type time_string: ``str``
    :param input_format_string: Format string of the input_time_string
    :type input_format_string: ``str``
    :param output_format: The format string to convert a time string into, defaults to ''
    :type output_format: str, optional
    :param timestamp: A flag to signal whether or not to return a timestamp, defaults to False
    :type timestamp: bool, optional
    :return: A datetime object, a time string or timestamp integer
    :rtype: ``datetime|str|int``
    """
    try:
        output = dateparser.parse(time_string, [input_format_string], **parser_args)
        if not isinstance(output, datetime):
            raise ValueError("The passed date string and/or format string is not valid")
        if is_utc:
            output = output.replace(tzinfo=timezone.utc)
        if in_iso_format:
            return output.isoformat()
        if output_format:
            return output.strftime(output_format)
        elif timestamp:
            return int(output.timestamp() * 1000)
        else:
            return output
    except ValueError as err:
        log(ERROR, f'An error was encountered at `convert_time_string()` {err=}')
        return ''


@logger
def deduplicate_and_create_incidents(fetched_incidents: List, last_run_incident_identifiers: List[str]) -> tuple[list, list]:
    """De-duplicates the fetched incidents and creates a list of actionable incidents.

    :param fetched_incidents: Context of the events fetched.
    :type fetched_incidents: List
    :param last_run_incident_identifiers: List of hashes generated for the events fetched in previous call.
    :type last_run_incident_identifiers: List[str]

    :return: Returns updated list of event hashes and unique incidents that should be created.
    :rtype: ``tuple[list,list]``
    """
    log(DEBUG, "at Dedup function")
    incidents: List[dict[str, Any]] = []
    new_incident_hashes = []
    for incident in fetched_incidents:
        try:
            incident_hash = sha256(str(incident.get('id')).encode()).hexdigest()
            new_incident_hashes.append(incident_hash)
        except Exception as e:
            log(ERROR, f'Skipping insertion of current incident. Error while calculating hash for {incident=}. Error: {str(e)}')
            continue
        if last_run_incident_identifiers and incident_hash in last_run_incident_identifiers:
            log(INFO, f'Skipping insertion of current incident since it already exists. \n\n {incident=}')
            continue
        else:
            log(DEBUG, "Creating unique incident")
            unique_mapped_incident = map_and_create_incident(incident)
            incidents.append(unique_mapped_incident)
    log(DEBUG, f'{incidents=}')
    return new_incident_hashes, incidents


def map_and_create_incident(unmapped_incident: dict) -> dict:
    """Use dictionary of unmapped fetched incident to create a mapped dictionary

    :param unmapped_incident: Fetched incident (unmapped)
    :type unmapped_incident: ``dict``
    :return: Incident in format ready for XSOAR
    :rtype: ``dict``
    """
    mapped_incident = {
        'name': unmapped_incident.get('remarks'),
        'occurred': convert_time_string(
            unmapped_incident.get('created_date', ''),
            CBS_INCOMING_DATE_FORMAT, in_iso_format=True, is_utc=True),
        'type': unmapped_incident.get('type'),
        'externalstatus': unmapped_incident.get('status'),
        'severity': convert_to_demisto_severity(unmapped_incident.get('severity', 'low')),
        'CustomFields': {
            'cbs_status': unmapped_incident.get('status'),
            'cbs_subject': unmapped_incident.get('subject'),
            'cbs_class': unmapped_incident.get('class'),
            'cbs_type': unmapped_incident.get('type'),
            'cbs_coa': unmapped_incident.get('coa'),
            'cbs_timestamp': unmapped_incident.get('timestamp'),
            'cbs_updated_date': convert_time_string(
                unmapped_incident.get('updated_date', ''),
                CBS_INCOMING_DATE_FORMAT, in_iso_format=True, is_utc=True)
        }
    }
    if MIRROR_DIRECTION:
        mapped_incident['xsoar_mirroring'] = {
            'mirror_direction': MIRROR_DIRECTION,
            'mirror_id': unmapped_incident.get('id'),
            'mirror_instance': INTEGRATION_INSTANCE,
        }

    mapped_incident['rawJson'] = json.dumps(mapped_incident)
    return mapped_incident


def to_snake_case(input_string: str) -> str:
    """helper function to return passed strings in snake_case

    :param input_string: Input string to change into snake case
    :type input_string: ``str``
    :return: A string in snake case
    :rtype: ``str``
    """
    return ''.join(['_' + i.lower() if i.isupper() else i for i in input_string]).lstrip('_')


''' COMMAND FUNCTIONS '''


def test_module(client: Client, params) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: `'ok'` if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    args: dict[str, Any] = {}
    try:
        log(DEBUG, f'{params=}')
        mirror_direction = params.get('mirror_direction', '')
        first_fetch = params.get('first_fetch', '')
        max_fetch = arg_to_number(params.get('max_fetch', ''))
        date_from = params.get('date_from', '')
        date_to = params.get('date_to', '')
        api_key = params.get('api_key', {}).get('password', '')

        if mirror_direction not in ['None', 'Incoming', 'Outgoing', 'Incoming And Outgoing']:
            log(INFO, 'Invalid "Mirror Direction" Value')
            raise DemistoException('Invalid "Mirroring Direction" Value')
        if first_fetch and not dateparser.parse(first_fetch):
            log(INFO, 'Invalid "First Fetch" Value')
            raise DemistoException('Invalid "First Fetch" Value')
        if max_fetch and (max_fetch <= 0 or max_fetch > ABSOLUTE_MAX_FETCH):
            log(INFO, f'Invalid "Max Fetch" Value. Should be between 1 to {ABSOLUTE_MAX_FETCH}')
            raise DemistoException(f'Invalid "Max Fetch" Value. Should be between 1 to {ABSOLUTE_MAX_FETCH}')
        else:
            args['max_hits'] = max_fetch
        if date_from and not dateparser.parse(date_from, [CBS_OUTGOING_DATE_FORMAT]):
            log(INFO, 'Invalid "Date From" Value (Does not match format "%d-%m-%Y %H:%M")')
            raise DemistoException('Invalid "Date From" Value (Does not match format "%d-%m-%Y %H:%M")')
        elif date_from:
            args['date_from'] = convert_time_string(date_from, CBS_OUTGOING_DATE_FORMAT, timestamp=True)
        if date_to and not dateparser.parse(date_to, [CBS_OUTGOING_DATE_FORMAT]):
            log(INFO, 'Invalid "Date To" Value (Does not match format "%d-%m-%Y %H:%M")')
            raise DemistoException('Invalid "Date To" Value (Does not match format "%d-%m-%Y %H:%M")')
        elif date_to:
            args['date_to'] = convert_time_string(date_to, CBS_OUTGOING_DATE_FORMAT, timestamp=True)
        if not api_key:
            log(INFO, 'Invalid "API Key" Value')
            raise DemistoException('Invalid "API Key" Value')
        incidents = client.test_configuration(args)
        if max_fetch and len(incidents) > max_fetch:
            log(INFO, f'Incidents fetched exceed the limit, removing the excess {len(incidents) - max_fetch} incidents.')
            incidents = incidents[::max_fetch - 1]
        message = 'ok'
    except DemistoException as e:
        expected_words = [
            "Forbidden",
            "Authorization",
            "Mirroring Direction",
            "First Fetch",
            "Max Fetch",
            "Date From",
            "Date To",
            "API Key",
            "does not match format '%d-%m-%Y %H:%M'"
        ]
        for word in expected_words:
            log(DEBUG, 'Exception in test_module()')
            if word in str(e.message):
                message = e.message
            else:
                raise e
    return message


def fetch_incidents(
        client: Client,
        last_fetch_hashes: list[str],
        params: dict[str, Any],
        last_run: dict[str, Any]) -> tuple[dict, list[dict]]:
    """Helper function to call client's `fetch_incidents` function.

    Args:
        client (Client): client
        last_fetch_hashes (list[str]): The list of hashes of unique incident IDs that were fetched in the last run
        params (dict[str, Any]): GET params to send with the fetch request

    Returns:
        tuple[dict, list[dict]]: The next run object and the list of incidents minus incidents from last run
    """
    incidents = client.fetch_incidents(params)

    max_fetch = arg_to_number(params.get('max_hits')) or MAX_FETCH
    if max_fetch and len(incidents) > max_fetch:
        log(INFO, f'Incidents fetched exceed the limit, removing the excess {len(incidents) - max_fetch} incidents.')
        incidents = incidents[::max_fetch - 1]

    if not incidents and not last_run:
        log(INFO, 'No incidents returned, and no last run data was found')
        return {}, []

    incident_hashes, unique_incidents = deduplicate_and_create_incidents(incidents, last_fetch_hashes)
    log(INFO, f'Received {len(incidents) - len(unique_incidents)} duplicates incidents to skip.')
    log(INFO, f'Calculated {len(incident_hashes)} hash(es).')

    dates = sorted([d['CustomFields']['cbs_timestamp'] for d in unique_incidents])
    last_fetched_timestamp = dates[-1] if dates else last_run.get('last_fetched_timestamp')

    log(INFO, f'setting last fetched timestamp - {last_fetched_timestamp=}')
    next_run = {'last_fetched_timestamp': last_fetched_timestamp, 'last_fetch_hashes': incident_hashes}
    return next_run, unique_incidents


def get_remote_data_command(client: Client, args: dict):
    """ get-remote-data command: Returns an updated incident and error entry (if needed)

    Args:
        client: client
        args (dict): The command arguments
        close_incident (bool): Indicates whether to close the corresponding XSOAR incident if the incident
            has been closed on CBS's end.
        close_end_statuses (bool): Specifies whether "End Status" statuses on CBS should be closed when mirroring.

    Returns:
        GetRemoteDataResponse: The Response containing the updated incident to mirror and its entries
    """
    entries = []
    updated_incident = {}
    remote_args = GetRemoteDataArgs(args)
    remote_incident_id = remote_args.remote_incident_id
    last_update = parse_date_string(remote_args.last_update)
    last_update_ts = last_update.timestamp() * 1000 if isinstance(last_update, datetime) else -1

    log(DEBUG, f'Performing get-remote-data command for the incident: {remote_incident_id}')

    params = {
        'ticket_id': remote_incident_id,
        't': datetime.now().timestamp() * 1000
    }

    updated_incident = client.fetch_incident(params)
    incident_updated_date = updated_incident.get('updated_date', '')
    settings = {'TIMEZONE': 'UTC'}
    remote_incident_last_update_ts = convert_time_string(
        incident_updated_date,
        CBS_INCOMING_DATE_FORMAT,
        timestamp=True,
        settings=settings)
    log(DEBUG, f'{updated_incident=}')
    log(DEBUG, f'{last_update_ts=}')
    log(DEBUG, f'{remote_incident_last_update_ts=}')
    status = updated_incident.get('status', '').lower()

    if status == 'closed':
        log(DEBUG, 'Incident seems to be closed. Adding closing entry')
        log(INFO, f'Updating incident {remote_incident_id} with status: {status}')
        close_reason = f'Incident was {"closed" if status == "closed" else "resolved through monitoring"} on CyberBlindspot.'
        entries.append({
            'Type': EntryType.NOTE,
            'Contents': {
                'dbotIncidentClose': True,
                'closeReason': close_reason
            },
            'ContentsFormat': EntryFormat.JSON
        })
    elif status == 'resolved':
        log(DEBUG, 'Incident seems to be resolved. Adding resolution entry')
        log(INFO, f'Updating incident {remote_incident_id} with status: {status}')
        note = 'Incident was resolved through monitoring on CyberBlindspot. Not closed yet.'
        entries.append({
            'Type': EntryType.NOTE,
            'Contents': note,
            'ContentsFormat': EntryFormat.TEXT
        })
    elif status == 'wip':
        log(DEBUG, 'Incident seems to be undergoing a process. Adding processing entry')
        log(INFO, f'Updating incident {remote_incident_id} with status: {status}')
        note = 'Incident is undergoing a process on CyberBlindspot. Actions will be unavailable until processing is done.'
        entries.append({
            'Type': EntryType.NOTE,
            'Contents': note,
            'ContentsFormat': EntryFormat.TEXT
        })
    elif status == 'monitoring':
        log(DEBUG, 'Incident seems to be have ongoing monitoring. Adding monitoring entry')
        log(INFO, f'Updating incident {remote_incident_id} with status: {status}')
        note = 'Incident is being monitored on CyberBlindspot. Actions will be unavailable until monitoring is done.'
        entries.append({
            'Type': EntryType.NOTE,
            'Contents': note,
            'ContentsFormat': EntryFormat.TEXT
        })

    else:
        log(DEBUG, f'This status value `{updated_incident.get("status")}` for incident {remote_incident_id}. Had some issue')
        return GetRemoteDataResponse([], [])
    log(DEBUG, f'Updated incident {remote_incident_id}')
    mapped_updated_incident = map_and_create_incident(updated_incident)
    return GetRemoteDataResponse(mirrored_object=mapped_updated_incident, entries=entries)


def get_modified_remote_data_command(client: Client, args):
    """ Gets the list of all incidents that have changed since a given timestamp

    Args:
        client: http Client
        args (dict): The command arguments

    Returns:
        GetModifiedRemoteDataResponse: The response containing the list of ids of incidents changed
    """
    modified_incident_ids: list = []
    remote_args = GetModifiedRemoteDataArgs(args)
    last_timestamp = convert_time_string(remote_args.last_update, '', timestamp=True)
    log(DEBUG, f'Performing get-modified-remote-data command with : {last_timestamp}({remote_args.last_update})')

    params = {
        'date_field': 'incident.last_updated_date',
        'order': 'asc',
        'date_from': last_timestamp,
        'max_hits': ABSOLUTE_MAX_FETCH,
        't': datetime.now().timestamp() * 1000
    }
    modified_incident_ids.extend(item['id'] for item in client.fetch_incidents(params))
    if len(modified_incident_ids) >= MIRROR_LIMIT:
        log(INFO, f'Warning: More than {MIRROR_LIMIT} incidents have been modified since the last update.')
    return GetModifiedRemoteDataResponse(modified_incident_ids=modified_incident_ids)


def update_remote_system_command(client: Client, args: dict):

    parsed_args = UpdateRemoteSystemArgs(args)
    log(DEBUG, f'Got the following update args:\n\n{parsed_args.entries=},')
    log(DEBUG, f'\n\n{parsed_args.data=}, ')
    log(DEBUG, f'\n\n{parsed_args.incident_changed=}, ')
    log(DEBUG, f'\n\n{parsed_args.inc_status=}, ')
    log(DEBUG, f'\n\n{parsed_args.remote_incident_id=}, ')
    log(DEBUG, f'\n\n{parsed_args.delta=}')
    if parsed_args.delta:
        log(DEBUG, f'Got the following delta keys {str(list(parsed_args.delta.keys()))}')

    remote_incident_id = parsed_args.remote_incident_id

    try:

        if parsed_args.incident_changed:
            issue_status: str = parsed_args.inc_status
            log(DEBUG, f'Incident {remote_incident_id} status changed to {issue_status}')
            if issue_status == IncidentStatus.DONE:
                log(DEBUG, f'Closing incident {remote_incident_id}')
                client.close_incident({'ticket_id': remote_incident_id, 't': datetime.now().timestamp()})
            else:
                log(DEBUG, f'Modification to {remote_incident_id} is not configured for outgoing mirroring..')
        else:
            log(DEBUG, f'Incident {remote_incident_id} was not modified locally..')
    except DemistoException as e:
        if 'Incident should be under Member Feedback or Monitoring to Close' in e.message:
            remote_incident = client.fetch_incident({'ticket_id': remote_incident_id})
            if remote_incident.get('status') is not None and remote_incident.get('status') == 'WIP':
                log(INFO, f'Incident {remote_incident_id} is undergoing a process..')

    return remote_incident_id


def get_mapping_fields_command():
    incident_type_scheme = SchemeTypeMapping(type_name='CyberBlindspot Incident')
    for field in CBS_INCIDENT_FIELDS:
        incident_type_scheme.add_field(name=field['name'], description=field['description'])

    return GetMappingFieldsResponse([incident_type_scheme])


def ctm360_cbs_incident_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    if args.get('dateFrom'):
        args['dateFrom'] = convert_time_string(args['dateFrom'], CBS_OUTGOING_DATE_FORMAT, timestamp=True)
    if args.get('dateTo'):
        args['dateTo'] = convert_time_string(args['dateTo'], CBS_OUTGOING_DATE_FORMAT, timestamp=True)
    params = {to_snake_case(key): v for key, v in args.items()}
    params |= {'date_field': '@timestamp', 't': datetime.now().timestamp()}
    log(DEBUG, f'{args=}')
    log(DEBUG, f'{params=}')
    result = client.fetch_incidents(params)
    log(INFO, f'Received {len(result)} incidents')
    if len(result) > 0:
        result = [map_and_create_incident(item) for item in result]

    return CommandResults(
        outputs_prefix='CyberBlindspot.IncidentList',
        outputs_key_field='id',
        outputs=result,
    )


def ctm360_cbs_incident_details_command(client: Client, args: dict[str, Any]) -> CommandResults:
    params = {to_snake_case(key): v for key, v in args.items()}
    params['t'] = datetime.now().timestamp()
    log(DEBUG, f'{args=}')
    log(DEBUG, f'{params=}')
    result = client.fetch_incident(params)
    log(INFO, f'Received {result}')

    return CommandResults(
        outputs_prefix='CyberBlindspot.RemoteIncident',
        outputs_key_field='id',
        outputs=result,
    )


def ctm360_cbs_incident_request_takedown_command(client: Client, args: dict[str, Any]) -> CommandResults:
    params = {to_snake_case(key): v for key, v in args.items()}
    log(DEBUG, f'{args=}')
    log(DEBUG, f'{params=}')
    result = client.request_takedown(params)
    msg = result.get('message')
    log(INFO, f'Request to takedown incident {args["ticketId"]} {"was " if result else "was un"}successful.')

    return CommandResults(
        readable_output=msg
    )


def ctm360_cbs_incident_close_command(client: Client, args: dict[str, Any]) -> CommandResults:
    params = {to_snake_case(key): v for key, v in args.items()}
    log(DEBUG, f'{args=}')
    log(DEBUG, f'{params=}')
    result = client.close_incident(params)
    msg = result.get('message')
    log(INFO, f'Request to close incident {args["ticketId"]} {"was " if result else "was un"}successful.')

    return CommandResults(
        readable_output=msg
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    try:

        log(DEBUG, "at main func")
        demisto_args = demisto.args()
        demisto_params = demisto.params()
        demisto_command = demisto.command()

        log(DEBUG, f'Command being called is {demisto_command}')
        log(DEBUG, f'Demisto Args are {demisto_args=}')
        log(DEBUG, f'Demisto Args are {demisto_params=}')

        client = Client(
            base_url=CBS_BASE_URL,
            verify=not demisto_params.get('insecure', False),
            headers={'api-key': demisto_params.get('api_key', {}).get('password')},
            proxy=demisto_params.get('proxy', False)
        )

        cbs_commands: dict[str, Any] = {
            'test-module': test_module,
            'get-mapping-fields': get_mapping_fields_command,
            'get-remote-data': get_remote_data_command,
            'get-modified-remote-data': get_modified_remote_data_command,
            'update-remote-system': update_remote_system_command,
            'ctm360-cbs-incident-list': ctm360_cbs_incident_list_command,
            'ctm360-cbs-incident-details': ctm360_cbs_incident_details_command,
            'ctm360-cbs-incident-request-takedown': ctm360_cbs_incident_request_takedown_command,
            'ctm360-cbs-incident-close': ctm360_cbs_incident_close_command,
        }

        if demisto_command == 'fetch-incidents':
            log(DEBUG, "at fetch command")
            last_run = demisto.getLastRun()
            last_fetched_timestamp = last_run.get('last_fetched_timestamp', '')
            last_fetch_hashes = last_run.get('last_fetch_hashes', [])
            first_fetch = demisto_params.get('first_fetch', '7 days')

            try:
                dateparser.parse(f'{first_fetch} UTC')
            except Exception:
                log(DEBUG, 'first_fetch is not parsable, setting to `7 days`')
                first_fetch = '7 days'

            if not last_fetched_timestamp:
                log(DEBUG, f'Fetch is set to fetch incidents from the {first_fetch} ago.')

            params = {
                'date_field': '@timestamp',
                'order': 'asc',
                'max_hits': MAX_FETCH,
                'date_from': last_fetched_timestamp if last_fetched_timestamp else convert_time_string(
                    f'{first_fetch} UTC', '', timestamp=True
                ),
                't': datetime.now().timestamp() * 1000
            }

            log(DEBUG, f'{demisto_params.get("date_from")=}')

            log(INFO, f'Will be fetching {MAX_FETCH} incidents.')

            log(DEBUG, f'LastRun was {last_fetched_timestamp if last_fetched_timestamp else "NOT FOUND"}')
            log(DEBUG, f'last run\'s calculated hashes were {last_run.get("last_fetch_hashes")}')

            log(DEBUG, f'Calling fetch with the following: {params=}')
            log(DEBUG, f'Mirroring set as: {MIRROR_DIRECTION}')

            next_run, incidents = fetch_incidents(client, last_fetch_hashes, params, last_run)

            log(DEBUG, 'Setting incidents and last run')
            log(DEBUG, f'{incidents=}')
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif demisto_command == 'test-module':
            return_results(test_module(client, demisto_params))
        else:
            if getfullargspec(cbs_commands[demisto_command]).args:
                return_results(cbs_commands[demisto_command](client, demisto_args))
            else:
                return_results(cbs_commands[demisto_command]())

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}', error=traceback.format_exc())


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
