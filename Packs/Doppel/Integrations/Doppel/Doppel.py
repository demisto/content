import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import uuid
from datetime import datetime, timedelta
"""Doppel for Cortex XSOAR (aka Demisto)

This integration contains features to mirror the alerts from Doppel to create incidents in XSOAR
and the commands to perform different updates on the alerts
"""

import urllib3
from typing import Dict, Any, Optional

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
XSOAR_DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
DOPPEL_API_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S'
DOPPEL_PAYLOAD_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%f'
MIRROR_DIRECTION = {
    "None": None,
    "Incoming": "In",
    "Outgoing": "Out",
    "Incoming And Outgoing": "Both",
}
DOPPEL_ALERT = 'Doppel Alert'
DOPPEL_INCIDENT = 'Doppel Incident'

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self, base_url, api_key):
        super().__init__(base_url)
        self._headers = dict()
        self._headers["accept"] = "application/json"
        self._headers["x-api-key"] = api_key

    def get_alert(self, id: str, entity: str) -> Dict[str, str]:
        """Return the alert's details when provided the Alert ID or Entity as input

        :type id: ``str``
        :param id: Alert id for which we need to fetch details

        :type entity: ``str``
        :param entity: Alert id for which we need to fetch details

        :return: dict as with alert's details
        :rtype: ``dict``
        """
        params: dict = {}
        if id:
            params['id'] = id
        if entity:
            params['entity'] = entity

        response_content = self._http_request(
            method="GET",
            url_suffix='alert',
            params=params
        )
        return response_content

    def update_alert(
        self,
        queue_state: str,
        entity_state: str,
        alert_id: Optional[str] = None,
        entity: Optional[str] = None,
        comment: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Updates an existing alert using either the alert ID or the entity.

        :param queue_state: The queue state to update to.
        :param entity_state: The entity state to update to.
        :param alert_id: The alert ID (optional).
        :param entity: The entity (optional).
        :param comment: The comment (optional).
        :return: JSON response containing the updated alert.
        """
        if alert_id and entity:
            raise ValueError("Only one of 'alert_id' or 'entity' can be specified, not both.")
        if not alert_id and not entity:
            raise ValueError("Either 'alert_id' or 'entity' must be specified.")

        api_name = "alert"
        api_url = f"{self._base_url}/{api_name}"
        params = {}
        if alert_id is not None:
            params["id"] = alert_id
        elif entity is not None:
            params["entity"] = entity
        payload = {"queue_state": queue_state, "entity_state": entity_state, "comment": comment}

        response_content = self._http_request(
            method="PUT",  # Changed to PUT as per reference
            full_url=api_url,
            params=params,
            json_data=payload,
        )
        return response_content

    def get_alerts(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fetches multiple alerts based on query parameters.

        :param params: A dictionary of query parameters to apply to the request.
        :return: A list of dictionaries containing alert details.
        """
        api_name = "alerts"
        api_url = f"{self._base_url}/{api_name}"
        # Filter out None values
        filtered_params = {k: v for k, v in params.items() if v is not None}

        demisto.debug(f"API Request Params: {filtered_params}")

        # Use params as query parameters, not json_data
        response_content = self._http_request(
            method="GET",
            full_url=api_url,
            params=filtered_params
        )
        return response_content

    def create_alert(self, entity: str) -> Dict[str, Any]:
        api_name = "alert"
        api_url = f"{self._base_url}/{api_name}"
        response_content = self._http_request(
            method="POST",
            full_url=api_url,
            json_data={"entity": entity}
        )
        return response_content

    def create_abuse_alert(self, entity: str) -> Dict[str, Any]:

        api_name = "alert/abuse"
        api_url = f"{self._base_url}/{api_name}"
        response_content = self._http_request(
            method="POST",
            full_url=api_url,
            json_data={"entity": entity}
        )
        return response_content


''' HELPER FUNCTIONS '''


def _get_remote_updated_incident_data_with_entry(client: Client, doppel_alert_id: str, last_update_str: str):
    """
    Retrieves updated incident data from the remote system based on the given alert ID and last update timestamp.

    Args:
        client (Client):
            An instance of the Client class used to interact with the remote Doppel API.
        doppel_alert_id (str):
            The unique identifier of the alert in the remote system.
        last_update_str (str):
            A string representing the last update timestamp in ISO 8601 format (e.g., "2025-01-19T08:44:52Z").

    Returns:
        Dict[str, Any]:
            A dictionary containing the updated incident details, including entries related to the alert.
    """

    # Truncate to microseconds since Python's datetime only supports up to 6 digits
    last_update_str = last_update_str[:26] + "Z"
    last_update = datetime.strptime(last_update_str, "%Y-%m-%dT%H:%M:%S.%fZ")
    demisto.debug(f'Getting Remote Data for {doppel_alert_id} which was last updated on: {last_update}')
    updated_doppel_alert = client.get_alert(id=doppel_alert_id, entity="")
    demisto.debug(f'Received alert data for {doppel_alert_id}')
    audit_logs = updated_doppel_alert.get('audit_logs')
    demisto.debug(f'The alert contains {len(audit_logs or "")} audit logs')

    if isinstance(audit_logs, list) and all(isinstance(log, dict) for log in audit_logs):
        most_recent_audit_log = max(audit_logs, key=lambda audit_log: audit_log['timestamp'])
        demisto.debug(f'Most recent audit log is {most_recent_audit_log}')
        if isinstance(most_recent_audit_log, dict):
            recent_audit_log_datetime_str = most_recent_audit_log['timestamp']
            recent_audit_log_datetime = datetime.strptime(recent_audit_log_datetime_str, DOPPEL_PAYLOAD_DATE_FORMAT)
            demisto.debug(f'The event was modified recently on {recent_audit_log_datetime}')
            if recent_audit_log_datetime > last_update:
                updated_doppel_alert['id'] = doppel_alert_id
                entries: list = [{
                    "Type": EntryType.NOTE,
                    "Contents": most_recent_audit_log,
                    "ContentsFormat": EntryFormat.JSON,
                    "Note": True
                }]
                demisto.debug(f'Successfully returning the updated alert and entries: {updated_doppel_alert, entries}')
                return updated_doppel_alert, entries
    return None, []


def _get_mirroring_fields():
    """
    Get tickets mirroring.
    """
    mirror_direction: str = demisto.params().get('mirror_direction', 'None')
    return {
        "mirror_direction": MIRROR_DIRECTION.get(mirror_direction),
        "mirror_instance": demisto.integrationInstance(),
        "incident_type": "Doppel_Incident",
    }


def _get_last_fetch_datetime(last_run):
    # Fetch the last run (time of the last fetch)
    last_fetch_datetime: datetime = datetime.now()
    if last_run:
        last_fetch_datetime = datetime.strptime(last_run, "%Y-%m-%dT%H:%M:%SZ")
        demisto.debug(f"Alerts were fetched last on: {last_fetch_datetime}")
    else:
        # If no last run is found
        first_fetch_time = demisto.params().get('first_fetch', '3 days').strip()
        last_fetch_datetime = dateparser.parse(first_fetch_time) or datetime.now()
        assert last_fetch_datetime is not None, f'could not parse {first_fetch_time}'
        demisto.debug(f"This is the first time we are fetching the incidents. This time fetching it from: {last_fetch_datetime}")

    return last_fetch_datetime


def _paginated_call_to_get_alerts(client, page, last_fetch_datetime):
    """
    Set the query parameters
    """
    last_fetch_str: str = last_fetch_datetime.strftime(DOPPEL_API_DATE_FORMAT)
    query_params = {
        'created_after': last_fetch_str,  # Fetch alerts after the last_fetch,
        'sort_type': 'date_sourced',
        'sort_order': 'asc',
        'page': page,
    }
    get_alerts_response = client.get_alerts(params=query_params)
    alerts = get_alerts_response.get('alerts', None)
    return alerts


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.password
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    try:
        # Using the same dates so that we do not fetch any data for testing,
        # but still get the response as 200
        current_datetime_str = datetime.now().strftime(DOPPEL_API_DATE_FORMAT)
        query_params = {
            'created_before': current_datetime_str,
            'created_after': current_datetime_str
        }

        # Call the client's `get_alerts` method to test the connection
        client.get_alerts(params=query_params)
        message: str = 'ok'

    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def doppel_get_alert_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Comand to get a specific alert in the Doppel client using the provided arguments.

    :param client: Client instance to interact with the API.
    :param args: Command arguments containing the query parameters as key-value pairs.
    :return: CommandResults object including alert details.

    """

    id: str = args.get('id', "")
    entity: str = args.get('entity', "")
    if not id and not entity:
        raise ValueError('Neither id nor the entity is specified. We need exactly single input for this command')
    if id and entity:
        raise ValueError('Both id and entity is specified. We need exactly single input for this command')

    try:
        result = client.get_alert(id=id, entity=entity)
    except Exception as exception:
        raise Exception(f'No alert found with the given parameters :- {str(exception)}')

    title = 'Alert Summary'
    human_readable = tableToMarkdown(title, result, removeNull=True)
    return CommandResults(
        outputs_prefix='Doppel.Alert',
        outputs_key_field='id',
        outputs=result,
        readable_output=human_readable,
    )


def doppel_update_alert_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Executes the update alert command.

    :param client: The Client instance.
    :param args: Command arguments.
    :return: CommandResults object.
    """
    alert_id = args.get('alert_id', '')
    entity = args.get('entity', '')
    queue_state = args.get('queue_state', '')
    entity_state = args.get('entity_state', '')
    comment = args.get('comment', '')

    if alert_id and entity:
        raise ValueError("Only one of 'alert_id' or 'entity' can be specified.")

    if not any([queue_state, entity_state, comment]):
        raise ValueError("At least one of 'queue_state', 'entity_state', or 'comment' must be provided.")

    try:
        result = client.update_alert(
            queue_state=queue_state,
            entity_state=entity_state,
            alert_id=alert_id,
            entity=entity,
            comment=comment)
    except Exception as exception:
        raise Exception(f'Failed to update the alert with the given parameters :- {str(exception)}.')

    title = 'Alert Summary'
    human_readable = tableToMarkdown(title, result, removeNull=True)
    return CommandResults(
        outputs_prefix='Doppel.UpdatedAlert',
        outputs_key_field='id',
        outputs=result,
        readable_output=human_readable,
    )


def format_datetime(timestamp_str):
    """
    Formats a given timestamp string into ISO 8601 format.

    :param timestamp_str: A string representing the datetime, which may or may not be in ISO 8601 format.
    :return: A formatted datetime string in ISO 8601 format (YYYY-MM-DDTHH:MM:SS).
    """
    if not timestamp_str:
        return None  # Return None if no timestamp is provided

    try:
        # Replace 'Z' with '+00:00' to make it compatible with fromisoformat()
        if timestamp_str.endswith('Z'):
            timestamp_str = timestamp_str.replace('Z', '+00:00')

        # Attempt to parse the string in ISO 8601 format
        datetime.fromisoformat(timestamp_str)
        return timestamp_str  # Already in ISO format
    except ValueError:
        datetime_obj = arg_to_datetime(timestamp_str)
        # Convert datetime object to string
        date_str = datetime_to_string(datetime_obj)
        # Convert to datetime object
        dt_obj = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S.%f%z")
        # Convert to ISO 8601 format
        iso_format_truncated = dt_obj.isoformat(timespec='seconds')
        return iso_format_truncated


def doppel_get_alerts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command to fetch multiple alerts based on query parameters.

    :param client: Client instance to interact with the API.
    :param args: Command arguments containing the query parameters as key-value pairs.
    :return: CommandResults object with the retrieved alerts.
    """

    created_before = format_datetime(args.get('created_before'))
    created_after = format_datetime(args.get('created_after'))

    # Extract query parameters directly from arguments
    query_params = {
        'search_key': args.get('search_key'),
        'queue_state': args.get('queue_state'),
        'product': args.get('product'),
        'created_before': created_before,
        'created_after': created_after,
        'sort_type': args.get('sort_type'),
        'sort_order': args.get('sort_order'),
        'page': args.get('page'),
        'tags': argToList(args.get('tags'), separator=',', transform=None)
    }

    # Call the client's `get_alerts` method to fetch data
    demisto.debug(f"Query parameters before sending to client: {query_params}")

    try:
        results = client.get_alerts(params=query_params)
    except Exception as exception:
        raise Exception(f'No alerts were found with the given parameters :- {str(exception)}.')
    demisto.debug(f"Results received: {results}")

    title = 'Alert Summary'
    human_readable = tableToMarkdown(title, results, removeNull=True)
    return CommandResults(
        outputs_prefix='Doppel.GetAlerts',
        outputs_key_field='id',
        outputs=results,
        readable_output=human_readable,
    )


def doppel_create_alert_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Comand to create an alert in the Doppel client using the provided arguments.

    :param client: Client instance to interact with the API.
    :param args: Command arguments containing the query parameters as key-value pairs.
    :return: CommandResults object including details of the created alert.
    """

    entity = args.get('entity')
    if not entity:
        raise ValueError("Entity must be specified to create an alert.")

    try:
        result = client.create_alert(entity=entity)
    except Exception as exception:
        raise Exception(f'Failed to create the alert with the given parameters:- {str(exception)}.')

    title = 'Alert Summary'
    human_readable = tableToMarkdown(title, result, removeNull=True)
    return CommandResults(
        outputs_prefix='Doppel.CreatedAlert',
        outputs_key_field='id',
        outputs=result,
        readable_output=human_readable,
    )


def doppel_create_abuse_alert_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Comand to create an abuse alert in the Doppel client using the provided arguments.

    :param client: Client instance to interact with the API.
    :param args: Command arguments containing the query parameters as key-value pairs.
    :return: CommandResults object including details of the created abuse alert.

    """

    entity = args.get('entity')
    if not entity:
        raise ValueError("Entity must be specified to create an abuse alert.")

    try:
        result = client.create_abuse_alert(entity=entity)
    except Exception as exception:
        raise Exception(f'Failed to create the abuse alert with the given parameters:- {str(exception)}.')

    title = 'Alert Summary'
    human_readable = tableToMarkdown(title, result, removeNull=True)
    return CommandResults(
        outputs_prefix='Doppel.AbuseAlert',
        outputs_key_field='id',
        outputs=result,
        readable_output=human_readable,
    )


def fetch_incidents_command(client: Client, args: Dict[str, Any]) -> None:
    """
    Fetch incidents from Doppel alerts, map fields to custom XSOAR fields, and create incidents.
    This function fetches alerts directly from Doppel
    """
    demisto.debug("Fetching alerts from Doppel.")
    start_time = time.time()
    timeout = float(demisto.params().get('fetch_timeout'))

    # Fetch the last run (time of the last fetch)
    last_run = demisto.getLastRun()
    demisto.debug(f"Last run details:- {last_run}")

    # creates incidents queue
    incidents_queue = last_run.get('incidents_queue', [])

    last_run = last_run.get("last_run", None)
    last_fetch_datetime = _get_last_fetch_datetime(last_run)

    # Fetch alerts
    fetch_limit = int(demisto.params().get("max_fetch"))

    if len(incidents_queue) < fetch_limit:
        page: int = 0
        incidents = []
        mirroring_object = _get_mirroring_fields()
        while True:
            time_delta = time.time() - start_time

            if timeout and time_delta > timeout:
                raise DemistoException(
                    "Fetch incidents - Time out. Please change first_fetch parameter to be more recent one")

            alerts = _paginated_call_to_get_alerts(client, page, last_fetch_datetime)

            if not alerts:
                demisto.info("No new alerts fetched from Doppel. Exiting fetch_incidents.")
                break

            for alert in alerts:
                # Building the incident structure
                created_at_str = alert.get("created_at")
                created_at_datetime = datetime.strptime(created_at_str, DOPPEL_PAYLOAD_DATE_FORMAT)
                alert.update(mirroring_object)
                incident = {
                    'name': f"Doppel Incident {uuid.uuid4()}",
                    'type': DOPPEL_ALERT,
                    'occurred': created_at_datetime.strftime(XSOAR_DATE_FORMAT),
                    'dbotMirrorId': str(alert.get("id")),
                    'rawJSON': json.dumps(alert),
                }
                incidents.append(incident)

            demisto.info(f'Fetched Doppel alerts from page {page} Successfully.')
            page = page + 1
            incidents_queue += incidents

    oldest_incidents = incidents_queue[:fetch_limit]

    if oldest_incidents:
        new_last_run = incidents_queue[-1]["occurred"]  # newest incident creation time
        last_fetch_datetime = datetime.strptime(new_last_run, "%Y-%m-%dT%H:%M:%SZ")
        # Increment by one second to make sure we don't pull same Doppel Alert twice
        next_fetch_datetime = last_fetch_datetime + timedelta(seconds=1)
        next_fetch = next_fetch_datetime.strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        next_fetch = last_run
    demisto.setLastRun({'last_run': next_fetch,
                        'incidents_queue': incidents_queue[fetch_limit:]})
    demisto.debug({'last_run': next_fetch, 'incidents_queue': incidents_queue[fetch_limit:]})

    # Create incidents in XSOAR
    if oldest_incidents and len(oldest_incidents) > 0:
        try:
            demisto.incidents(oldest_incidents)
            demisto.info(f"Successfully created {len(oldest_incidents)} incidents in XSOAR.")
        except Exception as e:
            raise ValueError(f"Incident creation failed due to: {str(e)}")
    else:
        demisto.incidents([])
        demisto.info("No incidents to create. Exiting fetch_incidents_command.")


def get_modified_remote_data_command(client: Client, args: Dict[str, Any]):
    demisto.debug('Command get-modified-remote-data is not implemented')
    raise NotImplementedError('The command "get-modified-remote-data" is not implemented, \
        as Doppel does provide the API to fetch updated alerts.')


def get_remote_data_command(client: Client, args: Dict[str, Any]) -> GetRemoteDataResponse:
    try:
        remote_updated_incident_data: Dict[str, Any] = {}
        mirrored_object: Dict[str, Any] = {}
        demisto.debug(f'Calling the "get-remote-data" for {args["id"]}')
        parsed_args = GetRemoteDataArgs(args)
        remote_updated_incident_data, parsed_entries = _get_remote_updated_incident_data_with_entry(
            client, parsed_args.remote_incident_id, parsed_args.last_update)
        if remote_updated_incident_data:
            demisto.debug(f'Found updates in the alert with id: {args["id"]}')
            return GetRemoteDataResponse(remote_updated_incident_data, parsed_entries)
        else:
            demisto.debug(f'Nothing new in the incident {parsed_args.remote_incident_id}')
            return GetRemoteDataResponse(mirrored_object, entries=[{}])

    except Exception as e:
        demisto.error(f'Error while running get_remote_data_command: {e}')
        if "Rate limit exceeded" in str(e):
            return_error("API rate limit")
        if not remote_updated_incident_data:
            remote_updated_incident_data = {"id": parsed_args.remote_incident_id}
        mirrored_object['in_mirror_error'] = str(e)
        return GetRemoteDataResponse(mirrored_object, entries=[])


def update_remote_system_command(client: Client, args: Dict[str, Any]) -> str:
    """update-remote-system command: pushes local changes to the remote system

    :type client: ``Client``
    :param client: XSOAR client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['data']`` the data to send to the remote system
        ``args['entries']`` the entries to send to the remote system
        ``args['incidentChanged']`` boolean telling us if the local incident indeed changed or not
        ``args['remoteId']`` the remote incident id

    :return:
        ``str`` containing the remote incident id - really important if the incident is newly created remotely

    :rtype: ``str``
    """
    demisto.debug(f'Arguments for the update-remote-system is: {args}')
    parsed_args = UpdateRemoteSystemArgs(args)
    new_incident_id = parsed_args.remote_incident_id

    demisto.debug(f'parsed_args data :- {parsed_args}')
    demisto.debug(f'parsed_args data :- {parsed_args.data}')
    try:
        # Only update Doppel Alert if the XSOAR Incident is closed
        if parsed_args.inc_status != IncidentStatus.DONE:
            demisto.debug(f'Incident not closed. Skipping update for remote ID [{new_incident_id}].')
            return new_incident_id

        demisto.debug(f'Sending incident with remote ID [{new_incident_id}] to remote system')

        if parsed_args.remote_incident_id and parsed_args.incident_changed:
            # Fetch existing incident details to preserve versioning
            old_incident = client.get_alert(id=new_incident_id, entity="")

            # Apply changes from XSOAR to the existing incident
            old_incident.update(parsed_args.delta)  # Simplifies key-value assignment

            parsed_args.data = old_incident
        elif not parsed_args.remote_incident_id:
            parsed_args.data['createInvestigation'] = True

        # Ensure queue_state is updated to 'archived' if necessary
        if parsed_args.data.get('queue_state') != 'archived':
            client.update_alert(
                queue_state='archived',
                entity_state=parsed_args.data.get('entity_state', ''),  # Preserve old entity_state
                comment=parsed_args.data.get('notes', ''),
                alert_id=new_incident_id
            )
    except Exception as e:
        demisto.error(f"Doppel - Error in outgoing mirror for incident {new_incident_id} \n"
                      f"Error message: {str(e)}")

    return new_incident_id


def get_mapping_fields_command(client: Client, args: Dict[str, Any]) -> GetMappingFieldsResponse:
    """
    Retrieves the mapping fields for Doppel alerts in XSOAR.

    This function defines a custom mapping for Doppel alerts, adding specific fields that
    can be used for incident mirroring and enrichment in Cortex XSOAR.

    Args:
        client (Client): The API client used to communicate with Doppel.
        args (Dict[str, Any]): Command arguments (not used in this function).

    Returns:
        GetMappingFieldsResponse: The mapping response containing field definitions.
    """
    demisto.debug("Executing get_mapping_fields_command")  # Debug statement

    # Define the incident mapping scheme
    xdr_incident_type_scheme = SchemeTypeMapping(type_name=DOPPEL_ALERT)
    xdr_incident_type_scheme.add_field(name='queue_state', description='Queue State of the Doppel Alert')

    # Create the response object
    mapping_response = GetMappingFieldsResponse()
    mapping_response.add_scheme_type(xdr_incident_type_scheme)

    demisto.debug(f"Mapping fields response created: {mapping_response}")  # Debug statement
    return mapping_response




''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    api_key = demisto.params().get('credentials', {}).get('password')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/v1')

    supported_commands = {
        'test-module': test_module,
        'fetch-incidents': fetch_incidents_command,
        'get-modified-remote-data': get_modified_remote_data_command,
        'get-remote-data': get_remote_data_command,
        'update-remote-system': update_remote_system_command,
        'get-mapping-fields': get_mapping_fields_command,

        # Doppel Specific alerts
        'doppel-get-alert': doppel_get_alert_command,
        'doppel-update-alert': doppel_update_alert_command,
        'doppel-get-alerts': doppel_get_alerts_command,
        'doppel-create-alert': doppel_create_alert_command,
        'doppel-create-abuse-alert': doppel_create_abuse_alert_command,
    }
    current_command: str = demisto.command()
    demisto.info(f'Command being called is {current_command}')
    try:
        client = Client(
            base_url=base_url,
            api_key=api_key)

        if current_command in supported_commands:
            demisto.info(f'Command run successful: {current_command}')
            return_results(supported_commands[current_command](client, demisto.args()))
        else:
            demisto.error(f'Command is not implemented: {demisto.command()}')
            raise NotImplementedError(f'The {current_command} command is not supported')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {current_command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
