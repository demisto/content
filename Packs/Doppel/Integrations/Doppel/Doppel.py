import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

import json
from datetime import datetime, timedelta
"""Doppel for Cortex XSOAR (aka Demisto)

This integration contains features to mirror the alerts from Doppel to create incidents in XSOAR
and the commands to perform different updates on the alerts
"""

import urllib3
from typing import Dict, Any

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
        :return: JSON response containing the updated alert.
        """
        if alert_id and entity:
            raise ValueError("Only one of 'alert_id' or 'entity' can be specified, not both.")
        if not alert_id and not entity:
            raise ValueError("Either 'alert_id' or 'entity' must be specified.")

        api_name = "alert"
        api_url = f"{self._base_url}/{api_name}"
        params = {"id": alert_id} if alert_id else {"entity": entity}
        payload = {"queue_state": queue_state, "entity_state": entity_state, "comment" :comment}

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
    # Truncate to microseconds since Python's datetime only supports up to 6 digits
    last_update_str = last_update_str[:26] + "Z"
    last_update = datetime.strptime(last_update_str, "%Y-%m-%dT%H:%M:%S.%fZ")
    demisto.debug(f'Getting Remote Data for {doppel_alert_id} which was last updated on: {last_update}')
    updated_doppel_alert = client.get_alert(id=doppel_alert_id, entity=None)
    demisto.debug(f'Received alert data for {doppel_alert_id}')
    audit_logs = updated_doppel_alert['audit_logs']
    demisto.debug(f'The alert contains {len(audit_logs)} audit logs')
    
    most_recent_audit_log = max(audit_logs, key=lambda audit_log: audit_log['timestamp'])
    demisto.debug(f'Most recent audit log is {most_recent_audit_log}')
    recent_audit_log_datetime_str = most_recent_audit_log['timestamp']
    recent_audit_log_datetime = datetime.strptime(recent_audit_log_datetime_str, DOPPEL_PAYLOAD_DATE_FORMAT)
    demisto.debug(f'The event was modified recently on {recent_audit_log_datetime}')
    if recent_audit_log_datetime > last_update:
        updated_doppel_alert['id'] = doppel_alert_id
        entries: list = [{
            "Type": EntryType.NOTE,
            "Contents": most_recent_audit_log,
            "ContentsFormat": EntryFormat.JSON,
        }]
        demisto.debug(f'Successfully returning the updated alert and entries: {updated_doppel_alert, entries}')
        return updated_doppel_alert, entries
        
    return None, []

def _get_mirroring_fields():
    """
    Get tickets mirroring.
    """
    mirror_direction: str = demisto.params().get('mirror_direction', None)
    return {
        "mirror_direction": MIRROR_DIRECTION.get(mirror_direction),
        "mirror_instance": demisto.integrationInstance(),
        "incident_type": "Doppel_Incident_Test",
    }

def _get_last_fetch_datetime():
    # Fetch the last run (time of the last fetch)
    last_run = demisto.getLastRun()
    last_fetch = last_run.get("last_fetch", None)
    last_fetch_datetime: datetime = datetime.now()
    if last_fetch and isinstance(last_fetch, float):
        last_fetch_datetime = datetime.fromtimestamp(last_fetch)
        demisto.debug(f"Alerts were fetch last on: {last_fetch_datetime}")  
    else:
        # If no last run is found
        historical_days: int = 1
        historical_days_str: str = demisto.params().get('historical_days', None)
        if historical_days_str:
            try:
                historical_days = int(historical_days_str)
            except ValueError:
                demisto.error(f'{historical_days} is not an int value. We will use the default historical value as {historical_days} day')
        demisto.info(f'Fetching alerts created in last {historical_days} days')
        last_fetch_datetime = datetime.now() - timedelta(days=historical_days)
        demisto.debug(f"This is the first time we are fetching the incidents. This time fetching it from: {last_fetch_datetime}")
        
    return last_fetch_datetime

def _paginated_call_to_get_alerts(client, page, last_fetch_datetime):
    # Set the query parameters
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


def test_module(client: Client, args: Dict[str, Any]) -> str:
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
        results = client.get_alerts(params=query_params)
        message: str = 'ok'

    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message

def doppel_get_alert_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    id: str = args.get('id', None)
    entity: str = args.get('entity', None)
    if not id and not entity:
        raise ValueError('Neither id nor the entity is specified. We need exactly single input for this command')
    if id and entity:
        raise ValueError('Both id and entity is specified. We need exactly single input for this command')
    
    result = client.get_alert(id=id, entity=entity)

    return CommandResults(
        outputs_prefix='Doppel.Alert',
        outputs_key_field='id',
        outputs=result,
    )

def doppel_update_alert_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Executes the update alert command.

    :param client: The Client instance.
    :param args: Command arguments.
    :return: CommandResults object.
    """
    alert_id = args.get('alert_id')
    entity = args.get('entity')
    queue_state = args.get('queue_state')
    entity_state = args.get('entity_state')
    comment = args.get('comment')

    if alert_id and entity:
        raise ValueError("Only one of 'alert_id' or 'entity' can be specified.")
    if not queue_state or not entity_state:
        raise ValueError("Both 'queue_state' and 'entity_state' must be specified.")

    result = client.update_alert(queue_state=queue_state, entity_state=entity_state, alert_id=alert_id, entity=entity , comment=comment)

    return CommandResults(
        outputs_prefix='Doppel.UpdatedAlert',
        outputs_key_field='id',
        outputs=result,
    )

def doppel_get_alerts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command to fetch multiple alerts based on query parameters.

    :param client: Client instance to interact with the API.
    :param args: Command arguments containing the query parameters as key-value pairs.
    :return: CommandResults object with the retrieved alerts.
    """

    # Extract query parameters directly from arguments
    query_params = {
        'search_key': args.get('search_key'),
        'queue_state': args.get('queue_state'),
        'product': args.get('product'),
        'created_before': args.get('created_before'),
        'created_after': args.get('created_after'),
        'sort_type': args.get('sort_type'),
        'sort_order': args.get('sort_order'),
        'page': args.get('page'),
        'tags': args.get('tags')
    }

    # Call the client's `get_alerts` method to fetch data
    demisto.debug(f"Query parameters before sending to client: {query_params}")
    results = client.get_alerts(params=query_params)
    demisto.debug(f"Results received: {results}")

    # Handle empty alerts response
    if not results:
        raise ValueError("No alerts were found with the given parameters.")

def doppel_create_alert_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    entity = args.get('entity')
    if not entity:
        raise ValueError("Entity must be specified to create an alert.")

    result = client.create_alert(entity=entity)

    return CommandResults(
        outputs_prefix='Doppel.CreatedAlert',
        outputs_key_field='id',
        outputs=result,
    )

def doppel_create_abuse_alert_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    entity = args.get('entity')
    if not entity:
        raise ValueError("Entity must be specified to create an abuse alert.")

    result = client.create_abuse_alert(entity=entity)

    return CommandResults(
        outputs_prefix='Doppel.AbuseAlert',
        outputs_key_field='id',
        outputs=result,
    )

def fetch_incidents_command(client: Client, args: Dict[str, Any]) -> None:
    """
    Fetch incidents from Doppel alerts, map fields to custom XSOAR fields, and create incidents.
    This function fetches alerts directly from Doppel
    """
    demisto.debug("Fetching alerts from Doppel.")
    # Fetch the last run (time of the last fetch)
    last_fetch_datetime: datetime = _get_last_fetch_datetime()
    
    # Fetch alerts
    page: int = 0
    incidents = []
    while True:
        alerts = _paginated_call_to_get_alerts(client, page, last_fetch_datetime)
        if not alerts:
            demisto.info("No new alerts fetched from Doppel. Exiting fetch_incidents.")
            break
        last_fetch = last_fetch_datetime.timestamp()
        new_last_fetch = last_fetch  # Initialize with the existing last fetch timestamp
        for alert in alerts:
            # Building the incident structure
            created_at_str = alert.get("created_at")
            created_at_datetime = datetime.strptime(created_at_str, DOPPEL_PAYLOAD_DATE_FORMAT)
            new_last_fetch = created_at_datetime.timestamp()
            if new_last_fetch > last_fetch:
                alert.update(_get_mirroring_fields())
                incident = {
                    'name': DOPPEL_INCIDENT,
                    'type': DOPPEL_ALERT,
                    'occurred': created_at_datetime.strftime(XSOAR_DATE_FORMAT),
                    'dbotMirrorId': str(alert.get("id")),
                    'rawJSON': json.dumps(alert),
                }
                incidents.append(incident)
        # Update last run with the new_last_fetch value
        demisto.setLastRun({"last_fetch": new_last_fetch})
        demisto.debug(f"Updated last_fetch to: {new_last_fetch}")
        demisto.info(f'Fetched Doppel alerts from page {page} Successfully.')
        page = page+1
    # Create incidents in XSOAR
    if incidents and len(incidents) > 0:
        try:
            demisto.incidents(incidents)
            demisto.info(f"Successfully created {len(incidents)} incidents in XSOAR.")
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
        demisto.debug(f'Calling the "get-remote-data" for {args["id"]}')
        parsed_args = GetRemoteDataArgs(args)
        remote_updated_incident_data, parsed_entries = _get_remote_updated_incident_data_with_entry(client, parsed_args.remote_incident_id, parsed_args.last_update)
        if remote_updated_incident_data:
            demisto.debug(f'Found updates in the alert with id: {args["id"]}')
            return GetRemoteDataResponse(remote_updated_incident_data, parsed_entries)
        else:
            demisto.debug(f'Nothing new in the incident {parsed_args.remote_incident_id}')
            return GetRemoteDataResponse(mirrored_object={}, entries=[{}])
      
    except Exception as e:
        demisto.error(f'Error while running get_remote_data_command: {e}')
        if "Rate limit exceeded" in str(e):
            return_error("API rate limit")
          
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
    new_incident_id: str = parsed_args.remote_incident_id
    # We will Update the Doppel Alert only if the XSOAR Incident is closed
    if parsed_args.delta and parsed_args.delta.get('closeReason'):
        demisto.debug(f'Sending incident with remote ID [{parsed_args.remote_incident_id}] to remote system')
        if not parsed_args.remote_incident_id or parsed_args.incident_changed:
            if parsed_args.remote_incident_id:
                # First, get the incident as we need the version
                old_incident = client.get_alert(id=parsed_args.remote_incident_id, entity=None)
                for changed_key in parsed_args.delta.keys():
                    old_incident[changed_key] = parsed_args.delta[changed_key]  # type: ignore
                parsed_args.data = old_incident
            else:
                parsed_args.data['createInvestigation'] = True

            # Update the queue_state value in the Doppel alert, if already not same
            current_queue_state = parsed_args.data.get('queue_state')
            target_queue_state = 'archived'
            if current_queue_state != target_queue_state:
                client.update_alert(
                    queue_state=target_queue_state,
                    entity_state=old_incident['entity_state'], # Keep the old entity_state
                    alert_id=new_incident_id
                )
        else:
            demisto.debug(f'Skipping updating remote incident fields [{parsed_args.remote_incident_id}] as it is '
                        f'not new nor changed.')
    else:
        demisto.debug(f'The incident changed, but it is not closed. Hence will not update the Doppel alert at this time')
        
    return new_incident_id

def get_mapping_fields_command(client: Client, args: Dict[str, Any]):
    xdr_incident_type_scheme = SchemeTypeMapping(type_name=DOPPEL_ALERT)
    xdr_incident_type_scheme.add_field(name='queue_state', description='Queue State of the Doppel Alert')
    return GetMappingFieldsResponse(xdr_incident_type_scheme)


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
        'get-modified-remote-data:': get_modified_remote_data_command,
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
    
    demisto.info(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            api_key=api_key)

        current_command: str = demisto.command()
        if current_command in supported_commands:
            demisto.info(f'Command run successful: {demisto.command()}')
            return_results(supported_commands[current_command](client, demisto.args()))
        else:
            demisto.error(f'Command is not implemented: {demisto.command()}')
            raise NotImplementedError(f'The {current_command} command is not supported')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()