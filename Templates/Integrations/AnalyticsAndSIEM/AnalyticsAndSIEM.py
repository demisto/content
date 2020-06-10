import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
from typing import Dict, Tuple, List, Optional, Union, AnyStr
import urllib3

"""Example for Analytics and SIEM integration
"""
# Disable insecure warnings
urllib3.disable_warnings()

"""GLOBALS/PARAMS
Attributes:
    INTEGRATION_NAME:
        Name of the integration as shown in the integration UI, for example: Microsoft Graph User.

    INTEGRATION_COMMAND_NAME:
        Command names should be written in all lower-case letters,
        and each word separated with a hyphen, for example: msgraph-user.

    INTEGRATION_CONTEXT_NAME:
        Context output names should be written in camel case, for example: MSGraphUser.
"""
INTEGRATION_NAME = 'Analytics & SIEM Integration'
# lowercase with `-` dividers
INTEGRATION_COMMAND_NAME = 'analytics-and-siem'
# No dividers
INTEGRATION_CONTEXT_NAME = 'AnalyticsAndSIEM'


class Client(BaseClient):
    def test_module(self) -> Dict:
        """Performs basic GET request to check if the API is reachable and authentication is successful.

        Returns:
            Response json
        """
        return self._http_request('GET', 'version')

    def list_events(self, max_results: Union[int, str] = None,
                    event_created_date_after: Optional[Union[str, datetime]] = None,
                    event_created_date_before: Optional[Union[str, datetime]] = None
                    ) -> Dict:
        """Returns all events by sending a GET request.

        Args:
            max_results: The maximum number of events to return.
            event_created_date_after: Returns events created after this date.
            event_created_date_before: Returns events created before this date.

        Returns:
            Response from API. from since_time if supplied else returns all events in given limit.
        """
        # The service endpoint to request from
        suffix = 'event'
        # Dictionary of params for the request
        params = assign_params(
            sinceTime=event_created_date_after,
            fromTime=event_created_date_before,
            limit=max_results)
        # Send a request using our http_request wrapper
        return self._http_request('GET', suffix, params=params)

    def get_event(self, event_id: AnyStr) -> Dict:
        """Return an event by the event ID.

        Args:
            event_id: Event ID to get.

        Returns:
            Response JSON
        """
        # The service endpoint to request from
        suffix = 'event'
        # Dictionary of params for the request
        params = assign_params(eventId=event_id)
        # Send a request using our http_request wrapper
        return self._http_request('GET', suffix, params=params)

    def close_event(self, event_id: AnyStr) -> Dict:
        """Closes the specified event.

        Args:
            event_id: The ID of the event to close.

        Returns:
            Response JSON
        """
        # The service endpoint to request from
        suffix = 'event'
        # Dictionary of params for the request
        params = assign_params(eventId=event_id)
        # Send a request using our http_request wrapper
        return self._http_request('DELETE', suffix, params=params)

    def update_event(self, event_id: AnyStr, description: Optional[AnyStr] = None,
                     assignee: Optional[List[str]] = None) -> Dict:
        """Updates the specified event.

        Args:
            event_id: The ID of the event to update.
            assignee: A list of user IDs to assign to the event.
            description: The updated description of the event.


        Returns:
            Response JSON
        """
        # The service endpoint to request from
        suffix = 'event'
        # Dictionary of params for the request
        params = assign_params(eventId=event_id, description=description, assignee=assignee)
        # Send a request using our http_request wrapper
        return self._http_request('POST', suffix, params=params)

    def create_event(self, description: str, assignee: List[str] = None) -> Dict:
        """Creates an event in the service.

        Args:
            description: A description of the event.
            assignee: A list of user IDs to assign to the event.

        Returns:
            Response JSON
        """
        # The service endpoint to request from
        suffix = 'event'
        # Dictionary of params for the request
        params = assign_params(description=description, assignee=assignee)
        # Send a request using our http_request wrapper
        return self._http_request('POST', suffix, params=params)

    def query(self, **kwargs) -> Dict:
        """Query the specified kwargs.

        Args:
            **kwargs: The keyword argument for which to search.

        Returns:
            Response JSON
        """
        # The service endpoint to request from
        suffix = 'query'
        # Send a request using our http_request wrapper
        return self._http_request('GET', suffix, params=kwargs)


''' HELPER FUNCTIONS '''


def raw_response_to_context(events: Union[Dict, List]) -> Union[Dict, List]:
    """Formats the API response to Demisto context.

    Args:
        events: The raw response from the API call. Can be a List or Dict.

    Returns:
        The formatted Dict or List.

    Examples:
        >>> raw_response_to_context({'eventId': '1', 'description': 'event description', 'createdAt':\
        '2019-09-09T08:30:07.959533', 'isActive': True, 'assignee': [{'name': 'user1', 'id': '142'}]})
        {'ID': '1', 'Description': 'event description', 'Created': '2019-09-09T08:30:07.959533', 'IsActive': True,\
 'Assignee': [{'Name': 'user1', 'ID': '142'}]}
    """
    if isinstance(events, list):
        return [raw_response_to_context(event) for event in events]
    return {
        'ID': events.get('eventId'),
        'Description': events.get('description'),
        'Created': events.get('createdAt'),
        'IsActive': events.get('isActive'),
        'Assignee': [
            {
                'Name': user.get('name'),
                'ID': user.get('id')
            } for user in events.get('assignee', [])
        ]}


''' COMMANDS '''


@logger
def test_module_command(client: Client, *_) -> Tuple[str, None, None]:
    """Performs a basic GET request to check if the API is reachable and authentication is successful.

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        'ok' if test successful.

    Raises:
        DemistoException: If test failed.
    """
    results = client.test_module()
    if 'version' in results:
        return 'ok', None, None
    raise DemistoException(f'Test module failed, {results}')


@logger
def fetch_incidents_command(
        client: Client,
        fetch_time: str,
        last_run: Optional[str] = None) -> Tuple[List, str]:
    """Uses to fetch incidents into Demisto
    Documentation: https://github.com/demisto/content/tree/master/docs/fetching_incidents

    Args:
        client: Client object with request
        fetch_time: From when to fetch if first time, e.g. `3 days`
        last_run: Last fetch object occurs.

    Returns:
        incidents, new last_run

    Examples:
        >>> fetch_incidents_command(client, '3 days', '2010-02-01T00:00:00')
    """
    occurred_format = '%Y-%m-%dT%H:%M:%SZ'
    # Get incidents from API
    if not last_run:  # if first time running
        datetime_new_last_run, _ = parse_date_range(fetch_time, date_format=occurred_format)
    else:
        datetime_new_last_run = parse_date_string(last_run)
    new_last_run = datetime_new_last_run.strftime(occurred_format)
    incidents: List = list()
    raw_response = client.list_events(event_created_date_after=datetime_new_last_run)
    events = raw_response.get('event')
    if events:
        for event in events:
            # Creates incident entry
            occurred = event.get('createdAt')
            datetime_occurred = parse_date_string(occurred)
            incidents.append({
                'name': f"{INTEGRATION_NAME}: {event.get('eventId')}",
                'occurred': occurred,
                'rawJSON': json.dumps(event)
            })
            if datetime_occurred > datetime_new_last_run:
                new_last_run = datetime_occurred.strftime(occurred_format)
    # Return results
    return incidents, new_last_run


@logger
def list_events_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Lists all events and return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    max_results = args.get('max_results')
    event_created_date_before = args.get('event_created_date_before')
    event_created_date_after = args.get('event_created_date_after')
    raw_response = client.list_events(
        event_created_date_before=event_created_date_before,
        event_created_date_after=event_created_date_after,
        max_results=max_results)
    events = raw_response.get('event')
    if events:
        title = f'{INTEGRATION_NAME} - List events:'
        context_entry = raw_response_to_context(events)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Event(val.ID && val.ID === obj.ID)': context_entry
        }
        # Creating human readable for War room
        human_readable = tableToMarkdown(title, context_entry)
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any events.', {}, {}


@logger
def get_event_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Gets an event by event ID and return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    # Get arguments from user
    event_id = args.get('event_id', '')
    # Make request and get raw response
    raw_response = client.get_event(event_id)
    # Parse response into context & content entries
    events = raw_response.get('event')
    if events:
        event = events[0]
        title = f'{INTEGRATION_NAME} - Event `{event_id}`:'
        context_entry = raw_response_to_context(event)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Event(val.ID && val.ID === obj.ID)': context_entry
        }
        # Creating human readable for War room
        human_readable = tableToMarkdown(title, context_entry, headers=[])
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find event `{event_id}`.', {}, {}


@logger
def close_event_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Closes an event and return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    # Get arguments from user
    event_id = args.get('event_id', '')
    # Make request and get raw response
    raw_response = client.close_event(event_id)
    # Parse response into context & content entries
    events = raw_response.get('event')
    if events and events[0].get('isActive') is False:
        event = events[0]
        title = f'{INTEGRATION_NAME} - Event `{event_id}` has been deleted.'
        context_entry = raw_response_to_context(event)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Event(val.ID && val.ID === obj.ID)': context_entry
        }
        # Creating human readable for War room
        human_readable = tableToMarkdown(title, context_entry)
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        raise DemistoException(f'{INTEGRATION_NAME} - Could not close event `{event_id}`')


@logger
def update_event_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Updates an event and return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    # Get arguments from user
    event_id = args.get('event_id', '')
    description = args.get('description')
    assignee = argToList(args.get('assignee', ''))
    # Make request and get raw response
    raw_response = client.update_event(event_id, description=description, assignee=assignee)
    events = raw_response.get('event')
    # Parse response into context & content entries
    if events:
        event = events[0]
        title = f'{INTEGRATION_NAME} - Event `{event_id}` has been updated.'
        context_entry = raw_response_to_context(event)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Event(val.ID && val.ID === obj.ID)': context_entry
        }
        human_readable = tableToMarkdown(title, context_entry)
        return human_readable, context, raw_response
    else:
        raise DemistoException(f'{INTEGRATION_NAME} - Could not update event `{event_id}`')


@logger
def create_event_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Creates a new event and return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    # Get arguments from user
    description = args.get('description', '')
    assignee = argToList(demisto.args().get('assignee', ''))
    # Make request and get raw response
    raw_response = client.create_event(description, assignee)
    events = raw_response.get('event')
    # Parse response into context & content entries
    if events:
        event = events[0]
        event_id: str = event.get('eventId', '')
        title = f'{INTEGRATION_NAME} - Event `{event_id}` has been created.'
        context_entry = raw_response_to_context(event)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Event(val.ID && val.ID === obj.ID)': context_entry
        }
        human_readable = tableToMarkdown(title, context_entry)
        return human_readable, context, raw_response
    else:
        raise DemistoException(f'{INTEGRATION_NAME} - Could not create new event.')


@logger
def query_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Search for event by given args

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    # Get arguments from user
    query_dict = assign_params(
        eventId=argToList(args.get('event_id')),
        fromTime=args.get('event_created_date_after'),
        toTime=args.get('event_created_date_before'),
        assignee=argToList(args.get('assignee')),
        isActive=args.get('is_active') == 'true' if args.get('is_active') else None
    )
    # Make request and get raw response
    raw_response = client.query(**query_dict)
    events = raw_response.get('event')
    # Parse response into context & content entries
    if events:
        title = f'{INTEGRATION_NAME} - Results for given query'
        context_entry = raw_response_to_context(events)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Event(val.ID && val.ID === obj.ID)': context_entry
        }
        human_readable = tableToMarkdown(title, context_entry)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():  # pragma: no cover
    params = demisto.params()
    base_url = urljoin(params.get('url'), '/api/v2/')
    verify_ssl = not params.get('insecure', False)
    proxy = params.get('proxy')
    client = Client(base_url=base_url, verify=verify_ssl, proxy=proxy)
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    # Switch case
    commands = {
        'test-module': test_module_command,
        'fetch-incidents': fetch_incidents_command,
        f'{INTEGRATION_COMMAND_NAME}-list-events': list_events_command,
        f'{INTEGRATION_COMMAND_NAME}-get-event': get_event_command,
        f'{INTEGRATION_COMMAND_NAME}-delete-event': close_event_command,
        f'{INTEGRATION_COMMAND_NAME}-update-event': update_event_command,
        f'{INTEGRATION_COMMAND_NAME}-create-event': create_event_command,
        f'{INTEGRATION_COMMAND_NAME}-query': query_command
    }
    try:
        if command == 'fetch-incidents':
            incidents, new_last_run = fetch_incidents_command(client, last_run=demisto.getLastRun())
            demisto.incidents(incidents)
            demisto.setLastRun(new_last_run)
        elif command in commands:
            readable_output, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output, outputs, raw_response)
    # Log exceptions
    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ == 'builtins':  # pragma: no cover
    main()
