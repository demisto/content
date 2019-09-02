import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
from typing import Dict, Tuple, List, Optional, Union, AnyStr
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    """
    Wrapper class for BaseClient with added functionality for the integration.
    """
    def test_module(self) -> bool:
        """Performs basic get request to get item samples

        Returns:
            True if request succeeded
        """
        self._http_request('GET', 'version')
        return True

    def list_events_request(self, limit: Union[int, AnyStr] = None, since_time: Optional[str] = None) -> Dict:
        """Gets all credentials from API.
        Args:
            limit: limit results
            since_time: timestamp to start pull events from
        Returns:
            events from sinceTime
        """
        suffix: str = 'event'
        params = dict()
        if since_time:
            params['sinceTime'] = since_time
        if limit:
            params['limit'] = limit
        return self._http_request('GET', suffix, params=params)

    def get_event_request(self, event_id: AnyStr) -> Dict:
        """Gets events from given ID

        Args:
            event_id: event id to get

        Returns:
            event details
        """
        # The service endpoint to request from
        suffix: str = 'event'
        # Dictionary of params for the request
        params = {
            'eventId': event_id
        }
        return self._http_request('GET', suffix, params=params)

    def close_event_request(self, event_id: AnyStr) -> Dict:
        """Gets events from given ID

        Args:
            event_id: event to delete

        Returns:
            response json
        """
        # The service endpoint to request from
        suffix = 'event'
        # Dictionary of params for the request
        params = {
            'eventId': event_id
        }
        # Send a request using our http_request wrapper
        return self._http_request('DELETE', suffix, params=params)

    def update_event_request(self, event_id: AnyStr, description: Optional[AnyStr] = None,
                             assignee: Optional[List[str]] = None) -> Dict:
        """Update given event

        Args:
            description: change description of event
            assignee: User to assign event to
            event_id: event ID

        Returns:
            response json
        """
        suffix = 'event'
        params: Dict[str, Union[List, AnyStr]] = {
            'eventId': event_id,
        }

        if description:
            params['description'] = description
        if assignee:
            params['assignee'] = assignee

        return self._http_request('POST', suffix, params=params)

    def create_event_request(self, description: str, assignee: List[str] = None) -> Dict:
        """Update given event

        Args:
            description: change description of event
            assignee: User to assign event to

        Returns:
            requests.Response
        """
        suffix = 'event'
        params = {
            'description': description,
            'assignee': assignee
        }

        return self._http_request('POST', suffix, params=params)

    def query_request(self, **kwargs):
        suffix = 'query'
        return self._http_request('GET', suffix, params=kwargs)


''' HELPER FUNCTIONS '''


def built_context(events: Union[Dict, List]) -> Union[Dict, List]:
    def build_dict(event: Dict) -> Dict:
        return {
            'ID': event.get('eventId'),
            'Description': event.get('description'),
            'Created': event.get('createdAt'),
            'IsActive': event.get('isActive'),
            'Assignee': [
                {
                    'Name': user.get('name'),
                    'ID': user.get('id')
                } for user in event.get('assignee', [])
            ]
        }

    if isinstance(events, list):
        return [build_dict(event) for event in events]
    return build_dict(events)


''' COMMANDS '''


def test_module(client: Client) -> str:
    """
    Performs basic get request to get item samples
    """
    if client.test_module():
        return 'ok'
    raise DemistoException('Test module failed')


def fetch_incidents(client: Client):
    """Uses to fetch credentials into Demisto
    Documentation: https://github.com/demisto/content/tree/master/docs/fetching_credentials
    """
    timestamp_format = '%Y-%m-%dT%H:%M:%S.%fZ"'
    # Get credentials from api
    last_run = demisto.getLastRun()
    if not last_run:  # if first time running
        last_run, _ = parse_date_range(demisto.params().get('fetch_time'))
        last_run_string = last_run.strftime(timestamp_format)
    else:
        last_run_string = datetime.strptime(last_run, timestamp_format)
    incidents: List[Dict] = list()
    raw_response = client.list_events_request(since_time=last_run_string)
    events: List[Dict] = raw_response.get('incidents', [])
    if events:
        # Creates incident entry
        incidents = [{
            'name': event.get('title'),
            'occurred': event.get('created'),
            'rawJSON': json.dumps(event)
        } for event in events]

        last_incident_timestamp = incidents[-1].get('occurred')
        demisto.setLastRun(last_incident_timestamp)
    demisto.incidents(incidents)


def list_events(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    limit: Optional[str] = args.get('limit')
    raw_response = client.list_events_request(limit=limit)
    events: List[Dict] = raw_response.get('incidents', [])
    if events:
        title: str = f'{client.get_integration_name()} - List events:'
        context_entry = built_context(events)
        context = {f'{client.get_integration_context()}.Event(val.ID && val.ID === obj.ID)': context_entry}
        # Creating human readable for War room
        human_readable = tableToMarkdown(title, context_entry)
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        raise DemistoException(f'{client.get_integration_name()} - Could not find any events.')


def get_event(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """
    Gets details about a raw_response using ID or some other filters
    """
    # Get arguments from user
    event_id: str = args.get('event_id', '')
    # Make request and get raw response
    raw_response: Dict = client.get_event_request(event_id)
    # Parse response into context & content entries
    event: Dict = raw_response.get('event', {})
    if event:
        title: str = f'{client.get_integration_name()} - Event `{event_id}`:'
        context_entry = built_context(event)
        context = {f'{client.get_integration_context()}.Event(val.ID && val.ID === obj.ID)': context_entry}
        # Creating human readable for War room
        human_readable = tableToMarkdown(title, context_entry)
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        raise DemistoException(f'{client.get_integration_name()} - Could not find event `{event_id}`')


def close_event(client: Client, args: Dict) -> Tuple[str, Dict, None]:
    """
    Gets details about a raw_response using ID or some other filters
    """
    # Get arguments from user
    event_id: str = args.get('event_id', '')
    # Make request and get raw response
    event = client.close_event_request(event_id)
    # Parse response into context & content entries
    if event:
        title = f'{client.get_integration_name()} - Event `{event_id}` has been deleted.'
        context_entry = built_context(event)
        context = {f'{client.get_integration_context()}.Event(val.ID && val.ID === obj.ID)': context_entry}
        # Creating human readable for War room
        human_readable: str = tableToMarkdown(title, context_entry)
        # Return data to Demisto
        return human_readable, context, None
    else:
        raise DemistoException(f'{client.get_integration_name()} - Could not delete event `{event_id}`')


def update_event(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    event_id: str = args.get('event_id', '')
    description: str = args.get('description', '')
    assignee: List[str] = argToList(args.get('assignee', ''))
    raw_response = client.update_event_request(event_id, description=description, assignee=assignee)
    event = raw_response.get('event')
    if event:
        title: str = f'{client.get_integration_name()} - Event `{event_id}` has been updated.'
        context_entry = built_context(event)
        context = {f'{client.get_integration_context()}.Event(val.ID && val.ID === obj.ID)': context_entry}
        human_readable = tableToMarkdown(title, context_entry)
        return human_readable, context, raw_response
    else:
        raise DemistoException(f'{client.get_integration_name()} - Could not update event `{event_id}`')


def create_event(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    description: str = args.get('description', '')
    assignee: List[str] = argToList(demisto.args().get('assignee', ''))
    raw_response: Dict = client.create_event_request(description, assignee)
    event: Dict = raw_response.get('event', {})
    if event:
        event_id: str = event.get('eventId', '')
        title = f'{client.get_integration_name()} - Event `{event_id}` has been created.'
        context_entry = built_context(event)
        context = {f'{client.get_integration_context()}.Event(val.ID && val.ID === obj.ID)': context_entry}
        human_readable = tableToMarkdown(title, context_entry)
        return human_readable, context, raw_response
    else:
        raise DemistoException(f'{client.get_integration_name()} - Could not create new event.')


def query(client: Client, args: Dict):
    query_dict = {
        'eventId': args.get('event_id'),
        'sinceTime': args.get('since_time'),
        'assignee': argToList(args.get('assignee')),
        'isActive': args.get('is_active') == 'true'
    }
    # Remove None/empty object
    query_dict = {key: value for key, value in query_dict.items() if vault is not None}
    if not query_dict.get('assignee'):
        del query_dict['assignee']
    raw_response: Dict = client.query_request(**query_dict)
    events: List = raw_response.get('event', [])
    if events:
        title = f'{client.get_integration_name()} - Results for given query'
        context_entry = built_context(events)
        context = {f'{client.get_integration_context()}.Event(val.ID && val.ID === obj.ID)': context_entry}
        human_readable: str = tableToMarkdown(title, context_entry)
        return human_readable, context, raw_response
    else:
        return_warning(f'{client.get_integration_name()} - Could not find any results for given query')


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    """ GLOBALS/PARAMS """
    integration_name = 'Analytics & SIEM Integration'
    # lowercase with `-` dividers
    integration_name_command = 'analytics-and-siem'
    # No dividers
    integration_name_context = 'AnalyticsAndSIEM'
    server: str = demisto.params().get('url', '')
    verify_ssl: bool = not demisto.params().get('insecure', False)
    proxy: Optional[bool] = demisto.params().get('proxy')
    base_suffix = '/api/v2/'
    client: Client = Client(server,
                            integration_name=integration_name,
                            integration_name_command=integration_name_command,
                            integration_name_context=integration_name_context,
                            base_suffix=base_suffix,
                            verify=verify_ssl,
                            proxy=proxy)
    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    # Switch case
    commands = {
        'test-module': test_module,
        'fetch-incidents': fetch_incidents,
        f'{integration_name_command}-list-events': list_events,
        f'{integration_name_command}-get-event': get_event,
        f'{integration_name_command}-delete-event': close_event,
        f'{integration_name_command}-update-event': update_event,
        f'{integration_name_command}-create-event': create_event,
        f'{integration_name_command}-query': query
    }
    try:
        if command in commands:
            human_readable, context, raw_response = commands[command](client, demisto.args())
            return_outputs(human_readable, context, raw_response)
    # Log exceptions
    except Exception as e:
        err_msg = f'Error in AuthenticationExample Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ == '__builtin__':
    main()

# TODO: add pip file
# Threahold
#
