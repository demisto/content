from CommonServerPython import *
import urllib3
from MicrosoftApiModule import *  # noqa: E402

# Disable insecure warnings
urllib3.disable_warnings()

INTEGRATION_CONTEXT_NAME = 'MSGraphCalendar'
DEFAULT_PAGE_SIZE = 100
NO_OUTPUTS: dict = {}
APP_NAME = 'ms-graph-calendar'
EVENT_HEADERS = ['Subject', 'Organizer', 'Attendees', 'Start', 'End', 'ID']
CALENDAR_HEADERS = ['Name', 'Owner Name', 'Owner Address', 'ID']


def camel_case_to_readable(cc: str | dict, fields_to_drop: list[str] = None) -> str | dict:
    """
    'camelCase' -> 'Camel Case' (text or dictionary keys)

    Args:
        cc: either a dictionary or a text to transform
        fields_to_drop: keys to drop from input dictionary

    Returns:
        A Camel Cased string of Dict.
    """
    if fields_to_drop is None:
        fields_to_drop = []
    if isinstance(cc, str):
        if cc == 'id':
            return 'ID'
        return ''.join(' ' + char if char.isupper() else char.strip() for char in cc).strip().title()

    elif isinstance(cc, dict):
        return {camel_case_to_readable(field): value for field, value in cc.items() if field not in fields_to_drop}
    return cc


def snakecase_to_camelcase(sc: str | dict, fields_to_drop: list[str] = None) -> str | dict:
    """
    'snake_case' -> 'snakeCase' (text or dictionary keys)

    Args:
        sc: either a dictionary or a text to transform
        fields_to_drop: keys to drop from input dictionary

    Returns:
        A connectedCamelCased string of Dict.
    """
    if fields_to_drop is None:
        fields_to_drop = []
    if isinstance(sc, str):
        return ''.join([word.title() for word in sc.split('_')])

    elif isinstance(sc, dict):
        return {snakecase_to_camelcase(field): value for field, value in sc.items() if field not in fields_to_drop}
    return sc


def parse_events(raw_events: dict | list[dict]) -> tuple[list[dict], list[dict]]:
    """
    Parse Calendar Events json data coming from Microsoft Graph into Demisto readable format
    :param raw_events: raw events data
    """
    # Fields to filter, dropping to not bloat the incident context.
    fields_to_drop = ['@odata.etag', 'color']
    if not isinstance(raw_events, list):
        raw_events = [raw_events]

    readable_events, context_output = [], []
    for event in raw_events:
        event_readable: dict = camel_case_to_readable(event, fields_to_drop)  # type: ignore
        if '@removed' in event:
            event_readable['Status'] = 'deleted'
        event_context = {field.replace(' ', ''): value for field, value in event_readable.items()}

        event_readable = {
            'Subject': event_readable.get('Subject'),
            'ID': event_readable.get('ID'),
            'Organizer': demisto.get(event_readable, 'Organizer.emailAddress.name'),
            'Attendees': [att.get('emailAddress', {}).get('name') for att in event_readable.get('Attendees', [])],
            'Start': event_readable.get('Start', {}).get('dateTime'),
            'End': event_readable.get('End', {}).get('dateTime')
        }
        readable_events.append(event_readable)
        context_output.append(event_context)

    return readable_events, context_output


def parse_calendar(raw_calendars: dict | list[dict]) -> tuple[list[dict], list[dict]]:
    """
    Parse Calendar json data coming from Microsoft Graph into Demisto readable format
    :param raw_calendars: raw calendars data
    """
    if not isinstance(raw_calendars, list):
        raw_calendars = [raw_calendars]

    readable_calendars, context_output = [], []
    for raw_calendar in raw_calendars:
        readable_calendar: dict = camel_case_to_readable(raw_calendar, ['@odata.context', 'color'])  # type: ignore
        if '@removed' in readable_calendar:
            readable_calendar['Status'] = 'deleted'
        context_calendar = {field.replace(' ', ''): value for field, value in readable_calendar.items()}

        readable_calendar = {
            'Name': readable_calendar.get('Name'),
            'Owner Name': readable_calendar.get('Owner', {}).get('name'),
            'Owner Address': readable_calendar.get('Owner', {}).get('address'),
            'ID': readable_calendar.get('ID')
        }
        context_output.append(context_calendar)
        readable_calendars.append(readable_calendar)

    return readable_calendars, context_output


def process_event_params(body: str = '', start: str = '', end: str = '', time_zone: str = '',
                         attendees: str = '', location: str = '', **other_params) -> dict:
    # some parameters don't need any processing
    event_params: dict[str, str | dict | list[dict]] = other_params

    event_params['body'] = {"content": body}
    event_params['location'] = {"displayName": location}
    if start:
        event_params['start'] = {"dateTime": start, "timeZone": time_zone}
    if end:
        event_params['end'] = {"dateTime": end, "timeZone": time_zone}
    event_params['attendees'] = [{'emailAddress': {'address': attendee}} for attendee in attendees.split(',')]
    return event_params


class MsGraphClient:

    def __init__(self, tenant_id, auth_id, enc_key, app_name, base_url, verify,
                 proxy, default_user, self_deployed, certificate_thumbprint, private_key,
                 managed_identities_client_id):
        self.ms_client = MicrosoftClient(tenant_id=tenant_id, auth_id=auth_id,
                                         enc_key=enc_key, app_name=app_name, base_url=base_url, verify=verify,
                                         proxy=proxy, self_deployed=self_deployed,
                                         certificate_thumbprint=certificate_thumbprint, private_key=private_key,
                                         managed_identities_client_id=managed_identities_client_id,
                                         managed_identities_resource_uri=Resources.graph,
                                         command_prefix="msgraph-calendar",
                                         )

        self.default_user = default_user

    def test_function(self):
        """
        Performs basic GET request to check if the API is reachable and authentication is successful.

        Returns ok if successful.
        """
        self.ms_client.http_request(method='GET', url_suffix='users/')
        return 'ok', NO_OUTPUTS, NO_OUTPUTS

    def get_calendar(self, user: str, calendar_id: str = None) -> dict:
        """Returns a single calendar by sending a GET request.

        Args:
        :argument user: the user id | userPrincipalName
        :argument calendar_id: calendar id  | name
        """
        if not user and not self.default_user:
            return_error('No user was provided. Please make sure to enter the use either in the instance setting,'
                         ' or in the command parameter.')
        calendar_raw = self.ms_client.http_request(
            method='GET',
            url_suffix=f'users/{user}/calendar' + f's/{calendar_id}' if calendar_id else '')

        return calendar_raw

    def list_calendars(self, user: str, order_by: str = None, next_link: str = None, top: int = DEFAULT_PAGE_SIZE,
                       filter_by: str = None) -> dict:
        """
        Lists all calendars by sending a GET request.

        Args:
        :argument user: the user id | userPrincipalName
        :argument order_by: specify the sort order of the items returned from Microsoft Graph
        :argument next_link: link for the next page of results, if exists. See Microsoft documentation for more details.
            docs.microsoft.com/en-us/graph/api/event-list?view=graph-rest-1.0
        :argument top: specify the page size of the result set.
        filter_by: filters results.
        """
        params = {'$orderby': order_by} if order_by else {}
        if next_link:  # pagination
            calendars = self.ms_client.http_request(method='GET', full_url=next_link)
        elif filter_by:
            calendars = self.ms_client.http_request(
                method='GET',
                url_suffix=f'users/{user}/calendars?$filter={filter_by}&$top={top}',
                params=params
            )
        else:
            calendars = self.ms_client.http_request(
                method='GET',
                url_suffix=f'users/{user}/calendars?$top={top}',
                params=params
            )

        return calendars

    def list_events(self, user: str, calendar_id: str = '', order_by: str = None, next_link: str = None,
                    top: int = DEFAULT_PAGE_SIZE, filter_by: str = None) -> dict:
        """
        Returns all events by sending a GET request.

        Args:
        :argument user: the user id | userPrincipalName
        :argument calendar_id: calendar id  | name
        :argument order_by: specify the sort order of the items returned from Microsoft Graph
        :argument next_link: the link for the next page of results. see Microsoft documentation for more details.
        :argument top: specify the page size of the result set.
        :argument filter_by: filters results.
        """
        calendar_url = f'{user}/calendars/{calendar_id}' if calendar_id else user
        params = {'$orderby': order_by} if order_by else {}
        if next_link:  # pagination
            events = self.ms_client.http_request(method='GET', full_url=next_link)
        elif filter_by:
            events = self.ms_client.http_request(
                method='GET',
                url_suffix=f'users/{calendar_url}/events?$filter={filter_by}&$top={top}', params=params)
        else:
            events = self.ms_client.http_request(
                method='GET',
                url_suffix=f'users/{calendar_url}/events?$top={top}',
                params=params)
        return events

    def get_event(self, user: str, event_id: str) -> dict:
        """
        Create a single event in a user calendar, or the default calendar of an Office 365 group.

        Args:
        :argument user: the user id | userPrincipalName
        :argument event_id: the event id
        """
        event = self.ms_client.http_request(method='GET', url_suffix=f'users/{user}/calendar/events/{event_id}')

        return event

    def create_event(self, user: str, calendar_id: str = '', **kwargs) -> dict:
        """
        Create a single event in a user calendar, or the default calendar of an Office 365 group.

        Args:
        :argument user: the user id | userPrincipalName
        :argument calendar_id: calendar id  | name

        Event Properties:
        :keyword attendees: The collection of attendees for the event.
        :keyword body: The body of the message associated with the event. It can be in HTML or text format.
        :keyword subject: The text of the event's subject line.
        :keyword location: The location of the event. an event as an online meeting such as a Zoom meeting. Read-only.
        :keyword end: The date, time, and time zone that the event ends. By default, the end time is in UTC.
        :keyword originalEndTimeZone: The end time zone that was set when the event was created.
        :keyword originalStart: The Timestamp type represents date and time using ISO 8601 format in UTC time.
         For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'
        :keyword originalStartTimeZone: The start time zone that was set when the event was created.
        """
        if calendar_id:
            event = self.ms_client.http_request(
                method='POST',
                url_suffix=f'/users/{user}/calendars/{calendar_id}/events',
                json_data=kwargs
            )
        else:
            event = self.ms_client.http_request(
                method='POST',
                url_suffix=f'users/{user}/calendar/events',
                json_data=kwargs
            )
        return event

    def update_event(self, user: str, event_id: str, **kwargs) -> dict:
        """
        Create a single event in a user calendar, or the default calendar of an Office 365 group.

        Args:
        :argument user: the user id | userPrincipalName
        :argument event_id: the event ID

        Event Properties:
        :keyword attendees: The collection of attendees for the event.
        :keyword body: The body of the message associated with the event. It can be in HTML or text format.
        :keyword subject:The text of the event's subject line.
        :keyword location: The location of the event.
         an event as an online meeting such as a Skype meeting. Read-only.
        :keyword end: The date, time, and time zone that the event ends. By default, the end time is in UTC.
        :keyword originalEndTimeZone: The end time zone that was set when the event was created.
        :keyword originalStart: The Timestamp type represents date and time using ISO 8601 format in UTC time.
         For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'
        :keyword originalStartTimeZone: The start time zone that was set when the event was created.
        """
        event = self.ms_client.http_request(
            method='PATCH',
            url_suffix=f'users/{user}/calendar/events/{event_id}',
            json_data=kwargs)
        return event

    def delete_event(self, user: str, event_id: str):
        """
        Delete a single event by sending a DELETE request.

        Args:
        :argument user: the user id | userPrincipalName
        :argument id: the event id
        """
        #  If successful, this method returns 204 No Content response code.
        #  It does not return anything in the response body.
        self.ms_client.http_request(
            method='DELETE',
            url_suffix=f'users/{user}/calendar/events/{event_id}',
            resp_type='text'
        )


def list_events_command(client: MsGraphClient, args: dict) -> tuple[str, dict, dict]:
    """
    Lists all events and return outputs in Demisto's format.

    Args:
        client: Client object with request
        args: Usually demisto.args()
    """
    events = client.list_events(**args)

    events_readable, events_outputs = parse_events(events.get('value'))  # type: ignore

    next_link_response = ''
    if '@odata.nextLink' in events:
        next_link_response = events['@odata.nextLink']

    if next_link_response:
        entry_context = {f'{INTEGRATION_CONTEXT_NAME}.Event(val.ID === obj.ID).NextLink': next_link_response,
                         f'{INTEGRATION_CONTEXT_NAME}.Event(val.ID === obj.ID)': events_outputs}
        title = 'Events (Note that there are more results. Please use the next_link argument to see them.):'
    else:
        entry_context = {f'{INTEGRATION_CONTEXT_NAME}.Event(val.ID === obj.ID)': events_outputs}
        title = 'Events:'

    human_readable = tableToMarkdown(
        name=title,
        t=events_readable,
        headers=EVENT_HEADERS,
        removeNull=True
    )

    return human_readable, entry_context, events


def get_event_command(client: MsGraphClient, args: dict) -> tuple[str, dict, dict]:
    """
    Retrieves an event by event id and return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()
    """
    event = client.get_event(**args)

    # display the event and it's properties
    event_readable, event_outputs = parse_events(event)
    human_readable = tableToMarkdown(
        name=f"Event - {event_outputs[0].get('Subject')}",
        t=event_readable,
        headers=EVENT_HEADERS,
        removeNull=True
    )
    entry_context = {f'{INTEGRATION_CONTEXT_NAME}.Event(val.ID === obj.ID)': event_outputs}
    return human_readable, entry_context, event


def create_event_command(client: MsGraphClient, args: dict) -> tuple[str, dict, dict]:
    """
    Creates an event by event id and return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()
    """
    args = process_event_params(**args)
    params: dict = snakecase_to_camelcase(args, fields_to_drop=['user', 'calendar_id'])  # type: ignore

    # create the event
    event = client.create_event(user=args.get('user', ''), calendar_id=args.get('calendar_id', ''), **params)

    # display the new event and it's properties
    event_readable, event_outputs = parse_events(event)
    human_readable = tableToMarkdown(
        name="Event was created successfully:",
        t=event_readable,
        headers=EVENT_HEADERS,
        removeNull=True
    )
    entry_context = {f'{INTEGRATION_CONTEXT_NAME}.Event(val.ID === obj.ID)': event_outputs}
    return human_readable, entry_context, event


def update_event_command(client: MsGraphClient, args: dict) -> tuple[str, dict, dict]:
    """
    Get a event by event id and return outputs in Demisto's format.

    Args:
        client: Client object with request
        args: Usually demisto.args()
    """
    event_id = args.get('event_id', '')
    args = process_event_params(**args)
    params: dict = snakecase_to_camelcase(args, fields_to_drop=['user', 'calendar_id', 'event_id'])  # type: ignore

    # update the event
    event = client.update_event(user=args.get('user', ''), event_id=args.get('event_id', ''), **params)

    # display the updated event and it's properties
    event_readable, event_outputs = parse_events(event)
    human_readable = tableToMarkdown(
        name="Event:",
        t=event_readable,
        headers=EVENT_HEADERS,
        removeNull=True
    )
    entry_context = {f'{INTEGRATION_CONTEXT_NAME}(obj.ID === {event_id})': event_outputs}
    return human_readable, entry_context, event


def delete_event_command(client: MsGraphClient, args: dict) -> tuple[str, dict, dict]:
    """
    Delete an event by event id and return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()
    """
    event_id = str(args.get('event_id'))
    client.delete_event(**args)

    # get the event data from the context
    event_data = demisto.dt(demisto.context(), f'{INTEGRATION_CONTEXT_NAME}.Event(val.ID === "{event_id}")')
    if isinstance(event_data, list):
        event_data = event_data[0]

    # add a field that indicates that the event was deleted
    event_data['Deleted'] = True  # add a field with the members to the event
    entry_context = {f'{INTEGRATION_CONTEXT_NAME}.Event(val.ID === obj.ID)': event_data}

    human_readable = 'Event was deleted successfully.'
    return human_readable, entry_context, NO_OUTPUTS


def list_calendars_command(client: MsGraphClient, args: dict) -> tuple[str, dict, dict]:
    """
    Get all the user's calendars (/calendars navigation property)

    Args:
        client: Client object with request
        args: Usually demisto.args()
    """
    calendar = client.list_calendars(**args)

    calendar_readable, calendar_outputs = parse_calendar(calendar.get('value'))  # type: ignore

    entry_context = {f'{INTEGRATION_CONTEXT_NAME}.Calendar(val.ID === obj.ID)': calendar_outputs}
    title = 'Calendar:'

    human_readable = tableToMarkdown(
        name=title,
        t=calendar_readable,
        headers=CALENDAR_HEADERS,
        removeNull=True
    )

    return human_readable, entry_context, calendar


def get_calendar_command(client: MsGraphClient, args: dict) -> tuple[str, dict, dict]:
    """
    Get the properties and relationships of a calendar object.
    The calendar can be one for a user, or the default calendar of an Office 365 group.

    Args:
        client: Client object with request
        args: Usually demisto.args()
    """
    calendar = client.get_calendar(**args)

    calendar_readable, calendar_outputs = parse_calendar(calendar)

    entry_context = {f'{INTEGRATION_CONTEXT_NAME}.Calendar(val.ID === obj.ID)': calendar_outputs}
    title = 'Calendar:'

    human_readable = tableToMarkdown(
        name=title,
        t=calendar_readable,
        headers=CALENDAR_HEADERS,
        removeNull=True
    )

    return human_readable, entry_context, calendar


def module_test_function_command(client: MsGraphClient, args: dict) -> tuple[str, dict, dict]:
    """
    Performs a basic GET request to check if the API is reachable and authentication is successful.

    Args:
        client: Client object with request
    """
    return client.test_function()


def main():
    params: dict = demisto.params()
    url = params.get('url', '').rstrip('/') + '/v1.0/'
    tenant = params.get('credentials_tenant_id', {}).get('password') or params.get('tenant_id')
    auth_and_token_url = params.get('credentials_auth_id', {}).get('password') or params.get('auth_id', '')
    enc_key = params.get('credentials_enc_key', {}).get('password') or params.get('enc_key')
    verify = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    default_user = params.get('default_user')
    certificate_thumbprint = params.get('credentials_certificate_thumbprint', {}).get(
        'password') or params.get('certificate_thumbprint')
    private_key = params.get('private_key')
    managed_identities_client_id = get_azure_managed_identities_client_id(params)
    self_deployed: bool = params.get('self_deployed', False) or managed_identities_client_id is not None

    if not managed_identities_client_id:
        if not self_deployed and not enc_key:
            raise DemistoException('Key must be provided. For further information see '
                                   'https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication')
        elif not enc_key and not (certificate_thumbprint and private_key):
            raise DemistoException('Key or Certificate Thumbprint and Private Key must be provided.')

    commands = {
        'test-module': module_test_function_command,
        'msgraph-calendar-list-calendars': list_calendars_command,
        'msgraph-calendar-get-calendar': get_calendar_command,
        'msgraph-calendar-list-events': list_events_command,
        'msgraph-calendar-get-event': get_event_command,
        'msgraph-calendar-create-event': create_event_command,
        'msgraph-calendar-update-event': update_event_command,
        'msgraph-calendar-delete-event': delete_event_command,
    }
    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        client: MsGraphClient = MsGraphClient(tenant_id=tenant, auth_id=auth_and_token_url, enc_key=enc_key,
                                              app_name=APP_NAME, base_url=url, verify=verify, proxy=proxy,
                                              default_user=default_user, self_deployed=self_deployed,
                                              certificate_thumbprint=certificate_thumbprint, private_key=private_key,
                                              managed_identities_client_id=managed_identities_client_id)
        if 'user' not in demisto.args():
            demisto.args()['user'] = client.default_user
        if command == 'msgraph-calendar-auth-reset':
            return_results(reset_auth())
        else:
            # Run the command
            human_readable, entry_context, raw_response = commands[command](client, demisto.args())  # type: ignore
            # create a war room entry
            return_outputs(readable_output=human_readable, outputs=entry_context, raw_response=raw_response)

    except Exception as err:
        return_error(str(err))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
