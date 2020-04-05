from CommonServerPython import *
from typing import List, Dict, Tuple, Optional, Union
from datetime import datetime
import base64
import urllib3
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Disable insecure warnings
urllib3.disable_warnings()

INTEGRATION_CONTEXT_NAME = 'MSGraphCalendar'
DEFAULT_PAGE_SIZE = 100
NO_OUTPUTS: dict = {}
APP_NAME = 'ms-graph-calendar'
EVENT_HEADERS = ['Subject', 'Organizer', 'Attendees', 'Start', 'End', 'ID']
CALENDAR_HEADERS = ['Name', 'Owner Name', 'Owner Address', 'ID']


def camel_case_to_readable(cc: Union[str, Dict], fields_to_drop: List[str] = None) -> Union[str, Dict]:
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

    elif isinstance(cc, Dict):
        return {camel_case_to_readable(field): value for field, value in cc.items() if field not in fields_to_drop}
    return cc


def snakecase_to_camelcase(sc: Union[str, Dict], fields_to_drop: List[str] = None) -> Union[str, Dict]:
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

    elif isinstance(sc, Dict):
        return {snakecase_to_camelcase(field): value for field, value in sc.items() if field not in fields_to_drop}
    return sc


def parse_events(raw_events: Union[Dict, List[Dict]]) -> Tuple[List[Dict], List[Dict]]:
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
        event_readable: Dict = camel_case_to_readable(event, fields_to_drop)  # type: ignore
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


def parse_calendar(raw_calendars: Union[Dict, List[Dict]]) -> Tuple[List[Dict], List[Dict]]:
    """
    Parse Calendar json data coming from Microsoft Graph into Demisto readable format
    :param raw_calendars: raw calendars data
    """
    if not isinstance(raw_calendars, list):
        raw_calendars = [raw_calendars]

    readable_calendars, context_output = [], []
    for raw_calendar in raw_calendars:
        readable_calendar: Dict = camel_case_to_readable(raw_calendar, ['@odata.context', 'color'])  # type: ignore
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
                         attendees: str = '', location: str = '', **other_params) -> Dict:
    # some parameters don't need any processing
    event_params: Dict[str, Union[str, Dict, List[Dict]]] = other_params

    event_params['body'] = {"content": body}
    event_params['location'] = {"displayName": location}
    if start:
        event_params['start'] = {"dateTime": start, "timeZone": time_zone}
    if end:
        event_params['end'] = {"dateTime": end, "timeZone": time_zone}
    event_params['attendees'] = [{'emailAddress': {'address': attendee}} for attendee in attendees.split(',')]
    return event_params


def epoch_seconds() -> int:
    """
    Returns the number of seconds for return current date.
    """
    return int((datetime.utcnow() - datetime.utcfromtimestamp(0)).total_seconds())


def get_encrypted(content: str, key: str) -> str:
    """

    Args:
        content: content to encrypt. For a request to Demistobot for a new access token, content should be
            the tenant id
        key: encryption key from Demistobot

    Returns:
        encrypted timestamp:content
    """

    def create_nonce() -> bytes:
        return os.urandom(12)

    def encrypt(string: str, enc_key: str) -> bytes:
        """
        Args:
        :argument enc_key:
        :argument string:
        """
        # String to bytes
        enc_key = base64.b64decode(enc_key)
        # Create key
        aes_gcm = AESGCM(enc_key)
        # Create nonce
        nonce = create_nonce()
        # Create ciphered data
        data = string.encode()
        ct_ = aes_gcm.encrypt(nonce, data, None)
        return base64.b64encode(nonce + ct_)

    now = epoch_seconds()
    encrypted = encrypt(f'{now}:{content}', key).decode('utf-8')
    return encrypted


class Client(BaseClient):
    """
    Client to use in the MS Graph Groups integration. Overrides BaseClient
    """

    def __init__(self, base_url: str, tenant: str, auth_and_token_url: str, auth_id: str, token_retrieval_url: str,
                 enc_key: str, verify: bool, proxy: bool, default_user: str):
        super().__init__(base_url, verify, proxy)
        self.tenant = tenant
        self.auth_and_token_url = auth_and_token_url
        self.auth_id = auth_id
        self.token_retrieval_url = token_retrieval_url
        self.enc_key = enc_key
        self.default_user = default_user

    def get_access_token(self):
        """
        Get the Microsoft Graph Access token from the instance token or generates a new one if needed.
        """
        integration_context = demisto.getIntegrationContext()
        access_token = integration_context.get('access_token')
        valid_until = integration_context.get('valid_until')
        if access_token and valid_until:
            if epoch_seconds() < valid_until:
                return access_token
        try:
            dbot_response = requests.post(
                self.token_retrieval_url,
                headers={'Accept': 'application/json'},
                data=json.dumps({
                    'app_name': APP_NAME,
                    'registration_id': self.auth_id,
                    'encrypted_token': get_encrypted(self.tenant, self.enc_key)
                }),
                verify=self._verify
            )
        except requests.exceptions.SSLError as err:
            demisto.debug(str(err))
            raise Exception(f'Connection error in the API call to Microsoft Graph.\n'
                            f'Check your not secure parameter.\n\n{err}')
        except requests.ConnectionError as err:
            demisto.debug(str(err))
            raise Exception(f'Connection error in the API call to Microsoft Graph.\n'
                            f'Check your Server URL parameter.\n\n{err}')
        if not dbot_response.ok:
            msg = 'Error in authentication. Try checking the credentials you entered.'
            try:
                demisto.info(f'Authentication failure from server: {dbot_response.status_code}'
                             f' {dbot_response.reason} {dbot_response.text}')
                err_response = dbot_response.json()
                server_msg = err_response.get('message')
                if not server_msg:
                    title = err_response.get('title')
                    detail = err_response.get('detail')
                    if title:
                        server_msg = f'{title}. {detail}'
                if server_msg:
                    msg += f' Server message: {server_msg}'
            except Exception as err:
                demisto.error(f'Failed parsing error response - Exception: {err}')
            raise Exception(msg)
        try:
            gcloud_function_exec_id = dbot_response.headers.get('Function-Execution-Id')
            demisto.info(f'Google Cloud Function Execution ID: {gcloud_function_exec_id}')
            parsed_response = dbot_response.json()
        except ValueError:
            raise Exception(
                'There was a problem in retrieving an updated access token.\n'
                'The response from the Demistobot server did not contain the expected content.'
            )
        access_token = parsed_response.get('access_token')
        expires_in = parsed_response.get('expires_in', 3595)
        time_buffer = 5  # seconds by which to shorten the validity period
        if expires_in - time_buffer > 0:
            # err on the side of caution with a slightly shorter access token validity period
            expires_in = expires_in - time_buffer

        demisto.setIntegrationContext({
            'access_token': access_token,
            'valid_until': epoch_seconds() + expires_in
        })
        return access_token

    def http_request(self, method: str = 'GET', url_suffix: str = None, params: Dict = None, body: Optional[str] = None,
                     next_link: str = None):
        """
        Generic request to Microsoft Graph
        """
        token = self.get_access_token()
        if next_link:
            url = next_link
        else:
            url = f'{self._base_url}{url_suffix}'

        try:
            response = requests.request(
                method,
                url,
                headers={
                    'Authorization': 'Bearer ' + token,
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                params=params,
                data=body,
                verify=self._verify,
            )
        except requests.exceptions.SSLError as err:
            demisto.debug(str(err))
            raise Exception(f'Connection error in the API call to Microsoft Graph.\n'
                            f'Check your not secure parameter.\n\n{err}')
        except requests.ConnectionError as err:
            demisto.debug(str(err))
            raise Exception(f'Connection error in the API call to Microsoft Graph.\n'
                            f'Check your Server URL parameter.\n\n{err}')
        try:
            data = response.json() if response.text else {}
            if not response.ok:
                raise Exception(f'API call to MS Graph failed [{response.status_code}]'
                                f' - {demisto.get(data, "error.message")}')
            elif response.status_code == 206:  # 206 indicates Partial Content, reason will be in the warning header
                demisto.debug(str(response.headers))

            return data

        except TypeError as exc:
            demisto.debug(str(exc))
            raise Exception(f'Error in API call to Microsoft Graph, could not parse result [{response.status_code}]')

    def test_function(self):
        """
        Performs basic GET request to check if the API is reachable and authentication is successful.

        Returns ok if successful.
        """
        self.http_request('GET', 'users/')
        return 'ok', NO_OUTPUTS, NO_OUTPUTS

    def get_calendar(self, user: str, calendar_id: str = None) -> Dict:
        """Returns a single calendar by sending a GET request.

        Args:
        :argument user: the user id | userPrincipalName
        :argument calendar_id: calendar id  | name
        """
        if not user and not self.default_user:
            return_error('No user was provided. Please make sure to enter the use either in the instance setting,'
                         ' or in the command parameter.')
        calendar_raw = self.http_request(
            method='GET',
            url_suffix=f'users/{user}/calendar' + f's/{calendar_id}' if calendar_id else '')

        return calendar_raw

    def list_calendars(self, user: str, order_by: str = None, next_link: str = None, top: int = DEFAULT_PAGE_SIZE,
                       filter_by: str = None) -> Dict:
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
            calendars = self.http_request(
                url_suffix=f'users/{user}/calendars',
                next_link=next_link
            )
        elif filter_by:
            calendars = self.http_request(
                url_suffix=f'users/{user}/calendars?$filter={filter_by}&$top={top}',
                params=params
            )
        else:
            calendars = self.http_request(
                url_suffix=f'users/{user}/calendars?$top={top}',
                params=params
            )

        return calendars

    def list_events(self, user: str, calendar_id: str = '', order_by: str = None, next_link: str = None,
                    top: int = DEFAULT_PAGE_SIZE, filter_by: str = None) -> Dict:
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
            events = self.http_request(url_suffix=f'users/{calendar_url}/events', next_link=next_link)
        elif filter_by:
            events = self.http_request(url_suffix=f'users/{calendar_url}/events?$filter={filter_by}&$top={top}',
                                       params=params)
        else:
            events = self.http_request(url_suffix=f'users/{calendar_url}/events?$top={top}', params=params)
        return events

    def get_event(self, user: str, event_id: str) -> Dict:
        """
        Create a single event in a user calendar, or the default calendar of an Office 365 group.

        Args:
        :argument user: the user id | userPrincipalName
        :argument event_id: the event id
        """
        event = self.http_request('GET', url_suffix=f'users/{user}/calendar/events/{event_id}')

        return event

    def create_event(self, user: str, calendar_id: str = '', **kwargs) -> Dict:
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
            event = self.http_request(
                method='POST',
                url_suffix=f'/users/{user}/calendars/{calendar_id}/events',
                body=json.dumps(kwargs)
            )
        else:
            event = self.http_request(
                method='POST',
                url_suffix=f'users/{user}/calendar/events',
                body=json.dumps(kwargs)
            )
        return event

    def update_event(self, user: str, event_id: str, **kwargs) -> Dict:
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
        event = self.http_request(
            method='PATCH',
            url_suffix=f'users/{user}/calendar/events/{event_id}',
            body=json.dumps(kwargs)
        )
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
        self.http_request(
            method='DELETE',
            url_suffix=f'users/{user}/calendar/events/{event_id}'
        )


def list_events_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
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


def get_event_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
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


def create_event_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """
    Creates an event by event id and return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()
    """
    args = process_event_params(**args)
    params: Dict = snakecase_to_camelcase(args, fields_to_drop=['user', 'calendar_id'])  # type: ignore

    # create the event
    event = client.create_event(user=args.get('user', ''), calendar_id=args.get('calendar_id', ''), **params)

    # display the new event and it's properties
    event_readable, event_outputs = parse_events(event)
    human_readable = tableToMarkdown(
        name=f"Event was created successfully:",
        t=event_readable,
        headers=EVENT_HEADERS,
        removeNull=True
    )
    entry_context = {f'{INTEGRATION_CONTEXT_NAME}.Event(val.ID === obj.ID)': event_outputs}
    return human_readable, entry_context, event


def update_event_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """
    Get a event by event id and return outputs in Demisto's format.

    Args:
        client: Client object with request
        args: Usually demisto.args()
    """
    event_id = args.get('event_id', '')
    args = process_event_params(**args)
    params: Dict = snakecase_to_camelcase(args, fields_to_drop=['user', 'calendar_id', 'event_id'])  # type: ignore

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


def delete_event_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
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

    human_readable = f'Event was deleted successfully.'
    return human_readable, entry_context, NO_OUTPUTS


def list_calendars_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
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


def get_calendar_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
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


def module_test_function_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """
    Performs a basic GET request to check if the API is reachable and authentication is successful.

    Args:
        client: Client object with request
    """
    return client.test_function()


def main():
    url = demisto.params().get('url').rstrip('/') + '/v1.0/'
    tenant = demisto.params().get('tenant_id')
    auth_and_token_url = demisto.params().get('auth_id').split('@')
    auth_id = auth_and_token_url[0]
    enc_key = demisto.params().get('enc_key')
    verify = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    default_user = demisto.params().get('default_user')

    if len(auth_and_token_url) != 2:
        token_retrieval = 'https://oproxy.demisto.ninja/obtain-token'  # disable-secrets-detection
    else:
        token_retrieval = auth_and_token_url[1]

    commands = {
        'test-module': module_test_function_command,
        'msgraph-calendar-list-calendars': list_calendars_command,
        'msgraph-calendar-get-calendar': get_calendar_command,
        'msgraph-calendar-list-events': list_events_command,
        'msgraph-calendar-get-event': get_event_command,
        'msgraph-calendar-create-event': create_event_command,
        'msgraph-calendar-update-event': update_event_command,
        'msgraph-calendar-delete-event': delete_event_command
    }
    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        client = Client(url, tenant, auth_and_token_url, auth_id, token_retrieval, enc_key, verify, proxy, default_user)
        if 'user' not in demisto.args():
            demisto.args()['user'] = client.default_user
        # Run the command
        human_readable, entry_context, raw_response = commands[command](client, demisto.args())  # type: ignore
        # create a war room entry
        return_outputs(readable_output=human_readable, outputs=entry_context, raw_response=raw_response)

    except Exception as err:
        return_error(str(err))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
