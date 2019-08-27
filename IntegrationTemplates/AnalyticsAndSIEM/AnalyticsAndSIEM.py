import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
from typing import cast, Any, Dict, Tuple, List, AnyStr, Optional
from xml.etree import ElementTree

import requests
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
INTEGRATION_NAME: str = 'Analytics & SIEM Integration'
# lowercase with `-` dividers
INTEGRATION_NAME_COMMAND: str = 'analytics-and-siem'
# No dividers
INTEGRATION_NAME_CONTEXT: str = 'AnalyticsAndSIEM'


class Client:
    def __init__(self, server: str, use_ssl: bool, fetch_time: Optional[str] = None):
        self._server: str = server.rstrip(chars='/')
        self._use_ssl: bool = use_ssl
        self._fetch_time: Optional[str] = fetch_time
        self._base_url: str = self._server + '/api/v2.0/'

    def _http_request(self, method: str, url_suffix: str, full_url: str = None, headers: Dict = None,
                      auth: Tuple = None, params: Dict = None, data: Dict = None, files: Dict = None,
                      timeout: float = 10, resp_type: str = 'json') -> Any:
        """A wrapper for requests lib to send our requests and handle requests
        and responses better

        Args:
            method:
                HTTP method, e.g. 'GET', 'POST' ... etc.
            url_suffix:
                API endpoint.
            full_url:
                Bypasses the use of BASE_URL + url_suffix. Useful if there is a need to
                make a request to an address outside of the scope of the integration
                API.
            headers:
                Headers to send in the request.
            auth:
                Auth tuple to enable Basic/Digest/Custom HTTP Auth.
            params:
                URL parameters.
            data:
                Data to be sent in a 'POST' request.
            files:
                File data to be sent in a 'POST' request.
            timeout:
                The amount of time in seconds a Request will wait for a client to
                establish a connection to a remote machine.
            resp_type:
                Determines what to return from having made the HTTP request. The default
                is 'json'. Other options are 'text', 'content' or 'response' if the user
                would like the full response object returned.

        Returns:
                Response JSON from having made the request.
        """
        try:
            address = full_url if full_url else self._base_url + url_suffix
            res = requests.request(
                method,
                address,
                verify=self._use_ssl,
                params=params,
                data=data,
                files=files,
                headers=headers,
                auth=auth,
                timeout=timeout
            )

            # Handle error responses gracefully
            if res.status_code not in (200, 201):
                err_msg = f'Error in {INTEGRATION_NAME} API call [{res.status_code}] - {res.reason}'
                try:
                    # Try to parse json error response
                    res_json = res.json()
                    message = res_json.get('message')
                    return_error(message)
                except json.decoder.JSONDecodeError:
                    if res.status_code in (400, 401, 501):
                        # Try to parse xml error response
                        resp_xml = ElementTree.fromstring(res.content)
                        codes = [child.text for child in resp_xml.iter() if child.tag == 'CODE']
                        messages = [child.text for child in resp_xml.iter() if child.tag == 'MESSAGE']
                        err_msg += ''.join([f'\n{code}: {msg}' for code, msg in zip(codes, messages)])
                    return_error(err_msg)

            resp_type = resp_type.casefold()
            try:
                if resp_type == 'json':
                    return res.json()
                elif resp_type == 'text':
                    return res.text
                elif resp_type == 'content':
                    return res.content
                else:
                    return res
            except json.decoder.JSONDecodeError:
                return_error(f'Failed to parse json object from response: {res.content}')

        except requests.exceptions.ConnectTimeout:
            err_msg = 'Connection Timeout Error - potential reasons may be that the Server URL parameter' \
                      ' is incorrect or that the Server is not accessible from your host.'
            return_error(err_msg)
        except requests.exceptions.SSLError:
            err_msg = 'SSL Certificate Verification Failed - try selecting \'Trust any certificate\' in' \
                      ' the integration configuration.'
            return_error(err_msg)
        except requests.exceptions.ProxyError:
            err_msg = 'Proxy Error - if \'Use system proxy\' in the integration configuration has been' \
                      ' selected, try deselecting it.'
            return_error(err_msg)
        except requests.exceptions.ConnectionError as e:
            # Get originating Exception in Exception chain
            while '__context__' in dir(e) and e.__context__:
                e = cast(Any, e.__context__)

            error_class = str(e.__class__)
            err_type = '<' + error_class[error_class.find('\'') + 1: error_class.rfind('\'')] + '>'
            err_msg = f'\nError Type: {err_type}\nError Number: [{e.errno}]\nMessage: {e.strerror}\n' \
                      f'Verify that the server URL parameter' \
                      f' is correct and that you have access to the server from your host.'
            return_error(err_msg)

    def get_last_fetch(self):
        return self._fetch_time

    def test_module(self) -> bool:
        """Performs basic get request to get item samples

        Returns:
            True if request succeeded
        """
        self._http_request('GET', 'version')
        return True

    def fetch_incidents(self, timestamp: datetime) -> Dict:
        """Gets all credentials from API.
        Args:
            timestamp: timestamp to start pull events from
        Returns:
            events from sinceTime
        """
        time_format: str = '%Y-%m-%dT%H:%M:%S.%fZ"'
        suffix: str = 'event'
        timestamp_str = timestamp.strftime(time_format)
        params = {
            'sinceTime': timestamp_str
        }
        return self._http_request('GET', suffix, params=params)

    def get_event_request(self, event_id: AnyStr) -> Dict:
        """Gets events from given IDS

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

    def close_event_request(self, event_id: AnyStr) -> requests.Response:
        """Gets events from given IDS

        Args:
            event_id: event to delete

        Returns:
            response json
        """
        # The service endpoint to request from
        suffix: str = 'event'
        # Dictionary of params for the request
        params = {
            'eventId': event_id
        }
        # Send a request using our http_request wrapper
        return self._http_request('DELETE', suffix, params=params, resp_type='response')

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
        suffix: str = 'event'
        params = {
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
        suffix: str = 'query'
        return self._http_request('GET', suffix, params=kwargs)


''' HELPER FUNCTIONS '''

''' COMMANDS '''


def test_module(client: Client):
    """
    Performs basic get request to get item samples
    """
    if client.test_module():
        demisto.results('ok')


def fetch_incidents(client: Client):
    """Uses to fetch credentials into Demisto
    Documentation: https://github.com/demisto/content/tree/master/docs/fetching_credentials
    """
    # Get credentials from api
    last_run = demisto.getLastRun()
    if not last_run:  # if first time running
        last_run, _ = parse_date_range(client.get_last_fetch())
    raw_response: Dict = client.fetch_incidents(last_run)
    events: List[Dict] = raw_response.get('incidents', [])
    if events:
        # Creates incident entry
        incidents = [{
            'name': event.get('title'),
            'occurred': event.get('created'),
            'rawJSON': json.dumps(event)
        } for event in events]
        demisto.setLastRun(datetime.now())
        demisto.incidents(incidents)


def get_event(client: Client):
    """
    Gets details about a raw_response using IDs or some other filters
    """
    # Initialize main vars
    context: Dict = dict()
    # Get arguments from user
    event_id: str = demisto.args().get('event_id', '')
    # Make request and get raw response
    raw_response: Dict = client.get_event_request(event_id)
    # Parse response into context & content entries
    event: Dict = raw_response.get('event', {})
    if event:
        title: str = f'{INTEGRATION_NAME} - Event `{event_id}`:'
        context_entry = {
            'ID': event_id,
            'Description': event.get('description'),
            'Created': event.get('createdAt'),
            'IsActive': event.get('isActive'),
            'Assignee': event.get('assignee')
        }
        context[f'{INTEGRATION_NAME_CONTEXT}.Event(val.ID && val.ID === obj.ID)'] = context_entry
        # Creating human readable for War room
        human_readable: str = tableToMarkdown(title, context_entry)
        # Return data to Demisto
        return_outputs(human_readable, context, raw_response)
    else:
        return_error(f'{INTEGRATION_NAME} - Could not find event `{event_id}`')


def close_event(client: Client):
    """
    Gets details about a raw_response using IDs or some other filters
    """
    # Initialize main vars
    context: Dict = dict()
    # Get arguments from user
    event_id: str = demisto.args().get('event_id', '')
    # Make request and get raw response
    response: requests.Response = client.close_event_request(event_id)
    # Parse response into context & content entries
    if response.status_code == 200:
        title: str = f'{INTEGRATION_NAME} - Event `{event_id}` has been deleted.'
        context_entry = {
            'ID': event_id,
            'IsActive': False
        }

        context[f'{INTEGRATION_NAME_CONTEXT}.Event(val.ID && val.ID === obj.ID)'] = context_entry
        # Creating human readable for War room
        human_readable: str = tableToMarkdown(title, context_entry)
        # Return data to Demisto
        return_outputs(human_readable, context)
    else:
        return_error(f'{INTEGRATION_NAME} - Could not delete event `{event_id}`')


def update_event(client: Client):
    event_id: str = demisto.args().get('event_id', '')
    description: str = demisto.args().get('description', '')
    assignee: List[str] = argToList(demisto.args().get('assignee', ''))
    raw_response = client.update_event_request(event_id, description=description, assignee=assignee)
    event = raw_response.get('event')
    if event:
        title: str = f'{INTEGRATION_NAME} - Event `{event_id}` has been updated.'
        context_entry = {
            'ID': event_id,
            'Description': event.get('description'),
            'Created': event.get('createdAt'),
            'IsActive': event.get('isActive'),
            'Assignee': event.get('assignee')
        }
        context = {
            f'{INTEGRATION_NAME_CONTEXT}.Event(val.ID && val.ID === obj.ID)': context_entry
        }
        human_readable = tableToMarkdown(title, context_entry)
        return_outputs(human_readable, context, raw_response)
    else:
        return_error(f'{INTEGRATION_NAME} - Could not update event `{event_id}`')


def create_event(client: Client):
    description: str = demisto.args().get('description', '')
    assignee: List[str] = argToList(demisto.args().get('assignee', ''))
    raw_response: Dict = client.create_event_request(description, assignee)
    event: Dict = raw_response.get('event', {})
    if event:
        event_id: str = event.get('eventId', '')
        title: str = f'{INTEGRATION_NAME} - Event `{event_id}` has been created.'
        context_entry = {
            'ID': event_id,
            'Description': event.get('description'),
            'Created': event.get('createdAt'),
            'IsActive': event.get('isActive'),
            'Assignee': event.get('assignee')
        }
        context = {
            f'{INTEGRATION_NAME_CONTEXT}.Event(val.ID && val.ID === obj.ID)': context_entry
        }
        human_readable = tableToMarkdown(title, context_entry)
        return_outputs(human_readable, context, raw_response)
    else:
        return_error(f'{INTEGRATION_NAME} - Could not create new event.')


def query(client: Client):
    query_dict: Dict = {
        'eventId': demisto.args().get('event_id', ''),
        'sinceTime': demisto.args().get('since_time', ''),
        'assignee': argToList(demisto.args().get('assignee')),
        'isActive': demisto.args().get('is_active') == 'true'
    }
    # filter dictionary
    query_dict = {key: value for key, value in query_dict.items() if vault is not None}
    if not query_dict.get('assignee'):
        del query_dict['assignee']
    raw_response: Dict = client.query_request()
    events: List = raw_response.get('event', [])
    if events:
        title: str = f'{INTEGRATION_NAME} - Results for given query'
        context_entry = [{
            'ID': event.get('id'),
            'Description': event.get('description'),
            'Created': event.get('createdAt'),
            'IsActive': event.get('isActive'),
            'Assignee': event.get('assignee')
        } for event in events]
        context = {
            f'{INTEGRATION_NAME_CONTEXT}.Event(val.ID && val.ID === obj.ID)': context_entry
        }
        human_readable: str = tableToMarkdown(title, context_entry)
        return_outputs(human_readable, context, raw_response)
    else:
        return_warning(f'{INTEGRATION_NAME} - Could not find any results for given query')


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    server: str = demisto.params().get('url', '')
    fetch_time: str = demisto.params().get('fetch_time', '')
    use_ssl: bool = not demisto.params().get('insecure', False)

    client: Client = Client(server, use_ssl, fetch_time)
    command: str = demisto.command()
    demisto.info(f'Command being called is {command}')
    commands: Dict = {
        'test-module': test_module,
        'fetch-incidents': fetch_incidents,
        f'{INTEGRATION_NAME_COMMAND}-get-event': get_event,
        f'{INTEGRATION_NAME_COMMAND}-delete-event': close_event,
        f'{INTEGRATION_NAME_COMMAND}-update-event': update_event,
        f'{INTEGRATION_NAME_COMMAND}-create-event': create_event,
        f'{INTEGRATION_NAME_COMMAND}-query': query
    }
    try:
        if command in commands:
            commands[command](client)
    # Log exceptions
    except Exception as e:
        err_msg = f'Error in AuthenticationExample Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ == '__builtin__':
    main()
