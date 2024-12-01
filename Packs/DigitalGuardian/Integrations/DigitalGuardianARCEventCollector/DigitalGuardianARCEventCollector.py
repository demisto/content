from CommonServerPython import *
import urllib3
import time
from typing import Any
from collections.abc import Generator, Iterable

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = 'Digital Guardian'
PRODUCT = 'ARC'

EventsGenerator = Generator[dict[str, Any], None, None]

''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client class to interact with the service API
    implements get_token and get_events functions
    """

    def __init__(
        self,
        verify: bool,
        proxy: bool,
        auth_url: str,
        base_url: str,
        client_id: str,
        client_secret: str,
        export_profile: str,
    ) -> None:
        self.__auth_url = auth_url
        self.__client_id = client_id
        self.__client_secret = client_secret
        self.export_profile = export_profile

        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self._headers = {'Authorization': f'Bearer {self._get_access_token()}'}

    def _get_access_token(self) -> str:
        """
        Tries to find a valid token in integration context. If not found or expired, generates a new token
        and sets it in the integration context.

        Returns:
            str: Access token.
        """
        integration_context = get_integration_context()
        token = integration_context.get('token')
        valid_until = integration_context.get('valid_until')
        time_now = int(time.time())

        if token and valid_until and time_now < valid_until:
            # Token is still valid - did not expire yet
            demisto.debug('Using cached token which is still valid')
            demisto.debug(f'time-now: {time_now}\n valid token until: {valid_until}')
            return token

        response = self._http_request(
            method='POST',
            full_url=urljoin(self.__auth_url, '/as/token.oauth2'),
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            data={
                'client_id': self.__client_id,
                'client_secret': self.__client_secret,
                'grant_type': 'client_credentials'
            },
            raise_on_status=True,
        )
        demisto.debug(f'Requested new token from {VENDOR}')

        integration_context = {
            'token': response['access_token'],
            'valid_until': time_now + int(response['expires_in']) - 100
        }
        set_integration_context(integration_context)

        return response['access_token']

    def get_watchlists(self) -> list[dict]:
        """
        Returns all watchlists configured to monitor and track specific data or activities.

        Returns:
            list: Watchlists.
        """
        return self._http_request(method='GET', url_suffix='/rest/1.0/watchlists', raise_on_status=True)

    def export_events(self) -> dict:
        """
        Exports events for the export profile that arrived after setting the internal bookmark.

        Returns:
            dict: Response JSON.
        """
        return self._http_request(
            method='POST',
            url_suffix=f'/rest/2.0/export_profiles/{self.export_profile}/export',
            raise_on_status=True,
        )

    def set_export_bookmark(self) -> str:
        """
        Advances the internal bookmark / pointer for the export profile based on the last export events.
        This is effectively an API-side implementation of `demisto.getLastRun` and `demisto.setLastRun`.

        *Only call after successfully exporting events and sending them to XSIAM!*

        Returns:
            str: Response text.
        """
        return self._http_request(
            method='POST',
            url_suffix=f'/rest/2.0/export_profiles/{self.export_profile}/acknowledge',
            raise_on_status=True,
            resp_type='text',
        )


def test_module(client: Client, params: dict[str, Any]) -> str:
    """
    Tests API connectivity and authentication.
    Args:
        client (Client): Digital Guardian client to use.
        params (dict): Integration parameters.
    Returns:
        str: 'ok' connection to the service is successful.
    Raises:
        DemistoException | HTTPError: If request failed.
    """
    try:
        client.get_watchlists()
        return 'ok'

    except Exception as e:
        if 'Forbidden' in str(e):
            raise DemistoException('Authorization Error: Make sure client credentials are correctly set') from e
        raise


def fetch_events(client: Client, limit: int | None = None) -> tuple[EventsGenerator, dict]:
    """
    Args:
        client (Client): Digital Guardian client.
        limit (int | None): Optional value to limit the number of yielded events.
    Returns:
        tuple[EventsGenerator, dict]: Events and last run dictionary.
    """
    demisto.debug('Fetching events')
    raw_response = client.export_events()

    demisto.info(f"Pulled {raw_response['total_hits']} events from {VENDOR}")
    events = create_events_for_push(raw_response, limit)

    last_run = {key: value for key, value in raw_response.items() if key in ('bookmark_values', 'search_after_values')}

    return events, last_run


def create_events_for_push(raw_response: dict, limit: int | None = None) -> EventsGenerator:
    """
    Yields key-value dictionaries of distinct events from the raw API response and adds the _time key to the events.
    Args:
        raw_response (dict): Export profile events raw API response.
        limit (int | None): Optional value to limit the number of yielded events.
    Yields:
        dict: Event from raw response.
    """
    event_fields = [field['name'] for field in raw_response['fields']]
    events_data = raw_response['data']

    ids = set()
    index = 0

    for event_data in events_data:
        if limit is not None and index == limit:  # No API-side limit param (needs to be managed on our end)
            break

        event = dict(zip(event_fields, event_data, strict=True))
        event_id = event['dg_guid']

        if event_id in ids:
            continue  # Skip duplicate event

        event_time = arg_to_datetime(arg=event.get('dg_time')) if event.get('dg_time') else None
        event['_time'] = event_time.strftime(DATE_FORMAT) if event_time else None

        ids.add(event_id)
        index += 1

        yield event


def get_events_command(client: Client, args: dict) -> tuple[list, dict, CommandResults]:
    """
    Fetches a limited number of events and returns it in the CommandResults as a human readable markdown table.
    Args:
        client (Client): Digital Guardian client.
        args (dict): Command arguments.
    Returns:
        tuple[list, dict, CommandResults]: List of events, last run dictionary, CommandResults with human readable output.
    """
    limit = arg_to_number(args.get('limit')) or 1000
    events, last_run = fetch_events(client, limit=limit)

    event_list = list(events)
    if event_list:
        human_readable = tableToMarkdown(
            name='Test Events',
            t=[{key: value for key, value in event.items() if value != "-"} for event in event_list],
        )
    else:
        human_readable = 'No events found.'

    demisto.debug(f'Displayed limit of {limit} events from response')

    return event_list, last_run, CommandResults(readable_output=human_readable)


def push_and_set_last_run(client: Client, events: Iterable, last_run: dict) -> None:
    """
    Saves last run and moves internal bookmark in the API for the time fetch-events is invoked.

    Args:
        client (Client): Digital Guardian client.
        events (Iterable): Events (A generator object if internal fetch or list of from get-events command).
        last_run (dict): Dictionary with 'bookmark_values' and 'search_after_values' from raw API response.
    """
    send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)

    demisto.debug(f'Setting export bookmark after run: {last_run}.')
    client.set_export_bookmark()  # API-managed bookmark / pointer removes the need for setting and getting last run on our end


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    auth_url = params.get('auth_server_url', '')
    base_url = params.get('gateway_base_url', '')
    client_id = params.get('credentials', {}).get('identifier', '')
    client_secret = params.get('credentials', {}).get('password', '')
    export_profile = params.get('export_profile', '')
    verify_certificate = not params.get('insecure', False)

    demisto.debug(f'Running {VENDOR} event collector with base url: {base_url}')

    # How much time before the first fetch to retrieve events
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            verify=verify_certificate,
            proxy=proxy,
            auth_url=auth_url,
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
            export_profile=export_profile,
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, params)
            return_results(result)

        elif command == 'digital-guardian-get-events':
            events, last_run, command_results = get_events_command(client, args)
            return_results(command_results)

            should_push_events = argToBoolean(args.pop('should_push_events'))
            if should_push_events:
                push_and_set_last_run(client, events, last_run)

        elif command == 'fetch-events':
            events, last_run = fetch_events(client)  # type: ignore
            push_and_set_last_run(client, events, last_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
