from CommonServerPython import *
import urllib3
import time
from typing import Any
from http import HTTPStatus

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = 'Digital Guardian'
PRODUCT = 'ARC'
SUPPORTED_EXPORT_PROFILES = ('defaultExportProfile', 'demisto')

''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client class to interact with the Digital Guardian service API
    Implements _get_or_generate_access_token, export_events, and set_export_bookmark methods
    """

    def __init__(
        self,
        verify: bool,
        proxy: bool,
        auth_url: str,
        base_url: str,
        client_id: str,
        client_secret: str,
    ) -> None:
        self.__auth_url = auth_url
        self.__client_id = client_id
        self.__client_secret = client_secret

        super().__init__(base_url=base_url, verify=verify, proxy=proxy)  # headers set below (requires Client)
        self._headers = {'Authorization': f'Bearer {self._get_or_generate_access_token()}'}

    def _get_or_generate_access_token(self) -> str:
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
            demisto.debug(f'Using cached token, still valid until: {valid_until}')
            return token

        response = self._http_request(
            method='POST',
            full_url=urljoin(self.__auth_url, '/as/token.oauth2'),
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            data={
                'client_id': self.__client_id,
                'client_secret': self.__client_secret,
                'grant_type': 'client_credentials',
            },
            raise_on_status=True,
        )
        demisto.debug('Requested new token')

        valid_until = time_now + int(response['expires_in']) - 30   # deducting 30 for extra safety
        integration_context = {'token': response['access_token'], 'valid_until': valid_until}

        demisto.debug(f'Setting new token in integration context, token valid until: {valid_until}')
        set_integration_context(integration_context)

        return response['access_token']

    def export_events(self, export_profile: str) -> dict:
        """
        Exports events for the export profile that arrived after setting the internal bookmark.

        Args:
            export_profile (str): Export profile name.

        Returns:
            dict: Response JSON.
        """
        return self._http_request(
            method='POST',
            url_suffix=f'/rest/2.0/export_profiles/{export_profile}/export',
            raise_on_status=True,
        )

    def set_export_bookmark(self, export_profile: str) -> str:
        """
        Advances the internal bookmark / pointer for the export profile based on the last export events.
        This is effectively an API-side implementation of `demisto.getLastRun` and `demisto.setLastRun`.

        *Only call after successfully exporting events and sending them to XSIAM!*

        Returns:
            str: Response text.
        """
        return self._http_request(
            method='POST',
            url_suffix=f'/rest/2.0/export_profiles/{export_profile}/acknowledge',
            raise_on_status=True,
            resp_type='text',
        )


def test_module(client: Client, export_profiles: list[str], export_calls_per_fetch: int) -> str:
    """
    Tests API connectivity and authentication and validates configuration parameters.
    Args:
        client (Client): Digital Guardian client to use.
        export_profiles (list): List of export profile names.
        export_calls_per_fetch (int): Number of API calls to export events.
    Returns:
        str: 'ok' if valid parameters and connection to the service is successful, an error message otherwise.
    Raises:
        DemistoException | Exception: If request failed.
    """
    if export_calls_per_fetch <= 0:
        return 'The number of export requests per fetch should be a positive integer.'

    invalid_export_profiles = set()

    for export_profile in export_profiles:
        try:
            # Client._http_request raises DemistoException if non-okay response
            client.export_events(export_profile)

        except DemistoException as e:
            error_status_code = e.res.status_code if isinstance(e.res, requests.Response) else None

            if error_status_code in (HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN):
                return 'Authorization Error: Make sure client credentials are correctly set'

            if error_status_code == HTTPStatus.NOT_FOUND:
                invalid_export_profiles.add(export_profile)

            else:
                # Some other exception type or HTTP error status code
                raise

    if invalid_export_profiles:
        return f'Invalid export profiles: {", ".join(invalid_export_profiles)}. Refer to the help documentation.'

    return 'ok'


def fetch_events(client: Client, export_profile: str, limit: int | None = None) -> tuple[list[dict], dict]:
    """
    Args:
        client (Client): Digital Guardian client.
        export_profile (str): Export profile name.
        limit (int | None): Optional value to limit the number of yielded events.
    Returns:
        tuple[list[dict], dict]: Events and last run dictionary.
    """
    demisto.debug(f'Fetching events for profile: {export_profile}')
    raw_response = client.export_events(export_profile)

    demisto.info(f"Got {raw_response['total_hits']} raw events")
    events = create_events_for_push(raw_response, export_profile, limit)

    # Fields relating to the internal API bookmark (pointer); logged before pushing events to XSIAM (for debugging purposes)
    last_run = {key: value for key, value in raw_response.items() if key in ('bookmark_values', 'search_after_values')}

    return events, last_run


def add_time_and_profile_to_event(event: dict, export_profile: str):
    """
    Add _time and dg_export_profile keys to the event dictionary.

    Args:
        event (dict): Event dictionary with _time field.
        export_profile (str): Name of export profile.
    """
    event_time = arg_to_datetime(arg=event['dg_time'], required=True)
    event['_time'] = event_time.strftime(DATE_FORMAT)  # type: ignore[union-attr]
    event['dg_export_profile'] = export_profile


def create_events_for_push(raw_response: dict, export_profile: str, limit: int | None = None) -> list[dict]:
    """
    Yields key-value dictionaries of distinct events from the raw API response and adds the _time key to the events.
    Args:
        raw_response (dict): Export profile events raw API response.
        export_profile (str): Export profile name.
        limit (int | None): Optional value to limit the number of yielded events.
    Returns:
        list[dict]: List of events from the raw API response.
    """
    event_fields = [field['name'] for field in raw_response['fields']]
    events_data = raw_response['data']

    events = []
    for index, event_data in enumerate(events_data):
        if limit is not None and index == limit:  # No API-side limit param (needs to be managed on our end)
            break

        event: dict[str, Any] = {}
        for field, value in zip(event_fields, event_data, strict=True):
            event[field] = value if value != "-" else None  # "-" mark an empty field in Digital Guardian

        add_time_and_profile_to_event(event, export_profile)

        events.append(event)

    return events


def get_events_command(client: Client, args: dict, export_profile: str) -> tuple[list[dict], dict, CommandResults]:
    """
    Fetches a limited number of events and returns it in the CommandResults as a human readable markdown table.
    Args:
        client (Client): Digital Guardian client.
        export_profile (str): Export profile name.
        args (dict): Command arguments.
    Returns:
        tuple[list, dict, CommandResults]: List of events, last run dictionary, CommandResults with human readable output.
    """
    limit = arg_to_number(args.get('limit')) or 1000
    events, last_run = fetch_events(client, export_profile, limit=limit)

    human_readable = tableToMarkdown(name=f'Events for Profile {export_profile}', t=events, removeNull=True)
    demisto.debug(f'Displayed limit of {limit} events from response')

    return events, last_run, CommandResults(readable_output=human_readable)


def push_events(events: list[dict], export_profile: str) -> None:
    """
    Pushes events from a specific export profile to XSIAM.

    Args:
        client (Client): Digital Guardian client.
        events (list[dict]): Events get_events_command or fetch_events.
        export_profile (str): Export profile name.
    """
    demisto.debug(f'Sending {len(events)} events to XSIAM from profile: {export_profile}.')
    # Module health updated in main() once all events from all export profiles are fetched and sent to XSIAM
    send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT, should_update_health_module=False)


def set_export_bookmark(client: Client, last_run: dict, export_profile: str) -> None:
    """
    Moves internal bookmark in the API for the next time fetch-events is invoked (API equivalent of `demisto.setLastRun`).

    Args:
        client (Client): Digital Guardian client.
        last_run (dict): Dictionary with 'bookmark_values' and 'search_after_values' from raw API response.
        export_profile (str): Export profile name.
    """
    demisto.debug(f'Setting export bookmark after run: {last_run} for profile: {export_profile}.')
    client.set_export_bookmark(export_profile)


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    # required
    auth_url = params['auth_server_url']
    base_url = params['gateway_base_url']
    client_id = params['credentials']['identifier']
    client_secret = params['credentials']['password']
    export_profiles = argToList(params['export_profile'])
    # optional
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    export_calls_per_fetch = arg_to_number(params.get('export_calls_per_fetch')) or 1

    demisto.debug(f'{base_url=}')

    custom_export_profiles = [
        export_profile for export_profile in export_profiles
        if export_profile not in SUPPORTED_EXPORT_PROFILES
    ]
    if custom_export_profiles:
        demisto.debug(f'Detected custom (unsupported) export profiles: {", ".join(custom_export_profiles)}.')

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            verify=verify_certificate,
            proxy=proxy,
            auth_url=auth_url,
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, export_profiles, export_calls_per_fetch)
            return_results(result)

        elif command == 'digital-guardian-get-events':
            should_push_events = argToBoolean(args.pop('should_push_events'))

            for export_profile in export_profiles:
                events, last_run, command_results = get_events_command(client, args, export_profile)
                return_results(command_results)

                if should_push_events:
                    push_events(events, export_profile)

        elif command == 'fetch-events':
            events_count = 0
            for export_profile in export_profiles:
                for call_number in range(export_calls_per_fetch):
                    demisto.debug(f'Export call {call_number + 1} out of {export_calls_per_fetch} for profile {export_profile}')
                    events, last_run = fetch_events(client, export_profile)
                    push_events(events, export_profile)
                    set_export_bookmark(client, last_run, export_profile)
                    events_count += len(events)
            demisto.debug(f'Pulled {events_count} events from profiles {export_profiles}. Updating module health')
            demisto.updateModuleHealth({'eventsPulled': events_count})

        else:
            raise NotImplementedError(f'Unknown command: {command}')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
