
import demistomock as demisto
from CommonServerPython import *
import urllib3
import base64

MAX_EVENTS = 500
# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = 'Druva'
PRODUCT = 'Druva'

''' CLIENT CLASS '''


class Client(BaseClient):

    def refresh_access_token(self, credentials: str):
        """
        Since the validity of the Access Token is 30 minutes, this method refreshes it.
        """
        encoded_credentials = base64.b64encode(credentials.encode())
        decoded_credentials = encoded_credentials.decode("utf-8")
        headers = {"Content-Type": "application/x-www-form-urlencoded", 'Authorization': f'Basic {decoded_credentials}'}
        data = {'grant_type': 'client_credentials', 'scope': 'read'}
        try:
            response_json = self._http_request(method='POST', url_suffix='/token', headers=headers, data=data)
        except Exception as e:
            # 400 - "invalid_grant" - reason: invalid Server URL, Client ID or Secret Key.
            if "invalid_grant" in str(e):
                informative_message = "Make sure Server URL, Client ID and Secret Key are correctly entered."
            else:
                informative_message = str(e)

            raise DemistoException(f'Error in test-module: {informative_message}') from e

        access_token = response_json['access_token']
        headers = {'Authorization': f'Bearer {access_token}'}
        self._headers = headers

    def search_events(self, tracker: Optional[str] = None) -> dict:
        """
        Searches for Druva events.

        Args:
            tracker: pointer to the last event we got last time

        Returns:
            List[Dict]: List of events
        """

        url_suffix_tracker = f'?tracker={tracker}' if tracker else ""
        headers = (self._headers or {}) | {'accept': 'application/json'}
        try:
            response = self._http_request(method='GET', url_suffix=f'/insync/eventmanagement/v2/events{url_suffix_tracker}',
                                          headers=headers)
        except Exception as e:
            # 403 - "User is not authorized to access this resource with an explicit deny" - reason: tracker is expired
            # 400 - "Invalid tracker"
            raise DemistoException(f'Error in search-events: {str(e)}') from e
        return response


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): Druva client to use.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    client.search_events()
    return 'ok'


def get_events(client: Client, tracker: Optional[str] = None) -> tuple[list[dict], str]:
    """
    Gets events from Druva API in one batch (max 500), if a tracker is given, the API returns events starting from its timestamp.
    Args:
        client: Druva client to use.
        tracker: A string received in a previous run, marking the point in time from which we want to fetch.

    Returns:
        Druva's events and tracker
    """

    response = client.search_events(tracker)
    return response.get('events', [{}]), response.get('tracker', "")


def fetch_events(client: Client, last_run: dict[str, str]) -> tuple[list[dict], dict[str, str]]:
    """
    Args:
        client (Client): Druva client to use.
        last_run (dict): A dict with a key containing a pointer to the latest event created time we got from last fetch.
    Returns:
        new_tracker (dict): Next run dict containing the next tracker (a pointer to the next event).
        events (list): List of events that will be created in XSIAM.
    """

    tracker = last_run.get('tracker')  # None on first run
    demisto.debug(f'fetching events, {tracker=}')
    events, new_tracker = get_events(client, tracker)
    demisto.debug(f"fetched {len(events or [])} events, {new_tracker=}")

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'tracker': new_tracker}

    demisto.debug(f'Setting next run {next_run}.')
    return events, next_run


''' MAIN FUNCTION '''


def add_time_to_events(events: list[dict]):
    """
    Adds the _time key to the events.
    Args:
        events: list[dict] - list of events to add the _time key to.
    Returns:
        list: The events with the _time key.
    """
    if events:
        for event in events:
            create_time = arg_to_datetime(event['timestamp'])
            event['_time'] = create_time.strftime(DATE_FORMAT)  # type: ignore[union-attr]


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    proxy = params.get('proxy', False)
    verify_certificate = not params.get('insecure', False)

    druva_client_id = params["credentials"]["identifier"]
    druva_secret_key = params["credentials"]["password"]
    credentials = f'{druva_client_id}:{druva_secret_key}'

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            base_url=params['url'],
            verify=verify_certificate,
            proxy=proxy
        )

        # The validity of the Access Token is 30 minutes.
        client.refresh_access_token(credentials)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

        elif command == 'druva-get-events':
            should_push_events = argToBoolean(args['should_push_events'])
            events, tracker = get_events(client, args.get('tracker'))
            return_results(
                CommandResults(readable_output=tableToMarkdown(f"{VENDOR} Events:", events),
                               outputs=tracker,
                               outputs_prefix=f'{VENDOR}.tracker',
                               outputs_key_field='tracker',
                               replace_existing=True)
            )
            if should_push_events:
                add_time_to_events(events)
                send_events_to_xsiam(
                    events,
                    vendor=VENDOR,
                    product=PRODUCT
                )

        elif command == 'fetch-events':
            events, next_run = fetch_events(
                client=client,
                last_run=demisto.getLastRun(),
            )

            add_time_to_events(events)
            send_events_to_xsiam(
                events,
                vendor=VENDOR,
                product=PRODUCT
            )
            demisto.setLastRun(next_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
