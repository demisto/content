import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S'
VENDOR = 'armis'
PRODUCT = 'security'
API_V1_ENDPOINT = '/api/v1'
DEFAULT_MAX_FETCH = 1000
EVENT_TYPES = {
    'Alerts': {'unique_id_key': 'alertId',
               'aql_query': 'in:alerts',
               'type': 'alerts'},
    'Threats': {
        'unique_id_key': 'activityUUID',
        'aql_query': 'in:activity type:"Threat Detected"',
        'type': 'threats'}}

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with Armis API - this Client implements API calls"""

    def __init__(self, base_url, api_key, access_token, verify=False, proxy=False):
        self._api_key = api_key
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        if not access_token or not self.is_valid_access_token(access_token):
            access_token = self.get_access_token()
        self.update_access_token(access_token)

    def update_access_token(self, access_token=None):
        if not access_token:
            access_token = self.get_access_token()
        headers = {
            'Authorization': f'{access_token}',
            "Accept": "application/json"
        }
        self._headers = headers
        self._access_token = access_token

    def fetch_by_aql_query(self, aql_query: str, max_fetch: int, after: None | datetime = None):
        """ Fetches alerts or threats using AQL query.

        Args:
            aql_query (str): AQL query request parameter for the API call.
            max_fetch (int): Max number of alerts/threats to fetch.
            time_frame (None | int, optional): Time frame in seconds to fetch alerts/threats from. Defaults to None.

        Returns:
            list[dict]: List of alerts/threats objects represented as dictionaries.
        """
        params: dict[str, Any] = {'aql': aql_query, 'includeTotal': 'true', 'length': max_fetch, 'orderBy': 'time'}
        if after:  # if there is a time frame thats relative to last run
            params['aql'] += f' after:{after.strftime(DATE_FORMAT)}'

        # make first request to get first page of threat activity
        raw_response = self._http_request(url_suffix='/search/', method='GET', params=params, headers=self._headers)
        results = raw_response.get('data', {}).get('results', [])

        # perform pagination if needed (until max_fetch limit),  cycle through all pages and add results to results list
        while (next := raw_response.get('data', '').get('next')) and (len(results) < max_fetch):
            if next < max_fetch:
                params['length'] = max_fetch - next
            params['from'] = next
            raw_response = self._http_request(url_suffix='/search/', method='GET', params=params, headers=self._headers)
            results.extend(raw_response.get('data', {}).get('results', []))

        return results

    def is_valid_access_token(self, access_token):
        """ Checks if current available access token is valid.

        Args:
            access_token (str): Access token to validate.

        Returns:
            Boolean: True if access token is valid, False otherwise.
        """
        try:
            headers = {
                'Authorization': f'{access_token}',
                "Accept": "application/json"
            }
            params = {'aql': 'in:alerts timeFrame:"1 seconds"',
                      'includeTotal': 'true', 'length': 1, 'orderBy': 'time'}
            self._http_request(url_suffix='/search/', method='GET', params=params, headers=headers)
        except Exception:
            return False
        return True

    def get_access_token(self):
        """ Generates access token for Armis API.

        Raises:
            DemistoException: If access token could not be generated.
        Returns:
            str: Access token.
        """
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json"
        }
        params = {"secret_key": self._api_key}
        response = self._http_request(url_suffix='/access_token/', method='POST', params=params, headers=headers)
        if access_token := response.get('data', {}).get('access_token'):
            return access_token
        else:
            raise DemistoException('Could not generate access token.')


''' TEST MODULE '''


def test_module(client: Client) -> str:
    """ Tests API connectivity and authentication.
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): Armis client to use for API calls.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    try:
        client.fetch_by_aql_query('in:alerts', 1)

    except Exception as e:
        raise DemistoException(f'Error in test-module: {e}') from e

    return 'ok'


''' HELPER FUNCTIONS '''


def calculate_fetch_start_time(last_fetch_time, fetch_start_time_param) -> datetime:
    """ Calculates the fetch start time.

    Args:
        last_fetch_time (str): Last fetch time (from last run).
        fetch_start_time_param (datetime): Fetch start time (usually current time).

    Raises:
        DemistoException: If the transformation of last_fetch_time to datetime object failed.

    Returns:
        datetime: Fetch start time value for current fetch cycle.
    """
    if last_fetch_time:
        last_fetch_time = arg_to_datetime(last_fetch_time)
        if not isinstance(last_fetch_time, datetime):
            raise DemistoException(f'last_fetch_time is not a valid date: {last_fetch_time}')
        return last_fetch_time
    else:
        return fetch_start_time_param


def are_two_event_time_equal(x: datetime, y: datetime):
    return (x.year == y.year) and (x.month == y.month) and (x.day == y.day) and (x.hour == y.hour) and (x.second == y.second)


def dedup_events(events: list[dict], events_last_fetch_ids: list[str], unique_id_key: str):
    """ Dedup events response.
    Armis API V.1.0 supports time filtering in requests only up to level of seconds (and not milliseconds).
    Therefore, if there are more events with the same timestamp than in the current fetch cycle,
    additional handling is necessary.

    Cases:
    1.  All events from the current fetch cycle have the same timestamp.
        Meaning: There are potentially more events with the same timestamp in the next fetch.
        Handle: Add the list of fetched events IDs to current 'events_last_fetch_ids' from last run,
                return list of dedup event and updated list of 'events_last_fetch_ids' for next run.

    2.  Most recent event has later timestamp then other events in the response.
        Meaning: This is the normal case where events in the response have different timestamps.
        Handle: Return list of dedup event and new list of 'new_ids' for next run.

    3.  Dedup list of events is empty.
        Meaning: Usually means there are not any more events to fetch at the moment.
        Handle: Return empty list and the unchanged list of 'events_last_fetch_ids' for next run.

    Args:
        events (list[dict]): List of events from the current fetch response.
        events_last_fetch_ids (list[str]): List of IDs of events from last fetch cycle.
        unique_id_key (str): Unique event ID key of specific event type (Alert, Threat Activity etc.)

    Returns:
        tuple[list[dict], list[str]: The list of dedup events and ID list of events of current fetch.
    """
    # remove events that already appeared in last fetch
    dedup_events: list[dict] = [event for event in events if event.get(unique_id_key) not in events_last_fetch_ids]
    # get ids of dedup events
    new_ids: list[str] = [event.get(unique_id_key, '') for event in dedup_events]

    latest_event_from_response = arg_to_datetime(events[-1].get('time'))
    earliest_event_from_response = arg_to_datetime(events[0].get('time'))

    if isinstance(latest_event_from_response, datetime) and isinstance(earliest_event_from_response, datetime)\
            and are_two_event_time_equal(latest_event_from_response, earliest_event_from_response):
        events_last_fetch_ids.extend(new_ids)
        return dedup_events, events_last_fetch_ids
    elif events:
        return dedup_events, new_ids
    else:
        return dedup_events, events_last_fetch_ids


def fetch_by_event_type(event_type: dict, events: list, next_run: dict, client: Client,
                        max_fetch: int, last_run: dict, fetch_start_time_param: datetime):
    """ Fetch events by specific event type.

    Args:
        event_type (dict): Dictionary containing event type unique ID key, AQL query and type name.
        events (list): List of fetched events.
        next_run (dict): Last run dictionary for next fetch cycle.
        client (Client): Armis client to use for API calls.
        max_fetch (int): Max number of events to fetch.
        last_run (dict): Last run dictionary.
        fetch_start_time_param (datetime): Fetch start time (usually current time).
    """
    unique_id_key, aql_query, type = event_type['unique_id_key'], event_type['aql_query'], event_type['type']
    last_fetch_ids = f'{type}_last_fetch_ids'
    last_fetch_time = f'{type}_last_fetch_time'

    demisto.debug(f'debug-log: handling event-type: {type}')
    if last_run:
        event_type_fetch_start_time = calculate_fetch_start_time(last_run.get(last_fetch_time), fetch_start_time_param)
    else:
        event_type_fetch_start_time = None

    response = client.fetch_by_aql_query(
        aql_query=aql_query,
        max_fetch=max_fetch,
        after=event_type_fetch_start_time
    )
    demisto.debug(f'debug-log: fetched {len(response)} {type} from API')
    if response:
        new_events, next_run[last_fetch_ids] = dedup_events(
            response, last_run.get(last_fetch_ids, []), unique_id_key)
        next_run[last_fetch_time] = new_events[-1].get('time') if new_events else last_run.get(last_fetch_time)

        events.extend(new_events)
        demisto.debug(f'debug-log: overall {len(new_events)} alerts (after dedup)')
        demisto.debug(f'debug-log: last {type} in list: {new_events[-1] if new_events else {}}')


def fetch_events(client: Client, max_fetch: int, last_run: dict, fetch_start_time_param: datetime,
                 log_types_to_fetch: list[str]):
    """ Fetch events from Armis API.

    Args:
        client (Client): Armis client to use for API calls.
        max_fetch (int): Max number of alerts/threats to fetch.
        last_run (dict): Last run dictionary.
        fetch_start_time_param (datetime): Fetch start time (usually current time).
        log_types_to_fetch (list[str]): List of log types to fetch.

    Returns:
        (list[dict], dict) : List of fetched events and next run dictionary.
    """
    events: list[dict] = []
    next_run: dict[str, list | str] = {}

    for event_type in log_types_to_fetch:
        try:
            fetch_by_event_type(EVENT_TYPES[event_type], events, next_run, client, max_fetch, last_run, fetch_start_time_param)
        except Exception as e:
            if "Invalid access token" in str(e):
                client.update_access_token()
                fetch_by_event_type(EVENT_TYPES[event_type], events, next_run, client,
                                    max_fetch, last_run, fetch_start_time_param)

    next_run['access_token'] = client._access_token

    demisto.debug(f'debug-log: events: {events}')
    return events, next_run


def add_time_to_events(events):
    """ Adds the _time key to the events.

    Args:
        events: list[dict] - list of events to add the _time key to.

    Returns:
        list: The events with the _time key.
    """
    if events:
        for event in events:
            create_time = arg_to_datetime(arg=event.get('time'))
            event['_time'] = create_time.strftime(DATE_FORMAT) if create_time else None


def handle_from_date_argument(from_date: str) -> datetime | None:
    """ Converts the from_date argument to a datetime object.
        This argument is used only in the armis-get-events command.

    Args:
        from_date: The from_date argument.

    Returns:
        datetime: The from_date argument as a datetime object or None if the argument is invalid.
    """
    from_date_datetime = arg_to_datetime(from_date)
    return from_date_datetime if isinstance(from_date_datetime, datetime) else None


def handle_fetched_events(events: list[dict[str, Any]], next_run: dict[str, str | list]):
    """ Handle fetched events.
    - Send the events to XSIAM.
    - Set last run values for next fetch cycle.

    Args:
        events (list[dict[str, Any]]): Fetched events.
        next_run (dict[str, str | list]): Next run dictionary.
    """
    if events:
        add_time_to_events(events)
        demisto.debug(f'debug-log: {len(events)} events are about to be sent to XSIAM.')
        send_events_to_xsiam(
            events,
            vendor=VENDOR,
            product=PRODUCT
        )
        demisto.setLastRun(next_run)
        demisto.debug(f'debug-log: {len(events)} events were sent to XSIAM.')
        demisto.debug(f'debug-log: {next_run=}')
    else:
        demisto.debug('debug-log: No new events fetched, Last run was not updated.')


def events_to_command_results(events: list[dict[str, Any]]) -> CommandResults:
    """ Return a CommandResults object with a table of fetched events.

    Args:
        events (list[dict[str, Any]]): list of fetched events.

    Returns:
        CommandResults: CommandResults object with a table of fetched events.
    """
    return CommandResults(
        raw_response=events,
        readable_output=tableToMarkdown(name=f'{VENDOR} {PRODUCT} events',
                                        t=events,
                                        removeNull=True))


''' MAIN FUNCTION '''


def main():
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    last_run = demisto.getLastRun()
    access_token = last_run.get('access_token')
    api_key = params.get('credentials', {}).get('password')
    base_url = urljoin(params.get('server_url'), API_V1_ENDPOINT)
    verify_certificate = not params.get('insecure', True)
    max_fetch = arg_to_number(params.get('max_fetch')) or DEFAULT_MAX_FETCH
    proxy = params.get('proxy', False)
    log_types_to_fetch = argToList(params.get('log_types_to_fetch', []))
    should_push_events = argToBoolean(args.get('should_push_events', False))
    from_date_datetime = None
    if from_date := args.get('from_date'):
        from_date_datetime = handle_from_date_argument(from_date)

    demisto.debug(f'Command being called is {command}')

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            api_key=api_key,
            access_token=access_token)

        if command == 'test-module':
            return_results(test_module(client))

        elif command in ('fetch-events', 'armis-get-events'):
            push_events = (command == 'fetch-events' or should_push_events)

            events, next_run = fetch_events(
                client=client,
                max_fetch=max_fetch,
                last_run=last_run,
                fetch_start_time_param=from_date_datetime or datetime.now(),
                log_types_to_fetch=log_types_to_fetch,
            )

            demisto.debug(f'debug-log: {len(events)} events fetched from armis api')

            if push_events:
                handle_fetched_events(events, next_run)

            if command == 'armis-get-events':
                return_results(events_to_command_results(events))

        else:
            return_error(f'Command {command} does not exist for this integration.')
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
