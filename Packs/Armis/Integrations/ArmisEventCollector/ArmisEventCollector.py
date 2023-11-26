import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any
import itertools
from dateutil import parser
# Disable insecure warnings
urllib3.disable_warnings()


class EVENT_TYPE:
    """
    This class defines an Event used to dynamically store different types of events data.
    """

    def __init__(self, unique_id_key, aql_query, type, order_by, dataset_name):
        self.unique_id_key = unique_id_key
        self.aql_query = aql_query
        self.type = type
        self.order_by = order_by
        self.dataset_name = dataset_name


''' CONSTANTS '''


DATE_FORMAT = '%Y-%m-%dT%H:%M:%S'
VENDOR = 'armis'
PRODUCT = 'security'
API_V1_ENDPOINT = '/api/v1'
DEFAULT_MAX_FETCH = 5000
DEVICES_DEFAULT_MAX_FETCH = 10000
EVENT_TYPES = {
    'Alerts': EVENT_TYPE(unique_id_key='alertId', aql_query='in:alerts', type='alerts', order_by='time', dataset_name='alerts'),
    'Activities': EVENT_TYPE(unique_id_key='activityUUID', aql_query='in:activity', type='activity',
                             order_by='time', dataset_name='activities'),
    'Devices': EVENT_TYPE(unique_id_key='id', aql_query='in:devices', type='devices', order_by='lastSeen',
                          dataset_name='devices'),
}
DEVICES_LAST_FETCH = 'devices_last_fetch_time'

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

    def fetch_by_aql_query(self, aql_query: str, max_fetch: int, after: None | datetime = None,
                           order_by: str = 'time'):
        """ Fetches events using AQL query.

        Args:
            aql_query (str): AQL query request parameter for the API call.
            max_fetch (int): Max number of events to fetch.
            after (None | datetime): The date and time to fetch events from. Defaults to None.
            order_by (str): Order by parameter for the API call. Defaults to 'time'.
        Returns:
            list[dict]: List of events objects represented as dictionaries.
        """
        params: dict[str, Any] = {'aql': aql_query, 'includeTotal': 'true', 'length': max_fetch, 'orderBy': order_by}
        if not after:  # this should only happen when get-events command is used without from_date argument
            after = datetime.now() - timedelta(minutes=1)
        params['aql'] += f' after:{after.strftime(DATE_FORMAT)}'  # add 'after' date filter to AQL query in the desired format
        raw_response = self._http_request(url_suffix='/search/', method='GET', params=params, headers=self._headers)
        results = raw_response.get('data', {}).get('results', [])

        # perform pagination if needed (until max_fetch limit),  cycle through all pages and add results to results list.
        # The response's 'next' attribute carries the index to start the next request in the
        # pagination (using the 'from' request parameter), or null if there are no more pages left.
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


def calculate_fetch_start_time(last_fetch_time: str | None, fetch_start_time: datetime | None):
    """ Calculates the fetch start time.
        There are three cases for fetch start time calculation:
        - Case 1: last_fetch_time exist in last_run, thus being prioritized (fetch-events / armis-get-events commands).
        - Case 2: last_run is empty & from_date parameter exist (armis-get-events command with from_date argument).
        - Case 3: first fetch in the instance (no last_run), this will return None
                  (The request will get the last events from the API in the
                  page size of 'max_events' (fetch-events / armis-get-events commands).

    Args:
        last_fetch_time (str | None): Last fetch time (from last run).
        fetch_start_time (datetime | None): Fetch start time.

    Raises:
        DemistoException: If the transformation to to datetime object failed.

    Returns:
        datetime: Fetch start time value for current fetch cycle.
    """
    # case 1
    if last_fetch_time:
        last_fetch_datetime = arg_to_datetime(last_fetch_time)
        if not last_fetch_datetime:
            raise DemistoException(f'last_fetch_time is not a valid date: {last_fetch_time}')
        return last_fetch_datetime
    # case 2
    elif fetch_start_time:
        return fetch_start_time
    # case 3
    else:
        return None


def are_two_datetime_equal_by_second(x: datetime, y: datetime):
    """Calculate if two datetime objects are equal up to the seconds value.
        Even though the 'time' attribute of each event has milliseconds,
        the API request supports time filtering of only up to seconds.
        There for, all events with the same time up to a seconds are considered to have the same time.

    Args:
        x (datetime): First datetime.
        y (datetime): Second datetime.

    Returns:
        Boolean: True if both datetime objects have the same time up to seconds, False otherwise.
    """
    return (x.year == y.year) and (x.month == y.month) and (x.day == y.day)\
        and (x.hour == y.hour) and (x.minute == y.minute) and (x.second == y.second)


def dedup_events(events: list[dict], events_last_fetch_ids: list[str], unique_id_key: str, event_order_by: str):
    """ Dedup events response.
    Armis API V.1.8 supports time filtering in requests only up to level of seconds (and not milliseconds).
    Therefore, if there are more events with the same timestamp than in the current fetch cycle,
    additional handling is necessary.

    Cases:
    1.  Empty event list (no new events received from API response).
        Meaning: Usually means there are not any more events to fetch at the moment.
        Handle: Return empty list of events and the unchanged list of 'events_last_fetch_ids' for next run.

    2.  All events from the current fetch cycle have the same timestamp.
        Meaning: There are potentially more events with the same timestamp in the next fetch.
        Handle: Add the list of fetched events IDs to current 'events_last_fetch_ids' from last run,
                return list of new events and updated list of 'events_last_fetch_ids' for next run.

    3.  Most recent event has later timestamp then other events in the response.
        Meaning: This is the normal case where events in the response have different timestamps.
        Handle: Return list of new events and a list of 'new_ids' containing only IDs of
                events with identical latest time (up to second) for next run.

    Args:
        events (list[dict]): List of events from the current fetch response.
        events_last_fetch_ids (list[str]): List of IDs of events from last fetch cycle.
        unique_id_key (str): Unique event ID key of specific event type (Alert, Threat Activity etc.)

    Returns:
        tuple[list[dict], list[str]: The list of dedup events and ID list of events of current fetch.
    """
    # case 1
    if not events:
        demisto.debug('debug-log: Dedup case 1 - Empty event list (no new events received from API response).')
        return [], events_last_fetch_ids

    new_events: list[dict] = [event for event in events if event.get(unique_id_key) not in events_last_fetch_ids]

    earliest_event_datetime = arg_to_datetime(events[0].get(event_order_by))
    latest_event_datetime = arg_to_datetime(events[-1].get(event_order_by))

    # case 2
    if earliest_event_datetime and latest_event_datetime and\
            are_two_datetime_equal_by_second(latest_event_datetime, earliest_event_datetime):
        demisto.debug('debug-log: Dedup case 2 - All events from the current fetch cycle have the same timestamp.')
        new_ids = [event.get(unique_id_key, '') for event in new_events]
        events_last_fetch_ids.extend(new_ids)
        return new_events, events_last_fetch_ids

    # case 3
    else:
        # Note that the following timestamps comparison are made between strings and assume
        # the following timestamp format from the response: "YYYY-MM-DDTHH:MM:SS.fffff+Z"
        demisto.debug('debug-log: Dedup case 3 - Most recent event has later timestamp then other events in the response.')

        latest_event_timestamp = events[-1].get(event_order_by, '')[:19]
        # itertools.takewhile is used to iterate over the list of events (from latest time to earliest)
        # and take only the events with identical latest time
        events_with_identical_latest_time = list(
            itertools.takewhile(lambda x: x.get(event_order_by, '')[:19] == latest_event_timestamp, reversed(events)))
        new_ids = [event.get(unique_id_key, '') for event in events_with_identical_latest_time]

        return new_events, new_ids


def fetch_by_event_type(event_type: EVENT_TYPE, events: dict, next_run: dict, client: Client,
                        max_fetch: int, last_run: dict, fetch_start_time: datetime | None):
    """ Fetch events by specific event type.

    Args:
        event_type (EVENT_TYPE): A namedtuple object containing the event's unique ID key, AQL query and type name.
        events (list): List of fetched events.
        next_run (dict): Last run dictionary for next fetch cycle.
        client (Client): Armis client to use for API calls.
        max_fetch (int): Max number of events to fetch.
        last_run (dict): Last run dictionary.
        fetch_start_time (datetime | None): Fetch start time.
    """
    last_fetch_ids = f'{event_type.type}_last_fetch_ids'
    last_fetch_time = f'{event_type.type}_last_fetch_time'

    demisto.debug(f'debug-log: handling event-type: {event_type.type}')
    demisto.debug(f'debug-log: last run of type: {event_type.type} is: {last_run.get(last_fetch_time)}')
    event_type_fetch_start_time = calculate_fetch_start_time(last_run.get(last_fetch_time), fetch_start_time)

    response = client.fetch_by_aql_query(
        aql_query=event_type.aql_query,
        max_fetch=max_fetch,
        after=event_type_fetch_start_time,
        order_by=event_type.order_by
    )

    demisto.debug(f'debug-log: fetched {len(response)} {event_type.type} from API')
    if response:
        new_events, next_run[last_fetch_ids] = dedup_events(
            response, last_run.get(last_fetch_ids, []), event_type.unique_id_key, event_type.order_by)
        next_run[last_fetch_time] = new_events[-1].get(event_type.order_by) if new_events else last_run.get(last_fetch_time)
        demisto.debug(f'debug-log: updated next_run with: {next_run[last_fetch_time]}')
        events.setdefault(event_type.dataset_name, []).extend(new_events)
        demisto.debug(f'debug-log: overall {len(new_events)} {event_type.dataset_name} (after dedup)')
        demisto.debug(f'debug-log: last {event_type.dataset_name} in list: {new_events[-1] if new_events else {}}')
    else:
        next_run.update(last_run)


def fetch_events(client: Client,
                 max_fetch: int,
                 devices_max_fetch: int,
                 last_run: dict,
                 fetch_start_time: datetime | None,
                 event_types_to_fetch: list[str],
                 device_fetch_interval: timedelta | None):
    """ Fetch events from Armis API.

    Args:
        client (Client): Armis client to use for API calls.
        max_fetch (int): Max number of alerts to fetch.
        last_run (dict): Last run dictionary.
        fetch_start_time (datetime | None): Fetch start time.
        event_types_to_fetch (list[str]): List of event types to fetch.
        device_fetch_interval (timedelta | None): Time interval to fetch devices.
    Returns:
        (list[dict], dict) : List of fetched events and next run dictionary.
    """
    events: dict[str, list[dict]] = {}
    next_run: dict[str, list | str] = {}
    if 'Devices' in event_types_to_fetch\
            and not should_run_device_fetch(last_run, device_fetch_interval, datetime.now()):
        event_types_to_fetch.remove('Devices')

    for event_type in event_types_to_fetch:
        event_max_fetch = max_fetch if event_type != "Devices" else devices_max_fetch
        try:
            fetch_by_event_type(EVENT_TYPES[event_type], events, next_run, client,
                                event_max_fetch, last_run, fetch_start_time)
        except Exception as e:
            if "Invalid access token" in str(e):
                demisto.debug("debug-log: Invalid access token")
                client.update_access_token()
                fetch_by_event_type(EVENT_TYPES[event_type], events, next_run, client,
                                    event_max_fetch, last_run, fetch_start_time)

    next_run['access_token'] = client._access_token

    demisto.debug(f'debug-log: events: {events}')
    return events, next_run


def add_time_to_events(events, event_type):
    """ Adds the _time key to the events.

    Args:
        events: list[dict] - list of events to add the _time key to.

    Returns:
        list: The events with the _time key.
    """
    if events:
        for event in events:
            if event_type == 'devices':
                event['_time'] = event.get('lastSeen')
            else:
                event['_time'] = event.get('time')


def handle_from_date_argument(from_date: str) -> datetime | None:
    """ Converts the from_date argument to a datetime object.
        This argument is used only in the armis-get-events command.

    Args:
        from_date: The from_date argument.

    Returns:
        datetime: The from_date argument as a datetime object or None if the argument is invalid.
    """
    from_date_datetime = arg_to_datetime(from_date)
    return from_date_datetime if from_date_datetime else None


def handle_fetched_events(events: dict[str, list[dict[str, Any]]],
                          next_run: dict[str, str | list]):
    """ Handle fetched events.
    - Send the fetched events to XSIAM.
    - Set last run values for next fetch cycle.

    Args:
        events (list[dict[str, Any]]): Fetched events.
        next_run (dict[str, str | list]): Next run dictionary.
    """
    if events:
        for event_type, events_list in events.items():
            if not events_list:
                demisto.debug(f'debug-log: No events of type: {event_type} fetched from API.')
            else:
                add_time_to_events(events_list, event_type)
                demisto.debug(f'debug-log: {len(events_list)} events of type: {event_type} are about to be sent to XSIAM.')
            product = f'{PRODUCT}_{event_type}' if event_type != 'alerts' else PRODUCT
            send_events_to_xsiam(
                events_list,
                vendor=VENDOR,
                product=product
            )
            demisto.debug(f'debug-log: {len(events)} events were sent to XSIAM.')
    else:
        demisto.debug('debug-log: No new events fetched. Sending 0 to XSIAM.')
        send_events_to_xsiam(events=[], vendor=VENDOR, product=PRODUCT)

    demisto.debug(f'debug-log: setting {next_run=}')
    demisto.setLastRun(next_run)


def events_to_command_results(events: dict[str, list], event_type) -> CommandResults:
    """ Return a CommandResults object with a table of fetched events.

    Args:
        events [dict[str, Any]]: fetched events.
        event_type str: type of the fetched events.

    Returns:
        CommandResults: CommandResults containing table of fetched events.
    """
    events_output = events[event_type] if events else []
    product = f'{PRODUCT}_{event_type}' if event_type != 'alerts' else PRODUCT
    return CommandResults(raw_response=events_output,
                          readable_output=tableToMarkdown(name=f'{VENDOR} {product} events',
                                                          t=events_output,
                                                          removeNull=True))


def set_last_run_for_last_minute(last_run: dict) -> None:
    """ Set last fetch time values for all event types to current time.
        This will set a fetch starting time until events are fetched for each event type.
    Args:
        last_run (dict): Last run dictionary.
    """
    now: datetime = datetime.now() - timedelta(minutes=1)
    now_str: str = now.strftime(DATE_FORMAT)
    for event_type in EVENT_TYPES.values():
        last_fetch_time = f'{event_type.type}_last_fetch_time'
        last_run[last_fetch_time] = now_str


def should_run_device_fetch(last_run,
                            device_fetch_interval: timedelta | None,
                            datetime_now: datetime):
    """
    Args:
        last_run: last run object.
        device_fetch_interval: device fetch interval.
        datetime_now: time now

    Returns: True if fetch device interval time has passed since last time that fetch run.

    """
    if not device_fetch_interval:
        return False
    if last_fetch_time := last_run.get(DEVICES_LAST_FETCH):
        last_fetch_datetime = parser.parse(last_fetch_time).replace(tzinfo=None)
    else:
        # first time device fetch
        return True
    demisto.debug(f'Should run device fetch? {last_fetch_datetime=}, {device_fetch_interval=}')
    return datetime_now - last_fetch_datetime > device_fetch_interval


''' MAIN FUNCTION '''


def main():  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    last_run = demisto.getLastRun()
    access_token = last_run.get('access_token')
    api_key = params.get('credentials', {}).get('password')
    base_url = urljoin(params.get('server_url'), API_V1_ENDPOINT)
    verify_certificate = not params.get('insecure', True)
    max_fetch = arg_to_number(params.get('max_fetch')) or DEFAULT_MAX_FETCH
    devices_max_fetch = arg_to_number(params.get('devices_max_fetch')) or DEVICES_DEFAULT_MAX_FETCH
    proxy = params.get('proxy', False)
    event_types_to_fetch = argToList(params.get('event_types_to_fetch', []))
    event_types_to_fetch = [event_type.strip(' ') for event_type in event_types_to_fetch]
    should_push_events = argToBoolean(args.get('should_push_events', False))
    from_date = args.get('from_date')
    fetch_start_time = handle_from_date_argument(from_date) if from_date else None
    parsed_interval = dateparser.parse(params.get('deviceFetchInterval', '24 hours')) or dateparser.parse('24 hours')
    device_fetch_interval: timedelta = (datetime.now() - parsed_interval)  # type: ignore[operator]

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
            should_return_results = False

            if not last_run:  # initial fetch - update last fetch time values to current time
                set_last_run_for_last_minute(last_run)
                demisto.debug('debug-log: Initial fetch - updating last fetch time value to current time for each event type.')

            if command == 'armis-get-events':
                event_type_name = args.get('event_type')
                if aql := args.get('aql'):
                    EVENT_TYPES[event_type_name].aql_query = aql
                event_type: EVENT_TYPE = EVENT_TYPES[event_type_name]
                last_run = {}
                should_return_results = True
                event_types_to_fetch = [event_type_name]

            should_push_events = (command == 'fetch-events' or should_push_events)

            events, next_run = fetch_events(
                client=client,
                max_fetch=max_fetch,
                devices_max_fetch=devices_max_fetch,
                last_run=last_run,
                fetch_start_time=fetch_start_time,
                event_types_to_fetch=event_types_to_fetch,
                device_fetch_interval=device_fetch_interval
            )
            for key, value in events.items():
                demisto.debug(f'debug-log: {len(value)} events of type: {key} fetched from armis api')

            if should_push_events:
                handle_fetched_events(events, next_run)

            if should_return_results:
                return_results(events_to_command_results(events=events, event_type=event_type.dataset_name))

        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
