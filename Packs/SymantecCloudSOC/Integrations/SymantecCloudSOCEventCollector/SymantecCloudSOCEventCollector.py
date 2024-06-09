import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *
import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
DATE_FORMAT_SYMANTEC = '%Y-%m-%dT%H:%M:%S'
VENDOR = 'symantec'
PRODUCT = 'cloud_soc'
LOG_TYPES = {"Investigate_logs": {"app": "Investigate", "subtype": "all"},
             "Incident_logs": {"app": "Detect", "subtype": "incidents"}}
MAX_LIMIT_PER_CALL = 1000

''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client class to interact with Symantec Cloud SOC service API.
    """

    def __init__(self, base_url, verify, proxy, headers):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def get_events_request(self, max_fetch: int | None, app: str | None = None, subtype: str | None = None,
                           next_url: str | None = None, created_timestamp: str = None
                           ) -> tuple[list, str | None]:
        """ Retrieve information about events.
            Args:
                max_fetch (int): Limit number of returned records.
                subtype (str): The subtype (URL parameters to specify the query)
                app (str): The app type (URL parameters to specify the query).
                next_url (Optional[str]): The token to the next page.
                created_timestamp (str): The created timestamp.
            Returns:
                logs (list): A list of dictionaries with the event details
                next_url (str): The a next url from response.
                total (int): The number of results.
        """
        response = {}
        # max limit for the API is 1000
        max_fetch = min(max_fetch, MAX_LIMIT_PER_CALL) if max_fetch else MAX_LIMIT_PER_CALL
        if next_url:
            demisto.debug(
                f'SymantecEventCollector: Get events request full_url: {next_url}')
            response = self._http_request(method='GET', full_url=next_url, headers=self._headers)
        else:
            params = assign_params(app=app, subtype=subtype, limit=max_fetch,
                                   created_timestamp=created_timestamp)
            demisto.debug(f'SymantecEventCollector: Get events request params: {params}')
            response = self._http_request(method='GET', headers=self._headers, params=params)
        return response.get("logs", []), response.get("next_url")


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): HelloWorld client to use.
        params (dict): Integration parameters.
        first_fetch_time (int): The first fetch time as configured in the integration params.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    try:
        for log_type, url_params in LOG_TYPES.items():
            demisto.debug(f'test_module: {log_type}')
            app = url_params.get("app")
            # created_timestamp is mandatory for investigate.
            if app == 'Investigate':
                client.get_events_request(max_fetch=1, app=app,
                                          subtype=url_params.get("subtype"),
                                          created_timestamp=datetime.now(timezone.utc).strftime(DATE_FORMAT))
            else:
                client.get_events_request(max_fetch=1, app=app, subtype=url_params.get("subtype"))

    except Exception as e:
        demisto.debug(f'SymantecEventCollector: {str(e)}')
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    return 'ok'


def get_all_events(client: Client, first_fetch_time: str,
                   first_fetch_time_investigate: str,
                   last_run: dict[str, dict],
                   limit: int = MAX_LIMIT_PER_CALL) -> tuple[list, list, dict]:
    """
    Gets all the events Symantec API for all log types.
    Args:
        client (Client): Symantec Cloud SOC client to use.
        first_fetch_time (str): The timestamp on when to start fetching events.
        first_fetch_time_investigate (str): The timestamp on when to start fetching events for investigate.
        limit (int): The limit of the results to return per log_type.
        last_run (dict): A dict with a key containing the latest event time we got from last fetch.
    Returns:
        investigate_logs_events (list): A list contains the investigate type logs.
        incident_logs_events (list): A list contains the incident type logs.
        new_last_run (dict): A dict with last run details for all log types.
    """
    # Initialize an empty lists of events to return
    # Each event is a dict with a string as a key
    demisto.debug(f'last_run in the get_all_events is {last_run}')
    investigate_logs_events: list[dict[str, Any]] = []
    incident_logs_events: list[dict[str, Any]] = []
    # Initialize an empty next_run object to return for each log type
    next_run: dict[str, dict] = {}
    # Initialize an empty next_run object to return
    new_last_run: dict = {}
    for log_type in LOG_TYPES:
        log_events, next_run = get_all_events_for_log_type(
            client=client,
            log_type=log_type,
            max_fetch=limit,
            last_run=last_run,
            first_fetch_time=first_fetch_time,
            first_fetch_time_investigate=first_fetch_time_investigate,
        )
        demisto.debug(f'SymantecEventCollector: Got {len(log_events)} events from log type: {log_type}')
        if log_type == "Investigate_logs":
            investigate_logs_events.extend(log_events)
        else:
            incident_logs_events.extend(log_events)
        new_last_run[log_type] = next_run
        demisto.debug(f'SymantecEventCollector: Setting new last run - {next_run} for {log_type}')
    demisto.debug(f'last_run in the get_all_events is {last_run}')
    return investigate_logs_events, incident_logs_events, new_last_run


def get_events_command(client: Client, first_fetch_time: str,
                       first_fetch_time_investigate: str,
                       last_run: dict[str, dict],
                       limit: int = MAX_LIMIT_PER_CALL) -> tuple[list[dict[str, Any]], CommandResults]:
    """
    Gets all the events Symantec API for each log type.
    Args:
        client (Client): Symantec Cloud SOC client to use.
        first_fetch_time (str): The timestamp on when to start fetching events.
        first_fetch_time_investigate (str): The timestamp on when to start fetching events for investigate.
        limit (int): The limit of the results to return per log_type.
        last_run (dict): A dict with a key containing the latest event time we got from last fetch.
    Returns:
        list: A list contains the events
        CommandResults: A CommandResults object that contains the events in a table format.
    """

    events: list[dict] = []
    investigate_logs_events: list = []
    incident_logs_events: list = []
    hr = ""
    demisto.debug(f'SymantecEventCollector: last_run is {last_run}')
    investigate_logs_events, incident_logs_events, _ = get_all_events(client, first_fetch_time,
                                                                      first_fetch_time_investigate,
                                                                      last_run, limit)
    if investigate_logs_events:
        events.extend(investigate_logs_events)
        hr += tableToMarkdown(
            name="Investigate Logs Events",
            t=investigate_logs_events,
            headerTransform=string_to_table_header,
            headers=["_id", "user_name", "_domain", "severity", "service", "created_timestamp", "message"],
        )
    else:
        hr += "No events found for investigate logs.\n"
    if incident_logs_events:
        events.extend(incident_logs_events)
        hr += tableToMarkdown(
            name="Incident Logs Events",
            t=incident_logs_events,
            headerTransform=string_to_table_header,
            headers=["_id", "message", "incident_start_time", "service", "hosts", "locations", "severity"],
        )
    else:
        hr += "No events found for incident logs.\n"

    return events, CommandResults(readable_output=hr, raw_response=events)


def add_fields_to_event(event: dict, log_type: str) -> None:
    """
    Adds the _time and type keys to the events.
    Args:
        events (List[Dict]): A list of events to add the _time and type keys to.
    Returns:
        list: The events with the _time and type keys.
    """
    if event:
        if log_type == "Incident_logs":
            event['_time'] = event.get('incident_start_time')
            event['type'] = "Detect incident"
        elif log_type == "Investigate_logs":
            event['_time'] = event.get('created_timestamp')
            event['type'] = "Investigate"


def get_date_timestamp(str_date: str) -> datetime:
    """
    Dedup mechanism for the fetch to check both log_id and created_timestamp/incident_start_time
    (since timestamp can be duplicate)
    Args:
        str_date (dict): A string that represents a date.
    Returns:
        - (datetime) A date.
    """
    try:

        return datetime.strptime(str_date, DATE_FORMAT_SYMANTEC)
    except ValueError:
        return datetime.strptime(str_date, DATE_FORMAT)


def dedup_by_id(last_run: dict, events: list, log_type: str, limit: int,
                number_of_events: int, last_fetch: str) -> tuple[list, dict]:
    """
    Dedup mechanism for the fetch to check both log_id and created_timestamp/incident_start_time
    (since timestamp can be duplicate)
    Args:
        last_run (dict): Last run.
        events (list): List of the events from the API.
        log_type (str): the log type.
        limit (int): The number of events to return.
        number_of_events (int): The number of event we already fetched
        last_fetch (str): Last fetch time.
    Returns:
        - list of events to send to XSIAM.
        - The new last_run (dictionary with the relevant timestamps and the events ids).
        - The new last_run timestamps.
    """
    last_run_ids = dict_safe_get(last_run, [f'{log_type}-ids'], default_return_value=[])
    last_run_time = dict_safe_get(last_run, ["last_run"]) or last_fetch
    new_events: list = []
    new_events_ids = []
    new_last_run: dict = {}
    new_last_run_time: str = last_run_time
    new_last_run_time_date = get_date_timestamp(new_last_run_time)
    # The logs sort by asc by default
    if events:
        for event in events:
            if len(new_events) + number_of_events < limit:
                event_timestamp = (event.get("incident_start_time")
                                   if log_type == "Incident_logs"
                                   else event.get("created_timestamp"))  # log type is Investigate_logs
                event_id = event.get('_id')
                # The event we are looking at has the same timestamp as previously fetched events
                if event_timestamp == last_run_time:
                    if event_id not in set(last_run_ids):
                        new_events.append(event)
                        last_run_ids.append(event_id)
                # The event has a timestamp we have not yet fetched meaning it is a new event
                else:
                    new_events.append(event)
                    new_events_ids.append(event_id)
                    # If the event has a timestamp newer than the saved one, we will update the last run to the
                    # current event time
                    event_timestamp_date = get_date_timestamp(event_timestamp)
                    if new_last_run_time_date < event_timestamp_date:
                        new_last_run_time = event_timestamp
                    else:
                        demisto.debug(f'SymantecEventCollector: new_last_run_time is {new_last_run_time}'
                                      f'event_timestamp is {event_timestamp} and command is {demisto.command()}')
                new_last_run_time_date = get_date_timestamp(new_last_run_time)
                add_fields_to_event(event, log_type)

        # If we have received events with a newer time (new_event_ids list) we save them,
        # otherwise we save the list that include the old ids together with the new event ids (last_run_ids).
        last_run_time_date = get_date_timestamp(last_run_time)
        if (last_run_time_date < new_last_run_time_date) and new_events_ids:
            new_last_run[f'{log_type}-ids'] = new_events_ids
        else:
            new_events_ids.extend(last_run_ids)
            new_last_run[f'{log_type}-ids'] = new_events_ids
        # new last_run is new_last_run_time if exists else last_run_time
        new_last_run["last_run"] = new_last_run_time or last_run_time
    # If we dont have any events last_run is still the last run time
    elif last_run_time:
        new_last_run["last_run"] = last_run_time
    demisto.debug(f'SymantecEventCollector: Setting new last run - {new_last_run} for {log_type}')
    return new_events, new_last_run


def get_all_events_for_log_type(client: Client, max_fetch: int, log_type: str, last_run: dict[str, dict],
                                first_fetch_time: str, first_fetch_time_investigate: str):
    """
    Gets all the events for a specific log type.
    Args:
        client (Client): Symantec Cloud SOC client to use.
        max_fetch (int): Maximum numbers of events per fetch.
        log_type (str): The log type.
        last_run (Dict): last run object.
        first_fetch_time (str): The timestamp on when to start fetching events.
        first_fetch_time_investigate (str): The timestamp on when to start fetching events for investigate.
    Returns:
        Client: Client class to interact with Symantec Cloud SOC service API.
    """
    demisto.debug(f'SymantecEventCollector: last_run is {last_run}')
    next_url: str | None = ''
    all_events_list: list = []
    subtype = dict_safe_get(LOG_TYPES, [log_type, "subtype"])
    app = dict_safe_get(LOG_TYPES, [log_type, "app"])
    last_fetch = dict_safe_get(last_run, [log_type, "last_run"])
    last_run_for_log_type = dict_safe_get(last_run, [log_type])
    if not last_fetch:
        last_fetch = first_fetch_time_investigate if log_type == "Investigate_logs" else first_fetch_time
        demisto.debug(f"SymantecEventCollector: last_fetch {last_fetch}; for log type: {log_type}")
    while next_url is not None and len(all_events_list) < max_fetch:
        number_of_events = len(all_events_list)
        log_events, next_url = client.get_events_request(
            max_fetch=MAX_LIMIT_PER_CALL,
            subtype=subtype,
            app=app,
            created_timestamp=last_fetch,
            next_url=next_url)
        list_of_events, last_run_for_log_type = dedup_by_id(last_run_for_log_type, log_events, log_type,
                                                            max_fetch, number_of_events, last_fetch)
        all_events_list.extend(list_of_events)
    demisto.debug(f'SymantecEventCollector: last_run is {last_run}')
    return all_events_list, last_run_for_log_type


def fetch_events_command(client: Client, max_fetch: int, last_run: dict[str, dict],
                         first_fetch_time: str,
                         first_fetch_time_investigate: str) -> tuple[dict, list[dict]]:
    """
    This function retrieves new events every interval (default is 1 minute).
    It has to implement the logic of making sure that events are fetched only onces and no events are missed.
    By default it's invoked by XSIAM every minute. It will use last_run to save the timestamp of the last event it
    processed. If last_run is not provided, it should use the integration parameter first_fetch_time to determine when
    to start fetching the first time.

    Args:
        client (Client): Symantec Cloud SOC client.
        max_fetch (int): Maximum numbers of events per fetch.
        last_run (dict): A dict with a key containing the latest event created time we got from last fetch.
        first_fetch_time(str): The timestamp in on when to start fetching events.
        first_fetch_time_investigate (datetime): The timestamp in on when to start fetching events for investigate app.
    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of events that will be created in XSIAM.
    """
    # Initialize an empty list of events to return
    # Each event is a dict with a string as a key
    events: list[dict[str, Any]] = []
    # Initialize an empty next_run object to return
    new_last_run: dict = {}
    investigate_logs_events, incident_logs_events, new_last_run = get_all_events(client, first_fetch_time,
                                                                                 first_fetch_time_investigate,
                                                                                 last_run, max_fetch)
    demisto.debug(f"SymantecEventCollector: Returning {len(events)} events in total")
    events.extend(investigate_logs_events)
    events.extend(incident_logs_events)
    return new_last_run, events


def create_client_with_authorization(base_url: str, verify_certificate: bool,
                                     proxy: bool, key_id: str, key_secret: str) -> Client:
    """
    Creates a client with basic access authentication.
    Args:
        base_url (str): Symantec Cloud SOC base URL.
        verify_certificate (bool): Whether the request should verify the SSL certificate.
        proxy (bool): Whether to run the integration using the system proxy.
        key_id (str): Symantec Cloud SOC key ID.
        key_secret (str): Symantec Cloud SOC key secret.
    Returns:
        Client: Client class to interact with Symantec Cloud SOC service API.
    """
    credentials = f'{key_id}:{key_secret}'
    encoded_credentials = base64.b64encode(credentials.encode()).decode()
    headers = {
        'Authorization': f'Basic {encoded_credentials}',
        'X-Elastica-Dbname-Resolved': 'True'
    }
    return Client(base_url=base_url,
                  verify=verify_certificate,
                  headers=headers,
                  proxy=proxy)


def get_first_fetch_time(params: dict) -> tuple[str, str]:
    """
    Gets a first_fetch_time arg for investigate logs and detect incidents logs.
    Args:
        params (dict): Parameters from XSIAM.
    Returns:
        first_fetch_str (str): first fetch.
        first_fetch_time_investigate_str (str): first fetch for investigate log type.
    """
    # How much time before the first fetch to retrieve events
    first_fetch = params.get('first_fetch', '3 days')
    first_fetch_time: datetime = arg_to_datetime(arg=first_fetch,
                                                 arg_name='First fetch time',
                                                 required=True)  # type: ignore[assignment]
    first_fetch_str = first_fetch_time.strftime(DATE_FORMAT_SYMANTEC)
    # API limitation for created_timestamp is 6 months.
    days_ago_limitation: datetime = dateparser.parse('180 days', settings={'TIMEZONE': 'UTC'})  # type: ignore[assignment]
    demisto.debug(f'SymantecEventCollector: first fetch time: {first_fetch_time}')
    # For investigate app type the created_timestamp must be less than 6 months.
    first_fetch_time_investigate: datetime = first_fetch_time
    if first_fetch_time_investigate <= days_ago_limitation:
        first_fetch_time_investigate = days_ago_limitation
    first_fetch_time_investigate_str = first_fetch_time_investigate.strftime(DATE_FORMAT_SYMANTEC)
    return first_fetch_str, first_fetch_time_investigate_str


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """
    params: dict = demisto.params()
    args = demisto.args()
    command = demisto.command()
    key_id = params.get('credentials', {}).get('identifier')
    key_secret = params.get('credentials', {}).get('password')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    max_fetch = arg_to_number(params.get('max_fetch')) or 1000
    first_fetch_time, first_fetch_time_investigate = get_first_fetch_time(params)
    # get the service API url
    base_url = urljoin(params.get('url'), '/api/admin/v1/logs/get/')
    demisto.debug(
        f'SymantecEventCollector: First fetch timestamp: {first_fetch_time} '
        f'First fetch timestamp investigate: {first_fetch_time_investigate}')
    demisto.info(f'SymantecEventCollector: Command being called is {command}')
    try:
        client = create_client_with_authorization(base_url, verify_certificate, proxy, key_id, key_secret)
        last_run = demisto.getLastRun()
        demisto.debug(f'SymantecEventCollector: last run is: {demisto.getLastRun()}')
        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

        elif command in ('symantec-cloudsoc-get-events', 'fetch-events'):
            if command == 'symantec-cloudsoc-get-events':
                demisto.debug(f'SymantecEventCollector: last_run in the get_events_command is {last_run}')
                should_push_events = argToBoolean(args.pop('should_push_events'))
                events, results = get_events_command(client=client,
                                                     limit=arg_to_number(args.get("limit")) or MAX_LIMIT_PER_CALL,
                                                     first_fetch_time=first_fetch_time,
                                                     first_fetch_time_investigate=first_fetch_time_investigate,
                                                     last_run=last_run)
                return_results(results)
                if should_push_events:
                    send_events_to_xsiam(
                        events,
                        vendor=VENDOR,
                        product=PRODUCT
                    )

            else:  # command == 'fetch-events':
                demisto.debug(f'SymantecEventCollector: last_run in the fetch_events_command is {last_run}')
                next_run, events = fetch_events_command(
                    client=client,
                    max_fetch=arg_to_number(max_fetch) or MAX_LIMIT_PER_CALL,
                    first_fetch_time=first_fetch_time,
                    first_fetch_time_investigate=first_fetch_time_investigate,
                    last_run=last_run,
                )

                send_events_to_xsiam(
                    events,
                    vendor=VENDOR,
                    product=PRODUCT
                )

                # saves next_run for the time fetch-events is invoked
                demisto.debug(f"SymantecEventCollector: setting next_run to {next_run}")
                demisto.setLastRun(next_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
