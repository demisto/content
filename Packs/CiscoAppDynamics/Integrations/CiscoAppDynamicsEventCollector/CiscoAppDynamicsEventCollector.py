import demistomock as demisto
from CommonServerPython import *
import urllib3
from dateutil import parser

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """
VENDOR = "cisco"
PRODUCT = "appdynamics"

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


class EventType:
    """
    This class defines a CybelAngel API Event - used to dynamically store
    per-type settings for fetching and deduplicating events.
    """

    def __init__(
        self,
        name: str,
        url_suffix: str,
        time_field: str,
        max_fetch: int,
        source_log_type: str,
        api_limit: int = 0,
        default_params: dict = {},
    ):
        """
        Args:
            name            (str): Human-friendly name of the event type.
            url_suffix      (str): URL suffix of the CybelAngel API endpoint (no leading slash).
            time_field      (str): Field name in the event used for timestamp mapping (`_time`).
            max_fetch       (int): Default value for the maximum number of events to fetch.
            source_log_type (str): Value to assign to each event's `source_log_type` field in XSIAM.
            api_limit       (int): Maximum events that the API can retrieve in one call.
            default_params (dict): Dict to contain default parameters for the API calls.
        """
        self.name = name
        self.url_suffix = url_suffix
        self.max_fetch = max_fetch
        self.time_field = time_field
        self.source_log_type = source_log_type
        self.api_limit = api_limit
        self.default_params = default_params


""" CLIENT CLASS """

AUDIT = EventType(
    name="Audit",
    url_suffix="/ControllerAuditHistory",
    time_field="timeStamp",
    max_fetch=3000,
    source_log_type="Audit History",
)

HEALTH_EVENT = EventType(
    name="Health Rule Violations",
    url_suffix="/rest/applications/application_id/problems/healthrule-violations",
    time_field="startTimeInMillis",
    max_fetch=3000,
    source_log_type="Health Rule Violations",
    api_limit=600,
    default_params={
        "time-range-type": "BETWEEN_TIMES",
        "output": "JSON",
    },
)

EVENT_TYPES = {"Audit": AUDIT, "Health Rule Violations": HEALTH_EVENT}


class Client(BaseClient):
    """
    Client class to interact with the service API
    """

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        application_id: str,
        verify: bool,
        proxy: bool,
    ) -> None:
        """
        Initializes the Client.
        """
        super().__init__(base_url=base_url, verify=verify, headers={}, proxy=proxy)
        self.client_id = client_id
        self.client_secret = client_secret
        self.application_id = application_id

    def create_access_token(self) -> str:
        """
        Generates a new access token via the OAuth API.
        Stores the token and computes its expiry time.

        Returns:
            str: The new access token.
        """
        demisto.debug("Requesting new access token from AppDynamics OAuth API")

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        params = {"grant_type": "client_credentials", "client_id": self.client_id, "client_secret": self.client_secret}

        response = self._http_request(method="POST", url_suffix="/api/oauth/access_token", params=params, headers=headers)

        access_token = response.get("access_token")
        expires_in = response.get("expires_in")
        demisto.debug(f"Access token expire in: {expires_in}")
        token_expiry = datetime.now(timezone.utc) + timedelta(seconds=int(expires_in) - 15)

        demisto.debug(f"Access token obtained, expires at {token_expiry.isoformat()}")
        set_integration_context({"access_token": access_token, "token_expiry": token_expiry.isoformat()})
        return access_token

    def get_access_token(self) -> str:
        """
        Returns a valid access token, generating a new one if necessary.
        """
        integration_context = get_integration_context()

        access_token = integration_context.get("access_token", "")
        token_expiry = integration_context.get("token_expiry", "")

        if not access_token or not token_expiry:
            demisto.debug("Token doesn't exists, requesting new token.")
            return self.create_access_token()

        if datetime.now(timezone.utc) >= datetime.fromisoformat(token_expiry):
            demisto.debug("Token Expired, requesting new token.")
            return self.create_access_token()

        demisto.debug(f"Using cached access token. Expires at {token_expiry}")
        return access_token

    def authorized_request(self, url_suffix: str, params: dict) -> list[dict]:
        """
        Wrapper for _http_request() that validate the token then adds it to the headers.
        Adds output="JSON" to params to return JSON format.
        Args:
            url_suffix (str): the url_suffix as described in the API docs foreach request type.
            params (Dict): hold time interval and additional params for the request.
        Return:
            List[Dict]: JSON-decoded list of events.
        """
        token = self.get_access_token()
        headers = {"Authorization": f"Bearer {token}"}
        params["output"] = "JSON"
        response = self._http_request(
            method="GET",
            url_suffix=url_suffix,
            params=params,
            headers=headers,
            resp_type="json",
        )
        return response

    def get_audit_logs(self, start_time: str, end_time: str) -> list[dict]:
        """
        Fetches audit-history events.
        API return all events from start_dt to end_dt include start and end.
        API return in ascending order.
        Args:
            start_dt (datetime): start time in the right format: '2015-12-19T10:50:03.607-0000'.
            end_dt (datetime):   end time in the right format: '2015-12-19T10:50:03.607-0000'.
        Returns:
            List[Dict]: JSON-decoded list of audit events.
        """
        params = {
            "startTime": start_time,
            "endTime": end_time,
        }
        demisto.debug(f"Fetching audit logs from {start_time} to {end_time}")

        events = self.authorized_request(
            url_suffix=AUDIT.url_suffix,
            params=params,
        )
        demisto.debug(f"Received {len(events)} audit logs from API.")

        return add_fields_to_events(events, AUDIT)

    def get_health_events(self, start_time: int, end_time: int) -> list[dict]:
        """
        Fetches all Health Rule Violations in a loop,
        using the API's BETWEEN_TIMES.
        start-time and end-time are in milliseconds.
        Args:
            from_date(int): timestamp.
            to_date  (int): timestamp.
        Returns:
            list[Dict]: list of all events.
        """
        events: list[dict] = []
        params = HEALTH_EVENT.default_params.copy()
        demisto.debug("Fetching Health Rule Violations")
        while len(events) <= HEALTH_EVENT.max_fetch:
            params.update(
                {
                    "start-time": start_time,
                    "end-time": end_time,
                }
            )
            batch = self.authorized_request(url_suffix=HEALTH_EVENT.url_suffix, params=params)
            demisto.debug(f"Fetched {len(batch)} events successfully.")
            if not batch:
                demisto.debug("No events fetched from API")
                break
            events.extend(batch)
            if len(batch) < HEALTH_EVENT.api_limit:
                demisto.debug(f"Fetched {len(batch)} events from API < API Limit {HEALTH_EVENT.api_limit} on the last page.")
                break
            start_time = events[-1][HEALTH_EVENT.time_field]

        demisto.debug(f"Fetched total {len(events)} Health Rule Violations from API.")
        return add_fields_to_events(events, HEALTH_EVENT)


def fetch_events(
    client: Client,
    events_type_to_fetch: list[EventType],
) -> tuple[list[dict], dict]:
    """
    Fetch events from the client based on the last run times and event types specified.

    Args:
        client (Client): The client instance to fetch events from.
        fetch_types (list[EventType]): A list of event types to fetch.

    Returns:
        tuple[List[Dict], Dict]: A tuple containing a list of fetched events and a dictionary with the next run times.
    """

    all_events = []
    current_time = int(time.time() * 1000)
    last_run = get_last_run(current_time, events_type_to_fetch)
    demisto.debug(f"fetch_events::Current time: {current_time}")

    event_fetch_function = {
        AUDIT.name: client.get_audit_logs,
        HEALTH_EVENT.name: client.get_health_events,
    }

    for event_type in events_type_to_fetch:
        demisto.debug(f"Fetching {event_type.name}")
        start_time = last_run[event_type.name]  # in timestamp
        demisto.debug(f"Last run {start_time}")
        events = event_fetch_function.get(event_type.name)(  # type: ignore
            start_time=timestamp_to_api_format(start_time, event_type),
            end_time=timestamp_to_api_format(current_time, event_type),
        )
        demisto.debug(f"Fetched {len(events)} events")
        if events:
            events = events[: event_type.max_fetch]
            all_events.extend(events)
            last_run[event_type.name] = int(events[-1][event_type.time_field]) + 1
        else:
            last_run[event_type.name] = current_time + 1

    demisto.debug(f"Total events fetched: {len(all_events)}")
    return all_events, last_run


def add_fields_to_events(events: list[dict], event_type: EventType) -> list[dict]:
    """
    Enriches each event dict with XSIAM fields, based on the provided source type.
    Args:
        events:     List of event dicts to enrich.
        event_type: The event type.
    Returns:
        The same list, with each dict now having:
          - '_time'           (int) timestamp taken from the correct field
          - 'SOURCE_LOG_TYPE' (str) set to event_type.source_log_type
    """
    if not events:
        return []
    for event in events:
        event["_time"] = timestamp_to_datestring(event[event_type.time_field], DATE_FORMAT, is_utc=True)
        event["SOURCE_LOG_TYPE"] = event_type.source_log_type

    return events


def test_module_command(client: Client, params: dict):  # pragma: no cover
    """
    Tests API connectivity and authentication
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): Cisco AppDynamics client to use.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    fetch_events(client, set_event_type_fetch_limit(params))
    return "ok"


def get_events(client: Client, args: dict[str, Any], params: dict[str, Any]) -> CommandResults:
    """
    A test‐driven version of fetch_events.

    Args (in `args` dict):
      - start_time (str): ISO 8601 string, e.g. "2025-04-27T10:00:00Z"
      - end_time   (str): ISO 8601 string, e.g. "2025-04-27T10:05:00Z"
      - limit      (str): comma-separated list of event types to fetch,
                         e.g. "Audit, Health Rule Violations".
      - should_push_events (bool): push events to XSIAM.

    Returns:
      - CommandResults: include human readable from the events.
    """
    event_type_name = args.get("events_type_to_fetch", AUDIT.name)
    if event_type_name == HEALTH_EVENT.name:
        HEALTH_EVENT.url_suffix = f"/rest/applications/{params['application_id']}/problems/healthrule-violations"
    limit = int(args.get("limit", 50))
    now = datetime.now(timezone.utc)
    end_time = parser.parse(args.get("end_date", "")) if args.get("end_date", "") else now
    start_time = parser.parse(args.get("start_date", "")) if args.get("start_date", "") else (now - timedelta(days=1))
    demisto.debug(f"Get events from {start_time} to {end_time}")
    event_fetch_function = {
        AUDIT.name: client.get_audit_logs,
        HEALTH_EVENT.name: client.get_health_events,
    }

    fetch_func = event_fetch_function[event_type_name]
    events = fetch_func(  # type: ignore
        start_time=datetime_to_api_format(start_time, EVENT_TYPES[event_type_name]),
        end_time=datetime_to_api_format(end_time, EVENT_TYPES[event_type_name]),
    )

    events = events[:limit]
    if argToBoolean(args.get("is_fetch_events", False)):
        send_events_to_xsiam(vendor=VENDOR, product=PRODUCT, events=events)
        demisto.debug(f"Successfully send {len(events)} to XSIAM.")
    return CommandResults(
        readable_output=tableToMarkdown(f"{event_type_name}", events),
    )


def timestamp_to_api_format(time: int, eventType: EventType) -> str | int:
    if eventType.name == AUDIT.name:
        ts_sec = time / 1000.0
        dt = datetime.fromtimestamp(ts_sec, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}" + "-0000"

    elif eventType.name == HEALTH_EVENT.name:
        return time
    return ""


def datetime_to_api_format(dt: datetime, eventType: EventType) -> str | int:
    if eventType.name == AUDIT.name:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}-0000"
    elif eventType.name == HEALTH_EVENT.name:
        return int(dt.timestamp() * 1000)
    return ""


def get_last_run(now: int, events_type_to_fetch: list[EventType]) -> dict[str, int]:
    """
    Retrieve and initialize the “last run” timestamps for a set of event types.
    This function loads the existing last‐run state via `demisto.getLastRun()`.
    For any event type that is missing or newly requested, it sets:
      - `EVENT_TYPES.name` to one minute before `now`.
    Args:
        now (datetime): Reference time for computing initial fetch timestamps.
        events_to_fetch (List[str]): Names of event types that should be tracked this run.
    Returns:
        Dict[str, Dict[str, Any]]: A mapping of each event type to its last-run info:
            {
                "AUDIT.name": timestamp int..
                "HEALTH.name" timestamp int.
            }
    """
    raw_last_run = demisto.getLastRun() or {}
    last_run = {}

    for event_type in EVENT_TYPES.values():
        last_time_iso = raw_last_run.get(event_type.name)
        if last_time_iso and event_type in events_type_to_fetch:
            last_run[event_type.name] = last_time_iso
        else:
            last_run[event_type.name] = now - (60 * 1000)

    return last_run


def set_event_type_fetch_limit(params: dict[str, Any]) -> list[EventType]:
    """
    Parses the event types to fetch from parameters and returns a dictionary mapping
    each selected event type's suffix to its corresponding max fetch limit.
    Args:
        params (Dict[str, Any]): Integration parameters.
    Returns:
        list[EventType]: List of event type to fetch from the api call.
    """
    application_id = params.get("application_id", "")
    event_types_to_fetch = [et.strip() for et in argToList(params.get("events_type_to_fetch", [AUDIT.name, HEALTH_EVENT.name]))]
    demisto.debug(f"List:{event_types_to_fetch}, list length:{len(event_types_to_fetch)}")
    fetch_limits = {
        AUDIT.name: arg_to_number(params.get("max_audit_fetch")) or AUDIT.max_fetch,
        HEALTH_EVENT.name: arg_to_number(params.get("max_healthrule_fetch")) or HEALTH_EVENT.max_fetch,
    }
    event_types = []
    for event_type in EVENT_TYPES.values():
        if event_type.name in event_types_to_fetch:
            event_type.max_fetch = fetch_limits[event_type.name]
            event_types.append(event_type)

    if HEALTH_EVENT.name in event_types_to_fetch:
        HEALTH_EVENT.url_suffix = f"/rest/applications/{application_id}/problems/healthrule-violations"

    return event_types


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    base_url = params.get("url", "")
    client_id = params.get("credentials", {}).get("identifier")
    client_secret = params.get("credentials", {}).get("password")
    application_id = params.get("application_id", "")
    verify = argToBoolean(not params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    demisto.debug(f"Command being called is {command}")
    try:
        client = Client(
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
            application_id=application_id,
            verify=verify,
            proxy=proxy,
        )

        if command == "test-module":
            return_results(test_module_command(client, params))

        elif command == "fetch-events":
            events, next_run = fetch_events(
                client,
                set_event_type_fetch_limit(params),
            )
            demisto.debug(f"Sending {len(events)} events to XSIAM.")
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.debug("Sent events to XSIAM successfully")
            demisto.debug(
                f"setLastRun going to set: Audit:{next_run.get(AUDIT.name,'')}, Health: {next_run.get(HEALTH_EVENT.name,'')}"
            )
            demisto.setLastRun(next_run)
            demisto.debug(f"Setting next run to {next_run}.")

        elif command == "cisco-appdynamics-get-events":
            return_results(get_events(client, args, params))

    except Exception as e:
        error_message = str(e)
        if "Verify that the server URL" in error_message or "Not Found" in error_message:
            return_error(
                f"Failed to execute {command} command.\n"
                "Error:\n"
                "Verify that the server URL parameter is correct and that you have access to the server from your host."
            )
        if "Unauthorized" in error_message:
            return_error(
                f"Failed to execute {command} command.\n"
                "Error:\n"
                "Verify that the server URL parameter and credentials are correct "
                "and that you have access to the server from your host."
            )
        if "Invalid application id" in error_message:
            return_error(f"Failed to execute {command} command.\nError:\nInvalid application id is specified.")
        return_error(f"Failed to execute {command} command.\nError:\n{error_message}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
