import demistomock as demisto
from CommonServerPython import *
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """
VENDOR = "cisco"
PRODUCT = "appdynamics"

TOKEN_URL = "/controller/api/oauth/access_token"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"
DAY_IN_MS = 24 * 60 * 60 * 1000

DEFAULT_MAX_AUDIT = 100
DEFAULT_MAX_HEALTH = 3000

HEALTH_RULE_API_LIMIT = 600


class EventType:
    """
    This class defines a CybelAngel API Event – used to dynamically store
    per-type settings for fetching and deduplicating events.
    """

    def __init__(self, name: str, url_suffix: str, time_field: str, source_log_type: str, default_params: dict = {}):
        """
        Args:
            name (str): Human-friendly name of the event type.
            url_suffix (str): URL suffix of the CybelAngel API endpoint (no leading slash).
            id_key (Union[str, List[str]]): Key or list of keys used to uniquely identify an event.
            ascending_order (bool): If the API return in sorted by ascending or descending order after returning from get_event.
            time_field (str): Field name in the event used for timestamp mapping (`_time`).
            source_log_type (str): Value to assign to each event’s `source_log_type` field in XSIAM.
        """
        self.name = name
        self.url_suffix = url_suffix
        self.max_fetch = 1
        self.time_field = time_field
        self.source_log_type = source_log_type
        self.default_params = default_params


""" CLIENT CLASS """

AUDIT = EventType(
    name="Audit",
    url_suffix="/controller/ControllerAuditHistory",
    time_field="timeStamp",
    source_log_type="Audit History",
)

HEALTH_EVENT = EventType(
    name="Healthrule Violations Events",
    url_suffix="",
    time_field="detectedTimeInMillis",
    source_log_type="Healthrule Violations Event",
    default_params={
        "time-range-type": "BETWEEN_TIMES",
        "output": "JSON",
    },
)

EVENT_TYPE = {"Audit": AUDIT, "Healthrule Violations Events": HEALTH_EVENT}


class Client(BaseClient):
    """
    Client class to interact with the service API
    """

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        verify: bool,
        proxy: bool,
    ) -> None:
        """
        Initializes the Client.
        """
        super().__init__(base_url=base_url, verify=verify, headers={}, proxy=proxy)
        self.client_id = client_id
        self.client_secret = client_secret
        self.token: str | None = None
        self.token_expiry: datetime | None = None

    def create_access_token(self) -> str:
        """
        Generates a new access token via the OAuth API.
        Stores the token and computes its expiry time.

        Returns:
            str: The new access token.
        """
        demisto.debug("Requesting new access token from AppDynamics OAuth API")

        params = {"grant_type": "client_credentials"}
        payload = {"client_id": self.client_id, "client_secret": self.client_secret}
        response = self._http_request(method="POST", url_suffix=TOKEN_URL, params=params, json_data=payload)
        access_token = response.get("access_token")
        expires_in = response.get("expires_in")
        demisto.debug(f"Access token expire in: {expires_in}")  # TODO
        self.token = access_token
        self.token_expiry = datetime.now(timezone.utc) + timedelta(seconds=int(expires_in) - 10)
        demisto.debug(f"Access token obtained, expires at {self.token_expiry.isoformat()}")
        set_integration_context({"access_token": access_token, "token_expiry": self.token_expiry.isoformat()})
        return access_token

    def _get_valid_token(self) -> str:
        """
        Returns a valid access token, generating a new one if necessary.
        """
        integration_context = get_integration_context()
        access_token = integration_context.get("access_token", "")
        token_expiry = integration_context.get("token_expiry", "")

        if not access_token or not token_expiry:
            demisto.debug("Token doesn't exists")
            return self.create_access_token()

        elif datetime.now(timezone.utc) >= datetime.fromisoformat(token_expiry):
            demisto.debug("Token Expired")
            return self.create_access_token()
        return access_token

    def _authorized_request(self, url_suffix: str, params: dict) -> list[dict]:
        """
        Wrapper for _http_request() that validate the token then adds it to the headers.
        Adds output="JSON" to params to return JSON format.
        Args:
            url_suffix (str): the url_suffix as described in the API docs foreach request type.
            params (Dict): hold time interval and additional params for the request.
        Return:
            List[Dict]: JSON-decoded list of events.
        """
        token = self._get_valid_token()
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

    def get_audit_logs(self, start_time: datetime, end_time: datetime) -> list[dict]:
        """
        Fetches audit-history events.
        If start_dt is more than 24 hours before end_dt, it will be adjusted to be exactly 24 hours before end_dt.
        If start_dt bigger or equal to end_dt return empty list.
        The API limit is 24 hours time interval.
        Args:
            start_dt (datetime): start time.
            end_dt (datetime):   end time.
        Returns:
            List[Dict]: JSON-decoded list of audit events.
        """
        max_delta = timedelta(hours=24)
        if end_time - start_time > max_delta:
            demisto.debug("Start time is more than 24 hours before end time. Adjusting start time to end time minus 24 hours.")
            start_time = end_time - max_delta

        if start_time >= end_time:
            demisto.debug("Start time is bigger than or equal to end time")
            return []

        params = {"startTime": start_time.strftime(DATE_FORMAT)[:-3] + "Z", "endTime": end_time.strftime(DATE_FORMAT)[:-3] + "Z"}

        demisto.debug(f"Fetching audit logs from {params['startTime']} to {params['endTime']}")

        events = self._authorized_request(
            url_suffix=AUDIT.url_suffix,
            params=params,
        )
        demisto.debug(f"Received {len(events)} audit logs from API.")

        add_fields_to_events(events, AUDIT)
        events.sort(key=lambda ev: ev["_time"] or "")

        return events

    def get_health_events(self, start_time: datetime, end_time: datetime) -> list[dict]:
        """
        Fetches all Healthrule Violations Events in a loop,
        using the API's BETWEEN_TIMES.
        start-time and end-time are in milliseconds.
        Args:
            from_date: datetime.
            to_date:   datetime.
        Returns:
            list[Dict]: list of all events.
        """
        events: list[dict] = []
        params = HEALTH_EVENT.default_params.copy()
        demisto.debug("Fetching Healthrule Violations Events")
        start_time = str(int(start_time.astimezone(timezone.utc).timestamp() * 1000))  # type: ignore
        end_time = str(int(end_time.astimezone(timezone.utc).timestamp() * 1000))  # type: ignore
        while len(events) <= HEALTH_EVENT.max_fetch:
            params.update({"start-time": start_time, "end-time": end_time})
            batch = self._authorized_request(url_suffix=HEALTH_EVENT.url_suffix, params=params)
            demisto.debug(f"Fetched {len(batch)} events successfully.")
            if not batch:
                break
            events.extend(batch)
            if len(batch) < HEALTH_RULE_API_LIMIT:
                break
            start_time = events[-1][HEALTH_EVENT.time_field]

        demisto.debug(f"Fetched {len(events)} Healthrule Violations Events from API.")
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
    current_time = datetime.now(timezone.utc)
    last_run = get_last_run(current_time, events_type_to_fetch)
    demisto.debug(f"fetch_events::Current time: {current_time}")

    event_fetch_function = {
        AUDIT.name: client.get_audit_logs,
        HEALTH_EVENT.name: client.get_health_events,
    }

    for event_type in events_type_to_fetch:
        demisto.debug(f"Fetching {event_type.name}")
        last_time = last_run[event_type.name]
        demisto.debug(f"Last run {last_time}")
        events = event_fetch_function[event_type.name](
            start_time=last_time,
            end_time=current_time,
        )
        demisto.debug(f"Fetched {len(events)} events")
        if events:
            events = events[: event_type.max_fetch]
            all_events.extend(events)
            last_run[event_type.name] = events[-1]["_time"]
        else:
            last_run[event_type.name] = current_time.strftime(DATE_FORMAT)[:-3] + "Z"  # type: ignore

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
        event["_time"] = timestamp_ms_to_iso(event.get(event_type.time_field))  # type: ignore
        event["SOURCE_LOG_TYPE"] = event_type.source_log_type

    return events


def test_module_command(client: Client):  # pragma: no cover
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
    fetch_events(client, set_event_type_fetch_limit(demisto.params()))
    return "ok"


def get_events(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    A test‐driven version of fetch_events.

    Args (in `args` dict):
      - start_time (str): ISO 8601 string, e.g. "2025-04-27T10:00:00Z"
      - end_time   (str): ISO 8601 string, e.g. "2025-04-27T10:05:00Z"
      - limit      (str): comma-separated list of event types to fetch,
                         e.g. "Audit,Healthrule Violations Events".
      - should_push_events (bool): push events to XSIAM.

    Returns:
      - CommandResults: include human readable from the events.
    """
    args = demisto.args()
    event_type_name = EVENT_TYPE[args.get("events_type_to_fetch", AUDIT.name)].name
    limit = int(args.get("limit", 50))
    now = datetime.now()
    end_date = args.get("end_date") or now.strftime(DATE_FORMAT)
    end_dt = dateparser.parse(end_date) or now
    start_date_dt = args.get("start_date") or (end_dt - timedelta(minutes=1)).strftime(DATE_FORMAT)

    event_fetch_function = {
        AUDIT.name: client.get_audit_logs,
        HEALTH_EVENT.name: client.get_health_events,
    }

    fetch_func = event_fetch_function.get(event_type_name)  # type: ignore
    events = fetch_func(start_date=start_date_dt, end_date=end_dt, limit=limit)  # type: ignore
    events = events[:limit]
    if argToBoolean(args.get("is_fetch_events") or False):
        send_events_to_xsiam(vendor=VENDOR, product=PRODUCT, events=events)
        demisto.debug(f"Successfully send {len(events)} to XSIAM.")
    return CommandResults(
        outputs_prefix="CybleAngel.Events",
        outputs=events,
        raw_response=events,
        readable_output=tableToMarkdown(f"{event_type_name}", events, headers=["_time", "SOURCE_LOG_TYPE"], removeNull=False),
    )


def parse_iso_millis_z(s: str) -> datetime:
    """
    Turn "2025-05-25T16:07:53.127Z" into a timezone-aware datetime.
    """
    # replace the 'Z' with '+00:00' so fromisoformat can parse it
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def timestamp_ms_to_iso(ts_ms: str) -> str:
    """
    Turn a millisecond‐since‐epoch int into "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    """
    dt = datetime.fromtimestamp(int(ts_ms) / 1000, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def get_last_run(now: datetime, events_type_to_fetch: list[EventType]) -> dict[str, datetime]:
    """
    Retrieve and initialize the “last run” timestamps for a set of event types.
    This function loads the existing last‐run state via `demisto.getLastRun()`.
    For any event type that is missing or newly requested, it sets:
      - `EVENT_TYPE.name` to one minute before `now`.
    Args:
        now (datetime): Reference time for computing initial fetch timestamps.
        events_to_fetch (List[str]): Names of event types that should be tracked this run.
    Returns:
        Dict[str, Dict[str, Any]]: A mapping of each event type to its last-run info:
            {
                "EVENT_TYPE.name": LATEST_TIME: "<ISO-formatted timestamp string>"
            }
    """
    raw_last_run = demisto.getLastRun() or {}
    last_run = {}

    for event_type in EVENT_TYPE.values():
        last_time_iso = raw_last_run.get(event_type.name)
        if last_time_iso and event_type in events_type_to_fetch:
            dt = parse_iso_millis_z(last_time_iso)
        else:
            dt = now - timedelta(minutes=1)
        last_run[event_type.name] = dt

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
    event_types_to_fetch = argToList(params.get("event_types_to_fetch", [AUDIT.name, HEALTH_EVENT.name]))
    event_types_to_fetch = [event_type.strip(" ") for event_type in event_types_to_fetch]
    demisto.debug(f"List:{event_types_to_fetch}, list length:{len(event_types_to_fetch)}")
    max_fetch_audit = arg_to_number(params.get("max_audit_fetch")) or AUDIT.max_fetch
    max_fetch_health = arg_to_number(params.get("max_healthrule_fetch")) or HEALTH_EVENT.max_fetch

    application_id = params.get("application_id", "")

    event_types = []
    if AUDIT.name in event_types_to_fetch:
        AUDIT.max_fetch = max_fetch_audit
        event_types.append(AUDIT)

    if HEALTH_EVENT.name in event_types_to_fetch:
        HEALTH_EVENT.max_fetch = max_fetch_health
        event_types.append(HEALTH_EVENT)
        HEALTH_EVENT.url_suffix = f"/controller/rest/applications/{application_id}/problems/healthrule-violations"

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
    client_id = params.get("client_id", "")
    client_secret = params.get("client_secret", {}).get("password")
    verify = argToBoolean(not params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    demisto.debug(f"Command being called is {command}")
    try:
        client = Client(
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
            verify=verify,
            proxy=proxy,
        )

        if command == "test-module":
            return_results(test_module_command(client))

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
            return_results(get_events(client, args))

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
