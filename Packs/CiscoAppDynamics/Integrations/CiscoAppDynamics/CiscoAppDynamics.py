import demistomock as demisto
from CommonServerPython import *
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """
VENDOR = "cisco"
PRODUCT = "appdynamics"

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"
AUDIT = "Audit"
HEALTH_EVENT = "Healthrule Violations Events"
DAY_IN_MS = 24 * 60 * 60 * 1000
GET_REQUEST = "GET"
POST_REQUEST = "POST"

DEFAULT_MAX_AUDIT = 100
DEFAULT_MAX_HEALTH = 3000

HEALTH_RULE_API_LIMIT = 600
""" CLIENT CLASS """


class Client(BaseClient):
    """
    Client class to interact with the service API
    """

    def __init__(self,
                 base_url: str,
                 client_id: str,
                 client_secret: str,
                 application_id: str,
                 max_audit_fetch: int,
                 max_healthrule_fetch: int,
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
        self.max_audit_fetch = max_audit_fetch
        self.max_healthrule_fetch = max_healthrule_fetch
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
        url_suffix = "/controller/api/oauth/access_token"
        params = {"grant_type": "client_credentials"}
        payload = {
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }
        response = self._http_request(
            method=POST_REQUEST,
            url_suffix=url_suffix,
            params=params,
            json_data=payload
        )
        access_token = response.get("access_token")
        expires_in = response.get("expires_in")
        demisto.debug(f"Access token expire in: {expires_in}") #TODO
        self.token = access_token
        self.token_expiry = datetime.now(timezone.utc) + timedelta(seconds=int(expires_in) - 10)
        demisto.debug(f"Access token obtained, expires at {self.token_expiry.isoformat()}")
        return access_token

    def _get_valid_token(self) -> str:
        """
        Returns a valid access token, generating a new one if necessary.
        """
        if not self.token or not self.token_expiry or datetime.now(timezone.utc) >= self.token_expiry:
            demisto.debug("Token not valid")
            return self.create_access_token()
        return self.token

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
        response = self._http_request(method=GET_REQUEST,
                                      url_suffix=url_suffix,
                                      params=params,
                                      headers=headers,
                                      resp_type="json",
                                      )

        return response

    def get_audit_logs(self, start_dt: datetime, end_dt: datetime) -> list[dict]:
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
        if end_dt - start_dt > max_delta:
            demisto.debug("Start time is more than 24 hours before end time. Adjusting start time to end time minus 24 hours.")
            start_dt = end_dt - max_delta
        
        if start_dt >= end_dt:
            demisto.debug("Start time is bigger than or equal to end time")
            return []

        params = {
            "startTime": start_dt.strftime(DATE_FORMAT)[:-3] + 'Z',
            "endTime": end_dt.strftime(DATE_FORMAT)[:-3] + 'Z'
        }
        demisto.debug(f"Fetching audit logs from {params['startTime']} to {params['endTime']}")
        events = self._authorized_request(
            url_suffix="/controller/ControllerAuditHistory",
            params=params,
        )
        demisto.debug(f"Received {len(events)} audit logs from API.")
        return events[:self.max_audit_fetch]

    def get_health_events(self, start_time: datetime,end_time: datetime) -> list[dict]:
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
        demisto.debug("Fetching Healthrule Violations Events")
        while len(events) <= self.max_healthrule_fetch:
            params = {
                "time-range-type": "BETWEEN_TIMES",
                "start-time": str(int(start_time.timestamp() * 1000)),
                "end-time": str(int(end_time.timestamp() * 1000)),
                "output": "JSON"
            }
            url = f"/controller/rest/applications/{self.application_id}/problems/healthrule-violations"
            batch = self._authorized_request(url_suffix=url,
                                             params=params)
            demisto.debug(f"Fetched {len(batch)} events successfully.")
            if not batch:
                break
            events.extend(batch)
            if len(batch) < HEALTH_RULE_API_LIMIT:
                break
            start_time = get_max_event_time(events, HEALTH_EVENT)
        demisto.debug(f"Fetched {len(events)} Healthrule Violations Events from API.")
        return events[:self.max_healthrule_fetch]


def get_max_event_time(
    events: list[dict],
    log_type: str,
) -> datetime:
    """
    Returns the maximum event time for the given batch.
    Pre-condition: events not empty.
    based on log_type.
    Args:
        events:           List of event dicts.
        log_type:  One of:
                            - "Audit History"
                            - "Healthrule Violations Events"
    Returns:
        datetime: The maximum datetime value found.
    """
    field = {
        AUDIT: "timeStamp",
        HEALTH_EVENT: "detectedTimeInMillis"
    }.get(log_type, "eventTime")
    max_time_ms = max(int(ev.get(field, 0)) for ev in events)
    return datetime.fromtimestamp(max_time_ms / 1000, tz=timezone.utc)


def fetch_events(
    client: Client,
    last_run: dict,
    fetch_types: list[str],
) -> tuple[list[dict], dict]:
    """
    Fetch events from the client based on the last run times and event types specified.

    Args:
        client (Client): The client instance to fetch events from.
        last_run (dict): A dictionary containing the last run datetimes for different event types.
        fetch_types (list[str]): A list of event types to fetch.

    Returns:
        tuple[List[Dict], Dict]: A tuple containing a list of fetched events and a dictionary with the next run times.
    """

    next_run: dict[str, str] = {
        AUDIT: "",
        HEALTH_EVENT: ""
    }
    events = []
    current_time = datetime.now(timezone.utc)
    demisto.debug(f"fetch_events::Current time: {current_time}")

    # ---------- Audit ----------
    if AUDIT in fetch_types:
        start = last_run[AUDIT]
        demisto.debug(f"Fetching audit events, last run time: {start}")
        audit_events = client.get_audit_logs(start, current_time)
        demisto.debug(f"Fetched {len(audit_events)} audit events.")
        if audit_events:
            add_fields_to_events(audit_events, AUDIT)
            events.extend(audit_events)
            next_run[AUDIT] = get_max_event_time(audit_events, AUDIT).isoformat()
        else:
            next_run[AUDIT] = current_time.isoformat()
        demisto.debug(f"Next run time for audit events: {next_run[AUDIT]}")

    # ---------- Health-rule Violations ----------
    if HEALTH_EVENT in fetch_types:
        start = last_run[HEALTH_EVENT]
        demisto.debug(f"Fetching health events last run time: {start}")
        health_events = client.get_health_events(start, current_time)
        demisto.debug(f"Fetched {len(health_events)} Healthrule Violations Events.")
        if health_events:
            add_fields_to_events(health_events, HEALTH_EVENT)
            events.extend(health_events)
            next_run[HEALTH_EVENT] = get_max_event_time(health_events, HEALTH_EVENT).isoformat()
        else:
            next_run[HEALTH_EVENT] = current_time.isoformat()
        demisto.debug(f"Next run time for health events: {next_run[HEALTH_EVENT]}")

    demisto.debug(f"Total events fetched: {len(events)}")
    return events, next_run


def add_fields_to_events(
    events: list[dict],
    source_log_type: str
) -> list[dict]:
    """
    Enriches each event dict with XSIAM fields, based on the provided source type.
    Args:
        events:            List of event dicts to enrich.
        source_log_type:   One of:
                             - "Audit History"
                             - "Healthrule Violations Events"
    Returns:
        The same list, with each dict now having:
          - '_time'           (int) timestamp taken from the correct field
          - 'SOURCE_LOG_TYPE' (str) set to source_log_type
    """
    key = {
        AUDIT: "timeStamp",
        HEALTH_EVENT: "detectedTimeInMillis"
    }.get(source_log_type)

    for event in events:
        event["_time"] = event.get(key)
        event["SOURCE_LOG_TYPE"] = source_log_type

    return events


def create_empty_last_run(current_time: datetime) -> Dict[str, datetime]:
    """
    Create last run for first fetch with time interval of one minute.
    Args:
        current_time: datetime
    Returns:
        Dict with log_type: datetime
        Where datetime = current_time less one minute
    """
    start_time = current_time + timedelta(minutes=-1)
    return {AUDIT: start_time,
            HEALTH_EVENT: start_time}


def test_module_command(client: Client, last_run: dict, events_type_to_fetch: list[str]):
    """
    Tests API connectivity and authentication
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): Cisco AppDynamics client to use.
        params (Dict): Integration parameters.
        first_fetch_time(str): The first fetch time as configured in the integration params.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    fetch_events(client, last_run, events_type_to_fetch)
    return "ok"

def iso_to_dt(iso_time: str) -> datetime:
    """Convert datetime string with the following format 2025-04-27T10:00:00Z to datetime object.

    Args:
        iso_time (str): date as string.

    Returns:
        datetime: datetime object for the string date.
    """
    if iso_time.endswith("Z"):
        iso_time = iso_time.replace("Z", "+00:00")
    return datetime.fromisoformat(iso_time)

def get_events(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    A test‐driven version of fetch_events.

    Args (in `args` dict):
      - start_time (str): ISO 8601 string, e.g. "2025-04-27T10:00:00Z"
      - end_time   (str): ISO 8601 string, e.g. "2025-04-27T10:05:00Z"
      - types      (str): comma-separated list of event types to fetch,
                         e.g. "Audit,Healthrule Violations Events".
      - max_audit  (int): override client.max_audit_fetch for this run.
      - max_health (int): override client.max_healthrule_fetch for this run.
      - should_push_events (bool): push events to XSIAM.

    Returns:
      - CommandResults: include human readable from the events.
    """
    fetch_types = argToList(args.get("types", f"{AUDIT},{HEALTH_EVENT}"))
    original_max_audit  = client.max_audit_fetch
    original_max_health = client.max_healthrule_fetch
    client.max_audit_fetch      = arg_to_number(args.get("max_audit"))  or original_max_audit
    client.max_healthrule_fetch = arg_to_number(args.get("max_health")) or original_max_health
    should_push_events = argToBoolean(args.get("should_push_events")) or False
    
    start_time = datetime.now(timezone.utc)
    start_dt = iso_to_dt(args.get("start_time", "")) or start_time + timedelta(minutes= - 1)
    end_dt   = iso_to_dt(args.get("end_time", "")) or start_time
    events   = []
    next_run = {}

    if AUDIT in fetch_types:
        demisto.debug(f"Fetching Audit logs from {start_dt} to {end_dt}.")
        audit_events = client.get_audit_logs(start_dt, end_dt)
        if audit_events:
            add_fields_to_events(audit_events, AUDIT)
            events.extend(audit_events)
            next_run[AUDIT] = get_max_event_time(audit_events, AUDIT).isoformat()
        else:
            next_run[AUDIT] = end_dt.isoformat()
            
        demisto.debug(f"Total {len(events)} Audit logs Fetched. With max time{next_run[AUDIT]}."
                      )
    if HEALTH_EVENT in fetch_types:
        demisto.debug(f"Fetching Health Events from {start_dt} to {end_dt}.")
        health_events = client.get_health_events(start_dt, end_dt)
        if health_events:
            add_fields_to_events(health_events, HEALTH_EVENT)
            events.extend(health_events)
            next_run[HEALTH_EVENT] = get_max_event_time(health_events, HEALTH_EVENT).isoformat()
        else:
            next_run[HEALTH_EVENT] = end_dt.isoformat()
        demisto.debug(f"Total {len(events)} Health Events Fetched. With max time{next_run[HEALTH_EVENT]}.")

    if should_push_events:
        demisto.debug(f"Sending {len(events)} events to XSIAM.")
        send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
        demisto.debug("Sent events to XSIAM successfully")
    
    client.max_audit_fetch      = original_max_audit
    client.max_healthrule_fetch = original_max_health
    hr = tableToMarkdown(name="Events", t=events)
    return CommandResults(readable_output=hr)

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
    application_id = params.get("application_id", "")
    verify = argToBoolean(not params.get('insecure', False))
    proxy = argToBoolean(params.get('proxy', False))

    events_type_to_fetch = argToList(params.get('events_type_to_fetch', [AUDIT, HEALTH_EVENT]))
    max_audit_fetch = arg_to_number(params.get("max_audit_fetch")) or DEFAULT_MAX_AUDIT
    max_healthrule_fetch = arg_to_number(params.get("max_healthrule_fetch")) or DEFAULT_MAX_HEALTH

    demisto.debug(f"Command being called is {command}")
    try:
        client = Client(base_url=base_url,
                        client_id=client_id,
                        client_secret=client_secret,
                        application_id=application_id,
                        max_audit_fetch=max_audit_fetch,
                        max_healthrule_fetch=max_healthrule_fetch,
                        verify=verify,
                        proxy=proxy,
                        )
        current_time = datetime.now(timezone.utc)
        last_run = demisto.getLastRun()
        if not last_run:
            last_run = create_empty_last_run(current_time)
        else:
            last_run = {log_type: datetime.fromisoformat(datetime_as_string) for log_type, datetime_as_string in last_run.items()}
        demisto.debug(f"getLastRun return: Audit:{last_run[AUDIT]}, Health: {last_run[HEALTH_EVENT]}")
        if command == "test-module":
            return_results(test_module_command(client, last_run, events_type_to_fetch))

        elif command == "fetch-events":
            events, next_run = fetch_events(
                client,
                last_run,
                events_type_to_fetch,
            )
            demisto.debug(f"Sending {len(events)} events to XSIAM.")
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.debug("Sent events to XSIAM successfully")
            demisto.debug(f"setLastRun going to set: Audit:{next_run[AUDIT]}, Health: {next_run[HEALTH_EVENT]}")
            demisto.setLastRun(next_run)
            demisto.debug(f"Setting next run to {next_run}.")
        
        elif command == "cisappdynamics-get-events":
            command_results = get_events(client, args)
            return_results(command_results)


    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
