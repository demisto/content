import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa
from dateutil import parser

""" CONSTANTS """

VENDOR = "cisco"
PRODUCT = "webex_v2"
DEFAULT_MAX_FETCH = 200
MAX_FETCH_LIMIT = 2000
ADMIN_AUDIT_EVENTS = "Admin Audit Events"
SECURITY_AUDIT_EVENTS = "Security Audit Events"
COMPLIANCE_EVENTS = "Events"

# Per event type: last_run key, API path, time-range parameter names, page size cap,
# whether the org ID is sent, and the message shown when the API returns 403.
EVENT_TYPES: dict[str, dict] = {
    ADMIN_AUDIT_EVENTS: {
        "last_run_key": "admin_audits",
        "url_suffix": "adminAudit/events",
        "from_param": "from",
        "to_param": "to",
        "page_size": 200,
        "needs_org_id": True,
        "forbidden_message": "Insufficient permissions: missing audit:events_read scope.",
    },
    SECURITY_AUDIT_EVENTS: {
        "last_run_key": "security_audits",
        "url_suffix": "admin/securityAudit/events",
        "from_param": "startTime",
        "to_param": "endTime",
        "page_size": 1000,
        "needs_org_id": True,
        "forbidden_message": "Ingesting security audit telemetry requires an active Webex Pro Pack license.",
    },
    COMPLIANCE_EVENTS: {
        "last_run_key": "compliance_officer_events",
        "url_suffix": "events",
        "from_param": "from",
        "to_param": "to",
        "page_size": 1000,
        "needs_org_id": False,
        "forbidden_message": "Insufficient permissions: missing spark-compliance:events_read scope.",
    },
}
UNAUTHORIZED_MESSAGE = "Authentication failure: authorization incomplete or expired. Select Re-authorize on the connector."

""" HELPER FUNCTIONS """


def date_time_to_iso_format(date_time: datetime) -> str:
    """Returns the datetime as an ISO 8601 string with milliseconds and a trailing Z."""
    return f"{date_time.isoformat(timespec='milliseconds')}Z"


def add_fields_to_events(events: list[dict], event_type: str):
    """Adds the `_time` and `source_log_type` fields to every event."""
    for event in events:
        event["_time"] = event.get("created")
        event["source_log_type"] = event_type


def increase_datetime_for_next_fetch(events: list, latest_datetime_previous_fetch: str) -> str:
    """Returns the latest event `created` time (or the previous fetch time, if later) plus one millisecond."""
    latest_event = max(events, key=lambda event: parser.parse(event["created"]))
    latest_date_time = max(
        parser.parse(latest_event.get("created"), ignoretz=True), parser.parse(latest_datetime_previous_fetch, ignoretz=True)
    )
    return date_time_to_iso_format(latest_date_time + timedelta(milliseconds=1))


def describe_error(event_type: str, error: Exception) -> str:
    """Maps an API error to the verification message for the given event type."""
    status_code = getattr(getattr(error, "res", None), "status_code", None)
    if status_code == 401:
        return UNAUTHORIZED_MESSAGE
    if status_code == 403:
        return EVENT_TYPES[event_type]["forbidden_message"]
    return str(error)


""" CLIENT CLASS """


class Client(BaseClient):
    """Webex API client. The OAuth access token is injected by BaseClient from the connector's authorization profile."""

    def __init__(self, base_url: str, verify: bool, proxy: bool, org_id: str):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.org_id = org_id

    def get_events(self, event_type: str, from_date: str, limit: int, next_url: str = "") -> requests.Response:
        """Returns one page of events, either from `next_url` or for the given time range."""
        if next_url:
            return self._http_request(method="GET", full_url=next_url, resp_type="response")
        config = EVENT_TYPES[event_type]
        params = {
            config["from_param"]: from_date,
            config["to_param"]: date_time_to_iso_format(datetime.utcnow()),
            "max": min(limit, config["page_size"]),
        }
        if config["needs_org_id"]:
            params["orgId"] = self.org_id
        return self._http_request(method="GET", url_suffix=config["url_suffix"], params=params, resp_type="response")


""" COMMAND FUNCTIONS """


def get_events_with_pagination(
    client: Client, event_type: str, from_date: str, limit: int, next_url: str = ""
) -> tuple[list, str]:
    """Collects events page by page (following the `Link: next` header) until `limit` is reached."""
    response = client.get_events(event_type, from_date, limit, next_url)
    events: list[dict] = response.json().get("items", [])

    while (next_url := demisto.get(response.links, "next.url", "")) and len(events) < limit:
        response = client.get_events(event_type, from_date, limit, next_url)
        events.extend(response.json().get("items", []))

    add_fields_to_events(events, event_type)
    return events, next_url


def test_module(client: Client, event_types: list[str]) -> str:
    """Queries every selected event type and reports a specific error line for each one that fails."""
    if not event_types:
        raise DemistoException("Select at least one event type.")
    from_date = date_time_to_iso_format(datetime.utcnow() - timedelta(hours=1))
    errors = []
    for event_type in event_types:
        try:
            client.get_events(event_type, from_date, limit=1)
        except Exception as e:
            errors.append(f"{event_type}: {describe_error(event_type, e)}")
    if errors:
        raise DemistoException("\n".join(errors))
    return "ok"


def get_events_command(client: Client, event_type: str, args: dict) -> tuple[CommandResults, list]:
    """Returns the events of one event type for manual review."""
    from_date = args.get("since_datetime") or date_time_to_iso_format(datetime.utcnow() - timedelta(hours=3))
    limit = arg_to_number(args.get("limit")) or 5
    events, _ = get_events_with_pagination(client, event_type, from_date, limit)
    return CommandResults(readable_output=tableToMarkdown(event_type, events)), events


def fetch_events(client: Client, last_run: dict, max_fetch: int, event_types: list[str]) -> tuple[list, dict]:
    """
    Fetches each selected event type from its own checkpoint. A failure in one event type is logged and
    leaves that type's checkpoint unchanged, without blocking the other types.
    """
    all_events: list[dict] = []
    first_fetch = date_time_to_iso_format(datetime.utcnow() - timedelta(weeks=1))
    demisto.debug(f"Starting fetch with last_run: {last_run}")

    for event_type in event_types:
        key = EVENT_TYPES[event_type]["last_run_key"]
        type_run = last_run.setdefault(key, {"since_datetime": first_fetch, "next_url": ""})
        since_datetime = type_run["since_datetime"]
        try:
            events, next_url = get_events_with_pagination(
                client, event_type, since_datetime, max_fetch, type_run.get("next_url", "")
            )
        except Exception as e:
            demisto.error(f"Failed fetching {event_type}: {describe_error(event_type, e)}")
            continue
        type_run["next_url"] = next_url
        if events:
            type_run["since_datetime"] = increase_datetime_for_next_fetch(events, since_datetime)
            all_events.extend(events)

    demisto.debug(f"Fetched {len(all_events)} events, next last_run: {last_run}")
    return all_events, last_run


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH
    if not 0 < max_fetch <= MAX_FETCH_LIMIT:
        max_fetch = DEFAULT_MAX_FETCH
    event_types = [event_type for event_type in argToList(params.get("event_types")) if event_type in EVENT_TYPES]

    demisto.debug(f"Command being called is {command}")
    try:
        client = Client(
            base_url=urljoin(params.get("base_url") or "https://webexapis.com", "/v1/"),
            verify=not argToBoolean(params.get("insecure", False)),
            proxy=argToBoolean(params.get("proxy", False)),
            org_id=params.get("org_id", ""),
        )
        command_to_event_type = {
            "cisco-webex-v2-get-admin-audit-events": ADMIN_AUDIT_EVENTS,
            "cisco-webex-v2-get-security-audit-events": SECURITY_AUDIT_EVENTS,
            "cisco-webex-v2-get-compliance-officer-events": COMPLIANCE_EVENTS,
        }

        if command == "test-module":
            return_results(test_module(client, event_types))

        elif command in command_to_event_type:
            command_results, events = get_events_command(client, command_to_event_type[command], args)
            if argToBoolean(args.get("should_push_events", False)):
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            return_results(command_results)

        elif command == "fetch-events":
            events, next_run = fetch_events(client, demisto.getLastRun() or {}, max_fetch, event_types)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)

        else:
            raise NotImplementedError(f'Command "{command}" was not implemented.')

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
