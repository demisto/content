import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from ContentClientApiModule import *

""" CONSTANTS """

VENDOR = "gitguardian"
PRODUCT = "saas"
API_VERSION_PATH = "/v1"
PAGE_SIZE = 100
DEFAULT_MAX_EVENTS_PER_TYPE = 1000
DEFAULT_FIRST_FETCH = "1 hour"
DEFAULT_GET_EVENTS_LIMIT = 10
MAX_RETRIES = 3
API_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
NEXT_LINK_REGEX = re.compile(r'<([^>]+)>\s*;\s*rel="?next"?')
AUTH_ERROR_MESSAGE = "Authorization Error: verify the API key is valid and has the incidents:read and audit_logs:read scopes."


@dataclass(frozen=True)
class EventType:
    """Describes a GitGuardian event type collected by the integration."""

    name: str  # Display name used in the integration parameters.
    key: str  # Key used in the last run object.
    endpoint: str  # API endpoint path relative to /v1.
    source_log_type: str  # Value of the _source_log_type field.
    table_headers: tuple[str, ...]


SECRET_INCIDENTS = EventType(
    name="Secret Incidents",
    key="secret_incidents",
    endpoint="/incidents/secrets",
    source_log_type="incident_secret",
    table_headers=("id", "date", "status", "severity", "validity", "gitguardian_url"),
)
AUDIT_LOGS = EventType(
    name="Audit Logs",
    key="audit_logs",
    endpoint="/audit_logs",
    source_log_type="audit_log",
    table_headers=("id", "date", "event_name", "action_type", "member_email", "ip_address"),
)
EVENT_TYPES_BY_NAME: dict[str, EventType] = {event_type.name: event_type for event_type in (SECRET_INCIDENTS, AUDIT_LOGS)}

""" CLIENT CLASS """


class Client(ContentClient):
    """GitGuardian SaaS API (v1.1) client.

    Uses ContentClient for retries with exponential backoff (429 / 5xx, honoring Retry-After)
    and thread-safe HTTP sessions, which allows collecting the event types concurrently.
    """

    def __init__(self, base_url: str, api_key: str, verify: bool, proxy: bool):
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            headers={"Accept": "application/json"},
            auth_handler=APIKeyAuthHandler(key=f"Token {api_key}", header_name="Authorization"),
            retry_policy=RetryPolicy(max_attempts=MAX_RETRIES + 1),  # type: ignore[call-arg]
            client_name="GitGuardianSaaS",
        )

    def get_page(
        self, endpoint: str, params: dict[str, Any] | None = None, next_url: str | None = None
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Retrieves a single page of events.

        Args:
            endpoint: The endpoint path, used only for the first page of a fetch.
            params: Query parameters, used only for the first page of a fetch.
            next_url: The rel="next" URL from the previous response. Called verbatim when provided.

        Returns:
            The events in the page and the next page URL (None when this is the last page).
        """
        if next_url:
            response = self._http_request(method="GET", full_url=next_url, resp_type="response")
        else:
            response = self._http_request(method="GET", url_suffix=endpoint, params=params, resp_type="response")
        events = response.json() or []
        return events, parse_next_link(response.headers.get("Link", ""))


""" HELPER FUNCTIONS """


def parse_next_link(link_header: str) -> str | None:
    """Extracts the rel="next" URL from an HTTP Link header, or None if there is no next page."""
    match = NEXT_LINK_REGEX.search(link_header or "")
    return match.group(1) if match else None


def parse_iso_datetime(value: Any) -> datetime | None:
    """Parses an ISO-8601 timestamp into an aware datetime. Returns None when the value is missing or invalid."""
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)  # noqa: UP017


def format_api_date(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime(API_DATE_FORMAT)  # noqa: UP017


def get_dedup_key(event: dict[str, Any]) -> str:
    """Builds the deduplication key. Includes the date so a re-triggered incident is collected again as an update."""
    return f"{event.get('id')}|{event.get('date')}"


def get_entry_status(event: dict[str, Any]) -> str:
    """Returns 'new' when the event date equals triggered_at, otherwise 'updated'.

    Audit logs have no triggered_at field, so they are always 'new'.
    """
    triggered_at = parse_iso_datetime(event.get("triggered_at"))
    event_date = parse_iso_datetime(event.get("date"))
    if triggered_at and event_date and event_date != triggered_at:
        return "updated"
    return "new"


def enrich_events(events: list[dict[str, Any]], event_type: EventType) -> list[dict[str, Any]]:
    """Adds the _time, _source_log_type and _ENTRY_STATUS fields to the events in place."""
    for event in events:
        event["_time"] = event.get("date")
        event["_source_log_type"] = event_type.source_log_type
        event["_ENTRY_STATUS"] = get_entry_status(event)
    return events


def get_boundary_keys(events: list[dict[str, Any]], window_end: str) -> list[str]:
    """Returns the dedup keys of events dated at the window end (second precision).

    The next fetch window starts at this timestamp, so these events could be returned again.
    """
    boundary = parse_iso_datetime(window_end)
    keys = []
    for event in events:
        event_date = parse_iso_datetime(event.get("date"))
        if boundary and event_date and event_date.replace(microsecond=0) >= boundary:
            keys.append(get_dedup_key(event))
    return keys


def parse_event_types(event_type_names: list[str]) -> list[EventType]:
    """Converts event type display names to EventType objects."""
    unknown = [name for name in event_type_names if name not in EVENT_TYPES_BY_NAME]
    if unknown:
        raise DemistoException(f"Invalid event types: {', '.join(unknown)}. Valid values: {', '.join(EVENT_TYPES_BY_NAME)}.")
    if not event_type_names:
        raise DemistoException("Select at least one event type.")
    return [EVENT_TYPES_BY_NAME[name] for name in event_type_names]


def get_type_state(last_run: dict[str, Any], event_type: EventType, first_fetch: str) -> dict[str, Any]:
    """Returns the saved fetch state of an event type, or the initial state for the first fetch."""
    return last_run.get(event_type.key) or {"last_date": first_fetch, "last_ids": []}


def fetch_events_for_type(
    client: Client, event_type: EventType, type_state: dict[str, Any], window_end: str, max_events: int
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Fetches the events of a single type, following the Link header until the last page or the max events budget.

    Args:
        client: GitGuardian SaaS client.
        event_type: The event type to fetch.
        type_state: The saved state of this type (last_date, last_ids, and window_end / next_url during pagination).
        window_end: The upper bound of a new fetch window. Ignored while resuming pagination.
        max_events: Maximum number of events to fetch (rounded up to a whole page).

    Returns:
        The new events and the next state of this type.
    """
    next_url = type_state.get("next_url")
    if next_url:
        window_end = type_state["window_end"]
    params = {"per_page": PAGE_SIZE, "date_after": type_state["last_date"], "date_before": window_end}
    seen_keys = set(type_state.get("last_ids") or [])
    demisto.debug(f"[{event_type.key}] Fetching window {params['date_after']} - {window_end}, resuming: {bool(next_url)}")

    events: list[dict[str, Any]] = []
    while len(events) < max_events:
        page, next_url = client.get_page(event_type.endpoint, params=params, next_url=next_url)
        events.extend(event for event in page if get_dedup_key(event) not in seen_keys)
        if not next_url:
            break

    demisto.debug(f"[{event_type.key}] Fetched {len(events)} events, pagination in progress: {bool(next_url)}")
    if next_url:
        next_state = {**type_state, "window_end": window_end, "next_url": next_url}
    else:
        next_state = {"last_date": window_end, "last_ids": get_boundary_keys(events, window_end)}
    return events, next_state


""" COMMAND FUNCTIONS """


def test_module(client: Client, event_types: list[EventType]) -> str:
    """Tests connectivity and authorization by requesting a single event of each configured type."""
    try:
        for event_type in event_types:
            client.get_page(event_type.endpoint, params={"per_page": 1})
    except ContentClientAuthenticationError as error:
        demisto.debug(f"Authentication failed: {error}")
        return AUTH_ERROR_MESSAGE
    return "ok"


def get_events_command(
    client: Client, args: dict[str, Any], default_event_types: list[EventType]
) -> tuple[list[dict[str, Any]], CommandResults]:
    """Manually fetches events, for development and debugging."""
    limit = arg_to_number(args.get("limit")) or DEFAULT_GET_EVENTS_LIMIT
    start_date = arg_to_datetime(args.get("start_date") or DEFAULT_FIRST_FETCH, arg_name="start_date", required=True)
    event_types = parse_event_types(argToList(args.get("event_types"))) if args.get("event_types") else default_event_types
    window_end = format_api_date(datetime.now(timezone.utc))  # noqa: UP017
    type_state = {"last_date": format_api_date(start_date), "last_ids": []}  # type: ignore[arg-type]

    all_events: list[dict[str, Any]] = []
    readable_output = ""
    for event_type in event_types:
        events, _ = fetch_events_for_type(client, event_type, type_state, window_end, limit)
        events = enrich_events(events[:limit], event_type)
        all_events.extend(events)
        readable_output += tableToMarkdown(
            f"GitGuardian SaaS {event_type.name}", events, headers=list(event_type.table_headers), removeNull=True
        )
    return all_events, CommandResults(readable_output=readable_output, raw_response=all_events)


def fetch_events(
    client: Client, last_run: dict[str, Any], event_types: list[EventType], max_events: int, first_fetch: str
) -> tuple[list[dict[str, Any]], dict[str, Any], list[str]]:
    """Fetches all configured event types concurrently.

    A failing event type does not block the others: its state is kept so it is retried in the next cycle.

    Returns:
        The enriched events, the next run object and the error messages of the failed event types.
    """
    window_end = format_api_date(datetime.now(timezone.utc))  # noqa: UP017
    next_run = {key: value for key, value in last_run.items() if key != "nextTrigger"}
    all_events: list[dict[str, Any]] = []
    errors: list[str] = []

    with ThreadPoolExecutor(max_workers=len(event_types)) as executor:
        futures = {
            event_type: executor.submit(
                fetch_events_for_type,
                client,
                event_type,
                get_type_state(last_run, event_type, first_fetch),
                window_end,
                max_events,
            )
            for event_type in event_types
        }
        for event_type, future in futures.items():
            try:
                events, type_state = future.result()
            except Exception as error:
                demisto.error(f"[{event_type.key}] Fetch failed: {error}")
                errors.append(f"{event_type.name}: {error}")
                continue
            all_events.extend(enrich_events(events, event_type))
            next_run[event_type.key] = type_state

    if any(next_run.get(event_type.key, {}).get("next_url") for event_type in event_types):
        next_run["nextTrigger"] = "0"
    return all_events, next_run, errors


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        base_url = urljoin(params.get("url") or "https://api.gitguardian.com", API_VERSION_PATH)
        event_types = parse_event_types(argToList(params.get("event_types")) or list(EVENT_TYPES_BY_NAME))
        max_events = arg_to_number(params.get("max_events_per_fetch")) or DEFAULT_MAX_EVENTS_PER_TYPE
        client = Client(
            base_url=base_url,
            api_key=params.get("api_key", {}).get("password", ""),
            verify=not argToBoolean(params.get("insecure", False)),
            proxy=argToBoolean(params.get("proxy", False)),
        )

        if command == "test-module":
            return_results(test_module(client, event_types))

        elif command == "gitguardian-saas-get-events":
            events, results = get_events_command(client, args, event_types)
            if argToBoolean(args.get("should_push_events", False)):
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            return_results(results)

        elif command == "fetch-events":
            first_fetch = format_api_date(arg_to_datetime(DEFAULT_FIRST_FETCH))  # type: ignore[arg-type]
            events, next_run, errors = fetch_events(client, demisto.getLastRun(), event_types, max_events, first_fetch)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)
            if errors:
                raise DemistoException(f"Failed to fetch some event types: {'; '.join(errors)}")

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except ContentClientAuthenticationError as error:
        return_error(f"Failed to execute {command} command.\n{AUTH_ERROR_MESSAGE}\nError: {error}")
    except Exception as error:
        return_error(f"Failed to execute {command} command.\nError:\n{error}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
