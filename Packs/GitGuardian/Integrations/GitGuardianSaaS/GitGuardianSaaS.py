import math
import re
import traceback
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from ContentClientApiModule import *

""" CONSTANTS """

VENDOR = "gitguardian"
PRODUCT = "saas"
DEFAULT_SERVER_URL = "https://api.gitguardian.com"
API_VERSION_PATH = "/v1"
PAGE_SIZE = 100
DEFAULT_MAX_EVENTS_PER_TYPE = 1000
DEFAULT_FIRST_FETCH = "1 hour"
DEFAULT_GET_EVENTS_LIMIT = 10
MAX_RETRIES = 3
FETCH_LAG_SECONDS = 60  # The fetch window ends this many seconds before now, so late-indexed events are not missed.
API_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
NEXT_LINK_REGEX = re.compile(r'<([^>]+)>\s*;\s*rel="?next"?')
NON_STALE_CURSOR_STATUS_CODES = (401, 403, 429)  # 4xx codes that do not mean the saved cursor is invalid.
AUTH_ERROR_MESSAGE = "Authorization Error: verify the API key is valid and has the incidents:read and audit_logs:read scopes."


@dataclass(frozen=True)
class EventType:
    """Describes a GitGuardian event type collected by the integration."""

    name: str  # Display name used in the integration parameters.
    key: str  # Key used in the last run object.
    endpoint: str  # API endpoint path relative to /v1.
    source_log_type: str  # Value of the _source_log_type field.
    required_scope: str  # API key scope required to read this event type.
    table_headers: tuple[str, ...]


SECRET_INCIDENTS = EventType(
    name="Secret Incidents",
    key="secret_incidents",
    endpoint="/incidents/secrets",
    source_log_type="incident_secret",
    required_scope="incidents:read",
    table_headers=("id", "date", "status", "severity", "validity", "gitguardian_url"),
)
AUDIT_LOGS = EventType(
    name="Audit Logs",
    key="audit_logs",
    endpoint="/audit_logs",
    source_log_type="audit_log",
    required_scope="audit_logs:read",
    table_headers=("id", "date", "event_name", "action_type", "member_email", "ip_address"),
)
EVENT_TYPES_BY_NAME: dict[str, EventType] = {event_type.name: event_type for event_type in (SECRET_INCIDENTS, AUDIT_LOGS)}


class UntrustedNextUrlError(DemistoException):
    """Raised when a pagination URL points to a different host than the configured server URL."""


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

    def is_trusted_url(self, url: str) -> bool:
        """Returns True when the URL has the same scheme and host as the configured server URL."""
        parsed_url, parsed_base_url = urlparse(url), urlparse(self._base_url)
        return (parsed_url.scheme, parsed_url.netloc.lower()) == (parsed_base_url.scheme, parsed_base_url.netloc.lower())

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

        Raises:
            UntrustedNextUrlError: The next URL points to a different host, so the API key is not sent to it.
        """
        if next_url:
            if not self.is_trusted_url(next_url):
                raise UntrustedNextUrlError(f"The next page URL host does not match the server URL {self._base_url}.")
            demisto.debug(f"[Client] GET next page: {next_url}")
            response = self._http_request(method="GET", full_url=next_url, resp_type="response")
        else:
            demisto.debug(f"[Client] GET {endpoint} with params: {params}")
            response = self._http_request(method="GET", url_suffix=endpoint, params=params, resp_type="response")
        events = response.json() or []
        next_page_url = parse_next_link(response.headers.get("Link", ""))
        demisto.debug(f"[Client] Received {len(events)} events, has next page: {bool(next_page_url)}")
        return events, next_page_url


""" HELPER FUNCTIONS """


def build_base_url(server_url: str | None) -> str:
    """Builds the API base URL. Accepts a server URL with or without a trailing slash or /v1 suffix."""
    url = (server_url or DEFAULT_SERVER_URL).strip().rstrip("/")
    if url.lower().endswith(API_VERSION_PATH):
        url = url[: -len(API_VERSION_PATH)]
    return f"{url}{API_VERSION_PATH}"


def parse_date_arg(value: str, arg_name: str) -> datetime:
    """Parses an absolute or relative date argument into an aware UTC datetime."""
    parsed = arg_to_datetime(
        value, arg_name=arg_name, required=True, settings={"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": True}
    )
    if parsed.tzinfo is None:  # type: ignore[union-attr]
        parsed = parsed.replace(tzinfo=timezone.utc)  # type: ignore[union-attr]  # noqa: UP017
    return parsed  # type: ignore[return-value]


def parse_positive_int(value: Any, arg_name: str, default: int) -> int:
    """Parses a positive integer argument, returning the default when the value is empty."""
    number = arg_to_number(value, arg_name=arg_name)
    if number is None:
        return default
    if number <= 0:
        raise DemistoException(f"{arg_name} must be a positive integer. Got: {number}.")
    return number


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
    """Builds the deduplication key. Includes the date so a re-triggered incident is collected again as an update.

    The date is normalized, so the same timestamp in a different ISO-8601 format produces the same key.
    """
    raw_date = event.get("date")
    parsed_date = parse_iso_datetime(raw_date)
    normalized_date = parsed_date.astimezone(timezone.utc).isoformat() if parsed_date else raw_date  # noqa: UP017
    return f"{event.get('id')}|{normalized_date}"


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
    """Adds the _time, _source_log_type and _ENTRY_STATUS fields to the events in place.

    Call this only right before sending the events to XSIAM.
    """
    for event in events:
        event["_time"] = event.get("date")
        event["_source_log_type"] = event_type.source_log_type
        event["_ENTRY_STATUS"] = get_entry_status(event)
    updated_count = sum(1 for event in events if event["_ENTRY_STATUS"] == "updated")
    demisto.debug(
        f"[Enrich][{event_type.key}] Enriched {len(events)} events: {len(events) - updated_count} new, {updated_count} updated"
    )
    return events


def deduplicate_events(events: list[dict[str, Any]], seen_keys: set[str], event_type: EventType) -> list[dict[str, Any]]:
    """Removes events that were already collected at the boundary of the previous fetch window."""
    new_events = [event for event in events if get_dedup_key(event) not in seen_keys]
    skipped_count = len(events) - len(new_events)
    if skipped_count:
        demisto.debug(f"[Dedup][{event_type.key}] Skipped {skipped_count} duplicate events out of {len(events)}")
    return new_events


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


def is_stale_cursor_error(error: Exception) -> bool:
    """Returns True when a request failed with a 4xx status that means the cursor is invalid (not auth or rate limit)."""
    status_code = getattr(getattr(error, "response", None), "status_code", None)
    return isinstance(status_code, int) and 400 <= status_code < 500 and status_code not in NON_STALE_CURSOR_STATUS_CODES


def get_first_page(
    client: Client, event_type: EventType, type_state: dict[str, Any], window_end: str
) -> tuple[list[dict[str, Any]], str | None, str]:
    """Gets the first page of a fetch: resumes the saved cursor, or starts a new window from last_date.

    When the saved cursor points to a different host or is rejected with a 4xx error (for example, an expired cursor),
    it is dropped and the window is restarted from last_date. Some events may be collected again in this case.

    Returns:
        The events in the page, the next page URL and the window end the fetch applies to.
    """
    prefix = f"[Pagination][{event_type.key}]"
    saved_next_url = type_state.get("next_url")
    if saved_next_url and not client.is_trusted_url(saved_next_url):
        demisto.info(f"{prefix} The saved cursor host does not match the server URL. Restarting from {type_state['last_date']}")
    elif saved_next_url:
        try:
            demisto.debug(f"{prefix} Resuming the saved cursor")
            page, next_url = client.get_page(event_type.endpoint, next_url=saved_next_url)
            return page, next_url, type_state["window_end"]
        except ContentClientError as error:
            if not is_stale_cursor_error(error):
                raise
            demisto.info(f"{prefix} The saved cursor was rejected ({error}). Restarting from {type_state['last_date']}")

    params = {"per_page": PAGE_SIZE, "date_after": type_state["last_date"], "date_before": window_end}
    page, next_url = client.get_page(event_type.endpoint, params=params)
    return page, next_url, window_end


def fetch_events_for_type(
    client: Client, event_type: EventType, type_state: dict[str, Any], window_end: str, max_events: int
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Fetches the events of a single type, following the Link header until the last page or the max events budget.

    Args:
        client: GitGuardian SaaS client.
        event_type: The event type to fetch.
        type_state: The saved state of this type (last_date, last_ids, and window_end / next_url during pagination).
        window_end: The upper bound of a new fetch window. Ignored while resuming pagination.
        max_events: Maximum number of events to fetch (rounded up to a whole page). Also caps the number of pages.

    Returns:
        The new events and the next state of this type.
    """
    prefix = f"[Fetch][{event_type.key}]"
    seen_keys = set(type_state.get("last_ids") or [])
    max_pages = math.ceil(max_events / PAGE_SIZE)
    demisto.debug(
        f"{prefix} Starting. last_date: {type_state['last_date']}, new window end: {window_end}, "
        f"saved cursor: {bool(type_state.get('next_url'))}, max events: {max_events}, max pages: {max_pages}, "
        f"boundary keys from last run: {len(seen_keys)}"
    )

    page, next_url, window_end = get_first_page(client, event_type, type_state, window_end)
    events = deduplicate_events(page, seen_keys, event_type)
    page_number = 1
    demisto.debug(f"[Pagination][{event_type.key}] Page 1: {len(page)} events, total so far: {len(events)}")
    while next_url and len(events) < max_events and page_number < max_pages:
        page_number += 1
        page, next_url = client.get_page(event_type.endpoint, next_url=next_url)
        events.extend(deduplicate_events(page, seen_keys, event_type))
        demisto.debug(f"[Pagination][{event_type.key}] Page {page_number}: {len(page)} events, total so far: {len(events)}")

    if next_url:
        demisto.debug(f"[Pagination][{event_type.key}] Reached the max events or pages limit, saving the next page link")
        next_state = {**type_state, "window_end": window_end, "next_url": next_url}
    else:
        demisto.debug(f"[Pagination][{event_type.key}] No next link, reached the last page")
        next_state = {"last_date": window_end, "last_ids": get_boundary_keys(events, window_end)}
    demisto.debug(
        f"{prefix} Done. Fetched {len(events)} events in {page_number} pages. Next state: last_date="
        f"{next_state['last_date']}, boundary keys: {len(next_state['last_ids'])}, pagination in progress: {bool(next_url)}"
    )
    return events, next_state


""" COMMAND FUNCTIONS """


def test_module(client: Client, event_types: list[EventType]) -> str:
    """Tests connectivity and authorization by requesting a single event of each configured type."""
    for event_type in event_types:
        demisto.debug(f"[Test Module] Checking access to {event_type.name}")
        try:
            client.get_page(event_type.endpoint, params={"per_page": 1})
        except ContentClientAuthenticationError as error:
            demisto.debug(f"[Test Module] Authentication failed for {event_type.name}: {error}")
            return (
                f"Authorization Error: the API key cannot access {event_type.name}. "
                f"Verify the API key is valid and has the {event_type.required_scope} scope."
            )
    demisto.debug("[Test Module] Success")
    return "ok"


def send_events(events: list[dict[str, Any]]) -> None:
    demisto.debug(f"[Send] Sending {len(events)} events to XSIAM")
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
    demisto.debug("[Send] Done")


def get_events_command(client: Client, args: dict[str, Any], default_event_types: list[EventType]) -> CommandResults:
    """Manually fetches events, for development and debugging.

    The events are enriched and sent to XSIAM only when should_push_events is true.
    """
    should_push_events = argToBoolean(args.get("should_push_events", False))
    limit = parse_positive_int(args.get("limit"), "limit", DEFAULT_GET_EVENTS_LIMIT)
    start_date = parse_date_arg(args.get("start_date") or DEFAULT_FIRST_FETCH, "start_date")
    end_date = parse_date_arg(args.get("end_date") or "now", "end_date")
    if start_date >= end_date:
        raise DemistoException("start_date must be earlier than end_date.")
    event_types = parse_event_types(argToList(args.get("event_types"))) if args.get("event_types") else default_event_types
    window_end = format_api_date(end_date)
    type_state = {"last_date": format_api_date(start_date), "last_ids": []}
    demisto.debug(
        f"[Get Events] Event types: {[event_type.name for event_type in event_types]}, limit: {limit}, "
        f"window: {type_state['last_date']} - {window_end}, push events: {should_push_events}"
    )

    all_events: list[dict[str, Any]] = []
    readable_output = ""
    for event_type in event_types:
        events, _ = fetch_events_for_type(client, event_type, type_state, window_end, limit)
        events = events[:limit]
        readable_output += tableToMarkdown(
            f"GitGuardian SaaS {event_type.name}", events, headers=list(event_type.table_headers), removeNull=True
        )
        if should_push_events:
            enrich_events(events, event_type)
        all_events.extend(events)

    if should_push_events:
        send_events(all_events)
    return CommandResults(readable_output=readable_output, raw_response=all_events)


def fetch_events(
    clients: dict[str, Client], last_run: dict[str, Any], event_types: list[EventType], max_events: int, first_fetch: str
) -> tuple[list[dict[str, Any]], dict[str, Any], list[str]]:
    """Fetches all configured event types concurrently.

    Each event type uses its own client, so failures of one type do not open the circuit breaker of another.
    A failing event type does not block the others: its state is kept so it is retried in the next cycle.

    Args:
        clients: A client per event type key.

    Returns:
        The enriched events, the next run object and the error messages of the failed event types.
    """
    window_end = format_api_date(datetime.now(timezone.utc) - timedelta(seconds=FETCH_LAG_SECONDS))  # noqa: UP017
    next_run = {key: value for key, value in last_run.items() if key != "nextTrigger"}
    all_events: list[dict[str, Any]] = []
    errors: list[str] = []
    demisto.debug(
        f"[Fetch] Starting {len(event_types)} event types in parallel: {[event_type.key for event_type in event_types]}. "
        f"Window end: {window_end} ({FETCH_LAG_SECONDS} seconds before now)"
    )

    with ThreadPoolExecutor(max_workers=len(event_types)) as executor:
        futures = {
            event_type: executor.submit(
                fetch_events_for_type,
                clients[event_type.key],
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
                demisto.error(
                    f"[Fetch][{event_type.key}] Failed, keeping the previous state to retry next cycle: {error}\n"
                    f"{traceback.format_exc()}"
                )
                errors.append(f"{event_type.name}: {error}")
                continue
            all_events.extend(enrich_events(events, event_type))
            next_run[event_type.key] = type_state

    if any(next_run.get(event_type.key, {}).get("next_url") for event_type in event_types):
        next_run["nextTrigger"] = "0"
        demisto.debug("[Last Run] Pagination in progress, setting nextTrigger=0 to continue immediately")
    demisto.debug(f"[Fetch] Done. Total events: {len(all_events)}, failed event types: {len(errors)}")
    return all_events, next_run, errors


""" MAIN FUNCTION """


def create_client(params: dict[str, Any]) -> Client:
    return Client(
        base_url=build_base_url(params.get("url")),
        api_key=params.get("api_key", {}).get("password", ""),
        verify=not argToBoolean(params.get("insecure", False)),
        proxy=argToBoolean(params.get("proxy", False)),
    )


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        event_types = parse_event_types(argToList(params.get("event_types")) or list(EVENT_TYPES_BY_NAME))

        if command == "test-module":
            return_results(test_module(create_client(params), event_types))

        elif command == "gitguardian-saas-get-events":
            return_results(get_events_command(create_client(params), args, event_types))

        elif command == "fetch-events":
            max_events = parse_positive_int(
                params.get("max_events_per_fetch"), "The maximum number of events per fetch", DEFAULT_MAX_EVENTS_PER_TYPE
            )
            first_fetch = format_api_date(arg_to_datetime(DEFAULT_FIRST_FETCH))  # type: ignore[arg-type]
            clients = {event_type.key: create_client(params) for event_type in event_types}
            last_run = demisto.getLastRun()
            demisto.debug(f"[Last Run] Loaded: {last_run}")
            events, next_run, errors = fetch_events(clients, last_run, event_types, max_events, first_fetch)
            send_events(events)
            demisto.setLastRun(next_run)
            demisto.debug(f"[Last Run] Saved: {next_run}")
            if errors:
                raise DemistoException(f"Failed to fetch some event types: {'; '.join(errors)}")

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except ContentClientAuthenticationError as error:
        demisto.debug(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\n{AUTH_ERROR_MESSAGE}\nError: {error}", error=error)
    except Exception as error:
        demisto.debug(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{error}", error=error)


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
