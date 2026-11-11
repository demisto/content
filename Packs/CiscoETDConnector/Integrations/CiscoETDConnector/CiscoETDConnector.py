"""Cisco Secure Email Threat Defense (ETD) event collector for Cortex XSIAM.

The ETD Log Export API does not return events directly. Each request returns a list of
pre-signed S3 links to hourly NDJSON export files, which are then downloaded and parsed.
API reference: https://developer.cisco.com/docs/message-search-api/log-export-api/
"""

import hashlib
import json
import re
import time
import traceback
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

import demistomock as demisto  # noqa: F401
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from CommonServerPython import *  # noqa: F401,F403
from ContentClientApiModule import *  # noqa: F401,F403

""" CONSTANTS """

VENDOR = "Cisco"
PRODUCT = "ETD"
ETD_LOG_TYPES = ["message", "audit", "connection"]

# The API rejects a time range longer than 3 hours ("400 Invalid daterange").
MAX_API_RANGE_HOURS = 3
# Fetch a single hour per request. A response is truncated after MAX_LINKS_PER_RESPONSE
# links, so a narrow window keeps us far below that ceiling.
FETCH_WINDOW_HOURS = 1
# The API returns at most 200 download URLs and silently truncates the rest.
MAX_LINKS_PER_RESPONSE = 200
# Export files for a given hour keep being generated for up to ~20 minutes after the hour
# closes, so recent hours are re-read. Files already downloaded are skipped by object path.
LOOKBACK_HOURS = 2
# The API rejects timestamps older than 30 days ("400 Invalid daterange").
MAX_LOOKBACK_DAYS = 30
# Upper bound on the number of processed file paths kept in the last run object.
MAX_TRACKED_FILES = 2000
# Stop fetching before the container is killed, so progress can be saved.
FETCH_TIME_BUDGET_SECONDS = 240

DEFAULT_MAX_FETCH = 5000
DEFAULT_LIMIT = 100
# Refresh the token slightly before it actually expires to avoid a mid-fetch 401.
TOKEN_EXPIRY_BUFFER_SECONDS = 300
DEFAULT_TOKEN_TTL_SECONDS = 55 * 60

HOUR_FORMAT = "%Y-%m-%dT%H"
XSIAM_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"

# Matches the log_date / hour partitions embedded in the export object path, in both the
# raw form ("log_date=2024-09-09/hour=11") and the percent-encoded form used by the API.
FILE_HOUR_PATTERN = re.compile(r"log_date(?:%3D|=)(\d{4}-\d{2}-\d{2}).*?hour(?:%3D|=)(\d{2})", re.IGNORECASE)

""" HELPERS """


def get_credential(param: dict | str | None) -> str:
    """Extract a secret from a credentials parameter, which may be a dict or a plain string."""
    if isinstance(param, dict):
        return param.get("password") or param.get("credentials", {}).get("password") or ""
    return param or ""


def get_positive_int(value: Any, default: int, name: str) -> int:
    """Parse a numeric setting, falling back to the default when it is blank or invalid.

    A misconfigured value should not break collection, so it is logged and the default used.
    """
    try:
        parsed = arg_to_number(value)
    except ValueError:
        parsed = None
    if not parsed or parsed <= 0:
        if value not in (None, ""):
            demisto.debug(f"Ignoring invalid {name} value {value!r}, using {default} instead.")
        return default
    return parsed


def format_hour(dt: datetime) -> str:
    """Format a datetime as the hour label expected by the API (YYYY-MM-DDTHH, UTC)."""
    return dt.strftime(HOUR_FORMAT)


def parse_hour(hour_label: str) -> datetime:
    """Parse an API hour label back into a UTC datetime."""
    return datetime.strptime(hour_label, HOUR_FORMAT).replace(tzinfo=UTC)


def floor_to_hour(dt: datetime) -> datetime:
    return dt.astimezone(UTC).replace(minute=0, second=0, microsecond=0)


def get_object_path(link: str) -> str:
    """Return the stable object path of a pre-signed link.

    The signature query string changes on every request, but the path identifies the export
    file itself and is therefore usable as a stable "already downloaded" marker.
    """
    try:
        return urlparse(link).path or link
    except Exception:
        return link


def generate_intervals(start_dt: datetime, end_dt: datetime, window_hours: int) -> list[tuple[datetime, datetime]]:
    """Split a time range into chunks the API accepts. Returns an empty list if the range is empty."""
    if window_hours > MAX_API_RANGE_HOURS:
        raise DemistoException(f"Window of {window_hours} hours exceeds the API maximum of {MAX_API_RANGE_HOURS} hours.")
    intervals = []
    current = start_dt
    while current < end_dt:
        next_dt = min(current + timedelta(hours=window_hours), end_dt)
        intervals.append((current, next_dt))
        current = next_dt
    return intervals


def parse_timestamp(value: Any) -> datetime | None:
    """Parse an ETD timestamp into an aware UTC datetime, or None if it cannot be parsed.

    ETD emits UTC in both forms: message events use "2025-07-16T05:59:42Z" while audit events
    use a naive "2025-06-16 06:54:55". Naive values are therefore treated as UTC rather than
    as container-local time.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        dt = arg_to_datetime(value)
    except Exception:
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def format_event_time(dt: datetime) -> str:
    """Format a UTC datetime for the XSIAM _time field, keeping millisecond precision."""
    return dt.strftime(XSIAM_TIME_FORMAT)[:-3] + "Z"


def get_partition_time(event: dict[str, Any]) -> datetime | None:
    """Derive an hour-accurate time from the logDate/logHour partition fields on the event."""
    log_date, log_hour = event.get("logDate"), event.get("logHour")
    if not log_date or log_hour is None:
        return None
    return parse_timestamp(f"{log_date}T{str(log_hour).zfill(2)}:00:00Z")


def get_event_time(event: dict[str, Any], log_type: str, fallback: datetime) -> str:
    """Resolve the event time, falling back to progressively coarser sources.

    The fallback is the start of the requested window rather than the current time. Using
    "now" would push the fetch checkpoint ahead of the data and silently drop every event
    that arrives afterwards with an earlier real timestamp.
    """
    candidates: list[Any] = []
    if log_type == "message":
        message = event.get("message")
        if isinstance(message, dict):
            candidates = [
                message.get("timestamp"),
                (message.get("action") or {}).get("timestamp") if isinstance(message.get("action"), dict) else None,
                (message.get("verdict") or {}).get("timestamp") if isinstance(message.get("verdict"), dict) else None,
            ]
    else:
        candidates = [event.get("timestamp")]

    for candidate in candidates:
        parsed = parse_timestamp(candidate)
        if parsed:
            return format_event_time(parsed)

    partition_time = get_partition_time(event)
    if partition_time:
        demisto.debug(f"No usable timestamp on a {log_type} event, using its logDate/logHour partition.")
        return format_event_time(partition_time)

    demisto.debug(f"No usable timestamp on a {log_type} event, using the window start {fallback.isoformat()}.")
    return format_event_time(fallback)


def get_event_id(event: dict[str, Any], log_type: str) -> str:
    """Build a stable identifier used to skip events that were already ingested.

    Message events are re-exported whenever a verdict or remediation changes, so hashing the
    whole record would ingest the same message again on every change. Instead the identity is
    the ETD message id combined with the markers that distinguish one state from the next.

    Audit and connection records are immutable once written, so the full record is hashed.
    """
    if log_type == "message":
        message = event.get("message")
        if isinstance(message, dict) and message.get("id"):
            verdict = message.get("verdict")
            action = message.get("action")
            identity = {
                "id": message.get("id"),
                "eventType": message.get("eventType"),
                "verdictTimestamp": verdict.get("timestamp") if isinstance(verdict, dict) else None,
                "actionTimestamp": action.get("timestamp") if isinstance(action, dict) else None,
            }
            return hash_identity(identity)
    return hash_identity(event)


def hash_identity(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def deduplicate_events(events: list[dict[str, Any]], seen_ids: set[str]) -> list[dict[str, Any]]:
    """Drop events whose id was already seen. The provided set is updated in place."""
    unique_events = []
    for event in events:
        event_id = event.get("event_id", "")
        if event_id in seen_ids:
            continue
        seen_ids.add(event_id)
        unique_events.append(event)
    return unique_events


""" FETCH STATE """


class FetchState:
    """Tracks which export files were already ingested, so re-read hours are not duplicated.

    File-level tracking is used instead of per-event ids because the number of export files
    per hour is small and bounded, while the number of events is not.
    """

    def __init__(self, last_run: dict[str, Any]):
        self.last_hour: str | None = last_run.get("last_hour")
        self.processed_files: list[str] = list(last_run.get("processed_files") or [])
        self.partial_file: dict[str, Any] = last_run.get("partial_file") or {}
        self._processed_lookup: set[str] = set(self.processed_files)

    def is_processed(self, path: str) -> bool:
        return path in self._processed_lookup

    def resume_offset(self, path: str) -> int:
        """Return the line to resume from when a file was only partially ingested."""
        if self.partial_file.get("path") == path:
            return int(self.partial_file.get("offset") or 0)
        return 0

    def mark_complete(self, path: str) -> None:
        if path not in self._processed_lookup:
            self.processed_files.append(path)
            self._processed_lookup.add(path)
        if self.partial_file.get("path") == path:
            self.partial_file = {}

    def mark_partial(self, path: str, offset: int) -> None:
        self.partial_file = {"path": path, "offset": offset}

    def to_last_run(self, last_hour: str) -> dict[str, Any]:
        """Serialize the state, pruning files that fall outside the next lookback window."""
        retain_from = parse_hour(last_hour) - timedelta(hours=LOOKBACK_HOURS)
        # A path whose hour cannot be parsed is kept, so an unexpected layout never drops state.
        retained = [path for path in self.processed_files if self._is_within(self._file_hour(path), retain_from)]
        if len(retained) > MAX_TRACKED_FILES:
            demisto.debug(f"Tracking {len(retained)} export files, keeping the newest {MAX_TRACKED_FILES}.")
            retained = retained[-MAX_TRACKED_FILES:]
        last_run: dict[str, Any] = {"last_hour": last_hour, "processed_files": retained}
        if self.partial_file:
            last_run["partial_file"] = self.partial_file
        return last_run

    @staticmethod
    def _is_within(file_hour: datetime | None, retain_from: datetime) -> bool:
        return file_hour is None or file_hour >= retain_from

    @staticmethod
    def _file_hour(path: str) -> datetime | None:
        """Extract the hour an export file belongs to from its partitioned object path."""
        match = FILE_HOUR_PATTERN.search(path)
        if not match:
            return None
        return parse_timestamp(f"{match.group(1)}T{match.group(2)}:00:00Z")


""" CLIENT """


class ETDClient(ContentClient):
    def __init__(self, base_url: str, params: dict):
        self.params = params
        super().__init__(
            base_url=base_url,
            headers={"Content-Type": "application/json"},
            verify=not params.get("insecure", False),
            proxy=params.get("proxy", False),
        )
        self.api_key = get_credential(params.get("api_key"))
        self._download_session = self._build_download_session()
        self._authenticate()

    def _build_download_session(self) -> requests.Session:
        """Session used for the pre-signed download links, with retries on transient failures.

        The links point at S3 rather than the ETD API, so they are fetched outside the API
        client. Proxy settings are inherited from the environment, which ContentClient already
        configured from the instance parameters.
        """
        session = requests.Session()
        retries = Retry(
            total=4,
            backoff_factor=1,
            status_forcelist=(408, 429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET"]),
            raise_on_status=False,
        )
        session.mount("https://", HTTPAdapter(max_retries=retries))
        session.mount("http://", HTTPAdapter(max_retries=retries))
        return session

    def _authenticate(self, force_refresh: bool = False) -> None:
        token = self.get_access_token(force_refresh=force_refresh)
        self._headers.update({"Authorization": f"Bearer {token}", "x-api-key": self.api_key})

    def get_access_token(self, force_refresh: bool = False) -> str:
        """Return a cached bearer token, requesting a new one when missing or close to expiry."""
        context = demisto.getIntegrationContext() or {}
        token = context.get("access_token")
        expiry = context.get("token_expiry") or 0
        if token and not force_refresh and datetime.now(UTC).timestamp() < expiry - TOKEN_EXPIRY_BUFFER_SECONDS:
            return token

        response = self._http_request(
            method="POST",
            url_suffix="/v1/oauth/token",
            headers={"x-api-key": self.api_key},
            auth=(str(self.params.get("client_id") or ""), get_credential(self.params.get("client_secret"))),
            timeout=30,
        )
        token = response.get("accessToken")
        if not token:
            raise DemistoException("Authentication succeeded but no access token was returned by Cisco ETD.")

        ttl = arg_to_number(response.get("expiresIn")) or DEFAULT_TOKEN_TTL_SECONDS
        context.update({"access_token": token, "token_expiry": datetime.now(UTC).timestamp() + ttl})
        demisto.setIntegrationContext(context)
        return token

    def request_log_export(self, start: str, end: str, event_types: list[str]) -> dict[str, Any]:
        """Request download links for a time range, retrying once if the token expired."""
        body = {"timeRange": [start, end], "logTypes": event_types}
        try:
            return self._http_request(method="POST", url_suffix="/v1/logs/downloadLinks", json_data=body, timeout=120)
        except DemistoException as error:
            if get_status_code(error) == 401:
                demisto.debug("Access token expired mid-fetch, refreshing and retrying once.")
                self._authenticate(force_refresh=True)
                return self._http_request(method="POST", url_suffix="/v1/logs/downloadLinks", json_data=body, timeout=120)
            raise translate_api_error(error)

    def get_links(self, response: dict[str, Any], event_types: list[str]) -> list[tuple[str, str]]:
        """Collect (log_type, link) pairs from the response, warning when the API truncated them."""
        data = response.get("data") or {}
        links: list[tuple[str, str]] = []
        for log_type in event_types:
            chunk = data.get(log_type)
            if not isinstance(chunk, list):
                continue
            if len(chunk) >= MAX_LINKS_PER_RESPONSE:
                demisto.error(
                    f"Cisco ETD returned {len(chunk)} '{log_type}' download links, which is the API maximum. "
                    "Some export files for this hour were truncated and their events will not be collected."
                )
            links.extend((log_type, link) for link in chunk if isinstance(link, str))
        return links

    def stream_events(
        self, log_type: str, link: str, window_start: datetime, limit: int, start_offset: int = 0
    ) -> tuple[list[dict[str, Any]], int, bool]:
        """Download one export file and parse up to `limit` events from it.

        Returns the parsed events, the line offset reached, and whether the file was read to
        the end. The response is streamed so a large export file is not held in memory twice.
        """
        events: list[dict[str, Any]] = []
        line_number = 0
        response = self._download_session.get(link, timeout=120, verify=self._verify, stream=True)
        if response.status_code != 200:
            raise DemistoException(f"Failed downloading the Cisco ETD '{log_type}' export file: {response.text[:500]}")

        with response:
            for line_number, line in enumerate(response.iter_lines(decode_unicode=True), start=1):
                if line_number <= start_offset:
                    continue
                if not line or not line.strip():
                    continue
                event = self.parse_line(line, log_type, window_start)
                if event:
                    events.append(event)
                if len(events) >= limit:
                    return events, line_number, False
        return events, line_number, True

    @staticmethod
    def parse_line(line: str, log_type: str, window_start: datetime) -> dict[str, Any] | None:
        """Parse a single NDJSON line into an event enriched with the fields XSIAM needs."""
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            demisto.error(f"Skipping an unparsable Cisco ETD '{log_type}' log line: {error}")
            return None
        if not isinstance(event, dict):
            demisto.error(f"Skipping a Cisco ETD '{log_type}' log line that is not a JSON object.")
            return None
        event["source_log_type"] = log_type
        event["event_id"] = get_event_id(event, log_type)
        event["_time"] = get_event_time(event, log_type, window_start)
        return event


""" ERROR HANDLING """


def get_status_code(error: DemistoException) -> int | None:
    response = getattr(error, "res", None)
    return getattr(response, "status_code", None)


def translate_api_error(error: DemistoException) -> DemistoException:
    """Turn an ETD API error into a message that tells the user what to actually do."""
    status_code = get_status_code(error)
    messages = {
        400: "Cisco ETD rejected the request. Verify the configured time range and credentials.",
        401: "The Cisco ETD access token expired and could not be refreshed. Verify the Client ID and Client Secret.",
        403: "Cisco ETD denied the request. Verify the API Key and that log export is enabled for this tenant.",
        429: "The Cisco ETD API rate limit or daily quota was exceeded. Contact Cisco support to request an increase.",
        503: "The Cisco ETD API is temporarily unavailable. Events will be collected on the next fetch.",
    }
    message = messages.get(status_code or 0)
    if not message:
        return error
    return DemistoException(f"{message}\nOriginal error: {error}", res=getattr(error, "res", None))


def is_fatal_error(error: Exception) -> bool:
    """Authentication and authorization problems will not resolve on their own, so they stop the fetch."""
    return isinstance(error, DemistoException) and get_status_code(error) in (400, 401, 403)


""" FETCH """


def calculate_fetch_window(last_hour: str | None, now: datetime) -> tuple[datetime, datetime]:
    """Determine which hours to request.

    The API cannot return the hour currently in progress, so the window always ends at the
    start of the current hour. Recent hours are re-read because export files keep being
    generated after an hour closes; already-downloaded files are skipped by path.
    """
    end = floor_to_hour(now)
    if last_hour:
        start = parse_hour(last_hour) - timedelta(hours=LOOKBACK_HOURS)
    else:
        # First run collects only the most recent completed hour, never historical data.
        start = end - timedelta(hours=FETCH_WINDOW_HOURS)

    earliest_allowed = end - timedelta(days=MAX_LOOKBACK_DAYS)
    if start < earliest_allowed:
        demisto.debug(f"Requested start {start.isoformat()} exceeds the 30 day retention, moving it forward.")
        start = earliest_allowed
    if start >= end:
        start = end - timedelta(hours=FETCH_WINDOW_HOURS)
    return start, end


def fetch_events(client: ETDClient, params: dict[str, Any]) -> None:
    """Collect events for every completed hour since the last run and send them to XSIAM."""
    max_fetch = get_positive_int(params.get("max_fetch"), DEFAULT_MAX_FETCH, "Max fetch")
    event_types = argToList(params.get("event_type")) or ETD_LOG_TYPES
    state = FetchState(demisto.getLastRun() or {})
    start, end = calculate_fetch_window(state.last_hour, datetime.now(UTC))
    demisto.debug(f"Fetching Cisco ETD {event_types} events for {format_hour(start)} -> {format_hour(end)}")

    reached_hour = state.last_hour or format_hour(start)
    try:
        reached_hour = collect_intervals(client, state, event_types, start, end, max_fetch, reached_hour)
    except Exception as error:
        # Progress made before the failure is kept so the same files are not downloaded again,
        # while the failed hours stay inside the next lookback window and will be retried.
        demisto.setLastRun(state.to_last_run(reached_hour))
        demisto.error(f"Cisco ETD fetch stopped after {reached_hour}: {error}")
        raise
    demisto.setLastRun(state.to_last_run(reached_hour))
    demisto.debug(f"Cisco ETD fetch finished, checkpoint saved at {reached_hour}")


def collect_intervals(
    client: ETDClient,
    state: FetchState,
    event_types: list[str],
    start: datetime,
    end: datetime,
    max_fetch: int,
    reached_hour: str,
) -> str:
    """Iterate the fetch window hour by hour. Returns the last hour that was fully processed."""
    remaining = max_fetch
    deadline = time.time() + FETCH_TIME_BUDGET_SECONDS
    seen_ids: set[str] = set()

    for window_start, window_end in generate_intervals(start, end, FETCH_WINDOW_HOURS):
        if remaining <= 0 or time.time() >= deadline:
            demisto.debug(f"Stopping at {format_hour(window_start)}: budget or max fetch reached.")
            break
        response = client.request_log_export(format_hour(window_start), format_hour(window_end), event_types)
        links = client.get_links(response, event_types)
        remaining = collect_links(client, state, links, window_start, remaining, deadline, seen_ids)
        if remaining <= 0:
            break
        # The hour is only checkpointed once all of its files were ingested.
        reached_hour = format_hour(window_end)
    return reached_hour


def collect_links(
    client: ETDClient,
    state: FetchState,
    links: list[tuple[str, str]],
    window_start: datetime,
    remaining: int,
    deadline: float,
    seen_ids: set[str],
) -> int:
    """Download and send the export files of a single hour. Returns the remaining event budget."""
    for log_type, link in links:
        if remaining <= 0 or time.time() >= deadline:
            return 0
        path = get_object_path(link)
        if state.is_processed(path):
            continue

        offset = state.resume_offset(path)
        events, reached_offset, completed = client.stream_events(log_type, link, window_start, remaining, offset)
        events = deduplicate_events(events, seen_ids)
        if events:
            send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            remaining -= len(events)
            demisto.debug(f"Sent {len(events)} '{log_type}' events from {path}")

        if completed:
            state.mark_complete(path)
        else:
            # The file was cut short by max_fetch, so the next run resumes from this line.
            state.mark_partial(path, reached_offset)
            return 0
    return remaining


""" COMMANDS """


def parse_command_range(args: dict[str, Any]) -> tuple[datetime, datetime]:
    """Resolve the start and end arguments of the debug command into API hour boundaries."""
    now = datetime.now(UTC)
    start = arg_to_datetime(args.get("start_time") or "1 hour ago", arg_name="start_time")
    end = arg_to_datetime(args.get("end_time") or "now", arg_name="end_time")
    if start is None or end is None:
        raise DemistoException("Could not parse start_time or end_time.")

    start_dt, end_dt = floor_to_hour(start), floor_to_hour(end)
    if end_dt > floor_to_hour(now):
        demisto.debug("end_time is in the current hour, which the API cannot return yet. Using the last closed hour.")
        end_dt = floor_to_hour(now)
    if start_dt >= end_dt:
        raise DemistoException("start_time must be at least one full hour earlier than end_time.")
    if start_dt < end_dt - timedelta(days=MAX_LOOKBACK_DAYS):
        raise DemistoException(f"start_time cannot be older than {MAX_LOOKBACK_DAYS} days, which is the ETD retention.")
    return start_dt, end_dt


def cisco_etd_get_events_command(client: ETDClient, args: dict[str, Any]) -> CommandResults:
    """Fetch events for an explicit time range without touching the fetch checkpoint."""
    limit = get_positive_int(args.get("limit"), DEFAULT_LIMIT, "limit")
    event_types = argToList(args.get("log_type")) or ETD_LOG_TYPES
    start_dt, end_dt = parse_command_range(args)

    events: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for window_start, window_end in generate_intervals(start_dt, end_dt, MAX_API_RANGE_HOURS):
        if len(events) >= limit:
            break
        response = client.request_log_export(format_hour(window_start), format_hour(window_end), event_types)
        for log_type, link in client.get_links(response, event_types):
            if len(events) >= limit:
                break
            batch, _, _ = client.stream_events(log_type, link, window_start, limit - len(events))
            events.extend(deduplicate_events(batch, seen_ids))

    if argToBoolean(args.get("should_push_events", False)) and events:
        send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)

    if not events:
        return CommandResults(readable_output="No events were found for the requested time range.")

    readable = tableToMarkdown(
        f"Cisco ETD events ({format_hour(start_dt)} -> {format_hour(end_dt)})",
        [
            {"Event ID": event.get("event_id"), "Log Type": event.get("source_log_type"), "Time": event.get("_time")}
            for event in events
        ],
        headers=["Event ID", "Log Type", "Time"],
        removeNull=True,
    )
    return CommandResults(readable_output=readable)


def test_module(client: ETDClient) -> str:
    """Verify credentials and export permissions without downloading any export file."""
    end = floor_to_hour(datetime.now(UTC))
    client.request_log_export(format_hour(end - timedelta(hours=1)), format_hour(end), ETD_LOG_TYPES)
    return "ok"


""" MAIN """


def main() -> None:
    params = demisto.params()
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    try:
        client = ETDClient(base_url=params.get("etd_base_url"), params=params)
        if command == "test-module":
            return_results(test_module(client))
        elif command == "cisco-etd-get-events":
            return_results(cisco_etd_get_events_command(client, demisto.args()))
        elif command == "fetch-events":
            fetch_events(client, params)
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as error:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute the {command} command.\nError: {error}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
