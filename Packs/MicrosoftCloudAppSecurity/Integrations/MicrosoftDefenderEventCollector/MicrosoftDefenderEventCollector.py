"""Microsoft Defender for Cloud Apps Event Collector Integration.

This integration fetches events from Microsoft Defender for Cloud Apps API
using async HTTP requests for improved throughput. It supports fetching
alerts, admin activities, and login activities concurrently.
"""

import asyncio
import ssl
from datetime import datetime, UTC
from typing import NamedTuple

import aiohttp
import dateparser
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from MicrosoftApiModule import *

# pylint: disable=no-name-in-module
# pylint: disable=no-self-argument
from CommonServerUserPython import *  # noqa

# Configuration
# Sequential pagination within each event type, but all 3 event types run concurrently
MAX_FETCH_PER_TYPE = 10000  # Max events per type per fetch cycle
DEFAULT_FROM_FETCH_PARAMETER = "3 days"
CONCURRENT_REQUESTS = 3  # One per event type (alerts, admin, login)
MAX_PAGES_PER_TYPE = 100  # Allow more pages for high-volume types

# Debug version identifier
DEBUG_VERSION = "2026-01-14-async-v13-revert-scan-mode"


class EventFilter(NamedTuple):
    """Event filter configuration."""

    ui_name: str
    name: str
    endpoint: str
    filters: dict


# Event type configurations
ALERTS_FILTER = EventFilter("Alerts", "alerts", "alerts", {})
ADMIN_ACTIVITIES_FILTER = EventFilter("Admin activities", "activities_admin", "activities", {"activity.type": {"eq": True}})
LOGIN_ACTIVITIES_FILTER = EventFilter(
    "Login activities",
    "activities_login",
    "activities",
    {"activity.eventType": {"eq": ["EVENT_CATEGORY_LOGIN", "EVENT_CATEGORY_FAILED_LOGIN"]}},
)

ALL_EVENT_FILTERS = [ALERTS_FILTER, ADMIN_ACTIVITIES_FILTER, LOGIN_ACTIVITIES_FILTER]
UI_NAME_TO_EVENT_FILTERS = {ef.ui_name: ef for ef in ALL_EVENT_FILTERS}

# Constants
AUTH_ERROR_MSG = "Authorization Error: make sure tenant id, client id and client secret is correctly set"
VENDOR = "Microsoft"
PRODUCT = "defender_cloud_apps"


def _get_token(params: dict) -> str:
    """Get OAuth token from Microsoft API."""
    endpoint_type_name = params.get("endpoint_type") or "Worldwide"
    endpoint_type = MICROSOFT_DEFENDER_FOR_APPLICATION_TYPE[endpoint_type_name]
    azure_cloud = AZURE_CLOUDS[endpoint_type]

    ms_client = MicrosoftClient(
        base_url=params["url"],
        tenant_id=params["tenant_id"],
        auth_id=params["client_id"],
        enc_key=params["client_secret"],
        scope=params["scope"],
        verify=params.get("verify", True),
        self_deployed=True,
        azure_cloud=azure_cloud,
        command_prefix="microsoft-defender-cloud-apps",
    )
    return ms_client.get_access_token()


async def _fetch_events_for_type(
    session: aiohttp.ClientSession,
    base_url: str,
    headers: dict,
    event_filter: EventFilter,
    after_timestamp: int | None,
    max_events: int = MAX_FETCH_PER_TYPE,
) -> list[dict]:
    """Fetch all events for a single event type.

    Args:
        session: aiohttp session
        base_url: API base URL
        headers: Request headers with auth token
        event_filter: Event filter configuration
        after_timestamp: Fetch events after this timestamp (ms)
        max_events: Maximum number of events to fetch for this type

    Returns:
        List of events for this event type
    """
    url = f"{base_url}{event_filter.endpoint}"

    # Build initial filters
    filters = dict(event_filter.filters)
    if after_timestamp:
        filters["date"] = {"gte": after_timestamp}

    # Request body
    request_body: dict = {
        "filters": filters,
        "limit": 100,
        "sortDirection": "asc",
    }

    all_events: list[dict] = []
    page = 1

    demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: ===== FETCHING {event_filter.name} =====")
    demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: URL: {url}, after_timestamp={after_timestamp}, max_events={max_events}")
    demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Initial request body: {json.dumps(request_body)}")

    while page <= MAX_PAGES_PER_TYPE:
        try:
            # Use POST with JSON body
            async with session.post(url, json=request_body, headers=headers) as response:
                if response.status == 429:
                    retry_after = int(response.headers.get("Retry-After", 60))
                    demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Rate limited, waiting {retry_after}s")
                    await asyncio.sleep(retry_after)
                    continue

                response.raise_for_status()
                data = await response.json()

        except aiohttp.ClientError as e:
            demisto.error(f"MD-DEBUG [{DEBUG_VERSION}]: Error fetching {event_filter.name}: {e}")
            raise DemistoException(f"Failed to fetch {event_filter.name}: {e}") from e

        events = data.get("data", [])
        has_next = data.get("hasNext", False)

        # Log first and last event timestamps for this page
        first_ts = events[0].get("timestamp") if events else None
        last_ts = events[-1].get("timestamp") if events else None

        demisto.debug(
            f"MD-DEBUG [{DEBUG_VERSION}]: {event_filter.name} page {page}: "
            f"{len(events)} events, hasNext={has_next}, "
            f"first_ts={first_ts}, last_ts={last_ts}, "
            f"total_so_far={len(all_events) + len(events)}"
        )

        # Tag events with their type
        for event in events:
            event["event_type_name"] = event_filter.name

        all_events.extend(events)

        # Check if we've reached our limit
        if len(all_events) >= max_events:
            events_before_truncate = len(all_events)
            all_events = all_events[:max_events]

            max_ts_in_kept = max((e.get("timestamp", 0) for e in all_events), default=0)

            demisto.debug(
                f"MD-DEBUG [{DEBUG_VERSION}]: {event_filter.name} TRUNCATING: "
                f"had {events_before_truncate} events, keeping {len(all_events)}, "
                f"max_ts in kept events: {max_ts_in_kept}"
            )
            break

        # Check if there are no more events
        if not has_next or not events:
            demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: {event_filter.name} no more events (hasNext={has_next})")
            break

        # Fallback to timestamp-based pagination
        # Note: API might return events in descending order despite sortDirection: asc
        # So we must find the MAX timestamp in the batch to ensure we move forward
        if events:
            max_timestamp = max(e.get("timestamp", 0) for e in events)
            filters = dict(event_filter.filters)
            filters["date"] = {"gte": max_timestamp + 1}
            request_body["filters"] = filters
            demisto.debug(
                f"MD-DEBUG [{DEBUG_VERSION}]: {event_filter.name} pagination: gte={max_timestamp + 1}"
            )
        else:
            demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: {event_filter.name} no pagination info, stopping")
            break

        page += 1

    if page > MAX_PAGES_PER_TYPE:
        demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: {event_filter.name} reached max pages limit ({MAX_PAGES_PER_TYPE})")

    # Final summary with min/max timestamps
    if all_events:
        min_ts = min(e.get("timestamp", float("inf")) for e in all_events)
        max_ts = max(e.get("timestamp", 0) for e in all_events)
        demisto.debug(
            f"MD-DEBUG [{DEBUG_VERSION}]: {event_filter.name} COMPLETE: "
            f"{len(all_events)} events in {page} pages, "
            f"timestamp range: {min_ts} to {max_ts}"
        )
    else:
        demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: {event_filter.name} COMPLETE: 0 events")

    return all_events


async def fetch_all_events(
    params: dict, event_filters: list[EventFilter], max_events_per_type: int = MAX_FETCH_PER_TYPE
) -> tuple[list[dict], dict[str, int | None]]:
    """Fetch events from all event types concurrently.

    Args:
        params: Integration parameters
        event_filters: List of event filters to fetch
        max_events_per_type: Maximum events to fetch per event type

    Returns:
        Tuple of (all_events, requested_start_times)
    """
    base_url = f"{params['url']}/api/v1/"
    # Use asyncio.to_thread to avoid blocking the event loop during token acquisition
    # MicrosoftClient.get_access_token() uses synchronous requests library internally
    token = await asyncio.to_thread(_get_token, params)
    headers = {"Authorization": f"Bearer {token}"}

    # Get last run timestamps
    last_run = demisto.getLastRun()
    demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Current last_run state: {last_run}")

    after_param = params.get("after") or DEFAULT_FROM_FETCH_PARAMETER

    default_after: int | None = None
    if after_param and not isinstance(after_param, int):
        parsed = dateparser.parse(after_param)
        default_after = int(parsed.timestamp() * 1000) if parsed else None
    elif isinstance(after_param, int):
        default_after = after_param

    demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: default_after={default_after}")

    # Configure SSL
    ssl_context: ssl.SSLContext | bool = True
    if not params.get("verify", True):
        ssl_context = False
    connector = aiohttp.TCPConnector(ssl=ssl_context, limit=CONCURRENT_REQUESTS)

    requested_start_times: dict[str, int | None] = {}

    async with aiohttp.ClientSession(connector=connector) as session:
        # Create tasks for all event types
        tasks = []
        for ef in event_filters:
            after_ts: int | None = last_run.get(ef.name) or default_after
            requested_start_times[ef.name] = after_ts
            demisto.debug(
                f"MD-DEBUG [{DEBUG_VERSION}]: {ef.name} starting from timestamp {after_ts} "
                f"(from last_run: {last_run.get(ef.name)}, default: {default_after})"
            )

            task = _fetch_events_for_type(session, base_url, headers, ef, after_ts, max_events_per_type)
            tasks.append(task)

        # Run all fetches concurrently
        demisto.debug(
            f"MD-DEBUG [{DEBUG_VERSION}]: Starting concurrent fetch for {len(tasks)} event types, "
            f"max_events_per_type={max_events_per_type}"
        )
        results = await asyncio.gather(*tasks, return_exceptions=True)

    # Collect results
    all_events: list[dict] = []
    for i, result in enumerate(results):
        ef = event_filters[i]
        if isinstance(result, BaseException):
            demisto.error(f"MD-DEBUG: Failed to fetch {ef.name}: {result}")
        elif isinstance(result, list):
            demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: {ef.name} returned {len(result)} events")
            all_events.extend(result)

    demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Total events fetched across all types: {len(all_events)}")
    return all_events, requested_start_times


def _timestamp_to_human(ts: int | None) -> str:
    """Convert millisecond timestamp to human readable format."""
    if ts is None:
        return "None"
    try:
        dt = datetime.fromtimestamp(ts / 1000, tz=UTC)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return f"Invalid({ts})"


def _get_time_gap(ts: int | None) -> str:
    """Get time gap from now."""
    if ts is None:
        return "N/A"
    try:
        now = datetime.now(tz=UTC)
        event_time = datetime.fromtimestamp(ts / 1000, tz=UTC)
        gap = now - event_time
        return f"{gap.days}d {gap.seconds // 3600}h {(gap.seconds % 3600) // 60}m ago"
    except Exception:
        return "N/A"


def calculate_last_run(events: list[dict], requested_start_times: dict[str, int | None]) -> dict[str, int]:
    """Calculate next last_run based on fetched events.

    Args:
        events: List of fetched events
        requested_start_times: Start times that were requested

    Returns:
        Updated last_run dictionary
    """
    last_run = demisto.getLastRun()
    demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: ========== CALCULATING LAST_RUN ==========")
    demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Total events to process: {len(events)}")
    demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Previous last_run: {last_run}")
    demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: requested_start_times: {requested_start_times}")

    # Count events and find min/max timestamps per type
    event_stats: dict[str, dict] = {}
    for event in events:
        event_type = event.get("event_type_name", "unknown")
        timestamp = event.get("timestamp")

        if event_type not in event_stats:
            event_stats[event_type] = {"count": 0, "min_ts": None, "max_ts": None}

        event_stats[event_type]["count"] += 1

        if timestamp:
            if event_stats[event_type]["min_ts"] is None or timestamp < event_stats[event_type]["min_ts"]:
                event_stats[event_type]["min_ts"] = timestamp
            if event_stats[event_type]["max_ts"] is None or timestamp > event_stats[event_type]["max_ts"]:
                event_stats[event_type]["max_ts"] = timestamp

    # Log detailed stats per event type
    for event_type, stats in event_stats.items():
        min_ts = stats["min_ts"]
        max_ts = stats["max_ts"]
        demisto.debug(
            f"MD-DEBUG [{DEBUG_VERSION}]: {event_type}: "
            f"count={stats['count']}, "
            f"min_ts={min_ts} ({_timestamp_to_human(min_ts)}), "
            f"max_ts={max_ts} ({_timestamp_to_human(max_ts)}, {_get_time_gap(max_ts)})"
        )

    # Update last_run with new timestamps (max_ts + 1)
    for event_type, stats in event_stats.items():
        max_ts = stats["max_ts"]
        if max_ts:
            old_value = last_run.get(event_type)
            new_value = max_ts + 1  # +1 to avoid re-fetching the same event
            last_run[event_type] = new_value

            # Calculate progress
            if isinstance(old_value, int):
                progress_ms = new_value - old_value
                progress_sec = progress_ms / 1000
                demisto.debug(
                    f"MD-DEBUG [{DEBUG_VERSION}]: {event_type}: "
                    f"{old_value} ({_timestamp_to_human(old_value)}) -> "
                    f"{new_value} ({_timestamp_to_human(new_value)}) "
                    f"[progress: {progress_sec:.1f}s = {progress_ms}ms]"
                )
            else:
                demisto.debug(
                    f"MD-DEBUG [{DEBUG_VERSION}]: {event_type}: " f"None -> {new_value} ({_timestamp_to_human(new_value)})"
                )

    # Ensure all requested types have entries (for types with no events)
    for event_type, start_time in requested_start_times.items():
        if event_type not in last_run and start_time:
            demisto.debug(
                f"MD-DEBUG [{DEBUG_VERSION}]: {event_type} had no events, "
                f"keeping start_time: {start_time} ({_timestamp_to_human(start_time)})"
            )
            last_run[event_type] = start_time

    demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Final last_run: {last_run}")
    demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: ========== END CALCULATING LAST_RUN ==========")
    return last_run


async def test_module_async(params: dict) -> str:
    """Test API connectivity."""
    try:
        events, _ = await fetch_all_events(params, [ALERTS_FILTER], max_events_per_type=1)
        return "ok"
    except DemistoException as e:
        if "Forbidden" in str(e) or "authenticate" in str(e):
            return AUTH_ERROR_MSG
        raise


def main():
    """Main entry point."""
    command = demisto.command()
    params = demisto.params() | demisto.args() | demisto.getLastRun()
    params["client_secret"] = params.get("credentials", {}).get("password", "")

    demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Command: {command}")
    demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Time: " f"{datetime.now(tz=UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}")

    try:
        # Determine which event types to fetch
        requested_types = argToList(params.get("event_types_to_fetch", []))
        if requested_types:
            event_filters = [ef for ef in ALL_EVENT_FILTERS if ef.ui_name in requested_types]
        else:
            event_filters = ALL_EVENT_FILTERS

        if command == "test-module":
            result = asyncio.run(test_module_async(params))
            return_results(result)

        elif command == "microsoft-defender-cloud-apps-auth-reset":
            return_results(reset_auth())

        elif command in ("fetch-events", "microsoft-defender-cloud-apps-get-events"):
            # Get limit - use MAX_FETCH_PER_TYPE for fetch-events, or user-specified for manual command
            if command == "fetch-events":
                max_events = MAX_FETCH_PER_TYPE
            else:
                max_events = arg_to_number(params.get("limit")) or MAX_FETCH_PER_TYPE

            demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Using max_events_per_type={max_events}")

            # Fetch events asynchronously
            events, requested_start_times = asyncio.run(fetch_all_events(params, event_filters, max_events))

            if command == "fetch-events":
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
                next_run = calculate_last_run(events, requested_start_times)
                demisto.setLastRun(next_run)
            else:
                return_results(
                    CommandResults(
                        readable_output=tableToMarkdown(
                            "Microsoft Defender Cloud Apps Events", events, headerTransform=pascalToSpace
                        ),
                        outputs_prefix="Microsoft.Events",
                        outputs_key_field="_id",
                        outputs=events,
                        raw_response=events,
                    )
                )
                if argToBoolean(params.get("should_push_events", False)):
                    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        else:
            raise DemistoException(f"Unknown command: {command}")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command}: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
