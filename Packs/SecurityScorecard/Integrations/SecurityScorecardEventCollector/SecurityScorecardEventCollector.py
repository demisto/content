import traceback
from datetime import datetime, timezone  # noqa: UP017
from typing import Any

import demistomock as demisto  # noqa: F401
from ContentClientApiModule import *
from CommonServerPython import *  # noqa: F401

# region Constants
INTEGRATION_NAME = "SecurityScorecard Event Collector"


class Config:
    """Global static configuration."""

    VENDOR = "SecurityScorecard"
    PRODUCT = "SecurityScorecard"

    # Date format for API requests (ISO 8601)
    DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

    # Fetch defaults
    DEFAULT_MAX_FETCH = 1000
    DEFAULT_FIRST_FETCH = "1 day"

    # API status codes
    RATE_LIMIT_STATUS_CODE = 429


# region Client
# =================================
# Client
# =================================


class Client(ContentClient):
    """SecurityScorecard API client for fetching history events.

    Extends ContentClient for built-in retry logic, rate-limit handling,
    structured logging, and authentication via APIKeyAuthHandler.

    Attributes:
        scorecard_identifier: The domain identifier for the scorecard (e.g., google.com).
    """

    def __init__(
        self,
        base_url: str,
        api_token: str,
        scorecard_identifier: str,
        verify: bool,
        proxy: bool,
    ):
        auth_handler = APIKeyAuthHandler(
            key=f"Token {api_token}",
            header_name="Authorization",
        )
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            auth_handler=auth_handler,
            headers={"Accept": "application/json"},
            client_name="SecurityScorecardEventCollector",
            ok_codes=(200, 429),
        )
        self.scorecard_identifier = scorecard_identifier

    def get_history_events(
        self,
        date_from: str,
        date_to: str,
    ) -> list[dict[str, Any]]:
        """Fetch history events for the scorecard identifier.

        Args:
            date_from: Start date in ISO 8601 format.
            date_to: End date in ISO 8601 format.

        Returns:
            List of event entries.

        Raises:
            RateLimitError: If the API returns a 429 status code.
        """
        params = assign_params(date_from=date_from, date_to=date_to)

        demisto.debug(f"[API] Fetching history events for '{self.scorecard_identifier}' from {date_from} to {date_to}")

        response = self._http_request(
            method="GET",
            url_suffix=f"companies/{self.scorecard_identifier}/history/events",
            params=params,
            resp_type="response",
            ok_codes=(200, 429),
        )

        if response.status_code == Config.RATE_LIMIT_STATUS_CODE:
            retry_after = response.headers.get("Retry-After", "60")
            demisto.debug(f"[API] Rate limit hit on history events. Retry-After: {retry_after}")
            raise RateLimitError(retry_after=retry_after)

        response_json = response.json()
        entries = response_json.get("entries", [])
        demisto.debug(f"[API] Fetched {len(entries)} history events.")
        return entries

    def get_detail_url_response(self, detail_url: str) -> dict[str, Any]:
        """Fetch the detailed response for a given detail_url.

        Args:
            detail_url: The full URL to fetch detail data from.

        Returns:
            The JSON response from the detail URL.

        Raises:
            RateLimitError: If the API returns a 429 status code.
        """
        demisto.debug(f"[API] Fetching detail URL: {detail_url}")

        response = self._http_request(
            method="GET",
            full_url=detail_url,
            resp_type="response",
            ok_codes=(200, 429),
        )

        if response.status_code == Config.RATE_LIMIT_STATUS_CODE:
            retry_after = response.headers.get("Retry-After", "60")
            demisto.debug(f"[API] Rate limit hit on detail URL. Retry-After: {retry_after}")
            raise RateLimitError(retry_after=retry_after)

        return response.json()


# endregion


# region Helpers
# =================================
# Helpers
# =================================


class RateLimitError(Exception):
    """Raised when the API returns a 429 Too Many Requests response."""

    def __init__(self, retry_after: str = "60"):
        self.retry_after = retry_after
        super().__init__(f"Rate limit exceeded. Retry after {retry_after} seconds.")


def add_time_to_events(events: list[dict[str, Any]]) -> None:
    """Add _time field to events for XSIAM ingestion.

    Maps the event's 'date' field to '_time' for proper XSIAM indexing.
    """
    for event in events:
        event_time = event.get("date")
        if event_time:
            event["_time"] = event_time
        else:
            demisto.debug(f"[Event Time] WARNING: Event missing 'date' field: {event.get('id', 'unknown')}")


def deduplicate_events(
    events: list[dict[str, Any]],
    last_fetched_ids: list[int],
) -> list[dict[str, Any]]:
    """Remove already-processed events based on previously fetched IDs.

    Args:
        events: List of events to deduplicate.
        last_fetched_ids: List of event IDs from the previous fetch cycle.

    Returns:
        List of new events that were not previously fetched.
    """
    if not events:
        demisto.debug("[Dedup] No events to process.")
        return events

    if not last_fetched_ids:
        demisto.debug("[Dedup] No deduplication needed (first run - no previous IDs).")
        return events

    demisto.debug(f"[Dedup] Checking {len(events)} events against " f"{len(last_fetched_ids)} previously fetched IDs.")

    fetched_ids_set = set(last_fetched_ids)
    new_events = [event for event in events if event.get("id") not in fetched_ids_set]

    skipped_count = len(events) - len(new_events)
    if skipped_count > 0:
        demisto.debug(f"[Dedup] Skipped {skipped_count} duplicates. {len(new_events)} new events remain.")
    else:
        demisto.debug("[Dedup] No duplicates found.")

    return new_events


def calculate_last_run(
    events: list[dict[str, Any]],
    last_run: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Calculate the last run state from the given events.

    Saves the most recent date and the IDs of events that share that date
    for deduplication on the next run. If the most recent date matches the
    previous fetch date from last_run, the IDs are merged to prevent
    duplicate ingestion across fetch cycles.

    Args:
        events: List of events (sorted by date ascending).
        last_run: Previous last run state dictionary (optional).

    Returns:
        Dictionary with 'last_fetch' (date string) and 'last_fetched_ids' (list of ints).
    """
    if not events:
        return {}

    last_event = events[-1]
    last_date = last_event.get("date", "")

    # Collect all IDs that share the same date as the last event
    ids_at_last_date = [event.get("id") for event in events if event.get("date") == last_date and event.get("id") is not None]

    # Merge with previous IDs if the date hasn't changed
    if last_run and last_run.get("last_fetch") == last_date:
        previous_ids: list[int] = last_run.get("last_fetched_ids", [])
        merged_ids = list(set(previous_ids) | set(ids_at_last_date))
        demisto.debug(
            f"[LastRun] Same date {last_date} as previous run. "
            f"Merged {len(previous_ids)} previous + {len(ids_at_last_date)} new IDs = {len(merged_ids)} total."
        )
        ids_at_last_date = merged_ids

    demisto.debug(f"[LastRun] New high-water mark: {last_date} with {len(ids_at_last_date)} IDs.")

    return {
        "last_fetch": last_date,
        "last_fetched_ids": ids_at_last_date,
    }


def get_fetch_start_time(params: dict[str, Any], last_run: dict[str, Any]) -> str:
    """Determine the start time for fetching events.

    Uses last_run if available, otherwise falls back to first_fetch parameter.

    Args:
        params: Integration parameters.
        last_run: Last run state dictionary.

    Returns:
        ISO 8601 formatted date string.
    """
    last_fetch = last_run.get("last_fetch")
    if last_fetch:
        demisto.debug(f"[Fetch] Continuing from last run: {last_fetch}")
        return last_fetch

    first_fetch = params.get("first_fetch", Config.DEFAULT_FIRST_FETCH)
    demisto.debug(f"[Fetch] First run - using first_fetch parameter: {first_fetch}")

    first_fetch_dt = arg_to_datetime(arg=first_fetch, arg_name="first_fetch", required=True)
    if first_fetch_dt is None:
        raise DemistoException(f"Failed to parse first_fetch parameter: {first_fetch}")

    return first_fetch_dt.strftime(Config.DATE_FORMAT)


# endregion


# region Commands
# =================================
# Commands
# =================================


def test_module(client: Client) -> str:
    """Test API connectivity by fetching a small window of events.

    Args:
        client: The SecurityScorecard API client.

    Returns:
        'ok' if the test succeeds.
    """
    demisto.debug("[Test Module] Starting...")
    try:
        now = datetime.now(timezone.utc)  # noqa: UP017
        date_from = (now - timedelta(days=1)).strftime(Config.DATE_FORMAT)
        date_to = now.strftime(Config.DATE_FORMAT)

        client.get_history_events(date_from=date_from, date_to=date_to)
        demisto.debug("[Test Module] Success.")
        return "ok"

    except RateLimitError:
        # If we hit rate limit, the connection is working
        demisto.debug("[Test Module] Rate limit hit but connection is working.")
        return "ok"

    except ContentClientAuthenticationError as error:
        demisto.debug(f"[Test Module] Auth failed: {error}")
        return "Authorization Error: Verify your API Token."

    except Exception as error:
        error_msg = str(error)
        demisto.debug(f"[Test Module] Failed: {error_msg}")
        if "401" in error_msg or "403" in error_msg:
            return "Authorization Error: Verify your API Token."
        raise


def get_events_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults | str:
    """Manual command to get events for debugging/development.

    Args:
        client: The SecurityScorecard API client.
        args: Command arguments including:
            - start_time: Start time for fetching events (required).
            - end_time: End time for fetching events (optional, defaults to now).
            - event_type: Filter events by type (optional).
            - limit: Maximum number of events to retrieve (optional, default 1000).
            - should_push_events: Whether to push events to XSIAM (optional, default false).

    Returns:
        CommandResults with the events or a string message if pushed to XSIAM.
    """
    demisto.debug("[Command] get-events triggered.")

    limit = arg_to_number(args.get("limit", Config.DEFAULT_MAX_FETCH)) or Config.DEFAULT_MAX_FETCH
    should_push_events = argToBoolean(args.get("should_push_events", False))
    event_type_filter = args.get("event_type")

    start_time_input = args.get("start_time", "3 days ago")
    end_time_input = args.get("end_time")

    start_time_dt = arg_to_datetime(arg=start_time_input, arg_name="start_time", required=True)
    if start_time_dt is None:
        raise DemistoException(f"Failed to parse start_time: {start_time_input}")
    date_from = start_time_dt.strftime(Config.DATE_FORMAT)

    if end_time_input:
        end_time_dt = arg_to_datetime(arg=end_time_input, arg_name="end_time")
        if end_time_dt is None:
            raise DemistoException(f"Failed to parse end_time: {end_time_input}")
        date_to = end_time_dt.strftime(Config.DATE_FORMAT)
    else:
        date_to = datetime.now(timezone.utc).strftime(Config.DATE_FORMAT)  # noqa: UP017

    demisto.debug(
        f"[Command Params] From: {date_from}, To: {date_to}, "
        f"Limit: {limit}, EventType: {event_type_filter}, Push: {should_push_events}"
    )

    events = client.get_history_events(date_from=date_from, date_to=date_to)

    # Sort by date ascending
    events.sort(key=lambda x: x.get("date", ""))

    # Filter by event_type if specified
    if event_type_filter:
        events = [event for event in events if event.get("event_type") == event_type_filter]
        demisto.debug(f"[Command] Filtered to {len(events)} events with event_type='{event_type_filter}'.")

    # Apply limit
    if len(events) > limit:
        events = events[:limit]

    # Enrich with detail URLs (use safe version to handle rate limits gracefully)
    events, rate_limited = _safe_enrich_events(client, events)
    if rate_limited:
        demisto.debug("[Command] Rate limit hit during enrichment. Returning partial results.")

    # Always add _time field for standardized event output
    add_time_to_events(events)

    if should_push_events and events:
        send_events_to_xsiam(events=events, vendor=Config.VENDOR, product=Config.PRODUCT)
        demisto.debug(f"[Command] Pushed {len(events)} events to XSIAM.")
        return f"Successfully retrieved and pushed {len(events)} events to XSIAM."

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Events",
        events,
        removeNull=True,
        headers=["id", "date", "event_type", "factor", "severity", "issue_type", "group_status"],
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="SecurityScorecard.Event",
        outputs_key_field="id",
        outputs=events,
    )


def fetch_events_command(client: Client, params: dict[str, Any]) -> None:
    """Scheduled command to fetch events and send them to XSIAM.

    Handles rate limiting gracefully by sending whatever events were collected
    before the rate limit was hit, updating last_run accordingly, and waiting
    for the next fetch cycle.

    Args:
        client: The SecurityScorecard API client.
        params: Integration parameters from demisto.params().
    """
    max_fetch = arg_to_number(params.get("max_fetch", Config.DEFAULT_MAX_FETCH)) or Config.DEFAULT_MAX_FETCH

    last_run = demisto.getLastRun()
    raw_ids = last_run.get("last_fetched_ids")
    last_fetched_ids: list[int] = raw_ids if isinstance(raw_ids, list) else []

    date_from = get_fetch_start_time(params, last_run)
    date_to = datetime.now(timezone.utc).strftime(Config.DATE_FORMAT)  # noqa: UP017

    demisto.debug(
        f"[Command Params] From: {date_from}, To: {date_to}, " f"Max: {max_fetch}, Previous IDs count: {len(last_fetched_ids)}"
    )

    # Step 1: Fetch history events
    rate_limit_on_history = False
    try:
        events = client.get_history_events(date_from=date_from, date_to=date_to)
    except RateLimitError:
        demisto.debug("[Fetch] Rate limit hit on history events API. No events to process.")
        rate_limit_on_history = True
        events = []

    if not events or rate_limit_on_history:
        demisto.debug("[Fetch] No events found or rate limited on initial fetch.")
        return

    # Step 2: Sort events by date ascending
    events.sort(key=lambda x: x.get("date", ""))

    # Step 3: Deduplicate against previous run
    events = deduplicate_events(events, last_fetched_ids)

    if not events:
        demisto.debug("[Fetch] All events were duplicates. Preserving last_run with existing dedup IDs.")
        demisto.setLastRun({"last_fetch": date_from, "last_fetched_ids": last_fetched_ids})
        return

    # Step 4: Apply max_fetch limit
    if len(events) > max_fetch:
        overflow = len(events) - max_fetch
        demisto.debug(
            f"[Fetch] Overflow: API returned {len(events)} events, max_fetch={max_fetch}. "
            f"{overflow} events deferred to the next fetch cycle."
        )
        events = events[:max_fetch]

    # Step 5: Enrich events with detail URL responses
    # Use _safe_enrich_events which handles rate limits gracefully
    # and returns partial results without re-raising
    enriched_events, rate_limit_on_detail = _safe_enrich_events(client, events)

    # Step 6: Send events to XSIAM
    if enriched_events:
        add_time_to_events(enriched_events)
        send_events_to_xsiam(events=enriched_events, vendor=Config.VENDOR, product=Config.PRODUCT)
        demisto.debug(f"[Fetch] Pushed {len(enriched_events)} events to XSIAM.")

        # Step 7: Update last run based on what was actually sent
        new_last_run = calculate_last_run(enriched_events, last_run)
        if new_last_run:
            demisto.setLastRun(new_last_run)
            demisto.debug(f"[Fetch] Last run updated: {new_last_run.get('last_fetch')}")
    else:
        demisto.debug("[Fetch] No enriched events to send.")

    if rate_limit_on_detail:
        demisto.debug("[Fetch] Rate limit was hit during enrichment. " "Remaining events will be fetched in the next cycle.")


def _safe_enrich_events(
    client: Client,
    events: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], bool]:
    """Enrich events with detail URLs, stopping gracefully on rate limit.

    Args:
        client: The SecurityScorecard API client.
        events: List of events to enrich.

    Returns:
        Tuple of (list of enriched events, whether rate limit was hit).
        The list may be partial if rate limited.
    """
    enriched_events: list[dict[str, Any]] = []
    rate_limited = False

    for event in events:
        detail_url = event.get("detail_url")
        if not detail_url:
            enriched_events.append(event)
            continue

        try:
            detail_response = client.get_detail_url_response(detail_url)
            event["detail_url_response"] = detail_response
            enriched_events.append(event)
        except RateLimitError:
            demisto.debug(
                f"[SafeEnrich] Rate limit hit at event {event.get('id')}. " f"Returning {len(enriched_events)} enriched events."
            )
            rate_limited = True
            break

    return enriched_events, rate_limited


# endregion


# region Main
# =================================
# Main
# =================================


def main() -> None:
    """Main entry point for SecurityScorecard Event Collector integration."""
    demisto.debug(f"{INTEGRATION_NAME} integration started.")
    command = demisto.command()
    params = demisto.params()

    try:
        base_url = params.get("url", "https://api.securityscorecard.io").rstrip("/")
        api_token = params.get("api_token", {}).get("password", "")
        scorecard_identifier = params.get("scorecard_identifier", "").strip()
        verify = not argToBoolean(params.get("insecure", False))
        proxy = argToBoolean(params.get("proxy", False))

        if not api_token:
            raise DemistoException("API Token is required.")
        if not scorecard_identifier:
            raise DemistoException("Scorecard Identifier is required.")

        client = Client(
            base_url=base_url,
            api_token=api_token,
            scorecard_identifier=scorecard_identifier,
            verify=verify,
            proxy=proxy,
        )

        if command == "test-module":
            result = test_module(client)
            return_results(result)

        elif command == "fetch-events":
            fetch_events_command(client, params)

        elif command == "securityscorecard-get-events":
            command_result = get_events_command(client, demisto.args())
            return_results(command_result)

        else:
            raise DemistoException(f"Command '{command}' is not implemented.")

    except Exception as error:
        error_msg = f"Failed to execute {command}. Error: {str(error)}"
        demisto.error(f"{error_msg}\n{traceback.format_exc()}")
        return_error(error_msg)

    demisto.debug(f"{INTEGRATION_NAME} integration finished.")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
