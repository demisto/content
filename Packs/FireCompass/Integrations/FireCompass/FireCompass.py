import demistomock as demisto
from CommonServerPython import *
from ContentClientApiModule import *
import urllib3
from datetime import UTC

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
VENDOR = "FireCompass"
PRODUCT = "FireCompass"
DEFAULT_MAX_EVENTS = 1000
MAX_PAGE_SIZE = 100  # API maximum per page
FIRST_FETCH = "1 hour"
API_DATE_FORMAT = "%Y-%m-%d"


""" CLIENT CLASS """


class Client(ContentClient):
    """Client class to interact with the FireCompass Risk API.

    Attributes:
        api_key: The API key for authentication via X-Api-Token header.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        verify: bool,
        proxy: bool,
    ):
        """Initialize the FireCompass Client.

        Args:
            base_url: The base URL of the FireCompass API (e.g., https://apis.firecompass.com).
            api_key: The API key for X-Api-Token authentication.
            verify: Whether to verify SSL certificates.
            proxy: Whether to use system proxy settings.
        """
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            headers={
                "accept": "application/json",
                "X-Api-Token": api_key,
            },
        )

    def get_risks(
        self,
        page: int,
        page_size: int,
        from_date: str,
        to_date: str,
    ) -> dict[str, Any]:
        """Fetch risk data from the FireCompass API.

        Args:
            page: Page number for pagination (1-based).
            page_size: Number of records per page (1-100).
            from_date: Start date filter in YYYY-MM-DD format.
            to_date: End date filter in YYYY-MM-DD format.

        Returns:
            dict: The API response containing risk data.

        Raises:
            DemistoException: If the API request fails.
        """
        params = {
            "page": page,
            "page_size": min(page_size, MAX_PAGE_SIZE),
            "from_date": from_date,
            "to_date": to_date,
        }

        demisto.debug(f"Fetching risks: page={page}, page_size={page_size}, from_date={from_date}, to_date={to_date}")

        return self._http_request(
            method="GET",
            url_suffix="/rest/v4/risk",
            params=params,
            resp_type="json",
        )


""" HELPER FUNCTIONS """


def _parse_date_string(date_str: str | None, default_days_ago: int = 3) -> datetime:
    """Parse a date string into a datetime object.

    Args:
        date_str: Date string to parse (ISO format or natural language like '3 days ago').
                  If None, returns current time minus default_days_ago.
        default_days_ago: Number of days to subtract from now if date_str is None.

    Returns:
        datetime: Parsed datetime object (timezone-aware, UTC).

    Raises:
        ValueError: If the date string cannot be parsed.
    """
    if date_str:
        dt = arg_to_datetime(date_str)
        if dt is None:
            raise ValueError(f"Failed to parse date string: {date_str}")
        return dt

    return datetime.now(tz=UTC) - timedelta(days=default_days_ago)


def _datetime_to_api_date(dt: datetime) -> str:
    """Convert a datetime object to the API date format (YYYY-MM-DD).

    Args:
        dt: The datetime object to convert.

    Returns:
        str: Date string in YYYY-MM-DD format.
    """
    return dt.strftime(API_DATE_FORMAT)


def _add_fields_to_events(events: list[dict[str, Any]]) -> None:
    """Add required fields to events for ingestion.

    Adds:
        - _time: Mapped from the 'created_at' field.
        - _ENTRY_STATUS: 'new' if updated_at == created_at, 'modified' if updated_at > created_at.

    Args:
        events: List of event dictionaries to enrich. Modified in place.
    """
    if not events:
        return

    for event in events:
        created_at = event.get("created_at")
        if created_at:
            event["_time"] = created_at

        # Determine _ENTRY_STATUS based on created_at vs updated_at
        updated_at = event.get("updated_at")
        if created_at and updated_at:
            if updated_at == created_at:
                event["_ENTRY_STATUS"] = "new"
            elif updated_at > created_at:
                event["_ENTRY_STATUS"] = "modified"


def _deduplicate_events(
    events: list[dict[str, Any]],
    last_run_ids: list[str],
) -> list[dict[str, Any]]:
    """Remove duplicate events based on event IDs from the previous fetch cycle.

    Args:
        events: List of events to deduplicate.
        last_run_ids: List of event IDs from the last run to filter out.

    Returns:
        list: Deduplicated events preserving original order.
    """
    if not events:
        return []

    if not last_run_ids:
        return events

    seen_ids = set(last_run_ids)
    deduplicated: list[dict[str, Any]] = []

    demisto.debug(f"Deduplicating {len(events)} events against {len(last_run_ids)} previous IDs")

    for event in events:
        event_id = event.get("id")
        if not event_id:
            # Events without IDs are always included
            deduplicated.append(event)
            continue

        if event_id not in seen_ids:
            deduplicated.append(event)
            seen_ids.add(event_id)
        else:
            demisto.debug(f"Duplicate event found with ID {event_id}, skipping.")

    demisto.debug(f"Deduplication complete: {len(deduplicated)} unique events from {len(events)} total")
    return deduplicated


def _fetch_events_with_pagination(
    client: Client,
    from_date: str,
    to_date: str,
    limit: int,
) -> list[dict[str, Any]]:
    """Fetch events with pagination support.

    Iterates through API pages collecting events until the limit is reached
    or no more events are available.

    Args:
        client: FireCompass client instance.
        from_date: Start date in YYYY-MM-DD format.
        to_date: End date in YYYY-MM-DD format.
        limit: Maximum number of events to fetch.

    Returns:
        list: All fetched events in API order, trimmed to the requested limit.
    """
    events: list[dict[str, Any]] = []
    page = 1

    demisto.debug(f"Fetching risks with pagination: from_date={from_date}, to_date={to_date}, limit={limit}")

    while len(events) < limit:
        remaining = limit - len(events)
        page_size = min(remaining, MAX_PAGE_SIZE)

        demisto.debug(f"Fetching page {page}: page_size={page_size}, total_so_far={len(events)}")

        response = client.get_risks(
            page=page,
            page_size=page_size,
            from_date=from_date,
            to_date=to_date,
        )

        batch = response if isinstance(response, list) else response.get("results", response.get("data", []))

        if not batch:
            demisto.debug("No more events available, stopping pagination")
            break

        if not isinstance(batch, list):
            demisto.debug(f"Unexpected response format: {type(batch)}, stopping pagination")
            break

        # Log the order of created_at timestamps to help verify API sort order
        #TODO remove after testing
        if batch:
            first_created = batch[0].get("created_at", "N/A")
            last_created = batch[-1].get("created_at", "N/A")
            demisto.debug(
                f"Page {page} event order: first created_at={first_created}, last created_at={last_created} "
                f"({'ascending' if first_created <= last_created else 'descending'})"
            )

        events.extend(batch)
        demisto.debug(f"Fetched {len(batch)} events in page {page}, total now: {len(events)}")

        # If we got fewer events than requested, there are no more pages
        if len(batch) < page_size:
            demisto.debug(f"Received {len(batch)} events (less than page_size {page_size}), no more pages")
            break

        page += 1

    demisto.debug(f"Total events fetched: {len(events)}")
    return events


def _update_last_run(
    events: list[dict[str, Any]],
    last_run: dict[str, Any],
) -> dict[str, Any]:
    """Calculate the next last_run state based on fetched events.

    Tracks the latest created_at timestamp and the IDs of events at that timestamp
    to enable proper deduplication across fetch cycles.

    Args:
        events: List of fetched events.
        last_run: Previous last_run state dictionary.

    Returns:
        dict: Updated last_run state with 'last_fetch_time' and 'last_fetch_ids'.

    Logic:
        - No new events: Keep old state.
        - New events: Update to the latest created_at and track IDs at that timestamp.
    """
    if not events:
        demisto.debug("No new events, keeping previous last_run state")
        return last_run

    # The last event has the latest created_at
    latest_created_at = events[-1].get("created_at", "")

    # Collect IDs of all events with the latest created_at timestamp
    latest_ids: list[str] = []
    for event in reversed(events):
        event_created_at = event.get("created_at", "")
        if event_created_at == latest_created_at:
            event_id = event.get("id")
            if event_id:
                latest_ids.append(event_id)
        else:
            break

    previous_time = last_run.get("last_fetch_time", "")
    previous_ids = last_run.get("last_fetch_ids", [])

    if latest_created_at == previous_time:
        # Same timestamp - combine IDs to avoid duplicates
        combined_ids = list(set(previous_ids + latest_ids))
        demisto.debug(
            f"Same timestamp {latest_created_at}, combined IDs: "
            f"{len(previous_ids)} old + {len(latest_ids)} new = {len(combined_ids)} total"
        )
        return {"last_fetch_time": latest_created_at, "last_fetch_ids": combined_ids}

    demisto.debug(f"Updated last_fetch_time from '{previous_time}' to '{latest_created_at}' with {len(latest_ids)} IDs")
    return {"last_fetch_time": latest_created_at, "last_fetch_ids": latest_ids}


""" COMMAND FUNCTIONS """


def test_module_command(client: Client) -> str:
    """Test API connectivity and authentication.

    Performs a minimal API call to verify the API key is valid and the server is reachable.

    Args:
        client: FireCompass client instance.

    Returns:
        str: 'ok' if test passed.

    Raises:
        DemistoException: If the test fails due to auth or connectivity issues.
    """
    try:
        today = _datetime_to_api_date(datetime.now(tz=UTC))
        client.get_risks(page=1, page_size=1, from_date=today, to_date=today)
    except Exception as e:
        error_str = str(e)
        if "401" in error_str or "Unauthorized" in error_str or "403" in error_str:
            return f"Authorization Error: make sure the API Key is correctly set.\n{error_str}"
        raise

    return "ok"


def get_events_command(client: Client, args: dict[str, Any]) -> tuple[list[dict[str, Any]], CommandResults]:
    """Get events from FireCompass API (manual command).

    Args:
        client: FireCompass client instance.
        args: Command arguments containing:
            - limit: Maximum number of events to return (default: 50).
            - from_date: Start date for event retrieval (default: 3 days ago).
            - to_date: End date for event retrieval (default: now).

    Returns:
        tuple: (List of events, CommandResults for display).
    """
    limit = arg_to_number(args.get("limit", 50)) or 50
    from_date_str = args.get("from_date")
    to_date_str = args.get("to_date")

    from_dt = _parse_date_string(from_date_str, default_days_ago=3)
    to_dt = _parse_date_string(to_date_str, default_days_ago=0)

    from_date = _datetime_to_api_date(from_dt)
    to_date = _datetime_to_api_date(to_dt)

    demisto.debug(f"Getting events: limit={limit}, from_date={from_date}, to_date={to_date}")

    events = _fetch_events_with_pagination(client, from_date, to_date, limit)

    demisto.debug(f"Retrieved {len(events)} total events")
    hr = tableToMarkdown(name="FireCompass Risk Events", t=events[:10], removeNull=True)
    return events, CommandResults(readable_output=hr)


def fetch_events_command(
    client: Client,
    last_run: dict[str, Any],
    max_events: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Fetch events from FireCompass API for ingestion.

    Handles deduplication, pagination, and state management across fetch cycles.

    Args:
        client: FireCompass client instance.
        last_run: Dictionary containing the last fetch state:
            - last_fetch_time: ISO timestamp of the latest fetched event's created_at.
            - last_fetch_ids: List of event IDs at the last_fetch_time for dedup.
        max_events: Maximum number of events to fetch per cycle.

    Returns:
        tuple: (next_run dictionary for state persistence, list of deduplicated events).
    """
    demisto.debug(f"Starting fetch_events_command: max_events={max_events}")

    last_fetch_time = last_run.get("last_fetch_time")
    last_fetch_ids = last_run.get("last_fetch_ids", [])

    # Determine the start date for fetching
    if last_fetch_time:
        # Parse the ISO timestamp from last run to get the date
        from_dt = arg_to_datetime(last_fetch_time)
        if from_dt is None:
            demisto.debug(f"Failed to parse last_fetch_time '{last_fetch_time}', falling back to FIRST_FETCH")
            from_dt = _parse_date_string(FIRST_FETCH)
        else:
            demisto.debug(f"Continuing fetch from last_fetch_time: {last_fetch_time}")
    else:
        # First fetch - hardcoded to FIRST_FETCH constant
        from_dt = _parse_date_string(FIRST_FETCH)
        demisto.debug(f"First fetch, starting from: {from_dt}")

    to_dt = datetime.now(tz=UTC)

    from_date = _datetime_to_api_date(from_dt)
    to_date = _datetime_to_api_date(to_dt)

    # Fetch events with pagination
    events = _fetch_events_with_pagination(client, from_date, to_date, max_events)
    demisto.debug(f"Fetched {len(events)} events before deduplication")

    # Deduplicate against previous fetch cycle
    events = _deduplicate_events(events, last_fetch_ids)
    demisto.debug(f"After deduplication: {len(events)} events")

    # Add fields for ingestion
    _add_fields_to_events(events)

    # Update last_run state
    next_run = _update_last_run(events, last_run)

    demisto.debug(f"Fetch complete: {len(events)} events, next_run={next_run}")
    return next_run, events


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """Main function that parses params and runs command functions."""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    # Parse connection parameters
    base_url = params.get("url", "https://apis.firecompass.com").rstrip("/")
    api_key = params.get("credentials", {}).get("password", "")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    # Parse fetch parameters
    max_events = arg_to_number(params.get("max_events", DEFAULT_MAX_EVENTS)) or DEFAULT_MAX_EVENTS

    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(
            base_url=base_url,
            api_key=api_key,
            verify=verify_certificate,
            proxy=proxy,
        )

        if command == "test-module":
            result = test_module_command(client)
            return_results(result)

        elif command == "firecompass-get-events":
            should_push_events = argToBoolean(args.pop("should_push_events", False))
            events, results = get_events_command(client, args)
            if should_push_events:
                _add_fields_to_events(events)
                demisto.debug(f"Sending {len(events)} events.")
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
                if results.readable_output:
                    results.readable_output += f"\n\n{len(events)} events sent."
            return_results(results)

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            demisto.debug(f"Last run state: {last_run}")
            next_run, events = fetch_events_command(
                client=client,
                last_run=last_run,
                max_events=max_events,
            )

            demisto.debug(f"Sending {len(events)} events.")
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.debug("Sent events successfully")
            demisto.setLastRun(next_run)
            demisto.debug(f"Setting next run to {next_run}.")

        else:
            raise NotImplementedError(f"Command '{command}' is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
