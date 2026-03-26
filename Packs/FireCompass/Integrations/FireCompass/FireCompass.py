import demistomock as demisto
from CommonServerPython import *
from ContentClientApiModule import *
import urllib3
from datetime import UTC

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

VENDOR = "FireCompass"
PRODUCT = "FireCompass"
DEFAULT_MAX_EVENTS = 1000
MAX_PAGE_SIZE = 100  # API maximum per page
API_DATE_FORMAT = "%Y-%m-%d"  # Date format supported by the FireCompass API (day precision, no time)


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
            dict: The API response containing risk data with keys:
                - results: List of risk events.
                - count: Total number of events matching the query.
                - total_pages: Total number of pages available.
                - page: Current page number.
                - page_size: Page size used.

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


def _parse_date_string(date_str: str | None, default_days_ago: int = 0) -> datetime:
    """Parse a date string into a datetime object.

    Args:
        date_str: Date string to parse (ISO format or natural language like '3 days ago').
                  If None, returns the current UTC time minus default_days_ago days.
                  Since the API only accepts day-level dates (YYYY-MM-DD), the time
                  component is discarded by _datetime_to_api_date() before sending.
        default_days_ago: Number of days to subtract from now if date_str is None (default: 0 = today).

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
    known_ids: list[str],
) -> list[dict[str, Any]]:
    """Remove duplicate events based on IDs already fetched.

    Used only for boundary deduplication when re-fetching the last page
    to detect new events on the same page.

    Args:
        events: List of events to deduplicate.
        known_ids: List of event IDs already fetched (to filter out).

    Returns:
        list: Deduplicated events preserving original order.
    """
    if not events:
        return []

    if not known_ids:
        return events

    seen_ids = set(known_ids)
    deduplicated: list[dict[str, Any]] = []

    demisto.debug(f"Deduplicating {len(events)} events against {len(known_ids)} known IDs")

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


def _advance_day(date_str: str) -> str:
    """Advance a YYYY-MM-DD date string by one day.

    Args:
        date_str: Date string in YYYY-MM-DD format.

    Returns:
        str: Next day in YYYY-MM-DD format.
    """
    dt = datetime.strptime(date_str, API_DATE_FORMAT)
    return (dt + timedelta(days=1)).strftime(API_DATE_FORMAT)


def _fetch_events_with_pagination(
    client: Client,
    from_date: str,
    to_date: str,
    start_page: int,
    limit: int,
    page_size: int = MAX_PAGE_SIZE,
) -> tuple[list[dict[str, Any]], int, int, int]:
    """Fetch events with pagination support, starting from a specific page.

    Uses a fixed page_size for all pages in the session to keep total_pages
    consistent across calls. Results are trimmed to the requested limit.

    Args:
        client: FireCompass client instance.
        from_date: Start date in YYYY-MM-DD format (should equal to_date for single-day queries).
        to_date: End date in YYYY-MM-DD format.
        start_page: Page number to start fetching from (1-based).
        limit: Maximum number of events to return.
        page_size: Number of events per page (default: MAX_PAGE_SIZE).
                   Must be consistent across all calls for the same date to keep
                   total_pages stable.

    Returns:
        tuple: (events, last_page_fetched, total_pages, count)
            - events: Fetched events trimmed to the requested limit.
            - last_page_fetched: The last page number that was fetched.
            - total_pages: Total pages reported by the API.
            - count: Total event count reported by the API.
    """
    events: list[dict[str, Any]] = []
    page = start_page
    last_page_fetched = start_page
    total_pages = 0
    count = 0

    demisto.debug(
        f"Fetching risks with pagination: from_date={from_date}, to_date={to_date}, "
        f"start_page={start_page}, limit={limit}, page_size={page_size}"
    )

    while len(events) < limit:
        demisto.debug(f"Fetching page {page}: total_so_far={len(events)}")

        response = client.get_risks(
            page=page,
            page_size=page_size,
            from_date=from_date,
            to_date=to_date,
        )

        # Extract metadata from API response
        total_pages = response.get("total_pages", 0)
        count = response.get("count", 0)
        demisto.debug(f"API metadata: total_pages={total_pages}, count={count}")

        batch = response.get("results", [])

        if not batch:
            demisto.debug("No events in response, stopping pagination")
            break

        if not isinstance(batch, list):
            demisto.debug(f"Unexpected response format: {type(batch)}, stopping pagination")
            break

        # Log the order of created_at timestamps to help verify API sort order
        # TODO: remove after testing with real API
        first_created = batch[0].get("created_at", "N/A")
        last_created = batch[-1].get("created_at", "N/A")
        demisto.debug(
            f"Page {page} event order: first created_at={first_created}, last created_at={last_created} "
            f"({'ascending' if first_created <= last_created else 'descending'})"
        )

        events.extend(batch)
        last_page_fetched = page
        demisto.debug(f"Fetched {len(batch)} events in page {page}, total now: {len(events)}")

        # Use total_pages from API as source of truth for pagination
        if page >= total_pages:
            demisto.debug(f"Reached last page ({page}/{total_pages}), stopping pagination")
            break

        page += 1

    events = events[:limit]
    demisto.debug(f"Pagination complete: returning {len(events)} events (limit={limit})")
    return events, last_page_fetched, total_pages, count


def _build_next_run(
    current_date: str,
    last_page_fetched: int,
    total_pages: int,
    count: int,
    last_batch: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the next_run state dictionary for persistence.

    Args:
        current_date: The date being fetched (YYYY-MM-DD).
        last_page_fetched: The last page number that was successfully fetched.
        total_pages: Total pages reported by the API.
        count: Total event count reported by the API.
        last_batch: The last batch of events fetched (for extracting IDs for boundary dedup).

    Returns:
        dict: State dictionary with current_date, next_page, total_pages, count,
              and last_page_fetched_ids.
    """
    # Extract IDs from the last batch for boundary deduplication
    last_page_ids = [str(e["id"]) for e in last_batch if e.get("id")]

    next_page = last_page_fetched + 1

    demisto.debug(
        f"Building next_run: current_date={current_date}, next_page={next_page}, "
        f"total_pages={total_pages}, count={count}, last_page_ids_count={len(last_page_ids)}"
    )

    return {
        "current_date": current_date,
        "next_page": next_page,
        "total_pages": total_pages,
        "count": count,
        "last_page_fetched_ids": last_page_ids,
    }


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

    page_size = min(limit, MAX_PAGE_SIZE)
    events, _, _, _ = _fetch_events_with_pagination(
        client,
        from_date,
        to_date,
        start_page=1,
        limit=limit,
        page_size=page_size,
    )

    demisto.debug(f"Retrieved {len(events)} total events")
    hr = tableToMarkdown(name="FireCompass Risk Events", t=events, removeNull=True)
    return events, CommandResults(readable_output=hr)


def _probe_for_new_events(
    client: Client,
    current_date: str,
    stored_count: int,
    stored_total_pages: int,
    last_page_fetched_ids: list[str],
    max_events: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Probe the API for new events on the current day.

    Re-fetches the last known page to get fresh count/total_pages metadata.
    If count is unchanged, returns the original state with no events.
    If count increased, deduplicates the re-fetched page and fetches any new pages.

    Args:
        client: FireCompass client instance.
        current_date: The day being fetched (YYYY-MM-DD).
        stored_count: Event count from the last fetch cycle.
        stored_total_pages: Total pages from the last fetch cycle.
        last_page_fetched_ids: IDs from the last fetched page (for boundary dedup).
        max_events: Maximum number of events to return.

    Returns:
        tuple: (next_run state dict, list of new events).
    """
    probe_page = max(stored_total_pages, 1)
    page_size = min(max_events, MAX_PAGE_SIZE)

    demisto.debug(
        f"Probing page {probe_page} for changes " f"(stored_count={stored_count}, stored_total_pages={stored_total_pages})"
    )

    response = client.get_risks(
        page=probe_page,
        page_size=page_size,
        from_date=current_date,
        to_date=current_date,
    )

    new_count = response.get("count", 0)
    new_total_pages = response.get("total_pages", 0)

    if new_count == stored_count:
        demisto.debug(f"No new events (count still {stored_count}), returning empty")
        return {
            "current_date": current_date,
            "next_page": stored_total_pages + 1,
            "total_pages": stored_total_pages,
            "count": stored_count,
            "last_page_fetched_ids": last_page_fetched_ids,
        }, []

    demisto.debug(
        f"New events detected: count {stored_count} → {new_count}, " f"total_pages {stored_total_pages} → {new_total_pages}"
    )

    probe_results = response.get("results", [])
    new_events = _deduplicate_events(probe_results, last_page_fetched_ids)

    if new_total_pages > stored_total_pages and new_total_pages > probe_page:
        # New pages appeared — fetch them after the deduped probe page
        additional_events, last_page, total_pages, count = _fetch_events_with_pagination(
            client,
            current_date,
            current_date,
            start_page=probe_page + 1,
            limit=max_events - len(new_events),
            page_size=page_size,
        )
        new_events += additional_events
        # Use the latest page's events for ID tracking
        id_source = additional_events if additional_events else new_events
        next_run = _build_next_run(current_date, last_page, total_pages, count, id_source)
    else:
        # Same or fewer total_pages — new events are on the last page only
        next_run = _build_next_run(current_date, probe_page, new_total_pages, new_count, probe_results)

    demisto.debug(f"Probe complete: {len(new_events)} new events")
    return next_run, new_events


def fetch_events_command(
    client: Client,
    last_run: dict[str, Any],
    max_events: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Fetch events from FireCompass API for ingestion using page-resumption.

    Uses a single-day-at-a-time strategy with page tracking to avoid redundant
    API calls and ensure complete deduplication.

    Algorithm:
        1. No last_run → first fetch: current_date = today, start at page 1.
        2. next_page <= total_pages → resume pagination from next_page.
        3. All pages consumed, current_date < today → advance to next day.
        4. All pages consumed, current_date == today → probe for new events.

    Args:
        client: FireCompass client instance.
        last_run: Dictionary containing the page-resumption state.
        max_events: Maximum number of events to fetch per cycle.

    Returns:
        tuple: (next_run dictionary for state persistence, list of events to ingest).
    """
    demisto.debug(f"Starting fetch_events_command: max_events={max_events}, last_run={last_run}")

    current_date = last_run.get("current_date")
    next_page = last_run.get("next_page", 1)
    stored_total_pages = last_run.get("total_pages", 0)
    stored_count = last_run.get("count", 0)
    last_page_fetched_ids = last_run.get("last_page_fetched_ids", [])
    page_size = min(max_events, MAX_PAGE_SIZE)

    today = _datetime_to_api_date(datetime.now(tz=UTC))

    if not current_date:
        # First fetch ever — start from today
        current_date = today
        start_page = 1
        demisto.debug(f"First fetch, starting from: {current_date}")

    elif next_page <= stored_total_pages:
        # More pages to fetch from the current date — resume (was not fetched due to low max_events limit)
        start_page = next_page
        demisto.debug(f"Resuming pagination: current_date={current_date}, start_page={start_page}")

    elif current_date < today:
        # All pages consumed for current_date, but before advancing to the next day,
        # probe the current day for late-arriving events (e.g., events added after
        # the last fetch ran but still dated on current_date).
        demisto.debug(f"All pages consumed for {current_date}, probing before advancing to next day")
        probe_next_run, probe_events = _probe_for_new_events(
            client,
            current_date,
            stored_count,
            stored_total_pages,
            last_page_fetched_ids,
            max_events,
        )
        if probe_events:
            # Late-arriving events found — return them before advancing
            demisto.debug(f"Found {len(probe_events)} late events on {current_date}, deferring day advance")
            return probe_next_run, probe_events

        # No new events on current_date — safe to advance
        current_date = _advance_day(current_date)
        start_page = 1
        demisto.debug(f"No late events, advancing to next day: {current_date}")

    else:
        # All pages consumed, still the same day — delegate to probe
        return _probe_for_new_events(
            client,
            current_date,
            stored_count,
            stored_total_pages,
            last_page_fetched_ids,
            max_events,
        )

    # Standard pagination flow (first fetch, resume, or day advance)
    events, last_page_fetched, total_pages, count = _fetch_events_with_pagination(
        client,
        current_date,
        current_date,
        start_page=start_page,
        limit=max_events,
        page_size=page_size,
    )

    if not events and not last_run:
        # First fetch with no events — save minimal state
        demisto.debug("First fetch returned no events")
        return _build_next_run(current_date, 0, 0, 0, []), []

    if not events:
        demisto.debug("No events returned, keeping previous state")
        return last_run, []

    next_run = _build_next_run(current_date, last_page_fetched, total_pages, count, events)
    demisto.debug(f"Fetch complete: {len(events)} events, next_run={next_run}")
    return next_run, events


def _send_events(events: list[dict[str, Any]]) -> None:
    """Add required fields and send events to the platform.

    Args:
        events: List of event dictionaries to enrich and send.
    """
    _add_fields_to_events(events)
    demisto.debug(f"Sending {len(events)} events.")
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
    demisto.debug("Sent events successfully.")


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
                _send_events(events)
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

            _send_events(events)
            demisto.setLastRun(next_run)
            demisto.debug(f"Setting next run to {next_run}.")

        else:
            raise NotImplementedError(f"Command '{command}' is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
