import demistomock as demisto
from CommonServerPython import *
from ContentClientApiModule import ContentClient  # noqa: E402
import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

VENDOR = "securiti"
PRODUCT = "securiti"

API_MAX_LIMIT = 5000
API_MAX_OFFSET = 10000
DEFAULT_MAX_EVENTS_PER_FETCH = 50000
FIRST_FETCH_DELAY_SECONDS = 60
AUDIT_TRAIL_QUERY_NAME = "get_audit_trail"
STORED_QUERIES_URL_SUFFIX = "/reporting/v1/stored_queries/execute"

""" CLIENT CLASS """


class Client(ContentClient):
    """Client class to interact with the Securiti API.

    This Client implements API calls and does not contain any Demisto logic.
    It inherits from ContentClient defined in ContentClientApiModule.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        api_secret: str,
        tenant_id: str,
        verify: bool = True,
        proxy: bool = False,
    ):
        headers = {
            "X-API-KEY": api_key,
            "X-API-SECRET": api_secret,
            "X-TIDENT": tenant_id,
            "Content-Type": "application/json",
        }
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def get_audit_trail_events(
        self,
        from_time: int,
        offset: int = 0,
        limit: int = API_MAX_LIMIT,
    ) -> list[dict]:
        """Fetch audit trail events from the Securiti API.

        Args:
            from_time: Epoch timestamp in milliseconds to filter events from.
            offset: Pagination offset.
            limit: Number of events to return per page (max 5000).

        Returns:
            List of event dictionaries.
        """
        body: dict[str, Any] = {
            "name": AUDIT_TRAIL_QUERY_NAME,
            "skip_cache": True,
            "response_config": {
                "format": 1,
            },
            "order_by": ["event_time", "id"],
            "pagination": {
                "type": "limit-offset",
                "offset": offset,
                "limit": limit,
            },
            "filter": {
                "op": "gte",
                "field": "event_time",
                "value": from_time,
            },
        }

        demisto.debug(f"Fetching audit trail events with offset={offset}, limit={limit}, from_time={from_time}")
        response = self._http_request(
            method="POST",
            url_suffix=STORED_QUERIES_URL_SUFFIX,
            json_data=body,
        )

        events: list[dict] = response.get("data", [])
        demisto.debug(f"Received {len(events)} audit trail events")
        return events


""" HELPER FUNCTIONS """


def get_first_fetch_time() -> int:
    """Return the first fetch time as epoch milliseconds (1 minute ago).

    Per the design document, audit trails may take up to 30 seconds to appear,
    so we start fetching from 1 minute ago to ensure we don't miss events.

    Returns:
        Epoch timestamp in milliseconds for 1 minute ago.
    """
    return int((datetime.utcnow() - timedelta(seconds=FIRST_FETCH_DELAY_SECONDS)).timestamp() * 1000)


def add_time_to_events(events: list[dict] | None) -> None:
    """Add the _time key to events for XSIAM ingestion.

    The _time field is derived from the event_time field (epoch ms).

    Args:
        events: List of event dictionaries.
    """
    if events:
        for event in events:
            event_time = event.get("event_time")
            if event_time:
                # event_time is epoch in milliseconds
                event["_time"] = timestamp_to_datestring(event_time)


def dedup_events(events: list[dict], last_run_ids: list[str]) -> list[dict]:
    """Remove duplicate events that were already fetched in the previous run.

    When we resume fetching from the same event_time, we may re-fetch events
    that were already ingested. This function filters them out using the stored IDs.

    Args:
        events: List of event dictionaries.
        last_run_ids: List of event IDs from the previous run's last timestamp.

    Returns:
        Deduplicated list of events.
    """
    if not last_run_ids:
        return events

    last_run_ids_set = set(last_run_ids)
    deduped = [e for e in events if e.get("id") not in last_run_ids_set]
    removed_count = len(events) - len(deduped)
    if removed_count > 0:
        demisto.debug(f"Removed {removed_count} duplicate events")
    return deduped


def get_events_for_type(
    client: Client,
    from_time: int,
    last_run_ids: list[str],
    start_offset: int,
    max_events: int,
) -> tuple[list[dict], dict]:
    """Fetch audit trail events with dedup-first pagination handling.

    The pagination strategy is:
    1. Always call the API with from_time and limit (offset=0 by default).
    2. Dedup the returned events against last_run_ids (events from the previous
       run that shared the same from_time).
    3. If ALL events on a page are deduped (the entire page consists of events
       we already fetched), use offset on the next call to skip past them.
    4. Otherwise, advance from_time to the last event's timestamp and track
       boundary IDs for dedup on the next page/run.

    Args:
        client: The Securiti API client.
        from_time: Epoch timestamp in milliseconds to start fetching from.
        last_run_ids: IDs of events from the last fetch at the boundary timestamp.
        start_offset: Starting offset (non-zero only when resuming after a full-page dedup).
        max_events: Maximum total events to fetch.

    Returns:
        Tuple of (events list, next_run state dict).
    """
    all_events: list[dict] = []
    current_from_time = from_time
    current_offset = start_offset
    current_dedup_ids = last_run_ids

    while len(all_events) < max_events:
        remaining = max_events - len(all_events)
        page_limit = min(remaining, API_MAX_LIMIT)

        events = client.get_audit_trail_events(
            from_time=current_from_time,
            offset=current_offset,
            limit=page_limit,
        )

        if not events:
            demisto.debug("No more events returned from API, stopping pagination.")
            break

        # Deduplicate against previously fetched IDs at the boundary.
        events_before_dedup = events
        events = dedup_events(events, current_dedup_ids)

        if not events:
            # All events on this page were duplicates.
            # Use offset on the next call to skip past these deduped events.
            current_offset += page_limit
            demisto.debug(
                f"All events on page were duplicates. Advancing offset to {current_offset} " f"to skip past deduped events."
            )
            # Keep current_dedup_ids — we still need to dedup against the same set
            continue

        # We got new (non-duplicate) events — reset offset to 0 for subsequent pages
        # since we'll be advancing from_time instead.
        current_offset = 0
        current_dedup_ids = []  # Dedup IDs consumed

        all_events.extend(events)
        demisto.debug(f"Total events collected so far: {len(all_events)}")

        # If we got fewer events than requested (before dedup), there are no more pages
        if len(events_before_dedup) < page_limit:
            demisto.debug("Received fewer events than requested (partial page), no more pages.")
            break

        # Advance from_time to the last event's timestamp for the next page.
        last_event = events[-1]
        last_event_time = last_event.get("event_time", current_from_time)

        # Collect boundary IDs: all events in this page that share the last event's timestamp.
        # These will be used for dedup on the next API call.
        boundary_ids = [e["id"] for e in events if e.get("event_time") == last_event_time and e.get("id")]
        current_from_time = last_event_time
        current_dedup_ids = boundary_ids
        demisto.debug(
            f"Advancing from_time to {last_event_time} with " f"{len(boundary_ids)} boundary IDs for dedup on next page."
        )

    # Build next_run state
    if all_events:
        last_event = all_events[-1]
        last_event_time = last_event.get("event_time", current_from_time)

        # Collect all IDs at the boundary timestamp for dedup on the next run
        boundary_ids = [e["id"] for e in all_events if e.get("event_time") == last_event_time and e.get("id")]
        next_run: dict[str, Any] = {
            "from_time": last_event_time,
            "offset": 0,
            "last_fetched_ids": boundary_ids,
        }
    else:
        # No events fetched. Preserve state for next run.
        # If we advanced offset due to full-page dedup, save it so we resume from there.
        next_run = {
            "from_time": current_from_time,
            "offset": current_offset,
            "last_fetched_ids": last_run_ids if current_offset == start_offset else [],
        }

    return all_events, next_run


""" COMMAND FUNCTIONS """


def test_module(client: Client, params: dict[str, Any]) -> str:
    """Test API connectivity and authentication.

    Args:
        client: The Securiti API client.
        params: Integration parameters.

    Returns:
        'ok' if test passed, error message otherwise.
    """
    try:
        # Try fetching a single event to verify connectivity
        client.get_audit_trail_events(
            from_time=0,
            offset=0,
            limit=1,
        )
    except Exception as e:
        error_message = str(e)
        if "Forbidden" in error_message or "401" in error_message or "403" in error_message:
            return "Authorization Error: make sure API Key, API Secret, and Tenant Identifier are correctly set."
        raise e

    return "ok"


def get_events_command(client: Client, args: dict) -> CommandResults | str:
    """Manual command to get events from Securiti.

    Performs a full fetch cycle with pagination, exactly like fetch-events,
    but without state management (last_run). Intended for manual debugging/testing.

    Args:
        client: The Securiti API client.
        args: Command arguments.

    Returns:
        CommandResults with events data, or a string message if events were pushed.
    """
    limit = arg_to_number(args.get("limit", 50)) or 50
    from_date = args.get("from_date")
    should_push_events = argToBoolean(args.get("should_push_events", False))

    if from_date:
        from_time_dt = arg_to_datetime(from_date)
        from_time = int(from_time_dt.timestamp() * 1000) if from_time_dt else 0
    else:
        from_time = 0

    demisto.debug(f"[get_events_command] from_time={from_time}, limit={limit}, should_push_events={should_push_events}")

    events, _ = get_events_for_type(
        client=client,
        from_time=from_time,
        last_run_ids=[],
        start_offset=0,
        max_events=limit,
    )

    demisto.debug(f"[get_events_command] Fetched {len(events)} events")

    if should_push_events and events:
        add_time_to_events(events)
        send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
        demisto.debug(f"[get_events_command] Pushed {len(events)} events to XSIAM")
        return f"Successfully retrieved and pushed {len(events)} events to XSIAM."

    hr = tableToMarkdown(
        name="Securiti Audit Trail Events",
        t=events,
        headers=["id", "event_time", "activity_type", "object_type", "user_email", "message", "ip_address"],
        removeNull=True,
    )
    return CommandResults(readable_output=hr)


def fetch_events(
    client: Client,
    last_run: dict[str, Any],
    max_events_per_fetch: int,
) -> tuple[dict[str, Any], list[dict]]:
    """Fetch events from Securiti for XSIAM ingestion.

    Args:
        client: The Securiti API client.
        last_run: Last run state dictionary.
        max_events_per_fetch: Maximum events to fetch per run.

    Returns:
        Tuple of (next_run dict, events list).
    """
    next_run: dict[str, Any] = {}

    audit_state = last_run.get("audit_trail", {})
    from_time = audit_state.get("from_time", get_first_fetch_time())
    last_fetched_ids = audit_state.get("last_fetched_ids", [])
    stored_offset = audit_state.get("offset", 0)

    demisto.debug(
        f"Fetching audit trail events from_time={from_time}, "
        f"offset={stored_offset}, last_fetched_ids count={len(last_fetched_ids)}"
    )

    events, audit_next_run = get_events_for_type(
        client=client,
        from_time=from_time,
        last_run_ids=last_fetched_ids,
        start_offset=stored_offset,
        max_events=max_events_per_fetch,
    )

    next_run["audit_trail"] = audit_next_run
    demisto.debug(f"Fetched {len(events)} audit trail events")

    return next_run, events


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """Main function, parses params and runs command functions."""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get("url", "").rstrip("/")
    api_key = params.get("api_key", {}).get("password", "")
    api_secret = params.get("api_secret", {}).get("password", "")
    tenant_id = params.get("tenant_id", "")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    max_events_per_fetch = arg_to_number(params.get("max_events_per_fetch")) or DEFAULT_MAX_EVENTS_PER_FETCH

    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(
            base_url=base_url,
            api_key=api_key,
            api_secret=api_secret,
            tenant_id=tenant_id,
            verify=verify_certificate,
            proxy=proxy,
        )

        if command == "test-module":
            result = test_module(client, params)
            return_results(result)

        elif command == "securiti-get-events":
            return_results(get_events_command(client, args))

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            next_run, events = fetch_events(
                client=client,
                last_run=last_run,
                max_events_per_fetch=max_events_per_fetch,
            )

            add_time_to_events(events)
            demisto.debug(f"Sending {len(events)} events to XSIAM.")
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.debug("Sent events to XSIAM successfully.")
            demisto.setLastRun(next_run)
            demisto.debug(f"Setting next run to {next_run}.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
