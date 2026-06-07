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
    """Fetch audit trail events with full pagination handling.

    Args:
        client: The Securiti API client.
        from_time: Epoch timestamp in milliseconds to start fetching from.
        last_run_ids: IDs of events from the last fetch at the boundary timestamp.
        start_offset: Starting offset (non-zero only when resuming from special case).
        max_events: Maximum total events to fetch.

    Returns:
        Tuple of (events list, next_run state dict).
    """
    all_events: list[dict] = []
    current_from_time = from_time
    current_offset = start_offset
    current_dedup_ids = last_run_ids
    # Track whether we stopped due to the special case (all same timestamp at offset boundary)
    stopped_at_offset_boundary = False

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
        # This only applies on the first page after a time-based shift.
        events = dedup_events(events, current_dedup_ids)
        current_dedup_ids = []  # Only dedup once

        if not events:
            # All events were duplicates. Advance offset to skip past them.
            current_offset += page_limit
            if current_offset >= API_MAX_OFFSET:
                demisto.debug(
                    "All events on page were duplicates and offset is at max. Stopping."
                )
                break
            demisto.debug(
                f"All events on page were duplicates. Advancing offset to {current_offset}."
            )
            continue

        all_events.extend(events)
        demisto.debug(f"Total events collected so far: {len(all_events)}")

        # If we got fewer events than requested, there are no more pages (partial page)
        if len(events) < page_limit:
            demisto.debug("Received fewer events than requested (partial page), no more pages.")
            break

        # Calculate next offset
        next_offset = current_offset + page_limit

        if next_offset >= API_MAX_OFFSET:
            # Cannot use offset beyond 10,000 — need to switch pagination strategy.
            last_event = events[-1]
            last_event_time = last_event.get("event_time", current_from_time)

            if last_event_time == current_from_time:
                # SPECIAL CASE: All events on this full page share the same timestamp
                # as our from_time filter. We CANNOT advance time — there may be more
                # events at this timestamp beyond offset 10,000.
                # Save the offset so the next fetch resumes from this exact position.
                demisto.debug(
                    f"All {len(events)} events share timestamp {last_event_time} "
                    f"and page is full at offset boundary. "
                    f"Saving offset={next_offset} for next run."
                )
                current_offset = next_offset
                stopped_at_offset_boundary = True
                break
            else:
                # Normal case: events have different timestamps.
                # Advance from_time to the last event's timestamp and track boundary
                # IDs for dedup on the next page.
                boundary_ids = [
                    e["id"] for e in all_events
                    if e.get("event_time") == last_event_time and e.get("id")
                ]
                current_from_time = last_event_time
                current_offset = 0
                current_dedup_ids = boundary_ids
                demisto.debug(
                    f"Advancing from_time to {last_event_time} with "
                    f"{len(boundary_ids)} boundary IDs for dedup."
                )
        else:
            current_offset = next_offset
            demisto.debug(f"Advancing offset to {current_offset}")

    # Build next_run state
    if all_events:
        last_event = all_events[-1]
        last_event_time = last_event.get("event_time", current_from_time)

        if stopped_at_offset_boundary:
            # Special case: save offset for next run, no dedup needed
            next_run: dict[str, Any] = {
                "from_time": last_event_time,
                "offset": current_offset,
                "last_fetched_ids": [],
            }
        else:
            # Normal case: save boundary IDs for dedup, no offset needed
            boundary_ids = [
                e["id"] for e in all_events
                if e.get("event_time") == last_event_time and e.get("id")
            ]
            next_run = {
                "from_time": last_event_time,
                "offset": 0,
                "last_fetched_ids": boundary_ids,
            }
    else:
        next_run = {
            "from_time": current_from_time,
            "offset": current_offset,
            "last_fetched_ids": last_run_ids,
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


def get_events_command(client: Client, args: dict) -> tuple[list[dict], CommandResults]:
    """Manual command to get events from Securiti.

    Args:
        client: The Securiti API client.
        args: Command arguments.

    Returns:
        Tuple of (events list, CommandResults).
    """
    limit = arg_to_number(args.get("limit", 50)) or 50
    from_date = args.get("from_date")

    if from_date:
        from_time_dt = arg_to_datetime(from_date)
        from_time = int(from_time_dt.timestamp() * 1000) if from_time_dt else 0
    else:
        from_time = 0

    events, _ = get_events_for_type(
        client=client,
        from_time=from_time,
        last_run_ids=[],
        start_offset=0,
        max_events=limit,
    )

    hr = tableToMarkdown(
        name="Securiti Audit Trail Events",
        t=events,
        headers=["id", "event_time", "activity_type", "object_type", "user_email", "message", "ip_address"],
        removeNull=True,
    )
    return events, CommandResults(readable_output=hr)


def fetch_events(
    client: Client,
    last_run: dict[str, Any],
    max_events_per_fetch: int,
    fetch_audit_trails: bool,
) -> tuple[dict[str, Any], list[dict]]:
    """Fetch events from Securiti for XSIAM ingestion.

    Args:
        client: The Securiti API client.
        last_run: Last run state dictionary.
        max_events_per_fetch: Maximum events to fetch per run.
        fetch_audit_trails: Whether to fetch audit trail events.

    Returns:
        Tuple of (next_run dict, events list).
    """
    all_events: list[dict] = []
    next_run: dict[str, Any] = {}

    if fetch_audit_trails:
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

        all_events.extend(events)
        next_run["audit_trail"] = audit_next_run
        demisto.debug(f"Fetched {len(events)} audit trail events")

    return next_run, all_events


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

    fetch_audit_trails = params.get("fetch_audit_trails", True)
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
            should_push_events = argToBoolean(args.pop("should_push_events"))
            events, results = get_events_command(client, args)
            return_results(results)
            if should_push_events:
                add_time_to_events(events)
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            next_run, events = fetch_events(
                client=client,
                last_run=last_run,
                max_events_per_fetch=max_events_per_fetch,
                fetch_audit_trails=fetch_audit_trails,
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
