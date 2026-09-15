from datetime import datetime, timedelta, UTC

import demistomock as demisto
import urllib3
from CommonServerPython import *
from dateutil import parser

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
VENDOR = "sailpoint"
PRODUCT = "identitynow"
CURRENT_TIME_STR = datetime.now(tz=UTC).strftime(DATE_FORMAT)
MAX_EVENTS_PER_API_CALL = 10000  # API limitation

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API"""

    def __init__(self, client_id: str, client_secret: str, base_url: str, proxy: bool, verify: bool, token: str | None = None):
        super().__init__(base_url=base_url, proxy=proxy, verify=verify)
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = token

        try:
            self.token = self.get_token()
            self.headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {self.token}",
            }
        except Exception as e:
            raise Exception(f"Failed to get token. Error: {e!s}")

    def generate_token(self) -> str:
        """
        Generates an OAuth 2.0 token using client credentials.
        Returns:
            str: token
        """
        resp = self._http_request(
            method="POST",
            url_suffix="oauth/token",
            data={
                "grant_type": "client_credentials",
            },
            auth=(self.client_id, self.client_secret),
        )

        token = resp.get("access_token")
        now_timestamp = arg_to_datetime("now").timestamp()  # type:ignore
        expiration_time = now_timestamp + resp.get("expires_in")
        demisto.debug(f"Generated token that expires at: {expiration_time}.")
        integration_context = get_integration_context()
        integration_context.update({"token": token})
        # Subtract 60 seconds from the expiration time to make sure the token is still valid
        integration_context.update({"expires": expiration_time - 60})
        set_integration_context(integration_context)

        return token

    def get_token(self) -> str:
        """
        Obtains token from integration context if available and still valid.
        After expiration, new token are generated and stored in the integration context.
        Returns:
            str: token that will be added to authorization header.
        """
        integration_context = get_integration_context()
        token = integration_context.get("token", "")
        valid_until = integration_context.get("expires")

        now_timestamp = arg_to_datetime("now").timestamp()  # type:ignore
        # if there is a key and valid_until, and the current time is smaller than the valid until
        # return the current token
        if token and valid_until and now_timestamp < valid_until:
            demisto.debug(f"Using existing token that expires at: {valid_until}.")
            return token

        # else generate a token and update the integration context accordingly
        token = self.generate_token()
        demisto.debug("Generated a new token.")

        return token

    def search_events(self, from_date: str, limit: int, prev_id: str | None = None) -> List[Dict]:
        """
        Searches for events in SailPoint IdentityNow
        Args:
            from_date: The date from which to fetch events
            limit: Maximum number of events to fetch
            prev_id: The id of the last event fetched
        Returns:
            List of events
        """
        query: Dict = {
            "indices": ["events"],
            "queryType": "SAILPOINT",
            "queryVersion": "5.2",
            "sort": ["+created"] if not prev_id else ["+id"],
        }
        if prev_id:
            query["query"] = {"query": "type:* "}
            query["searchAfter"] = [prev_id]
        else:
            query["query"] = {"query": f"type:* AND created: [{from_date} TO now]"}
            query["timeZone"] = "GMT"

        url_suffix = f"/v3/search?limit={limit}"
        demisto.debug(f"Searching for events with query: {query}.")
        return self._http_request(method="POST", headers=self.headers, url_suffix=url_suffix, data=json.dumps(query))


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication
    Args:
        client: Client object with the API client
    Returns:
        'ok' if test passed, anything else will fail the test
    """

    try:
        fetch_events(
            client=client,
            limit=1,
            look_back=0,
            last_run={},
        )

    except Exception as e:
        if "Forbidden" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        else:
            raise e

    return "ok"


def get_events(client: Client, from_date: str, from_id: str | None, limit: int = 50) -> tuple[List[Dict], CommandResults]:
    """
    Gets events from the SailPoint IdentityNow API
    Args:
        client: Client object with the API client
        limit: Maximum number of events to fetch
        from_date: The date from which to get events
        from_id: The ID of an event from which to start to get events from
    Returns:
        List of events and CommandResults object
    """
    events = client.search_events(prev_id=from_id, from_date=from_date, limit=limit)
    demisto.debug(f"Got {len(events)} events.")
    hr = tableToMarkdown(name="Test Events", t=events)
    return events, CommandResults(readable_output=hr)


def fetch_events(client: Client, limit: int, look_back: int, last_run: dict) -> tuple[Dict, List[Dict]]:
    """
    Fetches events from the SailPoint IdentityNow API
    Args:
        client: Client object with the API client
        look_back: Look back timedelta in minutes
        limit: Maximum number of events to fetch per call
        last_run: Dict containing the last run data
    Returns:
        Tuple with the next run data and the list of events fetched
    """
    # Currently the API fails fetching events by id, so we are fetching by date only.
    # Once the issue is resolved, we can switch to ID-based fetching and remove
    # all deduplication logic (dedup_events, _migrate_legacy_ids, etc.).
    demisto.debug(f"Starting fetch up to {limit} events with last_run: {last_run} and look_back: {look_back}.")

    # Calculate fetch start time with lookback
    if "prev_date" in last_run:
        # Use prev_date from last run and apply lookback
        prev_date = dateparser.parse(last_run["prev_date"], settings={"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": True})
        fetch_start = prev_date - timedelta(minutes=look_back)  # type: ignore[operator]
        last_fetched_creation_date = fetch_start.strftime(DATE_FORMAT)  # type: ignore[union-attr]
        demisto.debug(
            f"Using prev_date '{last_run['prev_date']}' with {look_back} min lookback → "
            f"fetch from '{last_fetched_creation_date}'"
        )
    else:
        # First run - use current time
        last_fetched_creation_date = CURRENT_TIME_STR
        demisto.debug(f"First run: fetching from current time '{last_fetched_creation_date}'")

    # Handle backward compatibility for deduplication
    if "last_fetched_id_timestamps" in last_run:
        # New format: pass full timestamp dict to maintain lookback window
        previous_id_timestamps = last_run["last_fetched_id_timestamps"]
        cached_ids_for_dedup = list(previous_id_timestamps.keys())
        demisto.debug(f"Using new timestamped format with {len(cached_ids_for_dedup)} cached IDs")

    elif "last_fetched_ids" in last_run:
        # Legacy format: use old IDs as-is for this cycle, no timestamps available
        previous_id_timestamps = {}
        cached_ids_for_dedup = last_run["last_fetched_ids"]
        demisto.debug(f"Using legacy format with {len(cached_ids_for_dedup)} cached IDs")
    else:
        # First run: no previous IDs
        previous_id_timestamps = {}
        cached_ids_for_dedup = []
        demisto.debug("First run: no previous IDs to cache")

    # Fetch events in batches with deduplication
    all_events, updated_dedup_cache = _fetch_events_batch(
        client, limit, last_fetched_creation_date, previous_id_timestamps, last_run.get("prev_date")
    )

    # Build next_run with filtered deduplication cache
    next_run = _build_next_run(all_events, updated_dedup_cache, last_fetched_creation_date, look_back)

    demisto.debug(f"Done fetching. Sum of all events: {len(all_events)}, the next run is {next_run}.")
    return next_run, all_events


""" HELPER FUNCTIONS """


def _fetch_events_batch(
    client: Client, limit: int, from_date: str, previous_id_timestamps: dict = None, prev_date: str = None
) -> tuple[List[Dict], dict]:
    """
    Fetches events in batches with deduplication until limit is reached or no more events.

    Args:
        client: API client for fetching events
        limit: Maximum number of events to fetch total
        from_date: Start date for fetching events
        previous_id_timestamps: Dict of previous event IDs to timestamps (for merging)
        prev_date: Previous progression date for lookback analysis

    Returns:
        Tuple of (deduplicated events list, updated dedup_cache dict with timestamps)
    """
    all_events = []
    remaining_events_to_fetch = limit

    # Start with previous timestamps and add current run's events to it
    dedup_cache = previous_id_timestamps.copy() if previous_id_timestamps else {}
    demisto.debug(f"Starting with {len(dedup_cache)} cached IDs from previous run")

    current_from_date = from_date
    loop_count = 0

    while remaining_events_to_fetch > 0:
        loop_count += 1
        current_batch_to_fetch = min(remaining_events_to_fetch, MAX_EVENTS_PER_API_CALL)

        demisto.debug(f"Loop {loop_count}: API call with from_date: {current_from_date}, remaining: {remaining_events_to_fetch}")
        events = client.search_events(from_date=current_from_date, limit=current_batch_to_fetch)

        if not events:
            demisto.debug("No events fetched. Exiting the loop.")
            break

        # If we got fewer events than requested, API has no more events
        if len(events) < current_batch_to_fetch:
            demisto.debug(
                f"Got {len(events)} events, requested {current_batch_to_fetch}. "
                f"API has no more events. Will process these and exit."
            )
            should_break_after_processing = True
        else:
            should_break_after_processing = False

        events_before_dedup = len(events)
        events = dedup_events(events, list(dedup_cache.keys()), prev_date)
        demisto.debug(f"After dedup: {events_before_dedup} -> {len(events)} events.")

        if events:
            # Add the batch of events to the total
            all_events.extend(events)

            # Update dedup cache with these events
            dedup_cache.update({event["id"]: event["created"] for event in events})

            # Update the from_date to the last fetched event's creation date for next iteration
            last_fetched_event = events[-1]
            current_from_date = last_fetched_event["created"]
            demisto.debug(f"Updated from_date to: {current_from_date}")

            # Only decrease remaining by NEW events after dedup
            remaining_events_to_fetch -= len(events)
            demisto.debug(f"Fetched {len(events)} new events, {remaining_events_to_fetch} remaining")
        else:
            # All events are duplicates - exit loop
            demisto.debug(f"Loop {loop_count}: All {events_before_dedup} events were duplicates. " f"Exiting loop.")
            break

        # Break if API returned fewer events than requested (no more events available)
        if should_break_after_processing:
            demisto.debug("API returned fewer events than requested. No more events available.")
            break

    demisto.debug(f"_fetch_events_batch completed after {loop_count} loops, returning {len(all_events)} events")

    return all_events, dedup_cache


def _build_next_run(all_events: List[Dict], dedup_cache: dict, fallback_date: str, look_back: int) -> dict:
    """
    Builds the next_run dict with the most recent timestamp and filtered deduplication cache.

    Args:
        all_events: Events fetched in this cycle
        dedup_cache: Current deduplication cache with timestamps
        fallback_date: Date to use if no events were fetched
        look_back: Lookback window in minutes

    Returns:
        Dict with prev_date and filtered last_fetched_id_timestamps
    """
    # Determine the most recent timestamp for next_run
    if all_events:
        most_recent_timestamp = max(dedup_cache.values())
        demisto.debug(f"Most recent timestamp from {len(all_events)} events: {most_recent_timestamp}")
    else:
        # No new events this cycle - use most recent from existing cache if available
        if dedup_cache:
            most_recent_timestamp = max(dedup_cache.values())
            demisto.debug(f"No new events, but using most recent from cache: {most_recent_timestamp}")
        else:
            most_recent_timestamp = fallback_date  # Truly first run with no events
            demisto.debug(f"No events and no cache, using fallback date: {most_recent_timestamp}")

    # Filter ID timestamps to maintain only those within the lookback window
    filtered_id_timestamps = _filter_dedup_cache(dedup_cache, most_recent_timestamp, look_back, bool(all_events))

    demisto.debug(f"Filtered dedup cache: {len(dedup_cache)} -> {len(filtered_id_timestamps)} IDs within lookback window")

    return {"prev_date": most_recent_timestamp, "last_fetched_id_timestamps": filtered_id_timestamps}


def _filter_dedup_cache(id_timestamps: dict, most_recent_timestamp: str, look_back: int, has_events: bool) -> dict:
    """
    Filters the deduplication cache based on lookback settings and current fetch results.

    Args:
        id_timestamps: Dict of event_id -> timestamp mappings
        most_recent_timestamp: The most recent timestamp from this fetch
        look_back: Look back time in minutes (0 means no lookback)
        has_events: Whether events were fetched in this cycle

    Returns:
        Filtered dict of IDs within the appropriate time window
    """
    if look_back > 0:
        demisto.debug(f"Applying lookback window of {look_back} minutes from timestamp {most_recent_timestamp}")
        return filter_id_timestamps_by_lookback_window(id_timestamps, most_recent_timestamp, look_back)

    # When no lookback, only keep IDs from the most recent timestamp
    if has_events and id_timestamps:
        filtered_same_timestamp = {
            event_id: timestamp for event_id, timestamp in id_timestamps.items() if timestamp == most_recent_timestamp
        }
        demisto.debug(f"No lookback configured, keeping {len(filtered_same_timestamp)} IDs from most recent timestamp")
        return filtered_same_timestamp

    demisto.debug("No events or no lookback, returning all cached IDs")
    return id_timestamps


def dedup_events(events: List[Dict], last_fetched_ids: list, prev_date: str = None) -> List[Dict]:
    """
    Dedupes the events fetched based on the last fetched ids and creation date.
    This process is based on the assumption that the events are sorted by creation date.

    Args:
        events: List of events.
        last_fetched_ids: List of the last fetched ids.
    Returns:
        List of deduped events.
    """
    if not last_fetched_ids:
        demisto.debug("No last fetched ids. Skipping deduping.")
        return events

    demisto.debug(f"Starting deduping. Events before: {len(events)}, cached ids: {len(last_fetched_ids)}")

    last_fetched_ids_set = set(last_fetched_ids)
    deduped_events = []
    filtered_ids = []
    kept_ids = []

    for event in events:
        if event["id"] not in last_fetched_ids_set:
            deduped_events.append(event)
            kept_ids.append(event["id"])
        else:
            filtered_ids.append(event["id"])

    if filtered_ids:
        demisto.debug(f"Filtered out {len(filtered_ids)} duplicate event IDs: {filtered_ids}")

    if kept_ids:
        demisto.debug(f"Kept {len(kept_ids)} new event IDs: {kept_ids}")

    return deduped_events


def filter_id_timestamps_by_lookback_window(id_timestamps: dict, current_date: str, look_back: int) -> dict:
    """
    Filters ID-timestamp mappings to only keep those within the lookback time window.
    This prevents the ID dict from growing indefinitely and maintains proper deduplication.

    Args:
        id_timestamps: Dict of event_id -> timestamp mappings from previous fetches
        current_date: Current fetch end date in string format
        look_back: Look back time in minutes

    Returns:
        Filtered dict of IDs within the lookback window
    """
    if not id_timestamps:
        return id_timestamps

    current_datetime = arg_to_datetime(current_date, required=True)
    # Add 1 minute buffer to lookback for better cache retention
    retention_minutes = look_back + 1 if look_back > 0 else look_back
    lookback_cutoff = current_datetime - timedelta(minutes=retention_minutes)  # type: ignore

    demisto.debug(f"Lookback window: from {current_datetime.strftime(DATE_FORMAT)} to {lookback_cutoff.strftime(DATE_FORMAT)}")  # type: ignore[union-attr]

    filtered_id_timestamps = {}
    removed_count = 0
    removed_ids = []
    for event_id, timestamp in id_timestamps.items():
        event_datetime = arg_to_datetime(timestamp, required=True)
        if event_datetime >= lookback_cutoff:  # type: ignore
            filtered_id_timestamps[event_id] = timestamp
        else:
            removed_count += 1
            removed_ids.append(event_id)

    if removed_ids:
        demisto.debug(f"Removing {removed_count} event IDs from cache: {removed_ids}")

    demisto.debug(f"Lookback filtering: kept {len(filtered_id_timestamps)} IDs, removed {removed_count} older IDs")
    return filtered_id_timestamps


def add_time_and_status_to_events(events: List[Dict]) -> None:
    """
    Adds _time and _ENTRY_STATUS fields to events
    Args:
        events: List of events
    Returns:
        None
    """
    for event in events:
        created = event["created"]
        created = parser.parse(created)

        modified = event.get("modified")
        if modified:
            modified = parser.parse(modified)

        is_modified = created and modified and modified > created
        event["_time"] = modified.strftime(DATE_FORMAT) if is_modified else created.strftime(DATE_FORMAT)
        event["_ENTRY_STATUS"] = "modified" if is_modified else "new"


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    client_id = params.get("credentials", {}).get("identifier")
    client_secret = params.get("credentials", {}).get("password")
    base_url = params["url"]
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    fetch_limit = arg_to_number(params.get("limit")) or 50000
    fetch_look_back = arg_to_number(params.get("look_back")) or 0

    demisto.debug(f"Command being called is {command}")
    try:
        client = Client(
            client_id=client_id, client_secret=client_secret, base_url=base_url, verify=verify_certificate, proxy=proxy
        )

        if command == "test-module":
            result = test_module(client)
            return_results(result)

        elif command == "identitynow-get-events":
            limit = arg_to_number(args.get("limit", 50)) or 50
            should_push_events = argToBoolean(args.get("should_push_events", False))
            time_to_start = arg_to_datetime(args.get("from_date"))
            formatted_time_to_start = time_to_start.strftime(DATE_FORMAT) if time_to_start else CURRENT_TIME_STR
            id_to_start = args.get("from_id")
            if not (id_to_start or time_to_start) or (id_to_start and time_to_start):
                raise DemistoException("Please provide either from_id or from_date.")
            events, results = get_events(client, from_date=formatted_time_to_start, from_id=id_to_start, limit=limit)
            return_results(results)
            if should_push_events:
                add_time_and_status_to_events(events)
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            next_run, events = fetch_events(
                client=client,
                limit=fetch_limit,
                look_back=fetch_look_back,
                last_run=last_run,
            )

            add_time_and_status_to_events(events)
            demisto.debug(f"Sending {len(events)} events to Xsiam.")
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)
            demisto.debug(f"Next run is set to: {next_run}.")
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e!s}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
