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


# TODO remove
def get_fetch_run_time_range_dev(
    last_run,
    first_fetch,
    look_back=0,
    timezone=0,
    date_format="%Y-%m-%dT%H:%M:%S",
    time_field_name="time",
):
    """
    Calculates the time range for fetch depending the look_back argument and the previous fetch start time
    given from the last_run object.

    :type last_run: ``dict``
    :param last_run: The LastRun object

    :type first_fetch: ``str``
    :param first_fetch: The first time to fetch, used in the first fetch of an instance

    :type look_back: ``int``
    :param look_back: The time to look back in fetch in minutes

    :type timezone: ``int``
    :param timezone: The time zone offset in hours

    :type date_format: ``str``
    :param date_format: The date format

    :type time_field_name: ``str``
    :param time_field_name: The name of the time field in the LastRun dictionary

    :return: The time range (start_time, end_time) of the creation date for the incidents to fetch in the current run.
    :rtype: ``Tuple``
    """
    last_run_time = last_run and time_field_name in last_run and last_run[time_field_name]
    now = get_current_time(timezone)
    if not last_run_time:
        last_run_time = dateparser.parse(first_fetch, settings={"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": True})
        if last_run_time:
            last_run_time += timedelta(hours=timezone)
    else:
        last_run_time = dateparser.parse(last_run_time, settings={"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": True})

    if look_back and look_back > 0:
        if now - last_run_time < timedelta(minutes=look_back):
            last_run_time = now - timedelta(minutes=look_back)

    demisto.debug(
        "lb: fetch start time: {}, fetch end time: {}".format(last_run_time.strftime(date_format), now.strftime(date_format))
    )
    return last_run_time.strftime(date_format), now.strftime(date_format)


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
    
    # Get fetch time range
    last_fetched_creation_date, _ = get_fetch_run_time_range_dev(
        last_run=last_run,
        first_fetch=CURRENT_TIME_STR,
        look_back=look_back,
        date_format=DATE_FORMAT,
        time_field_name="prev_date",
    )
    
    # Handle backward compatibility for deduplication
    if "last_fetched_id_timestamps" in last_run:
        # New format: use timestamped IDs
        cached_ids_for_dedup = list(last_run["last_fetched_id_timestamps"].keys())
        demisto.debug(f"Using new timestamped format with {len(cached_ids_for_dedup)} cached IDs")
    elif "last_fetched_ids" in last_run:
        # Legacy format: use old IDs as-is for this cycle
        cached_ids_for_dedup = last_run["last_fetched_ids"]
        demisto.debug(f"Using legacy format with {len(cached_ids_for_dedup)} cached IDs")
    else:
        # First run: no previous IDs
        cached_ids_for_dedup = []
        demisto.debug("First run: no previous IDs to cache")
    
    # Fetch events in batches with deduplication
    all_events, updated_dedup_cache = _fetch_events_batch(client, limit, last_fetched_creation_date, cached_ids_for_dedup)
    
    # Build next_run with filtered deduplication cache
    next_run = _build_next_run(all_events, updated_dedup_cache, last_fetched_creation_date, look_back)
    
    demisto.debug(f"Done fetching. Sum of all events: {len(all_events)}, the next run is {next_run}.")
    return next_run, all_events


""" HELPER FUNCTIONS """



def _fetch_events_batch(client: Client, limit: int, from_date: str, cached_ids: list) -> tuple[List[Dict], dict]:
    """
    Fetches events in batches with deduplication until limit is reached or no more events.
    
    Args:
        client: API client for fetching events
        limit: Maximum number of events to fetch total
        from_date: Start date for fetching events
        cached_ids: List of cached event IDs for deduplication
        
    Returns:
        Tuple of (deduplicated events list, updated dedup_cache dict with timestamps)
    """
    all_events = []
    remaining_events_to_fetch = limit
    dedup_cache = {}  # Build new timestamp cache from fetched events
    
    while remaining_events_to_fetch > 0:
        current_batch_to_fetch = min(remaining_events_to_fetch, MAX_EVENTS_PER_API_CALL)
        demisto.debug(f"trying to fetch {current_batch_to_fetch} events.")
        
        events = client.search_events(from_date=from_date, limit=current_batch_to_fetch)
        demisto.debug(f"Successfully fetched {len(events)} events in this cycle.")
        
        if not events:
            demisto.debug("No events fetched. Exiting the loop.")
            break
        
        events = dedup_events(events, cached_ids)
        if events:
            # Store ID-to-timestamp mappings from current cycle
            for event in events:
                dedup_cache[event["id"]] = event["created"]
            all_events.extend(events)
            
            last_fetched_event = events[-1]
            demisto.debug(
                f"information of the last event in this cycle: id: {last_fetched_event['id']}, created: {last_fetched_event['created']}."
            )
            remaining_events_to_fetch -= len(events)
            demisto.debug(f"{remaining_events_to_fetch} events are left to fetch in the next calls.")
        else:
            # Avoid infinite loop if all events are duplicates
            demisto.debug("No new events after deduplication. Exiting the loop.")
            break
    
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
        most_recent_timestamp = fallback_date  # Keep original start time if no events
        demisto.debug(f"No events fetched, using fallback date: {most_recent_timestamp}")
    
    # Filter ID timestamps to maintain only those within the lookback window
    filtered_id_timestamps = _filter_dedup_cache(
        dedup_cache, most_recent_timestamp, look_back, bool(all_events)
    )
    
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
            event_id: timestamp
            for event_id, timestamp in id_timestamps.items()
            if timestamp == most_recent_timestamp
        }
        demisto.debug(f"No lookback configured, keeping {len(filtered_same_timestamp)} IDs from most recent timestamp")
        return filtered_same_timestamp
    
    demisto.debug("No events or no lookback, returning all cached IDs")
    return id_timestamps


def dedup_events(events: List[Dict], last_fetched_ids: list) -> List[Dict]:
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

    demisto.debug(f"Starting deduping. Number of events before deduping: {len(events)}, last fetched ids: {last_fetched_ids}")

    last_fetched_ids_set = set(last_fetched_ids)
    deduped_events = [event for event in events if event["id"] not in last_fetched_ids_set]

    demisto.debug(f"Done deduping. Number of events after deduping: {len(deduped_events)}")
    for number, event in enumerate(
        deduped_events, start=1
    ):  # TODO For debugging custom version, remove before marketplace release!
        demisto.debug(f"New event {number} of {len(deduped_events)}: {event}")
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
    lookback_cutoff = current_datetime - timedelta(minutes=look_back)  # type: ignore
    
    demisto.debug(f"Lookback window: {lookback_cutoff.strftime(DATE_FORMAT)} to {current_datetime.strftime(DATE_FORMAT)}")

    filtered_id_timestamps = {}
    removed_count = 0
    for event_id, timestamp in id_timestamps.items():
        event_datetime = arg_to_datetime(timestamp, required=True)
        if event_datetime >= lookback_cutoff:  # type: ignore
            filtered_id_timestamps[event_id] = timestamp
        else:
            removed_count += 1
    
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
    # TODO add here a validation for look_back to be greater than the fetch interval

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
