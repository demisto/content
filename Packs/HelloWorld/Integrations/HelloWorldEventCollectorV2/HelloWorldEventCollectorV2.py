from datetime import datetime, timezone

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
VENDOR = "hello"
PRODUCT = "world"
DEFAULT_MAX_EVENTS_PER_FETCH = 1000
DEFAULT_GET_EVENTS_LIMIT = 50
PAGE_SIZE = 100  # Maximum number of events to request from the API in a single page.

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def search_events(
        self,
        prev_id: int,
        alert_status: str | None,
        limit: int,
        from_date: str | None = None,
    ) -> List[Dict]:
        """
        Searches for HelloWorld alerts using the '/get_alerts' API endpoint.

        The API returns events in pages. This method iterates over the pages using the
        cursor returned by the API (``next_page``) until either ``limit`` events have been
        collected or there are no more pages to fetch.

        Args:
            prev_id (int): The last event id that was fetched. Only events with a greater id are returned.
            alert_status (str | None): Status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'.
            limit (int): Maximum number of events to return across all pages.
            from_date (str | None): Get events from this date onwards.

        Returns:
            List[Dict]: The list of events fetched from the API, ordered by id.
        """
        demisto.debug(f"Starting to fetch events. prev_id={prev_id}, limit={limit}, from_date={from_date}")
        events: List[Dict] = []
        next_page: str | None = None

        while len(events) < limit:
            params = assign_params(
                after_id=prev_id,
                status=alert_status,
                from_date=from_date,
                limit=min(limit - len(events), PAGE_SIZE),
                page=next_page,
            )
            demisto.debug(f"Requesting events page with params: {params}")
            response = self._http_request(
                method="GET",
                url_suffix="/get_alerts",
                params=params,
            )

            page_events = response.get("alerts", [])
            events.extend(page_events)
            demisto.debug(f"Fetched {len(page_events)} events in this page (total so far: {len(events)}).")

            next_page = response.get("next_page")
            if not next_page or not page_events:
                break

        # Trim to the requested limit in case the last page returned more than needed.
        return events[:limit]


def test_module(client: Client, params: dict[str, Any], first_fetch_time: str) -> str:
    """
    Tests API connectivity and authentication
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): HelloWorld client to use.
        params (Dict): Integration parameters.
        first_fetch_time(str): The first fetch time as configured in the integration params.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """

    try:
        alert_status = params.get("alert_status", None)

        fetch_events(
            client=client,
            last_run={},
            first_fetch_time=first_fetch_time,
            alert_status=alert_status,
            max_events_per_fetch=1,
        )

    except Exception as e:
        if "Forbidden" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        else:
            raise e

    return "ok"


def get_events(client: Client, alert_status: str, args: dict) -> tuple[List[Dict], CommandResults]:
    """Gets events from API

    Args:
        client (Client): The client.
        alert_status (str): Status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'.
        args (dict): Additional arguments (limit, from_date).

    Returns:
        tuple[List[Dict], CommandResults]:
            - The list of events fetched from the API.
            - The CommandResults object with the human readable output and outputs.
    """
    limit = arg_to_number(args.get("limit")) or DEFAULT_GET_EVENTS_LIMIT
    from_date = args.get("from_date")
    events = client.search_events(
        prev_id=0,
        alert_status=alert_status,
        limit=limit,
        from_date=from_date,
    )
    hr = tableToMarkdown(name="Test Event", t=events)
    return events, CommandResults(
        readable_output=hr,
        outputs_prefix="HelloWorld.Event",
        outputs_key_field="id",
        outputs=events,
    )


def deduplicate_events(events: List[Dict], last_fetched_ids: List[str]) -> List[Dict]:
    """
    Removes already-processed events based on the IDs fetched in the previous run.

    Args:
        events (List[Dict]): The events returned from the API in the current fetch.
        last_fetched_ids (List[str]): The event IDs that were already fetched in the previous run.

    Returns:
        List[Dict]: The events that were not fetched in the previous run.
    """
    if not last_fetched_ids:
        demisto.debug("[Dedup] No deduplication needed (first run - no previous IDs).")
        return events

    demisto.debug(f"[Dedup] Checking {len(events)} events against {len(last_fetched_ids)} previously fetched IDs.")

    # Convert to a set for O(1) lookups.
    fetched_ids_set = set(last_fetched_ids)
    new_events = [event for event in events if str(event.get("id")) not in fetched_ids_set]

    skipped_count = len(events) - len(new_events)
    if skipped_count:
        demisto.debug(f"[Dedup] Skipped {skipped_count} duplicates. {len(new_events)} new events remain.")
    else:
        demisto.debug("[Dedup] No duplicates found.")

    return new_events


def fetch_events(
    client: Client,
    last_run: dict,
    first_fetch_time: str,
    alert_status: str | None,
    max_events_per_fetch: int,
) -> tuple[Dict, List[Dict]]:
    """
    Fetches events from the API, deduplicates them against the previous run, and computes the next run.

    Args:
        client (Client): HelloWorld client to use.
        last_run (dict): A dict holding the last fetched id (``prev_id``) and the ids fetched in the
            previous run (``fetched_ids``) used for deduplication.
        first_fetch_time (str): If last_run is empty (first time we are fetching), it contains the timestamp
            on when to start fetching events.
        alert_status (str | None): Status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'.
        max_events_per_fetch (int): Number of events per fetch.

    Returns:
        dict: Next run dictionary containing the last fetched id (``prev_id``) and the ids fetched in this
            run (``fetched_ids``) that will be used in ``last_run`` on the next fetch.
        list: List of new (deduplicated) events that will be created in XSIAM.
    """
    prev_id = last_run.get("prev_id") or 0
    last_fetched_ids = last_run.get("fetched_ids", [])

    events = client.search_events(
        prev_id=prev_id,
        alert_status=alert_status,
        limit=max_events_per_fetch,
        from_date=first_fetch_time,
    )
    demisto.debug(f"Fetched {len(events)} events (before deduplication).")

    # Remove events that were already fetched in the previous run.
    events = deduplicate_events(events, last_fetched_ids)

    # Compute the next run: the highest fetched id and the ids fetched in this run (for the next dedup).
    fetched_ids = [str(event.get("id")) for event in events if event.get("id") is not None]
    max_fetched_id = max((int(event["id"]) for event in events if event.get("id") is not None), default=prev_id)
    next_run = {
        "prev_id": max_fetched_id if events else prev_id + 1,
        "fetched_ids": fetched_ids or last_fetched_ids,
    }
    demisto.debug(f"Setting next run to {next_run}.")
    return next_run, events


""" HELPER FUNCTIONS """


def add_time_to_events(events: List[Dict] | None) -> None:
    """
    Adds the _time key to the events in place.

    Args:
        events (List[Dict] | None): List of events to add the _time key to. The list is modified in place.

    Returns:
        None: The events are modified in place.
    """
    if events:
        for event in events:
            create_time = arg_to_datetime(arg=event.get("created_time"))
            event["_time"] = create_time.strftime(DATE_FORMAT) if create_time else None


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    api_key = params.get("apikey", {}).get("password")
    base_url = urljoin(params.get("url"), "/api/v1")
    verify_certificate = not params.get("insecure", False)

    # The first fetch starts from the current time.
    first_fetch_time = datetime.now(timezone.utc).isoformat()
    proxy = params.get("proxy", False)
    alert_status = params.get("alert_status", "")
    max_events_per_fetch = arg_to_number(params.get("max_events_per_fetch")) or DEFAULT_MAX_EVENTS_PER_FETCH

    demisto.debug(f"Command being called is {command}")
    try:
        headers = {"Authorization": f"Bearer {api_key}"}
        client = Client(base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy)

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client, params, first_fetch_time)
            return_results(result)

        elif command == "hello-world-get-events":
            should_push_events = argToBoolean(args.get("should_push_events", False))
            events, results = get_events(client, args.get("status", alert_status), args)
            return_results(results)
            if should_push_events:
                add_time_to_events(events)
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            next_run, events = fetch_events(
                client=client,
                last_run=last_run,
                first_fetch_time=first_fetch_time,
                alert_status=alert_status,
                max_events_per_fetch=max_events_per_fetch,
            )

            add_time_to_events(events)
            demisto.debug(f"Sending {len(events)} events to XSIAM.")
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.debug("Sent events to XSIAM successfully")
            demisto.setLastRun(next_run)
            demisto.debug(f"Setting next run to {next_run}.")

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
