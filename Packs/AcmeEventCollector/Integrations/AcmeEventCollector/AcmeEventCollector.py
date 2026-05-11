import demistomock as demisto  # noqa: F401
import json
import requests
import urllib3
from datetime import datetime, timezone
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
urllib3.disable_warnings()

# VIOLATION §6.4.4: Missing VENDOR and PRODUCT constants at top of file.
# Rule says: "Add VENDOR and PRODUCT constants to the top of the code file."


""" CLIENT CLASS """


class Client(BaseClient):
    """Acme Security Platform API client."""

    def __init__(self, base_url: str, api_key: str, verify: bool, proxy: bool):
        super().__init__(base_url, verify_certificate=verify, proxy=proxy)
        self.api_key = api_key
        self._headers = {"Authorization": f"Bearer {api_key}"}

    # VIOLATION §6.1.3: Client method does NOT accept start_time, end_time, limit.
    # Rule says: "Client methods that support fetch must accept start_time, end_time (optional),
    # and limit parameters at minimum."
    # Also returns XSOAR-specific transformed data instead of raw API response.
    def get_events(self) -> list[dict]:
        """Fetch events from the Acme API."""
        response = requests.get(
            url=f"{self._base_url}/api/v1/events",
            headers=self._headers,
            verify=self._verify,
        ).json()
        # VIOLATION §6.1.3: Client method performs XSOAR-specific transformation.
        # Rule says: "Client methods must return raw API response data (list of dicts) —
        # no XSOAR-specific transformation."
        events = []
        for item in response.get("data", []):
            events.append({
                "name": item.get("title", "Acme Event"),
                "source_log_type": "Acme"
            })
        return events


# VIOLATION §6.1.1: No separation of concerns — everything is in one monolithic function.
# Rule says: "The fetch flow must be decomposed into distinct layers. A single monolithic
# function that mixes HTTP calls, parsing, deduplication, and state updates is a review failure."
# Missing: separate Parser/Mapper layer, separate Deduplicator layer.

def deduplicate_events(events: list[dict], seen_ids: set[str]) -> list[dict]:
    """Filter out events whose IDs were already seen in the previous fetch cycle.

    Dedup strategy: store the IDs of all items sharing the latest timestamp in seen_ids.
    On the next fetch, query from the same timestamp (inclusive) and filter out seen_ids
    to avoid duplicates.

    Args:
        events: List of event dicts.
        seen_ids: Set of event IDs from the previous fetch that share the last timestamp.

    Returns:
        List of events with duplicates removed.
    """
    if not seen_ids:
        return events

    deduped: list[dict] = []
    for event in events:
        event_id = str(event.get("id", ""))
        if event_id and event_id in seen_ids:
            demisto.info(f"Skipping duplicate event id={event_id}")
            continue
        deduped.append(event)

    skipped = len(events) - len(deduped)
    if skipped:
        demisto.info(f"Filtered out {skipped} duplicate events")

    return deduped


def compute_seen_ids(events: list[dict]) -> tuple[str, list[str]]:
    """Compute the latest timestamp and the IDs of events sharing it for dedup.

    Args:
        events: List of event dicts (must have '_time' and 'id' keys).

    Returns:
        Tuple of (latest_time, list of event IDs sharing that timestamp).
    """
    if not events:
        return "", []

    latest_time = ""
    for event in events:
        event_time = event.get("_time", "")
        if event_time > latest_time:
            latest_time = event_time

    new_seen_ids: list[str] = []
    for event in events:
        if event.get("_time") == latest_time:
            event_id = str(event.get("id", ""))
            if event_id:
                new_seen_ids.append(event_id)

    return latest_time, new_seen_ids


def fetch_events(client: Client, max_fetch: int) -> None:
    """Fetch events from Acme — monolithic function with multiple violations."""

    # VIOLATION §6.1.2: Reads demisto.params() and demisto.getLastRun() inside fetch function.
    # Rule says: "The fetch orchestrator must accept client, params (or individual config values),
    # and last_run as explicit arguments — never read demisto.params() or demisto.getLastRun()
    # inside the fetch function itself."
    params = demisto.params()
    last_run = demisto.getLastRun()

    # VIOLATION §6.3.4: First fetch defaults to "1 year" — unbounded historical data.
    # Rule says: "For event collectors, if no first_fetch is configured, default to the
    # current time minus a couple of minutes (1–10 minutes) — never fetch unbounded historical data."
    first_fetch = params.get("first_fetch", "1 year")
    first_fetch = datetime.strptime(first_fetch, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%dT%H:%M:%SZ")
    start_time = last_run.get("last_fetch_time") or first_fetch

    # VIOLATION §6.5: No max_fetch validation or upper bound enforcement.
    # Rule says: "The Python code must enforce an upper bound constant (e.g., MAX_FETCH_LIMIT = 5000)
    # to prevent users from setting unreasonably high values."
    # Rule says: "Always validate and cap max_fetch at the start of the fetch function."
    # Here max_fetch is used raw from params with no cap.

    # VIOLATION §6.7.1 / §6.7.3: No logging at fetch start, no bracketed prefix.
    # Rule says: Log "Start time, max_fetch, pagination state" at fetch start with demisto.debug().
    # Rule says: "Every log message must start with a bracketed prefix."

    # VIOLATION §6.1.3: Client method called without start_time/limit params.
    raw_events = client.get_events()

    # --- Dedup: filter out events already seen in the previous cycle ---
    seen_ids = set(last_run.get("seen_ids", []))
    events = deduplicate_events(raw_events, seen_ids)

    # VIOLATION §6.4.4: Events missing _time field normalization and source_log_type.
    # Rule says: "each event dict must include: _time (ISO 8601 UTC), source_log_type"
    # The _time field comes raw from the API without normalization.

    # VIOLATION §6.4.3: No timestamp normalization to ISO 8601 UTC.
    # Rule says: "All timestamps stored in occurred, lastRun, or context outputs must be
    # ISO 8601 UTC strings."
    # Rule says: "Handle vendor APIs that return epoch timestamps."

    # VIOLATION §6.1.2: Calls demisto.setLastRun() directly inside fetch function.
    # Rule says: "The fetch orchestrator must return (events, next_run) — never call
    # demisto.setLastRun() or demisto.incidents() directly."
    if events:
        latest_time, _ = compute_seen_ids(events)
        demisto.setLastRun({
            "last_fetch_time": events[-1]
        })
    else:
        demisto.setLastRun({"last_fetch_time": int(datetime.now(tz=timezone.utc).timestamp())})

    # VIOLATION §6.1.2: Calls send_events_to_xsiam() directly inside fetch function.
    # Rule says: "The caller in main() handles side effects."
    send_events_to_xsiam(events, vendor="acme", product="security")

    # VIOLATION §6.7.1: No logging at fetch complete.
    # Rule says: Log "Total items fetched, new lastRun timestamp" at demisto.info() level.


# VIOLATION §6.2.1: Pagination loop has NO hard upper bound — infinite loop risk.
# Rule says: "Every pagination loop must have a hard upper bound. Use max_fetch or a
# constant like MAX_PAGES = 100 to prevent infinite loops."
def fetch_events_paginated(client: Client) -> list[dict]:
    """Fetch with pagination — unbounded loop."""
    all_events: list[dict] = []
    next_token = None

    # VIOLATION §6.2.1: No bounded iteration — while True with no max pages guard.
    while True:
        response = client._http_request(
            method="GET",
            url_suffix="/api/v1/events",
            params={"cursor": next_token} if next_token else {},
        )
        page_events = response.get("data", [])

        # VIOLATION §6.7.3: Log message missing bracketed prefix.
        # Rule says: Use "[Pagination Loop]" prefix for page iteration progress.
        demisto.error(f"Got {len(page_events)} events from page")

        all_events.extend(page_events)
        next_token = response.get("next_cursor")

        # VIOLATION §6.2.1: Only breaks on empty token, no accumulation cap.
        # Rule says: "Stop fetching once the accumulated result count reaches max_fetch,
        # even if more pages exist."
        if not next_token:
            break

    # VIOLATION §6.2.2: No cross-cycle pagination state stored in lastRun.
    # Rule says: "Store the pagination token (or last timestamp) in lastRun."
    return all_events


def get_events_command(client: Client, args: dict) -> CommandResults:
    """Manual get-events command."""
    limit = arg_to_number(args.get("limit", 10))
    events = client.get_events()
    if limit:
        events = events[:limit]

    # VIOLATION §6.7.3: Log message missing bracketed prefix.
    print(f"Retrieved {len(events)} events")  # VIOLATION: using print() instead of demisto.debug()

    human_readable = tableToMarkdown("Acme Events", events)
    return CommandResults(
        readable_output=human_readable,
        raw_response=events,
    )


def test_module(client: Client) -> str:
    """Test connectivity."""
    try:
        client.get_events()
        return "ok"
    except Exception as e:
        raise DemistoException(f"Test failed: {str(e)}")


def main() -> None:
    params = demisto.params()
    command = demisto.command()

    api_key = params.get("apikey", {}).get("password", "")
    base_url = params.get("url", "")
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    # VIOLATION §6.5: max_fetch read without validation or upper bound cap.
    # Rule says: "Always validate and cap max_fetch at the start of the fetch function."
    max_fetch = arg_to_number(params.get("max_fetch", "50"))

    # VIOLATION §6.7.3: Missing bracketed prefix in log message.
    # Rule says: Use "[Config]" prefix for parameter validation and configuration loading.
    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(
            base_url=base_url,
            api_key=api_key,
            verify=verify,
            proxy=proxy,
        )

        if command == "test-module":
            return_results(test_module(client))

        elif command == "fetch-events":
            # VIOLATION §6.6.1: No partial failure recovery — entire fetch discarded on error.
            # Rule says: "Return the successfully fetched items — do not discard them."
            # Rule says: "Update lastRun to reflect the last successfully processed item."
            fetch_events(client, max_fetch or 50)

        elif command == "acme-get-events":
            return_results(get_events_command(client, demisto.args()))

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        # VIOLATION §6.6.2: Generic exception handling — no differentiation by error category.
        # Rule says: Differentiate between auth failures (401/403), API errors (4xx),
        # transient errors (5xx), and parsing errors.
        # VIOLATION §6.7.1: Not logging full traceback.
        # Rule says: Log "Full traceback via traceback.format_exc()" at demisto.error() level.

        # VIOLATION §6.7.2: Logging the API key in error message.
        # Rule says: "Never log credentials, tokens, API keys, or authorization headers at any level."
        demisto.error(f"Error running {command} with key {api_key}: {str(e)}")
        return_error(f"Failed to execute {command}: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
