from typing import Any

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa

from ContentClientApiModule import *  # noqa: F401

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

VENDOR = "proofpoint"
PRODUCT = "tessian"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_LIMIT = 100
MAX_API_LIMIT = 100
DEFAULT_MAX_FETCH = 1000
MAX_API_CALLS_PER_FETCH = 10
CLIENT_NAME = "TessianEventCollector"

""" CLIENT CLASS """


class Client(ContentClient):
    """Client class to interact with the Proofpoint Tessian Security Events API.

    Extends ContentClient with Tessian-specific functionality including
    API-Token authentication and the security events endpoint.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        verify: bool,
        proxy: bool,
    ):
        """Initialize the Tessian client.

        Args:
            base_url: Proofpoint Tessian portal URL.
            api_key: API token for authentication.
            verify: Whether to verify SSL certificates.
            proxy: Whether to use proxy settings.
        """
        auth_handler = APIKeyAuthHandler(
            key=f"API-Token {api_key}",
            header_name="Authorization",
        )

        retry_policy = RetryPolicy(  # type: ignore[call-arg]
            max_attempts=4,
            retryable_status_codes=(429, 500, 502, 503, 504),
        )

        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            auth_handler=auth_handler,
            client_name=CLIENT_NAME,
            timeout=30,
            retry_policy=retry_policy,
        )

    def list_events(
        self,
        limit: int | None = None,
        after_checkpoint: str | None = None,
        created_after: str | None = None,
    ) -> dict[str, Any]:
        """Fetch security events from the Tessian API.

        Args:
            limit: Maximum number of events to return (2-100).
            after_checkpoint: Pagination cursor from a previous response.
            created_after: Only include events created after this ISO 8601 datetime.

        Returns:
            API response containing results, checkpoint, and additional_results flag.
        """
        params = assign_params(
            limit=limit,
            after_checkpoint=after_checkpoint,
            created_after=created_after,
        )

        return self._http_request(
            method="GET",
            url_suffix="/api/v1/events",
            params=params,
        )


""" HELPER FUNCTIONS """


def format_url(url: str) -> str:
    """Strips and normalizes the URL to ensure it is in the expected format.

    Expected format: https://domain.tessian-platform.com

    Args:
        url: The raw URL input from the user.

    Returns:
        A normalized URL with https:// prefix and no trailing path.
    """
    if url.startswith("http://"):
        url = url[7:]
    elif url.startswith("https://"):
        url = url[8:]

    if "/" in url:
        url = url.split("/")[0]

    return f"https://{url}"


def enrich_events(events: list[dict]) -> list[dict]:
    """Enriches events with _time and _ENTRY_STATUS fields for XSIAM.

    Sets _time to created_at.
    Sets _ENTRY_STATUS based on comparison of updated_at and created_at:
      - "new" if updated_at == created_at
      - "updated" if updated_at > created_at

    Args:
        events: A list of event dictionaries from the API.

    Returns:
        The enriched list of events.
    """
    for event in events:
        created_at = event.get("created_at")
        updated_at = event.get("updated_at")

        if created_at:
            event["_time"] = created_at

        if created_at and updated_at:
            if updated_at == created_at:
                event["_ENTRY_STATUS"] = "new"
            elif updated_at > created_at:
                event["_ENTRY_STATUS"] = "updated"

    return events


def fetch_events_with_pagination(
    client: Client,
    created_after: str | None,
    initial_checkpoint: str | None,
    max_fetch: int,
) -> tuple[list[dict], str | None]:
    """Fetches events using checkpoint-based pagination.

    Makes up to MAX_API_CALLS_PER_FETCH API calls, each returning up to
    MAX_API_LIMIT events, until max_fetch is reached or no more results.

    Args:
        client: The Tessian API client.
        created_after: ISO 8601 datetime filter for first call (used only if no checkpoint).
        initial_checkpoint: Checkpoint from previous fetch cycle.
        max_fetch: Maximum total events to collect.

    Returns:
        A tuple of (collected_events, last_checkpoint).
    """
    all_events: list[dict] = []
    checkpoint = initial_checkpoint
    api_calls = 0

    while len(all_events) < max_fetch and api_calls < MAX_API_CALLS_PER_FETCH:
        remaining = max_fetch - len(all_events)
        page_limit = min(remaining, MAX_API_LIMIT)

        demisto.debug(f"Fetching events: call={api_calls + 1}, " f"checkpoint={checkpoint}, page_limit={page_limit}")

        if checkpoint:
            response = client.list_events(
                limit=page_limit,
                after_checkpoint=checkpoint,
            )
        else:
            response = client.list_events(
                limit=page_limit,
                created_after=created_after,
            )

        events = response.get("results", [])
        new_checkpoint = response.get("checkpoint")
        has_more = response.get("additional_results", False)

        if events:
            all_events.extend(events)

        if new_checkpoint:
            checkpoint = new_checkpoint

        api_calls += 1

        if not events or not has_more:
            demisto.debug(f"Stopping pagination: events={len(events)}, has_more={has_more}")
            break

    demisto.debug(f"Pagination complete: total_events={len(all_events)}, " f"api_calls={api_calls}, last_checkpoint={checkpoint}")

    return all_events, checkpoint


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication.

    Args:
        client: The Tessian API client.

    Returns:
        'ok' if the test passed, otherwise raises an exception.
    """
    try:
        response = client.list_events(limit=2)
        if demisto.get(response, "checkpoint") is None:
            return f"Unexpected result from the service: " f"expected checkpoint to be a string, response={response!s}"
        return "ok"
    except Exception as e:
        exception_text = str(e).lower()
        if "forbidden" in exception_text or "authorization" in exception_text:
            return "Authorization Error: make sure API Key is correctly set"
        raise


def get_events_command(
    client: Client,
    args: dict[str, Any],
) -> tuple[list[dict], CommandResults]:
    """Manual command to fetch events for debugging/development.

    This command is used for developing/debugging and should be used with caution,
    as it can create duplicate events and exceed API request limits.

    Args:
        client: The Tessian API client.
        args: Command arguments including limit, created_after, and should_push_events.

    Returns:
        A tuple of (events, CommandResults).
    """
    limit = arg_to_number(args.get("limit")) or DEFAULT_LIMIT
    limit = max(2, min(limit, DEFAULT_MAX_FETCH))
    created_after = args.get("created_after")
    should_push_events = argToBoolean(args.get("should_push_events", False))

    events, _ = fetch_events_with_pagination(
        client=client,
        created_after=created_after,
        initial_checkpoint=None,
        max_fetch=limit,
    )

    enriched = enrich_events(events)

    if should_push_events and enriched:
        send_events_to_xsiam(enriched, vendor=VENDOR, product=PRODUCT)

    hr = tableToMarkdown(
        name="Tessian Security Events",
        t=[
            {
                "Event ID": event.get("id"),
                "Type": event.get("type"),
                "Created At": event.get("created_at"),
                "Updated At": event.get("updated_at"),
                "Entry Status": event.get("_ENTRY_STATUS"),
                "Portal Link": event.get("portal_link"),
            }
            for event in enriched
        ],
        headers=["Event ID", "Type", "Created At", "Updated At", "Entry Status", "Portal Link"],
        removeNull=True,
    )

    return enriched, CommandResults(readable_output=hr, raw_response=enriched)


def fetch_events_command(
    client: Client,
    last_run: dict[str, Any],
    max_fetch: int,
) -> tuple[list[dict], dict[str, Any]]:
    """Fetches security events from Tessian for XSIAM ingestion.

    Uses checkpoint-based pagination. On first run, uses created_after
    set to the current time. On subsequent runs, uses the stored checkpoint.

    Args:
        client: The Tessian API client.
        last_run: The last run dictionary containing checkpoint state.
        max_fetch: Maximum number of events to fetch per cycle.

    Returns:
        A tuple of (enriched_events, updated_last_run).
    """
    checkpoint = last_run.get("checkpoint")
    created_after = last_run.get("created_after")

    if not checkpoint and not created_after:
        created_after = datetime.now(timezone.utc).strftime(DATE_FORMAT)
        demisto.debug(f"First fetch, starting from: {created_after}")

    events, new_checkpoint = fetch_events_with_pagination(
        client=client,
        created_after=created_after,
        initial_checkpoint=checkpoint,
        max_fetch=max_fetch,
    )

    enriched = enrich_events(events)

    next_run: dict[str, Any] = {}
    if new_checkpoint:
        next_run["checkpoint"] = new_checkpoint
    elif checkpoint:
        next_run["checkpoint"] = checkpoint
    else:
        next_run["created_after"] = created_after

    demisto.debug(f"Fetch complete: {len(enriched)} events, next_run={next_run}")

    return enriched, next_run


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """Main function, parses params and runs command functions."""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = format_url(params.get("url", ""))
    api_key = params.get("api_key", {}).get("password", "")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH
    max_fetch = max(2, min(max_fetch, DEFAULT_MAX_FETCH))

    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(
            base_url=base_url,
            api_key=api_key,
            verify=verify_certificate,
            proxy=proxy,
        )

        if command == "test-module":
            return_results(test_module(client))

        elif command == "tessian-get-events":
            events, results = get_events_command(client=client, args=args)
            return_results(results)

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            demisto.debug(f"Starting fetch with last_run: {last_run}")

            events, next_run = fetch_events_command(
                client=client,
                last_run=last_run,
                max_fetch=max_fetch,
            )

            demisto.debug(f"Fetched {len(events)} total events")

            if events:
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

            if next_run:
                demisto.debug(f"Setting new last_run: {next_run}")
                demisto.setLastRun(next_run)

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e!s}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
