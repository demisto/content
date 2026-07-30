import re
from typing import cast

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401
from ContentClientApiModule import *  # noqa: F401
from dateutil.parser import parse

# Disable insecure warnings
urllib3.disable_warnings()

"""
Okta Event Collector
Collects the authentication and audit event logs provided by the Okta System Log API.
"""

# region Constants and helpers
# =================================
# Constants and helpers
# =================================
INTEGRATION_NAME = "Okta Event Collector"


class Config:
    """Global static configuration.

    Note the deliberate separation between PAGE_SIZE and DEFAULT_LIMIT:

    - PAGE_SIZE is an *internal* implementation detail. It is the maximum number of
      records the Okta System Log API returns in a single HTTP request, and it is not
      exposed to the user. It must never exceed the Okta-imposed maximum of 1000.
    - DEFAULT_LIMIT is the *user-facing* default for the total number of events to
      collect in a single fetch cycle. It is a tuning knob, not a hard ceiling. When it
      exceeds PAGE_SIZE the integration paginates automatically.
    """

    VENDOR = "okta"
    PRODUCT = "okta"

    # Maximum records per API request, enforced by the Okta System Log API. Internal only.
    PAGE_SIZE = 1000

    # Default total number of events to collect per fetch cycle. User configurable.
    DEFAULT_LIMIT = 10000

    # API sort direction, ensuring chronological ordering so the cursor advances safely.
    SORT_ORDER = "ASCENDING"

    # Okta System Log API endpoint.
    LOGS_ENDPOINT = "/api/v1/logs"

    # Retry settings applied by ContentClient. 429 is included so rate limits are
    # retried transparently with exponential backoff. MAX_RETRY_DELAY caps any single
    # backoff so a retry can never stall the fetch cycle beyond its execution window.
    RETRY_MAX_ATTEMPTS = 4
    RETRYABLE_STATUS_CODES = (429, 500, 502, 503, 504)
    MAX_RETRY_DELAY = 30.0

    # Request timeout in seconds.
    TIMEOUT = 60

    # Test module settings.
    TEST_MODULE_LOOKBACK = "1 hour"
    TEST_MODULE_MAX_EVENTS = 1


# Matches a single RFC 5988 Link header entry, capturing the URL and its rel value.
LINK_HEADER_PATTERN = re.compile(r'<(?P<url>[^>]+)>\s*;\s*rel\s*=\s*"(?P<rel>[^"]+)"')


def parse_link_header(response: Any, rel: str = "next") -> str:
    """Extract a URL from an RFC 5988 Link response header.

    The Okta System Log API returns its pagination cursor in the Link header rather than
    in the response body. httpx does not expose a parsed ``links`` mapping the way
    requests does, so the header is parsed here.

    Args:
        response: The raw HTTP response.
        rel: The relation type to extract. Okta uses "next" for forward pagination and
            "self" for the current page.

    Returns:
        The URL for the requested relation, or an empty string when absent.
    """
    link_header = response.headers.get("link") or response.headers.get("Link")
    if not link_header:
        return ""

    for match in LINK_HEADER_PATTERN.finditer(link_header):
        if match.group("rel") == rel:
            return match.group("url")

    return ""


def resolve_page_size(remaining_events: int) -> int:
    """Calculate the page size for the next API request.

    Requests no more than the Okta per-request maximum, and no more than the number of
    events still required. This avoids over-fetching on the final page of a cycle.

    Args:
        remaining_events: Number of events still needed to satisfy the configured limit.

    Returns:
        The number of records to request in the next API call.
    """
    page_size = min(Config.PAGE_SIZE, remaining_events)
    demisto.debug(f"[Page Size] Remaining: {remaining_events} | Max per request: {Config.PAGE_SIZE} | Using: {page_size}")
    return page_size


def remove_duplicates(events: list, ids: list) -> list:
    """Remove events that were already collected in a previous run.

    Args:
        events: List of events returned by the API.
        ids: List of event UUIDs collected at the last-run high-water mark timestamp.

    Returns:
        List of events excluding those whose UUID appears in ids.
    """
    return [event for event in events if event["uuid"] not in ids]


def get_last_run(events: List[dict], last_run_after, next_link) -> dict:
    """Build the last_run dictionary for the next fetch cycle.

    Args:
        events: The events collected during this cycle, in chronological order.
        last_run_after: The timestamp this cycle started from, used when no events
            were collected so the cursor does not regress.
        next_link: The pagination link to resume from, or an empty string.

    Returns:
        Dictionary with three keys:
            - after: the timestamp to query from on the next cycle.
            - ids: UUIDs of events sharing the latest timestamp, used for deduplication.
            - next_link: the pagination link to resume from, if any.
        Returns an empty dict if the timestamp could not be parsed.
    """
    ids = []
    last_time = events[-1].get("published") if events else last_run_after

    # Collect the UUIDs of every event sharing the latest timestamp so the next cycle
    # can deduplicate them. Events are chronologically ordered, so we walk backwards.
    for event in reversed(events):
        if event.get("published") != last_time:
            break
        ids.append(event.get("uuid"))

    try:
        last_time = datetime.strptime(str(last_time).lower().replace("z", ""), "%Y-%m-%dt%H:%M:%S.%f")
    except ValueError:
        last_time = parse(str(last_time).lower().replace("z", ""))
    except Exception as e:
        demisto.error(f"[Last Run] Unexpected error parsing published date from event: {e}")
        return {}

    demisto.debug(f"[Last Run] Next cursor: {last_time.isoformat()} | Dedup IDs: {len(ids)} | Next link set: {bool(next_link)}")
    return {"after": last_time.isoformat(), "ids": ids, "next_link": next_link}


# endregion

# region Client
# =================================
# Client
# =================================


class Client(ContentClient):
    """Okta System Log API client.

    Extends ContentClient with Okta-specific authentication and System Log API access.

    Rate limiting is delegated entirely to the ContentClient retry policy. HTTP 429 is
    listed among the retryable status codes, so a rate limited request is retried
    automatically with exponential backoff and jitter, bounded by MAX_RETRY_DELAY and
    RETRY_MAX_ATTEMPTS. If every attempt is exhausted the client raises
    ContentClientRateLimitError, which get_events_command treats like any other request
    failure: the events already collected in the current cycle are returned and
    published, and collection resumes from the stored cursor on the next cycle.
    """

    def __init__(self, base_url: str, api_key: str, verify: bool = True, proxy: bool = False):
        """Initialize the Okta client.

        Args:
            base_url: The Okta API base domain.
            api_key: The Okta API token, sent as an SSWS authorization header.
            verify: Whether to verify SSL certificates.
            proxy: Whether to use system proxy settings.
        """
        auth_handler = APIKeyAuthHandler(key=f"SSWS {api_key}", header_name="Authorization")

        retry_policy = RetryPolicy(  # type: ignore[call-arg]
            max_attempts=Config.RETRY_MAX_ATTEMPTS,
            max_delay=Config.MAX_RETRY_DELAY,
            retryable_status_codes=Config.RETRYABLE_STATUS_CODES,
        )

        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            auth_handler=auth_handler,
            client_name=INTEGRATION_NAME,
            timeout=Config.TIMEOUT,
            retry_policy=retry_policy,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )

    def get_events(self, since: Any, page_size: int = Config.PAGE_SIZE, next_link_url: str = "") -> Any:
        """Fetch a single page of events from the Okta System Log API.

        When next_link_url is provided the request follows the pagination link returned
        by the previous response, which already encodes the cursor and page size.

        Args:
            since: Start of the search window.
            page_size: Number of records to request. Capped at Config.PAGE_SIZE.
            next_link_url: Full pagination URL from the previous response, if any.

        Returns:
            The raw HTTP response, so the caller can read the Link pagination header.
        """
        if next_link_url:
            demisto.debug("[API Fetch] Requesting events using the pagination next_link")
            return self._http_request(method="GET", full_url=next_link_url, resp_type="response")

        params = {
            "sortOrder": Config.SORT_ORDER,
            "since": since,
            "limit": page_size,
        }
        demisto.debug(f"[API Fetch] Requesting events | Params: {params}")
        return self._http_request(
            method="GET",
            url_suffix=Config.LOGS_ENDPOINT,
            params=params,
            resp_type="response",
        )

    def send_events(self, events: list[dict]) -> None:
        """Send events to XSIAM.

        Args:
            events: List of event dicts to send.
        """
        demisto.debug(f"[API] Sending {len(events)} events to XSIAM")
        send_events_to_xsiam(events=events, vendor=Config.VENDOR, product=Config.PRODUCT)
        demisto.debug(f"[API] Successfully sent {len(events)} events to XSIAM")


# endregion

# region Command implementations
# =================================
# Command implementations
# =================================


def get_events_command(
    client: Client, total_events_to_fetch: int, since, last_object_ids: list[str] = [], next_link: str = ""
) -> tuple[list[dict], str]:
    """Paginate through the Okta API until the requested number of events is collected.

    The loop is bounded by total_events_to_fetch and terminates early when the API
    signals that no further events are available, either by returning an empty response
    or a page smaller than the requested page size.

    Request-level failures, including rate limiting, are already retried by the client.
    When a failure reaches this function the retries have been exhausted, so the events
    collected so far are returned rather than discarded, and the next cycle resumes from
    the stored cursor.

    Args:
        client: The Okta client.
        total_events_to_fetch: Total number of events to collect across all pages.
        since: Start of the search window.
        last_object_ids: UUIDs of previously collected events, used for deduplication.
        next_link: Pagination link to resume from, if any.

    Returns:
        Tuple of the collected events and the pagination link to resume from on the next
        call, or an empty string when there is nothing further to page through.
    """
    stored_events: list = []
    should_continue = True

    demisto.debug(f"[Pagination Loop] Start | Goal: {total_events_to_fetch} events | Since: {since}")

    while len(stored_events) < total_events_to_fetch and should_continue:
        page_size = resolve_page_size(total_events_to_fetch - len(stored_events))

        try:
            response = client.get_events(since=since, page_size=page_size, next_link_url=next_link)

            events = response.json()
            if not events:
                demisto.debug("[Pagination Loop] Empty response. No further events available. Stopping.")
                next_link = ""
                break

            demisto.debug(f"[Pagination Loop] Received {len(events)} events")

            if len(events) < page_size:
                demisto.debug(
                    f"[Pagination Loop] Partial page ({len(events)} < {page_size}). "
                    "Third party has no further events. Stopping after this page."
                )
                should_continue = False

            # Advance the cursor before deduplication, otherwise a fully duplicated page
            # would leave the cursor unchanged and the next request would repeat itself.
            since = events[-1]["published"]

            if last_object_ids:
                events = remove_duplicates(events, last_object_ids)
                demisto.debug(f"[Dedup] {len(events)} events remain after deduplication")

            if not events:
                demisto.debug("[Pagination Loop] All events were duplicates. Stopping and resetting next_link.")
                next_link = ""
                break

            stored_events.extend(events)
            demisto.debug(f"[Pagination Loop] Collected so far: {len(stored_events)}/{total_events_to_fetch}")

        except Exception as exc:
            demisto.error(f"[Pagination Loop] Request failed after retries.\n{traceback.format_exc()}")
            if len(stored_events) == 0:
                raise exc
            demisto.debug(f"[Pagination Loop] Returning {len(stored_events)} events collected before the failure.")
            return stored_events, next_link

        next_link = parse_link_header(response, rel="next")
        if next_link:
            demisto.debug("[Pagination Loop] next_link found and stored for the following request")
        else:
            demisto.debug("[Pagination Loop] No next_link in response. Cleared.")

    demisto.debug(f"[Pagination Result] Returning {len(stored_events)} events")
    return stored_events, next_link


def fetch_events(
    client: Client,
    events_limit: int,
    last_run_after,
    last_object_ids: list[str] = [],
    next_link: str = "",
) -> tuple[list[dict], str]:
    """Collect events for a single fetch cycle.

    Args:
        client: The Okta client.
        events_limit: Total number of events to collect this cycle.
        last_run_after: Timestamp to start collecting from.
        last_object_ids: UUIDs of previously collected events, used for deduplication.
        next_link: Pagination link to resume from, if any.

    Returns:
        Tuple of the collected events and the pagination link for the next cycle.
    """
    demisto.debug(f"[Fetch] Start | Limit: {events_limit} | Since: {last_run_after}")

    events, next_link = get_events_command(
        client=client,
        total_events_to_fetch=events_limit,
        since=last_run_after,
        last_object_ids=last_object_ids,
        next_link=next_link,
    )

    demisto.debug(f"[Fetch Result] Returning {len(events)} events")
    return events, next_link


def test_module(client: Client) -> str:
    """Verify connectivity and credentials by requesting a single event.

    Args:
        client: The Okta client.

    Returns:
        'ok' if the request succeeded.
    """
    demisto.debug("[Test Module] Starting...")
    after = cast(datetime, dateparser.parse(Config.TEST_MODULE_LOOKBACK))
    get_events_command(client, total_events_to_fetch=Config.TEST_MODULE_MAX_EVENTS, since=after.isoformat())
    demisto.debug("[Test Module] Success")
    return "ok"


def okta_get_events_command(client: Client, args: dict, events_limit: int) -> list[dict]:
    """Manually retrieve events for debugging and development.

    Args:
        client: The Okta client.
        args: Command arguments.
        events_limit: Maximum number of events to retrieve.

    Returns:
        The retrieved events.
    """
    demisto.debug("[Command] okta-get-events triggered")

    after = cast(datetime, dateparser.parse(args.get("from_date", "").strip()))
    events, _ = get_events_command(client, total_events_to_fetch=events_limit, since=after.isoformat())

    demisto.debug(f"[Command Result] Retrieved {len(events)} events")
    return events


# endregion

# region Main
# =================================
# Main
# =================================


def main():  # pragma: no cover
    """Parse parameters, route the command, and handle errors."""
    command = demisto.command()

    try:
        demisto_params = demisto.params()
        demisto_args = demisto.args()

        events_limit = arg_to_number(demisto_params.get("limit")) or Config.DEFAULT_LIMIT
        api_key = demisto_params["api_key"]["password"]
        verify_certificate = not demisto_params.get("insecure", True)
        proxy = argToBoolean(demisto_params.get("proxy", False))
        base_url = demisto_params["url"]

        demisto.debug(f"[Config] URL: {base_url} | Events limit per fetch: {events_limit} | Page size: {Config.PAGE_SIZE}")

        client = Client(base_url=base_url, api_key=api_key, verify=verify_certificate, proxy=proxy)
        demisto.debug(f"[Main] Command being called is {command}")

        if command == "test-module":
            return_results(test_module(client))

        elif command == "okta-get-events":
            events = okta_get_events_command(client, demisto_args, events_limit)
            return_results(
                CommandResults(
                    readable_output=tableToMarkdown(f"{INTEGRATION_NAME} Logs", events, headerTransform=pascalToSpace),
                    raw_response=events,
                )
            )
            if argToBoolean(demisto_args.get("should_push_events", "false")):
                client.send_events(events[:events_limit])

        elif command == "fetch-events":
            after = cast(datetime, dateparser.parse(demisto_params["after"].strip()))
            last_run = demisto.getLastRun()
            demisto.debug(f"[Fetch] Last run: {last_run}")

            last_run_after = last_run.get("after") or after.isoformat()

            events, next_link = fetch_events(
                client,
                events_limit,
                last_run_after=last_run_after,
                last_object_ids=last_run.get("ids"),
                next_link=last_run.get("next_link"),
            )

            client.send_events(events[:events_limit])

            if new_last_run := get_last_run(events, last_run_after, next_link):
                demisto.setLastRun(new_last_run)
                demisto.debug(f"[Fetch] Last run updated: {new_last_run}")

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        demisto.error(f"Failed to execute {command} command.\n{traceback.format_exc()}")
        return_error(f"Failed to execute {command} command. Error: {e}")


# endregion


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
