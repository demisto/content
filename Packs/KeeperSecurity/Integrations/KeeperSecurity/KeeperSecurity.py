import hashlib
from datetime import datetime, timedelta, UTC

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401

""" CONSTANTS """

# We fetch from the Keeper Security Admin Console, so the Product is not "Security", but we assigned it as such
# so the dataset could have the name keeper_security_raw
VENDOR = "Keeper"
PRODUCT = "Security"
LOG_LINE = f"{VENDOR}_{PRODUCT}:"
DEFAULT_MAX_FETCH = 10000
API_MAX_FETCH = 1000
DEFAULT_FIRST_FETCH = "1 hour"
EVENTS_ENDPOINT = "/api/rest/public/events"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, the only format the API parses reliably
INVALID_TOKEN_MESSAGE = (
    "Authorization failed. Make sure the API key is valid, has not expired or been revoked, and was created with the "
    "'SIEM:1' (read) integration scope."
)

# Disable insecure warnings
urllib3.disable_warnings()


""" CLIENT CLASS """


class Client(BaseClient):
    """Client for the Keeper Security Admin REST API (ARAM events)."""

    def __init__(self, base_url: str, api_key: str, verify: bool = True, proxy: bool = False) -> None:
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            headers={"x-api-token": f"Bearer {api_key}", "Accept": "application/json"},
        )

    @staticmethod
    def _error_handler(res: requests.Response) -> None:
        if res.status_code == 403:
            raise DemistoException(f"{INVALID_TOKEN_MESSAGE} Response: {res.text}", res=res)
        if res.status_code == 429:
            raise DemistoException(f"Keeper Security throttled the request (HTTP 429). Response: {res.text}", res=res)
        raise DemistoException(f"Error in API call [{res.status_code}] - {res.reason}. Response: {res.text}", res=res)

    def get_events(
        self,
        start_date: datetime,
        end_date: datetime,
        limit: int = API_MAX_FETCH,
        continuation_token: str | None = None,
    ) -> dict[str, Any]:
        """Gets one page of audit events, in ascending order. Both date bounds are inclusive.

        Note that a continuation token is only valid together with the same start and end dates it was issued for.
        """
        params: dict[str, Any] = {
            "start_date": start_date.strftime(DATE_FORMAT),
            "end_date": end_date.strftime(DATE_FORMAT),
            "limit": limit,
        }
        if continuation_token:
            params["continuation_token"] = continuation_token
        return self._http_request(
            "GET",
            EVENTS_ENDPOINT,
            params=params,
            # The API allows 10 requests per 10 seconds per API key and answers 429 when throttled.
            retries=3,
            status_list_to_retry=[429],
            backoff_factor=3,
            error_handler=self._error_handler,
        )


""" HELPER FUNCTIONS """


def normalize_base_url(url: str) -> str:
    """Accepts 'keepersecurity.com' as well as 'https://keepersecurity.com/' and returns a clean base URL."""
    url = (url or "keepersecurity.com").strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url


def event_hash(event: dict[str, Any]) -> str:
    """The API does not return an event ID, so identify an event by the fields that describe it."""
    fields = ("timestamp", "audit_event", "username", "remote_address", "client_version", "category", "enterprise_id")
    raw = "|".join(str(event.get(field, "")) for field in fields)
    return hashlib.sha256(raw.encode()).hexdigest()


def add_time_to_events(audit_events: list[dict[str, Any]]) -> None:
    """Adds the `_time` field, which XSIAM uses as the event time. `timestamp` is in epoch milliseconds."""
    for audit_event in audit_events:
        audit_event["_time"] = timestamp_to_datestring(audit_event["timestamp"], is_utc=True)


def dedup_events(
    audit_events: list[dict[str, Any]], last_fetch_time_ms: int, last_fetched_hashes: set[str]
) -> list[dict[str, Any]]:
    """Removes events that were already fetched.

    The query's start date has a resolution of seconds and is inclusive, so the same second can be returned again.
    """
    return [
        audit_event
        for audit_event in audit_events
        if int(audit_event["timestamp"]) > last_fetch_time_ms
        or (int(audit_event["timestamp"]) == last_fetch_time_ms and event_hash(audit_event) not in last_fetched_hashes)
    ]


def get_audit_logs(
    client: Client,
    start_time_ms: int,
    max_fetch_limit: int,
    last_fetched_hashes: set[str],
    end_date: datetime | None = None,
) -> tuple[list[dict[str, Any]], int, set[str]]:
    """Fetches events newer than start_time_ms, following the continuation token.

    Returns:
        The events, the timestamp (ms) of the latest event and the hashes of the events with that timestamp.
    """
    end_date = end_date or datetime.now(UTC)
    start_date = datetime.fromtimestamp(start_time_ms // 1000, tz=UTC)
    events: list[dict[str, Any]] = []
    latest_time_ms = start_time_ms
    latest_hashes = set(last_fetched_hashes)
    continuation_token = None
    has_more = True

    while has_more and len(events) < max_fetch_limit:
        response = client.get_events(
            start_date=start_date,
            end_date=end_date,
            limit=min(API_MAX_FETCH, max_fetch_limit - len(events)),
            continuation_token=continuation_token,
        )
        page = response.get("events") or []
        demisto.debug(f"{LOG_LINE} got {len(page)} events from API")
        new_events = dedup_events(page, start_time_ms, last_fetched_hashes)
        demisto.debug(f"{LOG_LINE} events count after dedup {len(new_events)}")
        new_events = new_events[: max_fetch_limit - len(events)]

        for audit_event in new_events:
            timestamp = int(audit_event["timestamp"])
            if timestamp > latest_time_ms:
                latest_time_ms = timestamp
                latest_hashes = set()
            if timestamp == latest_time_ms:
                latest_hashes.add(event_hash(audit_event))
        events.extend(new_events)

        continuation_token = response.get("continuation_token")
        has_more = bool(response.get("has_more") and continuation_token)

    add_time_to_events(events)
    return events, latest_time_ms, latest_hashes


def fetch_events(
    client: Client, last_run: dict[str, Any], max_fetch_limit: int, first_fetch: datetime
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    demisto.debug(f"last_run: {last_run}" if last_run else "last_run is empty")
    start_time_ms = int(last_run.get("last_fetch_time_ms") or first_fetch.timestamp() * 1000)
    last_fetched_hashes = set(last_run.get("last_fetch_hashes", []))

    events, latest_time_ms, latest_hashes = get_audit_logs(
        client=client,
        start_time_ms=start_time_ms,
        max_fetch_limit=max_fetch_limit,
        last_fetched_hashes=last_fetched_hashes,
    )
    next_run = {"last_fetch_time_ms": latest_time_ms, "last_fetch_hashes": list(latest_hashes)}
    return events, next_run


""" COMMANDS """


def test_module(client: Client) -> str:
    now = datetime.now(UTC)
    client.get_events(start_date=now - timedelta(hours=1), end_date=now, limit=1)
    return "ok"


def get_events_command(client: Client, args: dict[str, Any]) -> tuple[list[dict[str, Any]], CommandResults]:
    limit = arg_to_number(args.get("limit")) or 50
    now = datetime.now(UTC)
    start_date = arg_to_datetime(args.get("start_date") or "1 hour", arg_name="start_date", required=True)
    end_date = arg_to_datetime(args.get("end_date"), arg_name="end_date") or now
    assert start_date is not None  # required=True
    events, _, _ = get_audit_logs(
        client=client,
        start_time_ms=int(start_date.timestamp() * 1000),
        max_fetch_limit=limit,
        last_fetched_hashes=set(),
        end_date=end_date,
    )
    results = CommandResults(
        readable_output=tableToMarkdown("Keeper Security Audit Events", events, removeNull=True),
        raw_response=events,
    )
    return events, results


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions"""
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()
    demisto.debug(f"Command being called is {command}")
    try:
        api_key = (params.get("credentials") or {}).get("password") or ""
        if not api_key:
            raise DemistoException("The API key is required.")
        client = Client(
            base_url=normalize_base_url(params.get("url", "")),
            api_key=api_key,
            verify=not params.get("insecure", False),
            proxy=params.get("proxy", False),
        )

        if command == "test-module":
            return_results(test_module(client))
        elif command == "keeper-security-get-events":
            events, results = get_events_command(client, args)
            return_results(results)
            if argToBoolean(args.get("should_push_events", False)):
                send_events_to_xsiam(events, VENDOR, PRODUCT)
        elif command == "fetch-events":
            first_fetch = arg_to_datetime(params.get("first_fetch") or DEFAULT_FIRST_FETCH, required=True)
            assert first_fetch is not None  # required=True
            events, next_run = fetch_events(
                client=client,
                last_run=demisto.getLastRun(),
                max_fetch_limit=arg_to_number(params.get("alerts_max_fetch")) or DEFAULT_MAX_FETCH,
                first_fetch=first_fetch,
            )
            demisto.debug(f"Sending {len(events)} events to XSIAM")
            send_events_to_xsiam(events, VENDOR, PRODUCT)
            demisto.setLastRun(next_run)
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e!s}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
