import json
import math
import traceback
from datetime import datetime, timezone  # noqa: UP017
from typing import Any

import dateparser
import demistomock as demisto  # noqa: F401
import jwt
import urllib3
from ContentClientApiModule import *
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
urllib3.disable_warnings()

"""
Uptycs Event Collector
Integration for fetching Alerts via JWT authentication from the Uptycs platform.
"""

# region Constants and helpers
# =================================
# Constants and helpers
# =================================
INTEGRATION_NAME = "Uptycs Event Collector"


class Config:
    """Global static configuration."""

    VENDOR = "Uptycs"
    PRODUCT = "Uptycs"

    DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"

    DEFAULT_LIMIT = 10000
    DEFAULT_FROM_TIME = "1 minute ago"
    MAX_PAGE_SIZE = 1000
    TOKEN_EXPIRY_SECONDS = 3600

    # Test module settings
    TEST_MODULE_LOOKBACK_MINUTES = 5
    TEST_MODULE_MAX_EVENTS = 1


class APIKeys:
    """API Parameter Keys."""

    FILTERS = "filters"
    SORT = "sort"
    OFFSET = "offset"
    LIMIT = "limit"


class APIValues:
    """API Endpoint paths and fixed Parameter Values."""

    ALERTS_ENDPOINT = "/public/api/customers/{customer_id}/alertsReporting"
    DEFAULT_SORT = "lastOccurredAt:asc"


def get_formatted_utc_time(date_input: str | None) -> str:
    """Helper to parse input and return the strictly formatted UTC string.

    Args:
        date_input: Date string to parse (e.g., '3 days ago', '2024-01-01')

    Returns:
        Formatted UTC time string (%Y-%m-%dT%H:%M:%S)
    """
    start_datetime = parse_date_or_use_current(date_input)
    formatted_time = start_datetime.strftime(Config.DATE_FORMAT)
    demisto.debug(f"[Date Helper] Input: '{date_input}' -> Output: '{formatted_time}' (UTC)")
    return formatted_time


def parse_date_or_use_current(date_string: str | None) -> datetime:
    """Parse a date string or return current UTC datetime if no input is provided.

    Ensures the result is always a timezone-aware UTC datetime object.

    Args:
        date_string: Date string to parse (e.g., '3 days ago', '2024-01-01'), or None/empty for current UTC time.

    Returns:
        Timezone-aware UTC datetime object.

    Raises:
        DemistoException: If the provided date string cannot be parsed.
    """
    if not date_string:
        current_time = datetime.now(timezone.utc)  # noqa: UP017
        demisto.debug(f"[Date Helper] No input provided. Using current UTC: {current_time}")
        return current_time

    demisto.debug(f"[Date Helper] Attempting to parse date string: '{date_string}'")
    parsed_datetime = dateparser.parse(
        date_string, settings={"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": True, "TO_TIMEZONE": "UTC"}
    )

    if not parsed_datetime:
        raise DemistoException(f"Failed to parse date string: '{date_string}'")

    if parsed_datetime.tzinfo != timezone.utc:  # noqa: UP017
        parsed_datetime = parsed_datetime.astimezone(timezone.utc)  # noqa: UP017

    demisto.debug(f"[Date Helper] Final parsed date: {parsed_datetime.isoformat()}")
    return parsed_datetime


def generate_jwt_token(api_key: str, api_secret: str, role_id: str | None = None, security_zone_id: str | None = None) -> str:
    """Generate a JWT token for Uptycs API authentication using PyJWT.

    Creates an HS256-signed JWT with the API key as issuer and optional
    role/security zone claims. Uses the PyJWT library for token encoding.

    Args:
        api_key: The Uptycs API key (used as JWT 'iss' claim).
        api_secret: The Uptycs API secret (used as the HS256 signing key).
        role_id: Optional role ID to include in the token.
        security_zone_id: Optional security zone ID to include in the token.

    Returns:
        Signed JWT token string.
    """
    demisto.debug("[JWT] Generating new JWT token")

    now = math.floor(datetime.now(timezone.utc).timestamp())  # noqa: UP017

    payload: dict[str, Any] = {
        "iss": api_key,
        "iat": now,
        "exp": now + Config.TOKEN_EXPIRY_SECONDS,
    }

    if role_id:
        payload["roleId"] = role_id
    if security_zone_id:
        payload["securityZoneId"] = security_zone_id

    token = jwt.encode(payload, api_secret, algorithm="HS256")
    demisto.debug("[JWT] Token generated successfully")
    return token


def parse_integration_params(params: dict[str, Any]) -> dict[str, Any]:
    """Parse and validate integration configuration parameters.

    Args:
        params: Raw parameters from demisto.params().

    Returns:
        Validated configuration dictionary.

    Raises:
        DemistoException: If required parameters are missing.
    """
    demisto.debug("[Config] Starting parameter validation")

    base_url = (params.get("url", "")).strip().rstrip("/")
    if not base_url:
        raise DemistoException("Server URL is required.")
    base_url += "/"

    api_key = params.get("api_key", "").strip() or None
    if not api_key:
        raise DemistoException("API Key is required.")

    credentials = params.get("credentials", {})
    api_secret = credentials.get("password", "").strip() or None
    if not api_secret:
        raise DemistoException("API Secret is required.")

    customer_id = params.get("customer_id", "").strip() or None
    if not customer_id:
        raise DemistoException("Customer ID is required.")

    role_id = params.get("role_id", "").strip() or None
    security_zone_id = params.get("security_zone_id", "").strip() or None

    proxy = argToBoolean(params.get("proxy", False))
    verify_certificate = not argToBoolean(params.get("insecure", False))

    demisto.debug(f"[Config] URL: {base_url} | Customer ID: {customer_id}")

    return {
        "base_url": base_url,
        "api_key": api_key,
        "api_secret": api_secret,
        "customer_id": customer_id,
        "role_id": role_id,
        "security_zone_id": security_zone_id,
        "verify": verify_certificate,
        "proxy": proxy,
    }


def determine_entry_status(created_at: str, updated_at: str) -> str:
    """Determine the entry status based on createdAt and updatedAt timestamps.

    Args:
        created_at: The event creation timestamp.
        updated_at: The event last-update timestamp.

    Returns:
        'new' if createdAt == updatedAt, 'updated' if updatedAt > createdAt.
    """
    if updated_at > created_at:
        return "updated"
    return "new"


def enrich_events_for_xsiam(events: list[dict[str, Any]]) -> None:
    """Enrich events with _time and _entry_status fields for XSIAM ingestion.

    Sets '_time' from 'createdAt' (falls back to 'updatedAt' if missing).
    Sets '_entry_status' to 'new' or 'updated' based on createdAt vs updatedAt.

    Args:
        events: List of event dictionaries to enrich in-place.
    """
    for event in events:
        event_id = event.get("id", "unknown")
        created_at = event.get("createdAt", "")
        updated_at = event.get("updatedAt", "")

        if created_at:
            event["_time"] = created_at
        elif updated_at:
            event["_time"] = updated_at
            demisto.debug(f"[Event Enrichment] Event {event_id}: 'createdAt' missing, using 'updatedAt' for _time")
        else:
            demisto.debug(f"[Event Enrichment] WARNING: Event {event_id} missing both 'createdAt' and 'updatedAt'")

        if created_at and updated_at:
            event["_entry_status"] = determine_entry_status(created_at, updated_at)
        else:
            demisto.debug(
                f"[Event Enrichment] WARNING: Event {event_id} missing 'createdAt' or 'updatedAt',"
                " cannot determine _entry_status"
            )


def deduplicate_events(events: list[dict[str, Any]], last_fetched_ids: list[str]) -> list[dict[str, Any]]:
    """Remove already-processed events based on previously fetched alert IDs.

    Args:
        events: List of event dictionaries.
        last_fetched_ids: List of alert IDs from the previous fetch cycle.

    Returns:
        Filtered list containing only new events.
    """
    if not events:
        demisto.debug("[Dedup] No events to process")
        return events

    if not last_fetched_ids:
        demisto.debug("[Dedup] No deduplication needed (first run - no previous IDs)")
        return events

    demisto.debug(f"[Dedup] Checking {len(events)} events against {len(last_fetched_ids)} previously fetched IDs")

    fetched_ids_set = set(last_fetched_ids)
    new_events = [event for event in events if event.get("id") not in fetched_ids_set]

    skipped_count = len(events) - len(new_events)
    if skipped_count > 0:
        demisto.debug(f"[Dedup] Skipped {skipped_count} duplicates. {len(new_events)} new events remain.")
    else:
        demisto.debug("[Dedup] No duplicates found.")

    return new_events


# endregion

# region Client
# =================================
# Client
# =================================


class Client(ContentClient):
    """Uptycs API client for fetching alerts.

    Extends ContentClient for built-in retry logic, rate-limit handling,
    structured logging, and authentication via BearerTokenAuthHandler.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        api_secret: str,
        customer_id: str,
        verify: bool,
        proxy: bool,
        role_id: str | None = None,
        security_zone_id: str | None = None,
    ):
        token = generate_jwt_token(
            api_key=api_key,
            api_secret=api_secret,
            role_id=role_id,
            security_zone_id=security_zone_id,
        )
        auth_handler = BearerTokenAuthHandler(token=token)
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            auth_handler=auth_handler,
            client_name="UptycsEventCollector",
            ok_codes=(200, 201, 202, 204),
        )
        self.customer_id = customer_id

    def get_alerts(
        self,
        created_after: str,
        created_before: str,
        offset: int = 0,
        limit: int = Config.MAX_PAGE_SIZE,
    ) -> list[dict[str, Any]]:
        """Retrieve a page of alerts from Uptycs alertsReporting endpoint.

        Args:
            created_after: Start time string (UTC, format: %Y-%m-%dT%H:%M:%S).
            created_before: End time string (UTC, format: %Y-%m-%dT%H:%M:%S).
            offset: Pagination offset (0-based).
            limit: Number of results per page.

        Returns:
            List of alert event dictionaries.
        """
        url_suffix = APIValues.ALERTS_ENDPOINT.format(customer_id=self.customer_id)

        # Build time filter
        filters = json.dumps({"lastOccurredAt": {"between": [created_after, created_before]}})

        request_params: dict[str, Any] = {
            APIKeys.SORT: APIValues.DEFAULT_SORT,
            APIKeys.FILTERS: filters,
            APIKeys.OFFSET: offset,
            APIKeys.LIMIT: limit,
        }

        demisto.debug(
            f"[API Fetch] Fetching alerts | From: {created_after} | To: {created_before} | Offset: {offset} | Limit: {limit}"
        )

        response = self._http_request(method="GET", url_suffix=url_suffix, params=request_params)

        items = response.get("items", [])

        demisto.debug(f"[API Fetch] Page fetched. Count: {len(items)}.")

        return items


# endregion

# region Command implementations
# =================================
# Command implementations
# =================================


def test_module(client: Client) -> str:
    """Test API connectivity by fetching a small number of recent alerts.

    Args:
        client: Configured Uptycs API client.

    Returns:
        'ok' on success, or an error message string.
    """
    demisto.debug("[Test Module] Starting...")
    try:
        utc_now = datetime.now(timezone.utc)  # noqa: UP017
        test_time = (utc_now - timedelta(minutes=Config.TEST_MODULE_LOOKBACK_MINUTES)).strftime(Config.DATE_FORMAT)

        demisto.debug(f"[Test Module] Fetching from: {test_time}")
        fetch_events_with_pagination(client, created_after=test_time, max_events=Config.TEST_MODULE_MAX_EVENTS)

        demisto.debug("[Test Module] Success")
        return "ok"

    except ContentClientAuthenticationError as error:
        demisto.debug(f"[Test Module] Auth failed: {error}")
        return "Authorization Error: Verify API Key, API Secret, and Customer ID."
    except Exception as error:
        demisto.debug(f"[Test Module] Failed: {error}")
        raise


def fetch_events_with_pagination(
    client: Client,
    created_after: str,
    created_before: str | None = None,
    max_events: int = Config.DEFAULT_LIMIT,
) -> list[dict[str, Any]]:
    """Fetch events with offset/limit pagination support.

    Fetches pages until the limit is reached or no more results exist.
    If created_before is not provided, the current UTC time is used and pinned for all pages.

    Args:
        client: Configured Uptycs API client.
        created_after: Start time (UTC formatted string).
        created_before: End time (UTC formatted string) or None for current time.
        max_events: Maximum total events to retrieve.

    Returns:
        List of alert event dictionaries, sorted by lastOccurredAt ascending (oldest first) as returned by the API.
    """
    if not created_before:
        created_before = datetime.now(timezone.utc).strftime(Config.DATE_FORMAT)  # noqa: UP017

    events: list[dict[str, Any]] = []
    offset = 0
    page_size = min(Config.MAX_PAGE_SIZE, max_events)

    demisto.debug(f"[Pagination Loop] Start. Goal: {max_events}. Time: {created_after} -> {created_before}")

    while len(events) < max_events:
        page_events = client.get_alerts(
            created_after=created_after,
            created_before=created_before,
            offset=offset,
            limit=page_size,
        )

        if not page_events:
            demisto.debug(f"[Pagination Loop] Offset {offset}: Empty page. Stopping.")
            break

        events.extend(page_events)
        demisto.debug(f"[Pagination Loop] Offset {offset}: +{len(page_events)} events. Total: {len(events)}")

        # If we got fewer results than the page size, there are no more pages
        if len(page_events) < page_size:
            demisto.debug("[Pagination Loop] Last page reached (partial page). Stopping.")
            break

        offset += page_size

    if len(events) >= max_events:
        demisto.debug(f"[Pagination Loop] Threshold reached ({len(events)} >= {max_events}).")

    if not events:
        demisto.debug("[Pagination Result] No events found.")
        return []

    # Slice to limit
    if len(events) > max_events:
        demisto.debug(f"[Pagination Loop] Slicing {len(events)} events to limit {max_events}")
        events = events[:max_events]

    return events


def get_events_command(client: Client, args: dict[str, Any]) -> CommandResults | str:
    """Manual command to get events (for debugging/development).

    Args:
        client: Configured Uptycs API client.
        args: Command arguments from demisto.args().

    Returns:
        CommandResults with events data, or a string message if events were pushed.
    """
    demisto.debug("[Command] uptycs-get-events triggered")

    start_time_input = args.get("start_time", Config.DEFAULT_FROM_TIME)
    end_time_input = args.get("end_time")
    limit = int(args.get("limit", Config.DEFAULT_LIMIT))
    should_push_events = argToBoolean(args.get("should_push_events", False))

    created_after = get_formatted_utc_time(start_time_input)
    created_before = get_formatted_utc_time(end_time_input) if end_time_input else None

    demisto.debug(f"[Command Params] From: {created_after}, To: {created_before}, Limit: {limit}, Push: {should_push_events}")

    events = fetch_events_with_pagination(client, created_after, created_before, limit)

    if should_push_events and events:
        enrich_events_for_xsiam(events)
        send_events_to_xsiam(events=events, vendor=Config.VENDOR, product=Config.PRODUCT)
        demisto.debug(f"[Command] Pushed {len(events)} events to XSIAM")
        return f"Successfully retrieved and pushed {len(events)} events to XSIAM"

    readable_output = tableToMarkdown(f"{INTEGRATION_NAME} Events", events, removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Uptycs.Alert",
        outputs_key_field="id",
        outputs=events,
    )


def fetch_events_command(client: Client) -> None:
    """Scheduled command to fetch events (called by XSIAM fetch-events mechanism).

    Manages state via demisto.getLastRun()/setLastRun() for incremental fetching
    with deduplication based on id.

    Args:
        client: Configured Uptycs API client.
    """
    params = demisto.params()
    max_events_to_fetch = int(params.get("max_fetch", Config.DEFAULT_LIMIT))

    last_run = demisto.getLastRun()
    last_fetch_timestamp = last_run.get("last_fetch")
    raw_ids = last_run.get("last_fetched_ids")
    last_fetched_ids: list[str] = raw_ids if isinstance(raw_ids, list) else []

    if last_fetch_timestamp:
        time_input = last_fetch_timestamp
        demisto.debug(f"[Fetch] Continuing from Last Run. Fetching from: {time_input}. Prev ID count: {len(last_fetched_ids)}")
    else:
        time_input = Config.DEFAULT_FROM_TIME
        demisto.debug("[Fetch] First Run - starting from default time")

    created_after = get_formatted_utc_time(time_input)

    # Fetch events
    events = fetch_events_with_pagination(client, created_after, None, max_events_to_fetch)

    if not events:
        demisto.debug("[Fetch] No events found.")
        if not last_fetch_timestamp:
            demisto.debug("[Fetch] First run with no events. Saving current time to avoid re-fetching from 'now'.")
            demisto.setLastRun({"last_fetch": created_after, "last_fetched_ids": []})
        return

    # Deduplicate
    new_events = deduplicate_events(events, last_fetched_ids)

    if new_events:
        enrich_events_for_xsiam(new_events)
        send_events_to_xsiam(events=new_events, vendor=Config.VENDOR, product=Config.PRODUCT)
        demisto.debug(f"[Fetch] Pushed {len(new_events)} events to XSIAM")

        # Update Last Run state
        last_event = events[-1]
        new_last_run_time = last_event.get("lastOccurredAt")

        if new_last_run_time:
            # Collect IDs at the last_fetch timestamp for deduplication
            ids_at_last_timestamp = [
                event.get("id") for event in events if event.get("lastOccurredAt") == new_last_run_time and event.get("id")
            ]

            demisto.setLastRun({"last_fetch": new_last_run_time, "last_fetched_ids": ids_at_last_timestamp})
            demisto.debug(f"[Fetch] State updated. New last_fetch: {new_last_run_time}")
        else:
            demisto.debug("[Fetch] Warning: Last event missing lastOccurredAt. State not updated.")
    else:
        demisto.debug("[Fetch] All events were duplicates.")


# endregion

# region Main router
# =================================
# Main router
# =================================


def main() -> None:
    """Main entry point for Uptycs Event Collector integration."""
    demisto.debug(f"{INTEGRATION_NAME} integration started")
    command = demisto.command()

    try:
        config = parse_integration_params(demisto.params())

        client = Client(
            base_url=config["base_url"],
            api_key=config["api_key"],
            api_secret=config["api_secret"],
            customer_id=config["customer_id"],
            verify=config["verify"],
            proxy=config["proxy"],
            role_id=config["role_id"],
            security_zone_id=config["security_zone_id"],
        )

        if command == "test-module":
            test_result = test_module(client)
            return_results(test_result)
        elif command == "fetch-events":
            fetch_events_command(client)
        elif command == "uptycs-get-events":
            command_result = get_events_command(client, demisto.args())
            return_results(command_result)
        else:
            raise DemistoException(f"Command '{command}' is not implemented")

    except Exception as error:
        error_msg = f"Failed to execute {command}. Error: {str(error)}"
        demisto.error(f"{error_msg}\n{traceback.format_exc()}")
        return_error(error_msg)

    demisto.debug(f"{INTEGRATION_NAME} integration finished")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
