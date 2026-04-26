# ruff: noqa: F401
import json
import traceback
from typing import Any

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from ContentClientApiModule import *
from BaseContentApiModule import *

# region Constants and helpers
# =================================
# Constants and helpers
# =================================

INTEGRATION_NAME = "SAP Enterprise Threat Detection"

ALERTS_ENDPOINT = "/sap/secmon/services/Alerts.xsjs"


class Config:
    """Global static configuration."""

    VENDOR = "SAP"
    PRODUCT = "Threat Detection"

    DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

    DEFAULT_MAX_FETCH = 10000
    MAX_PAGE_SIZE = 1000
    DEFAULT_LIMIT = 50
    DEFAULT_FIRST_FETCH = "3 days ago"

    # Test module settings
    TEST_MODULE_LOOKBACK_MINUTES = 1
    TEST_MODULE_MAX_EVENTS = 1


def parse_date_to_iso(date_input: str | None) -> str:
    """Parse a date string and return an ISO 8601 formatted timestamp.

    Uses arg_to_datetime for consistent date parsing across the platform.

    Args:
        date_input: Date string to parse (e.g., '3 days ago', '2025-09-15T17:10:00Z').

    Returns:
        ISO 8601 formatted timestamp string (e.g., '2026-01-15T15:00:00.000000Z').
    """
    demisto.debug(f"[Date Helper] Attempting to parse date string: '{date_input}'")
    try:
        parsed = arg_to_datetime(
            arg=date_input,
            required=False,
            settings={"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": True, "TO_TIMEZONE": "UTC"},
        )
    except ValueError:
        parsed = None

    if not parsed:
        demisto.debug(f"[Date Helper] Failed to parse '{date_input}'. Falling back to current UTC.")
        return datetime.now(tz=timezone.utc).strftime(Config.DATE_FORMAT)

    result = parsed.strftime(Config.DATE_FORMAT)
    demisto.debug(f"[Date Helper] Input: '{date_input}' -> Output: '{result}'")
    return result


def add_time_to_events(events: list[dict[str, Any]]) -> None:
    """Add _time field to events for XSIAM ingestion.

    Maps the event's 'AlertCreationTimestamp' field to '_time' for proper XSIAM indexing.
    Ensures the timestamp is in ISO 8601 format accepted by XSIAM.

    Args:
        events: List of alert event dicts.
    """
    for event in events:
        raw_timestamp = event.get("AlertCreationTimestamp")
        if raw_timestamp:
            parsed_time = arg_to_datetime(raw_timestamp)
            event["_time"] = parsed_time.isoformat() if parsed_time else raw_timestamp
        else:
            demisto.debug(
                f"[Event Time] WARNING: Event missing 'AlertCreationTimestamp' "
                f"(AlertId: {event.get('AlertId', 'unknown')}). Skipping _time assignment."
            )


def deduplicate_events(
    events: list[dict[str, Any]],
    last_fetched_ids: list[int],
) -> list[dict[str, Any]]:
    """Remove already-processed events based on previously fetched AlertIds.

    Args:
        events: List of alert event dicts.
        last_fetched_ids: List of AlertId values from the previous fetch cycle.

    Returns:
        List of new (non-duplicate) events.
    """
    if not events:
        demisto.debug("[Dedup] No events to process")
        return events

    if not last_fetched_ids:
        demisto.debug("[Dedup] No deduplication needed (first run - no previous IDs)")
        return events

    demisto.debug(f"[Dedup] Checking {len(events)} events against {len(last_fetched_ids)} previously fetched AlertIds")

    fetched_ids_set = set(last_fetched_ids)
    new_events = [event for event in events if event.get("AlertId") not in fetched_ids_set]
    skipped_count = len(events) - len(new_events)

    if skipped_count > 0:
        demisto.debug(f"[Dedup] Skipped {skipped_count} duplicates. {len(new_events)} new events remain.")
    else:
        demisto.debug("[Dedup] No duplicates found.")

    return new_events


# endregion

# region Config
# =================================
# Config
# =================================


def parse_integration_params(params: dict[str, Any]) -> dict[str, Any]:
    """Parse and validate integration configuration parameters.

    Args:
        params: Raw parameters dict from demisto.params().

    Returns:
        Validated configuration dict with keys: base_url, username, password, verify, proxy, max_fetch.

    Raises:
        DemistoException: If required parameters are missing.
    """
    demisto.debug("[Config] Starting parameter validation")

    base_url = (params.get("url", "")).strip().rstrip("/")
    if not base_url:
        raise DemistoException("Server URL is required. Please provide the SAP ETD server URL.")

    credentials = params.get("credentials", {})
    username = credentials.get("identifier", "").strip()
    password = credentials.get("password", "").strip()
    if not username or not password:
        raise DemistoException("Username and Password are required for Basic Auth.")

    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    max_fetch = arg_to_number(params.get("max_fetch", Config.DEFAULT_MAX_FETCH)) or Config.DEFAULT_MAX_FETCH

    demisto.debug(f"[Config] Base URL: {base_url} | Verify: {verify_certificate} | Proxy: {proxy} | Max Fetch: {max_fetch}")

    return {
        "base_url": base_url,
        "username": username,
        "password": password,
        "verify": verify_certificate,
        "proxy": proxy,
        "max_fetch": max_fetch,
    }


# endregion

# region Client
# =================================
# Client
# =================================


class SAPETDClient(ContentClient):
    """SAP Enterprise Threat Detection API client.

    Extends ContentClient for built-in retry logic, rate limit handling,
    authentication, and thread safety.
    """

    def __init__(self, config: dict[str, Any]):
        """Initialize SAP ETD client with ContentClient capabilities.

        Args:
            config: Validated configuration dict from parse_integration_params.
        """
        auth_handler = BasicAuthHandler(
            username=config["username"],
            password=config["password"],
        )
        super().__init__(
            base_url=config["base_url"],
            verify=config["verify"],
            proxy=config["proxy"],
            auth_handler=auth_handler,
            client_name="SAPETDClient",
        )
        demisto.debug("[API] SAPETDClient initialized")

    def send_events(self, events: list[dict[str, Any]]) -> None:
        """Send events to XSIAM using the ContentClient context.

        Wraps send_events_to_xsiam to keep event sending encapsulated
        within the client class for consistent logging and diagnostics.

        Args:
            events: List of event dicts to send.
        """
        demisto.debug(f"[API] Sending {len(events)} events to XSIAM")
        send_events_to_xsiam(events=events, vendor=Config.VENDOR, product=Config.PRODUCT)
        demisto.debug(f"[API] Successfully sent {len(events)} events to XSIAM")

    def get_alerts(
        self,
        from_timestamp: str,
        batch_size: int = Config.DEFAULT_MAX_FETCH,
    ) -> list[dict]:
        """Fetch alerts from the SAP ETD Alerts API.

        Args:
            from_timestamp: ISO 8601 timestamp to filter alerts from.
            batch_size: Maximum number of alerts to retrieve.

        Returns:
            List of alert dictionaries.
        """
        demisto.debug(f"[HTTP Call] GET {ALERTS_ENDPOINT} | from: {from_timestamp} | batch_size: {batch_size}")

        params = {
            "$query": f"AlertCreationTimestamp ge {from_timestamp}",
            "$format": "JSON",
            "$batchSize": str(batch_size),
            "$includeEvents": "true",
        }

        response = self.get(
            url_suffix=ALERTS_ENDPOINT,
            params=params,
        )

        # The API returns a JSON array of alert objects
        if isinstance(response, list):
            demisto.debug(f"[API] Retrieved {len(response)} alerts")
            return response

        # Handle unexpected response format
        demisto.debug(f"[API] Unexpected response type: {type(response)}. Returning empty list.")
        return []


# endregion

# region Command implementations
# =================================
# Command implementations
# =================================


def fetch_alerts_with_pagination(
    client: SAPETDClient,
    from_timestamp: str,
    max_alerts: int = Config.DEFAULT_MAX_FETCH,
) -> list[dict[str, Any]]:
    """Fetch alerts from SAP ETD with pagination support.

    Paginates in batches of Config.MAX_PAGE_SIZE, accumulating results until
    the desired max_alerts count is reached or no more data is available.

    Args:
        client: SAP ETD API client instance.
        from_timestamp: ISO 8601 timestamp to filter alerts from.
        max_alerts: Maximum number of alerts to return.

    Returns:
        List of alert dicts sorted by AlertCreationTimestamp ascending, limited to max_alerts.
    """
    events: list[dict[str, Any]] = []
    page_count = 0

    demisto.debug(f"[Pagination Loop] Start. Goal: {max_alerts}. From: {from_timestamp}")

    while len(events) < max_alerts:
        page_count += 1
        remaining_needed = max_alerts - len(events)
        batch_size = min(Config.MAX_PAGE_SIZE, remaining_needed)

        batch = client.get_alerts(from_timestamp=from_timestamp, batch_size=batch_size)

        if not batch:
            demisto.debug(f"[Pagination Loop] Page {page_count}: Empty. Stopping.")
            break

        events.extend(batch)
        demisto.debug(f"[Pagination Loop] Page {page_count}: +{len(batch)} alerts. Total accumulated: {len(events)}")

        if len(batch) < batch_size:
            demisto.debug("[Pagination Loop] No more alerts available. Stopping.")
            break

        if len(events) >= max_alerts:
            demisto.debug(f"[Pagination Loop] Threshold reached ({len(events)} >= {max_alerts}). Stopping.")
            break

        # Update from_timestamp to the last alert's timestamp for the next batch
        last_alert_timestamp = batch[-1].get("AlertCreationTimestamp")
        if last_alert_timestamp:
            from_timestamp = last_alert_timestamp
        else:
            demisto.debug(f"[Pagination Loop] Page {page_count}: Last alert missing timestamp. Stopping.")
            break

    if not events:
        demisto.debug("[Pagination Result] No alerts found.")
        return []

    # Sort by AlertCreationTimestamp ascending
    events.sort(key=lambda e: e.get("AlertCreationTimestamp", ""))

    # Slice to limit
    if len(events) > max_alerts:
        events = events[:max_alerts]

    demisto.debug(f"[Pagination Result] Returning {len(events)} alerts (sorted by AlertCreationTimestamp asc)")
    return events


def test_module(client: SAPETDClient) -> str:
    """Test API connectivity by fetching 1 alert.

    Args:
        client: SAP ETD API client instance.

    Returns:
        'ok' if successful, error message otherwise.
    """
    demisto.debug("[Test Module] Starting connectivity test...")
    try:
        from_timestamp = parse_date_to_iso(f"{Config.TEST_MODULE_LOOKBACK_MINUTES} minute ago")
        fetch_alerts_with_pagination(client, from_timestamp=from_timestamp, max_alerts=Config.TEST_MODULE_MAX_EVENTS)
        demisto.debug("[Test Module] Success - API connection verified")
        return "ok"

    except Exception as error:
        error_msg = str(error)
        demisto.debug(f"[Test Module] Failed: {error_msg}")
        if "401" in error_msg or "unauthorized" in error_msg.lower():
            return "Authorization Error: Verify username and password are correct."
        if "403" in error_msg or "forbidden" in error_msg.lower():
            return "Authorization Error: User lacks required application privileges."
        raise


def get_events_command(client: SAPETDClient, args: dict[str, Any]) -> CommandResults | str:
    """Manual command to get alerts from SAP ETD.

    Args:
        client: SAP ETD API client instance.
        args: Command arguments dict.

    Returns:
        CommandResults with alert data, or a string message if events were pushed.
    """
    demisto.debug("[Command] sap-etd-get-events triggered")

    from_date_input = args.get("from_date", Config.DEFAULT_FIRST_FETCH)
    limit = arg_to_number(args.get("limit", Config.DEFAULT_LIMIT)) or Config.DEFAULT_LIMIT
    should_push_events = argToBoolean(args.get("should_push_events", False))

    from_timestamp = parse_date_to_iso(from_date_input)

    demisto.debug(f"[Command] Params - From: {from_timestamp}, Limit: {limit}, Push: {should_push_events}")

    events = fetch_alerts_with_pagination(client, from_timestamp=from_timestamp, max_alerts=limit)

    demisto.debug(f"[Command] Retrieved {len(events)} events")

    if should_push_events and events:
        add_time_to_events(events)
        client.send_events(events)
        return f"Successfully retrieved and pushed {len(events)} events to XSIAM."

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Alerts",
        events,
        headers=["AlertId", "AlertSeverity", "AlertStatus", "Category", "PatternName", "AlertCreationTimestamp", "Text", "Score"],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="SAPETD.Alert",
        outputs_key_field="AlertId",
        outputs=events,
    )


def fetch_events_command(client: SAPETDClient, max_fetch: int) -> None:
    """Scheduled command to fetch events using high-water mark pattern.

    Args:
        client: SAP ETD API client instance.
        max_fetch: Maximum number of alerts to fetch per cycle.
    """
    demisto.debug(f"[Fetch] Starting fetch-events cycle. Max fetch: {max_fetch}")

    last_run = demisto.getLastRun()
    last_fetch_timestamp = last_run.get("last_fetch")
    raw_ids = last_run.get("last_fetched_alert_ids")
    last_fetched_alert_ids: list[int] = raw_ids if isinstance(raw_ids, list) else []

    if last_fetch_timestamp:
        from_timestamp = last_fetch_timestamp
        demisto.debug(
            f"[Fetch] Continuing from Last Run. Fetching from: {from_timestamp}. "
            f"Prev AlertId count: {len(last_fetched_alert_ids)}"
        )
    else:
        from_timestamp = parse_date_to_iso(Config.DEFAULT_FIRST_FETCH)
        demisto.debug(f"[Fetch] First Run - starting from: {from_timestamp}")

    # Fetch alerts (sorted and limited by shared function)
    events = fetch_alerts_with_pagination(client, from_timestamp=from_timestamp, max_alerts=max_fetch)

    if not events:
        demisto.debug("[Fetch] No events found.")
        return

    # Deduplicate
    new_events = deduplicate_events(events, last_fetched_alert_ids)

    if not new_events:
        demisto.debug("[Fetch] All events were duplicates.")
    else:
        add_time_to_events(new_events)
        client.send_events(new_events)

    # Update Last Run - always update based on ALL fetched events (not just new_events)
    # This ensures we advance the high-water mark even if some/all events were duplicates
    last_event = events[-1]
    new_last_fetch = last_event.get("AlertCreationTimestamp")

    if new_last_fetch:
        # Collect AlertIds at the high-water mark timestamp for deduplication
        ids_at_hwm = [
            event.get("AlertId")
            for event in events
            if event.get("AlertCreationTimestamp") == new_last_fetch and event.get("AlertId") is not None
        ]

        demisto.setLastRun(
            {
                "last_fetch": new_last_fetch,
                "last_fetched_alert_ids": ids_at_hwm,
            }
        )
        demisto.debug(f"[Fetch] State updated. New HWM: {new_last_fetch}, AlertIds at HWM: {len(ids_at_hwm)}")
    else:
        demisto.debug("[Fetch] Warning: Last event missing AlertCreationTimestamp. State not updated.")


# endregion

# region Main router
# =================================
# Main router
# =================================


def main() -> None:
    """Main entry point for SAP Enterprise Threat Detection integration."""
    demisto.debug(f"[Main] {INTEGRATION_NAME} integration started")
    command = demisto.command()
    demisto.debug(f"[Main] Executing command: {command}")

    client: SAPETDClient | None = None

    try:
        params = demisto.params()
        config = parse_integration_params(params)

        client = SAPETDClient(config)

        if command == "test-module":
            return_results(test_module(client))

        elif command == "fetch-events":
            fetch_events_command(client, max_fetch=config["max_fetch"])

        elif command == "sap-etd-get-events":
            return_results(get_events_command(client, demisto.args()))

        else:
            raise DemistoException(f"Command '{command}' is not implemented.")

    except Exception as error:
        error_msg = f"Failed to execute {command}. Error: {str(error)}"
        demisto.error(f"{error_msg}\n{traceback.format_exc()}")
        return_error(error_msg)

    finally:
        if client:
            try:
                report = client.get_diagnostic_report()
                demisto.debug(f"[Main] Diagnostic Report: {json.dumps(report.__dict__, default=str, indent=2)}")
            except Exception as e:
                demisto.debug(f"[Main] Failed to generate diagnostic report: {e}")

        demisto.debug(f"[Main] {INTEGRATION_NAME} integration finished")


# endregion

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
