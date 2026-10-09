# ruff: noqa: F401
import re
import traceback
from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import demistomock as demisto
from CommonServerPython import *

from ContentClientApiModule import *

# region Constants and helpers
# =================================
# Constants and helpers
# =================================

INTEGRATION_NAME = "SAP Enterprise Threat Detection"


class Edition:
    """Supported SAP ETD editions (values of the 'edition' integration parameter)."""

    ON_PREM = "On-Premise"
    CLOUD = "Cloud Edition"
    ALL = (ON_PREM, CLOUD)


class Config:
    """Global static configuration shared by both editions."""

    VENDOR = "SAP"
    PRODUCT = "Threat Detection"
    CLIENT_NAME = "SAPETDClient"

    # Unique alert identifier in both editions: used to deduplicate alerts that share the cursor timestamp.
    ALERT_ID_FIELD = "AlertId"
    # Field read by XSIAM as the event time.
    XSIAM_TIME_FIELD = "_time"

    # Seconds format; milliseconds are appended separately (see format_timestamp).
    DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"
    # Matches fractional seconds longer than milliseconds (Cloud Edition returns 7 digits).
    SUB_MILLISECOND_PATTERN = re.compile(r"(\.\d{3})\d+")

    # Path appended to the Cloud Edition token URL (the 'uaa.url' of the service binding) when missing.
    TOKEN_PATH = "/oauth/token"

    DEFAULT_MAX_FETCH = 10000
    MAX_PAGE_SIZE = 1000
    DEFAULT_LIMIT = 50
    DEFAULT_FIRST_FETCH = "5 minutes ago"

    # Last run keys: the high-water mark timestamp and the AlertIds already sent at that timestamp.
    LAST_RUN_TIMESTAMP_KEY = "last_fetch"
    LAST_RUN_IDS_KEY = "last_fetched_alert_ids"

    # Command outputs
    OUTPUTS_PREFIX = "SAPETD.Alert"
    TABLE_TITLE = f"{INTEGRATION_NAME} Alerts"

    # Test module settings
    TEST_MODULE_LOOKBACK = "1 minute ago"
    TEST_MODULE_MAX_EVENTS = 1


class Messages:
    """User-facing messages shared by both editions."""

    INVALID_EDITION = "Invalid edition '{edition}'. Choose one of: {options}."
    MISSING_URL = "Server URL is required. Please provide the SAP ETD server URL."
    MISSING_CREDENTIALS = "Both the Username / Client ID and the Password / Client Secret are required."
    MISSING_TOKEN_URL = "Token URL is required for SAP ETD Cloud Edition (the 'uaa.url' value of the service binding)."
    NON_JSON_RESPONSE = "Connection Error: The server did not return JSON. Verify the Server URL points to the SAP ETD server."
    TOKEN_ERROR = "Authorization Error: Failed to get an access token. Verify the Token URL, Client ID, and Client Secret."
    PUSHED_EVENTS = "Successfully retrieved and pushed {count} events to XSIAM."
    UNKNOWN_COMMAND = "Command '{command}' is not implemented."
    COMMAND_FAILED = "Failed to execute {command}. Error: {error}"


class Commands:
    """Supported command names."""

    TEST_MODULE = "test-module"
    FETCH_EVENTS = "fetch-events"
    GET_EVENTS = "sap-etd-get-events"


class OnPremAlertsApi:
    """SAP ETD on-premise Alert Pull API: GET Alerts.xsjs with Basic auth, returns a JSON array."""

    EDITION = Edition.ON_PREM
    ENDPOINT = "/sap/secmon/services/Alerts.xsjs"
    # Alert creation time: used in the query filter, as the fetch cursor, for sorting, and as the source of _time.
    TIME_FIELD = "AlertCreationTimestamp"
    QUERY_TEMPLATE = "{field} ge {timestamp}"
    RESPONSE_FORMAT = "JSON"
    INCLUDE_EVENTS = "true"
    TABLE_HEADERS = [
        Config.ALERT_ID_FIELD,
        "AlertSeverity",
        "AlertStatus",
        "Category",
        "PatternName",
        TIME_FIELD,
        "Text",
        "Score",
    ]
    UNEXPECTED_RESPONSE = (
        "Unexpected response from the SAP ETD Alerts API: expected a JSON array of alerts, "
        "received {type_name}. Verify the Server URL points to the SAP ETD server."
    )
    HTTP_ERRORS = {
        HTTPStatus.UNAUTHORIZED: "Authorization Error: Verify username and password are correct.",
        HTTPStatus.FORBIDDEN: "Authorization Error: User lacks required application privileges (e.g. sap.secmon::AlertRead).",
        HTTPStatus.NOT_FOUND: f"Connection Error: {ENDPOINT} was not found. Verify the Server URL.",
    }

    def build_request(self, from_timestamp: str, batch_size: int) -> tuple[dict[str, str], str]:
        """Build the query parameters for one page of alerts.

        Args:
            from_timestamp: ISO 8601 timestamp to fetch alerts from.
            batch_size: Maximum number of alerts to retrieve.

        Returns:
            The query parameters dict, and an empty raw query (not used by this edition).
        """
        params = {
            "$query": self.QUERY_TEMPLATE.format(field=self.TIME_FIELD, timestamp=from_timestamp),
            "$format": self.RESPONSE_FORMAT,
            "$batchSize": str(batch_size),
            "$includeEvents": self.INCLUDE_EVENTS,
        }
        return params, ""

    def extract_alerts(self, response: Any) -> list[dict]:
        """Return the alerts from the response, which must be a JSON array.

        Raises:
            DemistoException: If the response is not a JSON array.
        """
        if not isinstance(response, list):
            raise DemistoException(self.UNEXPECTED_RESPONSE.format(type_name=type(response).__name__))
        return response


class CloudAlertsApi:
    """SAP ETD Cloud Edition Data Retriever API: OData V4, OAuth2 client credentials, returns {"value": [...]}."""

    EDITION = Edition.CLOUD
    ENDPOINT = "/alerts/v1/Alerts"
    # Alert creation time: used in $filter/$orderby, as the fetch cursor, for sorting, and as the source of _time.
    TIME_FIELD = "CreationTimestamp"
    # Characters left unescaped so the filter stays readable; spaces must be sent as %20 (the server rejects '+').
    FILTER_SAFE_CHARS = ":.-"
    ORDER_BY_SAFE_CHARS = ","
    FILTER_TEMPLATE = "{field} ge {timestamp}"
    ORDER_BY_TEMPLATE = "{time_field} asc,{id_field} asc"
    RESPONSE_ITEMS_KEY = "value"
    TABLE_HEADERS = [
        Config.ALERT_ID_FIELD,
        "Status",
        "PatternName",
        TIME_FIELD,
        "Score",
        "MinTimestamp",
        "MaxTimestamp",
    ]
    UNEXPECTED_RESPONSE = (
        "Unexpected response from the SAP ETD Cloud Edition Alerts API: expected an object with a 'value' list, "
        "received {type_name}. Verify the Server URL is the 'url' value of the Data Retriever service binding."
    )
    HTTP_ERRORS = {
        HTTPStatus.UNAUTHORIZED: "Authorization Error: The access token was rejected. Verify the Client ID and Client Secret.",
        HTTPStatus.FORBIDDEN: "Authorization Error: The service binding lacks the AlertsInformationRead scope.",
        HTTPStatus.NOT_FOUND: f"Connection Error: {ENDPOINT} was not found. Verify the Server URL is the service binding 'url'.",
    }

    def build_request(self, from_timestamp: str, batch_size: int) -> tuple[dict[str, str], str]:
        """Build the raw OData query string for one page of alerts.

        The query is returned pre-encoded because the HTTP client would encode spaces as '+',
        which the Cloud Edition server rejects with HTTP 400.

        Args:
            from_timestamp: ISO 8601 timestamp to fetch alerts from.
            batch_size: Maximum number of alerts to retrieve.

        Returns:
            An empty params dict, and the raw query string.
        """
        timestamp = truncate_to_milliseconds(from_timestamp)
        filter_value = quote(self.FILTER_TEMPLATE.format(field=self.TIME_FIELD, timestamp=timestamp), safe=self.FILTER_SAFE_CHARS)
        order_by = quote(
            self.ORDER_BY_TEMPLATE.format(time_field=self.TIME_FIELD, id_field=Config.ALERT_ID_FIELD),
            safe=self.ORDER_BY_SAFE_CHARS,
        )
        return {}, f"$filter={filter_value}&$orderby={order_by}&$top={batch_size}"

    def extract_alerts(self, response: Any) -> list[dict]:
        """Return the alerts from the 'value' list of the OData response.

        Raises:
            DemistoException: If the response is not an object with a 'value' list.
        """
        alerts = response.get(self.RESPONSE_ITEMS_KEY) if isinstance(response, dict) else None
        if not isinstance(alerts, list):
            raise DemistoException(self.UNEXPECTED_RESPONSE.format(type_name=type(response).__name__))
        return alerts


AlertsApi = OnPremAlertsApi | CloudAlertsApi
ALERTS_APIS: dict[str, type[OnPremAlertsApi] | type[CloudAlertsApi]] = {
    Edition.ON_PREM: OnPremAlertsApi,
    Edition.CLOUD: CloudAlertsApi,
}


def format_timestamp(value: datetime) -> str:
    """Format a datetime as an ISO 8601 UTC string with millisecond precision.

    Args:
        value: Timezone-aware or naive (assumed UTC) datetime.

    Returns:
        Timestamp string such as '2026-01-15T15:00:00.000Z'.
    """
    return f"{value.strftime(Config.DATE_FORMAT)}.{value.microsecond // 1000:03d}Z"


def truncate_to_milliseconds(timestamp: str) -> str:
    """Drop fractional-second digits beyond milliseconds (e.g. Cloud Edition's 7-digit precision).

    Args:
        timestamp: ISO 8601 timestamp string.

    Returns:
        The timestamp with at most 3 fractional digits.
    """
    return Config.SUB_MILLISECOND_PATTERN.sub(r"\1", timestamp)


def parse_date_to_iso(date_input: str | None) -> str:
    """Parse a date string and return an ISO 8601 formatted timestamp.

    Falls back to the current UTC time when the input is empty or cannot be parsed.

    Args:
        date_input: Date string to parse (e.g., '5 minutes ago', '2025-09-15T17:10:00Z').

    Returns:
        ISO 8601 formatted timestamp string (e.g., '2026-01-15T15:00:00.000Z').
    """
    try:
        parsed = arg_to_datetime(
            arg=date_input,
            required=False,
            settings={"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": True, "TO_TIMEZONE": "UTC"},
        )
    except ValueError:
        parsed = None

    if not parsed:
        demisto.debug(f"[Date Helper] Could not parse '{date_input}'. Falling back to current UTC.")
        return format_timestamp(datetime.now(tz=timezone.utc))

    result = format_timestamp(parsed)
    demisto.debug(f"[Date Helper] '{date_input}' -> '{result}'")
    return result


def build_token_url(raw_token_url: str) -> str:
    """Return the OAuth2 token endpoint, appending the token path when only the base URL is given.

    Args:
        raw_token_url: The 'uaa.url' value of the service binding, with or without the token path.

    Returns:
        The full token endpoint URL.
    """
    token_url = raw_token_url.strip().rstrip("/")
    return token_url if token_url.endswith(Config.TOKEN_PATH) else f"{token_url}{Config.TOKEN_PATH}"


def add_time_to_events(events: list[dict[str, Any]], time_field: str) -> None:
    """Set the XSIAM time field on each event from its creation timestamp.

    Args:
        events: Alert dicts, updated in place.
        time_field: Name of the creation time field for the configured edition.
    """
    for event in events:
        raw_timestamp = event.get(time_field)
        if not raw_timestamp:
            demisto.debug(
                f"[Event Time] Alert {event.get(Config.ALERT_ID_FIELD, 'unknown')} has no {time_field}. "
                f"Skipping {Config.XSIAM_TIME_FIELD}."
            )
            continue
        parsed_time = arg_to_datetime(truncate_to_milliseconds(raw_timestamp))
        event[Config.XSIAM_TIME_FIELD] = parsed_time.isoformat() if parsed_time else raw_timestamp


def deduplicate_events(events: list[dict[str, Any]], last_fetched_ids: list[int]) -> list[dict[str, Any]]:
    """Remove alerts already sent in the previous fetch cycle.

    Args:
        events: Alert dicts from the current cycle.
        last_fetched_ids: AlertIds sent at the previous high-water mark timestamp.

    Returns:
        Alerts whose AlertId was not sent before.
    """
    if not events or not last_fetched_ids:
        return events

    fetched_ids = set(last_fetched_ids)
    new_events = [event for event in events if event.get(Config.ALERT_ID_FIELD) not in fetched_ids]
    demisto.debug(f"[Dedup] {len(events) - len(new_events)} duplicates skipped, {len(new_events)} new alerts.")
    return new_events


def filter_new_alerts(batch: list[dict[str, Any]], seen_ids: set[Any]) -> list[dict[str, Any]]:
    """Return only the alerts from a page that have not been collected yet in this fetch cycle.

    The 'ge' filter makes the next page start from the last alert's timestamp,
    so alerts on the page boundary are returned again. This drops those already-collected alerts.

    Args:
        batch: Alerts returned for the current page.
        seen_ids: AlertIds already collected in this cycle. Updated in place with new ids.

    Returns:
        The subset of batch whose AlertId was not seen before.
    """
    new_alerts = [alert for alert in batch if alert.get(Config.ALERT_ID_FIELD) not in seen_ids]
    seen_ids.update(alert_id for alert in new_alerts if (alert_id := alert.get(Config.ALERT_ID_FIELD)) is not None)
    return new_alerts


def build_next_last_run(events: list[dict[str, Any]], time_field: str) -> dict[str, Any] | None:
    """Build the next last run from the alerts of the current cycle.

    Uses all fetched alerts (not only the new ones) so the high-water mark always advances.

    Args:
        events: Alerts of the current cycle, sorted by creation time.
        time_field: Name of the creation time field for the configured edition.

    Returns:
        The last run dict, or None when the last alert has no creation timestamp.
    """
    high_water_mark = events[-1].get(time_field)
    if not high_water_mark:
        return None

    ids_at_high_water_mark = [
        event[Config.ALERT_ID_FIELD]
        for event in events
        if event.get(time_field) == high_water_mark and event.get(Config.ALERT_ID_FIELD) is not None
    ]
    return {Config.LAST_RUN_TIMESTAMP_KEY: high_water_mark, Config.LAST_RUN_IDS_KEY: ids_at_high_water_mark}


def get_error_status_code(error: Exception) -> int | None:
    """Return the HTTP status code attached to a client error, if any.

    Args:
        error: Exception raised by the HTTP client.

    Returns:
        The HTTP status code, or None when the error has no HTTP response.
    """
    status_code = getattr(getattr(error, "response", None), "status_code", None)
    return status_code if isinstance(status_code, int) else None


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
        Validated configuration dict with keys: edition, base_url, username, password, token_url,
        verify, proxy, max_fetch. For Cloud Edition, username and password hold the client ID and secret.

    Raises:
        DemistoException: If required parameters are missing or invalid.
    """
    edition = params.get("edition") or Edition.ON_PREM
    if edition not in Edition.ALL:
        raise DemistoException(Messages.INVALID_EDITION.format(edition=edition, options=", ".join(Edition.ALL)))

    base_url = params.get("url", "").strip().rstrip("/")
    if not base_url:
        raise DemistoException(Messages.MISSING_URL)

    credentials = params.get("credentials", {})
    username = credentials.get("identifier", "").strip()
    password = credentials.get("password", "").strip()
    if not username or not password:
        raise DemistoException(Messages.MISSING_CREDENTIALS)

    token_url = ""
    if edition == Edition.CLOUD:
        raw_token_url = params.get("token_url", "").strip()
        if not raw_token_url:
            raise DemistoException(Messages.MISSING_TOKEN_URL)
        token_url = build_token_url(raw_token_url)

    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))
    max_fetch = arg_to_number(params.get("max_fetch", Config.DEFAULT_MAX_FETCH)) or Config.DEFAULT_MAX_FETCH

    # Credentials are intentionally not logged.
    demisto.debug(
        f"[Config] Edition: {edition} | URL: {base_url} | Token URL: {token_url or 'n/a'} | "
        f"Verify: {verify_certificate} | Proxy: {proxy} | Max fetch: {max_fetch}"
    )

    return {
        "edition": edition,
        "base_url": base_url,
        "username": username,
        "password": password,
        "token_url": token_url,
        "verify": verify_certificate,
        "proxy": proxy,
        "max_fetch": max_fetch,
    }


# endregion

# region Client
# =================================
# Client
# =================================


class CloudOAuth2Handler(OAuth2ClientCredentialsHandler):
    """OAuth2 client credentials handler that also sets a pre-encoded query string on each request.

    ContentClient encodes query parameters with '+' for spaces, which the Cloud Edition OData
    server rejects with HTTP 400. The client sets raw_query before each call, and this handler
    writes it onto the request after the HTTP client has built it.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.raw_query = ""

    async def on_request(self, client: "ContentClient", request: httpx.Request) -> None:
        await super().on_request(client, request)
        if self.raw_query:
            request.url = request.url.copy_with(query=self.raw_query.encode("ascii"))


class SAPETDClient(ContentClient):
    """SAP Enterprise Threat Detection API client for the on-premise and Cloud editions.

    Extends ContentClient for built-in retry logic, rate limit handling,
    authentication, and thread safety.
    """

    def __init__(self, config: dict[str, Any]):
        """Initialize the client with the authentication of the configured edition.

        Args:
            config: Validated configuration dict from parse_integration_params.
        """
        self.api: AlertsApi = ALERTS_APIS[config["edition"]]()
        self._cloud_auth: CloudOAuth2Handler | None = None
        auth_handler: AuthHandler

        if config["edition"] == Edition.CLOUD:
            self._cloud_auth = CloudOAuth2Handler(
                token_url=config["token_url"],
                client_id=config["username"],
                client_secret=config["password"],
                context_store=ContentClientContextStore(namespace=Config.CLIENT_NAME),
            )
            auth_handler = self._cloud_auth
        else:
            auth_handler = BasicAuthHandler(username=config["username"], password=config["password"])

        super().__init__(
            base_url=config["base_url"],
            verify=config["verify"],
            proxy=config["proxy"],
            auth_handler=auth_handler,
            client_name=Config.CLIENT_NAME,
        )

    def send_events(self, events: list[dict[str, Any]]) -> None:
        """Send events to XSIAM.

        Args:
            events: List of event dicts to send.
        """
        demisto.debug(f"[XSIAM] Sending {len(events)} events")
        send_events_to_xsiam(events=events, vendor=Config.VENDOR, product=Config.PRODUCT)
        demisto.debug(f"[XSIAM] Sent {len(events)} events")

    def get_alerts(self, from_timestamp: str, batch_size: int = Config.MAX_PAGE_SIZE) -> list[dict]:
        """Fetch one page of alerts created at or after from_timestamp.

        Args:
            from_timestamp: ISO 8601 timestamp to filter alerts from.
            batch_size: Maximum number of alerts to retrieve.

        Returns:
            List of alert dictionaries.

        Raises:
            DemistoException: If the API response does not have the expected shape.
        """
        params, raw_query = self.api.build_request(from_timestamp, batch_size)
        demisto.debug(f"[API] GET {self.api.ENDPOINT} ({self.api.EDITION}) | from: {from_timestamp} | batch size: {batch_size}")

        self._set_raw_query(raw_query)
        try:
            # ContentClient.get() returns the raw response object unless resp_type="json" is passed.
            response = self.get(url_suffix=self.api.ENDPOINT, params=params, resp_type="json")
        finally:
            self._set_raw_query("")

        alerts = self.api.extract_alerts(response)
        demisto.debug(f"[API] Retrieved {len(alerts)} alerts")
        return alerts

    def _set_raw_query(self, raw_query: str) -> None:
        """Set the pre-encoded query string used by the Cloud Edition auth handler, if any."""
        if self._cloud_auth:
            self._cloud_auth.raw_query = raw_query


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
    """Fetch alerts page by page, moving a timestamp cursor forward, up to max_alerts.

    Args:
        client: SAP ETD API client instance.
        from_timestamp: ISO 8601 timestamp to fetch alerts from.
        max_alerts: Maximum number of alerts to return.

    Returns:
        Alerts sorted by creation time ascending, limited to max_alerts.
    """
    time_field = client.api.TIME_FIELD
    events: list[dict[str, Any]] = []
    seen_ids: set[Any] = set()
    previous_cursor: str | None = None
    page = 0
    demisto.debug(f"[Pagination] Start from {from_timestamp}, max {max_alerts} alerts")

    while len(events) < max_alerts:
        page += 1
        batch_size = min(Config.MAX_PAGE_SIZE, max_alerts - len(events))
        batch = client.get_alerts(from_timestamp=from_timestamp, batch_size=batch_size)
        if not batch:
            demisto.debug(f"[Pagination] Page {page} is empty. Stopping.")
            break

        new_alerts = filter_new_alerts(batch, seen_ids)
        events.extend(new_alerts)
        demisto.debug(
            f"[Pagination] Page {page}: {len(new_alerts)} new, {len(batch) - len(new_alerts)} boundary duplicates. "
            f"Total: {len(events)}"
        )

        if len(batch) < batch_size:
            demisto.debug("[Pagination] Last page reached. Stopping.")
            break

        cursor = batch[-1].get(time_field)
        if not cursor:
            demisto.debug(f"[Pagination] Page {page}: last alert has no timestamp. Stopping.")
            break

        # A full page sharing one timestamp cannot move the cursor; stop instead of re-fetching the same page.
        if cursor == previous_cursor and not new_alerts:
            demisto.debug("[Pagination] Cursor did not advance. Stopping.")
            break
        previous_cursor = from_timestamp = cursor

    events.sort(key=lambda event: event.get(time_field, ""))
    demisto.debug(f"[Pagination] Done after {page} pages: {len(events)} alerts")
    # Guards against a server that ignores the page size and returns more alerts than requested.
    return events[:max_alerts]


def test_module(client: SAPETDClient) -> str:
    """Test API connectivity by fetching 1 alert.

    Errors are classified by HTTP status code, never by searching the error text, so numbers
    that happen to contain '401' or '403' are not reported as authorization errors.

    Args:
        client: SAP ETD API client instance.

    Returns:
        'ok' if successful, error message otherwise.
    """
    try:
        from_timestamp = parse_date_to_iso(Config.TEST_MODULE_LOOKBACK)
        fetch_alerts_with_pagination(client, from_timestamp=from_timestamp, max_alerts=Config.TEST_MODULE_MAX_EVENTS)
        return "ok"

    except ValueError:
        # JSONDecodeError subclasses ValueError: the server answered with something other than JSON.
        demisto.debug("[Test Module] Non-JSON response")
        return Messages.NON_JSON_RESPONSE

    except Exception as error:
        status_code = get_error_status_code(error)
        # Only the status and error type are logged; the response body may contain server data.
        demisto.debug(f"[Test Module] Failed with status {status_code} ({type(error).__name__})")
        if status_code in client.api.HTTP_ERRORS:
            return client.api.HTTP_ERRORS[HTTPStatus(status_code)]
        if status_code is None and isinstance(error, ContentClientAuthenticationError):
            # Raised without a response when the OAuth2 token request fails.
            return Messages.TOKEN_ERROR
        raise


def get_events_command(client: SAPETDClient, args: dict[str, Any]) -> CommandResults | str:
    """Manual command to get alerts from SAP ETD.

    Args:
        client: SAP ETD API client instance.
        args: Command arguments dict.

    Returns:
        CommandResults with alert data, or a string message if events were pushed.
    """
    from_timestamp = parse_date_to_iso(args.get("from_date", Config.DEFAULT_FIRST_FETCH))
    limit = arg_to_number(args.get("limit", Config.DEFAULT_LIMIT)) or Config.DEFAULT_LIMIT
    should_push_events = argToBoolean(args.get("should_push_events", False))
    demisto.debug(f"[Get Events] From: {from_timestamp} | Limit: {limit} | Push: {should_push_events}")

    events = fetch_alerts_with_pagination(client, from_timestamp=from_timestamp, max_alerts=limit)

    if should_push_events and events:
        add_time_to_events(events, client.api.TIME_FIELD)
        client.send_events(events)
        return Messages.PUSHED_EVENTS.format(count=len(events))

    return CommandResults(
        readable_output=tableToMarkdown(Config.TABLE_TITLE, events, headers=client.api.TABLE_HEADERS, removeNull=True),
        outputs_prefix=Config.OUTPUTS_PREFIX,
        outputs_key_field=Config.ALERT_ID_FIELD,
        outputs=events,
    )


def fetch_events_command(client: SAPETDClient, max_fetch: int) -> None:
    """Fetch new alerts since the last run, send them to XSIAM and save the new high-water mark.

    Args:
        client: SAP ETD API client instance.
        max_fetch: Maximum number of alerts to fetch per cycle.
    """
    time_field = client.api.TIME_FIELD
    last_run = demisto.getLastRun()
    raw_ids = last_run.get(Config.LAST_RUN_IDS_KEY)
    last_fetched_ids: list[int] = raw_ids if isinstance(raw_ids, list) else []
    from_timestamp = last_run.get(Config.LAST_RUN_TIMESTAMP_KEY) or parse_date_to_iso(Config.DEFAULT_FIRST_FETCH)
    demisto.debug(f"[Fetch] From: {from_timestamp} | Previous AlertIds: {len(last_fetched_ids)} | Max: {max_fetch}")

    events = fetch_alerts_with_pagination(client, from_timestamp=from_timestamp, max_alerts=max_fetch)
    if not events:
        demisto.debug("[Fetch] No alerts found.")
        return

    new_events = deduplicate_events(events, last_fetched_ids)
    if new_events:
        add_time_to_events(new_events, time_field)
        client.send_events(new_events)

    # Saved only after a successful send, so a failed send is retried on the next cycle.
    next_run = build_next_last_run(events, time_field)
    if next_run is None:
        demisto.debug(f"[Fetch] Last alert has no {time_field}. Last run not updated.")
        return
    demisto.setLastRun(next_run)
    demisto.debug(
        f"[Fetch] Last run updated: {next_run[Config.LAST_RUN_TIMESTAMP_KEY]} "
        f"({len(next_run[Config.LAST_RUN_IDS_KEY])} AlertIds at that timestamp)"
    )


# endregion

# region Main router
# =================================
# Main router
# =================================


def main() -> None:
    """Main entry point for SAP Enterprise Threat Detection integration."""
    command = demisto.command()
    demisto.debug(f"[Main] Command: {command}")

    try:
        config = parse_integration_params(demisto.params())
        client = SAPETDClient(config)

        if command == Commands.TEST_MODULE:
            return_results(test_module(client))
        elif command == Commands.FETCH_EVENTS:
            fetch_events_command(client, max_fetch=config["max_fetch"])
        elif command == Commands.GET_EVENTS:
            return_results(get_events_command(client, demisto.args()))
        else:
            raise DemistoException(Messages.UNKNOWN_COMMAND.format(command=command))

    except Exception as error:
        error_msg = Messages.COMMAND_FAILED.format(command=command, error=error)
        demisto.error(f"{error_msg}\n{traceback.format_exc()}")
        return_error(error_msg)


# endregion

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
