import tempfile
import time
import traceback
from enum import StrEnum
from typing import Any

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401, F403

# Disable insecure warnings
urllib3.disable_warnings()

"""
SAP BTP (Business Technology Platform)

Sections:
- Constants and helpers
- Client (API paths and methods)
- Command implementations
- Main router
"""

# region Constants and helpers
# =================================
# Constants and helpers
# =================================
INTEGRATION_NAME = "SAP BTP (Business Technology Platform)"


class IntegrationConfig:
    """Global static configuration."""

    VENDOR = "SAP"
    PRODUCT = "BTP"
    DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
    DEFAULT_LIMIT = 5000
    MAX_PAGE_SIZE = 500
    CACHE_BUFFER_SECONDS = 60
    DEFAULT_TOKEN_TTL_HOURS = 6
    DEFAULT_TOKEN_TTL_SECONDS = DEFAULT_TOKEN_TTL_HOURS * 60 * 60


class AuthType(StrEnum):
    """Authentication methods."""

    MTLS = "mTLS"
    NON_MTLS = "Non-mTLS"


class ContextKeys(StrEnum):
    """Keys used for Integration Context (Caching) and API Response."""

    ACCESS_TOKEN = "access_token"
    EXPIRES_IN = "expires_in"
    VALID_UNTIL = "valid_until"


class APIKeys(StrEnum):
    """API Parameter Keys and Header Names."""

    HEADER_PAGING = "Paging"
    HEADER_AUTH = "Authorization"
    FILTER = "$filter"
    TOP = "$top"
    HANDLE = "handle"
    GRANT_TYPE = "grant_type"
    CLIENT_ID = "client_id"


class ApiValues(StrEnum):
    """API Endpoint paths and fixed Parameter Values."""

    AUDIT_ENDPOINT = "/auditlog/v2/auditlogrecords"
    GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials"


class DefaultValues(StrEnum):
    """Default values for command arguments."""

    FROM_TIME = "now"  # Default time range for get-events command


def parse_date_or_use_current(date_string: str | None) -> datetime:
    """Parse a date string or return current datetime if parsing fails.

    Args:
        date_string: ISO 8601 date string or None

    Returns:
        Parsed datetime object or current datetime if parsing fails or input is None
    """
    if not date_string:
        current_time = datetime.now()
        demisto.debug(f"No date provided, using current time: {current_time}")
        return current_time

    parsed_datetime = dateparser.parse(date_string)
    if parsed_datetime:
        demisto.debug(f"Parsed date '{date_string}' to: {parsed_datetime}")
        return parsed_datetime

    demisto.debug(f"Failed to parse date '{date_string}', using current time")
    return datetime.now()


def create_mtls_cert_files(certificate: str, private_key: str) -> tuple[str, str]:
    """Create temporary certificate files for mTLS authentication.

    Args:
        certificate: PEM-encoded certificate content
        private_key: PEM-encoded private key content

    Returns:
        Tuple of (cert_file_path, key_file_path)

    Raises:
        DemistoException: If file creation fails
    """
    demisto.debug("Creating temporary mTLS certificate files")

    try:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".pem") as cert_file:
            cert_file.write(certificate)
            cert_file.flush()
            cert_path = cert_file.name

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".key") as key_file:
            key_file.write(private_key)
            key_file.flush()
            key_path = key_file.name

        demisto.debug(f"mTLS certificate files created: cert={cert_path}, key={key_path}")
        return cert_path, key_path

    except Exception as e:
        raise DemistoException(f"Failed to create mTLS certificate files: {e}")


def parse_integration_params(params: dict[str, Any]) -> dict[str, Any]:
    """Parse and validate integration configuration parameters."""
    demisto.debug("Parsing integration parameters.")

    base_url = (params.get("url", "")).rstrip("/")
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))
    auth_type = params.get("auth_type", AuthType.NON_MTLS)

    client_id = params.get("client_id", "").strip()
    client_secret = params.get("client_secret", "").strip()
    certificate = params.get("certificate", "").strip()
    key = params.get("key", "").strip()

    demisto.debug(
        f"Parsed config: {base_url=}, {auth_type=}, has_client_id={bool(client_id)}, "
        f"has_client_secret={bool(client_secret)}, has_certificate={bool(certificate)}, has_key={bool(key)}"
    )

    if not base_url:
        raise DemistoException("Server URL is required.")

    if not client_id:
        raise DemistoException("Client ID is required for both mTLS and Non-mTLS authentication.")

    token_url = f"{base_url}/oauth/token"
    demisto.debug(f"Constructed token URL: {token_url}")

    if auth_type == AuthType.MTLS:
        missing_fields = []
        if not certificate:
            missing_fields.append("Certificate")
        if not key:
            missing_fields.append("Private Key")

        if missing_fields:
            raise DemistoException(
                f"mTLS authentication selected but missing required fields: {', '.join(missing_fields)}. "
                f"Please provide Certificate and Private Key for mTLS authentication."
            )
        demisto.debug("Using mTLS authentication with valid credentials")

    elif auth_type == AuthType.NON_MTLS:
        if not client_secret:
            raise DemistoException(
                "Non-mTLS authentication selected but Client Secret is missing. "
                "Please provide Client Secret for Non-mTLS authentication."
            )
        demisto.debug("Using Non-mTLS authentication with valid credentials")

    else:
        raise DemistoException(
            f"Invalid authentication type '{auth_type}'. Please select either 'mTLS' or 'Non-mTLS'."
        )

    return {
        "base_url": base_url,
        "token_url": token_url,
        "verify": verify_certificate,
        "proxy": proxy,
        "auth_type": auth_type,
        "client_id": client_id,
        "client_secret": client_secret,
        "certificate": certificate,
        "key": key,
    }


# endregion

# region Client
# =================================
# Client
# =================================


class Client(BaseClient):
    """SAP BTP API client."""

    def __init__(
        self,
        base_url: str,
        token_url: str,
        client_id: str,
        client_secret: str | None,
        verify: bool,
        proxy: bool,
        auth_type: str,
        cert_data: tuple[str, str] | None = None,
    ):
        """Initialize SAP BTP API client.

        Args:
            base_url: Base URL for SAP BTP Audit Log service
            token_url: OAuth2 token endpoint URL
            client_id: OAuth2 client ID (required for both auth types)
            client_secret: OAuth2 client secret (required for Non-mTLS)
            verify: Whether to verify SSL certificates
            proxy: Whether to use system proxy
            auth_type: Authentication type (mTLS or Non-mTLS)
            cert_data: Tuple of (cert_path, key_path) for mTLS
        """
        base_url = base_url.rstrip("/") + "/"
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)

        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_type = auth_type
        self.cert_data = cert_data

        demisto.debug(f"Client initialized: base_url={base_url}, verify_ssl={verify}, proxy={proxy}, auth_type={auth_type}")

    def _get_access_token(self) -> str:
        """Get or refresh OAuth2 access token with caching.

        Returns:
            Valid OAuth2 access token

        Raises:
            DemistoException: If token generation fails
        """
        current_timestamp = int(time.time())
        cached_context = get_integration_context() or {}
        cached_token = cached_context.get(ContextKeys.ACCESS_TOKEN)
        cached_valid_until = cached_context.get(ContextKeys.VALID_UNTIL)

        if cached_token and cached_valid_until:
            try:
                valid_until_timestamp = int(cached_valid_until)
                if current_timestamp < valid_until_timestamp:
                    seconds_remaining = valid_until_timestamp - current_timestamp
                    demisto.debug(f"Using cached token (valid for {seconds_remaining}s)")
                    return cached_token
                demisto.debug(f"Cached token expired at {time.ctime(valid_until_timestamp)}, renewing")
            except (ValueError, TypeError) as e:
                demisto.debug(f"Invalid cached token expiration value: {e}, forcing renewal")

        demisto.debug(f"Requesting new OAuth2 token from {self.token_url}")

        token_params: dict[str, Any] = {APIKeys.GRANT_TYPE: ApiValues.GRANT_TYPE_CLIENT_CREDENTIALS}
        request_kwargs: dict[str, Any] = {"method": "POST", "full_url": self.token_url}

        if self.auth_type == AuthType.NON_MTLS:
            demisto.debug("Using Non-mTLS authentication (client credentials)")
            request_kwargs["auth"] = (self.client_id, self.client_secret)
            request_kwargs["params"] = token_params
        elif self.auth_type == AuthType.MTLS:
            demisto.debug("Using mTLS authentication (client certificate)")
            if not self.cert_data:
                raise DemistoException("mTLS authentication requires certificate files")
            request_kwargs["cert"] = self.cert_data
            token_params[APIKeys.CLIENT_ID] = self.client_id
            request_kwargs["data"] = token_params

        token_response = self._http_request(**request_kwargs)
        demisto.debug(f"Token request completed, response contains {len(token_response)} fields")

        access_token = token_response.get(ContextKeys.ACCESS_TOKEN)
        if not access_token:
            demisto.debug(f"Token response missing '{ContextKeys.ACCESS_TOKEN}': {token_response}")
            raise DemistoException("Failed to obtain access token from SAP BTP")

        token_expires_in = token_response.get(ContextKeys.EXPIRES_IN, IntegrationConfig.DEFAULT_TOKEN_TTL_SECONDS)
        token_valid_until = current_timestamp + token_expires_in - IntegrationConfig.CACHE_BUFFER_SECONDS
        demisto.debug(f"Token will expire in {token_expires_in}s, caching until {token_valid_until}")

        new_context = {ContextKeys.ACCESS_TOKEN: access_token, ContextKeys.VALID_UNTIL: str(token_valid_until)}
        set_integration_context(new_context)

        demisto.debug(f"New token cached successfully (expires in {token_expires_in}s, valid until {time.ctime(token_valid_until)})")

        return access_token

    def http_request(
        self, method: str, url_suffix: str, params: dict[str, Any] | None = None, return_full_response: bool = False
    ) -> Any:
        """Execute authenticated HTTP request to SAP BTP API.

        Args:
            method: HTTP method (GET, POST, etc.)
            url_suffix: API endpoint path
            params: Query parameters
            return_full_response: If True, return (json_body, headers) tuple

        Returns:
            JSON response or (json_body, headers) tuple if return_full_response=True
        """
        access_token = self._get_access_token()
        auth_headers = {APIKeys.HEADER_AUTH: f"Bearer {access_token}"}

        demisto.debug(f"Executing {method} request to {url_suffix}")
        if params:
            demisto.debug(f"Request parameters: {params}")

        http_response = self._http_request(
            method=method,
            url_suffix=url_suffix,
            params=params,
            headers=auth_headers,
            resp_type="response" if return_full_response else "json",
            ok_codes=(200, 201, 202, 204),
        )

        if return_full_response:
            response_body = http_response.json()
            response_headers = http_response.headers
            body_size = len(response_body) if isinstance(response_body, list) else len(response_body.keys())
            demisto.debug(f"Response received: {body_size} items/fields, {len(response_headers)} headers")
            return response_body, response_headers

        demisto.debug(f"Response received successfully (status: {http_response.status_code})")
        return http_response

    def get_audit_log_events(
        self, created_after: str, limit: int, pagination_handle: str | None = None
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Retrieve audit log events from SAP BTP.

        Args:
            created_after: ISO 8601 timestamp to filter events created after this time
            limit: Maximum number of events to retrieve (capped at MAX_PAGE_SIZE)
            pagination_handle: Optional handle for fetching next page of results

        Returns:
            Tuple of (list of event dictionaries, next pagination handle or None)
        """
        demisto.debug(
            f"Fetching audit log events: created_after={created_after}, "
            f"limit={limit}, has_pagination_handle={pagination_handle is not None}"
        )

        request_params: dict[str, Any] = {}

        if pagination_handle:
            demisto.debug(f"Using pagination handle: {pagination_handle[:50]}...")
            request_params[APIKeys.HANDLE] = pagination_handle
        else:
            events_filter = f"created_at gt {created_after}"
            page_size = min(limit, IntegrationConfig.MAX_PAGE_SIZE)
            demisto.debug(f"First page request: filter='{events_filter}', page_size={page_size}")
            request_params[APIKeys.FILTER] = events_filter
            request_params[APIKeys.TOP] = page_size

        response_body, response_headers = self.http_request(
            method="GET", url_suffix=ApiValues.AUDIT_ENDPOINT, params=request_params, return_full_response=True
        )

        events_list = response_body if isinstance(response_body, list) else response_body.get("value", [])
        demisto.debug(f"Retrieved {len(events_list)} events from API")

        next_page_handle = self._extract_pagination_handle(response_headers)
        if next_page_handle:
            demisto.debug("Pagination handle available for next page")
        else:
            demisto.debug("No pagination handle - this is the last page")

        return events_list, next_page_handle

    def _extract_pagination_handle(self, headers: dict[str, Any]) -> str | None:
        """Extract pagination handle from response headers.

        Args:
            headers: HTTP response headers

        Returns:
            Pagination handle string or None if not present
        """
        paging_header_value = headers.get(APIKeys.HEADER_PAGING) or headers.get(APIKeys.HEADER_PAGING.lower())

        if not paging_header_value:
            demisto.debug("No pagination header found in response")
            return None

        if "handle=" not in paging_header_value:
            demisto.debug(f"Pagination header present but no handle found: {paging_header_value}")
            return None

        try:
            handle_value = paging_header_value.split("handle=")[1].strip()
            demisto.debug(f"Extracted pagination handle: {handle_value[:50]}...")
            return handle_value
        except IndexError:
            demisto.debug(f"Failed to parse pagination handle from header: {paging_header_value}")
            return None


# endregion

# region Command implementations
# =================================
# Command implementations
# =================================


def test_module(client: Client) -> str:
    """Test API connectivity and authentication."""
    demisto.debug("Starting execution of command: Test Module")
    try:
        current_time = datetime.now().strftime(IntegrationConfig.DATE_FORMAT)
        demisto.debug(f"Testing with current time: {current_time}")
        client.get_audit_log_events(created_after=current_time, limit=1)
        demisto.debug("Command 'Test Module' execution finished successfully.")
        return "ok"
    except Exception as e:
        if "401" in str(e) or "403" in str(e):
            return "Authorization Error: Verify Client ID, Secret, or Certificates."
        raise


def fetch_events_with_pagination(
    client: Client, created_after: str, max_events: int
) -> list[dict[str, Any]]:
    """Fetch events with automatic pagination handling.

    Args:
        client: SAP BTP API client
        created_after: ISO 8601 timestamp to filter events
        max_events: Maximum number of events to fetch

    Returns:
        List of event dictionaries
    """
    events: list[dict[str, Any]] = []
    pagination_handle: str | None = None

    demisto.debug(f"Starting pagination loop: max_events={max_events}")

    while len(events) < max_events:
        remaining_events = max_events - len(events)
        demisto.debug(
            f"Fetching page: current_count={len(events)}, "
            f"remaining={remaining_events}, has_handle={pagination_handle is not None}"
        )

        page_events, pagination_handle = client.get_audit_log_events(
            created_after=created_after,
            limit=remaining_events,
            pagination_handle=pagination_handle
        )

        if not page_events:
            demisto.debug("No more events returned, ending pagination")
            break

        events.extend(page_events)
        demisto.debug(f"Added {len(page_events)} events, total: {len(events)}")

        if not pagination_handle:
            demisto.debug("No next page handle, ending pagination")
            break

    demisto.debug(f"Pagination complete: fetched {len(events)} total events")
    return events


def get_events_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get audit log events manually.

    Args:
        client: SAP BTP API client
        args: Command arguments from demisto.args()

    Returns:
        CommandResults with events data
    """
    demisto.debug("Starting execution of command: Get Events")

    from_time = args.get("from", DefaultValues.FROM_TIME)
    limit = arg_to_number(args.get("limit")) or IntegrationConfig.DEFAULT_LIMIT
    demisto.debug(f"Parsed arguments: from={from_time}, limit={limit}")

    start_datetime = parse_date_or_use_current(from_time if from_time != DefaultValues.FROM_TIME else None)
    created_after = start_datetime.strftime(IntegrationConfig.DATE_FORMAT)
    demisto.debug(f"Fetching events from: {created_after}")

    events = fetch_events_with_pagination(client, created_after, int(limit))
    demisto.debug(f"Retrieved {len(events)} events")

    readable_output = tableToMarkdown(f"{INTEGRATION_NAME} Events", events, removeNull=True)

    demisto.debug("Command 'Get Events' execution finished successfully.")
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="SAPBTP.Event",
        outputs_key_field="uuid",
        outputs=events,
    )


def fetch_events_command(client: Client, args: dict[str, Any]) -> None:
    """Fetch events and send to XSIAM (scheduled job).

    Args:
        client: SAP BTP API client
        args: Command arguments from demisto.args()
    """
    demisto.debug("Starting execution of command: Fetch Events")

    args.update(demisto.params())

    last_run = demisto.getLastRun()
    last_fetch_timestamp = last_run.get("last_fetch")
    demisto.debug(f"Last run: {last_run}")

    last_fetch_datetime = parse_date_or_use_current(last_fetch_timestamp)
    created_after = last_fetch_datetime.strftime(IntegrationConfig.DATE_FORMAT)

    max_events_to_fetch = args.get("max_fetch", IntegrationConfig.DEFAULT_LIMIT)
    demisto.debug(f"Fetch parameters: created_after={created_after}, max_events={max_events_to_fetch}")

    events = fetch_events_with_pagination(client, created_after, int(max_events_to_fetch))

    if events:
        demisto.debug(f"Fetched {len(events)} events, sorting by time")
        events.sort(key=lambda x: x.get("time", ""))

        first_event_time = events[0].get("time")
        last_event_time = events[-1].get("time")
        demisto.debug(f"Event time range: {first_event_time} to {last_event_time}")

        if last_event_time:
            demisto.setLastRun({"last_fetch": last_event_time})
            demisto.debug(f"Updated last run to: {last_event_time}")
        else:
            demisto.debug("Warning: Last event has no 'time' field, last run not updated")

        send_events_to_xsiam(events, vendor=IntegrationConfig.VENDOR, product=IntegrationConfig.PRODUCT)
        demisto.debug(f"Successfully sent {len(events)} events to XSIAM")
    else:
        demisto.debug(f"No events fetched from {created_after}, nothing to send to XSIAM")

    demisto.debug("Command 'Fetch Events' execution finished successfully.")


# endregion

# region Main router
# =================================
# Main router
# =================================

COMMAND_MAP: dict[str, Any] = {
    "test-module": test_module,
    "sap-btp-get-events": get_events_command,
    "fetch-events": fetch_events_command,
}


def main() -> None:
    """Main entry point for SAP BTP integration."""
    demisto.debug(f"{INTEGRATION_NAME} integration started")

    command = demisto.command()
    demisto.debug(f"Received command: '{command}'")

    try:
        if command not in COMMAND_MAP:
            raise DemistoException(f"Command '{command}' is not implemented")
        demisto.debug(f"Command '{command}' validated successfully")

        demisto.debug("Parsing integration configuration")
        config = parse_integration_params(demisto.params())
        demisto.debug(f"Configuration parsed successfully: base_url={config['base_url']}, auth_type={config['auth_type']}")

        cert_data = None
        if config["auth_type"] == AuthType.MTLS:
            cert_data = create_mtls_cert_files(config["certificate"], config["key"])

        demisto.debug(f"Initializing {INTEGRATION_NAME} Client")
        client = Client(
            base_url=config["base_url"],
            token_url=config["token_url"],
            client_id=config["client_id"],
            client_secret=config["client_secret"],
            verify=config["verify"],
            proxy=config["proxy"],
            auth_type=config["auth_type"],
            cert_data=cert_data,
        )
        demisto.debug("Client initialized successfully")

        command_func = COMMAND_MAP[command]
        demisto.debug(f"Executing command function for '{command}'")

        if command == "test-module":
            result = command_func(client)
        else:
            result = command_func(client, demisto.args())

        if result:
            return_results(result)
            demisto.debug(f"Command '{command}' returned results successfully")
        else:
            demisto.debug(f"Command '{command}' completed successfully (no results to return)")

    except Exception as error:
        error_msg = f"Failed to execute {command=}. Error: {str(error)}"
        demisto.debug(f"Error: {error_msg}\nTrace: {traceback.format_exc()}")
        return_error(error_msg, error=str(error))

    finally:
        demisto.debug(f"{INTEGRATION_NAME} integration finished")


# endregion

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
