import tempfile
import time
import traceback
from enum import Enum
from typing import Any
import datetime as dt

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401, F403

urllib3.disable_warnings()

"""
SAP BTP (Business Technology Platform)
"""

# region Constants and helpers
# =================================
# Constants and helpers
# =================================
INTEGRATION_NAME = "SAP BTP (Business Technology Platform)"


class Config:
    """Global static configuration."""

    VENDOR = "SAP"
    PRODUCT = "BTP"
    DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"
    CACHE_BUFFER_SECONDS = 60
    DEFAULT_TOKEN_TTL_HOURS = 6
    DEFAULT_TOKEN_TTL_SECONDS = DEFAULT_TOKEN_TTL_HOURS * 60 * 60


class AuthType(str, Enum):
    """Authentication methods."""

    MTLS = "mTLS"
    NON_MTLS = "Non-mTLS"


class ContextKeys(str, Enum):
    """Keys used for Integration Context (Caching) and API Response."""

    ACCESS_TOKEN = "access_token"
    EXPIRES_IN = "expires_in"
    VALID_UNTIL = "valid_until"


class APIKeys(str, Enum):
    """API Parameter Keys and Header Names."""

    HEADER_PAGING = "Paging"
    HEADER_AUTH = "Authorization"
    TIME_FROM = "time_from"
    TIME_TO = "time_to"
    HANDLE = "handle"
    GRANT_TYPE = "grant_type"
    CLIENT_ID = "client_id"
    CLIENT_SECRET = "client_secret"


class APIValues(str, Enum):
    """API Endpoint paths and fixed Parameter Values."""

    AUDIT_ENDPOINT = "/auditlog/v2/auditlogrecords"
    GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials"


class DefaultValues(str, Enum):
    """Default values for command arguments and parameters."""

    FROM_TIME = "1 minute ago"
    MAX_FETCH = "5000"


def get_formatted_utc_time(date_input: str | None) -> str:
    """Helper to parse input and return the strictly formatted UTC string for SAP."""
    start_datetime = parse_date_or_use_current(date_input)
    return start_datetime.strftime(Config.DATE_FORMAT)


def parse_date_or_use_current(date_string: str | None) -> datetime:
    """Parse a date string or return current UTC datetime if parsing fails."""
    if not date_string:
        current_time = dt.datetime.now(dt.UTC)
        demisto.debug(f"No date provided, using current time: {current_time}")
        return current_time

    parsed_datetime = dateparser.parse(date_string)
    if parsed_datetime:
        if not parsed_datetime.tzinfo:
            parsed_datetime = parsed_datetime.replace(tzinfo=dt.UTC)
        else:
            parsed_datetime = parsed_datetime.astimezone(dt.UTC)

        demisto.debug(f"Parsed date '{date_string}' to UTC: {parsed_datetime}")
        return parsed_datetime

    demisto.debug(f"Failed to parse date '{date_string}', using current UTC time")
    return dt.datetime.now(dt.UTC)


def create_mtls_cert_files(certificate: str, private_key: str) -> tuple[str, str]:
    """Create temporary certificate files for mTLS authentication."""
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

    except Exception as error:
        raise DemistoException(f"Failed to create mTLS certificate files. Error: {str(error)}")


def parse_integration_params(params: dict[str, Any]) -> dict[str, Any]:
    """Parse and validate integration configuration parameters."""
    demisto.debug("Parsing integration parameters.")
    base_url = (params.get("url", "")).strip().rstrip("/")
    token_url_param = params.get("token_url", "").strip().rstrip("/")

    if not base_url:
        raise DemistoException("API URL is required. Please provide the Service Key 'url' field.")

    if not token_url_param:
        raise DemistoException("Token URL is required. Please provide the Service Key 'uaa.url' field.")

    token_url = f"{token_url_param}/oauth/token"
    demisto.debug(f"Configured URLs - API: {base_url}, Token: {token_url}")

    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))
    auth_type = params.get("auth_type", AuthType.NON_MTLS.value)
    client_id = params.get("client_id", "").strip() or None
    client_secret = params.get("client_secret", "").strip() or None
    certificate = params.get("certificate", "").strip() or None
    private_key = params.get("private_key", "").strip() or None

    if not client_id:
        raise DemistoException("Client ID is required.")

    if auth_type == AuthType.MTLS.value:
        if not certificate or not private_key:
            raise DemistoException("mTLS requires Certificate and Private Key.")
    elif auth_type == AuthType.NON_MTLS.value:
        if not client_secret:
            raise DemistoException("Non-mTLS requires Client Secret.")
    else:
        raise DemistoException(f"Invalid authentication type '{auth_type}'.")

    return {
        "base_url": base_url,
        "token_url": token_url,
        "verify": verify_certificate,
        "proxy": proxy,
        "auth_type": auth_type,
        "client_id": client_id,
        "client_secret": client_secret,
        "certificate": certificate,
        "private_key": private_key,
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
        base_url = base_url.rstrip("/") + "/"
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_type = auth_type
        self.cert_data = cert_data

    def _get_access_token(self) -> str:
        """Get or refresh OAuth2 access token."""
        current_timestamp = int(time.time())
        cached_context = get_integration_context() or {}
        cached_token = cached_context.get(ContextKeys.ACCESS_TOKEN.value)
        cached_valid_until = cached_context.get(ContextKeys.VALID_UNTIL.value)

        if cached_token and cached_valid_until:
            try:
                valid_until_timestamp = int(cached_valid_until)
                if current_timestamp < valid_until_timestamp:
                    return cached_token
            except (ValueError, TypeError):
                pass

        demisto.debug(f"Requesting new OAuth2 token from {self.token_url}")
        request_kwargs: dict[str, Any] = {"method": "POST", "full_url": self.token_url}

        if self.auth_type == AuthType.NON_MTLS.value:
            request_kwargs["auth"] = (self.client_id, self.client_secret)
            request_kwargs["params"] = {
                APIKeys.GRANT_TYPE.value: APIValues.GRANT_TYPE_CLIENT_CREDENTIALS.value,
            }
        elif self.auth_type == AuthType.MTLS.value:
            if not self.cert_data:
                raise DemistoException("mTLS authentication requires certificate files")
            request_kwargs["cert"] = self.cert_data
            token_data = {
                APIKeys.GRANT_TYPE.value: APIValues.GRANT_TYPE_CLIENT_CREDENTIALS.value,
                APIKeys.CLIENT_ID.value: self.client_id,
            }
            request_kwargs["data"] = token_data

        token_response = self._http_request(**request_kwargs)
        access_token = token_response.get(ContextKeys.ACCESS_TOKEN.value)
        if not access_token:
            raise DemistoException("Failed to obtain access token from SAP BTP")

        token_expires_in = token_response.get(ContextKeys.EXPIRES_IN.value, Config.DEFAULT_TOKEN_TTL_SECONDS)
        token_valid_until = current_timestamp + token_expires_in - Config.CACHE_BUFFER_SECONDS

        new_context = {ContextKeys.ACCESS_TOKEN.value: access_token, ContextKeys.VALID_UNTIL.value: str(token_valid_until)}
        set_integration_context(new_context)

        return access_token

    def http_request(
        self, method: str, url_suffix: str, params: dict[str, Any] | None = None, return_full_response: bool = False
    ) -> Any:
        access_token = self._get_access_token()
        auth_headers = {APIKeys.HEADER_AUTH.value: f"Bearer {access_token}"}

        demisto.debug(f"Executing {method} request to {url_suffix}")

        http_response = self._http_request(
            method=method,
            url_suffix=url_suffix,
            params=params,
            headers=auth_headers,
            resp_type="response",
            ok_codes=(200, 201, 202, 204),
        )

        if http_response.status_code == 204:
            demisto.debug("Received 204 No Content")
            if return_full_response:
                return {}, http_response.headers
            return {}

        try:
            response_json = http_response.json()
        except ValueError:
            demisto.debug(f"Failed to parse JSON. Body: {http_response.text}")
            raise DemistoException(f"API returned non-JSON response with status {http_response.status_code}")

        if return_full_response:
            return response_json, http_response.headers

        return response_json

    def get_audit_log_events(
        self, created_after: str, created_before: str | None = None, limit: int = 0, pagination_handle: str | None = None
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Retrieve audit log events from SAP BTP."""
        demisto.debug(
            f"Fetching audit log events: created_after={created_after}, created_before={created_before}, "
            f"has_pagination_handle={pagination_handle is not None}"
        )

        request_params: dict[str, Any] = {}

        if pagination_handle:
            demisto.debug(f"Using pagination handle: {pagination_handle[:50]}...")
            request_params[APIKeys.HANDLE.value] = pagination_handle
        else:
            request_params[APIKeys.TIME_FROM.value] = created_after
            if created_before:
                request_params[APIKeys.TIME_TO.value] = created_before
            demisto.debug(f"First page request: params={request_params}")
        response_body, response_headers = self.http_request(
            method="GET", url_suffix=APIValues.AUDIT_ENDPOINT.value, params=request_params, return_full_response=True
        )

        if isinstance(response_body, list):
            events_list = response_body
        else:
            events_list = response_body.get("results") or response_body.get("d", {}).get("results") or []
            if not events_list and isinstance(response_body, dict) and "message_uuid" in response_body:
                events_list = [response_body]

        demisto.debug(f"Retrieved {len(events_list)} events from API")
        next_page_handle = self._extract_pagination_handle(response_headers)

        return events_list, next_page_handle

    def _extract_pagination_handle(self, headers: dict[str, Any]) -> str | None:
        """Extract pagination handle from response headers."""
        paging_header_value = headers.get(APIKeys.HEADER_PAGING.value) or headers.get(APIKeys.HEADER_PAGING.value.lower())

        if not paging_header_value or "handle=" not in paging_header_value:
            return None

        try:
            return paging_header_value.split("handle=")[1].strip()
        except IndexError:
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
        utc_now = dt.datetime.now(dt.UTC)
        test_time = (utc_now - timedelta(minutes=1)).strftime(Config.DATE_FORMAT)
        demisto.debug(f"Testing with time (now - 1 minute): {test_time}")
        fetch_events_with_pagination(client, created_after=test_time, max_events=1)
        demisto.debug("Command 'Test Module' execution finished successfully.")
        return "ok"
    except Exception as error:
        if "401" in str(error) or "403" in str(error):
            return "Authorization Error: Verify Client ID, Secret, or Certificates."
        raise


def fetch_events_with_pagination(
    client: Client, created_after: str, max_events: int, created_before: str | None = None
) -> list[dict[str, Any]]:
    """Fetch, Sort (Oldest First), and Slice events.

    This function implements a "Fetch-Sort-Slice" strategy to ensure data integrity:
    1. Optimization: We fetch pages until we have at least 'max_events' raw items.
    2. Sorting: We sort the raw list by time (Oldest -> Newest).
    3. Slicing: We return exactly 'max_events' (the oldest ones).
    Any excess events (which are newer) are discarded here and will be
    picked up naturally in the next run.

    Args:
        client: API Client
        created_after: UTC formatted time string
        max_events: Hard limit on how many events to return

    Returns:
        List of sorted event dictionaries (length <= max_events).
    """
    events: list[dict[str, Any]] = []
    pagination_handle: str | None = None

    demisto.debug(f"Starting pagination loop: target_limit={max_events}")

    while len(events) < max_events:
        remaining_needed = max_events - len(events)

        page_events, pagination_handle = client.get_audit_log_events(
            created_after=created_after,
            created_before=created_before,
            limit=remaining_needed,
            pagination_handle=pagination_handle,
        )

        if not page_events:
            demisto.debug("No events returned in this page, ending pagination")
            break

        events.extend(page_events)
        demisto.debug(f"Fetched page. Total raw events so far: {len(events)}")

        if not pagination_handle:
            demisto.debug("No next page handle, ending pagination")
            break

    if not events:
        return []

    events.sort(key=lambda x: x.get("time", ""))
    final_events = events[:max_events]

    demisto.debug(f"Returning {len(final_events)} sorted events (sliced from {len(events)})")
    return final_events


def get_events_command(client: Client, args: dict[str, Any]) -> CommandResults | str:
    """Get audit log events manually."""
    from_time_input = args.get("from_time", DefaultValues.FROM_TIME.value)
    end_time_input = args.get("end_time")
    limit = int(args.get("limit", DefaultValues.MAX_FETCH.value))
    should_push_events = argToBoolean(args.get("should_push_events", True))

    created_after = get_formatted_utc_time(from_time_input)
    created_before = get_formatted_utc_time(end_time_input) if end_time_input else None

    demisto.debug(f"Fetching events from (UTC): {created_after} to {created_before or 'now'}")

    events = fetch_events_with_pagination(client, created_after, limit, created_before)

    if should_push_events and events:
        send_events_to_xsiam(events, vendor=Config.VENDOR, product=Config.PRODUCT)
        demisto.debug(f"Pushed {len(events)} events to XSIAM")
        return f"Successfully retrieved and pushed {len(events)} events to XSIAM"

    readable_output = tableToMarkdown(f"{INTEGRATION_NAME} Events", events, removeNull=True)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="SAPBTP.Event",
        outputs_key_field="uuid",
        outputs=events,
    )


def fetch_events_command(client: Client) -> None:
    """Fetch events and send to XSIAM (scheduled job)."""
    demisto.debug("Starting execution of command: Fetch Events")

    params = demisto.params()
    first_fetch_param = params.get("first_fetch")
    last_run = demisto.getLastRun()
    last_fetch_timestamp = last_run.get("last_fetch")
    demisto.debug(f"Fetch params - first_fetch: {first_fetch_param}, last_run: {last_run}, last_fetch: {last_fetch_timestamp}")

    if last_fetch_timestamp:
        time_input = last_fetch_timestamp
        demisto.debug(f"Fetching using stored Last Run: {time_input}")

    elif first_fetch_param:
        time_input = first_fetch_param
        demisto.debug(f"First run detected. Using configured 'first_fetch' param: {time_input}")

    else:
        time_input = DefaultValues.FROM_TIME.value
        demisto.debug("First run detected. No 'first_fetch' param found. Using default: 1 minute ago")

    # time_input = '2025-12-02T17:04:58' # TODO for test
    created_after = get_formatted_utc_time(time_input)

    max_events_to_fetch = int(params.get("max_fetch", DefaultValues.MAX_FETCH.value))
    demisto.debug(f"Fetch parameters: created_after={created_after} (UTC), limit={max_events_to_fetch}")

    events = fetch_events_with_pagination(client, created_after, max_events_to_fetch, None)

    if events:
        last_event = events[-1]
        new_last_run_time = last_event.get("time")

        if new_last_run_time:
            demisto.setLastRun({"last_fetch": new_last_run_time})
            demisto.debug(f"Updated last run to: {new_last_run_time}")

        send_events_to_xsiam(events, vendor=Config.VENDOR, product=Config.PRODUCT)
        demisto.debug(f"Successfully sent {len(events)} events to XSIAM")
    else:
        demisto.debug("No events fetched")

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

        config = parse_integration_params(demisto.params())

        cert_data = None
        if config["auth_type"] == AuthType.MTLS.value:
            cert_data = create_mtls_cert_files(config["certificate"], config["private_key"])

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

        result = None
        command_func = COMMAND_MAP[command]
        if command == "test-module":
            result = command_func(client)
        elif command == "fetch-events":
            command_func(client)
        else:
            result = command_func(client, demisto.args())

        if result:
            return_results(result)

    except Exception as error:
        error_msg = f"Failed to execute {command=}. Error: {str(error)}"
        demisto.debug(f"Error: {error_msg}\nTrace: {traceback.format_exc()}")
        return_error(error_msg)

    finally:
        demisto.debug(f"{INTEGRATION_NAME} integration finished")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
