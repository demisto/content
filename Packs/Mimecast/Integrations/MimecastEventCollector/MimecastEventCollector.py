import hashlib
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import aiohttp
from http import HTTPStatus
import asyncio
from typing import Any
from collections.abc import Callable
from datetime import datetime, timedelta, UTC

""" CONSTANTS """

# Date formats
AUDIT_DATE_FILTER_FORMAT = "%Y-%m-%dT%H:%M:%S+0000"
SIEM_DATE_FILTER_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"  # Call the `convert_to_siem_filter_format` function instead of using directly!
EVENTS_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# Events dataset
VENDOR = "mimecast"
PRODUCT = "mimecast"
EVENT_TIME_KEY = "_time"
SOURCE_LOG_TYPE_KEY = "source_log_type"
FILTER_TIME_KEY = "_filter_time"  # For last run and deduplication (will be removed before sending to dataset)

# Response general error fields
IS_FAIL = "fail"
IS_ERROR = "error"

# Access token response fields and default values
ACCESS_TOKEN_KEY = "access_token"
TOKEN_TYPE_KEY = "token_type"
TOKEN_TTL_KEY = "expires_in"  # TTL in seconds
TOKEN_VALID_UNTIL_KEY = "valid_until"
DEFAULT_TOKEN_TTL = 1800  # 30 minutes
DEFAULT_TOKEN_TYPE = "bearer"

# Default connection values
DEFAULT_BASE_URL = "https://api.services.mimecast.com"  # Global region
DEFAULT_RETRY_COUNT = 3

# Default page size values
DEFAULT_AUDIT_PAGE_SIZE = 500
DEFAULT_SIEM_PAGE_SIZE = 100

# Default limit values
DEFAULT_GET_EVENTS_LIMIT = 10
DEFAULT_FETCH_EVENTS_LIMIT = 1000

# Default dates
UTC_NOW = datetime.now(tz=UTC)
UTC_HOUR_AGO = UTC_NOW - timedelta(hours=1)
UTC_MINUTE_AGO = UTC_NOW - timedelta(minutes=1)

# Event ID and time fields (for deduplication and formatting)
EVENT_ID_KEY = "id"  # generated if not exists
AUDIT_TIME_KEY = "eventTime"
SIEM_TIME_KEY = "timestamp"

# Last run fields
DEPRECATED_AUDIT_START_DATE_KEY = "audit_last_run"
DEPRECATED_AUDIT_LAST_FETCHED_IDS_KEY = "audit_event_dedup_list"
DEPRECATED_SIEM_NEXT_PAGE_KEY = "siem_last_run"
DEPRECATED_SIEM_LAST_FETCHED_IDS_KEY = "siem_events_from_last_run"
START_DATE_KEY = "start_date"
LAST_FETCHED_IDS_KEY = "last_fetched_ids"
NEXT_PAGE_KEY = "next_page"

# Event types (Audit + SIEM types)
DEFAULT_EVENT_TYPES = [
    "audit",
    "av",
    "delivery",
    "internal email protect",
    "impersonation protect",
    "journal",
    "process",
    "receipt",
    "attachment protect",
    "spam",
    "url protect",
]
DATEPARSER_SETTINGS = {"RETURN_AS_TIMEZONE_AWARE": True, "TIMEZONE": str(UTC)}

""" CLIENT CLASS """


class AsyncClient:
    """An asynchronous client for interacting with the Mimecast API; used for SIEM event collection"""

    def __init__(self, base_url: str, client_id: str, client_secret: str, verify: bool, proxy: bool):
        self.base_url = base_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._access_token: str | None = None
        self._verify = verify
        self._proxy_url = handle_proxy().get("http", "") if proxy else None

    async def __aenter__(self):
        self._session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=self._verify), proxy=self._proxy_url)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            exception_traceback = "".join(traceback.format_exception(exc_type, exc_val, exc_tb))
            demisto.error(f"AsyncClient context exited with an exception: {exception_traceback}.")
        else:
            demisto.debug("AsyncClient context exited normally.")

        # Always ensure HTTP client session is closed
        await self._session.close()

    async def _generate_new_access_token(self) -> dict[str, Any]:
        """
        Generates a new OAuth2 access token using client credentials flow.

        Raises:
            ClientResponseError: If request failed.
            DemistoException: If response contains an error message and/or no access token.

        Returns:
            dict[str, Any]: The token raw API response.
        """
        token_url = urljoin(self.base_url, "/oauth/token")
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        body = {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "grant_type": "client_credentials",
        }
        demisto.debug(f"Requesting new OAuth2 access token using {token_url=}.")
        async with self._session.post(url=token_url, headers=headers, data=body) as response:
            response_json = await response.json()
            try:
                response.raise_for_status()
            except aiohttp.ClientResponseError as e:
                raise DemistoException(
                    f"Request to {token_url} failed with HTTP {e.status} status. Got response: {response_json}."
                ) from e

            if is_fail := response_json.get(IS_FAIL):
                error_message = is_fail[0]["message"]
                raise DemistoException(f"Request to {token_url} failed. Got error: {error_message}.")

            if not response_json.get(ACCESS_TOKEN_KEY):
                raise DemistoException(f"Request to {token_url} failed. Failed to get access token from response.")

            token_type = response_json.get(TOKEN_TYPE_KEY)
            token_ttl = response_json.get(TOKEN_TTL_KEY)  # TTL in seconds

            demisto.debug(f"Successfully obtained OAuth2 access token. {token_type=}, {token_ttl=}.")
            return response_json

    async def get_authorization_header(self, force_generate_new_token: bool = False) -> str:
        """
        Constructs Authorization header using the access token in the integration context (if found), or generating a new one.

        Args:
            force_generate_new_token (bool, optional): Whether to request a new OAuth access token. Defaults to False.

        Returns:
            str: The Authorization header containing the token type and access token.
        """
        demisto.debug(f"Constructing Authorization header using {force_generate_new_token=}.")
        integration_context = get_integration_context()
        access_token = integration_context.get(ACCESS_TOKEN_KEY)
        token_type = integration_context.get(TOKEN_TYPE_KEY, DEFAULT_TOKEN_TYPE)
        token_valid_until = arg_to_datetime(integration_context.get(TOKEN_VALID_UNTIL_KEY))
        is_valid_token = token_valid_until and token_valid_until > UTC_NOW
        demisto.debug(f"Found in integration context {token_valid_until=}, {is_valid_token=}.")

        if access_token and is_valid_token and not force_generate_new_token:
            demisto.debug("Using valid access token in integration context to construct Authorization header.")
        else:
            demisto.debug("Generating new access token.")
            token_response = await self._generate_new_access_token()
            access_token = token_response.get(ACCESS_TOKEN_KEY)
            token_type = token_response.get(TOKEN_TYPE_KEY, DEFAULT_TOKEN_TYPE)
            token_ttl = token_response.get(TOKEN_TTL_KEY, DEFAULT_TOKEN_TTL) - 300  # subtract 5 minutes as a safety margin
            token_response[TOKEN_VALID_UNTIL_KEY] = (UTC_NOW + timedelta(seconds=token_ttl)).isoformat()
            demisto.debug("Saving new access token in integration context.")
            set_integration_context(token_response)

        demisto.debug(f"Constructed Authorization header using {token_type=}.")
        return f"{token_type.capitalize()} {access_token}"

    async def _handle_request_with_retries(
        self,
        method: str,
        endpoint: str,
        max_retries: int,
        event_type: str,
        **request_kwargs,
    ) -> dict[str, Any]:
        """
        Handles HTTP requests with automatic retry logic for 401 and 429 errors.

        Args:
            method (str): The HTTP method to use (e.g., "GET", "POST").
            url (str): The full URL.
            headers (dict[str, str]): The request headers, including the "Authorization" header.
            max_retries (int): Maximum number of retries for rate limit errors.
            context (str): Context string for logging (e.g., event type).
            **request_kwargs: Additional keyword arguments to pass to the request (e.g., json, params).

        Raises:
            ClientResponseError: If the request fails after retries.
            DemistoException: If the request fails with a non-retryable error.

        Returns:
            dict[str, Any]: The API response as JSON.
        """
        url = urljoin(self.base_url, endpoint)
        headers = {"Accept": "application/json", "Authorization": await self.get_authorization_header()}

        retry_count = 0

        while retry_count <= max_retries:
            try:
                async with self._session.request(method=method, url=url, headers=headers, **request_kwargs) as response:
                    response_json = await response.json()
                    response.raise_for_status()
                    return response_json

            except aiohttp.ClientResponseError as e:
                status_code = e.status

                # Handle 401 Unauthorized - regenerate token and retry once
                if status_code == HTTPStatus.UNAUTHORIZED:
                    demisto.debug(f"[{event_type}] Received HTTP 401 Unauthorized. Generating new token and retrying...")
                    headers["Authorization"] = await self.get_authorization_header(force_generate_new_token=True)
                    # Retry immediately with new token
                    async with self._session.request(method=method, url=url, headers=headers, **request_kwargs) as response:
                        response_json = await response.json()
                        response.raise_for_status()
                        return response_json

                # Handle 429 Too Many Requests - exponential backoff
                elif status_code == HTTPStatus.TOO_MANY_REQUESTS:
                    if retry_count >= max_retries:
                        raise
                    wait_time = 2**retry_count  # Exponential backoff: 1s, 2s, 4s
                    demisto.debug(
                        f"[{event_type}] Received HTTP 429 Too Many Requests. "
                        f"Retrying {retry_count + 1} of {max_retries} after {wait_time} seconds..."
                    )
                    await asyncio.sleep(wait_time)
                    retry_count += 1

                # Handle other errors - don't retry
                else:
                    demisto.error(
                        f"[{event_type}] {e.request_info.method} Request failed to {e.request_info.url}. "
                        f"Got {status_code=} and {response_json=}."
                    )
                    raise DemistoException(f"Request to {e.request_info.url} failed with HTTP {e.status} status.") from e

        # Should not reach here, but just in case
        raise DemistoException(f"Failed after {max_retries} retries.")

    async def get_audit_events(
        self,
        start_date: str,
        end_date: str,
        next_page: str | None = None,
        page_size: int = DEFAULT_AUDIT_PAGE_SIZE,
        max_retries: int = DEFAULT_RETRY_COUNT,
    ) -> dict[str, Any]:
        """
        Retrieves audit events from Mimecast.

        Args:
            start_date (str): The start date for the audit events in Mimecast format.
            end_date (str): The end date for the audit events in Mimecast format.
            next_page (str | None): Optional page token for pagination.
            page_size (int): The number of items per page. Defaults to 500.
            max_retries (int): Maximum number of retries for rate limit errors. Defaults to 3.

        Raises:
            ClientResponseError: If the request fails (after retry on 401 or 429 errors or some other status code).

        Returns:
            dict[str, Any]: A dictionary containing the audit events raw API response.
        """
        payload = {
            "data": [{"startDateTime": start_date, "endDateTime": end_date}],
            "meta": {"pagination": assign_params(pageSize=page_size, pageToken=next_page)},
        }

        demisto.debug(f"Requesting audit events using {payload=}.")

        response_json = await self._handle_request_with_retries(
            method="POST",
            endpoint="/api/audit/get-audit-events",
            max_retries=max_retries,
            event_type="audit",
            json=payload,
        )

        events_count = len(response_json.get("data", []))
        demisto.debug(f"Fetched {events_count} audit events using {payload=}.")

        return response_json

    async def get_siem_events(
        self,
        event_type: str,
        start_date: str | None = None,
        end_date: str | None = None,
        next_page: str | None = None,
        page_size: int = DEFAULT_SIEM_PAGE_SIZE,
        max_retries: int = DEFAULT_RETRY_COUNT,
    ) -> dict[str, Any]:
        """
        Retrieves SIEM events from Mimecast.

        Args:
            event_type (str): The type of SIEM events to fetch.
            start_date (str | None): The start date in ISO 8601 format.
            next_page (str | None): Optional next page token for pagination.
            page_size (int): The number of items per page. Defaults to 100.
            max_retries (int): Maximum number of retries for rate limit errors. Defaults to 3.

        Raises:
            ClientResponseError: If the request fails.

        Returns:
            dict[str, Any]: A dictionary containing the SIEM events.
        """
        if not (start_date or next_page):
            raise ValueError("Either 'start_date' or 'next_page' should be specified.")

        params = assign_params(
            types=event_type,
            pageSize=page_size,
            dateRangeStartsAt=start_date,
            dateRangeEndsAt=end_date,
            nextPage=next_page,
        )

        demisto.debug(f"[{event_type}] Requesting SIEM events using {params=}.")

        response_json = await self._handle_request_with_retries(
            method="GET",
            endpoint="/siem/v1/events/cg",
            max_retries=max_retries,
            event_type=event_type,
            params=params,
        )

        events_count = len(response_json.get("value", []))
        demisto.debug(f"[{event_type}] Fetched {events_count} SIEM events using {params=}.")

        return response_json


""" HELPER FUNCTIONS """


def generate_event_id_if_not_exists(events: list[dict[str, Any]]):
    """
    Generates a unique SHA256 hash as the event ID if the `id` field does not exist in the event JSON.

    Args:
        events (list[dict[str, Any]]): The list of events to deduplicate.
    """
    for event in events:
        if EVENT_ID_KEY in event:
            continue

        # SIEM events do *not* have an "id" field, so we need to generate a unique hash for deduplication
        encoded_event: bytes = json.dumps(event, sort_keys=True).encode("utf-8")
        event_id = str(hashlib.sha256(encoded_event).hexdigest())
        event[EVENT_ID_KEY] = event_id
        demisto.debug(f"Generated a unique SHA256 {event_id=} using the contents of {event=}.")


def convert_to_audit_filter_format(filter_datetime: datetime) -> str:
    """
    Converts datetime object (e.g. 2025-12-24T11:23:41.955Z).

    Removes last colon from the time format.
    """
    return filter_datetime.strftime(AUDIT_DATE_FILTER_FORMAT)


def convert_to_siem_filter_format(filter_datetime: datetime) -> str:
    """
    Converts datetime object (e.g. 2025-12-24T11:23:41.955Z).

    Removes last colon from the time format.
    """
    return filter_datetime.strftime(SIEM_DATE_FILTER_FORMAT)[:-3] + "Z"


def is_within_last_24_hours(filter_datetime: datetime | str) -> bool:
    """
    Checks if a given timezone-aware datetime is within the last 24 hours.

    Args:
        filter_datetime (datetime | str): A datetime object or a string timestamp.

    Returns:
        bool: True if the datetime is within the last 24 hours, False otherwise.
    """
    if isinstance(filter_datetime, str):
        filter_datetime = cast(datetime, arg_to_datetime(filter_datetime, settings=DATEPARSER_SETTINGS))

    # Ensure the input datetime is timezone-aware
    if filter_datetime.tzinfo is None:
        demisto.debug(f"No timezone info in provided datetime object. Assuming {str(UTC)} timezone for comparison.")
        filter_datetime = filter_datetime.replace(tzinfo=timezone.utc)

    # Calculate the time 24 hours ago
    twenty_four_hours_ago = UTC_NOW - timedelta(hours=24)

    # Check if the target datetime is after or equal to the time 24 hours ago
    return filter_datetime >= twenty_four_hours_ago


def deduplicate_and_format_events(
    events: list[dict[str, Any]],
    all_fetched_ids: set[str],
    event_time_key: str,
    event_type: str,
    filter_format_func: Callable[[datetime], str],
) -> list[dict[str, Any]]:
    """
    Deduplicates raw events based on a unique identifier and formats them by adding `_time` and `_source_log_type` fields.

    Args:
        events (list[dict[str, Any]]): List of raw events.
        all_fetched_ids (set[str]): Set of event IDs that have already been fetched.
        event_time_key (str): Key denoting the occurrence time of the each raw event (for deduplication and formatting).
        event_type (str): Type of event (either "Audit" or "SIEM log").
        filter_format_func (Callable[[datetime], str]): Function formats a datetime object as a string (for deduplication).

    Returns:
        list[dict[str, Any]]: A list of deduplicated events.
    """
    demisto.debug(f"[{event_type}] Starting to deduplicate {len(events)} events.")
    if not events:
        demisto.debug(f"[{event_type}] No events to deduplicate. Returning empty list.")
        return []

    generate_event_id_if_not_exists(events)
    deduplicated_events = []

    for event in events:
        event_id = event[EVENT_ID_KEY]

        if event_id in all_fetched_ids:
            demisto.debug(f"[{event_type}] Skipping duplicate {event_id=}.")
            continue

        event_time = cast(datetime, arg_to_datetime(event[event_time_key], required=True))

        # For dataset
        event[EVENT_TIME_KEY] = event_time.strftime(EVENTS_DATE_FORMAT)
        event[SOURCE_LOG_TYPE_KEY] = event_type
        # For last run (will be removed before sending to dataset)
        event[FILTER_TIME_KEY] = filter_format_func(event_time)

        all_fetched_ids.add(event_id)
        deduplicated_events.append(event)

    demisto.debug(f"[{event_type}] Finished deduplicating {len(events)} events. Got {len(deduplicated_events)} unique events.")
    return deduplicated_events


async def get_audit_events(
    client: AsyncClient,
    start_date: str,
    end_date: str,
    limit: int,
    last_fetched_ids: list[str] | None = None,
) -> list[dict[str, Any]]:
    """
    Asynchronously fetches audit events from Mimecast for a specific time range.

    Args:
        client (AsyncClient): An instance of the AsyncClient.
        start_date (str): The start time in Mimecast format.
        end_date (str): The end time in Mimecast format.
        limit (int): The maximum number of events to retrieve.
        last_fetched_ids (list[str]): A list of IDs of events that have already been fetched.

    Returns:
        list[dict[str, Any]]: List of audit events.
    """
    last_fetched_ids = last_fetched_ids or []
    all_fetched_ids = set(last_fetched_ids)
    all_events: list[dict[str, Any]] = []
    page_number: int = 0
    next_page: str | None = None

    demisto.debug(f"Fetching audit events between {start_date=} and {end_date=}.")
    while len(all_events) < limit:
        page_number += 1
        page_size = min(DEFAULT_AUDIT_PAGE_SIZE, (limit - len(all_events)))

        response = await client.get_audit_events(
            start_date=start_date,
            end_date=end_date,
            next_page=next_page,
            page_size=page_size,
        )

        # Check for errors (if any) under "fail" key in audit endpoint
        if errors := response.get(IS_FAIL):
            raise DemistoException(f"Audit events API call failed with {errors=}.")

        page_events = response.get("data", [])
        next_page = response.get("meta", {}).get("pagination", {}).get("next")

        # Process and deduplicate events
        deduplicated_events = deduplicate_and_format_events(
            page_events,
            all_fetched_ids,
            event_time_key=AUDIT_TIME_KEY,
            event_type="audit",
            filter_format_func=convert_to_audit_filter_format,
        )
        all_events.extend(deduplicated_events)

        # If number of page events is less than requested page size *or* no next page, assume no more events to fetch
        if len(page_events) < page_size or next_page is None:
            demisto.debug(
                f"No more audit events available after {page_number=}. "
                f"Got {len(page_events)} page events and {next_page=}. Breaking..."
            )
            break

        if len(all_events) >= limit:
            demisto.debug(f"Reached {limit=} for audit events on {page_number=}. Breaking...")
            break

    demisto.debug(
        f"Finished fetching {len(all_events)} audit events from {page_number} pages " f"between {start_date=} and {end_date=}."
    )
    return sorted(all_events, key=lambda item: item[FILTER_TIME_KEY])


async def get_siem_events(
    client: AsyncClient,
    event_type: str,
    start_date: str | None,
    limit: int,
    last_fetched_ids: list[str] | None = None,
    end_date: str | None = None,
    next_page: str | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    """
    Asynchronously fetches SIEM events from Mimecast for a specific SIEM event type.

    Args:
        client (AsyncClient): An instance of the AsyncClient.
        event_type (str): The SIEM event type.
        start_date (str | None): The start date in ISO 8601 format.
        limit (int): The maximum number of events to retrieve.
        last_fetched_ids (list[str]): A list of IDs of events that have already been fetched.
        next_page (str | None): The last next page token.

    Returns:
        tuple[list[dict[str, Any]], str | None]: Tuple of a list of SIEM events and new next page token.
    """
    last_fetched_ids = last_fetched_ids or []
    all_fetched_ids = set(last_fetched_ids)
    all_events: list[dict[str, Any]] = []
    page_number: int = 0

    demisto.debug(f"[{event_type}] Starting to fetch SIEM events between {start_date=} and {end_date=} with {next_page=}.")
    while len(all_events) < limit:
        page_number += 1
        page_size = min(DEFAULT_SIEM_PAGE_SIZE, (limit - len(all_events)))

        response = await client.get_siem_events(
            event_type=event_type,
            start_date=start_date,
            end_date=end_date,
            next_page=next_page,
            page_size=page_size,
        )

        # Check for errors (if any) under "error" key in SIEM endpoint
        if errors := response.get(IS_ERROR):
            raise DemistoException(f"[{event_type}] SIEM events API call failed with {errors=}.")

        page_events = response.get("value", [])
        next_page = response.get("@nextPage")

        # Process and deduplicate events
        deduplicated_events = deduplicate_and_format_events(
            page_events,
            all_fetched_ids,
            event_time_key=SIEM_TIME_KEY,
            event_type=event_type,
            filter_format_func=convert_to_siem_filter_format,
        )
        all_events.extend(deduplicated_events)

        # If number of page events is less than requested page size *or* no next page, assume no more events to fetch
        if len(page_events) < page_size or next_page is None:
            demisto.debug(
                f"[{event_type}] No more SIEM events available after {page_number=}. "
                f"Got {len(page_events)} page events and {next_page=}. Breaking..."
            )
            break

        if len(all_events) >= limit:
            demisto.debug(f"[{event_type}] Reached {limit=} for SIEM events on {page_number=}. Breaking...")
            break

    demisto.debug(
        f"[{event_type}] Finished fetching {len(all_events)} SIEM events from {page_number} pages "
        f"between {start_date=} and {end_date=}. Got {next_page=}."
    )
    return sorted(all_events, key=lambda item: item[FILTER_TIME_KEY]), next_page


""" COMMAND FUNCTIONS """


async def test_module(client: AsyncClient, event_types: list[str]) -> str:
    """
    Tests the connection to the Mimecast API.

    Args:
        client (AsyncClient): An instance of the AsyncClient.
        event_types (list[str]): List of event types to test.

    Returns:
        str: "ok" if connection succeeded.
    """
    demisto.debug(f"Starting test module using {event_types=}.")

    # Test Audit events
    if "audit" in event_types:
        audit_start_date = convert_to_audit_filter_format(UTC_MINUTE_AGO)
        audit_end_date = convert_to_audit_filter_format(UTC_NOW)
        demisto.debug(f"Testing fetching of audit events from {audit_start_date=} to {audit_end_date=}.")
        await get_audit_events(
            client,
            start_date=audit_start_date,
            end_date=audit_end_date,
            limit=1,
        )

    # Test SIEM events
    siem_event_types = [event_type for event_type in event_types if event_type != "audit"]
    if siem_event_types:
        siem_start_date = convert_to_siem_filter_format(UTC_MINUTE_AGO)
        demisto.debug(f"Testing fetching of SIEM events from {siem_start_date=} with {siem_event_types=}.")
        siem_tasks = [
            get_siem_events(
                client,
                event_type=event_type,
                start_date=siem_start_date,
                limit=1,
            )
            for event_type in siem_event_types
        ]
        await asyncio.gather(*siem_tasks)

    demisto.debug("Test module completed successfully.")
    return "ok"


async def get_events_command(client: AsyncClient, args: dict[str, Any]) -> tuple[list[dict[str, Any]], list[CommandResults]]:
    """
    Implements the `mimecast-get-events` command. Gets events using the AsyncClient.

    Args:
        client (AsyncClient): An instance of the AsyncClient.
        args (dict[str, Any]): The command arguments.

    Returns:
        tuple[list[dict[str, Any]], list[CommandResults]]: A tuple of the events list and the CommandResults list.
    """
    limit = arg_to_number(args.get("limit")) or DEFAULT_GET_EVENTS_LIMIT  # limit is per event type
    event_types = argToList(args.get("event_types")) or DEFAULT_EVENT_TYPES

    start_date = arg_to_datetime(args.get("start_date"), settings=DATEPARSER_SETTINGS) or UTC_HOUR_AGO
    end_date = arg_to_datetime(args.get("end_date"), settings=DATEPARSER_SETTINGS) or UTC_NOW

    demisto.debug(f"Starting to get events with {limit=} and {event_types=}.")
    all_events: list[dict[str, Any]] = []
    command_results: list[CommandResults] = []

    # Fetch audit events
    if "audit" in event_types:
        audit_start_date = convert_to_audit_filter_format(start_date)
        audit_end_date = convert_to_audit_filter_format(end_date)

        demisto.debug(f"Getting audit events between {audit_start_date=} and {audit_end_date=} with {limit=}.")
        audit_events = await get_audit_events(client, start_date=audit_start_date, end_date=audit_end_date, limit=limit)
        demisto.debug(f"Got {len(audit_events)} audit events between {audit_start_date=} and {audit_end_date=}.")

        all_events.extend(audit_events)
        human_readable = tableToMarkdown(name="Mimecast Audit Events", t=audit_events)
        command_results.append(CommandResults(readable_output=human_readable))

    # Fetch SIEM events
    siem_event_types = [event_type for event_type in event_types if event_type != "audit"]
    if siem_event_types:
        if not (is_within_last_24_hours(start_date) and is_within_last_24_hours(end_date)):
            human_readable = "The 'start_date' and 'end_date' arguments must be within the last 24 hours to get SIEM events."
            command_results.append(CommandResults(readable_output=human_readable, entry_type=EntryType.ERROR))
        else:
            siem_start_date = convert_to_siem_filter_format(start_date)
            siem_end_date = convert_to_siem_filter_format(end_date)

            demisto.debug(f"Getting audit events between {siem_start_date=} and {siem_end_date=} with {limit=}.")
            siem_tasks = [
                get_siem_events(client, event_type=event_type, start_date=siem_start_date, end_date=siem_end_date, limit=limit)
                for event_type in siem_event_types
            ]
            siem_results = await asyncio.gather(*siem_tasks)
            # Flatten the list of lists
            siem_events = []
            for siem_result in siem_results:
                event_type_events, _ = siem_result
                siem_events.extend(event_type_events)
            demisto.debug(f"Got {len(siem_events)} SIEM events between {siem_start_date=} and {siem_end_date=}.")

            all_events.extend(siem_events)
            human_readable = tableToMarkdown(name="Mimecast SIEM Events", t=siem_events)
            command_results.append(CommandResults(readable_output=human_readable))

    demisto.debug(f"Got {len(all_events)} events in total with {limit=} and {event_types=}.")
    return all_events, command_results


async def fetch_audit_events(
    client: AsyncClient,
    audit_last_run: dict,
    max_fetch: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """
    Fetches audit events from Mimecast.

    Args:
        client (AsyncClient): An instance of the AsyncClient.
        audit_last_run (dict): The last run object containing audit event state.
        max_fetch (int): The maximum number of events to fetch.

    Returns:
        tuple[dict[str, Any], list[dict[str, Any]]]: A tuple of (next_run_state, fetched_events).
    """
    demisto.debug(f"Starting to fetch audit events. Got {audit_last_run=}.")
    start_date = audit_last_run.get(START_DATE_KEY) or convert_to_audit_filter_format(UTC_MINUTE_AGO)
    end_date = convert_to_audit_filter_format(UTC_NOW)
    last_fetched_ids = audit_last_run.get(LAST_FETCHED_IDS_KEY, [])

    demisto.debug(f"Fetching audit events using {start_date=}, {end_date=}, {max_fetch=}.")
    # Fetch audit events
    audit_events = await get_audit_events(
        client,
        start_date=start_date,
        end_date=end_date,
        limit=max_fetch,
        last_fetched_ids=last_fetched_ids,
    )

    # Update next run state
    if not audit_events:
        demisto.debug(f"No new audit events found. Keeping {audit_last_run=}.")
        return audit_last_run, []

    new_start_time = audit_events[-1].get(FILTER_TIME_KEY)
    new_last_fetched_ids = [event.get(EVENT_ID_KEY) for event in audit_events if event.pop(FILTER_TIME_KEY) == new_start_time]
    audit_next_run = {START_DATE_KEY: new_start_time, LAST_FETCHED_IDS_KEY: new_last_fetched_ids}

    demisto.debug(f"Finished fetching {len(audit_events)} audit events " f"with {new_start_time=}, {new_last_fetched_ids=}.")
    return audit_next_run, audit_events


async def fetch_siem_events(
    client: AsyncClient,
    siem_last_run: dict,
    max_fetch: int,
    event_types: list[str],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """
    Fetches SIEM events from Mimecast for all configured event types concurrently.

    Args:
        client (AsyncClient): An instance of the AsyncClient.
        last_run (dict): The last run object containing SIEM event states for each type.
        max_fetch (int): The maximum number of events to fetch per event type.
        event_types (list[str]): List of SIEM event types to fetch.

    Returns:
        tuple[dict[str, Any], list[dict[str, Any]]]: A tuple of (next_run, all_fetched_events).
    """
    demisto.debug(f"Starting to fetch SIEM events for {event_types=}. Got {siem_last_run=}")

    default_start_date = convert_to_siem_filter_format(UTC_MINUTE_AGO)
    all_events: list[dict[str, Any]] = []
    siem_next_run: dict[str, Any] = {}

    # Prepare SIEM tasks for concurrent fetching
    siem_tasks = []
    for event_type in event_types:
        event_type_last_run = siem_last_run.get(event_type, {})
        last_fetched_ids = event_type_last_run.get(LAST_FETCHED_IDS_KEY, [])
        start_date = event_type_last_run.get(START_DATE_KEY) or default_start_date
        next_page = event_type_last_run.get(NEXT_PAGE_KEY)

        # Ensure the start date within than 24 hours to avoid HTTP 400 (bad request) errors from SIEM API endpoint
        # If no events were fetched within the last 24 hours, the start date may not be within the allowed API range
        if not is_within_last_24_hours(start_date):
            demisto.info(f"[{event_type}] {start_date=} is older than 24 hours. Skipping forward to last 23 hours.")
            start_date = convert_to_siem_filter_format(UTC_NOW - timedelta(hours=23))

        demisto.debug(f"[{event_type}] Creating task to fetch SIEM events using {start_date=}, {next_page=}, {max_fetch=}.")
        # Create async task
        siem_tasks.append(
            get_siem_events(
                client,
                event_type=event_type,
                start_date=start_date,
                limit=max_fetch,
                last_fetched_ids=last_fetched_ids,
                next_page=next_page,
            )
        )

    demisto.debug(f"Fetching SIEM events concurrently for {len(siem_tasks)} event types.")

    # Execute all SIEM fetches concurrently
    siem_results = await asyncio.gather(*siem_tasks, return_exceptions=True)

    # Process results
    for event_type, result in zip(event_types, siem_results):
        event_type_last_run = siem_last_run.get(event_type, {})

        # Handle exceptions
        if isinstance(result, Exception):
            error_traceback = "".join(traceback.format_exception(type(result), result, result.__traceback__))
            demisto.error(
                f"[{event_type}] Failed to fetch SIEM events. Keeping Keeping {event_type_last_run=}. Got {error_traceback=}."
            )
            siem_next_run[event_type] = event_type_last_run
            continue

        event_type_events, new_next_page = cast(tuple[list, str], result)

        # Handle empty results
        if not event_type_events:
            demisto.debug(f"[{event_type}] No new SIEM events found. Keeping {event_type_last_run=}.")
            siem_next_run[event_type] = event_type_last_run
            continue

        # Update state with newest events
        new_start_time = event_type_events[-1].get(FILTER_TIME_KEY)
        new_last_fetched_ids = [
            event.get(EVENT_ID_KEY) for event in event_type_events if event.pop(FILTER_TIME_KEY) == new_start_time
        ]
        siem_next_run[event_type] = {
            START_DATE_KEY: new_start_time,
            LAST_FETCHED_IDS_KEY: new_last_fetched_ids,
            NEXT_PAGE_KEY: new_next_page,
        }

        all_events.extend(event_type_events)
        demisto.debug(
            f"[{event_type}] Fetched {len(event_type_events)} SIEM events "
            f"with {new_start_time=}, {new_next_page=}, {new_last_fetched_ids=}."
        )

    demisto.debug(f"Finished fetching {len(all_events)} SIEM events from {len(event_types)} SIEM event types.")
    return siem_next_run, all_events


def ensure_new_last_run_schema(last_run: dict) -> dict[str, Any]:
    """
    Migrates the old last run schema (API 1.0) to the new schema (API 2.0) if needed.

    Args:
        last_run (dict): The old last run object.
        event_types (list[str]): List of event types to migrate.

    Returns:
        dict[str, Any]: The migrated last run object in the new schema.
    """
    demisto.debug(f"Ensuring new schema for {last_run=}.")

    if not last_run:
        demisto.debug("Got empty last run. Skipping migration to new last run schema.")
        return {}

    deprecated_last_run_keys = {
        DEPRECATED_AUDIT_LAST_FETCHED_IDS_KEY,
        DEPRECATED_AUDIT_START_DATE_KEY,
        DEPRECATED_SIEM_NEXT_PAGE_KEY,
        DEPRECATED_SIEM_LAST_FETCHED_IDS_KEY,
    }
    if not any(key in last_run for key in deprecated_last_run_keys):
        demisto.debug("Last run is already in the new schema.")
        return last_run  # return last run without any change if it is in the new schema

    new_last_run: dict[str, Any] = {}

    # Migrate audit events
    if DEPRECATED_AUDIT_START_DATE_KEY in last_run:
        demisto.info("Detected old audit last run schema.")
        try:
            old_audit_start_date = cast(datetime, arg_to_datetime(last_run.get(DEPRECATED_AUDIT_START_DATE_KEY)))
            new_last_run["audit"] = {
                START_DATE_KEY: convert_to_audit_filter_format(old_audit_start_date),
                LAST_FETCHED_IDS_KEY: last_run.get(DEPRECATED_AUDIT_LAST_FETCHED_IDS_KEY, []),
            }
            demisto.info(f"Successfully migrated audit previous run schema to {new_last_run['audit']}.")
        except (ValueError, AttributeError):
            # `arg_to_datetime` throws an exception if value is not a valid datetime string / timestamp
            demisto.error("Could not migrate audit previous run schema. Failed to parse audit start date.")

    # Migrate SIEM events
    if DEPRECATED_SIEM_NEXT_PAGE_KEY in last_run:  # API V1.0 next page token (incompatible with API 2.0 next page token)
        demisto.info("Detected old SIEM last run schema.")
        demisto.error("SIEM last run cannot be migrated to new schema due to next page token incompatibility.")
        new_last_run["siem"] = {}  # initialize to empty dict

    demisto.info(f"Finished migrating last run to new schema {new_last_run=}.")
    return new_last_run


async def fetch_events_command(
    client: AsyncClient,
    last_run: dict,
    max_fetch: int,
    event_types: list[str],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """
    Implements `fetch-events` command. Orchestrates concurrent fetching of both audit and SIEM events.

    Args:
        client (AsyncClient): An instance of the AsyncClient.
        last_run (dict): The last run object.
        max_fetch (int): The maximum number of events to fetch.
        event_types (list[str]): List of event types to fetch.

    Returns:
        tuple[dict[str, Any], list[dict[str, Any]]]: A tuple of next run dictionary and all events list.
    """
    demisto.debug(f"Starting to fetch events with {max_fetch=} and {len(event_types)} event types. Got {last_run=}.")

    # Detect and migrate old last run schema (API 1.0) to new schema (API 2.0)
    last_run = ensure_new_last_run_schema(last_run)

    next_run = {}
    all_events = []

    if "audit" in event_types:
        audit_last_run = last_run.get("audit", {})
        audit_next_run, audit_events = await fetch_audit_events(client, audit_last_run, max_fetch)
        next_run["audit"] = audit_next_run
        all_events.extend(audit_events)

    siem_event_types = [event_type for event_type in event_types if event_type != "audit"]
    if siem_event_types:
        siem_last_run = last_run.get("siem", {})
        siem_next_run, siem_events = await fetch_siem_events(client, siem_last_run, max_fetch, siem_event_types)
        next_run["siem"] = siem_next_run
        all_events.extend(siem_events)

    demisto.debug(f"Finished fetching events. Got {len(all_events)} total events. Updating {next_run=}.")
    return next_run, all_events


""" MAIN FUNCTION """


async def main() -> None:  # pragma: no cover
    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()
    command: str = demisto.command()

    # HTTP Connection
    base_url: str = params.get("base_url", DEFAULT_BASE_URL).rstrip("/")
    verify: bool = not params.get("insecure", False)
    proxy: bool = params.get("proxy", False)

    # OAuth Credentials
    client_id: str = params.get("client_credentials", {}).get("identifier", "")
    client_secret: str = params.get("client_credentials", {}).get("password", "")

    # Fetch Events
    max_fetch: int = arg_to_number(params.get("max_fetch")) or DEFAULT_FETCH_EVENTS_LIMIT
    event_types: list = argToList(params.get("event_types")) or DEFAULT_EVENT_TYPES

    demisto.debug(f"Command being called is {command!r}.")

    try:
        async with AsyncClient(
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
            verify=verify,
            proxy=proxy,
        ) as async_client:
            if command == "test-module":
                return_results(await test_module(async_client, event_types=event_types))

            elif command == "mimecast-get-events":
                should_push_events = argToBoolean(args.pop("should_push_events", False))
                events, command_results = await get_events_command(async_client, args)
                return_results(command_results)
                if should_push_events:
                    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

            elif command == "fetch-events":
                last_run = demisto.getLastRun()
                next_run, events = await fetch_events_command(
                    async_client,
                    last_run=last_run,
                    max_fetch=max_fetch,
                    event_types=event_types,
                )
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
                demisto.setLastRun(next_run)

            else:
                raise NotImplementedError(f"Command {command!r} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    asyncio.run(main())
