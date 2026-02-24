import asyncio
import aiohttp
import hashlib
import traceback
from enum import Enum
from types import DynamicClassAttribute
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from http import HTTPStatus
from typing import cast, Any
from collections.abc import Awaitable, Callable
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

# Default limit values
DEFAULT_GET_EVENTS_LIMIT = 10
DEFAULT_FETCH_EVENTS_LIMIT = 1000

# Default dates
UTC_NOW = datetime.now(tz=UTC)
UTC_HOUR_AGO = UTC_NOW - timedelta(hours=1)
UTC_MINUTE_AGO = UTC_NOW - timedelta(minutes=1)
UTC_WEEK_AGO = UTC_NOW - timedelta(days=7)

# Event ID field (for deduplication)
EVENT_ID_KEY = "id"  # generated if not exists

# Last run fields
START_DATE_KEY = "start_date"
LAST_FETCHED_IDS_KEY = "last_fetched_ids"
NEXT_PAGE_KEY = "next_page"


class EventTypes(Enum):
    AUDIT = "audit"
    SIEM = "siem"

    @classmethod
    def all_values(cls) -> list[str]:
        return [member.value for member in cls]

    @DynamicClassAttribute
    def endpoint(self) -> str:
        mapping = {"audit": "/api/audit/get-audit-events", "siem": "/siem/v1/events/cg"}
        return mapping[self.value]

    @DynamicClassAttribute
    def log_prefix(self) -> str:
        return "[" + self.value.upper() + "]"

    @DynamicClassAttribute
    def source_log_type(self) -> str:
        mapping = {"audit": "Audit", "siem": "SIEM"}
        return mapping[self.value]

    @DynamicClassAttribute
    def filter_format_func(self) -> Callable[[datetime], str]:
        mapping = {"audit": convert_to_audit_filter_format, "siem": convert_to_siem_filter_format}
        return mapping[self.value]

    @DynamicClassAttribute
    def event_time_key(self) -> str:
        mapping = {"audit": "eventTime", "siem": "timestamp"}
        return mapping[self.value]

    @DynamicClassAttribute
    def default_page_size(self) -> int:
        mapping = {"audit": 500, "siem": 100}
        return mapping[self.value]


DATEPARSER_SETTINGS = {"RETURN_AS_TIMEZONE_AWARE": True, "TIMEZONE": str(UTC)}

""" CLIENT CLASS """


class AsyncClient:
    """An asynchronous client for interacting with the Mimecast API; used for SIEM event collection"""

    def __init__(self, base_url: str, client_id: str, client_secret: str, verify: bool, proxy: bool):
        self.base_url = base_url
        self._client_id = client_id
        self._client_secret = client_secret
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
        # Pre-validate to avoid failed API calls due to empty of incomplete OAuth2 client credentials
        if not (self._client_id and self._client_secret):
            raise DemistoException(
                "Empty or incomplete OAuth2 credentials. Specify valid 'Client ID' and 'Client Secret' parameters."
            )

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
            token_ttl = token_response.get(TOKEN_TTL_KEY, DEFAULT_TOKEN_TTL)
            token_response[TOKEN_VALID_UNTIL_KEY] = (UTC_NOW + timedelta(seconds=token_ttl)).isoformat()
            demisto.debug("Saving new access token in integration context.")
            set_integration_context(token_response)

        demisto.debug(f"Constructed Authorization header using {token_type=}.")
        return f"{token_type.capitalize()} {access_token}"

    async def _handle_request_with_retries(
        self,
        method: str,
        event_type: EventTypes,
        max_retries: int,
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
        log_prefix = event_type.log_prefix
        url = urljoin(self.base_url, event_type.endpoint)
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

                # Handle 401 Unauthorized - regenerate token and retry once and return
                if status_code == HTTPStatus.UNAUTHORIZED:
                    demisto.debug(f"{log_prefix} Received HTTP 401 Unauthorized. Generating new token and retrying...")
                    headers["Authorization"] = await self.get_authorization_header(force_generate_new_token=True)
                    # Retry immediately with new token
                    async with self._session.request(method=method, url=url, headers=headers, **request_kwargs) as response:
                        response_json = await response.json()
                        response.raise_for_status()
                        return response_json

                # Handle 429 Too Many Requests - retry up to `max_retries` with exponential backoff
                elif status_code == HTTPStatus.TOO_MANY_REQUESTS:
                    if retry_count >= max_retries:
                        raise
                    wait_time = 2**retry_count  # Exponential backoff: 1s, 2s, 4s
                    demisto.debug(
                        f"{log_prefix} Received HTTP 429 Too Many Requests. "
                        f"Retrying {retry_count + 1} of {max_retries} after {wait_time} seconds..."
                    )
                    await asyncio.sleep(wait_time)
                    retry_count += 1

                # Handle other errors - don't retry
                else:
                    demisto.error(
                        f"{log_prefix} {e.request_info.method} Request failed to {e.request_info.url}. "
                        f"Got {status_code=} and {response_json=}."
                    )
                    raise DemistoException(f"Request to {e.request_info.url} failed with HTTP {e.status} status.") from e

        # Should not reach here, but just in case
        raise DemistoException(f"{log_prefix} Failed after {max_retries} retries.")

    async def get_audit_events(
        self,
        start_date: str,
        end_date: str,
        next_page: str | None = None,
        page_size: int = EventTypes.AUDIT.default_page_size,
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
        log_prefix = EventTypes.AUDIT.log_prefix
        payload = {
            "data": [{"startDateTime": start_date, "endDateTime": end_date}],
            "meta": {"pagination": assign_params(pageSize=page_size, pageToken=next_page)},
        }

        demisto.debug(f"{log_prefix} Requesting events using {payload=}.")

        response_json = await self._handle_request_with_retries(
            method="POST",
            event_type=EventTypes.AUDIT,
            max_retries=max_retries,
            json=payload,
        )

        events_count = len(response_json.get("data", []))
        demisto.debug(f"{log_prefix} Fetched {events_count} events using {payload=}.")

        return response_json

    async def get_siem_events(
        self,
        start_date: str | None = None,
        end_date: str | None = None,
        next_page: str | None = None,
        page_size: int = EventTypes.SIEM.default_page_size,
        max_retries: int = DEFAULT_RETRY_COUNT,
    ) -> dict[str, Any]:
        """
        Retrieves SIEM logs from Mimecast.

        Args:
            start_date (str | None): The start date in ISO 8601 format.
            next_page (str | None): Optional next page token for pagination.
            page_size (int): The number of items per page. Defaults to 100.
            max_retries (int): Maximum number of retries for rate limit errors. Defaults to 3.

        Raises:
            ClientResponseError: If the request fails.

        Returns:
            dict[str, Any]: A dictionary containing the SIEM logs.
        """
        log_prefix = EventTypes.SIEM.log_prefix
        if not (start_date or next_page):
            raise ValueError("Either 'start_date' or 'next_page' should be specified.")

        params = assign_params(
            pageSize=page_size,
            dateRangeStartsAt=start_date,
            dateRangeEndsAt=end_date,
            nextPage=next_page,
        )

        demisto.debug(f"{log_prefix} Requesting events using {params=}.")

        response_json = await self._handle_request_with_retries(
            method="GET",
            event_type=EventTypes.SIEM,
            max_retries=max_retries,
            params=params,
        )

        events_count = len(response_json.get("value", []))
        demisto.debug(f"{log_prefix} Fetched {events_count} events using {params=}.")

        return response_json


""" HELPER FUNCTIONS """


def generate_event_id_if_not_exists(events: list[dict[str, Any]], event_type: EventTypes):
    """
    Generates a unique SHA256 hash as the event ID if the `id` field does not exist in the event JSON.

    Args:
        events (list[dict[str, Any]]): The list of events to deduplicate.
    """
    log_prefix = event_type.log_prefix
    for event in events:
        if EVENT_ID_KEY in event:
            continue

        # SIEM logs do *not* have an "id" field, so we need to generate a unique hash for deduplication
        event_copy = event.copy()
        encoded_event: bytes = json.dumps(event_copy, sort_keys=True).encode("utf-8")
        event_id = str(hashlib.sha256(encoded_event).hexdigest())
        event[EVENT_ID_KEY] = event_id
        demisto.debug(f"{log_prefix} Generated a unique SHA256 {event_id=} using the contents of {event=}.")


def convert_to_audit_filter_format(filter_datetime: datetime) -> str:
    """
    Converts datetime object to the `AUDIT_DATE_FILTER_FORMAT` (e.g. 2025-12-24T11:23:41.955Z).

    Removes last colon from the time format.
    """
    return filter_datetime.strftime(AUDIT_DATE_FILTER_FORMAT)


def convert_to_siem_filter_format(filter_datetime: datetime) -> str:
    """
    Converts datetime object to the `SIEM_DATE_FILTER_FORMAT` (e.g. 2025-12-24T11:23:41.955Z).

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
        # Datetime object will be returned since it is set as `required=True`
        filter_datetime = cast(datetime, arg_to_datetime(filter_datetime, settings=DATEPARSER_SETTINGS, required=True))

    # Ensure the input datetime is timezone-aware
    if filter_datetime.tzinfo is None:
        demisto.debug(f"No timezone info in provided datetime object. Assuming {str(UTC)} timezone for comparison.")
        filter_datetime = filter_datetime.replace(tzinfo=timezone.utc)

    # Calculate the time 24 hours ago
    twenty_four_hours_ago = UTC_NOW - timedelta(hours=24)

    # Check if the target datetime is after or equal to the time 24 hours ago
    return filter_datetime >= twenty_four_hours_ago


def deduplicate_and_format_events(events: list[dict], all_fetched_ids: set[str], event_type: EventTypes) -> list[dict]:
    """
    Deduplicates raw events based on a unique identifier and formats them by adding `_time` and `_source_log_type` fields.

    Args:
        events (list[dict]): List of raw events.
        all_fetched_ids (set[str]): Set of event IDs that have already been fetched.
        event_time_key (str): Key denoting the occurrence time of the each raw event (for deduplication and formatting).
        event_type (str): Type of event (either "Audit" or "SIEM log").

    Returns:
        list[dict]: A list of deduplicated events.
    """
    log_prefix = event_type.log_prefix
    demisto.debug(f"{log_prefix} Starting to deduplicate {len(events)} events.")
    if not events:
        demisto.debug(f"{log_prefix} No events to deduplicate. Returning empty list.")
        return []

    generate_event_id_if_not_exists(events, event_type)
    deduplicated_events = []

    for event in events:
        event_id = event[EVENT_ID_KEY]

        if event_id in all_fetched_ids:
            demisto.debug(f"{log_prefix} Skipping duplicate {event_id=}.")
            continue

        event_time_key = event_type.event_time_key
        event_time = cast(datetime, arg_to_datetime(event[event_time_key], required=True))

        # For dataset
        event[EVENT_TIME_KEY] = event_time.strftime(EVENTS_DATE_FORMAT)
        event[SOURCE_LOG_TYPE_KEY] = event_type.source_log_type
        # For last run (will be removed before sending to dataset)
        event[FILTER_TIME_KEY] = event_type.filter_format_func(event_time)

        all_fetched_ids.add(event_id)
        deduplicated_events.append(event)

    demisto.debug(f"{log_prefix} Finished deduplicating {len(events)} events. Got {len(deduplicated_events)} unique events.")
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
    log_prefix = EventTypes.AUDIT.log_prefix
    last_fetched_ids = last_fetched_ids or []
    all_fetched_ids = set(last_fetched_ids)
    all_events: list[dict[str, Any]] = []
    page_number: int = 0
    next_page: str | None = None

    demisto.debug(f"{log_prefix} Fetching events between {start_date=} and {end_date=}.")
    while len(all_events) < limit:
        page_number += 1
        page_size = min(EventTypes.AUDIT.default_page_size, (limit - len(all_events)))

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
            event_type=EventTypes.AUDIT,
        )
        all_events.extend(deduplicated_events)

        # If number of page events is less than requested page size *or* no next page, assume no more events to fetch
        if len(page_events) < page_size or next_page is None:
            demisto.debug(
                f"{log_prefix} No more events available after {page_number=}. "
                f"Got {len(page_events)} page events and {next_page=}. Breaking..."
            )
            break

        if len(all_events) >= limit:
            demisto.debug(f"{log_prefix} Reached {limit=} on {page_number=}. Breaking...")
            break

    demisto.debug(
        f"{log_prefix} Finished fetching {len(all_events)} events from {page_number} pages "
        f"between {start_date=} and {end_date=}."
    )
    return sorted(all_events, key=lambda item: item[FILTER_TIME_KEY])


async def get_siem_events(
    client: AsyncClient,
    start_date: str | None,
    limit: int,
    last_fetched_ids: list[str] | None = None,
    end_date: str | None = None,
    next_page: str | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    """
    Asynchronously fetches SIEM logs from Mimecast for a specific SIEM event type.

    Args:
        client (AsyncClient): An instance of the AsyncClient.
        event_type (str): The SIEM event type.
        start_date (str | None): The start date in ISO 8601 format.
        limit (int): The maximum number of events to retrieve.
        last_fetched_ids (list[str]): A list of IDs of events that have already been fetched.
        next_page (str | None): The last next page token.

    Returns:
        tuple[list[dict[str, Any]], str | None]: Tuple of a list of SIEM logs and new next page token.
    """
    log_prefix = EventTypes.SIEM.log_prefix
    last_fetched_ids = last_fetched_ids or []
    all_fetched_ids = set(last_fetched_ids)
    all_events: list[dict[str, Any]] = []
    page_number: int = 0

    demisto.debug(f"{log_prefix} Starting to fetch SIEM logs between {start_date=} and {end_date=} with {next_page=}.")
    while len(all_events) < limit:
        page_number += 1
        page_size = min(EventTypes.SIEM.default_page_size, (limit - len(all_events)))

        response = await client.get_siem_events(
            start_date=start_date,
            end_date=end_date,
            next_page=next_page,
            page_size=page_size,
        )

        # Check for errors (if any) under "error" key in SIEM endpoint
        if errors := response.get(IS_ERROR):
            raise DemistoException(f"{log_prefix} API call failed with {errors=}.")

        page_events = response.get("value", [])
        next_page = response.get("@nextPage")

        # Process and deduplicate events
        deduplicated_events = deduplicate_and_format_events(
            page_events,
            all_fetched_ids,
            event_type=EventTypes.SIEM,
        )
        all_events.extend(deduplicated_events)

        # If number of page events is less than requested page size *or* no next page, assume no more events to fetch
        if len(page_events) < page_size or next_page is None:
            demisto.debug(
                f"{log_prefix} No more events available after {page_number=}. "
                f"Got {len(page_events)} page events and {next_page=}. Breaking..."
            )
            break

        if len(all_events) >= limit:
            demisto.debug(f"{log_prefix} Reached {limit=} on {page_number=}. Breaking...")
            break

    demisto.debug(
        f"{log_prefix} Finished fetching {len(all_events)} events from {page_number} pages "
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

    await fetch_events_command(client, last_run={}, max_fetch=1, event_types=event_types, audit_first_fetch=UTC_MINUTE_AGO)

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
    event_types = argToList(args.get("event_types"), transform=lambda x: x.lower()) or EventTypes.all_values()

    start_date = arg_to_datetime(args.get("start_date"), settings=DATEPARSER_SETTINGS) or UTC_HOUR_AGO
    end_date = arg_to_datetime(args.get("end_date"), settings=DATEPARSER_SETTINGS) or UTC_NOW

    demisto.debug(f"Starting to get events with {limit=} and {event_types=}.")
    all_events: list[dict[str, Any]] = []
    command_results: list[CommandResults] = []

    # Fetch audit events
    if EventTypes.AUDIT.value in event_types:
        log_prefix = EventTypes.AUDIT.log_prefix
        audit_start_date = convert_to_audit_filter_format(start_date)
        audit_end_date = convert_to_audit_filter_format(end_date)

        demisto.debug(f"{log_prefix} Getting events between {audit_start_date=} and {audit_end_date=} with {limit=}.")
        audit_events = await get_audit_events(client, start_date=audit_start_date, end_date=audit_end_date, limit=limit)
        demisto.debug(f"{log_prefix} Got {len(audit_events)} events between {audit_start_date=} and {audit_end_date=}.")

        all_events.extend(audit_events)
        human_readable = tableToMarkdown(name="Mimecast Audit Events", t=audit_events)
        command_results.append(CommandResults(readable_output=human_readable))

    # Fetch SIEM logs
    if EventTypes.SIEM.value in event_types:
        log_prefix = EventTypes.SIEM.log_prefix
        if not (is_within_last_24_hours(start_date) and is_within_last_24_hours(end_date)):
            human_readable = "The 'start_date' and 'end_date' arguments must be within the last 24 hours to get SIEM logs."
            command_results.append(CommandResults(readable_output=human_readable, entry_type=EntryType.ERROR))
        else:
            siem_start_date = convert_to_siem_filter_format(start_date)
            siem_end_date = convert_to_siem_filter_format(end_date)

            demisto.debug(f"{log_prefix} Getting events between {siem_start_date=} and {siem_end_date=} with {limit=}.")
            siem_events, _ = await get_siem_events(client, start_date=siem_start_date, end_date=siem_end_date, limit=limit)
            demisto.debug(f"{log_prefix} Got {len(siem_events)} events between {siem_start_date=} and {siem_end_date=}.")

            all_events.extend(siem_events)
            human_readable = tableToMarkdown(name="Mimecast SIEM Events", t=siem_events)
            command_results.append(CommandResults(readable_output=human_readable))

    demisto.debug(f"Got {len(all_events)} events in total with {limit=} and {event_types=}.")
    return all_events, command_results


async def fetch_audit_events(
    client: AsyncClient,
    audit_last_run: dict,
    max_fetch: int,
    first_fetch: datetime,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """
    Fetches audit events from Mimecast.

    Args:
        client (AsyncClient): An instance of the AsyncClient.
        audit_last_run (dict): The last run object containing audit event state.
        max_fetch (int): The maximum number of events to fetch.
        first_fetch(datetime): The date and time from which to begin to fetch audit events.

    Returns:
        tuple[dict[str, Any], list[dict[str, Any]]]: A tuple of (next_run_state, fetched_events).
    """
    log_prefix = EventTypes.AUDIT.log_prefix
    demisto.debug(f"{log_prefix} Starting to fetch audit events. Got {audit_last_run=}.")
    start_date = audit_last_run.get(START_DATE_KEY) or convert_to_audit_filter_format(first_fetch)
    end_date = convert_to_audit_filter_format(UTC_NOW)
    last_fetched_ids = audit_last_run.get(LAST_FETCHED_IDS_KEY, [])

    demisto.debug(f"{log_prefix} Fetching events using {start_date=}, {end_date=}, {max_fetch=}.")
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
        demisto.debug(f"{log_prefix} No new events found. Keeping {audit_last_run=}.")
        return audit_last_run, []

    new_start_time = audit_events[-1][FILTER_TIME_KEY]
    new_last_fetched_ids = [event[EVENT_ID_KEY] for event in audit_events if event[FILTER_TIME_KEY] == new_start_time]
    audit_next_run = {START_DATE_KEY: new_start_time, LAST_FETCHED_IDS_KEY: new_last_fetched_ids}

    # Remove internal key used for deduplication purposes before sending events to dataset
    for event in audit_events:
        event.pop(FILTER_TIME_KEY)

    demisto.debug(f"{log_prefix} Finished fetching {len(audit_events)} events with {new_start_time=}, {new_last_fetched_ids=}.")
    return audit_next_run, audit_events


async def fetch_siem_events(
    client: AsyncClient,
    siem_last_run: dict,
    max_fetch: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """
    Fetches SIEM logs from Mimecast for all configured event types concurrently.

    Args:
        client (AsyncClient): An instance of the AsyncClient.
        last_run (dict): The last run object containing SIEM event states for each type.
        max_fetch (int): The maximum number of events to fetch per event type.

    Returns:
        tuple[dict[str, Any], list[dict[str, Any]]]: A tuple of (next_run, all_fetched_events).
    """
    log_prefix = EventTypes.SIEM.log_prefix
    demisto.debug(f"{log_prefix} Starting to fetch events. Got {siem_last_run=}")
    default_start_date = convert_to_siem_filter_format(UTC_MINUTE_AGO)
    last_fetched_ids = siem_last_run.get(LAST_FETCHED_IDS_KEY, [])
    start_date = siem_last_run.get(START_DATE_KEY) or default_start_date
    next_page = siem_last_run.get(NEXT_PAGE_KEY)

    # Ensure the start date within than 24 hours to avoid HTTP 400 (bad request) errors from SIEM API endpoint
    # If no events were fetched within the last 24 hours, the start date may not be within the allowed API range
    if not is_within_last_24_hours(start_date):
        demisto.info(f"{log_prefix} {start_date=} is older than 24 hours. Skipping forward to last 23 hours.")
        start_date = convert_to_siem_filter_format(UTC_NOW - timedelta(hours=23))

    siem_events, new_next_page = await get_siem_events(
        client,
        start_date=start_date,
        limit=max_fetch,
        last_fetched_ids=last_fetched_ids,
        next_page=next_page,
    )

    # Handle empty results
    if not siem_events:
        demisto.debug(f"{log_prefix} No new events found. Keeping {siem_last_run=}.")
        return siem_last_run, []

    # Update state with newest events
    new_start_time, new_last_fetched_ids = get_siem_new_start_time_last_fetched_ids(siem_events)
    siem_next_run = {START_DATE_KEY: new_start_time, LAST_FETCHED_IDS_KEY: new_last_fetched_ids, NEXT_PAGE_KEY: new_next_page}

    # Remove internal key used for deduplication purposes before sending events to dataset
    for event in siem_events:
        event.pop(FILTER_TIME_KEY)

    demisto.debug(
        f"{log_prefix} Finished fetching {len(siem_events)} events. "
        f"Got {new_start_time=}, {new_next_page=}, {new_last_fetched_ids=}."
    )
    return siem_next_run, siem_events


def get_siem_new_start_time_last_fetched_ids(events: list[dict[str, Any]]) -> tuple[str, list[str]]:
    """
    Gets the new `start_time` based on the `_filter_time` key in formatted and sorted events as well as
    the list of last fetched IDs either with the newest time or last page (whichever is larger).

    Args:
        events (list[dict[str, Any]]): List of events from the SIEM event type (must be sorted and formatted).
        event_type (str): SIEM event type name.

    Returns:
        tuple[str, str]: Tuple of new start time and list of last fetched IDs.

    Raises:
        IndexError: If called with an empty events list.
    """
    log_prefix = EventTypes.SIEM.log_prefix
    page_size = EventTypes.SIEM.default_page_size

    new_start_time = events[-1][FILTER_TIME_KEY]
    events_with_newest_time = [event[EVENT_ID_KEY] for event in events if event.get(FILTER_TIME_KEY) == new_start_time]
    events_from_last_page = [event[EVENT_ID_KEY] for event in events[-page_size:]]

    if len(events_with_newest_time) > len(events_from_last_page):
        demisto.debug(f"{log_prefix} Using event IDs with time={new_start_time} for last run {LAST_FETCHED_IDS_KEY!r} value.")
        new_last_fetched_ids = events_with_newest_time
    else:
        # Sometimes, even when using passing `next_page` to SIEM endpoint, we may get events from previous page on the next page
        # So save IDs from the last page (default 100) or all IDs with the latest `_filter_time` (whichever is greater)
        demisto.debug(f"{log_prefix} Using all event IDs in last SIEM page for last run {LAST_FETCHED_IDS_KEY!r} value.")
        new_last_fetched_ids = events_from_last_page

    return new_start_time, new_last_fetched_ids


async def fetch_events_command(
    client: AsyncClient,
    last_run: dict,
    max_fetch: int,
    event_types: list[str],
    audit_first_fetch: datetime,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """
    Implements `fetch-events` command. Orchestrates concurrent fetching of both audit events and SIEM logs.

    Args:
        client (AsyncClient): An instance of the AsyncClient.
        last_run (dict): The last run object.
        max_fetch (int): The maximum number of events to fetch.
        event_types (list[str]): List of event types to fetch.
        audit_first_fetch (datetime): The date and time from which to begin to fetch audit events.

    Returns:
        tuple[dict[str, Any], list[dict[str, Any]]]: A tuple of next run dictionary and all events list.
    """
    demisto.debug(f"Starting to fetch events with {max_fetch=} and {event_types=}. Got {last_run=}.")

    run_event_types: list[EventTypes] = []
    run_tasks: list[Awaitable[tuple[dict, list]]] = []
    # Prepare audit fetch task
    if EventTypes.AUDIT.value in event_types:
        audit_type = EventTypes.AUDIT
        audit_last_run = last_run.get(audit_type.value, {})
        run_event_types.append(audit_type)
        run_tasks.append(fetch_audit_events(client, audit_last_run, max_fetch, audit_first_fetch))

    # Prepare SIEM fetch task
    if EventTypes.SIEM.value in event_types:
        siem_type = EventTypes.SIEM
        siem_last_run = last_run.get(siem_type.value, {})
        run_event_types.append(siem_type)
        run_tasks.append(fetch_siem_events(client, siem_last_run, max_fetch))

    # Validate run tasks and execute all fetch tasks concurrently
    if not run_tasks:
        # If no tasks ran, it means none of the "if" conditions above were not met
        raise DemistoException(f"Invalid fetch {event_types=}.")
    demisto.debug(f"Fetching events concurrently for {len(run_tasks)} event types.")
    results = await asyncio.gather(*run_tasks)

    next_run: dict[str, Any] = {}
    all_events: list[dict] = []
    # Process results from all run tasks
    for event_type, event_type_result in zip(run_event_types, results):
        event_type_next_run, event_type_events = event_type_result
        next_run[event_type.value] = event_type_next_run
        all_events.extend(event_type_events)

    demisto.debug(f"Finished fetching events. Got {len(all_events)} events for {event_types=}. Updating {next_run=}.")
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
    audit_first_fetch: datetime = arg_to_datetime(params.get("after")) or UTC_WEEK_AGO
    max_fetch: int = arg_to_number(params.get("max_fetch")) or DEFAULT_FETCH_EVENTS_LIMIT
    event_types: list = argToList(params.get("event_types"), transform=lambda x: x.lower()) or EventTypes.all_values()

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
                    audit_first_fetch=audit_first_fetch,
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
