import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import aiohttp
from http import HTTPStatus
import asyncio
import math
from typing import Any
from datetime import datetime, timedelta, UTC

""" CONSTANTS """

# Dataset
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
VENDOR = "Genesys"
PRODUCT = "Cloud"

# Access Token
ACCESS_TOKEN_KEY = "access_token"
TOKEN_TYPE_KEY = "token_type"
TOKEN_TTL_KEY = "expires_in"  # TTL in seconds
TOKEN_ERROR_KEY = "error"  # Optional error message if request fails
TOKEN_VALID_UNTIL_KEY = "valid_until"

# Default Values
DEFAULT_SERVER_URL = "https://api.mypurecloud.com"
DEFAULT_SERVICE_NAMES = [
    "Architect",
    "PeoplePermissions",
    "ContactCenter",
    "Groups",
    "Telephony",
    "Outbound",
    "Routing",
    "Integrations",
    "AnalyticsReporting",
]
DEFAULT_AUDIT_PAGE_SIZE = 500
DEFAULT_AUDIT_RETRY_COUNT = 3
DEFAULT_GET_EVENTS_LIMIT = 10
DEFAULT_FETCH_EVENTS_LIMIT = 2500  # per service
DEFAULT_TOKEN_TTL = 86400
DEFAULT_TOKEN_TYPE = "bearer"

""" CLIENT CLASS """


class AsyncClient:
    """An asynchronous client for interacting with the Genesys Cloud API; used for SIEM event collection"""

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

        Example:
            >>> async_client.generate_access_token()
            {
                "access_token": "token",
                "token_type": "bearer",
                "expires_in": 86400,
                "error": "optional-error-message",
            }
        """
        login_url = self.base_url.replace("api.", "login.")
        token_url = urljoin(login_url, "/oauth/token")

        demisto.debug(f"Requesting new OAuth2 access token using {token_url=}.")
        async with self._session.post(
            url=token_url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            params={"grant_type": "client_credentials"},
            auth=aiohttp.BasicAuth(self._client_id, self._client_secret),
        ) as response:
            response_json = await response.json()
            try:
                response.raise_for_status()
            except aiohttp.ClientResponseError as e:
                raise DemistoException(
                    f"Request to {token_url} failed with HTTP {e.status} status. Got response: {response_json}."
                ) from e

            if error_message := response_json.get(TOKEN_ERROR_KEY):  # Optional error message if request fails
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

        Example:
            >>> async_client.get_authorization_header()
            "Bearer MyToken1245"
        """
        demisto.debug(f"Constructing Authorization header using {force_generate_new_token=}.")
        integration_context = get_integration_context()
        access_token = integration_context.get(ACCESS_TOKEN_KEY)
        token_type = integration_context.get(TOKEN_TYPE_KEY, DEFAULT_TOKEN_TYPE)
        token_valid_until = arg_to_datetime(integration_context.get(TOKEN_VALID_UNTIL_KEY))
        is_valid_token = token_valid_until and token_valid_until > datetime.now(tz=UTC)
        demisto.debug(f"Found in integration context {token_valid_until=}, {is_valid_token=}.")

        if access_token and is_valid_token and not force_generate_new_token:
            demisto.debug("Using valid access token in integration context to construct Authorization header.")
        else:
            demisto.debug("Generating new access token.")
            token_response = await self._generate_new_access_token()
            access_token = token_response.get(ACCESS_TOKEN_KEY)
            token_type = token_response.get(TOKEN_TYPE_KEY, DEFAULT_TOKEN_TYPE)
            token_ttl = token_response.get(TOKEN_TTL_KEY, DEFAULT_TOKEN_TTL) - 300  # subtract 5 minutes as a safety margin
            token_response[TOKEN_VALID_UNTIL_KEY] = (datetime.now(tz=UTC) + timedelta(seconds=token_ttl)).isoformat()
            demisto.debug("Saving new access token in integration context.")
            set_integration_context(token_response)

        demisto.debug(f"Constructed Authorization header using {token_type=}.")
        return f"{token_type.capitalize()} {access_token}"

    async def _send_audits_post_request(
        self,
        url: str,
        params: dict[str, str],
        headers: dict[str, str],
        body: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Sends HTTP POST request to get realtime audits.

        Args:
            url (str): The full URL.
            params (dict[str, str]): The URL query parameters.
            headers (dict[str, str]): The request headers, including the "Authorization" header.
            body (dict[str, Any]): The request body, including "interval", "serviceName", and "pageNumber".

        Raises:
            ClientResponseError: If the request fails.

        Returns:
            dict[str, Any]: The audit events raw API response.
        """
        async with self._session.post(url=url, params=params, headers=headers, json=body) as response:
            response.raise_for_status()
            return await response.json()

    async def get_realtime_audits(
        self,
        from_date: str,
        to_date: str,
        service_name: str,
        page_number: int,
        page_size: int = DEFAULT_AUDIT_PAGE_SIZE,
        max_retries: int = DEFAULT_AUDIT_RETRY_COUNT,
    ) -> dict[str, Any]:
        """
        Retrieves audit events from Genesys Cloud for a specific service using the realtime audit query API.

        Args:
            from_date (str): The start date for the audit events in ISO 8601 format.
            to_date (str): The end date for the audit events in ISO 8601 format.
            service_name (str): The name of the service to fetch events for.
            page_number (int): The page number to retrieve.
            page_size (int): The number of items per page. Defaults to 500.
            max_retries (int): Maximum number of retries for rate limit errors. Defaults to 3.

        Raises:
            ClientResponseError: If the request fails (after retry on 401 or 429 errors or some other status code).

        Returns:
            dict[str, Any]: A dictionary containing the audit events raw API response.
        """
        url = urljoin(self.base_url, "/api/v2/audits/query/realtime")
        params = {"expand": "user"}
        body = {
            "interval": f"{from_date}/{to_date}",
            "serviceName": service_name,
            "sort": [{"name": "Timestamp", "sortOrder": "ascending"}],
            "pageNumber": page_number,
            "pageSize": page_size,
        }
        # Get authorization header (will try to get token from integration context or generate new one if needed)
        headers = {"Content-Type": "application/json", "Authorization": await self.get_authorization_header()}

        demisto.debug(f"[{service_name}] Requesting audits using {from_date=}, {to_date=}, {page_number=}.")

        retry_count = 0
        while retry_count <= max_retries:
            try:
                response_json = await self._send_audits_post_request(url, params=params, headers=headers, body=body)
                break  # Success, exit retry loop

            except aiohttp.ClientResponseError as e:
                status_code = e.status
                error_message = e.message

                if status_code == HTTPStatus.UNAUTHORIZED:
                    demisto.debug(
                        f"[{service_name}] Received HTTP 401 Unauthorized error. Forcing new token generation and retrying..."
                    )
                    headers["Authorization"] = await self.get_authorization_header(force_generate_new_token=True)
                    response_json = await self._send_audits_post_request(url, params=params, headers=headers, body=body)
                    break  # Success after token refresh, exit retry loop

                if status_code == HTTPStatus.TOO_MANY_REQUESTS:
                    if retry_count < max_retries:
                        # Exponential backoff: 2^retry_count seconds (1s, 2s, 4s)
                        wait_time = 2**retry_count
                        demisto.debug(
                            f"[{service_name}] Received HTTP 429 Too Many Requests error. "
                            f"Retrying {retry_count + 1} of {max_retries} after {wait_time} seconds..."
                        )
                        await asyncio.sleep(wait_time)
                        retry_count += 1

                else:
                    demisto.error(
                        f"[{service_name}] Request using {from_date=}, {to_date=}, {page_number=} failed. "
                        f"Got {status_code=}, {error_message=}."
                    )
                    raise DemistoException(f"Request to {e.request_info.url} failed with HTTP {e.status} status.") from e

        entities_count = len(response_json.get("entities", []))
        demisto.debug(f"[{service_name}] Fetched {entities_count} audits using {from_date=}, {to_date=}, {page_number=}.")

        return response_json


""" HELPER FUNCTIONS """


def deduplicate_and_format_events(
    raw_response: dict[str, Any],
    all_fetched_ids: set[str],
    service_name: str,
) -> list[dict[str, Any]]:
    """
    Processes events from a raw API response, deduplicates them, and adds the `_time` and `source_log_type` fields.

    Args:
        raw_response (dict[str, Any]): A dictionary containing the raw API response of the audit events.
        all_fetched_ids (set[str]): A set of event IDs that have already been fetched.
        service_name (str): The name of the service the events were fetched from.

    Returns:
        list[dict[str, Any]]: A list of new, processed events.
    """
    events = []
    for event in raw_response.get("entities", []):
        event_id = event.get("id")
        if event_id in all_fetched_ids:
            demisto.debug(f"Skipping duplicate {event_id=}.")
            continue
        all_fetched_ids.add(event_id)
        event["_time"] = arg_to_datetime(event.get("eventDate"), required=True).strftime(DATE_FORMAT)  # type: ignore [union-attr]
        event["source_log_type"] = service_name
        events.append(event)
    return events


async def get_audit_events_for_service(
    client: AsyncClient,
    from_date: str,
    to_date: str,
    service_name: str,
    limit: int,
    last_fetched_ids: list[str] | None = None,
) -> list[dict[str, Any]]:
    """
    Asynchronously fetches audit events from Genesys Cloud for a specific service.

    Args:
        client (AsyncClient): An instance of the AsyncClient.
        from_date (str): The start date for the audit events in ISO 8601 format.
        to_date (str): The end date for the audit events in ISO 8601 format.
        service_name (str): The name of the service to fetch events for.
        limit (int): The maximum number of events to retrieve.
        last_fetched_ids (list[str]): A list of IDs of events that have already been fetched.

    Returns:
        list[dict[str, Any]]: A list of new audit events for the service.
    """
    last_fetched_ids = last_fetched_ids or []
    all_fetched_ids = set(last_fetched_ids)
    all_events: list[dict[str, Any]] = []

    # Calculate number of pages needed based on limit and page size
    start_page_number = 1  # Page numbers start from 1
    stop_page_number = math.ceil(limit / DEFAULT_AUDIT_PAGE_SIZE) + 1  # Stop page not included (range stops one before)
    demisto.debug(f"[{service_name}] Fetching {stop_page_number} pages concurrently to retrieve up to {limit} events.")

    # Create tasks for fetching all pages concurrently
    page_tasks = [
        client.get_realtime_audits(
            from_date=from_date,
            to_date=to_date,
            service_name=service_name,
            page_number=page_number,
            page_size=DEFAULT_AUDIT_PAGE_SIZE,
        )
        for page_number in range(start_page_number, stop_page_number)  # Page numbers start from 1
    ]

    # Fetch all pages concurrently
    page_responses = await asyncio.gather(*page_tasks)

    # Process results from all pages
    for page_number, page_response in enumerate(page_responses, start=start_page_number):
        # Process and deduplicate events from this page
        page_events = deduplicate_and_format_events(page_response, all_fetched_ids, service_name)
        for event in page_events:
            all_events.append(event)

            # Stop if limit was reached
            if len(all_events) >= limit:
                demisto.debug(f"[{service_name}] Reached {limit=} after processing events on {page_number=}.")
                break

    demisto.debug(f"[{service_name}] Fetched total of {len(all_events)} events from {stop_page_number} pages.")
    return all_events


""" COMMAND FUNCTIONS """


async def test_module(client: AsyncClient, service_names: list[str]) -> str:
    """
    Tests the connection to the Genesys Cloud realtime audit events API.

    Args:
        client (AsyncClient): An instance of the AsyncClient.
        service_names (list[str]): List of service names to fetch events from.

    Returns:
        str: "ok" if connection to the realtime audit events API succeeded.
    """
    await fetch_events_command(client, last_run={}, max_fetch=1, service_names=service_names)
    return "ok"


async def get_events_command(client: AsyncClient, args: dict[str, Any]) -> tuple[list[dict[str, Any]], CommandResults]:
    """
    Implements the `genesis-cloud-get-events` command. Gets audit events using the AsyncClient.

    Args:
        client (AsyncClient): An instance of the AsyncClient.
        args (dict[str, Any]): The command arguments.

    Returns:
        tuple[list[dict[str, Any]], CommandResults]: A tuple of the events list and the CommandResults.
    """
    from_date = arg_to_datetime(args.get("from_date")) or (datetime.now(tz=UTC) - timedelta(hours=1))
    to_date = arg_to_datetime(args.get("to_date")) or datetime.now(tz=UTC)
    limit = arg_to_number(args.get("limit")) or DEFAULT_GET_EVENTS_LIMIT
    service_name = args["service_name"]

    events = await get_audit_events_for_service(
        client=client,
        from_date=from_date.strftime(DATE_FORMAT),
        to_date=to_date.strftime(DATE_FORMAT),
        service_name=service_name,
        limit=limit,
    )

    human_readable = tableToMarkdown(name=f"Genesys Cloud Audit Events from Service: {service_name}", t=events)
    return events, CommandResults(readable_output=human_readable)


async def fetch_events_command(
    client: AsyncClient,
    last_run: dict,
    max_fetch: int,
    service_names: list[str],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """
    Implements `fetch-events` command. Fetches audit events using the AsyncClient.

    Fetches events from multiple services concurrently. If one service fails,
    it will not impact the fetching of events from other services.

    Args:
        client (AsyncClient): An instance of the AsyncClient.
        last_run (dict): The last run object.
        max_fetch (int): The maximum number of events to fetch per service.
        service_names (list[str]): List of service names to fetch events from.

    Returns:
        tuple[dict[str, Any], list[dict[str, Any]]]: A tuple of the next run object and a list of fetched events.
    """
    demisto.debug(f"Starting fetching events with {last_run=}.")
    default_from_date = (datetime.now(tz=UTC) - timedelta(minutes=1)).strftime(DATE_FORMAT)
    to_date = datetime.now(tz=UTC).strftime(DATE_FORMAT)

    service_tasks = []
    # Create tasks for fetching events from each service concurrently
    for service_name in service_names:
        service_last_run = last_run.get(service_name, {})
        from_date = service_last_run.get("from_date") or default_from_date
        last_fetched_ids = service_last_run.get("last_fetched_ids", [])

        service_tasks.append(
            get_audit_events_for_service(
                client=client,
                from_date=from_date,
                to_date=to_date,
                service_name=service_name,
                limit=max_fetch,
                last_fetched_ids=last_fetched_ids,
            )
        )

    # Gather results with `return_exceptions=True` to prevent one failure from affecting others
    demisto.debug(f"Fetching events from {len(service_names)} services concurrently: {service_names}")
    results = await asyncio.gather(*service_tasks, return_exceptions=True)

    # Process results and handle any exceptions
    next_run = {}
    all_events = []
    per_service_errors = {}

    for service_name, result in zip(service_names, results):
        service_last_run = last_run.get(service_name, {})

        if isinstance(result, Exception):
            # Log the error but continue processing events from other services
            service_traceback = "".join(traceback.format_exception(type(result), result, result.__traceback__))
            demisto.error(f"[{service_name}] Failed to fetch events. Traceback: {service_traceback}.")
            per_service_errors[service_name] = str(result)

        elif isinstance(result, list):
            # Successfully fetched events from service
            service_events = result
            demisto.debug(f"[{service_name}] Fetched {len(service_events)} events using {from_date=}, {to_date=}, {max_fetch=}.")

            # If no new events from service, set its next run same as last run
            if not service_events:
                demisto.debug(f"[{service_name}] No new events found since {service_last_run=}.")
                next_run[service_name] = service_last_run
                continue

            # Get the newest event timestamp
            newest_event_time = service_events[-1].get("eventDate")
            demisto.debug(f"[{service_name}] Got {len(service_events)} deduplicated events with {newest_event_time=}.")

            # Get the IDs of the service events that have the newest time
            new_last_fetched_ids = [event.get("id") for event in service_events if event.get("eventDate") == newest_event_time]

            # Update next run for service
            service_next_run = {"from_date": newest_event_time, "last_fetched_ids": new_last_fetched_ids}
            demisto.debug(f"[{service_name}] Updating {service_next_run=} after fetching {len(service_events)} events.")

            # Set next run
            all_events.extend(service_events)
            next_run[service_name] = service_next_run

        else:
            # Unlikely case of getting unknown / unexpected result
            demisto.debug(f"[{service_name}] Unexpected result type: {type(result)}.")

    # If all services failed, raise an exception
    if len(per_service_errors) == len(service_names):
        error_summary = "\n".join(f"{service_name}: {error}" for service_name, error in per_service_errors.items())
        raise DemistoException(f"Fetching events failed from all services:\n{error_summary}.")

    demisto.debug(f"Finished fetching {len(all_events)} events. Setting {next_run=}.")
    return next_run, all_events


""" MAIN FUNCTION """


async def main() -> None:  # pragma: no cover
    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()
    command: str = demisto.command()

    # HTTP Connection
    base_url: str = params.get("url") or DEFAULT_SERVER_URL
    verify: bool = not params.get("insecure", False)
    proxy: bool = params.get("proxy", False)

    # OAuth Credentials
    client_id: str = params.get("credentials", {}).get("identifier", "")
    client_secret: str = params.get("credentials", {}).get("password", "")

    # Fetch Events
    max_fetch: int = arg_to_number(params.get("max_fetch")) or DEFAULT_FETCH_EVENTS_LIMIT
    service_names: list = argToList(params.get("service_names")) or DEFAULT_SERVICE_NAMES

    demisto.debug(f"Command being called is {command}.")

    try:
        async with AsyncClient(
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
            verify=verify,
            proxy=proxy,
        ) as async_client:
            if command == "test-module":
                return_results(await test_module(async_client, service_names=service_names))

            elif command == "genesys-cloud-get-events":
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
                    service_names=service_names,
                )
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
                demisto.setLastRun(next_run)

            else:
                raise NotImplementedError(f"{command} command is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    asyncio.run(main())
