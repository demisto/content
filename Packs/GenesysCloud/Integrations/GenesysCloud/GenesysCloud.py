import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import aiohttp
import asyncio
from typing import Any
from datetime import datetime, timedelta, UTC

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
VENDOR = "Genesys"
PRODUCT = "Cloud"

DEFAULT_SERVER_URL = "https://api.mypurecloud.com"
DEFAULT_GET_EVENTS_LIMIT = 10
DEFAULT_FETCH_EVENTS_LIMIT = 2500  # per service

""" CLIENT CLASS """


class AsyncClient:
    """An asynchronous client for interacting with the Genesys Cloud API; used for SIEM event collection"""

    def __init__(self, base_url: str, client_id: str, client_secret: str, verify: bool, proxy: bool):
        self.base_url = base_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._access_token: str | None = None
        self._verify = verify
        self._proxy_url = handle_proxy().get("http") if proxy else None

    async def __aenter__(self):
        self._session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=self._verify))
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            exception_traceback = "".join(traceback.format_exception(exc_type, exc_val, exc_tb))
            demisto.error(f"AsyncClient context exited with an exception: {exception_traceback}.")
        else:
            demisto.debug("AsyncClient context exited normally.")

        # Always ensure HTTP client session is closed
        await self._session.close()

    async def get_access_token(self) -> str:
        """
        Obtains an OAuth2 access token using client credentials flow.

        Returns:
            str: The access token.
        """
        # Implement OAuth2 token retrieval
        return "token"

    async def get_realtime_audits(
        self,
        from_date: str,
        to_date: str,
        service_name: str,
    ) -> dict[str, Any]:
        """
        Retrieves audit events from Genesys Cloud for a specific service.

        Args:
            from_date (str): The start date for the audit events in ISO 8601 format.
            to_date (str): The end date for the audit events in ISO 8601 format.
            service_name (str): The name of the service to fetch events for.

        Returns:
            dict[str, Any]: A dictionary containing the audit events raw API response.
        """
        # Implement audit query here
        return {}


""" HELPER FUNCTIONS """


def deduplicate_and_format_events(
    raw_response: dict[str, Any],
    all_fetched_ids: set[str],
) -> list[dict[str, Any]]:
    """
    Processes events from a raw API response, deduplicates them, and adds the _time field.

    Args:
        raw_response (dict[str, Any]): A dictionary containing the raw API response of the audit events.
        all_fetched_ids (set[str]): A set of event IDs that have already been fetched.

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
        event["_time"] = arg_to_datetime(event.get("eventTime"), required=True).strftime(DATE_FORMAT)  # type: ignore [union-attr]
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
    # all_fetched_ids = set(last_fetched_ids)
    all_events: list[dict[str, Any]] = []

    return all_events[:limit]


async def get_events_command(
    client: AsyncClient,
    args: dict[str, Any],
    service_names: list[str],
) -> tuple[list[dict[str, Any]], CommandResults]:
    """
    Implements the `genesis-cloud-get-events` command. Gets audit events using the AsyncClient.

    Args:
        client (AsyncClient): An instance of the AsyncClient.
        args (dict[str, Any]): The command arguments.
        service_names (list[str]): List of service names to fetch events from.

    Returns:
        tuple[list[dict[str, Any]], CommandResults]: A tuple of the events list and the CommandResults.
    """
    from_date = arg_to_datetime(args.get("from_date")) or (datetime.now(tz=UTC) - timedelta(hours=1))
    to_date = datetime.now(tz=UTC)
    limit = arg_to_number(args.get("limit")) or DEFAULT_GET_EVENTS_LIMIT
    service_name = args.get("service_name")

    # If specific service is requested, use only that one
    services_to_fetch = [service_name] if service_name else service_names

    all_events = []
    for service in services_to_fetch:
        events = await get_audit_events_for_service(
            client=client,
            from_date=from_date.strftime(DATE_FORMAT),
            to_date=to_date.strftime(DATE_FORMAT),
            service_name=service,
            limit=limit,
        )
        all_events.extend(events)

    return all_events, CommandResults(readable_output=tableToMarkdown(name="Genesys Cloud Audit Events", t=all_events))


async def fetch_events_command(
    client: AsyncClient,
    last_run: dict,
    max_fetch: int,
    service_names: list[str],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """
    Implements `fetch-events` command. Fetches audit events using the AsyncClient.

    Args:
        client (AsyncClient): An instance of the AsyncClient.
        last_run (dict): The last run object.
        max_fetch (int): The maximum number of events to fetch.
        service_names (list[str]): List of service names to fetch events from.

    Returns:
        tuple[dict[str, Any], list[dict[str, Any]]]: A tuple of the next run object and a list of fetched events.
    """
    demisto.debug(f"Starting fetching events with {last_run=}.")

    default_from_date = (datetime.now(tz=UTC) - timedelta(hours=1)).strftime(DATE_FORMAT)
    from_date = last_run.get("from_date") or default_from_date
    to_date = datetime.now(tz=UTC).strftime(DATE_FORMAT)
    last_fetched_ids = last_run.get("last_fetched_ids", [])

    all_events = []

    # Fetch events from each service
    for service_name in service_names:
        events = await get_audit_events_for_service(
            client=client,
            from_date=from_date,
            to_date=to_date,
            service_name=service_name,
            limit=max_fetch,
            last_fetched_ids=last_fetched_ids,
        )
        all_events.extend(events)

    if not all_events:
        demisto.debug(f"No new events found since {last_run=}.")
        return last_run, []

    # Sort events by timestamp
    all_events.sort(key=lambda event: event.get("eventTime", ""))

    # Get the newest event timestamp
    newest_event_timestamp = all_events[-1].get("eventTime")
    demisto.debug(f"Got {len(all_events)} deduplicated events with {newest_event_timestamp=}.")

    # Get the IDs of the events that have the newest timestamp
    new_last_fetched_ids = [event.get("id") for event in all_events if event.get("eventTime") == newest_event_timestamp]

    next_run = {"from_date": newest_event_timestamp, "last_fetched_ids": new_last_fetched_ids}
    demisto.debug(f"Updating {next_run=} after fetching {len(all_events)} events.")

    return next_run, all_events


""" MAIN FUNCTION """


async def main() -> None:
    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()
    command: str = demisto.command()

    # HTTP Connection
    base_url = params.get("url") or DEFAULT_SERVER_URL
    verify: bool = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    # OAuth Credentials
    client_id = params.get("credentials", {}).get("identifier")
    client_secret = params.get("credentials", {}).get("password")

    # Fetch Events
    is_fetch_events = params.get("isFetchEvents", False)
    max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_FETCH_EVENTS_LIMIT
    service_names = argToList(params.get("service_names"))

    demisto.debug(f"Command being called is {command}")

    try:
        async with AsyncClient(
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
            verify=verify,
            proxy=proxy,
        ) as async_client:
            if command == "test-module":
                test_results = "ok"
                if is_fetch_events:
                    pass
                return_results(test_results)

            elif command == "genesis-cloud-get-events":
                should_push_events = argToBoolean(args.pop("should_push_events", False))
                events, command_results = await get_events_command(async_client, args, service_names)
                return_results(command_results)
                if should_push_events:
                    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

            elif command == "fetch-events":
                last_run = demisto.getLastRun()
                next_run, events = await fetch_events_command(
                    async_client, last_run=last_run, max_fetch=max_fetch, service_names=service_names
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
