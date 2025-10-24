from itertools import chain
from aiohttp import ClientResponseError
import asyncio
import aiohttp
import traceback

import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

""" CONSTANTS """

ALL_SUPPORTED_EVENT_TYPES = ["application", "alert", "page", "audit", "network", "incident"]
MAX_EVENTS_PAGE_SIZE = 10000
MAX_RETRY = 3
NETSKOPE_SEMAPHORE_COUNT = 4
MAX_FAILURE_ENTRIES_TO_HANDLE_PER_TYPE = 10

# Netskope response constants
RATE_LIMIT_REMAINING = "ratelimit-remaining"  # Rate limit remaining
RATE_LIMIT_RESET = "ratelimit-reset"  # Rate limit RESET value is in seconds
VENDOR = "netskope"
PRODUCT = "netskope"
XSIAM_SEM = asyncio.Semaphore(20)

# Event type configuration mapping
# Each event type can have specific endpoint, time parameters, and count field configurations
EVENT_TYPE_CONFIGS = {
    "incident": {
        "endpoint": "/events/datasearch/incident",
        "time_params": {"start_time": "starttime", "end_time": "endtime"},
        "count_field": "event_count:count(_id)",
    }
}

# Default configuration for all other event types
DEFAULT_EVENT_TYPE_CONFIG = {
    "endpoint": "/events/data/{type}",
    "time_params": {"start_time": "insertionstarttime", "end_time": "insertionendtime"},
    "count_field": "event_count:count(id)",
}


def get_event_type_config(event_type: str) -> dict:
    """Get configuration for a specific event type.

    Args:
        event_type (str): The type of event

    Returns:
        dict: Configuration dictionary for the event type
    """
    return EVENT_TYPE_CONFIGS.get(event_type, DEFAULT_EVENT_TYPE_CONFIG)


""" CLIENT CLASS """


class Client:
    """
    Client for Netskope RESTful API.

    Args:
        base_url (str): The base URL of Netskope.
        token (str): The token to authenticate against Netskope API.
        validate_certificate (bool): Specifies whether to verify the SSL certificate or not.
        proxy (bool): Specifies if to use XSOAR proxy settings.
    """

    def __init__(self, base_url: str, token: str, proxy: bool, verify: bool, event_types_to_fetch: list[str]):
        self.fetch_status: dict = {event_type: False for event_type in event_types_to_fetch}
        self.event_types_to_fetch: list[str] = event_types_to_fetch
        self.netskope_semaphore = asyncio.Semaphore(NETSKOPE_SEMAPHORE_COUNT)
        self._headers = {"Netskope-Api-Token": f"{token}", "Accept": "application/json"}
        self._base_url = base_url
        self._verify = verify
        self._proxy_url = handle_proxy().get("http") if proxy else None
        self._async_session: aiohttp.ClientSession | None = None

    async def __aenter__(self):
        demisto.debug("Opening the aiohttp session")
        self._async_session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(verify_ssl=self._verify))
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        demisto.debug("Closing aiohttp session")
        if self._async_session is not None:
            await self._async_session.close()

    async def get_events_data_async(self, event_type: str, params: dict) -> dict:
        """Fetch events data asynchronously from Netskope API.

        Args:
            event_type (str): The type of events to fetch (e.g., 'alert', 'network', 'incident')
            params (dict): Query parameters for the API request

        Returns:
            dict: JSON response from the API containing events data

        Raises:
            aiohttp.ClientResponseError: If the HTTP request fails
        """
        # Use the correct endpoint depending on the event type
        config = get_event_type_config(event_type)
        endpoint = config["endpoint"].replace("{type}", event_type)
        url = urljoin(self._base_url, endpoint)
        # Type check for mypy
        if self._async_session is None:
            raise RuntimeError("ClientSession not initialized. Use 'async with' context manager.")
        async with (
            self.netskope_semaphore,
            self._async_session.get(url, params=params, headers=self._headers, proxy=self._proxy_url) as resp,
        ):
            demisto.debug(f"Fetching {event_type} events with params: {params}")
            resp.raise_for_status()
            return await resp.json()

    async def get_events_count(self, event_type: str, params: dict) -> int:
        """Get the count of events for a given type and time range.

        Args:
            event_type (str): The type of events to count
            params (dict): Query parameters for the API request

        Returns:
            int: The count of events available for the given type and time range

        Raises:
            aiohttp.ClientResponseError: If the HTTP request fails
        """
        # Use the correct count field depending on the event type
        config = get_event_type_config(event_type)
        count_field = config["count_field"]

        try:
            res = await self.get_events_data_async(event_type, params | {"fields": count_field})

            # Extract event count from response
            event_count = 0
            if res.get("result") and len(res["result"]) > 0:
                event_count = res["result"][0].get("event_count", 0)

            # Ensure event_count is always a valid integer
            if not isinstance(event_count, int):
                demisto.debug(f"Invalid event_count received: {event_count}, defaulting to 0")
                event_count = 0

            demisto.debug(f"Found {event_count} total {event_type} events for the given time range")
            return event_count

        except Exception as e:
            demisto.error(f"Failed to get event count for {event_type}: {str(e)}")
            raise


""" HELPER FUNCTIONS """


def next_trigger_time(num_of_events, max_fetch, new_last_run):
    """Check whether to add the next trigger key to the next_run dict based on number of fetched events.

    Args:
        num_of_events (int): The number of events fetched.
        max_fetch (int): The maximum fetch limit.
        new_last_run (dict): the next_run to update
    """
    if num_of_events > (max_fetch / 2):
        new_last_run["nextTrigger"] = "0"
    else:
        new_last_run.pop("nextTrigger", None)


def populate_parsing_rule_fields(event: dict, event_type: str):
    """
    Handles the source_log_event and _time fields.
    Sets the source_log_event to the given event type and _time to the time taken from the timestamp field

    Args:
        event (dict): the event to edit
        event_type (str): the event type to set in the source_log_event field
    """
    event["source_log_event"] = event_type
    try:
        event["_time"] = timestamp_to_datestring(event["timestamp"] * 1000, is_utc=True)
    except (TypeError, KeyError):
        # modeling rule will default on ingestion time if _time is missing
        pass


def prepare_events(events: list, event_type: str) -> list:
    """
    Iterates over a list of given events and add/modify special fields like event_id, _time and source_log_event.

    Args:
        events (list): list of events to modify.
        event_type (str): the type of events given in the list.

    Returns:
        list: the list of modified events
    """
    for event in events:
        populate_parsing_rule_fields(event, event_type)
        event_id = event.get("_id")
        event["event_id"] = event_id

    return events


def handle_event_types_to_fetch(event_types_to_fetch) -> list[str]:
    """Handle event_types_to_fetch parameter.
    Transform the event_types_to_fetch parameter into a pythonic list with lowercase values.
    """
    return argToList(
        arg=event_types_to_fetch if event_types_to_fetch else ALL_SUPPORTED_EVENT_TYPES,
        transform=lambda x: x.lower(),
    )


def remove_unsupported_event_types(last_run_dict: dict, event_types_to_fetch: list):
    keys_to_remove = []

    for key in last_run_dict:
        if (key in ALL_SUPPORTED_EVENT_TYPES) and (key not in event_types_to_fetch):
            keys_to_remove.append(key)

    for key in keys_to_remove:
        last_run_dict.pop(key, None)


def get_time_window_params(event_type: str, start_time: str, end_time: str) -> dict:
    """Get time window parameters based on event type configuration.

    Args:
        event_type (str): The type of event
        start_time (str): Start time for the query
        end_time (str): End time for the query

    Returns:
        dict: Time parameters formatted for the specific event type
    """
    config = get_event_type_config(event_type)
    time_params = config["time_params"]
    return {time_params["start_time"]: start_time, time_params["end_time"]: end_time}


def handle_errors(failures):
    failures_res = []
    if failures:
        for failure in failures:
            if isinstance(failure, DemistoException):
                if "Unauthorized" in failure.message:
                    raise failure

                failure_data: dict = failure.res
                demisto.debug(f"error occurred when fetching {failure_data}, {str(failure.exception)}")
                failures_res.append(
                    {
                        "start_time": failure_data.get("insertionstarttime"),
                        "end_time": failure_data.get("insertionendtime"),
                        "offset": failure_data.get("offset", 0),
                        "limit": failure_data.get("limit"),
                    }
                )
            else:
                demisto.error(f"error occurred when fetching, {str(failure)}")

    return failures_res


def handle_prev_fetch_failures(client: Client, last_run: dict, event_type: str, send_to_xsiam: bool, coord_id: str):
    tasks = []
    failure_data = demisto.get(last_run, f"{event_type}.failures", defaultParam=[])
    if failure_data:
        # each failure entry are with the structure {'start_time': ..., 'end_time': ..., 'offset': ..., 'limit':...}
        demisto.debug(
            f"[{coord_id}] there is {len(failure_data)} failure records for {event_type=}, {failure_data=}, handle them"
        )
        for failure_entry in failure_data:
            tasks.append(
                handle_event_type_async(
                    client=client,
                    event_type=event_type,
                    send_to_xsiam=send_to_xsiam,
                    coord_id=coord_id,
                    is_re_fetch_failed_fetch=True,
                    **failure_entry,
                )
            )
    return tasks


async def honor_rate_limiting_async(headers, event_type, params) -> bool:
    """
    Identify the response headers carrying the rate limiting value.
    If the rate limit remaining is 0 then wait for the rate limit reset time before sending the response to the
    client.
    """
    try:
        if RATE_LIMIT_REMAINING in headers:
            remaining = headers.get(RATE_LIMIT_REMAINING)
            demisto.debug(f"Remaining rate limit is: {remaining}")
            if int(remaining) <= 0:
                demisto.debug(f"Rate limiting reached for {event_type=} and {params=}")
                if to_sleep := headers.get(RATE_LIMIT_RESET):
                    demisto.debug(f"Going to async sleep for {to_sleep} seconds to avoid rate limit error")
                    await asyncio.sleep(int(to_sleep))
                else:
                    # if the RESET value does not exist in the header then
                    # sleep for default 1 second as the rate limit remaining is 0
                    demisto.debug("Did not find a rate limit reset value, going to sleep for 1 second to avoid rate limit error")
                    await asyncio.sleep(1)

                return True

    except ValueError as ve:
        logging.error(f"Value error when honoring the rate limiting wait time {headers} {str(ve)}")

    return False


async def handle_event_type_async(
    client: Client,
    event_type: str,
    start_time: str,
    end_time: str,
    offset: int,
    limit: int,
    send_to_xsiam: bool,
    coord_id: str,
    is_re_fetch_failed_fetch: bool = False,
) -> tuple[str, dict]:
    page_size = min(limit, MAX_EVENTS_PAGE_SIZE)
    params = assign_params(limit=page_size, offset=offset, **get_time_window_params(event_type, start_time, end_time))

    demisto.debug(f"[{coord_id}] Fetching '{event_type}' events with params: {params}")
    # If this is a retry of a previous failure, log it.
    if is_re_fetch_failed_fetch:
        demisto.debug(f"[{coord_id}] Retrying failed fetch for type={event_type}, params={params}")

    demisto.debug(f"[{coord_id}] Starting fetch_and_send_events_async")
    success_res, failures = await fetch_and_send_events_async(
        client, event_type, params, limit, send_to_xsiam, is_re_fetch_failed_fetch
    )
    demisto.debug(f"[{coord_id}] Completed fetch_and_send_events_async - success: {len(success_res)}, failures: {len(failures)}")

    if is_re_fetch_failed_fetch and success_res:
        demisto.debug(f"[{coord_id}] Retry succeeded for type={event_type}, params={params}")

    if not success_res and failures and not is_re_fetch_failed_fetch:
        # if there are no success fetch/send, raise an exception and keep the previous next_fetch_start_time
        e: DemistoException = failures[0]
        demisto.error(f"Failed to fetch events for type={event_type}, params={params}: {str(e)}")
        if hasattr(e, "exception") and hasattr(e.exception, "status"):
            demisto.error(f"HTTP status: {getattr(e.exception, 'status', None)}")
        if hasattr(e, "res"):
            demisto.error(f"API response: {getattr(e, 'res', None)}")
        # Try to get status code first, fall back to message checking
        status_code = None
        if hasattr(e, "exception") and hasattr(e.exception, "status"):
            status_code = getattr(e.exception, "status", None)

        # Handle based on status code if available, otherwise use message strings
        error_message = str(e)
        if status_code == 401 or "Unauthorized" in e.message:
            msg = "Unauthorized Error: please validate your credentials and API token permissions."
        elif status_code == 403 or (status_code is None and "forbidden" in error_message.lower()):
            msg = "Forbidden Error: API token lacks required permissions. Please check token permissions in Netskope admin."
        elif "certificate verify failed" in e.message:
            msg = "Connection Error: certificate verification failed, try to use the insecure checkbox."
        elif "Cannot connect to host" in e.message:
            msg = "Connection Error: please validate your Server URL."
        else:
            status_info = f" (HTTP {status_code})" if status_code else ""
            msg = (
                f"Fetching event_type_start_time_end_time_offset: {event_type}_{start_time}_{end_time}_{offset} "
                f"Failed{status_info}, {str(failures[0])}"
            )
        demisto.error(msg)
        raise DemistoException(msg, exception=failures[0])
    failures_data = handle_errors(failures)
    events = list(chain.from_iterable(success_res))

    res_dict = {"events": events, "failures": failures_data}
    demisto.debug(f"[{coord_id}] Fetched {len(events)} {event_type} events")
    if not is_re_fetch_failed_fetch:
        # if we are retrying a failed fetch (is_re_fetch_failed_fetch=True)
        # no additional info is needed, as we are only trying to fetch the same chunk again.
        if len(events) == limit:
            # meaning, there may be another events to fetch for the current time "window"
            # save the start_time and end_time and the next offset

            next_fetch_data = {
                "next_fetch_start_time": start_time,
                "next_fetch_end_time": end_time,
                "next_fetch_offset": offset + len(events),
            }
            demisto.debug(
                f"[{coord_id}] fetched {(len(events) == limit)=}, need to store the time window and offset "
                f"for next fetch, {next_fetch_data=}"
            )
            res_dict |= next_fetch_data
        else:
            res_dict |= {"next_fetch_start_time": end_time}

    demisto.debug(f"[{coord_id}] Completed event_type processing, returning {len(events)} events")
    return event_type, res_dict


async def fetch_and_send_events_async(
    client: Client, type: str, request_params: dict, limit: int, send_to_xsiam: bool, is_re_fetch_failed_fetch: bool = False
) -> tuple[list, list]:
    async def _handle_page(params):
        async def _fetch_page():
            retry_count = 0
            while retry_count < MAX_RETRY:
                try:
                    if retry_count > 0:
                        # in retry
                        demisto.debug(
                            f"Rate limit (429) occurred for {type=} with {params=}, will retry as {retry_count=} < {MAX_RETRY=}"
                        )

                    offset = params.get("offset")
                    demisto.debug(f"fetching {type=} events from {offset=}")
                    return await client.get_events_data_async(type, params)
                except ClientResponseError as e:
                    if e.status != 429:  # not rate limit
                        raise e
                    if await honor_rate_limiting_async(e.headers, type, params):
                        retry_count += 1
                    else:
                        raise e
            demisto.debug(f"Rate limit (429) occurred and {retry_count=} reached the {MAX_RETRY=}")
            return {}

        async def _send_page_to_xsiam(events):
            async with XSIAM_SEM:
                demisto.debug(f"send {len(events)} events to xsiam")
                await asyncio.to_thread(
                    send_events_to_xsiam, events=events, vendor=VENDOR, product=PRODUCT, chunk_size=XSIAM_EVENT_CHUNK_SIZE_LIMIT
                )

        try:
            res = await _fetch_page()
            events = res.get("result", [])
            events = prepare_events(events, type)
            if send_to_xsiam:
                await _send_page_to_xsiam(events)
        except Exception as e:
            raise DemistoException(message=str(e), exception=e, res=params)
        return events

    async def _handle_all_pages():
        try:
            # the `offset` should not be in the get_events_count request
            init_offset = int(request_params.pop("offset", 0))

            if is_re_fetch_failed_fetch:
                # in case of re-fetch failures we don't use pagination, just the fetch the failed chunk
                total_events = limit
                max_offset = init_offset + int(limit)
            else:
                total_events = await client.get_events_count(type, request_params)
                max_offset = min(total_events, init_offset + int(limit))

            request_limit = request_params.get("limit", MAX_EVENTS_PAGE_SIZE)
            demisto.debug(
                f"Going to fetch {min(total_events, limit)} events from {init_offset=} by chunks of {request_limit} ..."
            )
            tasks = [
                # asyncio.create_task(_handle_page(request_params | {'offset': offset}))
                _handle_page(request_params | {"offset": offset})
                for offset in range(init_offset, max_offset, request_limit)
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            return results
        except Exception as e:
            raise DemistoException(message=str(e), exception=e, res=request_params)

    try:
        results: list[list[dict] | BaseException] = await _handle_all_pages()
        success_tasks = list(filter(lambda res: not isinstance(res, BaseException), results))
        failures = list(filter(lambda res: isinstance(res, BaseException), results))
        return success_tasks, failures
    except Exception as e:
        return [], [e]


""" COMMANDS FUNCTIONS """


async def handle_fetch_and_send_all_events(
    client: Client, last_run: dict, limit: int = MAX_EVENTS_PAGE_SIZE, send_to_xsiam=False
) -> tuple[list[dict], dict]:
    """
    Iterates over all supported event types and call the handle event fetch logic and send the events to XSIAM.

    Endpoint: /api/v2/events/data/
    Docs: https://www.postman.com/netskope-tech-alliances/netskope-rest-api/request/zknja6y/get-network-events-generated-by-netskope

    Example HTTP request:
    <baseUrl>/api/v2/events/data/network?offset=0&insertionstarttime=1707466628&insertionendtime=1739089028&

    Args:
        client (Client): The Netskope client.
        last_run (dict): The execution last run dict where the relevant operations are stored.
        limit (int): The limit which after we stop pulling.
        send_to_xsiam(bool): Whether to send the fetched events to XSIAM or not.

    Returns:
        list: The accumulated list of all events.
        dict: The updated last_run object.
    """
    start = time.time()
    # needed as we use concurrent async tasks
    support_multithreading()

    remove_unsupported_event_types(last_run, client.event_types_to_fetch)

    all_events = []
    epoch_current_time = str(int(arg_to_datetime("now").timestamp()))  # type: ignore[union-attr]
    epoch_last_day = str(int(arg_to_datetime("1 day").timestamp()))  # type: ignore[union-attr]
    page_size = min(limit, MAX_EVENTS_PAGE_SIZE)

    # Create main coordination ID for async logging traceability
    coord_id = f"coord_{int(time.time() * 1000) % 10000}"
    demisto.debug(f"[{coord_id}] Starting events fetch with {page_size=}, {limit=}")

    prev_fetch_failure_tasks = []
    new_tasks = []
    for event_type in client.event_types_to_fetch:
        # for each event type, we run 2 separated async fetch
        # 1. to fetch the previous failed fetches (which stored in the last run) collected in prev_fetch_failure_tasks
        # 2. fetch the new events (regular fetch) collected in the new_tasks list

        demisto.debug(f"[{coord_id}] Processing event type: {event_type}")
        # get failures from previous iteration
        prev_fetch_failure_tasks.extend(handle_prev_fetch_failures(client, last_run, event_type, send_to_xsiam, coord_id))
        last_run_current_type = last_run.get(event_type, {})
        start_time = last_run_current_type.get("next_fetch_start_time", epoch_last_day)
        end_time = last_run_current_type.get("next_fetch_end_time", epoch_current_time)
        offset = int(last_run_current_type.get("next_fetch_offset", 0))
        demisto.debug(f"[{coord_id}] Scheduling async task for {event_type}: start={start_time}, end={end_time}, offset={offset}")
        new_tasks.append(
            handle_event_type_async(client, event_type, start_time, end_time, offset, limit, send_to_xsiam, coord_id)
        )

    demisto.debug(
        f"[{coord_id}] Starting asyncio.gather for {len(prev_fetch_failure_tasks)} retry tasks + {len(new_tasks)} new tasks"
    )
    results = await asyncio.gather(*prev_fetch_failure_tasks, *new_tasks, return_exceptions=True)
    success_tasks = list(filter(lambda res: not isinstance(res, BaseException), results))
    failures_tasks = list(filter(lambda res: isinstance(res, BaseException), results))
    demisto.debug(f"[{coord_id}] Async gather completed - success: {len(success_tasks)}, failures: {len(failures_tasks)}")

    if failures_tasks and not success_tasks:
        # meaning, all the tasks was failed
        demisto.debug(f"[{coord_id}] All tasks failed, raising exception")
        raise DemistoException(failures_tasks[0])
    new_last_run: dict = {}
    for task_result in success_tasks:
        # Type check for mypy
        if isinstance(task_result, tuple):
            event_type, event_type_res = task_result
            # event_type_res is in structure of:
            # {'events':[...], ''failures':[...], additional data like next_run_start_time, next_run_offset}
            all_events.extend(event_type_res.pop("events", []))
            existing_failures = demisto.get(new_last_run, f"{event_type}.failures", defaultParam=[])
            existing_failures.extend(event_type_res.pop("failures", []))

            # in the init, set to the old last_run data
            new_last_run.setdefault(event_type, last_run.get(event_type, {}))
            if event_type_res:
                # in case of new data - override the old data
                new_last_run[event_type] = event_type_res
            if len(existing_failures) > MAX_FAILURE_ENTRIES_TO_HANDLE_PER_TYPE:
                demisto.debug(
                    f"Truncating failures for {event_type}: {len(existing_failures)} > {MAX_FAILURE_ENTRIES_TO_HANDLE_PER_TYPE}, "
                    f"storing only the first {MAX_FAILURE_ENTRIES_TO_HANDLE_PER_TYPE}."
                )
            new_last_run[event_type]["failures"] = existing_failures[:MAX_FAILURE_ENTRIES_TO_HANDLE_PER_TYPE]

    demisto.debug(f"Handled {len(all_events)} total events in {time.time() - start:.2f} seconds")

    return all_events, new_last_run


async def get_events_command_async(
    client: Client, args: dict[str, Any], last_run: dict, send_to_xsiam: bool = False
) -> CommandResults:
    limit = arg_to_number(args.get("limit")) or 10
    events, _ = await handle_fetch_and_send_all_events(client=client, last_run=last_run, limit=limit, send_to_xsiam=send_to_xsiam)

    for event in events:
        event["timestamp"] = timestamp_to_datestring(event["timestamp"] * 1000)

    readable_output = tableToMarkdown(
        "Events List:",
        events,
        removeNull=True,
        headers=["_id", "timestamp", "type", "access_method", "app", "traffic_type"],
        headerTransform=string_to_table_header,
    )

    results = CommandResults(
        outputs_prefix="Netskope.Event",
        outputs_key_field="_id",
        outputs=events,
        readable_output=readable_output,
        raw_response=events,
    )

    return results


async def test_module(client: Client, last_run: dict) -> str:
    await get_events_command_async(client=client, args={"limit": 1}, last_run=last_run, send_to_xsiam=False)
    return "ok"


""" MAIN FUNCTION """


async def main() -> None:  # pragma: no cover
    try:
        params = demisto.params()

        url = params.get("url")
        base_url = urljoin(url, "/api/v2/")
        token = params.get("credentials", {}).get("password")
        verify_certificate = not params.get("insecure", False)
        proxy = params.get("proxy", False)
        max_fetch: int = arg_to_number(params.get("max_fetch")) or 10000

        command_name = demisto.command()
        demisto.debug(f"Command being called is {command_name}")

        event_types_to_fetch = handle_event_types_to_fetch(params.get("event_types_to_fetch"))
        demisto.debug(f"Event types that will be fetched in this instance: {event_types_to_fetch}")

        async with Client(base_url, token, proxy, verify_certificate, event_types_to_fetch) as client:
            last_run = demisto.getLastRun()
            demisto.debug(f"Running with the following last_run - {last_run}")

            new_last_run: dict = {}
            if command_name == "test-module":
                # This is the call made when pressing the integration Test button.
                result = await test_module(client, last_run)  # type: ignore[arg-type]
                return_results(result)

            elif command_name == "netskope-get-events":
                args = demisto.args()
                send_to_xsiam = argToBoolean(args.get("should_push_events", "true"))
                demisto.debug(f"Running netskope-get-events with send_to_xsiam={send_to_xsiam}")
                results = await get_events_command_async(client, args, last_run, send_to_xsiam)
                return_results(results)

            elif command_name == "fetch-events":
                demisto.debug(f"Starting fetch with last run {last_run}")
                all_events, new_last_run = await handle_fetch_and_send_all_events(
                    client=client, last_run=last_run, limit=max_fetch, send_to_xsiam=True
                )
                demisto.debug(f"Fetched {len(all_events)} total events.")
                next_trigger_time(len(all_events), max_fetch, new_last_run)
                demisto.debug(f"Setting the last_run to: {new_last_run}")
                demisto.setLastRun(new_last_run)

    except Exception as e:
        # Log the specific exception type and full traceback for better debugging
        error_traceback = traceback.format_exc()
        demisto.error(f"{type(e).__name__} in {command_name}: {str(e)}\nTraceback:\n{error_traceback}")
        last_run = new_last_run if new_last_run else demisto.getLastRun()
        last_run.pop("nextTrigger", None)
        demisto.setLastRun(last_run)
        demisto.debug(f"last run after removing nextTrigger {last_run}")
        return_error(f"Failed to execute {command_name} command.\nError: {type(e).__name__}: {str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    asyncio.run(main())
