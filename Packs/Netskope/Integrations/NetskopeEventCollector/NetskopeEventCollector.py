from itertools import chain
from aiohttp import ClientResponseError
import asyncio
import aiohttp
import time
from typing import Any

import urllib3

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member
''' CONSTANTS '''

ALL_SUPPORTED_EVENT_TYPES = ['application', 'alert', 'page', 'audit', 'network', 'incident']
MAX_EVENTS_PAGE_SIZE = 10000
MAX_RETRY = 3
NETSKOP_SEMAPHORE_COUNT = 4
MAX_FAILURE_ENTRIES_TO_HANDLE_PER_TYPE = 10

# Netskope response constants
RATE_LIMIT_REMAINING = "ratelimit-remaining"  # Rate limit remaining
RATE_LIMIT_RESET = "ratelimit-reset"  # Rate limit RESET value is in seconds
VENDOR = "netskope"
PRODUCT = "netskope"
XSIAM_SEM = asyncio.Semaphore(20)

''' CLIENT CLASS '''


class Client:
    """
    Client for Netskope RESTful API.

    Args:
        base_url (str): The base URL of Netskope.
        token (str): The token to authenticate against Netskope API.
        validate_certificate (bool): Specifies whether to verify the SSL certificate or not.
        proxy (bool): Specifies if to use XSOAR proxy settings.
    """

    def __init__(self, base_url: str, token: str, proxy: bool, session: aiohttp.ClientSession, event_types_to_fetch: list[str]):
        self.fetch_status: dict = {event_type: False for event_type in event_types_to_fetch}
        self.event_types_to_fetch: list[str] = event_types_to_fetch
        self.netskope_semaphore = asyncio.Semaphore(NETSKOP_SEMAPHORE_COUNT)
        self._async_session = session
        self._headers = {"Netskope-Api-Token": f"{token}", "Accept": "application/json"}
        self._base_url = base_url
        self._proxy_url = handle_proxy().get('http') if proxy else None

    async def get_events_data_async(self, type, params):
        url_suffix = f"events/data/{type}"
        url = urljoin(self._base_url, url_suffix)
        async with self.netskope_semaphore:

            async with self._async_session.get(url, params=params, headers=self._headers, proxy=self._proxy_url) as resp:
                demisto.debug(f'getting {type} events data, {params=}')
                resp.raise_for_status()
                return await resp.json()

    async def get_events_count(self, type, params):
        """Return the count of event existing for the given type and time

        Args:
            type (str): the events type
            params (dict): request params
            session (aiohttp.ClientSession): the session
            sem (asyncio.Semaphore): a semaphore

        Returns:
            str: the count of event existing for the given type and time
        """
        event_count = 0
        res = await self.get_events_data_async(type, params | {'fields': 'event_count:count(id)'})
        if res.get('result'):
            event_count = res.get('result')[0].get('event_count')

        demisto.debug(f'there is {event_count} total {type} events for the given time')
        return event_count


''' HELPER FUNCTIONS '''


def next_trigger_time(num_of_events, max_fetch, new_last_run):
    """Check wether to add the next trigger key to the next_run dict based on number of fetched events.

    Args:
        num_of_events (int): The number of events fetched.
        max_fetch (int): The maximum fetch limit.
        new_last_run (dict): the next_run to update
    """
    if num_of_events > (max_fetch / 2):
        new_last_run['nextTrigger'] = '0'
    else:
        new_last_run.pop('nextTrigger', None)


def populate_parsing_rule_fields(event: dict, event_type: str):
    """
    Handles the source_log_event and _time fields.
    Sets the source_log_event to the given event type and _time to the time taken from the timestamp field

    Args:
        event (dict): the event to edit
        event_type (str): the event type tp set in the source_log_event field
    """
    event['source_log_event'] = event_type
    try:
        event['_time'] = timestamp_to_datestring(event['timestamp'] * 1000, is_utc=True)
    except TypeError:
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
        event_id = event.get('_id')
        event['event_id'] = event_id

    return events


def handle_event_types_to_fetch(event_types_to_fetch) -> list[str]:
    """ Handle event_types_to_fetch parameter.
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


def hanlde_errors(failures):
    failures_res = []
    if failures:
        for failure in failures:
            if isinstance(failure, DemistoException):
                if 'Unauthorized' in failure.message:
                    raise failure

                failure_data: dict = failure.res
                demisto.debug(f'error occured when fetching {failure_data}, {str(failure.exception)}')
                failures_res.append(
                    {
                        'start_time': failure_data.get('insertionstarttime'),
                        'end_time': failure_data.get('insertionendtime'),
                        'offset': failure_data.get('offset', 0),
                        'limit': failure_data.get('limit')
                    }
                )
            else:
                demisto.error(f'error occured when fetching, {str(failure)}')

    return failures_res


def handle_prev_fetch_failures(client: Client, last_run: dict, event_type: str, send_to_xsiam: bool):
    tasks = []
    failure_data = demisto.get(last_run, f'{event_type}.failures', defaultParam=[])
    if failure_data:
        # each failre entry are with the structore {'start_time': ..., 'end_time': ..., 'offset': ..., 'limit':...}
        demisto.debug(f'there is {len(failure_data)} failure records for {event_type=}, {failure_data=}, handle them')
        for failure_entry in failure_data:
            tasks.append(
                handle_event_type_async(
                    client=client,
                    event_type=event_type,
                    send_to_xsiam=send_to_xsiam,
                    is_re_fetch_failed_fetch=True,
                    **failure_entry
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
            demisto.debug(f'Remaining rate limit is: {remaining}')
            if int(remaining) <= 0:
                demisto.debug(f'Rate limiting reached for {event_type=} and {params=}')
                if to_sleep := headers.get(RATE_LIMIT_RESET):
                    demisto.debug(f'Going to async sleep for {to_sleep} seconds to avoid rate limit error')
                    await asyncio.sleep(int(to_sleep))
                else:
                    # if the RESET value does not exist in the header then
                    # sleep for default 1 second as the rate limit remaining is 0
                    demisto.debug('Did not find a rate limit reset value, going to sleep for 1 second to avoid rate limit error')
                    await asyncio.sleep(1)

                return True

    except ValueError as ve:
        logging.error(f"Value error when honoring the rate limiting wait time {headers} {str(ve)}")

    return False


async def handle_event_type_async(client: Client, event_type: str, start_time: str, end_time: str, offset: int, limit: int, send_to_xsiam: bool, is_re_fetch_failed_fetch: bool = False):
    page_size = min(limit, MAX_EVENTS_PAGE_SIZE)
    params = assign_params(
        limit=page_size,
        offset=offset,
        insertionstarttime=start_time,
        insertionendtime=end_time
    )

    demisto.debug(f"Fetching '{event_type}' events with params: {params}")
    success_res, failures = await fetch_and_send_events_async(client, event_type, params, limit, send_to_xsiam, is_re_fetch_failed_fetch)

    if not success_res and failures and not is_re_fetch_failed_fetch:
        # this case mean that there is no success fetch/send, so need to raise exception
        # and stay with the previos next_fetch_start_time
        e: DemistoException = failures[0]
        if 'Unauthorized' in e.message:
            msg = 'Unauthorized Error: please validate your credentials.'
        elif 'certificate verify failed' in e.message:
            msg = 'Connection Error: certificate verification failed, try to use the insecure checkbox.'
        elif 'Cannot connect to host' in e.message:
            msg = 'Connection Error: please validate your Server URL.'
        else:
            msg = f'Fetching event_type_start_time_end_time_offset: {event_type}_{start_time}_{end_time}_{offset} Failed, {str(failures[0])}'
        demisto.error(msg)
        raise DemistoException(
            msg,
            exception=failures[0]
        )
    failures_data = hanlde_errors(failures)
    events = list(chain.from_iterable(success_res))
    demisto.debug(f"The number of fetched events - {len(events)}")

    res_dict = {'events': events, 'failures': failures_data}
    demisto.debug(f"Fetched {len(events)} {event_type} events")
    if not is_re_fetch_failed_fetch:
        # in case of is_re_fetch_failed_fetch=True, it's mean we are trying to fetch a chunk from previos fetch that failed
        # so, no aditional info is needed.
        if len(events) == limit:
            # meaning, there may be another events to fetch for the current time "window"
            # save the start_time and end_time and the next offset

            next_fetch_data = {
                "next_fetch_start_time": start_time,
                "next_fetch_end_time": end_time,
                "next_fetch_offset": offset + len(events)
            }
            demisto.debug(
                f'fetched {(len(events) == limit)=}, need to store the time window and offset for next fetch, {next_fetch_data=}')
            res_dict |= next_fetch_data
        else:
            res_dict |= {"next_fetch_start_time": end_time}
    return event_type, res_dict


async def fetch_and_send_events_async(client: Client, type: str, request_params: dict, limit: int, send_to_xsiam: bool, is_re_fetch_failed_fetch: bool = False):

    async def _handle_page(params):

        async def _fetch_page():
            retry_count = 0
            while retry_count < MAX_RETRY:
                try:
                    if retry_count > 0:
                        # in retry
                        demisto.debug(
                            f'Rate limit (429) occured for {type=} with {params=}, will retrying as {retry_count=} < {MAX_RETRY=}')

                    offset = params.get('offset')
                    demisto.debug(f"fetching {type=} events from {offset=}")
                    return await client.get_events_data_async(type, params)
                except ClientResponseError as e:
                    if e.status != 429:  # not rate limit
                        raise e
                    if await honor_rate_limiting_async(e.headers, type, params):
                        retry_count += 1
                    else:
                        raise e
            demisto.debug(f'Rate limit (429) occured and {retry_count=} reached the {MAX_RETRY=}')
            return {}

        async def _send_page_to_xsiam(events):
            async with XSIAM_SEM:
                demisto.debug(f"send {len(events)} events to xsiam")
                await asyncio.to_thread(
                    send_events_to_xsiam,
                    events=events, vendor=VENDOR,
                    product=PRODUCT,
                    chunk_size=XSIAM_EVENT_CHUNK_SIZE_LIMIT
                )
        try:
            res = await _fetch_page()
            events = res.get('result', [])
            events = prepare_events(events, type)
            if send_to_xsiam:
                await _send_page_to_xsiam(events)
        except Exception as e:
            raise DemistoException(message=str(e), exception=e, res=params)
        return events

    async def _handle_all_pages():

        try:
            # the `offset` shouldnt be in the get_events_count request
            init_offset = int(request_params.pop('offset', 0))

            if is_re_fetch_failed_fetch:
                # in case of re-fetch failures we don't use pagination, just the fetch the failed chunk
                total_events = limit
                max_offset = init_offset + int(limit)
            else:
                total_events = await client.get_events_count(type, request_params)
                max_offset = min(total_events, init_offset + int(limit))

            request_limit = request_params.get('limit', MAX_EVENTS_PAGE_SIZE)
            demisto.debug(
                f"Going to fetch {min(total_events, limit)} events from {init_offset=} by chunks of {request_limit} ...")
            tasks = [
                # asyncio.create_task(_handle_page(request_params | {'offset': offset}))
                _handle_page(request_params | {'offset': offset})
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


''' COMMANDS FUNCTIONS '''


async def handle_fetch_and_send_all_events(client: Client,
                                           last_run: dict,
                                           limit: int = MAX_EVENTS_PAGE_SIZE,
                                           send_to_xsiam=False) -> tuple[list[dict], dict]:
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
    # support_multithreading()

    remove_unsupported_event_types(last_run, client.event_types_to_fetch)

    all_events = []
    epoch_current_time = str(int(arg_to_datetime("now").timestamp()))  # type: ignore[union-attr]
    epoch_last_month = str(int(arg_to_datetime("1 month").timestamp()))  # type: ignore[union-attr]
    page_size = min(limit, MAX_EVENTS_PAGE_SIZE)

    demisto.debug(f"Starting events fetch with {page_size=}, {limit=} ")

    prev_fetch_failure_tasks = []
    new_tasks = []
    for event_type in client.event_types_to_fetch:
        # for each event type, we run 2 seperated async fecth
        # 1. to fetch the previous failed fetchs (which stored in the last run) collected in prev_fetch_failure_tasks
        # 2. fecth the new events (regular fetch) collected in the new_tasks list

        # get failures from previous iteration
        prev_fetch_failure_tasks.extend(
            handle_prev_fetch_failures(client, last_run, event_type, send_to_xsiam)
        )
        last_run_current_type = last_run.get(event_type, {})
        start_time = last_run_current_type.get("next_fetch_start_time", epoch_last_month)
        end_time = last_run_current_type.get("next_fetch_end_time", epoch_current_time)
        offset = int(last_run_current_type.get("next_fetch_offset", 0))
        new_tasks.append(
            handle_event_type_async(client, event_type, start_time, end_time, offset, limit, send_to_xsiam)
        )

    results = await asyncio.gather(*prev_fetch_failure_tasks, *new_tasks, return_exceptions=True)
    success_tasks = list(filter(lambda res: not isinstance(res, BaseException), results))
    failures_tasks = list(filter(lambda res: isinstance(res, BaseException), results))

    if failures_tasks and not success_tasks:
        # meainig, all the tasks was failed
        raise DemistoException(failures_tasks[0])
    new_last_run: dict = {}
    for event_type, event_type_res in success_tasks:

        # event_type_res is in structore of:
        # {'events':[...], ''failures':[...], additional data like next_run_start_time, next_run_offset}
        all_events.extend(event_type_res.pop('events', []))
        existing_failures = demisto.get(new_last_run, f'{event_type}.failures', defaultParam=[])
        existing_failures.extend(event_type_res.pop('failures', []))

        # in the init, set to the old last_run data
        new_last_run.setdefault(event_type, last_run.get(event_type, {}))
        if event_type_res:
            # in case of new data - ovveride the old data
            new_last_run[event_type] = event_type_res

        # if len(existing_failures) >= MAX_FAILURE_ENTRIES_TO_HANDLE_PER_TYPE:
        #     demisto.error(f'there is {existing_failures=} >= {MAX_FAILURE_ENTRIES_TO_HANDLE_PER_TYPE=} for {event_type=},'
        #                   f'storing the first {MAX_FAILURE_ENTRIES_TO_HANDLE_PER_TYPE} only')
        new_last_run[event_type]['failures'] = existing_failures[:MAX_FAILURE_ENTRIES_TO_HANDLE_PER_TYPE]

    demisto.debug(f"Handled {len(all_events)} total events in {time.time() - start:.2f} seconds")

    return all_events, new_last_run


async def get_events_command_async(client: Client, args: dict[str, Any], last_run: dict, send_to_xsiam: bool = False) -> CommandResults:
    limit = arg_to_number(args.get('limit')) or MAX_EVENTS_PAGE_SIZE
    events, _ = await handle_fetch_and_send_all_events(client=client, last_run=last_run, limit=limit, send_to_xsiam=send_to_xsiam)

    for event in events:
        event['timestamp'] = timestamp_to_datestring(event['timestamp'] * 1000)

    readable_output = tableToMarkdown('Events List:', events,
                                      removeNull=True,
                                      headers=['_id', 'timestamp', 'type', 'access_method', 'app', 'traffic_type'],
                                      headerTransform=string_to_table_header)

    results = CommandResults(outputs_prefix='Netskope.Event',
                             outputs_key_field='_id',
                             outputs=events,
                             readable_output=readable_output,
                             raw_response=events)

    return results


async def test_module(client: Client, last_run: dict) -> str:
    await get_events_command_async(client=client, args={'limit': 1}, last_run=last_run, send_to_xsiam=False)
    return 'ok'


''' MAIN FUNCTION '''


async def main() -> None:  # pragma: no cover
    try:
        params = demisto.params()

        url = params.get('url')
        base_url = urljoin(url, '/api/v2/')
        token = params.get('credentials', {}).get('password')
        verify_certificate = not params.get('insecure', False)
        proxy = params.get('proxy', False)
        max_fetch: int = arg_to_number(params.get('max_fetch')) or 10000

        command_name = demisto.command()
        demisto.debug(f'Command being called is {command_name}')

        event_types_to_fetch = handle_event_types_to_fetch(params.get('event_types_to_fetch'))
        demisto.debug(f'Event types that will be fetched in this instance: {event_types_to_fetch}')

        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(verify_ssl=verify_certificate)) as session:
            client = Client(base_url, token, proxy, session, event_types_to_fetch)

            last_run = demisto.getLastRun()
            demisto.debug(f'Running with the following last_run - {last_run}')

            new_last_run: dict = {}
            if command_name == 'test-module':
                # This is the call made when pressing the integration Test button.
                result = await test_module(client, last_run)  # type: ignore[arg-type]
                return_results(result)

            elif command_name == 'netskope-get-events':
                args = demisto.args()
                send_to_xsiam = argToBoolean(args.get('should_push_events', 'true'))
                results = await get_events_command_async(client, args, last_run, send_to_xsiam)
                return_results(results)

            elif command_name == 'fetch-events':
                demisto.debug(f'Starting fetch with last run {last_run}')
                all_event_types, new_last_run = await handle_fetch_and_send_all_events(
                    client=client,
                    last_run=last_run,
                    limit=max_fetch,
                    send_to_xsiam=False
                )
                next_trigger_time(len(all_event_types), max_fetch, new_last_run)
                demisto.debug(f"Setting the last_run to: {new_last_run}")
                demisto.setLastRun(new_last_run)

    # Log exceptions and return errors
    except Exception as e:
        last_run = new_last_run if new_last_run else demisto.getLastRun()
        last_run.pop('nextTrigger', None)
        demisto.setLastRun(last_run)
        demisto.debug(f'last run after removing nextTrigger {last_run}')
        return_error(f'Failed to execute {command_name} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    asyncio.run(main())
