import functools
from requests import Request
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
""" IMPORTS """
# Std imports
from datetime import datetime, timezone
from base64 import b64decode

# 3-rd party imports
from typing import Any
from collections.abc import Iterator, Sequence
import urllib.parse
import urllib3
from akamai.edgegrid import EdgeGridAuth
# Local imports
from CommonServerUserPython import *
import concurrent.futures
import asyncio
import aiohttp


"""GLOBALS/PARAMS

Attributes:
    INTEGRATION_NAME:
        Name of the integration as shown in the integration UI, for example: Microsoft Graph User.

    INTEGRATION_COMMAND_NAME:
        Command names should be written in all lower-case letters,
        and each word separated with a hyphen, for example: msgraph-user.

    INTEGRATION_CONTEXT_NAME:
        Context output names should be written in camel case, for example: MSGraphUser.
"""
INTEGRATION_NAME = 'Akamai SIEM'
INTEGRATION_COMMAND_NAME = 'akamai-siem'
INTEGRATION_CONTEXT_NAME = 'Akamai'


VENDOR = "Akamai"
PRODUCT = "WAF"
FETCH_EVENTS_MAX_PAGE_SIZE = 20000  # Allowed events limit per request.
TIME_TO_RUN_BUFFER = 30  # When calculating time left to run, will use this as a safe zone delta.
EXECUTION_START_TIME = datetime.now()
ALLOWED_PAGE_SIZE_DELTA_RATIO = 0.95  # uses this delta to overcome differences from Akamai When calculating latest request size.
MAX_ALLOWED_FETCH_LIMIT = 80000
SEND_EVENTS_TO_XSIAM_CHUNK_SIZE = 9 * (10 ** 6)  # 9 MB

# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    def get_events(self, config_ids: str, offset: str | None = '', limit: str | int | None = None,
                   from_epoch: str | None = '', to_epoch: str | None = '') \
            -> tuple[list[Any], Any]:
        """
            Get security events from Akamai WAF service by - https://developer.akamai.com/api/cloud_security/siem/v1.html,
            Pay attention response as text of multiple json objects
            Allowed query parameters combinations:
                1. offset - Since a prior request.
                2. offset, limit - Since a prior request, limited.
                3. from - Since a point in time.
                4. from, limit - Since a point in time, limited.
                5. from, to - Over a range of time.
                6. from, to, limit - Over a range of time, limited.
        Args:
            config_ids: Unique identifier for each security configuration. To report on more than one configuration, separate
                      integer identifiers with semicolons, e.g. 12892;29182;82912.
            offset: This token denotes the last message. If specified, this operation fetches only security events that have
                    occurred from offset. This is a required parameter for offset mode and you can’t use it in time-based
                    requests.
            limit: Defines the approximate maximum number of security events each fetch returns, in both offset and
                   time-based modes. The default limit is 10000. Expect requests to return a slightly higher number of
                   security events than you set in the limit parameter, because data is stored in different buckets.
            from_epoch: The start of a specified time range, expressed in Unix epoch seconds.
                        This is a required parameter to get time-based results for a set period, and you can’t use it in
                        offset mode.
            to_epoch: The end of a specified time range, expressed in Unix epoch seconds. You can’t use this parameter in
                      offset mode and it’s an optional parameter in time-based mode. If omitted, the value defaults to the
                      current time.

        Returns:
            Multiple json objects as list of dictionaries, offset for next pagination
        """
        params = {
            'offset': offset,
            'limit': limit,
            'to': to_epoch,
            'from': from_epoch,
        }
        raw_response: str = self._http_request(method='GET',
                                               url_suffix=f'/{config_ids}',
                                               params=assign_params(**params),
                                               resp_type='text')
        events: list = []
        if '{ "total": 0' not in raw_response:
            events = [json.loads(event) for event in raw_response.split('\n')[:-2]]
            new_offset = str(max([int(event.get('httpMessage', {}).get('start')) for event in events]))
        else:
            new_offset = str(from_epoch)
        return events, new_offset

    def get_events_with_offset(
        self,
        config_ids: str,
        offset: str | None = '',
        limit: int = 20,
        from_epoch: str = ''
    ) -> tuple[list[str], str | None]:
        params: dict[str, int | str] = {
            'limit': limit
        }
        if offset:
            demisto.info(f"received {offset=} will run an offset based request.")
            params["offset"] = offset
        else:
            from_param = int(from_epoch)
            params["from"] = from_param
            demisto.info(f"did not receive an offset. will run a time based request with {from_param=}")
        raw_response: str = self._http_request(
            method='GET',
            url_suffix=f'/{config_ids}',
            params=params,
            resp_type='text',
        )
        demisto.info("Finished executing request to Akamai, processing")
        events: list[str] = raw_response.split('\n')
        offset = None
        try:
            if events and events[-1] == "":
                events.pop()
            offset_context = events.pop()
            loaded_offset_context = json.loads(offset_context)
            offset = loaded_offset_context.get("offset")
        except Exception as e:
            demisto.error(f"couldn't decode offset with {offset_context=}, reason {e}")
        return events, offset


'''HELPER FUNCIONS'''


def date_format_converter(from_format: str, date_before: str, readable_format: str = '%Y-%m-%dT%H:%M:%SZ%Z') -> str:
    """
        Convert datatime object from epoch time to follow format %Y-%m-%dT%H:%M:%SZ
    Args:
        from_format: format to convert from.
        date_before: date before conversion epoch time or %Y-%m-%dT%H:%M:%SZ format
        readable_format: readable format by default %Y-%m-%dT%H:%M:%SZ
    Examples:
        >>> date_format_converter(from_format='epoch', date_before='1576570098')
        '2019-12-17T08:08:18Z'
        >>> date_format_converter(from_format='epoch', date_before='1576570098', readable_format='%Y-%m-%d %H:%M:%S')
        '2019-12-17 08:08:18'
        >>> date_format_converter(from_format='readable', date_before='2019-12-17T08:08:18Z')
        '1576570098'

    Returns:
        Converted date as Datetime object or string object
    """
    converted_date: str | int = ''
    if from_format == 'epoch':
        converted_date = datetime.utcfromtimestamp(int(date_before)).strftime(readable_format)
    elif from_format == 'readable':
        date_before += 'UTC'
        converted_date = int(datetime.strptime(date_before,
                                               readable_format).replace(tzinfo=timezone.utc).timestamp())  # noqa: UP017

    return str(converted_date)


def decode_message(msg: str) -> Sequence[str | None]:
    """
        Follow these steps for data members that appear within the event’s attackData section:
            1. If the member name is prefixed rule, URL-decode the value.
            2. The result is a series of base64-encoded chunks delimited with semicolons.
            3. Split the value at semicolon (;) characters.
            4. base64-decode each chunk of split data.
             The example above would yield a sequence of alert, alert, and deny.
    Args:
        msg: Messeage to decode

    Returns:
        Decoded message as array

    Examples:
        >>> decode_message(msg='ZGVueQ%3d%3d')
        ['deny']
        >>> decode_message(msg='Q3VzdG9tX1JlZ0VYX1J1bGU%3d%3bTm8gQWNjZXB0IEhlYWRlciBBTkQgTm8gVXNlciBBZ2VudCBIZWFkZXI%3d')
        ['Custom_RegEX_Rule', 'No Accept Header AND No User Agent Header']
    """
    readable_msg = []
    translated_msg = urllib.parse.unquote(msg).split(';')
    for word in translated_msg:
        word = b64decode(word).decode('utf-8', errors='replace')
        if word:
            readable_msg.append(word)
    return readable_msg


def events_to_ec(raw_response: list) -> tuple[list, list, list]:
    """
        Convert raw response response to ec
    Args:
        raw_response: events as list from raw response

    Returns:
        events as defined entry context and events for human readable
    """
    events_ec: list[dict] = []
    ip_ec: list[dict] = []
    events_human_readable: list[dict] = []

    for event in raw_response:
        events_ec.append(
            {
                "AttackData": assign_params(
                    ConfigID=event.get('attackData', {}).get('configId'),
                    PolicyID=event.get('attackData', {}).get('policyId'),
                    ClientIP=event.get('attackData', {}).get('clientIP'),
                    Rules=decode_message(event.get('attackData', {}).get('rules')),
                    RuleMessages=decode_message(event.get('attackData', {}).get('ruleMessages')),
                    RuleTags=decode_message(event.get('attackData', {}).get('ruleTags')),
                    RuleData=decode_message(event.get('attackData', {}).get('ruleData')),
                    RuleSelectors=decode_message(event.get('attackData', {}).get('ruleSelectors')),
                    RuleActions=decode_message(event.get('attackData', {}).get('ruleActions'))
                ),
                "HttpMessage": assign_params(
                    RequestId=event.get('httpMessage', {}).get('requestId'),
                    Start=event.get('httpMessage', {}).get('start'),
                    Protocol=event.get('httpMessage', {}).get('protocol'),
                    Method=event.get('httpMessage', {}).get('method'),
                    Host=event.get('httpMessage', {}).get('host'),
                    Port=event.get('httpMessage', {}).get('port'),
                    Path=event.get('httpMessage', {}).get('path'),
                    RequestHeaders=event.get('httpMessage', {}).get('requestHeaders'),
                    Status=event.get('httpMessage', {}).get('status'),
                    Bytes=event.get('httpMessage', {}).get('bytes'),
                    ResponseHeaders=event.get('httpMessage', {}).get('responseHeaders')
                ),
                "Geo": assign_params(
                    Continent=event.get('geo', {}).get('continent'),
                    Country=event.get('geo', {}).get('country'),
                    City=event.get('geo', {}).get('city'),
                    RegionCode=event.get('geo', {}).get('regionCode'),
                    Asn=event.get('geo', {}).get('asn')
                )
            }
        )

        ip_ec.append(assign_params(
            Address=event.get('attackData', {}).get('clientIP'),
            ASN=event.get('geo', {}).get('asn'),
            Geo={
                "Country": event.get('geo', {}).get('country')
            }
        ))

        events_human_readable.append(assign_params(**{
            'Attacking IP': event.get('attackData', {}).get('clientIP'),
            "Config ID": event.get('attackData', {}).get('configId'),
            "Policy ID": event.get('attackData', {}).get('policyId'),
            "Rules": decode_message(event.get('attackData', {}).get('rules')),
            "Rule messages": decode_message(event.get('attackData', {}).get('ruleMessages')),
            "Rule actions": decode_message(event.get('attackData', {}).get('ruleActions')),
            'Date occured': date_format_converter(from_format='epoch',
                                                  date_before=event.get('httpMessage', {}).get('start')),
            "Location": {
                'Country': event.get('geo', {}).get('country'),
                'City': event.get('geo', {}).get('city')
            }
        }))

    return events_ec, ip_ec, events_human_readable


''' COMMANDS '''


@logger
def test_module_command(client: Client) -> tuple[None, None, str]:
    """Performs a basic GET request to check if the API is reachable and authentication is successful.

    Args:
        client: Client object with request
        *_: Usually demisto.args()

    Returns:
        'ok' if test successful.

    Raises:
        DemistoException: If test failed.
    """
    # Test on the following date Monday, 6 March 2017 16:07:22
    events, offset = client.get_events(config_ids=demisto.params().get('configIds'),
                                       from_epoch='1488816442',
                                       limit='1')
    if isinstance(events, list):
        return None, None, 'ok'
    raise DemistoException(f'Test module failed, {events}')


@logger
def fetch_incidents_command(
        client: Client,
        fetch_time: str,
        fetch_limit: str | int,
        config_ids: str,
        last_run: str | None = None) -> tuple[list[dict[str, Any]], dict]:
    """Uses to fetch incidents into Demisto
    Documentation: https://github.com/demisto/content/tree/master/docs/fetching_incidents

    Args:
        client: Client object with request
        fetch_time: From when to fetch if first time, e.g. `3 days`
        fetch_limit: limit of incidents in a fetch
        config_ids: security configuration ids to fetch, e.g. `51000;56080`
        last_run: Last fetch object occurs.

    Returns:
        incidents, new last_run
    """
    raw_response: list | None = []
    if not last_run:
        last_run, _ = parse_date_range(date_range=fetch_time, date_format='%s')
    raw_response, offset = client.get_events(config_ids=config_ids, from_epoch=last_run, limit=fetch_limit)

    incidents = []
    if raw_response:
        for event in raw_response:
            attack_data = event.get('attackData', {})
            http_message = event.get('httpMessage', {})
            incidents.append({
                'name': f"{INTEGRATION_NAME}: {attack_data.get('configId')} - {http_message.get('requestId')}",
                'occurred': date_format_converter(from_format='epoch', date_before=http_message.get('start')),
                'rawJSON': json.dumps(event)
            })

    return incidents, {'lastRun': offset}


def get_events_command(client: Client, config_ids: str, offset: str | None = None, limit: str | None = None,
                       from_epoch: str | None = None, to_epoch: str | None = None, time_stamp: str | None = None) \
        -> tuple[object, dict, list | dict]:
    """
        Get security events from Akamai WAF service
        Allowed query parameters combinations:
            1. offset - Since a prior request.
            2. offset, limit - Since a prior request, limited.
            3. from - Since a point in time.
            4. from, limit - Since a point in time, limited.
            5. from, to - Over a range of time.
            6. from, to, limit - Over a range of time, limited.
    Args:
        client: Client object
        config_ids: Unique identifier for each security configuration. To report on more than one configuration, separate
                  integer identifiers with semicolons, e.g. 12892;29182;82912.
        offset: This token denotes the last message. If specified, this operation fetches only security events that have
                occurred from offset. This is a required parameter for offset mode and you can’t use it in time-based requests.
        limit: Defines the approximate maximum number of security events each fetch returns, in both offset and
               time-based modes. The default limit is 10000. Expect requests to return a slightly higher number of
               security events than you set in the limit parameter, because data is stored in different buckets.
        from_epoch: The start of a specified time range, expressed in Unix epoch seconds.
                    This is a required parameter to get time-based results for a set time_stamp, and you can’t use it in
                    offset mode.
        to_epoch: The end of a specified time range, expressed in Unix epoch seconds. You can’t use this parameter in
                  offset mode and it’s an optional parameter in time-based mode. If omitted, the value defaults to the
                  current time.
        time_stamp: timestamp (<number> <time unit>, e.g., 12 hours, 7 days of events

    Returns:
        Human readable, entry context, raw response
    """
    if time_stamp:
        from_epoch, to_epoch = parse_date_range(date_range=time_stamp,
                                                date_format="%s")
    raw_response, offset = client.get_events(config_ids=config_ids,
                                             offset=offset,
                                             limit=limit,
                                             from_epoch=from_epoch,
                                             to_epoch=to_epoch)
    if raw_response:
        events_ec, ip_ec, events_human_readable = events_to_ec(raw_response)
        entry_context = {
            "Akamai.SIEM(val.HttpMessage.RequestId && val.HttpMessage.RequestId == obj.HttpMessage.RequestId)": events_ec,
            outputPaths.get('ip'): ip_ec
        }
        title = f'{INTEGRATION_NAME} - Attacks data'

        human_readable = tableToMarkdown(name=title,
                                         t=events_human_readable,
                                         removeNull=True)

        return human_readable, entry_context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


def reset_offset_command(client: Client):  # pragma: no cover
    ctx = get_integration_context()
    if "offset" in ctx:
        del ctx["offset"]
    set_integration_context(ctx)
    return 'Offset was reset successfully.', {}, {}


def is_last_request_smaller_than_page_size(num_events_from_previous_request: int, page_size: int) -> bool:
    """Checks wether the number of events from the last API call was lower by a certain delta than the request page size.

    Args:
        num_events_from_previous_request (int): The length of the list of events from previous response
        page_size (int): the request limit for the last request.

    Returns:
        bool: True if the number of events from last API call was lower by a certain delta for the requested page size.
              Otherwise, return False
    """
    demisto.info(f"Checking whether execution should break with {num_events_from_previous_request=} and {page_size=}")
    return num_events_from_previous_request < page_size * ALLOWED_PAGE_SIZE_DELTA_RATIO


def is_interval_doesnt_have_enough_time_to_run(min_allowed_delta: int, max_time_took: float) -> tuple[bool, float]:
    """
    Checking whether there's enough time for another fetch request to the Akamai API before docker timeout.
    The function calculates the time of the first request (including the send_events_to_xsiam_part).
    And checks wether the remaining running time (plus a little delta) is less or equal the expected running time.
    The remaining running time is docker timeout limit in seconds - the run time so far (now time - docker execution start time).

    Args:
        min_allowed_delta (int): The minimum allowed delta that should remain before going on another fetch interval.
        max_time_took (float): The worst case execution (the first execution) to compare the rest of the executions to.
    Returns:
        bool: Return True if there's not enough time. Otherwise, return False.
    """
    timeout_time_nano_seconds = demisto.callingContext.get('context', {}).get('TimeoutDuration')
    demisto.info(f"Got {timeout_time_nano_seconds} non seconds for the execution.")
    timeout_time_seconds = timeout_time_nano_seconds / 1_000_000_000
    now = datetime.now()
    time_since_interval_beginning = (now - EXECUTION_START_TIME).total_seconds()
    if not max_time_took:
        max_time_took = time_since_interval_beginning
    demisto.info(f"Checking if execution should break with {time_since_interval_beginning=}, {max_time_took=}.")
    return (timeout_time_seconds - time_since_interval_beginning - min_allowed_delta) <= max_time_took, max_time_took


@logger
def fetch_events_command(
    client: Client,
    fetch_time: str,
    fetch_limit: int,
    config_ids: str,
    ctx: dict,
    page_size: int,
    should_skip_decode_events: bool
) -> Iterator[Any]:
    """Iteratively gathers events from Akamai SIEM. Stores the offset in integration context.

    Args:
        client: Client object with request
        fetch_time: From when to fetch if first time, e.g. `3 days`
        fetch_limit: limit of events in a fetch
        config_ids: security configuration ids to fetch, e.g. `51000;56080`
        ctx: The integration context
        page_size: The number of events to limit for every request.
        should_skip_decode_events: Wether to skip events decoding or not.

    Yields:
        (list[dict], str, int, set[str], bool): events, new offset, total number of events fetched,
        event hashes from current fetch, and whether to set nexttrigger=0 for next execution.
    """
    total_events_count = 0
    offset = ctx.get("offset")
    from_epoch, _ = parse_date_range(fetch_time, date_format='%s')
    auto_trigger_next_run = False
    worst_case_time: float = 0
    execution_counter = 0
    while total_events_count < fetch_limit:
        if execution_counter > 0:
            demisto.info(f"The execution number is {execution_counter}, checking for breaking conditions.")
            if is_last_request_smaller_than_page_size(len(events), page_size):  # type: ignore[has-type]  # pylint: disable=E0601
                demisto.info("last request wasn't big enough, breaking.")
                break
            should_break, worst_case_time = is_interval_doesnt_have_enough_time_to_run(TIME_TO_RUN_BUFFER, worst_case_time)
            if should_break:
                demisto.info("Not enough time for another execution, breaking and triggering next run.")
                auto_trigger_next_run = True
                break
        if (remaining_events_to_fetch := fetch_limit - total_events_count) < page_size:
            demisto.info(f"{remaining_events_to_fetch=} < {page_size=}, lowering page_size to {remaining_events_to_fetch}.")
            page_size = remaining_events_to_fetch
        demisto.info(f"Preparing to get events with {offset=}, {page_size=}, and {fetch_limit=}")
        try:
            events, offset = client.get_events_with_offset(config_ids, offset, page_size, from_epoch)
        except DemistoException as e:
            demisto.error(f"Got an error when trying to request for new events from Akamai\n{e}")
            if "Requested Range Not Satisfiable" in str(e):
                err_msg = f'Got offset out of range error when attempting to fetch events from Akamai.\n' \
                    "This occurred due to offset pointing to events older than 12 hours.\n" \
                    "Restarting fetching events after 11 hours ago. Some events were missed.\n" \
                    "If you wish to fetch more up to date events, " \
                    "please run 'akamai-siem-reset-offset' on the specific instance.\n" \
                    'For more information, please refer to the Troubleshooting section in the integration documentation.\n' \
                    f'original error: [{e}]'
                raise DemistoException(err_msg)
            else:
                raise DemistoException(e)

        if not events:
            demisto.info("Didn't receive any events, breaking.")
            break
        demisto.info(f"got {len(events)} events, moving to processing events data.")
        processed_events = []
        if should_skip_decode_events:
            demisto.info("skipping events decode.")
            processed_events = events
        else:
            demisto.info("Preparing to load and decode events.")
            for event in events:
                try:
                    event = json.loads(event)
                    if "attackData" in event:
                        for attack_data_key in ['rules', 'ruleMessages', 'ruleTags', 'ruleData', 'ruleSelectors',
                                                'ruleActions', 'ruleVersions']:
                            event['attackData'][attack_data_key] = decode_message(  # type: ignore[index, attr-defined]
                                event.get('attackData',  # type: ignore[attr-defined]
                                          {}).get(attack_data_key, ""))
                    if "httpMessage" in event:
                        event['httpMessage']['requestHeaders'] = decode_url(  # type: ignore[index]
                            event.get('httpMessage', {}).get('requestHeaders', ""))  # type: ignore[attr-defined]
                        event['httpMessage']['responseHeaders'] = decode_url(  # type: ignore[index]
                            event.get('httpMessage', {}).get('responseHeaders', ""))  # type: ignore[attr-defined]
                except Exception as e:
                    demisto.debug(f"Couldn't decode {event=}, reason: {e}")
                finally:
                    processed_events.append(event)
        total_events_count += len(processed_events)
        execution_counter += 1
        yield processed_events, offset, total_events_count, auto_trigger_next_run
    yield [], offset, total_events_count, auto_trigger_next_run


def decode_url(headers: str) -> dict:
    """Decoding the httpMessage headers parts of the response.

    Args:
        headers (str): The headers to decode

    Returns:
        dict: The decoded and parsed headers as a dictionary.
    """
    decoded_lines = urllib.parse.unquote(headers).replace("\r", "").split("\n")
    decoded_dict = {}
    for line in decoded_lines:
        parts = line.split(': ', 1)
        if len(parts) == 2:
            key, value = parts
            decoded_dict[key.replace("-", "_")] = value.replace('"', '')
    return decoded_dict


def post_latest_event_time(latest_event, base_msg):
    try:
        if isinstance(latest_event, str):
            latest_event = json.loads(latest_event)
        latest_event_time = date_format_converter(
            from_format='epoch', date_before=latest_event.get("httpMessage", {}).get("start", "0"))
        demisto.info(f"{base_msg} latest event time is: {latest_event_time}")
    except Exception as e:
        demisto.debug(f"caught an exception when attempting to execute latest_event_time {e}")
        demisto.info(base_msg)


############################################## Beginning of beta part ##############################################
BETA_FETCH_EVENTS_MAX_PAGE_SIZE = 600000  # Allowed events limit per request.
MAX_ALLOWED_CONCURRENT_TASKS = 10000


async def get_events_with_offset_aiohttp(
    client: Client,
    config_ids: str,
    offset: str | None = '',
    limit: int = 200000,
    from_epoch: str = '',
    counter: int = 0
) -> tuple[list[str], str | None]:
    """Send request to get events from Akamai.

    Args:
        client: Client object with request.
        config_ids (str): security configuration ids to fetch, e.g. `51000;56080`.
        offset (str | None): The offset (hash) to use for offset based mechanism.
        limit (int, optional): The number of events to limit for every request.
        from_epoch (str): From when to fetch if first time.
        counter (int, optional): The execution number.

    Returns:
        tuple[list[str], str | None]: The events and offset obtained from last request.
    """
    params: dict[str, int | str] = {
        'limit': limit
    }
    if offset:
        demisto.info(f"Running in interval = {counter}. received {offset=} will run an offset based request.")
        params["offset"] = offset
    else:
        from_param = int(from_epoch)
        params["from"] = from_param
        demisto.info(f"Running in interval = {counter}. didn't receive offset. will run a time based request with {from_param=}.")

    url = f"{client._base_url}/{config_ids}"
    demisto.info(f"Running in interval = {counter}. Init session and sending request.")
    loop = asyncio.get_event_loop()
    import requests
    # response = await loop.run_in_executor(None, requests.get, url=url, auth=client._auth, params=params)
    try:
        response = await loop.run_in_executor(None, functools.partial(requests.get, url, params=params, auth=client._auth, verify=client._verify))
        response.raise_for_status()  # Check for any HTTP errors
        raw_response=response.text
    except aiohttp.ClientResponseError as e:
        raise DemistoException(f"Running in interval = {counter}. Error occurred when fetching from Akamai: {e.message}")
    demisto.info(f"Running in interval = {counter}. Finished executing request to Akamai, processing")
    events: list[str] = raw_response.split('\n')
    new_offset = None
    try:
        offset_context = events.pop()
        loaded_offset_context = json.loads(offset_context)
        new_offset = loaded_offset_context.get("offset")
    except Exception as e:
        demisto.error(f"Running in interval = {counter}. Couldn't decode offset with {offset_context=}, reason {e}")
        new_offset = offset
    return events, new_offset


''' COMMANDS '''


async def wait_until_tasks_load_decrease(counter: int, max_concurrent_tasks: int):
    """Testing if there's a tasks load. If so, will go to sleep for 30 seconds so execution can catch up.

    Args:
        counter (int): The current execution number.
        max_concurrent_tasks (int): The maximum number of tasks allowed to run concurrently.
    """
    while (num_of_tasks := len(asyncio.all_tasks())) > max_concurrent_tasks:
        demisto.info(f"Running in interval = {counter}. current tasks total size = {num_of_tasks} is larger than the max allowed"
                     f" number of tasks {max_concurrent_tasks}. sleeping for 30 seconds to let other tasks finish.")
        await asyncio.sleep(30)


@logger
async def fetch_events_long_running_command(client: Client,
                                            from_time: str,
                                            page_size: int,
                                            config_ids: str,
                                            ctx: dict,
                                            should_skip_decode_events: bool,
                                            max_concurrent_tasks: int):
    """Asynchronously gathers events from Akamai SIEM. Decode them, and send them to xsiam.

    Args:
        client: Client object with request.
        from_time (str): From when to fetch if first time, e.g. `3 days`.
        page_size (int): The number of events to limit for every request.
        config_ids (str): security configuration ids to fetch, e.g. `51000;56080`.
        ctx (dict): The integration context.
        should_skip_decode_events (bool): Whether we should skip serializing and decoding events or not.
        max_concurrent_tasks (int): The maximum number of tasks allowed to run concurrently.

    """
    offset = ctx.get("offset")
    async for events, counter, last_offset in get_events_from_akamai(client, config_ids, from_time, page_size,
                                                                     offset, max_concurrent_tasks):
        asyncio.create_task(process_and_send_events_to_xsiam(events, should_skip_decode_events,  # noqa: RUF006
                                                             last_offset, counter))
        offset = last_offset


async def process_and_send_events_to_xsiam(events: list[str], should_skip_decode_events: bool, offset: str | None, counter: int):
    """Process the event if should_skip_decode_events=False (json serialize and decode).
    Send the events to CSP's send_events_to_xsiam.
    save the offset after the execution is done and update the module health.

    Args:
        events (list[str]): The list of json serialized events.
        should_skip_decode_events (bool): Whether we should skip serializing and decoding events or not.
        offset (str | None): The offset hash.
        counter (int): The current execution number.
    """
    demisto.info(f"Running in interval = {counter}. got {len(events)} events, moving to processing events data.")
    processed_events = []
    if should_skip_decode_events:
        demisto.info(f"Running in interval = {counter}. Skipping decode events.")
        processed_events = events
    else:
        demisto.info(f"Running in interval = {counter}. decoding events.")
        processed_events = []
        for event in events:
            try:
                event = json.loads(event)
                if "attackData" in event:
                    for attack_data_key in ['rules', 'ruleMessages', 'ruleTags', 'ruleData', 'ruleSelectors',
                                            'ruleActions', 'ruleVersions']:
                        event['attackData'][attack_data_key] = decode_message(  # type: ignore[index, attr-defined]
                            event.get('attackData',  # type: ignore[attr-defined]
                                      {}).get(attack_data_key, ""))
                if "httpMessage" in event:
                    event['httpMessage']['requestHeaders'] = decode_url(  # type: ignore[index]
                        event.get('httpMessage', {}).get('requestHeaders', ""))  # type: ignore[attr-defined]
                    event['httpMessage']['responseHeaders'] = decode_url(  # type: ignore[index]
                        event.get('httpMessage', {}).get('responseHeaders', ""))  # type: ignore[attr-defined]
            except Exception as e:
                demisto.debug(f"Couldn't decode {event=}, reason: {e}")
            finally:
                processed_events.append(event)
    post_latest_event_time(
        latest_event=processed_events[-1],
        base_msg=f"Running in interval = {counter}. Sending {len(processed_events)} events to xsiam."
    )
    demisto.info("skipping sending events to xsiam due to custom content item.")
    # tasks = send_events_to_xsiam_akamai(processed_events, VENDOR, PRODUCT, should_update_health_module=False,
    #                                     chunk_size=SEND_EVENTS_TO_XSIAM_CHUNK_SIZE, send_events_asynchronously=True,
    #                                     url_key="host", data_format="json", data_size_expected_to_split_evenly=True,
    #                                     counter=counter)
    demisto.info(f"Running in interval = {counter}. Finished executing send_events_to_xsiam, waiting for tasks to end.")
    # await asyncio.gather(*tasks)
    demisto.info(f"Running in interval = {counter}. Finished gathering all tasks.")
    demisto.info(f"Running in interval = {counter}. Updating module health.")
    set_integration_context({"offset": offset})
    demisto.updateModuleHealth({'eventsPulled': len(processed_events)})
    demisto.info(f"Running in interval = {counter}. Finished updating module health.")


async def get_events_from_akamai(client: Client,
                                 config_ids: str,
                                 from_time: str,
                                 page_size: int,
                                 offset: str | None,
                                 max_concurrent_tasks: int):
    """Iteratively checks for condition where the loop should wait due to multiple reasons
    and then gathers events from Akamai SIEM.

    Args:
        client: Client object with request.
        config_ids (str): security configuration ids to fetch, e.g. `51000;56080`.
        from_time (str): From when to fetch if first time, e.g. `3 days`.
        page_size: The number of events to limit for every request.
        offset (str | None): The offset (hash) to use for offset based mechanism.
        max_concurrent_tasks (int): The maximum number of tasks allowed to run concurrently.

    Yields:
        (list[str], int, str): events (not serialized), counter (the current execution number), and the new offset.
    """
    counter = 0
    while True:
        if counter > 100_000:
            demisto.info("counter reach 100k, bringing it back to 0.")
            counter = 0
        counter += 1
        from_epoch, _ = parse_date_range(date_range=from_time, date_format='%s')
        demisto.info(f"Running in interval = {counter}. Preparing to get events with {offset=}, and {page_size=}.")
        try:
            demisto.info(f"Running in interval = {counter}. Testing for possible tasks qt overflow.")
            await wait_until_tasks_load_decrease(counter, max_concurrent_tasks)
            demisto.info(f"Running in interval = {counter}. Finished testing for possible tasks qt overflow.")
            get_events_task = get_events_with_offset_aiohttp(client, config_ids, offset, page_size, from_epoch, counter=counter)
            events, offset = None, None
            events, offset = await get_events_task
            demisto.info(f"Running in interval = {counter}. got {len(events)} events and {offset=}.")
        except DemistoException as e:
            demisto.error(f"{e.message}")
            err = str(e)
            if "Requested Range Not Satisfiable" in err:
                err = f"Running in interval = {counter}. Got offset out of range error when attempting to fetch events from" \
                    "Akamai. \nThis occurred due to offset pointing to events older than 12 hours which isn't supported by " \
                    f"akamai.\nRestarting fetching events to start from {from_time} ago." \
                    'For more information, please refer to the Troubleshooting section in the integration documentation.\n' \
                    f'original error: [{err}]'
                offset = None
            demisto.updateModuleHealth(err, is_error=True)
            demisto.info(f"Running in interval = {counter}. Going to sleep for 60 seconds.")
            await asyncio.sleep(60)
            demisto.info(f"Running in interval = {counter}. Done sleeping 60 seconds.")
        if events:
            yield events, counter, offset
        if not events or is_last_request_smaller_than_page_size(len(events), page_size):
            if not events:
                demisto.debug(f"Running in interval = {counter}. No events were received from Akamai,"
                              "going to sleep for 60 seconds.")
            else:
                demisto.debug(f"Running in interval = {counter}. got {len(events)} events which is less"
                              f" than {ALLOWED_PAGE_SIZE_DELTA_RATIO} % of the {page_size=}, going to sleep for 60 seconds.")
            await asyncio.sleep(60)
            demisto.info(f"Running in interval = {counter}. Finished sleeping for 60 seconds.")


############################################## Beginning of CSP copy-paste part ##############################################


def akamai_send_data_to_xsiam(data, vendor, product, data_format=None, url_key='url', num_of_attempts=3,
                              chunk_size=XSIAM_EVENT_CHUNK_SIZE, data_type=EVENTS, should_update_health_module=True,
                              add_proxy_to_request=False, snapshot_id='', items_count=None, send_events_asynchronously=False,
                              data_size_expected_to_split_evenly=False, counter=0):  # pragma: no cover
    """
    Send the supported fetched data types into the XDR data-collector private api.

    :type data: ``Union[str, list]``
    :param data: The data to send to XSIAM server. Should be of the following:
        1. List of strings or dicts where each string or dict represents an event or asset.
        2. String containing raw events separated by a new line.

    :type vendor: ``str``
    :param vendor: The vendor corresponding to the integration that originated the data.

    :type product: ``str``
    :param product: The product corresponding to the integration that originated the data.

    :type data_format: ``str``
    :param data_format: Should only be filled in case the 'events' parameter contains a string of raw
        events in the format of 'leef' or 'cef'. In other cases the data_format will be set automatically.

    :type url_key: ``str``
    :param url_key: The param dict key where the integration url is located at. the default is 'url'.

    :type num_of_attempts: ``int``
    :param num_of_attempts: The num of attempts to do in case there is an api limit (429 error codes)

    :type chunk_size: ``int``
    :param chunk_size: Advanced - The maximal size of each chunk size we send to API. Limit of 9 MB will be inforced.

    :type data_type: ``str``
    :param data_type: Type of data to send to Xsiam, events or assets.

    :type should_update_health_module: ``bool``
    :param should_update_health_module: whether to trigger the health module showing how many events were sent to xsiam
        This can be useful when using send_data_to_xsiam in batches for the same fetch.

    :type add_proxy_to_request: ``bool``
    :param add_proxy_to_request: whether to add proxy to the send evnets request.

    :type snapshot_id: ``str``
    :param snapshot_id: the snapshot id.

    :type items_count: ``str``
    :param items_count: the asset snapshot items count.

    :type send_events_asynchronously: ``bool``
    :param send_events_asynchronously: whether to use asyncio to send the events to xsiam asynchronously or not.
    Note that when set to True, the updateModuleHealth should be done from the integration itself.

    :type data_size_expected_to_split_evenly: ``bool``
    :param data_size_expected_to_split_evenly: whether the events should be about the same size or not.
    Use this to split data to chunks faster.

    :return: Either None if running regularly or a list of asyncio task objects if running asynchronously:.
    In case of running asynchronously:, the list of tasks will hold the number of events sent and can be accessed by:
    await asyncio.gather(*tasks)
    :rtype: ``List[Task]`` or ``None``
    """
    data_size = 0
    params = demisto.params()
    url = params.get(url_key)
    calling_context = demisto.callingContext.get('context', {})
    instance_name = calling_context.get('IntegrationInstance', '')
    collector_name = calling_context.get('IntegrationBrand', '')
    if not items_count:
        items_count = len(data) if isinstance(data, list) else 1
    if data_type not in DATA_TYPES:
        demisto.debug("data type must be one of these values: {types}".format(types=DATA_TYPES))
        return

    if not data:
        demisto.debug('send_data_to_xsiam function received no {data_type}, '
                      'skipping the API call to send {data} to XSIAM'.format(data_type=data_type, data=data_type))
        demisto.updateModuleHealth({'{data_type}Pulled'.format(data_type=data_type): data_size})
        return

    # only in case we have data to send to XSIAM we continue with this flow.
    # Correspond to case 1: List of strings or dicts where each string or dict represents an one event or asset or snapshot.
    if isinstance(data, list):
        # In case we have list of dicts we set the data_format to json and parse each dict to a stringify each dict.
        demisto.debug("Sending {size} {data_type} to XSIAM".format(size=len(data), data_type=data_type))
        if isinstance(data[0], dict):
            data = [json.dumps(item) for item in data]
            data_format = 'json'
        # Separating each event with a new line
        data = '\n'.join(data)
    elif not isinstance(data, str):
        raise DemistoException('Unsupported type: {data} for the {data_type} parameter.'
                               ' Should be a string or list.'.format(data=type(data), data_type=data_type))
    if not data_format:
        data_format = 'text'

    xsiam_api_token = demisto.getLicenseCustomField('Http_Connector.token')
    xsiam_domain = demisto.getLicenseCustomField('Http_Connector.url')
    xsiam_url = 'https://api-{xsiam_domain}'.format(xsiam_domain=xsiam_domain)
    headers = remove_empty_elements({
        'authorization': xsiam_api_token,
        'format': data_format,
        'product': product,
        'vendor': vendor,
        'content-encoding': 'gzip',
        'collector-name': collector_name,
        'instance-name': instance_name,
        'final-reporting-device': url,
        'collector-type': ASSETS if data_type == ASSETS else EVENTS
    })
    if data_type == ASSETS:
        if not snapshot_id:
            snapshot_id = str(round(time.time() * 1000))

        # We are setting a time stamp ahead of the instance name since snapshot-ids must be configured in ascending
        # alphabetical order such that first_snapshot < second_snapshot etc.
        headers['snapshot-id'] = snapshot_id + instance_name
        headers['total-items-count'] = str(items_count)

    header_msg = 'Error sending new {data_type} into XSIAM.\n'.format(data_type=data_type)

    def data_error_handler(res):
        """
        Internal function to parse the XSIAM API errors
        """
        try:
            response = res.json()
            error = res.reason
            if response.get('error').lower() == 'false':
                xsiam_server_err_msg = response.get('error')
                error += ": " + xsiam_server_err_msg

        except ValueError:
            if res.text:
                error = '\n{}'.format(res.text)
            else:
                error = "Received empty response from the server"

        api_call_info = (
            'Parameters used:\n'
            '\tURL: {xsiam_url}\n'
            '\tHeaders: {headers}\n\n'
            'Response status code: {status_code}\n'
            'Error received:\n\t{error}'
        ).format(xsiam_url=xsiam_url, headers=json.dumps(headers, indent=8), status_code=res.status_code, error=error)

        demisto.error(header_msg + api_call_info)
        raise DemistoException(header_msg + error, DemistoException)

    client = BaseClient(base_url=xsiam_url, proxy=add_proxy_to_request)
    if data_size_expected_to_split_evenly:
        data_chunks = split_data_by_slices(data, chunk_size)
    else:
        data_chunks = split_data_to_chunks(data, chunk_size)

    def send_events(data_chunk):
        chunk_size = len(data_chunk)
        data_chunk = '\n'.join(data_chunk)
        zipped_data = gzip.compress(data_chunk.encode('utf-8'))  # type: ignore[AttributeError,attr-defined]
        xsiam_api_call_with_retries(client=client, events_error_handler=data_error_handler,
                                    error_msg=header_msg, headers=headers,
                                    num_of_attempts=num_of_attempts, xsiam_url=xsiam_url,
                                    zipped_data=zipped_data, is_json_response=True, data_type=data_type)
        return chunk_size

    async def send_events_async(data_chunk):
        chunk_size = len(data_chunk)
        data_chunk = '\n'.join(data_chunk)
        zipped_data = gzip.compress(data_chunk.encode('utf-8'))  # type: ignore[AttributeError,attr-defined]
        _ = await xsiam_api_call_async_with_retries(headers=headers,
                                                    num_of_attempts=num_of_attempts, xsiam_url=xsiam_url,
                                                    zipped_data=zipped_data, data_type=data_type)
        return chunk_size

    if send_events_asynchronously:
        demisto.info(f"Running in interval = {counter}. Sending events to xsiam asynchronously.")
        all_chunks = list(data_chunks)
        demisto.info(f"Running in interval = {counter}. Finished appending all data_chunks to a list.")
        tasks = [asyncio.create_task(send_events_async(chunk)) for chunk in all_chunks]

        demisto.info(f'Finished submiting {len(tasks)} tasks for the {counter} time')
        return tasks
    else:
        demisto.info("Sending events to xsiam synchronously.")
        for chunk in data_chunks:
            data_size += send_events(chunk)

        if should_update_health_module:
            demisto.updateModuleHealth({'{data_type}Pulled'.format(data_type=data_type): data_size})
    return


def split_data_by_slices(data, target_chunk_size):  # pragma: no cover
    """
    Splits a string/list of data into chunks of an approximately specified size.
    The actual size can be lower. the slicing is based on the assumption that all entries have the same size.

    :type data: ``list`` or a ``string``
    :param data: A list of data or a string delimited with \n  to split to chunks.
    :type target_chunk_size: ``int``
    :param target_chunk_size: The maximum size of each chunk. The maximal size allowed is 9MB.

    :return: An iterable of lists where each list contains events with approx size of chunk size.
    :rtype: ``collections.Iterable[list]``
    """
    target_chunk_size = min(target_chunk_size, XSIAM_EVENT_CHUNK_SIZE_LIMIT)
    if isinstance(data, str):
        data = data.split('\n')
    entry_size = sys.getsizeof(data[0])
    num_of_entries_per_chunk = target_chunk_size // entry_size
    for i in range(0, len(data), num_of_entries_per_chunk):
        chunk = data[i:i + num_of_entries_per_chunk]
        yield chunk


async def xsiam_api_call_async_with_retries(
    xsiam_url,
    zipped_data,
    headers,
    num_of_attempts,
    data_type=EVENTS,
):  # pragma: no cover
    """
    Send the fetched events or assets into the XDR data-collector private api.
    :type xsiam_url: ``str``
    :param xsiam_url: The URL of XSIAM to send the api request.
    :type zipped_data: ``bytes``
    :param zipped_data: encoded events
    :type headers: ``dict``
    :param headers: headers for the request
    :type num_of_attempts: ``int``
    :param num_of_attempts: The num of attempts to do in case there is an api limit (429 error codes).
    :type data_type: ``str``
    :param data_type: events or assets
    :return: Response object or DemistoException
    :rtype: ``requests.Response`` or ``DemistoException``
    """
    # retry mechanism in case there is a rate limit (429) from xsiam.
    status_code = None
    attempt_num = 1
    response = None
    while status_code != 200 and attempt_num < num_of_attempts + 1:
        demisto.debug('Sending {data_type} into xsiam, attempt number {attempt_num}'.format(
            data_type=data_type, attempt_num=attempt_num))
        # in the last try we should raise an exception if any error occurred, including 429
        ok_codes = (200, 429) if attempt_num < num_of_attempts else None
        async with aiohttp.ClientSession() as session:
            async with session.post(urljoin(xsiam_url, '/logs/v1/xsiam'), data=zipped_data, headers=headers) as response:
                try:
                    response.raise_for_status()  # This raises an exception for non-2xx status codes
                    status_code = response.status
                except aiohttp.ClientResponseError as e:
                    if ok_codes and e.status in ok_codes:
                        continue
                    else:
                        header_msg = 'Error sending new {data_type} into XSIAM.\n'.format(data_type=data_type)
                        api_call_info = (
                            'Parameters used:\n'
                            '\tURL: {xsiam_url}\n'
                            '\tHeaders: {headers}\n\n'
                            'Response status code: {status_code}\n'
                            'Error received:\n\t{error}\n'
                            'additional request info: \n\t{additional_info}'
                        ).format(xsiam_url=xsiam_url, headers=json.dumps(e.headers, indent=8), status_code=e.status,
                                 error=e.message, additional_info=e.request_info)

                        demisto.error(header_msg + api_call_info)
                        demisto.updateModuleHealth(header_msg + e.message, is_error=True)

        demisto.debug('received status code: {status_code}'.format(status_code=status_code))
        if status_code == 429:
            await asyncio.sleep(1)
        attempt_num += 1
    return response


def send_events_to_xsiam_akamai(events, vendor, product, data_format=None, url_key='url', num_of_attempts=3,
                                chunk_size=XSIAM_EVENT_CHUNK_SIZE, should_update_health_module=True,
                                add_proxy_to_request=False, send_events_asynchronously=False,
                                data_size_expected_to_split_evenly=False, counter=0):  # pragma: no cover
    """
    Send the fetched events into the XDR data-collector private api.

    :type events: ``Union[str, list]``
    :param events: The events to send to XSIAM server. Should be of the following:
        1. List of strings or dicts where each string or dict represents an event.
        2. String containing raw events separated by a new line.

    :type vendor: ``str``
    :param vendor: The vendor corresponding to the integration that originated the events.

    :type product: ``str``
    :param product: The product corresponding to the integration that originated the events.

    :type data_format: ``str``
    :param data_format: Should only be filled in case the 'events' parameter contains a string of raw
        events in the format of 'leef' or 'cef'. In other cases the data_format will be set automatically.

    :type url_key: ``str``
    :param url_key: The param dict key where the integration url is located at. the default is 'url'.

    :type num_of_attempts: ``int``
    :param num_of_attempts: The num of attempts to do in case there is an api limit (429 error codes)

    :type chunk_size: ``int``
    :param chunk_size: Advanced - The maximal size of each chunk size we send to API. Limit of 9 MB will be inforced.

    :type should_update_health_module: ``bool``
    :param should_update_health_module: whether to trigger the health module showing how many events were sent to xsiam

    :type add_proxy_to_request :``bool``
    :param add_proxy_to_request: whether to add proxy to the send evnets request.

    :type send_events_asynchronously: ``bool``
    :param send_events_asynchronously: whether to use asyncio to send the events to xsiam asynchronously or not.
    Note that when set to True, the updateModuleHealth should be done from the integration itself.

    :type data_size_expected_to_split_evenly: ``bool``
    :param data_size_expected_to_split_evenly: whether the events should be about the same size or not.
    Use this to split data to chunks faster.

    :return: Either None if running regularly or a list of asyncio task objects if running asynchronously:.
    In case of running asynchronously:, the list of tasks will hold the number of events sent and can be accessed by:
    await asyncio.gather(*tasks)
    :rtype: ``List[Task]`` or ``None``
    """
    return akamai_send_data_to_xsiam(
        events,
        vendor,
        product,
        data_format,
        url_key,
        num_of_attempts,
        chunk_size,
        data_type="events",
        should_update_health_module=should_update_health_module,
        add_proxy_to_request=add_proxy_to_request,
        send_events_asynchronously=send_events_asynchronously,
        data_size_expected_to_split_evenly=data_size_expected_to_split_evenly,
        counter=counter
    )


############################################## end of CSP copy-paste part ##############################################


############################################## end of beta part ##############################################


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():  # pragma: no cover
    params = demisto.params()
    client = Client(
        base_url=urljoin(params.get('host'), '/siem/v1/configs'),
        verify=not params.get('insecure', False),
        proxy=params.get('proxy'),
        auth=EdgeGridAuth(
            client_token=params.get('clienttoken_creds', {}).get('password') or params.get('clientToken'),
            access_token=params.get('accesstoken_creds', {}).get('password') or params.get('accessToken'),
            client_secret=params.get('clientsecret_creds', {}).get('password') or params.get('clientSecret'),
        )
    )
    commands = {
        "test-module": test_module_command,
        f"{INTEGRATION_COMMAND_NAME}-get-events": get_events_command,
        f"{INTEGRATION_COMMAND_NAME}-reset-offset": reset_offset_command
    }
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        if params.get("isFetch") and not (0 < (arg_to_number(params.get('fetchLimit')) or 20) <= 2000):
            raise DemistoException('Fetch limit must be an integer between 1 and 2000')

        if command == 'fetch-incidents':
            incidents, new_last_run = fetch_incidents_command(client,
                                                              fetch_time=params.get('fetchTime'),
                                                              fetch_limit=params.get('fetchLimit'),
                                                              config_ids=params.get('configIds'),
                                                              last_run=demisto.getLastRun().get('lastRun'))
            demisto.incidents(incidents)
            demisto.setLastRun(new_last_run)
        elif command == "fetch-events":
            if params.get("longRunning", False):
                raise DemistoException("Cannot run both fetch events and long-running command simultaneously.\n"
                                       "Please make sure to set either isFetchEvents or longRunning to false in"
                                       " the integration configuration.")
            page_size = int(params.get("page_size", FETCH_EVENTS_MAX_PAGE_SIZE))
            limit = int(params.get("fetchLimit", 300000))
            if limit > MAX_ALLOWED_FETCH_LIMIT:
                demisto.info(f"Got {limit=} larger than {MAX_ALLOWED_FETCH_LIMIT=}, setting limit to {MAX_ALLOWED_FETCH_LIMIT}.")
                limit = MAX_ALLOWED_FETCH_LIMIT
            if limit < page_size:
                demisto.info(f"Got {limit=} lower than {page_size=}, lowering page_size to {limit}.")
                page_size = limit
            should_skip_decode_events = params.get("should_skip_decode_events", False)
            for events, offset, total_events_count, auto_trigger_next_run in (  # noqa: B007
            fetch_events_command(
                client,
                params.get("fetchTime", "5 minutes"),
                fetch_limit=limit,
                config_ids=params.get("configIds", ""),
                ctx=get_integration_context() or {},
                page_size=page_size,
                should_skip_decode_events=should_skip_decode_events
            )):
                if events:
                    post_latest_event_time(
                        latest_event=events[-1],
                        base_msg=f"Sending {len(events)} events to xsiam using multithreads."
                    )
                    futures = send_events_to_xsiam(events, VENDOR, PRODUCT, should_update_health_module=False,
                                                   chunk_size=SEND_EVENTS_TO_XSIAM_CHUNK_SIZE,
                                                   multiple_threads=True, data_format="json")
                    demisto.info("Finished executing send_events_to_xsiam, waiting for futures to end.")
                    data_size = 0
                    for future in concurrent.futures.as_completed(futures):
                        data_size += future.result()
                    demisto.info(f"Done sending {data_size} events to xsiam."
                                 f"sent {total_events_count} events to xsiam in total during this interval.")
                set_integration_context({"offset": offset})
            demisto.updateModuleHealth({'eventsPulled': (total_events_count or 0)})
            next_run = {}
            if auto_trigger_next_run or total_events_count >= limit:
                demisto.info(f"got {auto_trigger_next_run=} or at least {limit} events this interval - setting nextTrigger=0.")
                next_run["nextTrigger"] = "0"
            else:
                demisto.info(f"Got less than {limit} events this interval - will not trigger next run automatically.")
            demisto.setLastRun(next_run)
        elif command == "long-running-execution":
            if params.get("isFetchEvents", False):
                raise DemistoException("Cannot run both fetch events and long-running command simultaneously.\n"
                                       "Please make sure to set either isFetchEvents or longRunning to false in"
                                       " the integration configuration.")
            page_size = min(int(params.get("beta_page_size", BETA_FETCH_EVENTS_MAX_PAGE_SIZE)), BETA_FETCH_EVENTS_MAX_PAGE_SIZE)
            should_skip_decode_events = params.get("should_skip_decode_events", False)
            max_concurrent_tasks = min(int(params.get("max_concurrent_tasks", 100)), MAX_ALLOWED_CONCURRENT_TASKS)
            demisto.info("Starting long-running execution.")

            asyncio.run(fetch_events_long_running_command(client,
                                                          from_time=params.get('fetchTime', '5 minutes'),
                                                          page_size=page_size,
                                                          config_ids=params.get("configIds", ""),
                                                          ctx=get_integration_context() or {},
                                                          should_skip_decode_events=should_skip_decode_events,
                                                          max_concurrent_tasks=max_concurrent_tasks))

        else:
            human_readable, entry_context, raw_response = commands[command](client, **demisto.args())
            return_outputs(human_readable, entry_context, raw_response)

    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ in ["__builtin__", "builtins", '__main__']:  # pragma: no cover
    main()
