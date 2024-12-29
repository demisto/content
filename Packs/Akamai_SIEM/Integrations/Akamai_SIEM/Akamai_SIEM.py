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
            Multiple json objects as list of dictionaries, offset for next pagnination
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
    ) -> tuple[list[dict], str | None]:
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
        events: list[dict] = []
        for event in raw_response.split('\n'):
            try:
                events.append(json.loads(event))
            except Exception as e:
                if event:  # The last element might be an empty dict.
                    demisto.error(f"Could not decode the {event=}, reason: {e}")
        offset = events.pop().get("offset")
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
        if should_skip_decode_events:
            for event in events:
                event["_time"] = event["httpMessage"]["start"]
        else:
            for event in events:
                try:
                    event["_time"] = event["httpMessage"]["start"]
                    if "attackData" in event:
                        for attack_data_key in ['rules', 'ruleMessages', 'ruleTags', 'ruleData', 'ruleSelectors',
                                                'ruleActions', 'ruleVersions']:
                            event['attackData'][attack_data_key] = decode_message(event.get('attackData', {}).get(attack_data_key,
                                                                                                                  ""))
                    if "httpMessage" in event:
                        event['httpMessage']['requestHeaders'] = decode_url(
                            event.get('httpMessage', {}).get('requestHeaders', ""))
                        event['httpMessage']['responseHeaders'] = decode_url(
                            event.get('httpMessage', {}).get('responseHeaders', ""))
                except Exception as e:
                    config_id = event.get('attackData', {}).get('configId', "")
                    policy_id = event.get('attackData', {}).get('policyId', "")
                    demisto.debug(f"Couldn't decode event with {config_id=} and {policy_id=}, reason: {e}")
        total_events_count += len(events)
        execution_counter += 1
        yield events, offset, total_events_count, auto_trigger_next_run
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
                    demisto.info(f"Sending {len(events)} events to xsiam using multithreads."
                                 f"latest event time is: {events[-1]['_time']}")
                    futures = send_events_to_xsiam(events, VENDOR, PRODUCT, should_update_health_module=False,
                                                   chunk_size=SEND_EVENTS_TO_XSIAM_CHUNK_SIZE,
                                                   multiple_threads=True)
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

        else:
            human_readable, entry_context, raw_response = commands[command](client, **demisto.args())
            return_outputs(human_readable, entry_context, raw_response)

    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ in ["__builtin__", "builtins", '__main__']:  # pragma: no cover
    main()
