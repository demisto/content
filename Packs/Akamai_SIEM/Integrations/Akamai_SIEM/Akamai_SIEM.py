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
import hashlib
# Local imports
from CommonServerUserPython import *

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
FETCH_EVENTS_PAGE_SIZE = 50000

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
        events: list[dict] = [json.loads(e) for e in raw_response.split('\n') if e]
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


def dedup_events(hashed_events_mapping: dict[str, dict], hashed_events_from_previous_run: set[str]) -> tuple[List[dict],
                                                                                                             set[str]]:
    """Implement the dedup logic and mapping between the hashes and the related events.

    Args:
        hashed_events_mapping (dict[str, dict]): A mapping between the event's httpMessage hash and the event itself.
        hashed_events_from_previous_run (set[str]): The set of httpMessage hashes from previous run.

    Returns:
        tuple[List[dict], set[str]]: The list of deduped event and the set of hashes from the current run to save to context.
    """
    hashed_events_from_current_run = set(hashed_events_mapping.keys())
    filtered_hashed_events = hashed_events_from_current_run - hashed_events_from_previous_run
    deduped_events: List[dict] = [event for hashed_event,
                                  event in hashed_events_mapping.items() if hashed_event in filtered_hashed_events]
    return deduped_events, hashed_events_from_current_run


@logger
def fetch_events_command(
    client: str,
    fetch_time: str,
    fetch_limit: int,
    config_ids: str,
    ctx: dict,
    page_size: int,
) -> Iterator[Any]:
    """Iteratively gathers events from Akamai SIEM. Stores the offset in integration context.

    Args:
        client: Client object with request
        fetch_time: From when to fetch if first time, e.g. `3 days`
        fetch_limit: limit of events in a fetch
        config_ids: security configuration ids to fetch, e.g. `51000;56080`
        ctx: The integration context
        page_size: The number of events to limit for every request.

    Yields:
        (list[dict], str, int, str): events, new offset, total number of events fetched, and new last_run time to set.
    """
    total_events_count = 0
    from_epoch, _ = parse_date_range(date_range=fetch_time, date_format='%s')
    offset = ctx.get("offset")
    hashed_events_from_previous_run = set(ctx.get("hashed_events_from_previous_run", set()))
    while total_events_count < int(fetch_limit):
        demisto.info(f"Preparing to get events with {offset=}, {page_size=}, and {fetch_limit=}")
        events, offset = get_events_with_offset(config_ids, offset, page_size, from_epoch)
        if not events:
            demisto.info("Didn't receive any events, breaking.")
            break
        hashed_events_mapping = {}
        for event in events:
            try:
                event["_time"] = event["httpMessage"]["start"]
                if "attackData" in event:
                    for attack_data_key in ['rules', 'ruleMessages', 'ruleTags', 'ruleData', 'ruleSelectors',
                                            'ruleActions', 'ruleVersions']:
                        event['attackData'][attack_data_key] = decode_message(event.get('attackData', {}).get(attack_data_key,
                                                                                                              ""))
                if "httpMessage" in event:
                    hashed_events_mapping[(hashlib.sha256(json.dumps(event['httpMessage'],
                                                                     sort_keys=True).encode('utf-8'))).hexdigest()] = event
                    event['httpMessage']['requestHeaders'] = decode_url(event.get('httpMessage', {}).get('requestHeaders', ""))
                    event['httpMessage']['responseHeaders'] = decode_url(event.get('httpMessage', {}).get('responseHeaders', ""))
            except Exception as e:
                config_id = event.get('attackData', {}).get('configId', "")
                policy_id = event.get('attackData', {}).get('policyId', "")
                demisto.debug(f"Couldn't decode event with {config_id=} and {policy_id=}, reason: {e}")
        demisto.info(f"Preparing to deduplicate events, currently got {len(events)} events.")
        deduped_events, hashed_events_from_current_run = dedup_events(hashed_events_mapping, hashed_events_from_previous_run)
        total_events_count += len(deduped_events)
        demisto.info(f"After deduplicate events, Got {len(deduped_events)} events, and {offset=}")
        hashed_events_from_previous_run = hashed_events_from_current_run
        yield deduped_events, offset, total_events_count, hashed_events_from_previous_run
    yield [], offset, total_events_count, hashed_events_from_previous_run


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


def get_events_with_offset(
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
        if not offset:
            demisto.info("preparing to get events without offset.")
            events = [{
  "attackData": {
    "clientIP": "192.0.2.82",
    "configId": "14227",
    "policyId": "qik1_26545",
    "ruleActions": "YWxlcnQ%3d%3bYWxlcnQ%3d%3bZGVueQ%3d%3d",
    "ruleData": "dGVsbmV0LmV4ZQ%3d%3d%3bdGVsbmV0LmV4ZQ%3d%3d%3bVmVjdG9yIFNjb3JlOiAxMCwgREVOWSB0aHJlc2hvbGQ6IDksIEFsZXJ0IFJ1bGVzOiA5NTAwMDI6OTUwMDA2LCBEZW55IFJ1bGU6ICwgTGFzdCBNYXRjaGVkIE1lc3NhZ2U6IFN5c3RlbSBDb21tYW5kIEluamVjdGlvbg%3d%3d",
    "ruleMessages": "U3lzdGVtIENvbW1hbmQgQWNjZXNz%3bU3lzdGVtIENvbW1hbmQgSW5qZWN0aW9u%3bQW5vbWFseSBTY29yZSBFeGNlZWRlZCBmb3IgQ29tbWFuZCBJbmplY3Rpb24%3d",
    "ruleSelectors": "QVJHUzpvcHRpb24%3d%3bQVJHUzpvcHRpb24%3d%3b",
    "ruleTags": "T1dBU1BfQ1JTL1dFQl9BVFRBQ0svRklMRV9JTkpFQ1RJT04%3d%3bT1dBU1BfQ1JTL1dFQl9BVFRBQ0svQ09NTUFORF9JTkpFQ1RJT04%3d%3bQUtBTUFJL1BPTElDWS9DTURfSU5KRUNUSU9OX0FOT01BTFk%3d",
    "ruleVersions": "NA%3d%3d%3bNA%3d%3d%3bMQ%3d%3d",
    "rules": "OTUwMDAy%3bOTUwMDA2%3bQ01ELUlOSkVDVElPTi1BTk9NQUxZ"
  },
  "botData": {
    "botScore": "100",
    "responseSegment": "3"
  },
  "clientData": {
    "appBundleId": "com.mydomain.myapp",
    "appVersion": "1.23",
    "sdkVersion": "4.7.1",
    "telemetryType": "2"
  },
  "format": "json",
  "geo": {
    "asn": "14618",
    "city": "ASHBURN",
    "continent": "288",
    "country": "US",
    "regionCode": "VA"
  },
  "httpMessage": {
    "bytes": "266",
    "host": "www.hmapi.com",
    "method": "GET",
    "path": "/",
    "port": "80",
    "protocol": "HTTP/1.1",
    "query": "option=com_jce%20telnet.exe",
    "requestHeaders": "User-Agent%3a%20BOT%2f0.1%20(BOT%20for%20JCE)%0d%0aAccept%3a%20text%2fhtml,application%2fxhtml+xml,application%2fxml%3bq%3d0.9,*%2f*%3bq%3d0.8%0d%0auniqueID%3a%20CR_H8%0d%0aAccept-Language%3a%20en-US,en%3bq%3d0.5%0d%0aAccept-Encoding%3a%20gzip,%20deflate%0d%0aConnection%3a%20keep-alive%0d%0aHost%3a%20www.hmapi.com%0d%0aContent-Length%3a%200%0d%0a",
    "requestId": "1158db1758e37bfe67b7c09",
    "responseHeaders": "Server%3a%20AkamaiGHost%0d%0aMime-Version%3a%201.0%0d%0aContent-Type%3a%20text%2fhtml%0d%0aContent-Length%3a%20266%0d%0aExpires%3a%20Tue,%2004%20Apr%202017%2010%3a57%3a02%20GMT%0d%0aDate%3a%20Tue,%2004%20Apr%202017%2010%3a57%3a02%20GMT%0d%0aConnection%3a%20close%0d%0aSet-Cookie%3a%20ak_bmsc%3dAFE4B6D8CEEDBD286FB10F37AC7B256617DB580D417F0000FE7BE3580429E23D%7epluPrgNmaBdJqOLZFwxqQLSkGGMy4zGMNXrpRIc1Md4qtsDfgjLCojg1hs2HC8JqaaB97QwQRR3YS1ulk+6e9Dbto0YASJAM909Ujbo6Qfyh1XpG0MniBzVbPMUV8oKhBLLPVSNCp0xXMnH8iXGZUHlUsHqWONt3+EGSbWUU320h4GKiGCJkig5r+hc6V1pi3tt7u3LglG3DloEilchdo8D7iu4lrvvAEzyYQI8Hao8M0%3d%3b%20expires%3dTue,%2004%20Apr%202017%2012%3a57%3a02%20GMT%3b%20max-age%3d7200%3b%20path%3d%2f%3b%20domain%3d.hmapi.com%3b%20HttpOnly%0d%0a",
    "start": "1491303422",
    "status": "200"
  },
  "type": "akamai_siem",
  "userRiskData": {
    "allow": "0",
    "general": "duc_1h:10|duc_1d:30",
    "originUserId": "jsmith007",
    "risk": "udfp:1325gdg4g4343g/M|unp:74256/H",
    "score": "75",
    "status": "0",
    "trust": "ugp:US",
    "username": "jsmith@example.com",
    "uuid": "964d54b7-0821-413a-a4d6-8131770ec8d5"
  },
  "version": "1.0"
}, {"offset": "aaa"}]
        else:
            demisto.info(f"preparing to get events with {offset=}")
            if offset == "aaa":
                events = [{
    "attackData": {
        "clientIP": "192.0.2.82",
        "configId": "14227",
        "policyId": "qik1_26545",
        "ruleActions": "YWxlcnQ%3d%3bYWxlcnQ%3d%3bZGVueQ%3d%3d",
        "ruleData": "dGVsbmV0LmV4ZQ%3d%3d%3bdGVsbmV0LmV4ZQ%3d%3d%3bVmVjdG9yIFNjb3JlOiAxMCwgREVOWSB0aHJlc2hvbGQ6IDksIEFsZXJ0IFJ1bGVzOiA5NTAwMDI6OTUwMDA2LCBEZW55IFJ1bGU6ICwgTGFzdCBNYXRjaGVkIE1lc3NhZ2U6IFN5c3RlbSBDb21tYW5kIEluamVjdGlvbg%3d%3d",
        "ruleMessages": "U3lzdGVtIENvbW1hbmQgQWNjZXNz%3bU3lzdGVtIENvbW1hbmQgSW5qZWN0aW9u%3bQW5vbWFseSBTY29yZSBFeGNlZWRlZCBmb3IgQ29tbWFuZCBJbmplY3Rpb24%3d",
        "ruleSelectors": "QVJHUzpvcHRpb24%3d%3bQVJHUzpvcHRpb24%3d%3b",
        "ruleTags": "T1dBU1BfQ1JTL1dFQl9BVFRBQ0svRklMRV9JTkpFQ1RJT04%3d%3bT1dBU1BfQ1JTL1dFQl9BVFRBQ0svQ09NTUFORF9JTkpFQ1RJT04%3d%3bQUtBTUFJL1BPTElDWS9DTURfSU5KRUNUSU9OX0FOT01BTFk%3d",
        "ruleVersions": "NA%3d%3d%3bNA%3d%3d%3bMQ%3d%3d",
        "rules": "OTUwMDAy%3bOTUwMDA2%3bQ01ELUlOSkVDVElPTi1BTk9NQUxZ"
    },
    "botData": {
        "botScore": "100",
        "responseSegment": "3"
    },
    "clientData": {
        "appBundleId": "com.mydomain.myapp",
        "appVersion": "1.23",
        "sdkVersion": "4.7.1",
        "telemetryType": "2"
    },
    "format": "json",
    "geo": {
        "asn": "14618",
        "city": "ASHBURN",
        "continent": "288",
        "country": "US",
        "regionCode": "VA"
    },
    "httpMessage": {
        "bytes": "266",
        "host": "www.hmapi.com",
        "method": "GET",
        "path": "/",
        "port": "80",
        "protocol": "HTTP/1.1",
        "query": "option=com_jce%20telnet.exe",
        "requestHeaders": "User-Agent%3a%20BOT%2f0.1%20(BOT%20for%20JCE)%0d%0aAccept%3a%20text%2fhtml,application%2fxhtml+xml,application%2fxml%3bq%3d0.9,*%2f*%3bq%3d0.8%0d%0auniqueID%3a%20CR_H8%0d%0aAccept-Language%3a%20en-US,en%3bq%3d0.5%0d%0aAccept-Encoding%3a%20gzip,%20deflate%0d%0aConnection%3a%20keep-alive%0d%0aHost%3a%20www.hmapi.com%0d%0aContent-Length%3a%200%0d%0a",
        "requestId": "1158db1758e37bfe67b7c09",
        "responseHeaders": "Server%3a%20AkamaiGHost%0d%0aMime-Version%3a%201.0%0d%0aContent-Type%3a%20text%2fhtml%0d%0aContent-Length%3a%20266%0d%0aExpires%3a%20Tue,%2004%20Apr%202017%2010%3a57%3a02%20GMT%0d%0aDate%3a%20Tue,%2004%20Apr%202017%2010%3a57%3a02%20GMT%0d%0aConnection%3a%20close%0d%0aSet-Cookie%3a%20ak_bmsc%3dAFE4B6D8CEEDBD286FB10F37AC7B256617DB580D417F0000FE7BE3580429E23D%7epluPrgNmaBdJqOLZFwxqQLSkGGMy4zGMNXrpRIc1Md4qtsDfgjLCojg1hs2HC8JqaaB97QwQRR3YS1ulk+6e9Dbto0YASJAM909Ujbo6Qfyh1XpG0MniBzVbPMUV8oKhBLLPVSNCp0xXMnH8iXGZUHlUsHqWONt3+EGSbWUU320h4GKiGCJkig5r+hc6V1pi3tt7u3LglG3DloEilchdo8D7iu4lrvvAEzyYQI8Hao8M0%3d%3b%20expires%3dTue,%2004%20Apr%202017%2012%3a57%3a02%20GMT%3b%20max-age%3d7200%3b%20path%3d%2f%3b%20domain%3d.hmapi.com%3b%20HttpOnly%0d%0a",
        "start": "1491303422",
        "status": "200"
    },
    "type": "akamai_siem",
    "userRiskData": {
        "allow": "0",
        "general": "duc_1h:10|duc_1d:30",
        "originUserId": "jsmith007",
        "risk": "udfp:1325gdg4g4343g/M|unp:74256/H",
        "score": "75",
        "status": "0",
        "trust": "ugp:US",
        "username": "jsmith@example.com",
        "uuid": "964d54b7-0821-413a-a4d6-8131770ec8d5"
    },
    "version": "1.0"
    }, {"offset": "bbb"}]
            elif offset == "bbb":
                events = [{
    "attackData": {
        "clientIP": "192.0.2.82",
        "configId": "14227",
        "policyId": "qik1_26545",
        "ruleActions": "YWxlcnQ%3d%3bYWxlcnQ%3d%3bZGVueQ%3d%3d",
        "ruleData": "dGVsbmV0LmV4ZQ%3d%3d%3bdGVsbmV0LmV4ZQ%3d%3d%3bVmVjdG9yIFNjb3JlOiAxMCwgREVOWSB0aHJlc2hvbGQ6IDksIEFsZXJ0IFJ1bGVzOiA5NTAwMDI6OTUwMDA2LCBEZW55IFJ1bGU6ICwgTGFzdCBNYXRjaGVkIE1lc3NhZ2U6IFN5c3RlbSBDb21tYW5kIEluamVjdGlvbg%3d%3d",
        "ruleMessages": "U3lzdGVtIENvbW1hbmQgQWNjZXNz%3bU3lzdGVtIENvbW1hbmQgSW5qZWN0aW9u%3bQW5vbWFseSBTY29yZSBFeGNlZWRlZCBmb3IgQ29tbWFuZCBJbmplY3Rpb24%3d",
        "ruleSelectors": "QVJHUzpvcHRpb24%3d%3bQVJHUzpvcHRpb24%3d%3b",
        "ruleTags": "T1dBU1BfQ1JTL1dFQl9BVFRBQ0svRklMRV9JTkpFQ1RJT04%3d%3bT1dBU1BfQ1JTL1dFQl9BVFRBQ0svQ09NTUFORF9JTkpFQ1RJT04%3d%3bQUtBTUFJL1BPTElDWS9DTURfSU5KRUNUSU9OX0FOT01BTFk%3d",
        "ruleVersions": "NA%3d%3d%3bNA%3d%3d%3bMQ%3d%3d",
        "rules": "OTUwMDAy%3bOTUwMDA2%3bQ01ELUlOSkVDVElPTi1BTk9NQUxZ"
    },
    "botData": {
        "botScore": "100",
        "responseSegment": "3"
    },
    "clientData": {
        "appBundleId": "com.mydomain.myapp",
        "appVersion": "1.23",
        "sdkVersion": "4.7.1",
        "telemetryType": "2"
    },
    "format": "json",
    "geo": {
        "asn": "14618",
        "city": "ASHBURN",
        "continent": "288",
        "country": "US",
        "regionCode": "VA"
    },
    "httpMessage": {
        "bytes": "2616",
        "host": "www.hmapi.com",
        "method": "GET",
        "path": "/",
        "port": "aa0",
        "protocol": "HTTP/1dasda.1",
        "query": "option=com_jce%20telnet.asdasdexe",
        "requestHeaders": "User-Agent%3a%20BOT%2f0.1%20(BOT%20for%20JCE)%0d%0aAccept%3a%20text%2fhtml,application%2fxhtml+xml,application%2fxml%3bq%3d0.9,*%2f*%3bq%3d0.8%0d%0auniqueID%3a%20CR_H8%0d%0aAccept-Language%3a%20en-US,en%3bq%3d0.5%0d%0aAccept-Encoding%3a%20gzip,%20deflate%0d%0aConnection%3a%20keep-alive%0d%0aHost%3a%20www.hmapi.com%0d%0aContent-Length%3a%200%0d%0a",
        "requestId": "1158db1758e37bfe67b7c09",
        "responseHeaders": "Server%3a%20AkamaiGHost%0d%0aMime-Version%3a%201.0%0d%0aContent-Type%3a%20text%2fhtml%0d%0aContent-Length%3a%20266%0d%0aExpires%3a%20Tue,%2004%20Apr%202017%2010%3a57%3a02%20GMT%0d%0aDate%3a%20Tue,%2004%20Apr%202017%2010%3a57%3a02%20GMT%0d%0aConnection%3a%20close%0d%0aSet-Cookie%3a%20ak_bmsc%3dAFE4B6D8CEEDBD286FB10F37AC7B256617DB580D417F0000FE7BE3580429E23D%7epluPrgNmaBdJqOLZFwxqQLSkGGMy4zGMNXrpRIc1Md4qtsDfgjLCojg1hs2HC8JqaaB97QwQRR3YS1ulk+6e9Dbto0YASJAM909Ujbo6Qfyh1XpG0MniBzVbPMUV8oKhBLLPVSNCp0xXMnH8iXGZUHlUsHqWONt3+EGSbWUU320h4GKiGCJkig5r+hc6V1pi3tt7u3LglG3DloEilchdo8D7iu4lrvvAEzyYQI8Hao8M0%3d%3b%20expires%3dTue,%2004%20Apr%202017%2012%3a57%3a02%20GMT%3b%20max-age%3d7200%3b%20path%3d%2f%3b%20domain%3d.hmapi.com%3b%20HttpOnly%0d%0a",
        "start": "14913031422",
        "status": "200"
    },
    "type": "akamai_siem",
    "userRiskData": {
        "allow": "0",
        "general": "duc_1h:10|duc_1d:30",
        "originUserId": "jsmith007",
        "risk": "udfp:1325gdg4g4343g/M|unp:74256/H",
        "score": "75",
        "status": "0",
        "trust": "ugp:US",
        "username": "jsmith@example.com",
        "uuid": "964d54b7-0821-413a-a4d6-8131770ec8d5"
    },
    "version": "1.0"
    }, {"offset": "ccc"}]
            elif offset == "ccc":
                events = [{"offset": "ccc"}]
        offset = events.pop().get("offset")
        return events, offset



def main():  # pragma: no cover
    params = demisto.params()
    # client = Client(
    #     base_url=urljoin(params.get('host'), '/siem/v1/configs'),
    #     verify=not params.get('insecure', False),
    #     proxy=params.get('proxy'),
    #     auth=EdgeGridAuth(
    #         client_token=params.get('clienttoken_creds', {}).get('password') or params.get('clientToken'),
    #         access_token=params.get('accesstoken_creds', {}).get('password') or params.get('accessToken'),
    #         client_secret=params.get('clientsecret_creds', {}).get('password') or params.get('clientSecret'),
    #     )
    # )
    client = "bla"
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
            page_size = int(params.get("page_size", FETCH_EVENTS_PAGE_SIZE))
            limit = int(params.get("fetchLimit", 300000))
            for events, offset, total_events_count, hashed_events_from_previous_run in fetch_events_command(  # noqa: B007
                client,
                "5 minutes",
                fetch_limit=limit,
                config_ids=params.get("configIds", ""),
                ctx=get_integration_context() or {},
                page_size=page_size
            ):
                if events:
                    demisto.info(f"Sending events to xsiam with latest event time is: {events[-1]['_time']}")
                    send_events_to_xsiam(events, VENDOR, PRODUCT, should_update_health_module=False)
                set_integration_context({"offset": offset,
                                         "hashed_events_from_previous_run": list(hashed_events_from_previous_run)})
            demisto.updateModuleHealth({'eventsPulled': (total_events_count or 0)})
            next_run = {}
            if total_events_count >= limit:
                next_run["nextTrigger"] = "0"
            demisto.setLastRun(next_run)

        else:
            human_readable, entry_context, raw_response = commands[command](client, **demisto.args())
            return_outputs(human_readable, entry_context, raw_response)

    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ in ["__builtin__", "builtins", '__main__']:  # pragma: no cover
    main()
