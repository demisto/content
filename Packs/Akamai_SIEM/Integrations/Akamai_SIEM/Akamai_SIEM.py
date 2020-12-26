""" IMPORTS """
# Std imports
from datetime import datetime, timezone
from base64 import b64decode

# 3-rd party imports
from typing import Dict, Tuple, Union, Optional, List, Any, Sequence
import urllib.parse
import urllib3
from akamai.edgegrid import EdgeGridAuth

# Local imports
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

"""GLOBALS/PARAMS

Attributes:
    INTEGRATION_NAME:
        Name of the integration as shown in the integration UI, for example: Microsoft Graph User.

    INTEGRATION_CONTEXT_NAME:
        Context output names should be written in camel case, for example: MSGraphUser.
"""
INTEGRATION_NAME = 'Akamai SIEM'
INTEGRATION_CONTEXT_NAME = 'Akamai'

# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    def get_events(self, config_ids: str, offset: Optional[str] = None, limit: Optional[Union[str, int]] = None,
                   from_epoch: Optional[str] = None, to_epoch: Optional[str] = None) \
            -> Tuple[List[Any], Any]:
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
        events: List = []
        if '{ "total": 0' not in raw_response:
            events = [json.loads(event) for event in raw_response.split('\n')[:-2]]
        offset_new = json.loads(raw_response.split('\n')[-2]).get('offset')
        return events, offset_new


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
    converted_date: Union[str, int] = ''
    if from_format == 'epoch':
        converted_date = datetime.utcfromtimestamp(int(date_before)).strftime(readable_format)
    elif from_format == 'readable':
        date_before += 'UTC'
        converted_date = int(datetime.strptime(date_before, readable_format).replace(tzinfo=timezone.utc).timestamp())

    return str(converted_date)


def decode_message(msg: str) -> Sequence[Optional[str]]:
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
        word = b64decode(word.encode('utf8')).decode('utf8')
        if word:
            readable_msg.append(word)
    return readable_msg


def events_to_ec(raw_response: List) -> Tuple[List, List, List]:
    """
        Convert raw response response to ec
    Args:
        raw_response: events as list from raw response

    Returns:
        events as defined entry context and events for human readable
    """
    events_ec: List[Dict] = []
    ip_ec: List[Dict] = []
    events_human_readable: List[Dict] = []

    for event in raw_response:
        events_ec.append(
            {
                "AttackData": assign_params(**{
                    "ConfigID": event.get('attackData', {}).get('configId'),
                    "PolicyID": event.get('attackData', {}).get('policyId'),
                    "ClientIP": event.get('attackData', {}).get('clientIP'),
                    "Rules": decode_message(event.get('attackData', {}).get('rules')),
                    "RuleMessages": decode_message(event.get('attackData', {}).get('ruleMessages')),
                    "RuleTags": decode_message(event.get('attackData', {}).get('ruleTags')),
                    "RuleData": decode_message(event.get('attackData', {}).get('ruleData')),
                    "RuleSelectors": decode_message(event.get('attackData', {}).get('ruleSelectors')),
                    "RuleActions": decode_message(event.get('attackData', {}).get('ruleActions'))
                }),
                "HttpMessage": assign_params(**{
                    "RequestId": event.get('httpMessage', {}).get('requestId'),
                    "Start": event.get('httpMessage', {}).get('start'),
                    "Protocol": event.get('httpMessage', {}).get('protocol'),
                    "Method": event.get('httpMessage', {}).get('method'),
                    "Host": event.get('httpMessage', {}).get('host'),
                    "Port": event.get('httpMessage', {}).get('port'),
                    "Path": event.get('httpMessage', {}).get('path'),
                    "RequestHeaders": event.get('httpMessage', {}).get('requestHeaders'),
                    "Status": event.get('httpMessage', {}).get('status'),
                    "Bytes": event.get('httpMessage', {}).get('bytes'),
                    "ResponseHeaders": event.get('httpMessage', {}).get('responseHeaders')
                }),
                "Geo": assign_params(**{
                    "Continent": event.get('geo', {}).get('continent'),
                    "Country": event.get('geo', {}).get('country'),
                    "City": event.get('geo', {}).get('city'),
                    "RegionCode": event.get('geo', {}).get('regionCode'),
                    "Asn": event.get('geo', {}).get('asn')
                })
            }
        )

        ip_ec.append(assign_params(**{
            "Address": event.get('attackData', {}).get('clientIP'),
            "ASN": event.get('geo', {}).get('asn'),
            "Geo": {
                "Country": event.get('geo', {}).get('country')
            }
        }))

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
def test_module_command(client: Client) -> Tuple[None, None, str]:
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
        fetch_limit: Union[str, int],
        config_ids: str,
        last_run: Optional[str] = None) -> Tuple[List[Dict[str, Any]], Dict]:
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
    raw_response: Optional[List] = []
    if not last_run:
        datetime_new_last_run, _ = parse_date_range(date_range=fetch_time,
                                                    date_format='%s')
        raw_response, offset = client.get_events(config_ids=config_ids,
                                                 from_epoch=datetime_new_last_run,
                                                 limit=fetch_limit)
    else:
        raw_response, offset = client.get_events(config_ids=config_ids,
                                                 offset=last_run,
                                                 limit=fetch_limit)

    incidents = []
    if raw_response:
        for event in raw_response:
            incidents.append({
                'name': f"{INTEGRATION_NAME}: {event.get('attackData').get('configId')}",
                'occurred': date_format_converter(from_format='epoch',
                                                  date_before=event.get('httpMessage', {}).get('start')),
                'rawJSON': json.dumps(event)
            })

    return incidents, {'lastRun': offset}


def get_events_command(client: Client, config_ids: str, offset: Optional[str] = None, limit: Optional[str] = None,
                       from_epoch: Optional[str] = None, to_epoch: Optional[str] = None, time_stamp: Optional[str] = None) \
        -> Tuple[object, dict, Union[List, Dict]]:
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


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    params = demisto.params()
    client = Client(
        base_url=urljoin(params.get('host'), '/siem/v1/configs'),
        verify=not params.get('insecure', False),
        proxy=params.get('proxy'),
        auth=EdgeGridAuth(
            client_token=params.get('clientToken'),
            access_token=params.get('accessToken'),
            client_secret=params.get('clientSecret')
        )
    )
    commands = {
        "test-module": test_module_command,
        "akamai-siem-get-events": get_events_command
    }
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        if command == 'fetch-incidents':
            incidents, new_last_run = fetch_incidents_command(client,
                                                              fetch_time=params.get('fetchTime'),
                                                              fetch_limit=params.get('fetchLimit'),
                                                              config_ids=params.get('configIds'),
                                                              last_run=demisto.getLastRun().get('lastRun'))
            demisto.incidents(incidents)
            demisto.setLastRun(new_last_run)
        else:
            human_readable, entry_context, raw_response = commands[command](client, **demisto.args())
            return_outputs(human_readable, entry_context, raw_response)

    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ == 'builtins':
    main()
