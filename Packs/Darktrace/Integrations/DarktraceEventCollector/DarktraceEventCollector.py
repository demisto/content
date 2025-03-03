import hashlib
import hmac
import json
from datetime import datetime, UTC
from typing import Any
from collections.abc import Mapping

import demistomock as demisto
import urllib3
from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()

"""*****CONSTANTS*****"""

VENDOR = 'Darktrace'
PRODUCT = 'Darktrace'
MODEL_BREACH_ENDPOINT = '/modelbreaches'
DARKTRACE_API_ERRORS = {
    'SIGNATURE_ERROR': 'API Signature Error. You have invalid credentials in your config.',
    'DATE_ERROR': 'API Date Error. Check that the time on this machine matches that of the Darktrace instance.',
    'ENDPOINT_ERROR': 'Invalid Endpoint.',
    'PRIVILEGE_ERROR': 'User has insufficient permissions to access the API endpoint.',
    'UNDETERMINED_ERROR': 'Darktrace was unable to process your request.',
    'FAILED_TO_PARSE': 'N/A'
}
DEFAULT_LIMIT = 10
DEFAULT_MAX_FETCH = 1000
DEFAULT_FIRST_FETCH = '3 days'
DEFAULT_STARTTIME = 10
DEFAULT_ENDTIME = 10
"""*****CLIENT CLASS*****
Wraps all the code that interacts with the Darktrace API."""


class Client(BaseClient):
    """Client class to interact with the Darktrace API
    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def get(self, query_uri: str, params: Dict[str, str] = None):
        """Handles Darktrace GET API calls"""
        return self._darktrace_api_call(query_uri, method='GET', params=params)

    def post(self, query_uri: str, data: Dict = None, json: Dict = None):
        """Handles Darktrace POST API calls"""
        return self._darktrace_api_call(query_uri, method='POST', data=data, json=json)

    def _darktrace_api_call(
        self,
        query_uri: str,
        method: str,
        params: Dict = None,
        data: Dict = None,
        json: Dict = None,
        headers: Dict[str, str] = None,
    ):
        """Handles Darktrace API calls"""
        headers = {
            **self._create_headers(query_uri, params or data or json or None, is_json=bool(json)),
            **(headers or {}),
        }

        res = self._http_request(
            method,
            url_suffix=query_uri,
            params=params,
            data=data,
            json_data=json,
            resp_type='response',
            headers=headers,
            error_handler=self.error_handler,
        )
        return self.parse_respone(res)

    def parse_respone(self, res: requests.Response):
        if res.status_code not in [200, 204]:
            raise Exception('Your request failed with the following error: ' + str(res.content)
                            + '. Response Status code: ' + str(res.status_code))
        try:
            return res.json()
        except Exception as e:
            raise ValueError(
                f'Failed to process the API response - {str(e)}'
            )

    def error_handler(self, res: requests.Response):
        """Handles authentication errors"""
        if res.status_code == 400:
            values = res.json().values()
            if 'API SIGNATURE ERROR' in values:
                raise Exception(DARKTRACE_API_ERRORS['SIGNATURE_ERROR'])
            elif 'API DATE ERROR' in values:
                raise Exception(DARKTRACE_API_ERRORS['DATE_ERROR'])
        elif res.status_code == 302:
            # Valid hmac but invalid endpoint (should not happen)
            if res.text == 'Found. Redirecting to /login':
                raise Exception(DARKTRACE_API_ERRORS['ENDPOINT_ERROR'])
            # Insufficient permissions but valid hmac
            elif res.text == 'Found. Redirecting to /403':
                raise Exception(DARKTRACE_API_ERRORS['PRIVILEGE_ERROR'])
        elif res.status_code >= 300:
            raise Exception(DARKTRACE_API_ERRORS['UNDETERMINED_ERROR'])

    def _create_headers(self, query_uri: str, query_data: Dict = None, is_json: bool = False) -> Dict[str, str]:
        """Create headers required for successful authentication"""
        public_token, _ = self._auth
        date = (datetime.now(UTC)).isoformat(timespec="auto")
        signature = _create_signature(self._auth, query_uri, date, query_data, is_json=is_json)
        return {'DTAPI-Token': public_token, 'DTAPI-Date': date, 'DTAPI-Signature': signature}

    def get_events(self, start_time, end_time) -> List[Dict[str, Any]]:
        """
        Get events from Darktrace API using the modelbreaches endpoint and the start and end time.
        """
        query_uri = MODEL_BREACH_ENDPOINT
        params = {'starttime': start_time, 'endtime': end_time, 'expandenums': "true", 'includeacknowledged': "true",
                  'minimal': "false", 'includebreachurl': "true"}
        return self.get(query_uri, params)


"""*****HELPER FUNCTIONS****"""


def stringify_data(data: Mapping) -> str:
    """Stringify a params or data Dict without encoding"""
    return "&".join([f"{k}={v}" for k, v in data.items()])


def _create_signature(tokens: tuple, query_uri: str, date: str, query_data: Dict = None, is_json: bool = False) -> str:
    """Create signature from Darktrace private token"""
    public_token, private_token = tokens
    query_string = f'?{json.dumps(query_data)}' if is_json else f'?{stringify_data(query_data)}' if query_data else ''

    return hmac.new(
        private_token.encode('ASCII'),
        f'{query_uri}{query_string}\n{public_token}\n{date}'.encode('ASCII'),
        hashlib.sha1,
    ).hexdigest()


def filter_events(events: List[Dict[str, Any]], last_fetched_pid: int, max_fetch: int) -> List[Dict[str, Any]]:
    """Filters events by ascending pbid and max_fetch"""
    for index, event in enumerate(events):
        if event.get('pbid', 0) > last_fetched_pid:
            return events[index:index + max_fetch]
    return []


def add_time_field(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Adds time field to the events"""
    for event in events:
        event['_time'] = timestamp_to_datestring(event['creationTime'])
    return events


def convert_to_timestamp(date: datetime | None) -> int:
    """Converts datetime to timestamp"""
    if date:
        if isinstance(date, datetime):
            return int(date.timestamp())
        elif isinstance(date, int):
            return int(date)
    return 0


"""*****COMMAND FUNCTIONS****"""


def test_module(client: Client, first_fetch_time: int, last_run: Dict[str, Any]) -> str:
    """
     Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    """
    try:
        fetch_events(client, max_fetch=1, last_run=last_run, start_time=first_fetch_time,
                     end_time=convert_to_timestamp(datetime.now()))
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def fetch_events(client: Client, max_fetch: int, last_run: Dict[str, Any],
                 start_time: int, end_time: int) -> \
        tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
       Fetches events from Darktrace API.
    """
    start_time = last_run.get('last_fetch_time', start_time)
    demisto.debug(f'Getting events from: {timestamp_to_datestring(start_time)}, till: {timestamp_to_datestring(end_time)}')
    retrieve_events = client.get_events(start_time, end_time)
    demisto.debug(f'Fetched {len(retrieve_events)} events.')

    # filtering events
    retrieve_events = filter_events(retrieve_events, int(last_run.get('last_fetch_pid', 0)), max_fetch)
    demisto.debug(f'Limiting to {len(retrieve_events)} events.')

    # setting last run object
    if retrieve_events:
        # extracting last fetch time and last fetched events.
        last_fetch_time = retrieve_events[-1].get('time')
        last_fetched_pbid = retrieve_events[-1].get('pbid')
        demisto.debug(f'Setting last run to pbid: {last_fetched_pbid} time:{timestamp_to_datestring(last_fetch_time)}')
        last_run = {'last_fetch_time': retrieve_events[-1].get('creationTime'),
                    'last_fetch_pid': last_fetched_pbid}
    return retrieve_events, last_run


def get_events_command(client: Client, args: Dict[str, Any], first_fetch_time_timestamp: int) -> \
        tuple[List[Dict[str, Any]], CommandResults]:
    """
        Gets events from Darktrace API.
    """
    limit = arg_to_number(args.get('limit')) or DEFAULT_LIMIT
    start_time = convert_to_timestamp(
        arg_to_datetime(arg=args.get('start_time'), arg_name='start_time')) or first_fetch_time_timestamp
    end_time = convert_to_timestamp(arg_to_datetime(arg=args.get('end_time'), arg_name='end_time')) or convert_to_timestamp(
        datetime.now())

    events, _ = fetch_events(client=client, max_fetch=limit, last_run={}, start_time=start_time, end_time=end_time)
    if events:
        return add_time_field(events), CommandResults(readable_output=tableToMarkdown("Open Incidents", events),
                                                      raw_response=events)
    return [], CommandResults(readable_output='No events found')


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions
    :return:
    :rtype:
    """
    params = demisto.params()
    args = demisto.args()
    try:
        public_api_token = params.get('public_creds', {}).get('password', '')
        private_api_token = params.get('private_creds', {}).get('password', '')
        max_fetch = arg_to_number(params.get('max_fetch')) or DEFAULT_MAX_FETCH
        first_fetch_time_timestamp = convert_to_timestamp(arg_to_datetime(params.get('first_fetch', DEFAULT_FIRST_FETCH)))
        proxy = argToBoolean(params.get('proxy', False))

        demisto.debug(f'Command being called is {demisto.command()}')

        client = Client(
            base_url=params.get('base_url'),
            verify=not params.get('insecure', False),
            proxy=proxy,
            auth=(public_api_token, private_api_token)
        )

        if demisto.command() == 'test-module':
            last_run = demisto.getLastRun()
            return_results(test_module(client, first_fetch_time_timestamp, last_run))
        elif demisto.command() == 'darktrace-get-events':
            events, results = get_events_command(client=client,
                                                 args=args,
                                                 first_fetch_time_timestamp=first_fetch_time_timestamp)
            return_results(results)
            if argToBoolean(args.get("should_push_events")):
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT, add_proxy_to_request=proxy)  # type: ignore
        elif demisto.command() == 'fetch-events':
            last_run = demisto.getLastRun()
            events, new_last_run = fetch_events(client=client,
                                                max_fetch=max_fetch,
                                                start_time=first_fetch_time_timestamp,
                                                end_time=int(datetime.now().timestamp()),
                                                last_run=last_run)
            if events:
                add_time_field(events)
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT, add_proxy_to_request=proxy)  # type: ignore
                if new_last_run:
                    demisto.setLastRun(new_last_run)

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


"""*****ENTRY POINT****"""
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
