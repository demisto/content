import hashlib
import hmac
import json
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Tuple

import demistomock as demisto
import urllib3
from CommonServerPython import *

"""Darktrace Integration for Cortex XSOAR (aka Demisto)"""

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

    def post(self, query_uri: str, data: dict = None, json: dict = None):
        """Handles Darktrace POST API calls"""
        return self._darktrace_api_call(query_uri, method='POST', data=data, json=json)

    def _darktrace_api_call(
        self,
        query_uri: str,
        method: str,
        params: dict = None,
        data: dict = None,
        json: dict = None,
        headers: Dict[str, str] = None,
    ):
        """Handles Darktrace API calls"""
        headers = {
            **self._create_headers(query_uri, params or data or json or None, is_json=bool(json)),
            **(headers or {}),
        }

        try:
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
            if res.status_code not in [200, 204]:
                raise Exception('Your request failed with the following error: ' + str(res.content)
                                + '. Response Status code: ' + str(res.status_code))
        except Exception as e:
            raise Exception(e)
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

    def _create_headers(self, query_uri: str, query_data: dict = None, is_json: bool = False) -> Dict[str, str]:
        """Create headers required for successful authentication"""
        public_token, _ = self._auth
        date = (datetime.now(timezone.utc)).isoformat(timespec="auto")
        signature = _create_signature(self._auth, query_uri, date, query_data, is_json=is_json)
        return {'DTAPI-Token': public_token, 'DTAPI-Date': date, 'DTAPI-Signature': signature}

    def get_events(self, start_time, end_time) -> List[Dict[str, Any]]:
        """
        Get events from Darktrace API using the modelbreaches endpoint and the start and end time.
        """
        query_uri = MODEL_BREACH_ENDPOINT
        params = {'starttime': start_time, 'endtime': end_time, 'expandenums': True, 'includeacknowledged': True}
        return self.get(query_uri, params)


"""*****HELPER FUNCTIONS****"""


def stringify_data(data: Mapping) -> str:
    """Stringify a params or data dict without encoding"""
    return "&".join([f"{k}={v}" for k, v in data.items()])


def _create_signature(tokens: tuple, query_uri: str, date: str, query_data: dict = None, is_json: bool = False) -> str:
    """Create signature from Darktrace private token"""
    public_token, private_token = tokens
    if is_json:
        query_string = f'?{json.dumps(query_data)}'
    else:
        query_string = f'?{stringify_data(query_data)}' if query_data else ''

    return hmac.new(
        private_token.encode('ASCII'),
        f'{query_uri}{query_string}\n{public_token}\n{date}'.encode('ASCII'),
        hashlib.sha1,
    ).hexdigest()


def filter_events(events: List[Dict[str, Any]], last_fetched_pid: int, max_fetch: int) -> List[Dict[str, Any]]:
    """Filters events by pbid and max_fetch"""
    for index, event in enumerate(events):
        if event.get('pbid') > last_fetched_pid:
            return events[index:index + max_fetch]
    return []


def add_time_field(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Adds time field to the events"""
    for event in events:
        event['_time'] = timestamp_to_datestring(event['creationTime'])
    return events


"""*****COMMAND FUNCTIONS****"""


def test_module(client: Client, first_fetch_time: Optional[float]) -> str:
    """
     Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    """
    try:
        client.get_events(start_time=first_fetch_time, end_time=datetime.now().timestamp())
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def fetch_events(client: Client, max_fetch: int, first_fetch_time: float, last_run: Dict[str, Any]) -> Tuple[
    List[Dict[str, Any]], Dict[str, Any]]:
    """
       Fetches events from Darktrace API.
    """
    start_time = last_run.get('last_fetch_time', first_fetch_time)
    end_time = datetime.now()
    demisto.debug(f'Getting events from: {timestamp_to_datestring(start_time)}, till: {end_time}')
    retrieve_events = client.get_events(start_time, end_time.timestamp())
    demisto.debug(f'Fetched {len(retrieve_events)} events.')
    # filtering events
    retrieve_events = filter_events(retrieve_events, last_run.get('last_fetch_pid', 0), max_fetch)
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


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions
    :return:
    :rtype:
    """
    params = demisto.params()
    base_url = params.get('base_url')
    public_api_token = params.get('public_creds', {}).get('password', '')
    private_api_token = params.get('private_creds', {}).get('password', '')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    max_fetch = arg_to_number(params.get('max_fetch')) or 1000
    first_fetch_time = arg_to_datetime(arg=params.get('first_fetch', '3 days'),
                                       arg_name='First fetch time',
                                       required=True).timestamp()
    tokens = (public_api_token, private_api_token)

    demisto.debug(f'Command being called is {demisto.command()}')

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            auth=tokens
        )

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client, first_fetch_time))

        elif demisto.command() == 'fetch-events':
            last_run = demisto.getLastRun()
            events, new_last_run = fetch_events(client=client,
                                                max_fetch=max_fetch,
                                                first_fetch_time=first_fetch_time,  # type: ignore
                                                last_run=last_run)
            if events:
                add_time_field(events)
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)  # type: ignore
                if new_last_run:
                    demisto.setLastRun(new_last_run)

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


"""*****ENTRY POINT****"""
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
