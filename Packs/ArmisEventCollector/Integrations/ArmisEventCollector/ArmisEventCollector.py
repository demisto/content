import uuid
import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any, Dict, Optional

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = 'armis'
PRODUCT = 'armis'
API_V1_ENDPOINT = '/api/v1'
DEFAULT_MAX_FETCH = 1000

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with Armis API - this Client implements API calls"""

    def __init__(self, base_url, api_key, access_token, verify=False, proxy=False):
        self._api_key = api_key
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        if not access_token or not self.is_valid_access_token(access_token):
            access_token = self.get_access_token()
        headers = {
            'Authorization': f'{access_token}',
            "Accept": "application/json"
        }
        self._headers = headers
        self._access_token = access_token

    def fetch_by_aql_query(self, aql_query: str, max_fetch: int, time_frame: None | int = None):
        params: dict[str, Any] = {'aql': aql_query, 'includeTotal': 'true', 'length': max_fetch, 'orderBy': 'time'}
        if time_frame:  # if there is a time frame thats relative to last run
            params['aql'] += f' timeFrame:"{time_frame} seconds"'

        # make first request to get first page of threat activity
        raw_response = self._http_request(url_suffix='/search/', method='GET', params=params, headers=self._headers)
        results = raw_response.get('data', {}).get('results', [])

        # perform pagination if needed, will cycle through all pages and add results to results list
        while (next := raw_response.get('data', '').get('next')):
            params['from'] = next
            raw_response = self._http_request(url_suffix='/search/', method='GET', params=params, headers=self._headers)
            results.extend(raw_response.get('data', {}).get('results', []))

        return results

    def is_valid_access_token(self, access_token):
        try:
            headers = {
                'Authorization': f'{access_token}',
                "Accept": "application/json"
            }
            params = {'aql': 'in:alerts timeFrame:"1 seconds"',
                      'includeTotal': 'true', 'length': 1, 'orderBy': 'time'}
            self._http_request(url_suffix='/search/', method='GET', params=params, headers=headers)
        except Exception:
            return False
        return True

    def get_access_token(self):
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json"
        }
        params = {"secret_key": self._api_key}
        response = self._http_request(url_suffix='/access_token/', method='POST', params=params, headers=headers)
        if access_token := response.get('data', {}).get('access_token'):
            return access_token
        else:
            raise DemistoException('Could not generate access token.')


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication.
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.
    Args:
        client (Client): HelloWorld client to use.
    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    try:
        client.fetch_alerts(1, 1)

    except Exception as e:
        raise DemistoException(f'Error while testing: {e}') from e

    return 'ok'


def get_events(client, alert_status):
    events = client.search_events(
        prev_id=0,
        alert_status=alert_status
    )
    hr = tableToMarkdown(name='Test Event', t=events)
    return events, CommandResults(readable_output=hr)


''' HELPER FUNCTIONS '''


def min_datetime(last_fetch_time, fetch_start_time_param):
    # TODO: remove if not used
    if not isinstance(last_fetch_time, datetime) or not isinstance(fetch_start_time_param, datetime):
        raise DemistoException(f'last_fetch_time or fetch_start_time_param is not a valid date: {last_fetch_time}')
    comparable_datetime = datetime(year=last_fetch_time.year, month=last_fetch_time.month,
                                   day=last_fetch_time.day,
                                   hour=last_fetch_time.hour,
                                   minute=last_fetch_time.minute,
                                   second=last_fetch_time.second,
                                   microsecond=last_fetch_time.microsecond)
    return min(comparable_datetime, fetch_start_time_param)


def calculate_fetch_start_time(last_fetch_time, fetch_start_time_param):
    if last_fetch_time:
        last_fetch_time = arg_to_datetime(last_fetch_time)
        if not isinstance(last_fetch_time, datetime):
            raise DemistoException(f'last_fetch_time is not a valid date: {last_fetch_time}')
        return last_fetch_time.replace(tzinfo=None)
    else:
        return fetch_start_time_param


def dedup_alerts(alerts, alerts_last_fetch_ids):
    return [alert for alert in alerts if alert.get('alertId') not in alerts_last_fetch_ids]


def dedup_threats(threats, threats_last_fetch_ids):
    return [threat for threat in threats if threat.get('activityUUID') not in threats_last_fetch_ids]


def fetch_events(client: Client, max_fetch, last_run, fetch_start_time_param, log_types_to_fetch):
    events = []
    now = datetime.now()
    next_run = {}

    if 'Alerts' in log_types_to_fetch:
        if last_run:
            alerts_first_fetch_time = calculate_fetch_start_time(last_run.get('alerts_last_fetch_time'), fetch_start_time_param)
            alerts_fetch_start_time_in_seconds = int((now - alerts_first_fetch_time).total_seconds() + 1)
        else:
            alerts_fetch_start_time_in_seconds = None

        alerts_response = client.fetch_by_aql_query(
            aql_query='in:alerts',
            max_fetch=max_fetch,
            time_frame=alerts_fetch_start_time_in_seconds
        )

        if alerts_response:
            alerts = dedup_alerts(alerts_response, last_run.get('alerts_last_fetch_ids', []))
            next_run['alerts_last_fetch_ids'] = [alert.get('alertId') for alert in alerts]
            next_run['alerts_last_fetch_time'] = alerts[-1].get('time') if alerts else last_run.get('alerts_last_fetch_time')
            events.extend(alerts)

    if 'Threats' in log_types_to_fetch:
        if last_run:
            threats_first_fetch_time = calculate_fetch_start_time(last_run.get('threats_last_fetch_time'), fetch_start_time_param)
            threats_fetch_start_time_in_seconds = int((now - threats_first_fetch_time).total_seconds() + 1)
        else:
            threats_fetch_start_time_in_seconds = None

        threats_response = client.fetch_by_aql_query(
            aql_query='in:activity type:"Threat Detected"',
            max_fetch=max_fetch,
            time_frame=threats_fetch_start_time_in_seconds
        )

        if threats_response:
            threats = dedup_threats(threats_response, last_run.get('threats_last_fetch_ids', []))
            next_run['threats_last_fetch_ids'] = [threat.get('activityUUID') for threat in threats]
            next_run['threats_last_fetch_time'] = threats[-1].get('time') if threats else last_run.get('threats_last_fetch_time')
            events.extend(threats)

    next_run['access_token'] = client._access_token

    demisto.debug(f'debug-log: next_run: {next_run}')
    demisto.debug(f'debug-log: events: {events}')
    return events, next_run


def add_time_to_events(events):
    """
    Adds the _time key to the events.
    Args:
        events: List[Dict] - list of events to add the _time key to.
    Returns:
        list: The events with the _time key.
    """
    if events:
        for event in events:
            create_time = arg_to_datetime(arg=event.get('time'))
            event['_time'] = create_time.strftime(DATE_FORMAT) if create_time else None


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    last_run = demisto.getLastRun()
    access_token = last_run.get('access_token')
    api_key = params.get('credentials', {}).get('password')
    base_url = urljoin(params.get('server_url'), API_V1_ENDPOINT)
    verify_certificate = not params.get('insecure', True)
    max_fetch = arg_to_number(params.get('max_fetch', DEFAULT_MAX_FETCH))
    proxy = params.get('proxy', False)
    log_types_to_fetch = argToList(params.get('log_types_to_fetch', []))

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            api_key=api_key,
            access_token=access_token)

        if command == 'test-module':
            return_results(test_module(client))

        elif command in ('fetch-events', 'armis-get-events'):
            events, next_run = fetch_events(
                client=client,
                max_fetch=max_fetch,
                last_run=last_run,
                fetch_start_time_param=datetime.now(),
                log_types_to_fetch=log_types_to_fetch,
            )

            if command in ('fetch-events'):
                add_time_to_events(events)
                send_events_to_xsiam(
                    events,
                    vendor=VENDOR,
                    product=PRODUCT
                )

            demisto.setLastRun(next_run)
        else:
            return_error(f'Command {command} does not exist for this integration.')
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
