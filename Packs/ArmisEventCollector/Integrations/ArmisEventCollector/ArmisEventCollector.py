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

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API - this Client implements API calls"""

    def __init__(self, base_url, api_key, access_token, verify=False, proxy=False):
        self._api_key = api_key
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        if not access_token:  # TODO: add current access token verification function
            access_token = self.get_access_token()
        headers = {
            'Authorization': f'{access_token}',
            "Accept": "application/json"
        }
        self._headers = headers
        self._access_token = access_token

    def fetch_alerts(self, max_fetch, time_frame):
        params = {'aql': f'in:alerts timeFrame:"{time_frame} seconds"',
                  'includeTotal': 'true', 'length': max_fetch, 'orderBy': 'time'}
        return self._http_request(url_suffix='/search/', method='GET', params=params, headers=self._headers)

    def fetch_threats(self, max_fetch, time_frame):
        params = {'aql': f'in:activity type:"Threat Detected" timeFrame:"{time_frame} seconds"',
                  'includeTotal': 'true', 'length': max_fetch, 'orderBy': 'time'}
        return self._http_request(url_suffix='/search/', method='GET', params=params, headers=self._headers)

    def get_access_token(self):
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json"
        }
        params = {"secret_key": self._api_key}
        # response = requests.request(
        #     url=urljoin(base_url, 'access_token'),
        #     headers=headers, params=params, method='POST').json()
        response = self._http_request(url_suffix='/access_token/', method='POST', params=params, headers=headers)
        if access_token := response.get('data', {}).get('access_token'):
            return access_token
        else:
            raise DemistoException('Could not get access token form get_access_token().')


def test_module(client: Client, params: Dict[str, Any], fetch_start_time: int) -> str:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.
    Args:
        client (Client): HelloWorld client to use.
        params (Dict): Integration parameters.
        fetch_start_time (int): The first fetch time as configured in the integration params.
    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """

    try:
        alert_status = params.get('alert_status', None)

        # fetch_events(
        #     client=client,
        #     last_run={},
        #     fetch_start_time=fetch_start_time,
        #     alert_status=alert_status,
        # )

    except Exception as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    return 'ok'


def get_events(client, alert_status):
    events = client.search_events(
        prev_id=0,
        alert_status=alert_status
    )
    hr = tableToMarkdown(name='Test Event', t=events)
    return events, CommandResults(readable_output=hr)


def calculate_fetch_start_time(last_fetch_time, fetch_start_time_param):
    if last_fetch_time and fetch_start_time_param:
        last_fetch_time = arg_to_datetime(last_fetch_time)
        if not isinstance(last_fetch_time, datetime):
            raise DemistoException(f'last_fetch_time is not a valid date: {last_fetch_time}')
        return min(last_fetch_time, fetch_start_time_param)
    else:
        return fetch_start_time_param


def dedup_alerts(alerts, alerts_last_fetch_ids):
    return [alert for alert in alerts if alert.get('alertId') not in alerts_last_fetch_ids]


def dedup_threats(threats, threats_last_fetch_ids):
    return [threat for threat in threats if threat.get('activityUUID') not in threats_last_fetch_ids]


def fetch_events(client: Client, max_fetch, last_run, fetch_start_time_param):
    events = []

    # calculate fetch start time for each event type
    alerts_first_fetch_time = calculate_fetch_start_time(last_run.get('alerts_last_fetch_time'), fetch_start_time_param)
    threats_first_fetch_time = calculate_fetch_start_time(last_run.get('threats_last_fetch_time'), fetch_start_time_param)

    # calculate time_frame query parameter in seconds for each event type
    now = datetime.now()
    alerts_fetch_start_time_in_seconds = int((now - alerts_first_fetch_time).total_seconds() + 1)
    threats_fetch_start_time_in_seconds = int((now - threats_first_fetch_time).total_seconds() + 1)

    alerts_response = client.fetch_alerts(max_fetch=max_fetch, time_frame=alerts_fetch_start_time_in_seconds)
    threats_response = client.fetch_threats(
        max_fetch=max_fetch - int(alerts_response.get('data', {}).get('count', 0)),
        time_frame=threats_fetch_start_time_in_seconds)

    # dedup events from last fetch
    alerts = dedup_alerts(alerts_response.get('data', {}).get('results', []), last_run.get('alerts_last_fetch_ids', []))
    threats = dedup_threats(threats_response.get('data', {}).get('results', []), last_run.get('threats_last_fetch_ids', []))

    events.extend(alerts)
    events.extend(threats)

    # determine last fetch time of each event type
    alerts_last_fetch_time = alerts[-1].get('time') if alerts[-1].get('time') else last_run.get('alerts_last_fetch_time')
    threats_last_fetch_time = threats[-1].get('time') if threats[-1].get('time') else last_run.get('threats_last_fetch_time')

    alerts_last_fetch_ids = [alert.get('alertId') for alert in alerts]
    threats_last_fetch_ids = [threat.get('activityUUID') for threat in threats]

    # set values for next fetch events
    next_run = {
        'alerts_last_fetch_ids': alerts_last_fetch_ids,
        'threats_last_fetch_ids': threats_last_fetch_ids,
        'alerts_last_fetch_time': alerts_last_fetch_time,
        'threats_last_fetch_time': threats_last_fetch_time,
        'access_token': client._access_token
    }

    return events, next_run


''' MAIN FUNCTION '''


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


def main() -> None:
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    last_run = demisto.getLastRun()
    access_token = last_run.get('access_token')
    api_key = params.get('credentials', {}).get('password')
    base_url = urljoin(params.get('server_url'), '/api/v1')
    verify_certificate = not params.get('insecure', True)
    max_fetch = params.get('max_fetch', 1000)
    first_fetch = params.get('first_fetch', '3 days')
    fetch_start_time_param = arg_to_datetime(first_fetch)
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            api_key=api_key,
            access_token=access_token)

        if command == 'test-module':
            try:
                client.fetch_alerts(1, 1)

            except Exception as e:
                raise DemistoException(f'Error while testing: {e}') from e

            return_results('ok')

        elif command in 'armis-get-events':
            ...
            # should_push_events = argToBoolean(args.pop('should_push_events'))
            # events, results = get_events(client)
            # return_results(results)
            # if should_push_events:
            #     add_time_to_events(events)
            #     send_events_to_xsiam(
            #         events,
            #         vendor=VENDOR,
            #         product=PRODUCT
            # )

        elif command in ('fetch-events', 'armis-get-events'):
            events, next_run = fetch_events(
                client=client,
                max_fetch=max_fetch,
                last_run=last_run,
                fetch_start_time_param=fetch_start_time_param
            )

            add_time_to_events(events)
            send_events_to_xsiam(
                events,
                vendor=VENDOR,
                product=PRODUCT
            )

            demisto.setLastRun(next_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
