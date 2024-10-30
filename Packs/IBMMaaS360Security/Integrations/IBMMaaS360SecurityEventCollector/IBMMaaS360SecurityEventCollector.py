from enum import Enum
import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = 'ibm'
PRODUCT = 'maas360 security'
TOKEN_VALIDITY_DURATION = 3600
PAGE_SIZE = 250
MAX_FETCHES = 5  # Maximum number of pages to fetch


class AuditEventType(Enum):
    ChangesAudit = ('adminChanges', 'adminChange', 'updateDate', 'admin_changes_audit',
                    '/account-provisioning/administrator/1.0/getAdminChangesAudit/customer/{billingId}')
    LoginReports = ('loginEvents', 'loginEvent', 'loginAttemptTime', 'admin_login_report',
                    '/account-provisioning/administrator/1.0/getAdminLoginReports/customer/{billingId}')

    def __init__(self, resp_dict_key: str, events_key: str, ts_field: str, source_log_type: str, url_suffix: str):
        self.resp_dict_key = resp_dict_key  # API response main key
        self.events_key = events_key  # key to events list in API response
        self.ts_field = ts_field
        self.source_log_type = source_log_type
        self.url_suffix = url_suffix


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def __init__(self, base_url, username, password, app_id, app_version,
                 platform_id, access_key, billing_id, verify=True, proxy=False):
        super().__init__(base_url, verify=verify, proxy=proxy)
        self.username = username
        self.password = password
        self.app_id = app_id
        self.app_version = app_version
        self.platform_id = platform_id
        self.access_key = access_key
        self.billing_id = billing_id

    def get_auth_token(self, use_cached_token=True) -> str:
        """
         Get an auth token for the IBM MaaS360 Security API.
         If one exists in the integration context and is not expired, returns it.
         Otherwise, refreshes the token (if possible) or generates a new one.

        Returns:
            auth_token (str): A valid auth token for the IBM MaaS360 Security API.
        """

        integration_context = get_integration_context()
        request_time = int(time.time())
        auth_token = integration_context.get('auth_token')
        expiry_time = integration_context.get('expiry_time', 0)
        refresh_token = integration_context.get('refresh_token')

        if use_cached_token and auth_token and expiry_time > request_time:
            demisto.debug('Returning cached auth token')
            return auth_token

        if isinstance(refresh_token, str):
            demisto.debug('Refreshing auth token.')
            try:
                auth_token, refresh_token = self.refresh_auth_token(refresh_token)
            except DemistoException as e:
                if 'Invalid credentials' in str(e):  # Refresh token might have expired
                    demisto.debug(f'Failed to refresh auth token, sending auth request. error msg: {e}')
                    auth_token, refresh_token = self.authenticate()
                else:
                    raise e
        else:
            demisto.debug('Sending authentication request.')
            auth_token, refresh_token = self.authenticate()

        integration_context.update({
            'auth_token': auth_token,
            'expiry_time': request_time + TOKEN_VALIDITY_DURATION,
            'refresh_token': refresh_token
        })
        set_integration_context(integration_context)

        return auth_token

    def authenticate(self) -> tuple[str, str]:
        """
        Authenticates with the IBM MaaS360 Security API and returns the auth token and refresh token.

        Returns:
            auth_token (str): The auth token.
            refresh_token (str): The refresh token.
        """

        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }

        json_data = {
            'authRequest': {
                'maaS360AdminAuth': {
                    'billingID': self.billing_id,
                    'platformID': self.platform_id,
                    'appID': self.app_id,
                    'appVersion': self.app_version,
                    'appAccessKey': self.access_key,
                    'userName': self.username,
                    'password': self.password,
                }
            }
        }

        res = self._http_request(
            method='POST',
            url_suffix=f'/auth-apis/auth/2.0/authenticate/customer/{self.billing_id}',
            json_data=json_data,
            headers=headers,
        )
        if res['authResponse']['authToken']:
            demisto.debug('Successfully authenticated with IBM MaaS360 Security API.')

        return res['authResponse']['authToken'], res['authResponse']['refreshToken']

    def refresh_auth_token(self, refresh_token: str) -> tuple[str, str]:
        """
        Refreshes the authentication token using the provided refresh token.

        Returns:
            auth_token (str): New auth token.
            refresh_token (str): New refresh.
        """

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        json_data = {
            'authRequest': {
                'maaS360AdminAuth': {
                    'billingID': self.billing_id,
                    'userName': self.username,
                    'appID': self.app_id,
                    'appVersion': self.app_version,
                    'platformID': self.platform_id,
                    'refreshToken': refresh_token,
                }
            }
        }

        res = self._http_request(
            method='POST',
            url_suffix=f'/auth-apis/auth/2.0/refreshToken/customer/{self.billing_id}',
            json_data=json_data,
            headers=headers,
        )

        return res['authResponse']['authToken'], res['authResponse']['refreshToken']

    def http_request(self, method: str, url_suffix: str = '', params: dict = {}):
        """
        Make an http request to the IBM MaaS360 Security API with the provided parameters.

        Args:
            method (str): HTTP method to use (e.g., 'GET', 'POST')
            url_suffix (str): Suffix to be appended to the base URL
            params (dict): Query parameters to be included in the request

        Returns:
            Response from the IBM MaaS360 Security API
        """
        headers = {
            'Authorization': f'MaaS token="{self.get_auth_token()}"',
            'Accept': 'application/json',
        }

        try:
            response = self._http_request(
                method=method,
                url_suffix=url_suffix,
                params=params,
                headers=headers,
            )
        except DemistoException as e:
            if 'Token invalid' in str(e):
                demisto.debug('Access token is invalid, reauthenticating and retrying the request')
                headers['Authorization'] = f'MaaS token="{self.get_auth_token(use_cached_token=False)}"'
                response = self._http_request(
                    method=method,
                    url_suffix=url_suffix,
                    params=params,
                    headers=headers,
                )
            else:
                raise e

        return response

    def fetch_admin_audit_events(self, event_type: AuditEventType, from_date: str, to_date: str, page_offset: int):
        """
        Fetches the admin audit events of the requested type for the specified time range.

        Args:
            events_type (EventType): The type of events to fetch.
            from_date (str): The start time to fetch from in epoch milliseconds.
            to_date (str): The end time to fetch to in epoch milliseconds.
            page_offset (int): The page number to start fetching from.

        Returns:
            events (list[dict]): List of admin audit events.
            page_offset (int): The next page number to fetch for the given event type. (0 if no more pages to fetch in time range)
        """
        url_suffix = event_type.url_suffix.format(billingId=self.billing_id)
        num_fetches = 0
        events = []
        pages_remaining = True

        while pages_remaining and num_fetches < MAX_FETCHES:
            page_number = 1 + page_offset + num_fetches
            params = {
                'fromDate': from_date,
                'toDate': to_date,
                'pageSize': PAGE_SIZE,
                'pageNumber': page_number,
            }
            demisto.debug(f'Fetching events of type {event_type.name} from {from_date} to {to_date} (page {page_number})')
            response = self.http_request('GET', url_suffix, params).get(event_type.resp_dict_key, {})
            response_events = response.get(event_type.events_key, [])
            if not isinstance(response_events, list):
                response_events = [response_events]

            for event in response_events:
                ts = arg_to_datetime(event[event_type.ts_field])
                event['_time'] = ts.strftime(DATE_FORMAT) if ts else None
                event['source_log_type'] = event_type.source_log_type
                events.append(event)

            num_fetches += 1
            if response['count'] < PAGE_SIZE:
                pages_remaining = False

        next_page = page_offset + num_fetches if pages_remaining else 0
        return events, next_page


def test_module(client: Client, params: dict[str, Any], first_fetch_time: int) -> str:
    """
    Tests API connectivity and authentication
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): HelloWorld client to use.
        params (Dict): Integration parameters.
        first_fetch_time(str): The first fetch time as configured in the integration params.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """

    try:
        fetch_events(
            client=client,
            last_run={},
            first_fetch_time=first_fetch_time,
            max_events_per_fetch=1,
        )

    except Exception as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    return 'ok'


def get_events(client: Client, args: dict) -> tuple[List[Dict], CommandResults]:
    return [], CommandResults()


def fetch_events(client: Client, last_run: dict[str, str],
                 first_fetch_time: int, max_events_per_fetch: int
                 ) -> tuple[Dict, List[Dict]]:
    """
    Args:
        client (Client): HelloWorld client to use.
        last_run (dict): A dict with a key containing the latest event created time we got from last fetch.
        first_fetch_time: If last_run is None (first time we are fetching), it contains the timestamp in
            milliseconds on when to start fetching events.
        alert_status (str): status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'.
        max_events_per_fetch (int): number of events per fetch
    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of events that will be created in XSIAM.
    """
    events = []
    next_run = {}
    if not last_run:  # First fetch
        last_run = {}
        for event_type in AuditEventType:
            last_run[event_type.name] = json.dumps({'from_date': first_fetch_time, 'page_offset': 0})

    for event_type in AuditEventType:
        last_run_params = json.loads(last_run.get(event_type.name, '{}'))
        to_date = last_run_params.pop('to_date', int(time.time() * 1000))

        audit_events, next_page_offset = client.fetch_admin_audit_events(event_type=event_type,
                                                                         from_date=str(last_run_params.get('from_date')),
                                                                         to_date=str(to_date),
                                                                         page_offset=last_run_params.get('page_offset'))
        demisto.debug(f'Fetched {len(audit_events)} {event_type.name} events.')

        if next_page_offset:
            # There are earlier entries left to fetch, keep fetched events for next interval
            demisto.debug('More pages left for timeframe, delaying push until all events are fetched')
            last_run_params['unpushed_events'] = last_run_params.get('unpushed_events', []).extend(audit_events)
            last_run_params['to_date'] = to_date  # ensure we keep fetching the earlier events we missed
        else:
            # Got the earliest events in the timeframe, push events from timeframe
            events.extend(last_run_params.pop('unpushed_events', []))
            events.extend(audit_events)
            last_run_params['from_date'] = to_date + 1

        # Update next run
        last_run_params['page_offset'] = next_page_offset
        next_run[event_type.name] = json.dumps(last_run_params)

    return next_run, events


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    base_url = params.get('url')
    verify_certificate = not params.get('insecure', False)
    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')
    app_id = params.get('app_id', '')
    app_version = params.get('app_version', '')
    platform_id = params.get('platform_id', '')
    access_key = params.get('app_access_key', {}).get('password')
    billing_id = params.get('billing_id', {}).get('password')

    # How much time before the first fetch to retrieve events
    first_fetch_time = int(time.time() * 1000)
    proxy = params.get('proxy', False)
    max_events_per_fetch = params.get('max_events_per_fetch', 1000)

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            username=username,
            password=password,
            app_id=app_id,
            app_version=app_version,
            platform_id=platform_id,
            access_key=access_key,
            billing_id=billing_id,
            verify=verify_certificate,
            proxy=proxy,
        )

        if command == 'test-module':
            result = test_module(client, params, first_fetch_time)
            return_results(result)

        elif command == 'ibm-maas360-security-get-events':
            should_push_events = argToBoolean(args.pop('should_push_events'))
            events, results = get_events(client, demisto.args())
            return_results(results)
            if should_push_events:
                send_events_to_xsiam(
                    events,
                    vendor=VENDOR,
                    product=PRODUCT
                )

        elif command == 'fetch-events':
            last_run = demisto.getLastRun()
            next_run, events = fetch_events(
                client=client,
                last_run=last_run,
                first_fetch_time=first_fetch_time,
                max_events_per_fetch=max_events_per_fetch,
            )

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
