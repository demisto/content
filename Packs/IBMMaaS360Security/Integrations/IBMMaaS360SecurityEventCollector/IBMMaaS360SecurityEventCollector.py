from enum import Enum
from math import ceil
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
DEFAULT_MAX_FETCH = 1250


class AuditEventType(Enum):
    ChangesAudit = ('adminChanges', 'adminChange', 'updateDate', 'admin_changes_audit',
                    '/account-provisioning/administrator/1.0/getAdminChangesAudit/customer/{billingId}')
    LoginReports = ('loginEvents', 'loginEvent', 'loginAttemptTime', 'admin_login_report',
                    '/account-provisioning/administrator/1.0/getAdminLoginReports/customer/{billingId}')

    def __init__(self, resp_dict_key: str, events_key: str, ts_field: str, source_log_type: str, url_suffix: str):
        self.resp_dict_key = resp_dict_key  # API responds with a dict containing a single key
        self.events_key = events_key  # key to events list in API response
        self.ts_field = ts_field
        self.source_log_type = source_log_type
        self.url_suffix = url_suffix


''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client class to interact with the IBM MaaS360 Security API
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

        Args:
            use_cached_token (bool): Whether to use the cached access token if it exists and is not expired.
                                     If set to false, the token will either be refreshed or a new one will be created.

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
        Authenticates with the IBM MaaS360 Security API and returns the auth and refresh tokens.

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
        ).get('authResponse')

        # Manually check for errors since for some reason the API returns status code 200 on errors too
        if errCode := res.get('errorCode', ''):
            err = res.get('errorDesc', 'Unknown error')
            raise DemistoException('Failed to authenticate with IBM MaaS360 Security. Ensure the credentials are valid. '
                                   f'Got error code {errCode}: {err}')

        add_sensitive_log_strs(res.get('authToken'))  # Ensure the token gets redacted from any logs

        return res.get('authToken'), res.get('refreshToken')

    def refresh_auth_token(self, refresh_token: str) -> tuple[str, str]:
        """
        Refreshes the authentication token using the provided refresh token.

        Args:
            refresh_token (str): The current refresh token.

        Returns:
            auth_token (str): New auth token.
            refresh_token (str): New refresh token.
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
        ).get('authResponse')

        # Manually check for errors since for some reason the API returns status code 200 on errors too
        if errCode := res.get('errorCode', ''):
            err = res.get('errorDesc', 'Unknown error')
            raise DemistoException('Failed to authenticate with IBM MaaS360 Security. Ensure the credentials are valid. '
                                   f'Got error code {errCode}: {err}')

        add_sensitive_log_strs(res.get('authToken'))  # Ensure the token gets redacted from any logs

        return res.get('authToken'), res.get('refreshToken')

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
            if 'Token invalid' in str(e) or 'Token expired.' in str(e):
                demisto.debug('Access token is invalid, re-authenticating and retrying the request')
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

    def fetch_admin_audit_events(self, event_type: AuditEventType, from_date: str,
                                 to_date: str, page_offset: int, max_fetch_amount: int) -> tuple[list, int, bool]:
        """
        Fetches the admin audit events of the requested type for the specified time range.

        Args:
            event_type (EventType): The type of events to fetch.
            from_date (str): The start time to fetch from in epoch milliseconds.
            to_date (str): The end time to fetch to in epoch milliseconds.
            page_offset (int): Number of pages already fetched from the given timeframe.

        Returns:
            events (list): List of admin audit events.
            page_offset (int): New total number of pages already fetched from the given timeframe.
            pages_remaining (bool): Whether there might be more pages to fetch from the given timeframe.
        """
        url_suffix = event_type.url_suffix.format(billingId=self.billing_id)
        events = []
        pages_remaining = True
        fetches_left = ceil(max_fetch_amount / PAGE_SIZE)

        while pages_remaining and fetches_left:
            page_number = 1 + page_offset
            params = {
                'fromDate': from_date,
                'toDate': to_date,
                'pageSize': PAGE_SIZE,
                'pageNumber': page_number,
            }

            demisto.debug(f'Fetching events of type {event_type.name} from {from_date} to {to_date} (page {page_number})')
            response = self.http_request('GET', url_suffix, params).get(event_type.resp_dict_key, {})
            response_events = response.get(event_type.events_key, [])
            if not isinstance(response_events, list):  # Single event is returned as a dict instead of a list
                response_events = [response_events]

            for event in response_events:
                ts = arg_to_datetime(event.get(event_type.ts_field))
                event['_time'] = ts.strftime(DATE_FORMAT) if ts else None
                event['source_log_type'] = event_type.source_log_type
                events.append(event)

            fetches_left -= 1
            page_offset += 1
            if len(response_events) < PAGE_SIZE:
                pages_remaining = False

        return events, page_offset, pages_remaining


def test_module(client: Client, params: dict[str, Any], first_fetch_time: int) -> str:
    """
    Tests API connectivity and authentication
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): client to use.
        params (dict): Integration parameters.
        first_fetch_time(str): The first fetch time as configured in the integration params.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """

    try:
        fetch_events(
            client=client,
            last_run={},
            first_fetch_time=first_fetch_time,
            max_events_per_fetch={
                AuditEventType.ChangesAudit: 1,
                AuditEventType.LoginReports: 1,
            },
        )

    except Exception as e:
        if 'Failed to authenticate' in str(e):
            return 'Authorization Error: Ensure credentials are set correctly'
        else:
            raise e

    return 'ok'


def get_events(client: Client, args: dict) -> tuple[list[dict], CommandResults]:
    """
    Get events from the IBM MaaS360 Security API.

    Args:
        client (Client): Client to use.
        args (dict): Command arguments.

    Returns:
        events (list): List of fetched events.
        results (CommandResults): CommandResults object to be returned to the war-room.
    """
    limit = arg_to_number(args.get('limit'), required=True) or 0
    if 'from_date' in args:
        first_fetch_time = int(date_to_timestamp(arg_to_datetime(args.get('from_date'))))
    else:
        first_fetch_time = int(time.time()) - timedelta(hours=3).seconds

    events: list[dict] = []
    # Fetch one event type at a time until we reach the limit or get them all
    for event_type in AuditEventType:
        if (limit_left := limit - len(events)) <= 0:
            break
        max_events_per_fetch = {
            event_type: limit_left,
        }

        _next_run, fetched_events = fetch_events(
            client=client,
            last_run={},
            first_fetch_time=first_fetch_time,
            max_events_per_fetch=max_events_per_fetch,
        )
        events.extend(fetched_events)

    # Trim any excess events
    events = events[:limit]

    # Create a table with time and log type as the first headers, followed by the rest
    headers = ['_time', 'source_log_type']
    headers.extend([header for event in events for header in event])
    events_hr = tableToMarkdown(name='Admin audits', t=events,
                                headers=list(dict.fromkeys(headers)))  # dict.fromkeys instead of set to maintain order

    return events, CommandResults(readable_output=events_hr)


def fetch_events(client: Client, last_run: dict[str, str], first_fetch_time: int, max_events_per_fetch: dict = {}
                 ) -> tuple[dict, list[dict]]:
    """
    Fetches events from the IBM MaaS360 Security API.

    Args:
        client (Client): Client to use.
        last_run (dict): A dict containing the next fetch time window and page offset for every event type.
        first_fetch_time: If last_run is None (first time we are fetching), it contains the timestamp in
            milliseconds of when to start fetching events.
        max_events_per_fetch (dict): Dict containing the maximum number of events per fetch for each event type.

    Returns:
        next_run (dict): Next run dictionary containing the next fetch time window and page offset for every event type.
        events (list): List of events to be pushed to XSIAM.
    """
    events = []
    next_run = {}

    for event_type in AuditEventType:
        last_run_params = json.loads(last_run.get(event_type.name, '{}')) or {}
        max_fetch_amount = max_events_per_fetch.get(event_type, 0)
        from_date = last_run_params.get('from_date', first_fetch_time)
        to_date = last_run_params.get('to_date', int(time.time() * 1000))
        page_offset = last_run_params.get('page_offset', 0)

        audit_events, next_page_offset, pages_remaining = client.fetch_admin_audit_events(event_type=event_type,
                                                                                          from_date=str(from_date),
                                                                                          to_date=str(to_date),
                                                                                          page_offset=page_offset,
                                                                                          max_fetch_amount=max_fetch_amount)

        demisto.debug(f'Fetched {len(audit_events)} {event_type.name} events.')
        events.extend(audit_events)

        # Update next run
        if pages_remaining:
            # Ensure we continue fetching from the same spot next time.
            next_run_params = {
                'from_date': from_date,
                'to_date': to_date,
                'page_offset': next_page_offset,
            }
        else:
            # Got all the events in the current timeframe, move starting point to the end of the current window.
            next_run_params = {
                'from_date': to_date + 1,
                'page_offset': 0,
            }

        next_run[event_type.name] = json.dumps(next_run_params)  # Next run only accepts strings

    demisto.debug(f'Returning {next_run=}.')
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

    first_fetch_time = int(time.time() * 1000)
    proxy = params.get('proxy', False)
    max_login_reports_per_fetch = arg_to_number(params.get('max_login_reports_per_fetch', DEFAULT_MAX_FETCH))
    max_admin_change_audits_per_fetch = arg_to_number(params.get('max_admin_change_audits_per_fetch', DEFAULT_MAX_FETCH))

    max_events_per_fetch = {
        AuditEventType.ChangesAudit: max_admin_change_audits_per_fetch,
        AuditEventType.LoginReports: max_login_reports_per_fetch,
    }

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
