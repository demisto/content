import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

MAX_EVENTS_PER_REQUEST = 100
VENDOR = 'Workday'
PRODUCT = 'Workday'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

        This Client implements API calls to the Saas Security platform, and does not contain any XSOAR logic.
        Handles the token retrieval.

        :param base_url (str): Workday server url.
        :param client_id (str): Workday client id.
        :param client_secret (str): Workday client_secret.
        :param tenant_name (str): Workday tenant name.
        :param refresh_token (str): Workday refresh token.
        :param verify (bool): specifies whether to verify the SSL certificate or not.
        :param proxy (bool): specifies if to use XSOAR proxy settings.
        """

    def __init__(self, base_url, verify, proxy, client_id, client_secret, refresh_token, tenant_name):
        super().__init__(base_url, verify=verify, proxy=proxy)
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_token = refresh_token
        self.tenant_name = tenant_name

    def get_access_token(self):
        """
         Getting access token from Workday API.
        """
        demisto.debug("Fetching access token from Workday API.")
        workday_req_token_endpoint = f"{self._base_url}/ccx/oauth2/{self.tenant_name}/token"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        b64_encoded_string = (self.client_id + ':' + self.client_secret).encode('utf-8')

        data = {"grant_type": "refresh_token", "Authorization": "Basic {}".format(b64_encoded_string)}

        workday_resp_token = self._http_request(method="POST",
                                                full_url=workday_req_token_endpoint,
                                                headers=headers,
                                                data=data)
        if workday_resp_token:
            return json.loads(workday_resp_token.text).get("access_token")

    def http_request(self,
                     method: str,
                     url_suffix: str = '',
                     params: dict = None,
                     json_data: dict = None) -> dict:  # pragma: no cover
        """
        Overriding BaseClient http request in order to use the access token.
        """
        access_token = self.get_access_token()
        headers = self._headers
        headers['Authorization'] = f"Bearer {access_token}"
        return self._http_request(method=method,
                                  url_suffix=url_suffix,
                                  params=params,
                                  json_data=json_data,
                                  headers=headers)

    def get_activity_logging_request(self, from_date: str, to_date: str, offset: int,
                                     user_activity_entry_count: bool = False, limit: int = 1000) -> Dict[str, str]:
        """Returns a simple python dict with the information provided
        Args:
            offset: The zero-based index of the first object in a response collection.
            limit: The maximum number of loggings to return.
            to_date: date to fetch events from.
            from_date: date to fetch events to.
            user_activity_entry_count: If true, returns only the total count of user activity instances for the specified parameters.

        Returns:
            activity loggings returned from Workday API.
        """
        params = {"from": from_date,
                  "to": to_date,
                  "limit": limit,
                  "instancesReturned": 1,
                  "offset": offset,
                  "returnUserActivityEntryCount": user_activity_entry_count}
        res = self.http_request(method='GET', url_suffix='/activityLogging', params=params)
        return res.get('data', [])


''' HELPER FUNCTIONS '''


def get_max_fetch_activity_logging(client: Client, logging_to_fetch: int, from_date: str, to_date: str):
    """
    Fetches up to logging_to_fetch activity logging avaiable from Workday.
    Args:
        client: Client object.
        logging_to_fetch: limit of logging to fetch from Workday.
        from_date: loggings from time.
        to_date: loggings to time.

    Returns:
        Activity loggings fetched from Workday.
    """
    activity_loggings = []
    offset = 0
    while logging_to_fetch > 0:
        res = client.get_activity_logging_request(from_date=from_date, to_date=to_date, offset=offset)
        demisto.debug(f'Fetched {len(res)} activity loggings.')
        activity_loggings.extend(res)
        offset += len(res)
        logging_to_fetch -= len(res)
        demisto.debug(f'{logging_to_fetch} loggings left to fetch.')
        if not res:
            break
    demisto.debug(f'Found {len(activity_loggings)} activity loggings.')
    return activity_loggings


''' COMMAND FUNCTIONS '''


def get_activity_logging_command(client: Client, from_date: str, to_date: str, limit: Optional[int],
                                 offset: Optional[int]) -> CommandResults:
    """

    Args:
        offset: The zero-based index of the first object in a response collection.
        limit: The maximum number of loggings to return.
        to_date: date to fetch events from.
        from_date: date to fetch events to.
        client: Client object.

    Returns:
        Activity loggings from Workday.
    """

    activity_logging = client.get_activity_logging_request(to_date=to_date, from_date=from_date, limit=limit,
                                                           offset=offset)

    readable_output = tableToMarkdown('Activity Logging List:', activity_logging,
                                      removeNull=True,
                                      headerTransform=string_to_table_header)

    return CommandResults(readable_output=readable_output, raw_response=activity_logging)


def fetch_activity_logging(client: Client, max_fetch: int, first_fetch: datetime, last_run: dict):
    """
    Fetches activity loggings from Workday.
    Args:
        first_fetch: first fetch date.
        client: Client object.
        max_fetch: max loggings to fetch set by customer.
        last_run: last run object.

    Returns:
        Activity loggings from Workday.

    """
    from_date = last_run.get('last_fetch_time', first_fetch.strftime(DATE_FORMAT))
    to_date = datetime.now(tz=timezone.utc).strftime(DATE_FORMAT)
    demisto.debug(f'Getting activity loggings {from_date=}, {to_date=}.')
    activity_loggings = get_max_fetch_activity_logging(client=client,
                                                       logging_to_fetch=max_fetch,
                                                       from_date=from_date,
                                                       to_date=to_date)
    # setting last run object
    if activity_loggings:
        last_log_time = activity_loggings[-1].get('requestTime')
        last_run = {'last_fetch_time': last_log_time}

    return activity_loggings, last_run


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    try:
        client.get_access_token()
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure all parameters are correctly set'
        else:
            raise e
    return message


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions"""
    command = demisto.command()
    args = demisto.args()
    params = demisto.params()

    base_url = params.get('base_url')
    client_id = params.get('credentials', {}).get('identifier')
    client_secret = params.get('credentials', {}).get('password')
    tenant_name = params.get('tenant_name')
    token = params.get('token', {}).get('password')

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    max_fetch = arg_to_number(params.get('max_fetch')) or 1000
    first_fetch: datetime = arg_to_datetime(params.get('first_fetch', '3 days'))

    demisto.debug(f'Command being called is {command}')
    try:

        client = Client(
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
            tenant_name=tenant_name,
            refresh_token=token,
            verify=verify_certificate,
            proxy=proxy)

        if command == 'test-module':
            return_results(test_module(client))

        elif command in ('workday-get-activity-logging', 'fetch-events'):

            if command == 'workday-get-activity-logging':
                results = get_activity_logging_command(client=client,
                                                       from_date=args.get('from_date'),
                                                       to_date=args.get('to_date'),
                                                       limit=arg_to_number(args.get('limit')),
                                                       offset=arg_to_number(args.get('offset')))
                return_results(results)
            else:  # command == 'fetch-events':
                last_run = demisto.getLastRun()

                activity_loggings, new_last_run = fetch_activity_logging(client=client,
                                                                         max_fetch=max_fetch,
                                                                         first_fetch=first_fetch,
                                                                         last_run=last_run)

                demisto.info(f'Setting new last_run to {new_last_run}')
                demisto.setLastRun(new_last_run)

            if argToBoolean(args.get('should_push_events', 'true')):
                send_events_to_xsiam(activity_loggings, vendor=VENDOR, product=PRODUCT)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
