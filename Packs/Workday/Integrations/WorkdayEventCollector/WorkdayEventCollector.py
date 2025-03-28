import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
import math

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

MAX_EVENTS_PER_REQUEST = 100
VENDOR = 'Workday'
PRODUCT = 'Activity'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

        This Client implements API calls to the Saas Security platform, and does not contain any XSOAR logic.
        Handles the token retrieval.

        :param base_url (str): Workday server url.
        :param client_id (str): Workday client id.
        :param client_secret (str): Workday client_secret.
        :param token_url (str): Workday token url.
        :param refresh_token (str): Workday refresh token.
        :param verify (bool): specifies whether to verify the SSL certificate or not.
        :param proxy (bool): specifies if to use XSOAR proxy settings.
        """

    def __init__(self, base_url, token_url, verify, proxy, headers, client_id, client_secret, refresh_token, max_fetch):
        super().__init__(base_url, verify=verify, proxy=proxy, headers=headers)
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_token = refresh_token
        self.token_url = token_url
        self.max_fetch = max_fetch
        self.access_token = self.get_access_token()

    def get_access_token(self):  # pragma: no cover
        """
         Getting access token from Workday API.
        """
        demisto.debug("Fetching access token from Workday API.")
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {"grant_type": "refresh_token", "refresh_token": self.refresh_token}

        workday_resp_token = self._http_request(method="POST",
                                                full_url=self.token_url,
                                                headers=headers,
                                                data=data,
                                                auth=(self.client_id, self.client_secret))
        if workday_resp_token:
            return workday_resp_token.get("access_token")
        return None

    def http_request(self,
                     method: str,
                     url_suffix: str = '',
                     params: dict = None,
                     json_data: dict = None,
                     retries: int = 0) -> dict:  # pragma: no cover
        """
        Overriding BaseClient http request in order to use the access token.
        """
        headers = self._headers
        headers['Authorization'] = f"Bearer {self.access_token}"
        return self._http_request(method=method,
                                  url_suffix=url_suffix,
                                  params=params,
                                  json_data=json_data,
                                  headers=headers,
                                  retries=retries)

    def get_activity_logging_request(self, from_date: str, to_date: str, offset: Optional[int] = 0,
                                     user_activity_entry_count: bool = False, limit: Optional[int] = 1000) -> list:
        """Returns a simple python dict with the information provided
        Args:
            offset: The zero-based index of the first object in a response collection.
            limit: The maximum number of loggings to return.
            to_date: date to fetch events from.
            from_date: date to fetch events to.
            user_activity_entry_count: If true, returns only the total count of user activity instances for the params.

        Returns:
            activity loggings returned from Workday API.
        """
        instance_returned = math.ceil(self.max_fetch / 10000)
        params = {
            "from": from_date,
            "to": to_date,
            "limit": limit,
            "instancesReturned": instance_returned,
            "offset": offset,
            "returnUserActivityEntryCount": user_activity_entry_count,
            "type": "userActivity"
        }
        demisto.debug(f'params sent to Workday API are {str(params)}')
        res = self.http_request(method='GET', url_suffix='/activityLogging', params=params, retries=3)
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
    activity_loggings: list = []
    offset = 0
    while logging_to_fetch > 0:
        limit = logging_to_fetch if logging_to_fetch < 1000 else 1000
        res = client.get_activity_logging_request(from_date=from_date, to_date=to_date, offset=offset, limit=limit)
        demisto.debug(f'Fetched {len(res)} activity loggings.')
        activity_loggings.extend(res)
        offset += len(res)
        logging_to_fetch -= len(res)
        if not res:
            break
        demisto.debug(f'{logging_to_fetch} loggings left to fetch.')
    demisto.debug(f'Found {len(activity_loggings)} activity loggings.')
    return activity_loggings


def remove_duplications(activity_loggings: list, last_run: dict):
    """
    Removes potential duplicated activity loggings.

    Args:
        activity_loggings: activity loggings fetched from Workday.
        last_run: Last run object.
    """
    demisto.debug('Started removing duplications')
    last_log_stored = last_run.get('last_log')
    log_found = False
    final_count = 0
    if last_log_stored:
        for count, log in enumerate(activity_loggings):
            if log == last_log_stored:
                log_found = True
                final_count = count
                break
        if log_found:
            demisto.debug(f"Found duplicated with {last_log_stored}, returning from {final_count}")
            return activity_loggings[final_count + 1:]
    demisto.debug("Didn't find duplications, returning everything")
    return activity_loggings


def remove_milliseconds_from_time_of_logging(activity_logging: dict):
    """
    Workday API receive from_date only without milliseconds, therefor need to be removed.
    Args:
        activity_logging: activity logging

    Returns:
        The logging with the string in the correct format.

    """
    demisto.debug("Changing timestamp of loggings to match date format.")
    date_format_with_milliseconds = '%Y-%m-%dT%H:%M:%S.%fZ'
    request_time_date_obj = datetime.strptime(activity_logging.get('requestTime'), date_format_with_milliseconds)
    request_time_date_obj = request_time_date_obj.replace(microsecond=0)
    return datetime.strftime(request_time_date_obj, DATE_FORMAT)


''' COMMAND FUNCTIONS '''


def get_activity_logging_command(client: Client, from_date: str, to_date: str, limit: Optional[int],
                                 offset: Optional[int]) -> tuple[list, CommandResults]:
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

    activity_loggings = client.get_activity_logging_request(to_date=to_date, from_date=from_date, limit=limit,
                                                            offset=offset)
    readable_output = tableToMarkdown('Activity Logging List:', activity_loggings,
                                      removeNull=True,
                                      headerTransform=lambda x: string_to_table_header(camel_case_to_underscore(x)))

    return activity_loggings, CommandResults(readable_output=readable_output)


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
    demisto.debug(f'Getting activity loggings from_date={from_date}, to_date={to_date}.')
    activity_loggings = get_max_fetch_activity_logging(client=client, logging_to_fetch=max_fetch, from_date=from_date, to_date=to_date)
    activity_loggings = remove_duplications(activity_loggings=activity_loggings, last_run=last_run)
    if activity_loggings:
        last_log = activity_loggings[-1]
        last_log_time = remove_milliseconds_from_time_of_logging(last_log)
        last_run = {'last_fetch_time': last_log_time, 'last_log': last_log}

    return activity_loggings, last_run


def test_module(client: Client) -> str:  # pragma: no cover
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    client.get_access_token()
    return 'ok'


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions"""
    command = demisto.command()
    args = demisto.args()
    params = demisto.params()

    base_url = params.get('base_url')
    token_url = params.get('token_url')
    client_id = params.get('credentials', {}).get('identifier')
    client_secret = params.get('credentials', {}).get('password')
    token = params.get('token', {}).get('password')

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    max_fetch = arg_to_number(params.get('max_fetch')) or 1000
    first_fetch = arg_to_datetime(arg=params.get('first_fetch', '3 days'),
                                  arg_name='First fetch time',
                                  required=True)

    demisto.debug(f'Command being called is {command}')
    try:

        client = Client(
            base_url=base_url,
            token_url=token_url,
            client_id=client_id,
            client_secret=client_secret,
            refresh_token=token,
            verify=verify_certificate,
            proxy=proxy,
            headers={
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            max_fetch=max_fetch)

        if command == 'test-module':
            return_results(test_module(client))

        elif command == 'workday-get-activity-logging':
            should_push_events = argToBoolean(args.pop('should_push_events'))
            activity_loggings, results = get_activity_logging_command(client=client,
                                                                      from_date=args.get('from_date'),
                                                                      to_date=args.get('to_date'),
                                                                      limit=arg_to_number(args.get('limit')),
                                                                      offset=arg_to_number(args.get('offset')))
            return_results(results)
            if should_push_events:
                send_events_to_xsiam(
                    activity_loggings,
                    vendor=VENDOR,
                    product=PRODUCT
                )
        elif command == 'fetch-events':
            last_run = demisto.getLastRun()
            activity_loggings, new_last_run = fetch_activity_logging(client=client,
                                                                     max_fetch=max_fetch,
                                                                     first_fetch=first_fetch,  # type: ignore
                                                                     last_run=last_run)
            send_events_to_xsiam(
                activity_loggings,
                vendor=VENDOR,
                product=PRODUCT
            )
            if new_last_run:
                # saves next_run for the time fetch-events is invoked
                demisto.info(f'Setting new last_run to {new_last_run}')
                demisto.setLastRun(new_last_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
