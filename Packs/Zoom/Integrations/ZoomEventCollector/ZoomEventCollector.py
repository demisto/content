import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any
from datetime import datetime, timezone, timedelta
from dateutil import relativedelta

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

REQUEST_DATE_FORMAT = '%Y-%m-%d'
RESPONSE_TIME_DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

VENDOR = 'Zoom'
PRODUCT = 'Zoom'

OAUTH_TOKEN_GENERATOR_URL = 'https://zoom.us/oauth/token'
# The token’s time to live is 1 hour,
# two minutes were subtract for extra safety.
TOKEN_LIFE_TIME = timedelta(minutes=58)

INVALID_CREDENTIALS = 'Invalid credentials. Verify that your credentials are valid.'
INVALID_API_SECRET = 'Invalid API Secret. Verify that your API Secret is valid.'
INVALID_ID_OR_SECRET = 'Invalid Client ID or Client Secret. Verify that your ID and Secret are valid.'
EXTRA_PARAMS = """Too many fields were filled. You should fill the Account ID, Client ID, and Client Secret fields (
OAuth)"""
INVALID_FIRST_FETCH_TIME = "The First fetch time should fall within the last six months."

LOG_TYPES = {"operationlogs": "operation_logs", "activities": "activity_logs"}

# maximum records that the api can return in one request
MAX_RECORDS_PER_PAGE = 300

''' CLIENT CLASS '''


class Client(BaseClient):
    """ A client class that implements logic to authenticate with Zoom application. """

    def __init__(
            self,
            base_url: str,
            account_id: str | None = None,
            client_id: str | None = None,
            client_secret: str | None = None,
            verify=True,
            proxy=False,
    ):
        super().__init__(base_url, verify, proxy)
        self.account_id = account_id
        self.client_id = client_id
        self.client_secret = client_secret
        # use the OAUTH authentication method.
        try:
            self.access_token = self.get_oauth_token()
        except Exception as e:
            demisto.debug(f"Cannot get access token. Error: {e}")
            self.access_token = None

    def generate_oauth_token(self):
        """

            Generate an OAuth Access token using the app credentials (AKA: client id and client secret)
            and the account id

            :return: valid token
         """
        token_res = self._http_request(method="POST", full_url=OAUTH_TOKEN_GENERATOR_URL,
                                       params={"account_id": self.account_id,
                                               "grant_type": "account_credentials"},
                                       auth=(self.client_id, self.client_secret))
        return token_res.get('access_token')

    def get_oauth_token(self, force_gen_new_token=False):
        """
            Retrieves the token from the server if it's expired and updates the global HEADERS to include it

            :param force_gen_new_token: If set to True will generate a new token regardless of time passed

            :rtype: ``str``
            :return: Token
        """
        now = datetime.now()
        ctx = get_integration_context()

        if not ctx or not ctx.get('token_info').get('generation_time', force_gen_new_token):
            # new token is needed
            oauth_token = self.generate_oauth_token()
            ctx = {}
        else:
            generation_time = dateparser.parse(ctx.get('token_info').get('generation_time'))
            if generation_time:
                time_passed = now - generation_time
            else:
                time_passed = TOKEN_LIFE_TIME
            if time_passed < TOKEN_LIFE_TIME:
                # token hasn't expired
                return ctx.get('token_info').get('oauth_token')
            else:
                # token expired
                oauth_token = self.generate_oauth_token()

        ctx.update({'token_info': {'oauth_token': oauth_token, 'generation_time': now.strftime("%Y-%m-%dT%H:%M:%S")}})
        set_integration_context(ctx)
        return oauth_token

    def error_handled_http_request(self, method, url_suffix='', full_url=None, headers=None,
                                   auth=None, json_data=None, params=None,
                                   return_empty_response: bool = False, resp_type: str = 'json', stream: bool = False):

        # all future functions should call this function instead of the original _http_request.
        # This is needed because the OAuth token may not behave consistently,
        # First the func will make an http request with a token,
        # and if it turns out to be invalid, the func will retry again with a new token.
        try:
            return super()._http_request(method=method, url_suffix=url_suffix, full_url=full_url, headers=headers,
                                         auth=auth, json_data=json_data, params=params,
                                         return_empty_response=return_empty_response, resp_type=resp_type,
                                         stream=stream)
        except DemistoException as e:
            if ('Invalid access token' in e.message
                    or "Access token is expired." in e.message):
                self.access_token = self.generate_oauth_token()
                headers = {'authorization': f'Bearer {self.access_token}'}
                return super()._http_request(method=method, url_suffix=url_suffix, full_url=full_url, headers=headers,
                                             auth=auth, json_data=json_data, params=params,
                                             return_empty_response=return_empty_response, resp_type=resp_type,
                                             stream=stream)
            else:
                raise DemistoException(e.message)

    def search_events(self, log_type: str, last_time: str = None, first_fetch_time: datetime = None,
                      limit: int = None) -> tuple[str, list[dict[str, Any]]]:
        """
        Searches for Zoom logs using the '/<url_suffix>' API endpoint.
        Args:
            log_type: str, The API endpoint to request.
            last_time: datetime, The datetime of the last event fetched.
            first_fetch_time: datetime, The first fetch time as configured in the integration params.
            limit: int, the limit of the results to return. (is received only in zoom-get-events command)
        Returns:
            Tuple:
                str: The time of the latest event fetched.
                List: A list containing the events.
        """

        results: list[dict] = []
        next_page_token = ''
        next_last_time = last_time
        first_page = True

        demisto.debug(f"Last run before the fetch run: {last_time}")
        start_date = first_fetch_time if not last_time else dateparser.parse(last_time).replace(tzinfo=timezone.utc)
        end_date = datetime.now(timezone.utc) + timedelta(days=1)

        demisto.debug(f"Starting to get logs from: {start_date} to: {end_date}")

        while start_date <= end_date:
            params = {
                'page_size': limit if limit else MAX_RECORDS_PER_PAGE,
                'from': start_date.strftime(REQUEST_DATE_FORMAT),
                'to': get_next_month(start_date).strftime(REQUEST_DATE_FORMAT) if start_date.month != end_date.month
                else end_date.strftime(REQUEST_DATE_FORMAT),
            }
            if next_page_token:
                params['next_page_token'] = next_page_token
                if start_date.month == end_date.month:
                    first_page = False
            demisto.debug(f'Sending HTTP request to {BASE_URL}/report/{log_type} with params: {params}')
            response = self.error_handled_http_request(
                method='GET',
                url_suffix=f'report/{log_type}',
                headers={'authorization': f'Bearer {self.access_token}'},
                params=params
            )

            logs = response.get(LOG_TYPES.get(log_type))
            for i, log in enumerate(logs):
                log_time = log.get("time")
                if not i and start_date.month == end_date.month and first_page:
                    next_last_time = log_time  # save the latest time
                if last_time and last_time == log_time:  # no more results
                    limit = True
                    break
                results.append(log)
            if limit:
                break

            if not (next_page_token := response.get("next_page_token")):
                start_date = get_next_month(start_date)

        demisto.debug(f"Last run after the fetch run: {next_last_time}")
        return next_last_time, results


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.
    Args:
        client (Client): Zoom client to use.
    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """

    try:
        client.search_events(log_type=next(iter(LOG_TYPES)), limit=1, first_fetch_time=datetime.now(timezone.utc))

    except DemistoException as e:
        error_message = e.message
        if 'Invalid access token' in error_message:
            error_message = INVALID_CREDENTIALS
        elif "The Token's Signature resulted invalid" in error_message:
            error_message = INVALID_API_SECRET
        elif 'Invalid client_id or client_secret' in error_message:
            error_message = INVALID_ID_OR_SECRET
        else:
            error_message = f'Problem reaching Zoom API, check your credentials. Error message: {error_message}'
        return error_message
    return 'ok'


def get_events(client: Client, first_fetch_time: datetime, limit: int = MAX_RECORDS_PER_PAGE) -> \
        tuple[list[dict[str, Any]], CommandResults]:
    """
    Gets all the events from the Zoom API for each log type.
    Args:
        client (Client): Zoom client to use.
        limit: int, the limit of the results to return per log_type.
        first_fetch_time(datetime): If last_run is None (first time we are fetching), it contains the timestamp in
            milliseconds on when to start fetching events.
    Returns:
        list: A list containing the events
        CommandResults: A CommandResults object that contains the events in a table format.
    """

    events: list[dict] = []

    if limit > MAX_RECORDS_PER_PAGE:
        raise DemistoException(
            f"The requested limit ({limit}) exceeds the maximum number of records per page ({MAX_RECORDS_PER_PAGE})."
            f" Please reduce the limit and try again.")
    hr = ""
    for log_type in LOG_TYPES:
        _, events_ = client.search_events(log_type=log_type, limit=limit, first_fetch_time=first_fetch_time)
        if events_:
            hr += tableToMarkdown(name=f"{log_type} Events", t=events_)
            events.extend(events_)
        else:
            hr += f"No events found for {log_type}.\n"
    return events, CommandResults(readable_output=hr)


def fetch_events(client: Client, last_run: dict[str, str], first_fetch_time: datetime | None) \
        -> tuple[dict[str, str], list[dict[str, Any]]]:
    """
    This function retrieves new alerts every interval (default is 1 minute).
    It will use last_run to save the timestamp of the last event it processed.
    If last_run is not provided, it should use the integration parameter first_fetch_time to determine when
    to start fetching the first time.

    Args:
        client (Client): Zoom client to use.
        last_run (dict): A dict with a key containing the latest event time we got from last fetch.
        first_fetch_time(datetime): If last_run is None (first time we are fetching), it contains the timestamp in
            milliseconds on when to start fetching events.
    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of events that will be created in XSIAM.
    """

    next_run: dict[str, str] = {}
    events = []

    for log_type in LOG_TYPES:
        next_run_time, events_ = client.search_events(
            log_type=log_type,
            last_time=last_run.get(log_type),
            first_fetch_time=first_fetch_time,
        )
        next_run[log_type] = next_run_time
        demisto.debug(f"Received {len(events_)} events for log type {log_type}")
        events.extend(events_)

    demisto.debug(f"Returning {len(events)} events in total")
    return next_run, events


def get_next_month(date_obj: datetime) -> datetime:
    """
    Given a datetime object, returns the datetime object of the next month on the same day.

    Args:
        date_obj (datetime): A datetime object representing the input date.

    Returns:
        datetime: A datetime object representing the date of the next month on the same day.

    Examples:
        get_next_month(datetime(2021, 12, 3)) -> 2022-01-03 00:00:00
    """
    return date_obj + relativedelta.relativedelta(months=1)


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()

    base_url = params.get('url')
    account_id = params.get('account_id')
    client_id = params.get('credentials', {}).get('identifier')
    client_secret = params.get('credentials', {}).get('password')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    command = demisto.command()

    demisto.debug(f'Command being called is {command}')
    try:

        # How much time before the first fetch to retrieve events
        first_fetch_time = params.get('first_fetch', '3 days')
        first_fetch_datetime = arg_to_datetime(
            arg=first_fetch_time,
            arg_name='First fetch time',
            required=True
        )
        if first_fetch_time == '6 months':
            first_fetch_datetime += timedelta(days=1)
        if first_fetch_datetime <= dateparser.parse('6 months', settings={'TIMEZONE': 'UTC'}):
            raise DemistoException("The First fetch time should fall within the last six months. "
                                   "Please provide a valid date within the last six months.")

        demisto.info(f'First fetch timestamp: {first_fetch_datetime}')


        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            account_id=account_id,
            client_id=client_id,
            client_secret=client_secret,
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif command in ('zoom-get-events', 'fetch-events'):
            if command == 'zoom-get-events':
                should_push_events = argToBoolean(args.pop('should_push_events'))
                events, results = get_events(client=client,
                                             limit=arg_to_number(args.get("limit")) or MAX_RECORDS_PER_PAGE,
                                             first_fetch_time=first_fetch_datetime.replace(tzinfo=timezone.utc),
                                             )
                return_results(results)

            else:  # command == 'fetch-events':
                should_push_events = True
                last_run = demisto.getLastRun()
                next_run, events = fetch_events(client=client,
                                                last_run=last_run,
                                                first_fetch_time=first_fetch_datetime.replace(tzinfo=timezone.utc),
                                                )
                # saves next_run for the time fetch-events is invoked
                demisto.debug(f'Set last run to {next_run}')
                demisto.setLastRun(next_run)
            if should_push_events:
                for event in events:
                    event["_time"] = event.get('time')
                send_events_to_xsiam(events,
                                     vendor=VENDOR,
                                     product=PRODUCT,
                                     )

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
