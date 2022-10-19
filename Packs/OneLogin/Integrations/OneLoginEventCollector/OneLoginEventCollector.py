import demistomock as demisto
from CommonServerPython import *

from typing import Tuple
from dateparser import parse
from datetime import datetime, timedelta


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = "onelogin"
PRODUCT = "iam"
DEFAULT_LIMIT = 1000


''' HELPER FUNCTIONS '''


def arg_to_strtime(value: Any) -> Optional[str]:
    if datetime_obj := arg_to_datetime(value):
        return datetime_obj.strftime(DATE_FORMAT)
    return None


def increase_time_with_second(timestamp):
    date_time_timestamp = parse(timestamp)
    if not date_time_timestamp:
        return timestamp
    return datetime.strftime(date_time_timestamp + timedelta(seconds=1), DATE_FORMAT)


def prepare_query_params(params: dict, last_run: dict = {}) -> dict:
    """
    Parses the given inputs into OneLogin Events API expected format.
    """
    query_params = {
        'limit': arg_to_number(params.get('limit', DEFAULT_LIMIT)),
        'since': arg_to_strtime(last_run.get('since') or params.get('since')),
        'until': arg_to_strtime(params.get('until')),
        'event_type_id': params.get('event_type_id'),
        'after_cursor': last_run.get('after_cursor') or params.get('after_cursor')
    }

    return query_params


''' CLIENT CLASS '''


class Client(BaseClient):

    def get_access_token(self):
        """
        Send request to get an access token from OneLogin.
        """
        res = self._http_request(method='POST', url_suffix='/auth/oauth2/v2/token',
                                 params={'grant_type': 'client_credentials'})

        if 'status' in res and res.get('status', {}).get('error'):
            error = res.get('status', {})
            return_error(f"Got error {error.get('code')} - {error.get('type')}.\nError message: {error.get('message')}")

        demisto.debug('Succesfully got access token.')
        return res.get('access_token')

    def get_events(self, access_token: str, query_params: dict) -> Tuple:
        """
        Send request to get events from OneLogin.
        """
        self._headers['Authorization'] = f'Bearer:{access_token}'
        raw_response = self._http_request(method='GET', url_suffix='/api/1/events', params=query_params)

        status = raw_response.get('status')
        if status.get('code') != 200 and status.get('error'):
            demisto.error(f"Failed to get events from OneLogin API. Error message: {status.get('message')}")
            raise Exception(f"Error code: {status.get('code')}. Error type: {status.get('type')}.\n"
                            f"Error message: {status.get('message')}")

        events = raw_response.get('data', [])
        cursor = raw_response.get('pagination', {}).get('after_cursor')
        demisto.debug(f'Succesfully got {len(events)} events.')
        return raw_response, events, cursor

    def handle_pagination_first_batch(self, access_token: str, query_params: dict, last_run: dict) -> Tuple:
        """
        Makes the first evets API call in the current fetch run.
        If `first_id` exists in the lastRun obj, finds it in the response and
        returns only the subsequent events (that weren't collected yet).
        """
        _, events, cursor = self.get_events(access_token, query_params)
        if last_run.get('first_id'):
            for idx, event in enumerate(events):
                if event.get('id') == last_run['first_id']:
                    events = events[idx:]
                    break
            last_run.pop('first_id', None)  # removing to make sure it won't be used in future runs
        return events, cursor

    def fetch_events(self, access_token: str, query_params: dict, last_run: dict) -> List[dict]:
        """
        Aggregates events using cursor-based pagination, until one of the following occurs:
        1. Reaches the user-defined limit (parameter).
           In this case, stores the last used `cursor` and `since` and the id of the next event to collect (`first_id`)
           and returns the events that have been accumulated so far.

        2. Reaches the end of the pagination.
           In this case, the lastRun obj will be updated with the `cursor` that will be None
           and with a new value for `since` taken from the last event that were fetched.

        3. Reaches a rate limit.
           In this case, stores the last cursor used in the lastRun obj
           and returns the events that have been accumulated so far.
        """
        aggregated_events: List[dict] = []

        user_defined_limit = query_params.pop('limit')
        query_params['limit'] = 1000  # Constant limit value for the request
        try:
            events, cursor = self.handle_pagination_first_batch(access_token, query_params, last_run)
            while events:
                for event in events:

                    if len(aggregated_events) == user_defined_limit:
                        demisto.debug(f'Reached the user-defined limit ({user_defined_limit}) - stopping.')
                        last_run['first_id'] = event.get('id')
                        cursor = query_params['after_cursor']
                        break

                    aggregated_events.append(event)

                else:
                    # Finished iterating through all events in this batch
                    if cursor:
                        demisto.debug('Using the cursor from the last API call to execute the next call.')
                        query_params['after_cursor'] = cursor
                        _, events, cursor = self.get_events(access_token, query_params)
                        continue

                demisto.debug('Finished iterating through all events in this fetch run.')
                break

        except DemistoException as e:
            if not e.res or e.res.status_code != 429:
                raise e
            demisto.debug('Reached API rate limit, storing last used cursor.')
            cursor = query_params['after_cursor']

        since = query_params['since'] if cursor or not aggregated_events else increase_time_with_second(
            aggregated_events[-1].get('created_at'))
        last_run.update({
            'after_cursor': cursor,
            'since': since
        })

        return aggregated_events


''' COMMAND FUNCTIONS '''


def test_module_command(client: Client) -> str:
    """
    Tests connection to OneLogin.
    Args:
        client (Client): the client implementing the API to OneLogin.

    Returns:
        (str) 'ok' if success.
    """
    access_token = client.get_access_token()
    client.get_events(access_token, {})
    return 'ok'


def get_events_command(client: Client, args: dict) -> Tuple[list, CommandResults]:
    """
    Gets log events from OneLogin.
    Args:
        cilent (Client): the client implementing the API to OneLogin.
        args (dict): the command arguments.

    Returns:
        (list) the events retrieved from the API call.
        (CommandResults) the CommandResults object holding the collected events information.
    """
    access_token = client.get_access_token()
    query_params = prepare_query_params(args)
    raw_response, events, cursor = client.get_events(access_token, query_params)
    results = CommandResults(
        raw_response=raw_response,
        readable_output=tableToMarkdown(
            'OneLogin Events',
            events,
            metadata=f'Cursor: {cursor}' if cursor else None,
            date_fields=['created_at'],
            removeNull=True
        ),
    )
    return events, results


def fetch_events_command(client: Client, params: dict, last_run: dict) -> Tuple[list, dict]:
    """
    Collects log events from OneLogin using pagination.
    Args:
        client (Client): the client implementing the API to OneLogin.
        params (dict): the instance configuration parameters.
        last_run (dict): the lastRun object, holding information from the previous run.

    Returns:
        (list) the events retrieved from the API call.
        (dict) the updated lastRun object.
    """
    access_token = client.get_access_token()
    query_params = prepare_query_params(params, last_run)
    events = client.fetch_events(access_token, query_params, last_run)
    return events, last_run


''' MAIN FUNCTION '''


def main() -> None:

    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    demisto.debug(f'Command being called is {command}')
    try:

        client_id = params.get('credentials', {}).get('identifier')
        client_secret = params.get('credentials', {}).get('password')

        client = Client(
            base_url=params.get('url'),
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False),
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'client_id:{client_id}, client_secret:{client_secret}'
            },
        )

        if command == 'test-module':
            return_results(test_module_command(client))

        else:
            if command == 'onelogin-get-events':
                events, results = get_events_command(client, args)
                return_results(results)

            else:  # command == 'fetch-events'
                last_run = demisto.getLastRun()
                events, last_run = fetch_events_command(client, params, last_run)
                demisto.setLastRun(last_run)

            if argToBoolean(args.get('should_push_events', 'true')):
                send_events_to_xsiam(
                    events,
                    vendor=VENDOR,
                    product=PRODUCT
                )
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{e}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
