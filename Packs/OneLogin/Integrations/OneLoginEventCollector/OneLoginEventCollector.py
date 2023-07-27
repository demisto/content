import demistomock as demisto
from CommonServerPython import *

from typing import Tuple


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


def prepare_query_params(params: dict, last_run: dict = {}) -> dict:
    """
    Parses the given inputs into OneLogin Events API expected format.
    """
    query_params = {
        'limit': arg_to_number(params.get('limit', DEFAULT_LIMIT)),
        'since': last_run.get('since') or arg_to_strtime(params.get('since')),
        'until': arg_to_strtime(params.get('until')),
        'event_type_id': params.get('event_type_id'),
        'after_cursor': last_run.get('after_cursor') or params.get('after_cursor')
    }

    return query_params


def check_response(raw_response):
    """
    Checks the status of the API raw respones and raises an exceptionif it's an error.
    """
    status = raw_response.get('status')
    if status and status.get('code') != 200 and status.get('error'):
        demisto.error(f"Failed to get events from OneLogin API. Error message: {status.get('message')}")
        raise Exception(f"Error code: {status.get('code')}. Error type: {status.get('type')}.\n"
                        f"Error message: {status.get('message')}")


def get_last_event_ids(events: List[dict]) -> list:
    """
    Gets the last event ids with the same created time from the last fetch to prevent duplications in the next fetches.
    """
    ids = []
    last_time = events[-1].get('created_at', '').rsplit('.')[0]  # Compare the times by seconds and not milliseconds
    for event in reversed(events):
        if event.get('created_at', '').rsplit('.')[0] != last_time:
            break
        ids.append(event.get('id'))
    return ids


''' CLIENT CLASS '''


class Client(BaseClient):

    def get_access_token_request(self):
        """
        Send request to get an access token from OneLogin.
        """
        raw_response = self._http_request(method='POST', url_suffix='/auth/oauth2/v2/token',
                                          params={'grant_type': 'client_credentials'})
        check_response(raw_response)

        demisto.info('Succesfully got access token.')
        return raw_response.get('access_token')

    def get_events_request(self, access_token: str, query_params: dict) -> Tuple:
        """
        Send request to get events from OneLogin.
        """
        self._headers['Authorization'] = f'Bearer:{access_token}'
        raw_response = self._http_request(method='GET', url_suffix='/api/1/events', params=query_params)
        check_response(raw_response)

        events = raw_response.get('data', [])
        cursor = raw_response.get('pagination', {}).get('after_cursor')
        demisto.info(f'Succesfully got {len(events)} events.')
        return raw_response, events, cursor

    def get_event_types_request(self) -> list:
        """
        Send request to get event types from OneLogin.
        """
        raw_response = self._http_request(method='GET', url_suffix='/api/1/events/types')
        check_response(raw_response)

        demisto.info('Succesfully got event types.')
        return raw_response.get('data', [])

    def get_event_types_from_last_run(self, last_run: dict):
        """
        Gets the event types from the LastRun obj.
        For the first fetch, will send a call to get the event types from OneLogin and will update the LastRun as well.
        """

        if 'event_types' not in last_run:
            event_types = self.get_event_types_request()
            last_run['event_types'] = {str(event_type['id']): event_type['name'] for event_type in event_types}

        return last_run.get('event_types')

    def convert_type_id_to_name(self, event: dict, event_types: dict, last_run: dict) -> str:
        """
        Gets the event type name by the event type id.

        Args:
            event: The event getting from the OneLogin events API call.
            event_types: Event types getting from the LastRun obj.
            last_run: The LastRun obj.

        Returns:
            (str): The event type name.
        """

        if event_type_name := event_types.get(str(event['event_type_id'])):
            return event_type_name

        demisto.info(f"Could not find the event type id {str(event['event_type_id'])}. "
                     f"Trying to request the event types from OneLogin.")
        event_types_res = self.get_event_types_request()
        event_types = {str(event_type['id']): event_type['name'] for event_type in event_types_res}

        if event_type_name := event_types.get(str(event['event_type_id'])):
            last_run['event_types'] = event_types
            return event_type_name

        demisto.info(f"Could not find the event type id '{str(event['event_type_id'])}' "
                     f"in the event types from OneLogin, returning an empty value")
        return ''

    def handle_pagination_first_batch(self, access_token: str, query_params: dict, last_run: dict) -> Tuple:
        """
        Makes the first events API call in the current fetch run.
        If `first_id` or `last_event_ids` exists in the lastRun obj, finds it in the response and
        returns only the subsequent events (that weren't collected yet).
        """
        _, events, cursor = self.get_events_request(access_token, query_params)

        if last_run.get('first_id'):

            for idx, event in enumerate(events):
                if event.get('id') == last_run['first_id']:
                    events = events[idx:]
                    break

            last_run.pop('first_id', None)  # removing to make sure it won't be used in future runs

        if event_ids := last_run.get('last_event_ids'):

            events_from_index = 0
            for idx, event in enumerate(events):
                if event.get('id') in event_ids:
                    events_from_index = idx + 1

            events = events[events_from_index:]

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

        event_types = self.get_event_types_from_last_run(last_run)

        user_defined_limit = query_params.pop('limit')
        query_params['limit'] = 1000  # Constant limit value for the request
        try:
            events, cursor = self.handle_pagination_first_batch(access_token, query_params, last_run)
            while events:
                for event in events:

                    if len(aggregated_events) == user_defined_limit:
                        demisto.info(f'Reached the user-defined limit ({user_defined_limit}) - stopping.')
                        last_run['first_id'] = event.get('id')
                        cursor = query_params['after_cursor']
                        break

                    event['event_type_name'] = self.convert_type_id_to_name(event, event_types, last_run)
                    aggregated_events.append(event)

                else:
                    # Finished iterating through all events in this batch
                    if cursor:
                        demisto.info('Using the cursor from the last API call to execute the next call.')
                        query_params['after_cursor'] = cursor
                        _, events, cursor = self.get_events_request(access_token, query_params)
                        continue

                demisto.info('Finished iterating through all events in this fetch run.')
                break

        except DemistoException as e:
            if not e.res or e.res.status_code != 429:
                raise e
            demisto.info('Reached API rate limit, storing last used cursor.')
            cursor = query_params['after_cursor']

        since = query_params['since'] if cursor or not aggregated_events else aggregated_events[-1].get('created_at')
        event_ids = last_run['last_event_ids'] if not aggregated_events else get_last_event_ids(aggregated_events)
        last_run.update({
            'after_cursor': cursor,
            'since': since,
            'last_event_ids': event_ids
        })

        return aggregated_events


''' COMMAND FUNCTIONS '''


def test_module_command(client: Client, params: dict) -> str:
    """
    Tests connection to OneLogin.
    Args:
        client (Client): The client implementing the API to OneLogin.
        params (dict): The configuration parameters.

    Returns:
        (str) 'ok' if success.
    """
    access_token = client.get_access_token_request()
    params = prepare_query_params(params)
    client.get_events_request(access_token, params)
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
    access_token = client.get_access_token_request()
    query_params = prepare_query_params(args)
    raw_response, events, cursor = client.get_events_request(access_token, query_params)
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
    access_token = client.get_access_token_request()
    query_params = prepare_query_params(params, last_run)
    events = client.fetch_events(access_token, query_params, last_run)
    return events, last_run


''' MAIN FUNCTION '''


def main() -> None:

    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    demisto.info(f'Command being called is {command}')
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
            return_results(test_module_command(client, params))

        elif command == 'onelogin-get-events':
            events, results = get_events_command(client, args)
            return_results(results)
            if argToBoolean(args.get('should_push_events', 'false')):
                send_events_to_xsiam(
                    events,
                    vendor=VENDOR,
                    product=PRODUCT
                )

        elif command == 'fetch-events':
            last_run = demisto.getLastRun()
            events, last_run = fetch_events_command(client, params, last_run)
            send_events_to_xsiam(
                events,
                vendor=VENDOR,
                product=PRODUCT
            )
            demisto.setLastRun(last_run)

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{e}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
