import demistomock as demisto
from CommonServerPython import *

from typing import Tuple
import time


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = "auth0"
PRODUCT = "identity"
DEFAULT_LIMIT = 1000
EXPIRED_TOKEN_RANGE = 23 * 60 * 60  # https://auth0.com/docs/secure/tokens/access-tokens/get-access-tokens#renew-access-tokens


''' HELPER FUNCTIONS '''


def arg_to_strtime(value: Any) -> Optional[str]:
    if datetime_obj := arg_to_datetime(value):
        return datetime_obj.strftime(DATE_FORMAT)
    return None


def prepare_query_params(params: dict, last_run: dict = {}) -> dict:
    """
    Parses the given inputs into Okta Auth0 Events API expected format.
    """
    since = arg_to_strtime(params.get('since'))
    query_params = {
        "q": last_run.get('query') or f"date:[{since} TO *]",
        "sort": "date:1",
        "page": last_run.get('page', 0),
        "per_page": arg_to_number(params.get('limit', DEFAULT_LIMIT))
    }

    return query_params


def should_refresh_access_token() -> bool:
    """Check whether the access token in the integration context has expired.

    Returns:
        bool: Whether the token has expired and should refresh the token.
    """
    int_context = get_integration_context()
    if 'expired_token_time' not in int_context or \
            int(time.time()) - int_context.get('expired_token_time', 1) > EXPIRED_TOKEN_RANGE:
        return True
    return False


def get_last_event_ids(events: List[dict]) -> list:
    """
    Gets the last 5 event ids from the last fetch to prevent duplications in the next fetch run.
    Currently the API returns in the response 2-3 events that their date is earlier than the date in the query.
    """
    return [event.get('_id') for event in reversed(events[-5:])]


''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, base_url, client_id, client_secret, verify, proxy):
        super().__init__(base_url, verify, proxy, headers={})
        self.client_id = client_id
        self.client_secret = client_secret

    def get_access_token_request(self):
        """
        Send request to get an access token from Okta Auth0.
        """
        body = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "audience": f"{self._base_url}/api/v2/",
            "grant_type": "client_credentials"
        }

        raw_response = self._http_request(
            method='POST',
            url_suffix='/oauth/token',
            data=body
        )

        demisto.info('Successfully got access token.')
        return raw_response

    def get_access_token(self):
        """Get the access token from the integration context if it has not expired.

        Returns:
            str: The access token.
        """

        if should_refresh_access_token():
            raw_response = self.get_access_token_request()
            set_integration_context({
                "access_token": raw_response.get("access_token"),
                "expired_token_time": raw_response.get("expires_in")
            })

        return get_integration_context()["access_token"]

    def get_events_request(self, query_params: dict) -> list:
        """
        Send request to get events from Okta Auth0.
        """
        query_params["per_page"] = 100 if query_params["per_page"] > 100 else query_params["per_page"]
        access_token = self.get_access_token()
        self._headers.update({'Authorization': f'Bearer {access_token}'})
        raw_response = self._http_request(method='GET', url_suffix='/api/v2/logs', params=query_params)

        demisto.info(f'Succesfully got {len(raw_response)} events.')
        return raw_response

    def handle_pagination_first_batch(self, query_params: dict, last_run: dict) -> list:
        """
        Makes the first events API call in the current fetch run to get the events from where the previous fetch has stopped.

        If `first_id` or `last_event_ids` exists in the lastRun obj, finds it in the response and
        returns only the subsequent events from these ids (that weren't collected yet).
        """
        events = self.get_events_request(query_params)

        if first_id := last_run.get('first_id'):

            for idx, event in enumerate(events):
                if event.get('_id') == first_id:
                    events = events[idx:]
                    break

            last_run.pop('first_id', None)  # removing to make sure it won't be used in future runs

        # In case that there is no first_id and because the API returns events
        # from earlier date than in the query
        elif event_ids := last_run.get('last_event_ids'):

            events_from_index = 0
            for idx, event in enumerate(events):
                if event.get('_id') in event_ids:
                    events_from_index = idx + 1

            events = events[events_from_index:]

        return events

    def fetch_events(self, query_params: dict, last_run: dict) -> List[dict]:
        """
        Aggregates events using pagination, until one of the following occurs:
        1. Reaches the user-defined limit (parameter).
           In this case, stores the last used `page` and `query` and the id of the next event to collect (`first_id`)
           and returns the events that have been accumulated so far.

        2. Reaches the end of the pagination.
           In this case, the lastRun obj will be updated with the `page` that will be 0
           and with a new date value in the `query` taken from the last event that were fetched.

        3. Reaches a rate limit.
           In this case, stores the last page used in the lastRun obj
           and returns the events that have been accumulated so far.
        """
        aggregated_events: List[dict] = []

        user_defined_limit = query_params.pop('per_page')
        query_params['per_page'] = 100  # Maximum value for per_page param
        try:
            page = 0
            events = self.handle_pagination_first_batch(query_params, last_run)
            while events:
                for event in events:

                    if len(aggregated_events) == user_defined_limit:
                        demisto.info(f'Reached the user-defined limit ({user_defined_limit}) - stopping.')
                        last_run['first_id'] = event.get('_id')
                        page = query_params['page']
                        break

                    aggregated_events.append(event)

                else:
                    # Finished iterating through all events in this batch
                    query_params['page'] += 1
                    demisto.info(f'Increasing the page value to {query_params["page"]} fetch more logs from the next page.')
                    events = self.get_events_request(query_params)
                    continue

                demisto.info('Finished iterating through all events in this fetch run.')
                break

        except DemistoException as e:
            if not e.res or e.res.status_code != 429:
                raise e
            page = query_params['page']
            demisto.info('Reached API rate limit, storing last used cursor.')

        query = query_params['q'] if page or not aggregated_events else f"date:[{aggregated_events[-1].get('date')} TO *]"
        event_ids = last_run['last_event_ids'] if not aggregated_events else get_last_event_ids(aggregated_events)
        last_run.update({
            'page': page,
            'query': query,
            'last_event_ids': event_ids
        })

        return aggregated_events


''' COMMAND FUNCTIONS '''


def test_module_command(client: Client, params: dict) -> str:
    """
    Tests connection with Okta Auth0.
    Args:
        client (Client): The client implementing the API to Okta Auth0.
        params (dict): The configuration parameters.

    Returns:
        (str) 'ok' if success.
    """
    params = prepare_query_params(params)
    client.get_events_request(params)
    return 'ok'


def get_events_command(client: Client, args: dict) -> Tuple[list, CommandResults]:
    """
    Gets log events from Okta Auth0.
    Args:
        cilent (Client): the client implementing the API to Okta Auth0.
        args (dict): the command arguments.

    Returns:
        (list) the events retrieved from the API call.
        (CommandResults) the CommandResults object holding the collected events information.
    """
    # access_token = client.get_access_token_request()
    query_params = prepare_query_params(args)
    raw_response, events, cursor = client.get_events_request(query_params)
    results = CommandResults(
        raw_response=raw_response,
        readable_output=tableToMarkdown(
            'Okta Auth0 Events',
            events,
            date_fields=['date'],
            removeNull=True
        ),
    )
    return events, results


def fetch_events_command(client: Client, params: dict, last_run: dict) -> tuple:
    """
    Collects log events from Okta Auth0 using pagination.
    Args:
        client (Client): the client implementing the API to Okta Auth0.
        params (dict): the instance configuration parameters.
        last_run (dict): the lastRun object, holding information from the previous run.

    Returns:
        (list) the events retrieved from the API call.
        (dict) the updated lastRun object.
    """
    query_params = prepare_query_params(params, last_run)
    events = client.fetch_events(query_params, last_run)
    return events, last_run


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
            create_time = arg_to_datetime(arg=event.get('date'))
            event['_time'] = create_time.strftime(DATE_FORMAT) if create_time else None


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
            client_id=client_id,
            client_secret=client_secret,
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False),
        )

        if command == 'test-module':
            return_results(test_module_command(client, params))

        elif command == 'okta-auth0-get-events':
            events, results = get_events_command(client, args)
            return_results(results)
            if argToBoolean(args.get('should_push_events', 'false')):
                add_time_to_events(events)
                send_events_to_xsiam(
                    events,
                    vendor=VENDOR,
                    product=PRODUCT
                )

        elif command == 'fetch-events':
            last_run = demisto.getLastRun()
            events, last_run = fetch_events_command(client, params, last_run)
            add_time_to_events(events)
            # print(f"first: {', '.join([e['date'] for e in events[:2]])}")
            # print(f"last: {', '.join([e['date'] for e in events[-2:]])}")
            # print(len(events))
            # print(f"{last_run}")
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
