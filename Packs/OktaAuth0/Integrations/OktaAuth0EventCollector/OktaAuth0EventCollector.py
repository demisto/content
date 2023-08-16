import demistomock as demisto
from CommonServerPython import *

import time


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = "okta"
PRODUCT = "auth0"
DEFAULT_LIMIT = 1000
TOKEN_TIME_TO_EXPIRE = 23 * 60 * 60  # https://auth0.com/docs/secure/tokens/access-tokens/get-access-tokens#renew-access-tokens


''' HELPER FUNCTIONS '''


def arg_to_strtime(value: Any) -> Optional[str]:
    if datetime_obj := arg_to_datetime(value):
        return datetime_obj.strftime(DATE_FORMAT)
    return None


def prepare_query_params(params: dict, last_run: dict = {}) -> dict:
    """
    Parses the given inputs into Okta Auth0 Events API expected params format.
    """
    query_params = {}

    if not last_run:  # requesting by time query
        since = arg_to_strtime(params.get('since'))
        query_params = {
            "q": f"date:[{since} TO *]",
            "sort": "date:1",
            "per_page": 100
        }

    else:  # requesting by log_id
        query_params = {
            "from": last_run.get('last_id'),
            "sort": "date:1",
            "take": 100
        }

    return query_params


def get_access_token_from_context() -> Optional[str]:
    """Returns an access token if exists in the integration context and is not expired. Otherwise, returns None.
    Returns:
        Optional[str]: A valid access token, or `None`.
    """
    int_context = get_integration_context()
    if 'token_creation_time' not in int_context or \
            int(time.time()) - int_context.get('token_creation_time', 1) > TOKEN_TIME_TO_EXPIRE:
        return None
    return int_context["access_token"]


''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, base_url, client_id, client_secret, verify, proxy):
        super().__init__(base_url, verify, proxy, headers={})
        self.client_id = client_id
        self.client_secret = client_secret

        self.access_token = self.get_access_token()
        self._headers.update({'Authorization': f'Bearer {self.access_token}'})

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

        demisto.debug('Successfully got access token.')
        return raw_response

    def get_access_token(self):
        """Get the access token from the integration context if it has not expired.

        Returns:
            str: The access token.
        """
        if not (access_token := get_access_token_from_context()):
            access_token = self.get_access_token_request()["access_token"]
            set_integration_context({
                "access_token": access_token,
                "token_creation_time": int(time.time())
            })

        return access_token

    def get_events_request(self, query_params: dict) -> list:
        """
        Send request to get events from Okta Auth0.
        """
        raw_response = self._http_request(method='GET', url_suffix='/api/v2/logs', params=query_params)

        demisto.info(f'Succesfully got {len(raw_response)} events.')
        return raw_response

    def fetch_events(self, query_params: dict, last_run: dict, fetch_events_limit: Optional[int] = 1000) -> List[dict]:
        """
        Aggregates logs from Okta Auth0 and updates the last run object with the ID of the latest fetched log.

        Args:
            query_params (dict): The query params to fetch the events.
            last_run (dict): The lastRun object to update for the next fetch.
            fetch_events_limit (int): The fetch limit parameter configured in the instance.

        Return:
            (list[dict]): The list of the aggregated events.
        """
        aggregated_events: List[dict] = []

        events = self.get_events_request(query_params)
        try:
            while events:
                for event in events:

                    if len(aggregated_events) == fetch_events_limit:
                        demisto.info(f'Reached the user-defined limit ({fetch_events_limit}) - stopping.')
                        last_run['last_id'] = aggregated_events[-1].get('_id')
                        break

                    aggregated_events.append(event)

                else:
                    # Finished iterating through all events in this batch
                    query_params.update({'from': aggregated_events[-1].get('_id'), 'take': 100})
                    events = self.get_events_request(query_params)
                    continue

                demisto.info('Finished iterating through all events in this fetch run.')
                break
        except DemistoException as e:
            if not e.res or e.res.status_code != 429:
                raise e
            demisto.info('Reached API rate limit, storing last id')

        if aggregated_events:
            last_run['last_id'] = aggregated_events[-1].get('_id')

        return aggregated_events


''' COMMAND FUNCTIONS '''


def test_module_command(client: Client, params: dict, last_run: dict) -> str:
    """
    Tests connection with Okta Auth0.
    Args:
        client (Client): The client implementing the API to Okta Auth0.
        params (dict): The configuration parameters.
        last_run (dict): the lastRun object, holding information from the previous fetch run.

    Returns:
        (str) 'ok' if success.
    """
    params = prepare_query_params(params)
    fetch_events_command(client, params, last_run)
    return 'ok'


def get_events_command(client: Client, args: dict) -> tuple[list, CommandResults]:
    """
    Gets log events from Okta Auth0.
    Args:
        client (Client): the client implementing the API to Okta Auth0.
        args (dict): the command arguments.

    Returns:
        (list) the events retrieved from the API call.
        (CommandResults) the CommandResults object holding the collected events information.
    """
    query_params = prepare_query_params(args)
    events = client.fetch_events(query_params, {}, args.get('limit', 100))
    results = CommandResults(
        raw_response=events,
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
    fetch_events_limit = arg_to_number(params.get('limit', DEFAULT_LIMIT))
    events = client.fetch_events(query_params, last_run, fetch_events_limit)
    return events, last_run


''' MAIN FUNCTION '''


def add_time_to_events(events):
    """
    Adds the _time key to the events.
    Args:
        events: List[Dict] - list of events to add the _time key to.
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
        last_run = demisto.getLastRun()

        if command == 'test-module':
            return_results(test_module_command(client, params, last_run))

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
            events, last_run = fetch_events_command(client, params, last_run)
            add_time_to_events(events)
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
