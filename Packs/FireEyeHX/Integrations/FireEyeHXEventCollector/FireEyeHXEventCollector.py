import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

VENDOR = 'FireEye'
PRODUCT = 'HX'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.000Z'


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls to fireeye.

    :param base_url (str): server url.
    :param username (str): the account username.
    :param password (str): the account password.
    :param verify (bool): specifies whether to verify the SSL certificate or not.
    :param proxy (bool): specifies if to use XSOAR proxy settings.
    """

    def __init__(self, base_url: str, username: str, password: str, verify: bool, proxy: bool, **kwargs):
        self.username = username
        self.password = password

        super().__init__(base_url=base_url, verify=verify, proxy=proxy, **kwargs)

    def http_request(self, *args, **kwargs):
        """
        Overrides Base client request function, retrieves and adds to headers access token before sending the request.
        """

        if not (token := demisto.getIntegrationContext().get('token')):
            token = self.get_access_token()

        headers = {'X-FeApi-Token': token}
        try:
            res = super()._http_request(*args, headers=headers, **kwargs)  # type: ignore[misc]
        except DemistoException as e:
            # in case the token expired - create the token again and make the request.
            if e.res is not None and e.res.status_code == 401:  # type: ignore[attr-defined]
                token = self.get_access_token()
                headers = {'X-FeApi-Token': token}
                res = super()._http_request(*args, headers=headers, **kwargs)  # type: ignore[misc]
            else:
                raise
        return res

    def get_access_token(self) -> str:
        """
       Obtains access and refresh token from server.
       Access token is used and stored in the integration context.

        Returns:
            str: the access token.
       """

        token_response = self._http_request('GET', url_suffix='/hx/api/v3/token', auth=(self.username, self.password),
                                            resp_type='response', ok_codes=[204])

        token = token_response.headers.get('X-FeApi-Token')
        demisto.setIntegrationContext({'token': token})
        return token

    def get_events_request(self, limit: str = '100', min_id: str = None, filter_query: str = None) -> dict:
        """
        Get alerts from fireeye
        """

        params = assign_params(sort='_id+ascending',
                               limit=limit,
                               min_id=min_id,
                               filterQuery=filter_query)

        return self.http_request(
            'GET',
            url_suffix='/hx/api/v3/alerts',
            ok_codes=[200],
            params=params
        )


''' COMMAND FUNCTIONS '''


def test_module(client: Client):
    """
    Testing we have a valid connection to fireeye.
    """
    client.get_events_request()
    return 'ok'


def get_events_command(
    client: Client,
    max_fetch: str,
    first_fetch: str,
    should_push_events: bool
) -> Union[str, CommandResults]:
    """
    Fetches events from the fireeye and return them to the war-room.
    """

    events = fetch_events(client=client, max_fetch=max_fetch, first_fetch=first_fetch,
                          should_push_events=should_push_events)

    if not events:
        return 'No events were found.'

    return CommandResults(
        readable_output=tableToMarkdown(
            'FireEye HX events',
            events,
            headerTransform=underscoreToCamelCase,
            removeNull=True
        ),
        raw_response=events,
        outputs=events,
        outputs_prefix='FireEyeHX.Event'
    )


def fetch_events(
    client: Client, max_fetch: str, first_fetch: str, min_id: str = None, should_push_events: bool = True
) -> list:
    """
    Fetches events from fireeye.
    """

    filter_query_str = None
    if not min_id:
        to_date = datetime.now().strftime(DATE_FORMAT)
        filter_query = {'operator': 'between', 'arg': [first_fetch, to_date], 'field': 'reported_at'}
        filter_query_str = json.dumps(filter_query)

    response = client.get_events_request(max_fetch, filter_query=filter_query_str, min_id=min_id)

    fetched_events = response.get('data', {}).get('entries', [])
    demisto.info(f'fetched events length: ({len(fetched_events)})')

    populate_modeling_rule_fields(fetched_events)

    if not should_push_events:
        return fetched_events

    try:
        demisto.info(f'sending the following amount of events into XSIAM: {len(fetched_events)}')
        send_events_to_xsiam(
            events=fetched_events,
            vendor=VENDOR,
            product=PRODUCT
        )
    except Exception as e:
        demisto.info(f'got error when trying to send events to XSIAM: [{e}]')
        raise e

    if fetched_events:
        last_alert: dict = fetched_events[-1]
        demisto.setLastRun({'last_alert_id': str(last_alert.get('id'))})

    return fetched_events


def populate_modeling_rule_fields(events: list) -> None:
    for event in events:
        try:
            # remove the _id field from the alert and set the id value instead
            event['id'] = event['_id']
            del event['_id']

        except TypeError:
            # modeling rule will default on ingestion time if _time is missing
            pass


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()

    username = params.get('credentials', {}).get('identifier', '')
    password = params.get('credentials', {}).get('password', '')
    base_url = params.get('url', '').rstrip('/')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    should_push_events = argToBoolean(args.get("should_push_events", False))
    max_fetch = args.get('limit') or params.get('max_fetch')

    last_run = demisto.getLastRun()

    first_fetch = params.get("first_fetch") or "3 days"
    last_fetch = arg_to_datetime(first_fetch).strftime(DATE_FORMAT)  # type: ignore[union-attr]

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            username=username,
            password=password,
            verify=verify_certificate,
            proxy=proxy,
        )
        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'fetch-events':
            fetch_events(client=client, max_fetch=max_fetch, first_fetch=last_fetch,
                         min_id=last_run.get('last_alert_id'))
        elif command == 'fireeye-hx-get-events':
            since = args.get("since") or "3 days"
            first_fetch = arg_to_datetime(since).strftime(DATE_FORMAT)  # type: ignore[union-attr]
            return_results(get_events_command(client, max_fetch=max_fetch, first_fetch=first_fetch,
                                              should_push_events=should_push_events))
        else:
            raise NotImplementedError(f'Command {command} is not implemented.')
    except Exception as e:
        return_error(
            f'Failed to execute {command} command. Error in FireEye HX Event Collector Integration [{e}].'
        )


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
