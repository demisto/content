import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from typing import Dict, Tuple

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

        token = demisto.getIntegrationContext().get('token')
        if not token:
            token = self.get_access_token()

        headers = {'X-FeApi-Token': token}
        try:
            res = super()._http_request(*args, headers=headers, **kwargs)  # type: ignore[misc]
        except Exception as e:
            # in case the token expired - create the token again and make the request.
            if e.res.status_code == 401:  # type: ignore[attr-defined]
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

    def get_events_request(self, limit: str = '100', min_id: str = None, filter_query: str = None,
                           resolution: str = None):
        """
        Get alerts from fireeye
        """

        params = assign_params(resolution=resolution,
                               sort='event_at+ascending',
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

    events = fetch_events(
        client=client, max_fetch=max_fetch, first_fetch=first_fetch)

    if not events:
        return 'No events were found.'

    if should_push_events:
        demisto.info(f'sending the following amount of events into XSIAM: {len(events)}')
        send_events_to_xsiam(
            events=events,
            vendor=VENDOR,
            product=PRODUCT
        )
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
    client: Client, max_fetch: str, first_fetch: str, resolution: str = None, min_id: str = None
) -> List[Dict]:
    """
    Fetches events from fireye.
    """

    # incase we want to retrieve all the resolution type, no need for this parameter.
    if resolution and resolution.lower() == 'all':
        resolution = None

    to_date = (datetime.now() + timedelta(days=1)).strftime(DATE_FORMAT)
    filter_query = {'operator': 'between', 'arg': [first_fetch, to_date], 'field': 'reported_at'}

    response = client.get_events_request(max_fetch, filter_query=json.dumps(filter_query), resolution=resolution,
                                         min_id=min_id)

    fetched_events = response.get('data', {}).get('entries', [])
    demisto.info(f'fetched events length: ({len(fetched_events)})')


    return fetched_events


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()

    username = params.get('credentials', {}).get('identifier', '')
    password = params.get('credentials', {}).get('password', '')
    base_url = params.get('url', '').rstrip('/')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    should_push_events = argToBoolean(args.get("should_push_events"))
    resolution = params.get('resolution')
    max_fetch = args.get('limit') or params.get('max_fetch')

    last_run = demisto.getLastRun()

    if last_run.get('last_alert_time'):
        last_fetch = last_run.get('last_alert_time')
    else:
        first_fetch = params.get("first_fetch") if params.get("first_fetch") else "3 days"
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
            events = fetch_events(
                client=client, max_fetch=max_fetch, first_fetch=last_fetch, resolution=resolution,
                min_id=last_run.get('last_alert_id'))

            if events:
                last_alert: dict = events[-1]
                demisto.setLastRun({'last_alert_id': str(last_alert.get('_id')),
                                    'last_alert_time': last_alert.get('event_at')})
            try:
                demisto.info(f'sending the following amount of events into XSIAM: {len(events)}')
                send_events_to_xsiam(
                    events=events,
                    vendor=VENDOR,
                    product=PRODUCT
                )
            except Exception as e:
                demisto.info(f'got error when trying to send events to XSIAM: [{e}]')
        elif command == 'fireeye-hx-get-events':
            since = args.get("since") if args.get("since") else "3 days"
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
