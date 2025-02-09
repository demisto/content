import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

VENDOR = 'paloaltonetworks'
PRODUCT = 'saassecurity'

MAX_ITERATIONS = 50
MAX_EVENTS_PER_REQUEST = 1000
MAX_LIMIT = 5000
DEFAULT_LIMIT = 1000

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls to the Saas Security platform, and does not contain any XSOAR logic.
    Handles the token retrieval.

    :param base_url (str): Saas Security server url.
    :param client_id (str): client ID.
    :param client_secret (str): client secret.
    :param verify (bool): specifies whether to verify the SSL certificate or not.
    :param proxy (bool): specifies if to use XSOAR proxy settings.
    """

    def __init__(self, base_url: str, client_id: str, client_secret: str, verify: bool, proxy: bool, **kwargs):
        self.client_id = client_id
        self.client_secret = client_secret

        super().__init__(base_url=base_url, verify=verify, proxy=proxy, **kwargs)

    def http_request(self, *args, **kwargs):
        """
        Overrides Base client request function, retrieves and adds to headers access token before sending the request.
        """
        token = self.get_access_token()
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
        }
        return super()._http_request(*args, headers=headers, **kwargs)  # type: ignore[misc]

    def get_access_token(self) -> str:
        """
       Obtains access and refresh token from server.
       Access token is used and stored in the integration context until expiration time.
       After expiration, new refresh token and access token are obtained and stored in the
       integration context.

        Returns:
            str: the access token.
       """
        integration_context = get_integration_context()
        access_token = integration_context.get('access_token')
        token_initiate_time = integration_context.get('token_initiate_time')
        token_expiration_seconds = integration_context.get('token_expiration_seconds')

        if access_token and not is_token_expired(
            token_initiate_time=float(token_initiate_time),
            token_expiration_seconds=float(token_expiration_seconds)
        ):
            return access_token

        # there's no token or it is expired
        access_token, token_expiration_seconds = self.get_token_request()
        integration_context = {
            'access_token': access_token,
            'token_expiration_seconds': token_expiration_seconds,
            'token_initiate_time': time.time()
        }
        demisto.debug(f'updating access token - {integration_context}')
        set_integration_context(context=integration_context)

        return access_token

    def get_token_request(self) -> tuple[str, str]:
        """
        Sends request to retrieve token.

       Returns:
           tuple[str, str]: token and its expiration date
        """
        base64_encoded_creds = b64_encode(f'{self.client_id}:{self.client_secret}')
        headers = {
            'accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded; charset=ISO-8859-1',
            'Authorization': f'Basic {base64_encoded_creds}',
        }
        data = {
            'grant_type': 'client_credentials',
            'scope': 'api_access',
        }
        token_response = self._http_request('POST', url_suffix='/oauth/token', data=data, headers=headers)
        return token_response.get('access_token'), token_response.get('expires_in')

    def get_events_request(self, size: int = MAX_EVENTS_PER_REQUEST):
        """
        Get up to 100 event logs.
        """
        return self.http_request(
            'GET',
            url_suffix='/api/v1/log_events_bulk',
            resp_type='response',
            ok_codes=[200, 204],
            params={"size": size}
        )


def is_token_expired(token_initiate_time: float, token_expiration_seconds: float) -> bool:
    """
    Check whether a token has expired. a token considered expired if it has been reached to its expiration date in
    seconds minus a minute.

    for example ---> time.time() = 300, token_initiate_time = 240, token_expiration_seconds = 120

    300.0001 - 240 < 120 - 60

    Args:
        token_initiate_time (float): the time in which the token was initiated in seconds.
        token_expiration_seconds (float): the time in which the token should be expired in seconds.

    Returns:
        bool: True if token has expired, False if not.
    """
    return time.time() - token_initiate_time >= token_expiration_seconds - 60


def get_max_fetch(limit: Optional[int]) -> int:
    """
    Validate and get the max fetch accodring to the following rules:

    1. if limit is negative raise an exception
    2. if limit is less than 10, limit will be equal to 10
    3. if limit is not dividable by 10, make sure it gets rounded down to a number that is dividable by 10.
    4. if limit > MAX_LIMIT (5000) - make sure it will always be MAX_LIMIT (5000).
    5. if limit is not provided, set it up for the default limit which is 1000.
    """
    if limit:
        if limit <= 0:
            raise DemistoException('fetch limit parameter cannot be negative number or zero')
        if limit < 10:
            limit = 10
        if limit > MAX_LIMIT:  # do not allow limit of more than 5000 to avoid timeouts
            limit = MAX_LIMIT
        if limit % 10 != 0:  # max limit must be a multiplier of 10 (SaaS api limit)
            # round down the limit
            limit = int(limit // 10) * 10
    else:
        limit = DEFAULT_LIMIT

    return limit


''' COMMAND FUNCTIONS '''


def test_module(client: Client):
    """
    Testing we have a valid connection to Saas-Security.
    """
    # if 401 will be raised, that means that the credentials are invalid an exception will be raised.
    client.get_token_request()
    return 'ok'


def get_events_command(
    client: Client,
    args: dict,
    max_fetch: Optional[int],
    vendor: str = VENDOR,
    product: str = PRODUCT,
    max_iterations: int = MAX_ITERATIONS
) -> Union[str, CommandResults]:
    """
    Fetches events from the saas-security queue and return them to the war-room.
    in case should_push_events is set to True, they will be also sent to XSIAM.
    """
    should_push_events = argToBoolean(args.get('should_push_events'))
    events, exception = fetch_events_from_saas_security(
        client=client, max_fetch=max_fetch, max_iterations=max_iterations
    )
    if exception:
        raise exception

    if events:
        if should_push_events:
            try:
                send_events_to_xsiam(events=events, vendor=vendor, product=product)
            except Exception as e:
                demisto.setLastRun({'events': events})
                raise e
        return CommandResults(
            readable_output=tableToMarkdown(
                'SaaS Security Logs',
                events,
                headers=['log_type', 'item_type', 'item_name', 'timestamp', 'serial'],
                headerTransform=underscoreToCamelCase,
                removeNull=True
            ),
            raw_response=events,
            outputs=events,
            outputs_key_field=['timestamp', 'log_type', 'item_name', 'item_type'],
            outputs_prefix='SaasSecurity.Event'
        )
    return 'No events were found.'


def fetch_events_from_saas_security(
    client: Client, max_fetch: Optional[int] = None, max_iterations: int = MAX_ITERATIONS
) -> tuple[List[dict], Exception | None]:
    """
    Fetches events from the saas-security queue.

    timeouts (204) docs:
    https://docs.paloaltonetworks.com/saas-security/saas-security-admin/saas-security-api/syslog-and-api-integration/
    api-client-integration/public-api-references/log-events-api#id2bfde842-f708-4e0b-bc41-9809903a6021_id8089db72-8f30-
    4cce-93d2-e39446be650d
    """
    events: List[dict] = []
    under_max_fetch = True

    #  if max fetch is None, all events will be fetched until there aren't anymore in the queue (until we get 204)
    try:
        iteration_num = 1  # this is done in order to prevent timeouts
        while under_max_fetch and iteration_num < max_iterations + 1:
            response = client.get_events_request()
            if response.status_code == 204:  # if we got 204, it means there aren't events in the queue, hence breaking.
                break
            fetched_events = response.json().get('events') or []
            demisto.info(f'fetched events length: ({len(fetched_events)}) in iteration {iteration_num}')
            demisto.info(f'fetched the following events: {fetched_events} in iteration {iteration_num}')
            events.extend(fetched_events)
            events_len = len(events)
            if max_fetch:
                under_max_fetch = events_len < max_fetch
            demisto.info(f'Collected already {events_len} events until iteration {iteration_num}')
            iteration_num += 1
    except Exception as exc:
        demisto.info(f'Got error get_events: {exc}')
        return events, exc

    return events, None


def main() -> None:  # pragma: no cover
    params = demisto.params()
    client_id: str = params.get('credentials', {}).get('identifier', '')
    client_secret: str = params.get('credentials', {}).get('password', '')
    base_url: str = params.get('url', '').rstrip('/')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    args = demisto.args()

    max_fetch = get_max_fetch(arg_to_number(args.get('limit') or params.get('max_fetch')))
    max_iterations = arg_to_number(params.get('max_iterations')) or MAX_ITERATIONS

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
            verify=verify_certificate,
            proxy=proxy,
        )
        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'fetch-events':
            integration_context = demisto.getIntegrationContext()
            demisto.info(f'{integration_context=}')
            if not integration_context.get('events'):
                events, exception = fetch_events_from_saas_security(
                    client=client, max_fetch=max_fetch, max_iterations=max_iterations
                )
                if len(events) == 0 and exception:
                    demisto.info(f'got exception when trying to fetch events: [{exception}]')
            else:
                events = integration_context.get('events')
                demisto.info('Fetching events from integration context')
            try:
                demisto.info(f'Sending the following amount of events into XSIAM: {len(events)}')
                send_events_to_xsiam(
                    events=events,
                    vendor=VENDOR,
                    product=PRODUCT
                )
                demisto.setIntegrationContext({})
            except Exception as e:
                demisto.info(f'Received error when trying to send events to XSIAM: [{e}]')
                demisto.setIntegrationContext({'events': events})
                demisto.info(f'Successfully set the following events into integration context: {events}')
        elif command == 'saas-security-get-events':
            return_results(get_events_command(client, args, max_fetch=max_fetch, max_iterations=max_iterations))
        else:
            raise NotImplementedError(f'Command {command} is not implemented in saas-security integration.')
    except Exception as e:
        return_error(
            f'Failed to execute {command} command. Error in Palo Alto Saas Security Event Collector Integration [{e}].'
        )


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
