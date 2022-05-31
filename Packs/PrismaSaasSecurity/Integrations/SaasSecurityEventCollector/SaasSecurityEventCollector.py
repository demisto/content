import json

import demistomock as demisto
import urllib3
import uuid
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import traceback
from typing import Dict, Tuple

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

MAX_EVENTS_PER_REQUEST = 100

# since the responses don't have an ID for an event, we will create one of our which will be a combination of
# timestamp and a random uuid.
OBJECT_KEYS = {'events': 'uuid'}

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
            token_initiate_time=float(json.loads(token_initiate_time)),
            token_expiration_seconds=float(json.loads(token_expiration_seconds))
        ):
            return json.loads(access_token)

        # there's no token or it is expired
        access_token, token_expiration_seconds = self.get_token_request()
        integration_context = {
            'access_token': access_token,
            'token_expiration_seconds': token_expiration_seconds,
            'token_initiate_time': time.time()
        }
        demisto.debug(f'updating access token - {integration_context}')
        set_to_integration_context_with_retries(context=integration_context)

        return access_token

    def get_token_request(self) -> Tuple[str, str]:
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
        params = {
            'grant_type': 'client_credentials',
            'scope': 'api_access',
        }
        token_response = self._http_request('POST', url_suffix='/oauth/token', params=params, headers=headers)
        return token_response.get('access_token'), token_response.get('expires_in')

    def get_events_request(self):
        """
        Get up to 100 event logs.
        """
        return self.http_request(
            'GET',
            url_suffix='/api/v1/log_events_bulk',
            resp_type='response',
            ok_codes=[200, 204],
        )

    def get_event_request(self):
        """
        Get only a single event log - used only for the test-module to verify log-access api scope.
        """
        return self.http_request(
            'GET',
            url_suffix='/api/v1/log_events',
            resp_type='response',
            ok_codes=[200, 204],
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


def validate_limit(limit: int):
    """
    Validate that the limit/max fetch is a number divisible by the MAX_EVENTS_PER_REQUEST (100) and that it is not
    a negative number.
    """
    if limit % MAX_EVENTS_PER_REQUEST != 0:
        raise DemistoException(f'fetch limit parameter should be divisible by {MAX_EVENTS_PER_REQUEST}')

    if limit <= 0:
        raise DemistoException('fetch limit parameter cannot be negative number or zero')


''' COMMAND FUNCTIONS '''


def test_module(client: Client):
    """
    Testing we have a valid connection to Saas-Security.

    The reason we must use the get events endpoint is because Saas-Security have different scopes for each type
    of api. To verify the customer have the log access scope we must try and fetch an event.
    Saves the events in the cache for fetching events.
    """
    response = client.get_event_request()
    if response.status_code == 200:
        fetched_event = response.json()
        demisto.info(f'fetched event in test-module: {fetched_event}')
        fetched_event['uuid'] = f'{uuid.uuid4()}'
        set_to_integration_context_with_retries(context={'events': fetched_event}, object_keys=OBJECT_KEYS)
        return 'ok'
    elif response.status_code == 204:
        return 'ok'


def get_events_command(
    client: Client, args: Dict, max_fetch: int, vendor='paloaltonetworks', product='saassecurity'
) -> Union[str, CommandResults]:
    """
    Fetches events from the saas-security queue and return them to the war-room.
    in case should_push_events is set to True, they will be also sent to XSIAM.
    """
    should_push_events = argToBoolean(args.get('should_push_events'))

    if events := fetch_events_from_saas_security(client=client, max_fetch=max_fetch):
        if should_push_events:
            send_events_to_xsiam(events=events, vendor=vendor, product=product)
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


def fetch_events_from_saas_security(client: Client, max_fetch: int) -> List[Dict]:
    """
    Fetches events from the saas-security queue.

    If the test-module produced any events, take them from the cache as well.
    """
    events: List[Dict] = []
    response = client.get_events_request()

    while len(events) < max_fetch and response.status_code == 200:
        fetched_events = response.json().get('events') or []
        demisto.info(f'fetched events: ({fetched_events}), fetched events length: ({len(fetched_events)})')
        events.extend(fetched_events)
        response = client.get_events_request()

    # get events fetched from test-module.
    integration_context_events = json.loads(demisto.getIntegrationContext().get('events') or '[]')
    demisto.info(
        f'integration context events: {integration_context_events}, '
        f'integration context events length {len(integration_context_events)}'
    )
    if integration_context_events:
        for event in integration_context_events:
            event.pop('uuid', None)
        # add integration context events to the fetched events.
        events.extend(integration_context_events)
        # set events to zero in case there was something in the cache from the test module.
        set_to_integration_context_with_retries(context={'events': []})

    return events


def main() -> None:
    params = demisto.params()
    client_id: str = params.get('credentials', {}).get('identifier', '')
    client_secret: str = params.get('credentials', {}).get('password', '')
    base_url: str = params.get('url', '').rstrip('/')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    args = demisto.args()
    max_fetch = arg_to_number(args.get('limit') or params.get('max_fetch')) or 100
    validate_limit(max_fetch)
    vendor, product = params.get('vendor'), params.get('product')

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
            return_results(test_module(client=client))
        elif command == 'fetch-events':
            send_events_to_xsiam(
                events=fetch_events_from_saas_security(client=client, max_fetch=max_fetch),
                vendor=vendor,
                product=product
            )
        elif command == 'saas-security-get-events':
            return_results(get_events_command(
                client=client, args=args, max_fetch=max_fetch, vendor=vendor, product=product)
            )
        else:
            raise ValueError(f'Command {command} is not implemented in saas-security integration.')
    except Exception as e:
        demisto.error(traceback.format_exc())
        raise Exception(f'Error in Palo Alto Saas Security Event Collector Integration [{e}]')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
