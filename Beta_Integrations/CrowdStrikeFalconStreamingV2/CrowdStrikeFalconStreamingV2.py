import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

import requests
from asyncio import Event, create_task, sleep, run
from contextlib import asynccontextmanager
from aiohttp import ClientSession, TCPConnector
from typing import Dict, AsyncGenerator, AsyncIterator

requests.packages.urllib3.disable_warnings()

TOKEN_RETRIEVAL_HEADERS = {'Content-Type': 'application/x-www-form-urlencoded'}

MINUTES_25 = 25 * 60
MINUTES_30 = 30 * 60
TIME_BUFFER_1_MINUTE = 1 * 60
CREATED_STATUS_CODE = 201
TOO_MANY_REQUESTS_STATUS_CODE = 429


class Client(BaseClient):
    """CrowdStrike Falcon Streaming Client.

    Args:
        base_url (str): CrowdStrike Falcon Cloud base URL.
        app_id (str): CrowdStrike Falcon application ID.
        verify_ssl (bool): Whether the request should verify the SSL certificate.
        proxy (bool): Whether to run the integration using the system proxy.

    Returns:
        None: No data returned.
    """

    def __init__(self, base_url: str, app_id: str, verify_ssl: bool, proxy: bool) -> None:
        self.app_id = app_id
        self.refresh_stream_url = None
        super().__init__(base_url=base_url, verify=verify_ssl, proxy=proxy)

    async def set_access_token(self, refresh_token: 'RefreshToken') -> None:
        await refresh_token.set_access_token(self)
        demisto.debug('Set access token successfully')

    def set_auth_headers(self, token: str) -> None:
        self._headers = {'Authorization': f'Bearer {token}'}
        demisto.debug('Set auth headers successfully')

    def discover_stream(self) -> Dict:
        demisto.debug('Sending request to discover stream')
        return self._http_request(
            method='GET',
            url_suffix='/sensors/entities/datafeed/v2',
            params={'appId': self.app_id},
        )

    def refresh_stream_session(self) -> None:
        demisto.debug('Sending request to refresh stream')
        self._http_request(
            method='POST',
            url_suffix='',
            full_url=self.refresh_stream_url
        )


class EventStream:
    """CrowdStrike Falcon Streaming event object.

    Args:
        base_url (str): CrowdStrike Falcon Cloud base URL.
        app_id (str): CrowdStrike Falcon application ID.
        verify_ssl (bool): Whether the request should verify the SSL certificate.
        proxy (bool): Whether to run the integration using the system proxy.

    Returns:
        None: No data returned.
    """

    def __init__(self, base_url: str, app_id: str, verify_ssl: bool, proxy: bool):
        self.base_url = base_url
        self.app_id = app_id
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.data_feed_url: str
        self.session_token: str
        self.refresh_token: RefreshToken

    def set_refresh_token(self, refresh_token) -> None:
        self.refresh_token = refresh_token

    async def _discover_refresh_stream(self, event: Event) -> None:
        """Discovers or refreshes a discovered CrowdStrike Falcon stream in a loop.

        Sleeps for 25 minutes (expiry time is 30 minutes) between operations.

        Args:
            event (Event): Asynchronous event object to set or clear its internal flag.

        Yields:
            Iterator[Dict]: Event fetched from the stream.
        """
        client = Client(base_url=self.base_url, app_id=self.app_id, verify_ssl=self.verify_ssl, proxy=self.proxy)
        while True:
            if client.refresh_stream_url:
                # We already discovered an event stream, need to refresh it
                demisto.debug('Starting stream refresh')
                client.refresh_stream_session()
                demisto.debug('Finished stream refresh')
            else:
                # We have no event stream, need to discover
                await client.set_access_token(self.refresh_token)
                demisto.debug('Starting stream discovery')
                discover_stream_response = client.discover_stream()
                demisto.debug('Finished stream discovery')
                resources = discover_stream_response.get('resources', [])
                if not resources:
                    raise ValueError(f'Did not get event stream resources - {str(discover_stream_response)}')
                resource = resources[0]
                self.data_feed_url = resource.get('dataFeedURL')
                self.session_token = resource.get('sessionToken', {}).get('token')
                refresh_url = resource.get('refreshActiveSessionURL')
                client.refresh_stream_url = refresh_url
                event.set()
            await sleep(MINUTES_25)
            event.clear()

    async def fetch_event(self, offset: int = 0, event_type: str = '') -> AsyncGenerator[Dict, None]:
        """Retrieves events from a CrowdStrike Falcon stream starting from given offset.

        Args:
            offset (int): Stream offset to start the fetch from.
            event_type (str): Stream event type to fetch.

        Yields:
            AsyncGenerator[Dict, None]: Event fetched from the stream.
        """
        demisto.debug('Fetching event')
        event = Event()
        create_task(self._discover_refresh_stream(event))
        demisto.debug('Waiting for stream discovery or refresh')
        await event.wait()
        demisto.debug('Done waiting for stream discovery or refresh')
        async with ClientSession(
            connector=TCPConnector(ssl=self.verify_ssl),
            headers={'Authorization': f'Token {self.session_token}'},
            trust_env=self.proxy
        ) as session:
            try:
                async with session.get(self.data_feed_url, params={'offset': offset, 'eventType': event_type}) as res:
                    demisto.debug(f'Fetched event: {res.content}')
                    async for line in res.content:
                        stripped_line = line.strip()
                        if stripped_line:
                            try:
                                yield json.loads(stripped_line)
                            except json.decoder.JSONDecodeError:
                                demisto.debug(f'Failed decoding event (skipping it) - {str(stripped_line)}')
            except Exception as e:
                demisto.debug(f'Failed to fetch event: {e} - Going to sleep for 10 seconds and then retry')
                await sleep(10)


class RefreshToken:
    """Object to represent CrowdStrike Falcon refresh token needed to get access token for API requests.

    Args:
        base_url (str): CrowdStrike Falcon Cloud base URL.
        client_id (str): CrowdStrike Falcon application ID.
        client_secret (str): CrowdStrike Falcon application secret.
        verify_ssl (bool): Whether the request should verify the SSL certificate.
        proxy (bool): Whether to run the integration using the system proxy.

    Returns:
        None: No data returned.
    """
    def __init__(self, base_url: str, client_id: str, client_secret: str, verify_ssl: bool, proxy: bool) -> None:
        self.base_url: str = base_url
        self.client_id: str = client_id
        self.client_secret: str = client_secret
        self.verify_ssl: bool = verify_ssl
        self.proxy: bool = proxy
        self.client: Client
        self.token: str = ''
        self.expiry_time: int = 0

    async def set_access_token(self, client: Client) -> None:
        self.client = client
        if not self.token:
            token = await self.get_access_token()
            self.token = token
        client.set_auth_headers(self.token)

    async def get_access_token(self) -> str:
        """Retrieves CrowdStrike Falcon access token required for API requests.

        Runs for max retries of 3 attempts in case of API rate limit hit.

        Returns:
            str: The access token retrieved.

        Raises:
            RuntimeError: An error occurred (json.decoder.JSONDecodeError) trying to deserialize the API response.
        """
        token = None
        body = None
        max_retries = 3
        async with ClientSession(
            connector=TCPConnector(ssl=self.verify_ssl),
            headers=TOKEN_RETRIEVAL_HEADERS,
            trust_env=self.proxy
        ) as session:
            for _ in range(max_retries):
                data = {
                    'client_id': self.client_id,
                    'client_secret': self.client_secret
                }
                async with session.post(f'{self.base_url}/oauth2/token', data=data) as res:
                    if res.status == TOO_MANY_REQUESTS_STATUS_CODE:
                        demisto.debug('Token retrieval requests status: rate limit exceeded, will retry in 5 seconds.')
                        await sleep(5)
                    elif res.status == CREATED_STATUS_CODE:
                        try:
                            body = await res.json()
                            break
                        except json.decoder.JSONDecodeError:
                            raise RuntimeError(
                                f'Failed to decode successful token retrieval response: {str(res.content)}'
                            )
                    else:
                        try:
                            body = await res.json()
                            error = body.get('errors', [{}])
                            error_message = error[0].get('message', '')
                            raise RuntimeError(
                                f'Failed to retrieve token, verify client details are correct: {error_message}'
                            )
                        except json.decoder.JSONDecodeError:
                            raise RuntimeError(
                                f'Failed to decode token retrieval failure response: {str(res.content)}'
                            )
            if not body:
                raise RuntimeError(f'Failed to retrieve token - got empty response: {str(res.content)}')
            token = body.get('access_token')
            self.expiry_time = body.get('expires_in', MINUTES_30) - TIME_BUFFER_1_MINUTE
        if not token:
            raise RuntimeError('Failed to retrieve token')
        return token

    async def refresh_token_loop(self) -> None:
        while True:
            await sleep(self.expiry_time)
            token = await self.get_access_token()
            self.token = token
            self.client.set_auth_headers(token)


@asynccontextmanager
async def init_refresh_token(
        base_url: str,
        client_id: str,
        client_secret: str,
        verify_ssl: bool,
        proxy: bool
) -> AsyncIterator[RefreshToken]:
    """Initializes RefreshToken instance and authenticates with CrowdStrike Falcon.

    Args:
        base_url (str): CrowdStrike Falcon Cloud base URL.
        client_id (str): CrowdStrike Falcon application ID.
        client_secret (str): CrowdStrike Falcon application secret.
        verify_ssl (bool): Whether the request should verify the SSL certificate.
        proxy (bool): Whether to run the integration using the system proxy.

    Yields:
        AsyncIterator[RefreshToken]: RefreshToken instance initialized with client details.
    """
    refresh_token = RefreshToken(base_url, client_id, client_secret, verify_ssl, proxy)
    await refresh_token.get_access_token()
    task = create_task(refresh_token.refresh_token_loop())
    yield refresh_token
    task.cancel()


async def long_running_loop(
        base_url: str,
        client_id: str,
        client_secret: str,
        stream: EventStream,
        offset: int,
        event_type: str,
        verify_ssl: bool,
        proxy: bool
) -> None:
    """Connects to a CrowdStrike Falcon stream and fetches events from it in a loop.

    Args:
        base_url (str): CrowdStrike Falcon Cloud base URL.
        client_id (str): CrowdStrike Falcon application ID.
        client_secret (str): CrowdStrike Falcon application secret.
        stream (EventStream): CrowdStrike Falcon stream to fetch events from.
        offset (int): Stream offset to start the fetch from.
        event_type (str): Stream event type to fetch.
        verify_ssl (bool): Whether the request should verify the SSL certificate.
        proxy (bool): Whether to run the integration using the system proxy.

    Returns:
        None: No data returned.
    """
    async with init_refresh_token(base_url, client_id, client_secret, verify_ssl, proxy) as refresh_token:
        stream.set_refresh_token(refresh_token)
        async for event in stream.fetch_event(offset=offset, event_type=event_type):
            event_metadata = event.get('metadata', {})
            event_type = event_metadata.get('eventType', '')
            event_offset = event_metadata.get('offset', '')
            demisto.info(f'Fetching event with offset: {event_offset}')
            incident_name = f'{event_type} - offset {event_offset}'
            incident = [{
                'name': incident_name,
                'details': json.dumps(event)
            }]
            demisto.createIncidents(incident)


async def test_module(base_url: str, client_id: str, client_secret: str, verify_ssl: bool, proxy: bool) -> None:
    async with init_refresh_token(base_url, client_id, client_secret, verify_ssl, proxy) as refresh_token:
        await refresh_token.get_access_token()
        demisto.results('ok')


def main():
    params: Dict = demisto.params()
    base_url: str = params.get('base_url', '')
    client_id: str = params.get('client_id', '')
    client_secret: str = params.get('client_secret', '')
    event_type = ','.join(params.get('event_type', []))
    verify_ssl = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    offset = params.get('offset', '0')
    try:
        offset = int(offset)
    except ValueError:
        offset = 0

    stream = EventStream(base_url=base_url, app_id='Demisto', verify_ssl=verify_ssl, proxy=proxy)

    LOG(f'Command being called is {demisto.command()}')
    try:
        if demisto.command() == 'test-module':
            run(test_module(base_url, client_id, client_secret, verify_ssl, proxy))
        elif demisto.command() == 'long-running-execution':
            run(long_running_loop(base_url, client_id, client_secret, stream, offset, event_type, verify_ssl, proxy))
    except Exception as e:
        error_msg = f'Error in CrowdStrike Falcon Streaming v2: {str(e)}'
        demisto.error(error_msg)
        demisto.updateModuleHealth(error_msg)
        return_error(error_msg)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
