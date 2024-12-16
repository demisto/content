from datetime import datetime, timedelta

import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

import traceback
from asyncio import create_task, sleep, run
from contextlib import asynccontextmanager
from aiohttp import ClientSession, TCPConnector, ClientTimeout
from collections.abc import AsyncGenerator, AsyncIterator
from collections import deque
from random import uniform
import json

import urllib3
urllib3.disable_warnings()

TOKEN_RETRIEVAL_HEADERS = {'Content-Type': 'application/x-www-form-urlencoded'}

MINUTES_30 = 30 * 60
TIME_BUFFER_1_MINUTE = 1 * 60
OK_STATUS_CODE = 200
CREATED_STATUS_CODE = 201
UNAUTHORIZED_STATUS_CODE = 401
TOO_MANY_REQUESTS_STATUS_CODE = 429

CONTAINER_ID = os.environ.get('HOSTNAME')


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
        super().__init__(
            base_url=base_url,
            verify=verify_ssl,
            proxy=proxy,
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        )

    async def set_access_token(self, refresh_token: 'RefreshToken') -> None:
        await refresh_token.set_access_token(self)
        demisto.debug('Set access token successfully')

    def set_auth_headers(self, token: str) -> None:
        self._headers.update({'Authorization': f'Bearer {token}'})
        demisto.debug('Set auth headers successfully')

    async def _http_request(  # type: ignore[override]
        self, method, url_suffix, full_url=None, headers=None, auth=None, json_data=None,  # noqa: F841
        params=None, data=None, files=None, timeout=10, resp_type='json', ok_codes=None,  # noqa: F841
        return_empty_response=False, retries=0, status_list_to_retry=None,  # noqa: F841
        backoff_factor=5, raise_on_redirect=False, raise_on_status=False,  # noqa: F841
        error_handler=None, **kwargs  # noqa: F841
    ):
        while True:
            try:
                res = super()._http_request(
                    method=method,
                    url_suffix=url_suffix,
                    params=params,
                    full_url=full_url,
                    resp_type='response',
                    ok_codes=(
                        OK_STATUS_CODE,
                        CREATED_STATUS_CODE,
                        UNAUTHORIZED_STATUS_CODE,
                        TOO_MANY_REQUESTS_STATUS_CODE,
                    ),
                )
                if res.ok:
                    try:
                        demisto.debug(f'Got status code {res.status_code}')
                        return res.json()
                    except ValueError as e:
                        demisto.debug(
                            f'Failed deserializing the json-encoded content of the response: {res.content} - {str(e)}'
                        )
                elif res.status_code == UNAUTHORIZED_STATUS_CODE:
                    sleep_time = uniform(1, 10)
                    demisto.debug(
                        f'Got status code 401 on stream discovery, going to sleep for {sleep_time} - {str(res.content)}'
                    )
                    await sleep(sleep_time)
                    demisto.debug('Getting new OAuth2 token')
                    token = await kwargs.get('refresh_token').get_access_token()  # type: ignore[union-attr]
                    self.set_auth_headers(token)
                elif res.status_code == TOO_MANY_REQUESTS_STATUS_CODE:
                    now_time = int(time.time())
                    retry_after = res.headers.get('X-Ratelimit-RetryAfter', 0)
                    time_to_wait = max(int(retry_after), now_time + 5) - now_time
                    demisto.debug(f'Rate limit exceeded, going to sleep for {time_to_wait} seconds and then retry. '
                                  f'Response headers: {str(res.headers)} '
                                  f'Response body: {str(res.content)}')
                    demisto.updateModuleHealth(
                        f'Rate limit exceeded, going to sleep for {time_to_wait} and then retry.'
                    )
                    await sleep(time_to_wait)
                    demisto.debug('Finished waiting - retrying')
            except Exception as e:
                demisto.debug(str(e))
                return {}

    async def discover_stream(self, refresh_token: 'RefreshToken') -> dict:
        demisto.debug('Sending request to discover stream')
        return await self._http_request(
            method='GET',
            url_suffix='/sensors/entities/datafeed/v2',
            params={'appId': self.app_id},
            refresh_token=refresh_token,
        )

    async def refresh_stream_session(self, refresh_token: 'RefreshToken') -> dict:
        demisto.debug(f'Sending request to refresh stream to {self.refresh_stream_url}')
        return await self._http_request(
            method='POST',
            url_suffix='',
            full_url=self.refresh_stream_url,
            refresh_token=refresh_token,
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
        self.client: Client

    def set_refresh_token(self, refresh_token) -> None:
        self.refresh_token = refresh_token

    async def _discover_stream(self) -> None:
        """Discovers a CrowdStrike Falcon stream
        and initializes the data feed URL and refresh session URL client resource attributes

        Returns:
            None: No data returned.

        Raises:
            RuntimeError: In case stream discovery failed.
        """
        await self.client.set_access_token(self.refresh_token)
        demisto.debug(f'Starting stream discovery. Container ID: {CONTAINER_ID}')
        discover_stream_response = await self.client.discover_stream(self.refresh_token)
        resources = discover_stream_response.get('resources', [])
        if not resources:
            demisto.updateModuleHealth(
                'Did not discover event stream resources, verify the App ID is not used'
                ' in another integration instance')
            raise RuntimeError(f'Did not discover event stream resources - {str(discover_stream_response)}')
        resource = resources[0]
        self.data_feed_url = resource.get('dataFeedURL')
        demisto.debug(f'Discovered data feed URL: {self.data_feed_url}')
        self.session_token = resource.get('sessionToken', {}).get('token')
        refresh_url = resource.get('refreshActiveSessionURL')
        self.client.refresh_stream_url = refresh_url
        demisto.updateModuleHealth('')
        demisto.debug('Finished stream discovery successfully')

    async def _refresh_stream(self) -> None:
        """Refreshes a CrowdStrike Falcon stream resource

        Returns:
            None: No data returned.

        Raises:
            RuntimeError: In case stream refresh failed.
        """
        demisto.debug(f'Starting stream refresh. Container ID: {CONTAINER_ID}')
        response = await self.client.refresh_stream_session(self.refresh_token)
        if not response:
            # Should get here in case we got unexpected status code (e.g. 404) from the refresh stream query
            demisto.updateModuleHealth('Failed refreshing stream session, will try to discover new stream.')
            raise RuntimeError(
                'Failed refreshing stream session. '
                'More details about the failure reason should appear in the logs above.'
            )
        else:
            demisto.debug(f'Refresh stream response: {response}')
        demisto.updateModuleHealth('')
        demisto.debug('Finished stream refresh successfully')

    async def fetch_event(
            self, first_fetch_time: datetime, initial_offset: int = 0, event_type: str = '', sock_read: int = 120
    ) -> AsyncGenerator[dict, None]:
        """Retrieves events from a CrowdStrike Falcon stream starting from given offset.

        Args:
            first_fetch_time (datetime): The start time to fetch from retroactively for the first fetch.
            initial_offset (int): Stream offset to start the fetch from.
            event_type (str): Stream event type to fetch.
            sock_read (int) Client session sock read timeout.

        Yields:
            AsyncGenerator[Dict, None]: Event fetched from the stream.
        """
        while True:
            try:
                demisto.debug(f'Starting event fetch loop. Container ID: {CONTAINER_ID}')
                self.client = Client(
                    base_url=self.base_url, app_id=self.app_id, verify_ssl=self.verify_ssl, proxy=self.proxy
                )
                await self._discover_stream()
                events_fetched = 0
                new_lines_fetched = 0
                last_fetch_stats_print = datetime.utcnow()
                last_refresh_stream = datetime.utcnow()
                async with ClientSession(
                    connector=TCPConnector(ssl=self.verify_ssl),
                    headers={
                        'Authorization': f'Token {self.session_token}',
                        'Connection': 'keep-alive'
                    },
                    trust_env=self.proxy,
                    timeout=ClientTimeout(total=None, connect=60, sock_connect=60, sock_read=sock_read)
                ) as session:
                    integration_context = get_integration_context()
                    offset = integration_context.get('offset', 0) or initial_offset
                    demisto.debug(f'Starting to fetch from offset {offset} events of type {event_type} '
                                  f'from time {first_fetch_time}')
                    async with session.get(
                        self.data_feed_url,
                        params={'offset': offset, 'eventType': event_type},
                        timeout=ClientTimeout(total=None, connect=60, sock_connect=60, sock_read=sock_read)
                    ) as res:
                        demisto.updateModuleHealth('')
                        buffer = b''
                        async for chunk in res.content.iter_any():
                            buffer += chunk
                            lines = buffer.splitlines(True)

                            for line in lines[:-1]:
                                stripped_line = line.decode().strip()
                                if stripped_line:
                                    events_fetched += 1
                                    try:
                                        streaming_event = json.loads(stripped_line)
                                        event_metadata = streaming_event.get('metadata', {})
                                        event_creation_time = event_metadata.get('eventCreationTime', 0)

                                        if not event_creation_time:
                                            demisto.debug('Could not extract "eventCreationTime" field, using 0 instead. '
                                                          f'{streaming_event}')
                                        else:
                                            event_creation_time /= 1000
                                        event_creation_time_dt = datetime.fromtimestamp(event_creation_time)

                                        if event_creation_time_dt < first_fetch_time:
                                            demisto.debug(
                                                f'Event with offset {event_metadata.get("offset")} '
                                                f'and creation time {event_creation_time} was skipped '
                                                f'because {first_fetch_time=}')
                                            continue
                                        yield streaming_event
                                    except json.decoder.JSONDecodeError:
                                        demisto.debug(f'Failed decoding event (skipping it) - {str(stripped_line)}')
                                else:
                                    new_lines_fetched += 1

                                if last_fetch_stats_print + timedelta(minutes=1) <= datetime.utcnow():
                                    demisto.info(
                                        f'Fetched {events_fetched} events and'
                                        f' {new_lines_fetched} new lines'
                                        f' from the stream in the last minute.')
                                    events_fetched = 0
                                    new_lines_fetched = 0
                                    last_fetch_stats_print = datetime.utcnow()
                                if last_refresh_stream + timedelta(minutes=25) <= datetime.utcnow():
                                    await self._refresh_stream()
                                    last_refresh_stream = datetime.utcnow()
                            buffer = lines[-1]
                        if buffer:
                            stripped_line = buffer.decode().strip()
                            demisto.debug(f"MISSING LINE: {stripped_line}")
            except Exception as e:
                demisto.debug(f'An error occurred in the fetch event loop: {e} - {traceback.format_exc()}. '
                              f'Going to sleep for 10 seconds and then retry. '
                              f'Container ID: {CONTAINER_ID}')
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
        demisto.debug('Setting access token')
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
        demisto.debug('Sending request to get access token')
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
                        await sleep(10)
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
            self.expiry_time = max(body.get('expires_in', MINUTES_30) - TIME_BUFFER_1_MINUTE, TIME_BUFFER_1_MINUTE)
        if not token:
            raise RuntimeError('Failed to retrieve token')
        demisto.debug('Got access token successfully')
        return token

    async def refresh_token_loop(self) -> None:
        while True:
            demisto.debug(f'Starting refresh token loop iteration, going to sleep for {self.expiry_time}')
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
        proxy: bool,
        incident_type: str,
        first_fetch_time: datetime,
        store_samples: bool = False,
        sock_read: int = 120,
) -> None:
    """Connects to a CrowdStrike Falcon stream and fetches events from it in a loop.

    Args:
        base_url (str): CrowdStrike Falcon Cloud base URL.
        client_id (str): CrowdStrike Falcon application ID.
        client_secret (str): CrowdStrike Falcon application secret.
        stream (EventStream): CrowdStrike Falcon stream to fetch events from.
        offset (int): Stream offset to start the fetch from.
        event_type (str): Stream event type to fetch.
        verify_ssl (bool): Whether the request should verify the SSL certificate or not.
        proxy (bool): Whether to run the integration using the system proxy or not.
        incident_type (str): Type of incident to create.
        store_samples (bool): Whether to store sample events in the integration context or not.
        first_fetch_time (datetime): The start time to fetch from retroactively for the first fetch.
        sock_read (int) Client session sock read timeout.

    Returns:
        None: No data returned.
    """
    try:
        offset_to_store = offset
        sample_events_to_store = deque(maxlen=20)  # type: ignore[var-annotated]
        async with init_refresh_token(base_url, client_id, client_secret, verify_ssl, proxy) as refresh_token:
            stream.set_refresh_token(refresh_token)
            demisto.debug('Finished initializing refresh token, starting fetch events loop')
            async for event in stream.fetch_event(
                    first_fetch_time=first_fetch_time, initial_offset=offset, event_type=event_type, sock_read=sock_read
            ):
                event_metadata = event.get('metadata', {})
                event_type = event_metadata.get('eventType', '')
                event_offset = event_metadata.get('offset', '')
                demisto.info(f'Fetching event with offset: {event_offset}')
                incident_name = f'{event_type} - offset {event_offset}'
                event_creation_time = event_metadata.get('eventCreationTime', 0)
                occurred = datetime.fromtimestamp(event_creation_time / 1000).strftime('%Y-%m-%dT%H:%M:%SZ')
                event_dump = json.dumps(event)
                incident = [{
                    'name': incident_name,
                    'details': event_dump,
                    'rawJSON': event_dump,
                    'type': incident_type,
                    'occurred': occurred
                }]
                demisto.createIncidents(incident)
                offset_to_store = int(event_offset) + 1
                integration_context = get_integration_context()
                integration_context['offset'] = offset_to_store
                if store_samples:
                    try:
                        event_obj_size = sys.getsizeof(event)
                        if event_obj_size <= 1000000:  # storing events of size up to 1MB
                            sample_events_to_store.append(event)
                            demisto.debug(f'Storing new {len(sample_events_to_store)} sample events')
                            sample_events = deque(json.loads(integration_context.get('sample_events', '[]')), maxlen=20)
                            sample_events += sample_events_to_store
                            integration_context['sample_events'] = list(sample_events)
                        else:
                            demisto.debug(f'Skipping event {event_offset} storage due to size {event_obj_size}')
                    except Exception as e:
                        demisto.error(f'Failed storing sample events - {e}')
                demisto.debug(f'Storing offset {offset_to_store}')
                set_to_integration_context_with_retries(integration_context)
    except Exception as e:
        demisto.error(f'An error occurred in the long running loop: {e}')
    finally:
        # store latest fetched event offset in case the loop crashes and we did not store it
        set_to_integration_context_with_retries({'offset': offset_to_store})


async def test_module(base_url: str, client_id: str, client_secret: str, verify_ssl: bool, proxy: bool) -> None:
    async with init_refresh_token(base_url, client_id, client_secret, verify_ssl, proxy) as refresh_token:
        await refresh_token.get_access_token()
        demisto.results('ok')


def fetch_samples() -> None:
    """Extracts sample events stored in the integration context and returns them as incidents

    Returns:
        None: No data returned.
    """
    integration_context = get_integration_context()
    sample_events = json.loads(integration_context.get('sample_events', '[]'))
    incidents = [{'rawJSON': json.dumps(event)} for event in sample_events]
    demisto.incidents(incidents)


def get_sample_events(store_samples: bool = False) -> None:
    """Extracts sample events stored in the integration context and returns them

    Args:
        store_samples (bool): Whether to store sample events in the integration context or not.

    Returns:
        None: No data returned.
    """
    integration_context = get_integration_context()
    sample_events = integration_context.get('sample_events')
    if sample_events:
        try:
            demisto.results(json.loads(sample_events))
        except json.decoder.JSONDecodeError as e:
            raise ValueError(f'Failed deserializing sample events - {e}')
    else:
        output = 'No sample events found.'
        if not store_samples:
            output += ' The "Store sample events for mapping" integration parameter ' \
                      'need to be enabled for this command to return results.'
        demisto.results(output)


def merge_integration_context() -> None:
    """Checks whether offset is of type int and sample_events is of type list in the integration context and
    casts them to string

    Returns:
        None: No data returned.
    """
    integration_context, version = get_integration_context_with_version()
    should_update_integration_context = False
    offset = integration_context.get('offset')
    if isinstance(offset, int):
        integration_context['offset'] = str(offset)
        should_update_integration_context = True
    sample_events = integration_context.get('sample_events')
    if isinstance(sample_events, list):
        integration_context['sample_events'] = json.dumps(sample_events)
        should_update_integration_context = True
    if should_update_integration_context:
        set_integration_context(integration_context, version)


def main():
    params: dict = demisto.params()
    base_url: str = params.get('base_url', '')
    client_id: str = params.get('credentials_client', {}).get('identifier') or params.get('client_id', '')
    client_secret: str = params.get('credentials_client', {}).get('password') or params.get('client_secret', '')
    if not (client_id and client_secret):
        raise DemistoException('Client ID and Client Secret must be provided.')
    event_type = ','.join(params.get('event_type', []) or [])
    verify_ssl = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    offset = params.get('offset', '0')
    try:
        offset = int(offset)
    except ValueError:
        offset = 0
    incident_type = params.get('incidentType', '')
    store_samples = params.get('store_samples', False)
    first_fetch_time, _ = parse_date_range(params.get('fetch_time', '1 hour'))
    app_id = params.get('app_id') or 'Demisto'
    if not re.match(r'^[A-Za-z0-9]{0,32}$', app_id):
        raise ValueError('App ID is invalid: Must be a max. of 32 alphanumeric characters (a-z, A-Z, 0-9).')
    sock_read = int(params.get('sock_read_timeout', 120))

    stream = EventStream(base_url=base_url, app_id=app_id, verify_ssl=verify_ssl, proxy=proxy)

    LOG(f'Command being called is {demisto.command()}')
    try:
        merge_integration_context()
        if demisto.command() == 'test-module':
            run(test_module(base_url, client_id, client_secret, verify_ssl, proxy))
        elif demisto.command() == 'long-running-execution':
            run(long_running_loop(
                base_url, client_id, client_secret, stream, offset, event_type, verify_ssl, proxy, incident_type,
                first_fetch_time, store_samples, sock_read
            ))
        elif demisto.command() == 'fetch-incidents':
            fetch_samples()
        elif demisto.command() == 'crowdstrike-falcon-streaming-get-sample-events':
            get_sample_events(store_samples)
    except Exception as e:
        error_msg = f'Error in CrowdStrike Falcon Streaming v2: {str(e)}'
        demisto.error(error_msg)
        demisto.updateModuleHealth(error_msg)
        return_error(error_msg)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
