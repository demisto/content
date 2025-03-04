import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


from CommonServerUserPython import *  # noqa
import asyncio
import concurrent
import aiohttp
import urllib3
from typing import Any
from urllib.parse import urlparse

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
DEFAULT_PAGE_NUMBER = 0
DEFAULT_PAGE_SIZE = 50
DEFAULT_LIMIT = 50
PLAYGROUND_INVESTIGATION_TYPE = 9
SECRET_TOKEN: str
BASE_URL: str
PROXY = False
VERIFY = False
SSL_CONTEXT: Optional[ssl.SSLContext]
PROXIES = {}
PROXY_URL: str
DEMISTO_URL: str
WEBSOCKET_URL: str
MAX_SAMPLES = 10
INCIDENT_TYPE: str
ALLOW_INCIDENTS: bool
PORT: int
MIRRORING_ENABLED: bool
LONG_RUNNING: bool
CACHED_INTEGRATION_CONTEXT: dict
VERIFY_CERT: bool
CACHE_EXPIRY: float
MESSAGE_FOOTER = '\n**From Mattermost**'
MIRROR_TYPE = 'mirrorEntry'
OBJECTS_TO_KEYS = {
    'mirrors': 'investigation_id',
    'messages': 'entitlement',
}
DEFAULT_OPTIONS: Dict[str, Any] = {
    "timeout": 100,
    "request_timeout": None,
    "mfa_token": None,
    "auth": None,
    "keepalive": False,
    "keepalive_delay": 5,
    "websocket_kw_args": {},
    "debug": False,
    "http2": False,
}
GUID_REGEX = r'(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}'
ENTITLEMENT_REGEX = fr'{GUID_REGEX}@(({GUID_REGEX})|(?:[\d_]+))_*(\|\S+)?\b'
PERMITTED_NOTIFICATION_TYPES: list[str]
INCIDENT_NOTIFICATION_CHANNEL = 'incidentNotificationChannel'
''' CLIENT CLASS '''


class WebSocketClient:  # pragma: no cover
    def __init__(
        self,
        base_url: str,
        token: str,
        verify: bool,
        proxy: bool
    ):
        self.base_url = base_url
        self.token = token
        self.alive = False
        self.last_msg = 0.0
        self.verify = verify
        self.proxy = proxy
        self.options = DEFAULT_OPTIONS.copy()

    async def connect(self, event_handler):
        """
        Connect to the websocket and authenticate it.
        When the authentication has finished, start the loop listening for messages,
        sending a ping to the server to keep the connection alive.

        :param event_handler: Every websocket event will be passed there. Takes one argument.
        :type event_handler: Function(message)
        :return:
        """
        if 'https://' in self.base_url:
            uri = self.base_url.replace("https://", "wss://", 1)
        else:
            uri = self.base_url.replace("http://", "ws://", 1)
        uri += '/api/v4/websocket'
        url = self.base_url + '/api/v4/websocket'
        demisto.debug(f'MM: The uri for the websocket is {uri}, the url is {url}')

        self.alive = True

        while True:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.ws_connect(
                        uri,
                        ssl=SSL_CONTEXT,  # type: ignore[arg-type]
                        proxy=PROXY_URL,
                    ) as websocket:
                        demisto.debug('MM: starting to authenticate')
                        await self.authenticate(websocket, event_handler)
                        while self.alive:
                            try:
                                await self.start_loop(websocket, event_handler)
                            except aiohttp.ClientError:
                                break
                        if (not self.options["keepalive"]) or (not self.alive):
                            break
            except Exception as e:
                demisto.info(f"MM: Failed to establish websocket connection: {type(e)} thrown - {str(e)}")
                await asyncio.sleep(float("inf"))

    async def start_loop(self, websocket, event_handler):
        """
        We will listen for websockets events, sending a heartbeats on a timer.
        If we don't the webserver would close the idle connection,
        forcing us to reconnect.
        """
        demisto.debug("MM: Starting websocket loop")
        keep_alive = asyncio.ensure_future(self.heartbeat(websocket))
        demisto.debug("MM: Waiting for messages on websocket")
        while self.alive:
            message = await websocket.receive_str()
            self.last_msg = time.time()
            demisto.debug(f"MM: {message=}")
            await event_handler(self, message)
        demisto.debug("MM: Cancelling heartbeat task")
        keep_alive.cancel()
        try:
            await keep_alive
        except asyncio.CancelledError:
            pass

    async def heartbeat(self, websocket):
        """
        Pongs the server if did not get a message within the timeframe
        """
        timeout: float = self.options["timeout"]
        while True:
            since_last_msg: float = time.time() - self.last_msg
            next_timeout: float = timeout - since_last_msg if since_last_msg <= timeout else timeout
            await asyncio.sleep(next_timeout)
            if time.time() - self.last_msg >= timeout:
                await websocket.pong()
                self.last_msg = time.time()

    def disconnect(self):
        """Sets `self.alive` to False so the loop in `self.start_loop` will finish."""
        demisto.debug("Disconnecting websocket")
        self.alive = False

    async def authenticate(self, websocket, event_handler):
        """
        Sends a authentication challenge over a websocket.
        """
        demisto.debug("MM: Authenticating websocket")
        json_data = json.dumps({"seq": 1, "action": "authentication_challenge", "data": {"token": self.token}})
        await websocket.send_str(json_data)
        while True:
            message = await websocket.receive_str()
            status = json.loads(message)
            demisto.debug(f"MM: The status is: {status}")
            await event_handler(self, message)
            if ("event" in status and status["event"] == "hello") and ("seq" in status and status["seq"] == 0):
                demisto.debug("MM: Websocket authentification OK")
                return True
            demisto.error("MM: Websocket authentification failed")


class HTTPClient(BaseClient):
    """Client class to interact with the MatterMost API
    """

    def __init__(
        self,
        base_url: str,
        headers: dict,
        personal_access_token: str,
        bot_access_token: str,
        team_name: str,
        notification_channel: str | None = None,
        verify: bool = True,
        proxy: bool = False,
    ):
        super().__init__(base_url, verify, proxy, headers=headers)
        self.bot_access_token = bot_access_token
        self.personal_access_token = personal_access_token
        self.team_name = team_name
        self.notification_channel = notification_channel

    def get_team_request(self, team_name: str) -> dict[str, str]:
        """Gets a team details based on its name"""
        response = self._http_request(method='GET', url_suffix=f'/api/v4/teams/name/{team_name}')

        return response

    def list_channel_request(self, team_id: str, params: dict, get_private: bool = False) -> list[dict[str, Any]]:
        """lists channels in a specific team"""
        if get_private:
            response = self._http_request(method='GET', url_suffix=f'/api/v4/teams/{team_id}/channels/private', params=params)
        else:
            response = self._http_request(method='GET', url_suffix=f'/api/v4/teams/{team_id}/channels', params=params)

        return response

    def list_channels_for_user_request(self, team_id: str, user: str) -> list[dict[str, Any]]:
        """lists channels by user in a specific team"""
        response = self._http_request(method='GET', url_suffix=f'/api/v4/users/{user}/teams/{team_id}/channels/members')

        return response

    def create_channel_request(self, params: dict) -> dict[str, str]:
        """Creates a channel"""
        response = self._http_request(method='POST', url_suffix='/api/v4/channels', json_data=params)

        return response

    def get_channel_by_name_and_team_name_request(self, team_name: str, channel_name: str) -> dict[str, Any]:
        """Gets a channel based on name and team name"""
        response = self._http_request(method='GET', url_suffix=f'/api/v4/teams/name/{team_name}/channels/name/{channel_name}')

        return response

    def set_channel_role_request(self, channel_id: str, user_id: str, roles: str) -> dict[str, str]:
        """Set a channel role for channel member"""
        data = {"roles": roles}
        response = self._http_request(
            method='PUT', url_suffix=f'/api/v4/channels/{channel_id}/members/{user_id}/roles', json_data=data)

        return response

    def add_channel_member_request(self, channel_id: str, data: dict) -> dict[str, str]:
        """Adds a channel member"""
        response = self._http_request(method='POST', url_suffix=f'/api/v4/channels/{channel_id}/members', json_data=data)

        return response

    def remove_channel_member_request(self, channel_id: str, user_id: str) -> dict[str, str]:
        """Removes a channel member"""
        response = self._http_request(method='DELETE', url_suffix=f'/api/v4/channels/{channel_id}/members/{user_id}')

        return response

    def list_users_request(self, params: dict) -> list[dict[str, Any]]:
        """lists users"""
        response = self._http_request(method='GET', url_suffix='/api/v4/users', params=params)

        return response

    def close_channel_request(self, channel_id: str) -> list[dict[str, Any]]:
        """Closes a channel"""
        response = self._http_request(method='DELETE', url_suffix=f'/api/v4/channels/{channel_id}')

        return response

    def send_file_request(self, file_info: dict, params: dict) -> dict[str, Any]:
        "Sends a file"
        files = {'file': (file_info['name'], open(file_info['path'], 'rb'))}

        response = self._http_request(
            method='POST',
            url_suffix='/api/v4/files',
            files=files,
            params=params,
            json_data={'channel_id': params.get('channel_id')}
        )
        return response

    def create_post_with_file_request(self, data: dict) -> list[dict[str, Any]]:
        """Creates a post with a file request"""
        response = self._http_request(method='POST', url_suffix='/api/v4/posts', json_data=data)

        return response

    def update_channel_request(self, channel_id: str, params: dict) -> list[dict[str, Any]]:
        """Updates a channel"""
        response = self._http_request(method='PUT', url_suffix=f'/api/v4/channels/{channel_id}', json_data=params)

        return response

    def get_user_request(self, user_id: str = '', bot_user: bool = False) -> dict[str, Any]:
        """Gets a user"""
        if not user_id:
            user_id = 'me'
        if bot_user:
            response = self._http_request(method='GET', url_suffix=f'/api/v4/users/{user_id}',
                                          headers={'authorization': f'Bearer {self.bot_access_token}'})
        else:
            response = self._http_request(method='GET', url_suffix=f'/api/v4/users/{user_id}')

        return response

    def send_notification_request(self, channel_id: str, message: str, file_ids: list[str] = [], root_id: str = '', props: dict = {}) -> dict[str, Any]:  # noqa: E501
        "Sends a notification"
        data = {"channel_id": channel_id,
                "message": message,
                "props": props,
                "root_id": root_id,
                "file_ids": file_ids,
                }
        remove_nulls_from_dictionary(data)
        response = self._http_request(method='POST', url_suffix='/api/v4/posts', json_data=data,
                                      headers={'authorization': f'Bearer {self.bot_access_token}'})

        return response

    def update_post_request(self, message: str, root_id: str) -> dict[str, Any]:  # noqa: E501
        "Sends a notification"
        data = {
            "message": message,
            "id": root_id,
        }
        demisto.debug(f"MM: {data=}")
        remove_nulls_from_dictionary(data)
        response = self._http_request(method='PUT', url_suffix=f'/api/v4/posts/{root_id}', json_data=data,
                                      headers={'authorization': f'Bearer {self.bot_access_token}'})

        demisto.debug(f"MM: response fom update message. {response=}")
        return response

    def get_user_by_email_request(self, user_email: str) -> dict[str, Any]:
        "Gets a user by email"
        response = self._http_request(method='GET', url_suffix=f'/api/v4/users/email/{user_email}')

        return response

    def get_user_by_username_request(self, username: str) -> dict[str, Any]:
        "Gets a user by username"
        response = self._http_request(method='GET', url_suffix=f'/api/v4/users/username/{username}')

        return response

    def create_direct_channel_request(self, user_id: list, bot_id: str) -> dict[str, Any]:
        "creates a direct channel"
        user_id.append(bot_id)
        url_suffix = '/api/v4/channels/direct' if len(user_id) == 2 else '/api/v4/channels/group'
        response = self._http_request(method='POST', url_suffix=url_suffix, json_data=user_id)

        return response

    def list_groups_request(self, params: dict) -> list[dict[str, Any]]:
        """lists groups in a specific team"""
        response = self._http_request(method='GET', url_suffix='/api/v4/groups', params=params)

        return response

    def list_group_members_request(self, group_id: str) -> dict[str, Any]:
        """list group members based on group id and team name"""
        response = self._http_request(method='GET', url_suffix=f'/api/v4/groups/{group_id}/members')

        return response

    def add_group_member_request(self, group_id: str, data: dict) -> dict[str, str]:
        """Adds a group member"""
        response = self._http_request(method='POST', url_suffix=f'/api/v4/groups/{group_id}/members', json_data=data)

        return response

    def remove_group_member_request(self, group_id: str, data: dict) -> dict[str, str]:
        """Removes a group member"""
        response = self._http_request(method='DELETE', url_suffix=f'/api/v4/groups/{group_id}/members', json_data=data)

        return response


CLIENT: HTTPClient

''' HELPER FUNCTIONS '''


def get_war_room_url(url: str, incident_id: str = '') -> str:
    # a workaround until this bug is resolved: https://jira-dc.paloaltonetworks.com/browse/CRTX-107526
    if is_xsiam():
        if not incident_id:
            incident_id = demisto.callingContext.get('context', {}).get('Inv', {}).get('id')
        incident_url = urlparse(url)
        war_room_url = f"{incident_url.scheme}://{incident_url.netloc}/incidents"
        # executed from the incident War Room
        if incident_id and incident_id.startswith('INCIDENT-'):
            war_room_url += f"/war_room?caseId={incident_id.split('-')[-1]}"
        # executed from the alert War Room
        else:
            war_room_url += f"/alerts_and_insights?caseId={incident_id}&action:openAlertDetails={incident_id}-warRoom"

        return war_room_url

    return url


def next_expiry_time() -> float:
    """
    Returns:
        A float representation of a new expiry time with an offset of 5 seconds
    """
    return (datetime.now(timezone.utc) + timedelta(seconds=5)).timestamp()


def get_current_utc_time() -> datetime:
    """
    Returns:
        The current UTC time.
    """
    return datetime.utcnow()


async def check_and_handle_entitlement(answer_text: str, root_id: str, user_name: str) -> str:  # pragma: no cover
    """
    Handles an entitlement message (a reply to a question)
    Args:
    Returns:
        If the message contains entitlement, return a reply.
    """
    integration_context = fetch_context(force_refresh=True)
    messages = integration_context.get('messages', [])
    reply = ''
    if not messages:
        return reply
    messages = json.loads(messages)
    demisto.debug(f"MM: messages with entitlements. {messages=}")
    message_filter = list(filter(lambda q: q.get('root_id') == root_id, messages))
    if message_filter:
        demisto.debug("MM: Found correct message")
        message = message_filter[0]
        entitlement = message.get('entitlement')
        reply = message.get('reply')
        guid, incident_id, task_id = extract_entitlement(entitlement)
        demisto.handleEntitlementForUser(incident_id, guid, user_name, answer_text, task_id)
        demisto.debug(f"MM: Handled entitlement for {incident_id=}, {task_id=} with {answer_text=}")
        message['remove'] = True
        set_to_integration_context_with_retries({'messages': messages}, OBJECTS_TO_KEYS)
    return reply


def run_long_running():  # pragma: no cover
    """
    Starts the long running thread.
    """
    try:
        asyncio.run(start_listening())
    except Exception as e:
        demisto.error(f"MM: The Loop has failed to run {str(e)}")
    finally:
        loop = asyncio.get_running_loop()
        try:
            loop.stop()
            loop.close()
        except Exception as e_:
            demisto.error(f'MM: Failed to gracefully close the loop - {e_}')


async def start_listening():  # pragma: no cover
    """
    Starts a Slack SocketMode client and checks for mirrored incidents.
    """
    try:
        demisto.debug('MM: Starting to listen')
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_in_executor(executor, long_running_loop)
        await mattermost_loop()
    except Exception as e:
        demisto.error(f"An error has occurred while gathering the loop tasks. {e}")


async def mattermost_loop():  # pragma: no cover

    try:
        exception_await_seconds = 1
        while True:
            ws_client = WebSocketClient(BASE_URL, SECRET_TOKEN, VERIFY, PROXY)

            try:
                demisto.debug('MM: Trying to connect')
                await ws_client.connect(event_handler)
                # After successful connection, we reset the backoff time.
                exception_await_seconds = 1
                await asyncio.sleep(float("inf"))
            except Exception as e:
                demisto.debug(f"MM: Exception in long running loop, waiting {exception_await_seconds} - {e}")
                await asyncio.sleep(exception_await_seconds)
                exception_await_seconds *= 2
            finally:
                try:
                    ws_client.disconnect()
                except Exception as e:
                    demisto.debug(f"MM: Failed to close client. - {e}")
    except Exception as e:
        demisto.error(f"MM: An error has occurred while trying to create the socket client. {e}")


def long_running_loop():  # pragma: no cover
    global MIRRORING_ENABLED
    tts = 30 if MIRRORING_ENABLED else 60
    while True:
        error = ''
        try:
            check_for_unanswered_messages()
            time.sleep(tts)
        except requests.exceptions.ConnectionError as e:
            error = f'Could not connect to the MatterMost endpoint: {str(e)}'
        except Exception as e:
            error = f'An error occurred: {e}'
        finally:
            demisto.updateModuleHealth('')
            if error:
                demisto.error(error)
                demisto.updateModuleHealth(error)


def check_for_unanswered_messages():
    integration_context = fetch_context()
    messages = integration_context.get('messages')
    if messages:
        messages = json.loads(messages)
        now = datetime.utcnow()
        updated_messages = []

        for message in messages:
            if message.get('expiry'):
                # Check if the question expired - if it did, answer it with the default response
                # and remove it
                expiry = datetime.strptime(message['expiry'], DATE_FORMAT)
                if expiry < now:
                    demisto.debug(f"MM: message expired: {message}, answering it with the default response")
                    answer_question(message.get('default_response'), message, email='')
                    message['remove'] = True
                    updated_messages.append(message)
                    continue
            updated_messages.append(message)

        if updated_messages:

            set_to_integration_context_with_retries({'messages': messages}, OBJECTS_TO_KEYS)


async def event_handler(client: WebSocketClient, req: str):
    """Handling the events coming from the websocket"""
    demisto.debug(f"MM: Got events: {req} - with type {type(req)}")
    payload = json.loads(req)

    if 'error' in payload:
        error = payload.get('error', {})
        error_code = error.get('id')
        error_msg = error.get('message')
        await handle_listen_error(
            f'MatterMost API has thrown an error. Code: {error_code}, Message: {error_msg}.')
        return

    if payload.get('event') == 'hello' or payload.get('seq_reply') == 1:
        # we handle hello and authentication events afterwards
        return

    if payload.get('event') == 'posted':
        await handle_posts(payload)
        return


def is_bot_message(payload: dict) -> bool:
    """
    Determines if the message received was created by a bot or not.
    :param payload: dict: The payload sent with the message
    :return: bool: True indicates the message was from a Bot, False indicates it was from an individual
    """
    global CLIENT
    from_bot = payload.get('props', {}).get('from_bot', '')
    bot_id = get_user_id_from_token(CLIENT, bot_user=True)
    post = json.loads(payload.get("data", {}).get("post"))

    if bot_id and bot_id == post.get('user_id', ''):
        return True
    elif from_bot:
        return True
    return False


def is_dm(payload: dict):
    """
    Takes the channel type and will see if it's 'D'. If so, we know it's from a direct message.
    :param channel: str: The channel ID to check.
    :return: bool: Boolean indicating if the channel is a DM or not.
    """
    channel_type = payload.get('data', {}).get('channel_type')
    return channel_type == 'D'


def is_thread(post: dict):
    """
    Takes the root ID and will see if its not empty. If so, we know it's from a direct message.
    :param post: str: The post to check.
    :return: bool: Boolean indicating if the post is part of a thread or not.
    """
    root_id = post.get('root_id', '')
    return root_id != ''


def get_user_id_from_token(client: HTTPClient, bot_user: bool = False) -> str:
    """
    Gets the user id from the token
    :return: str: The id of the user
    """
    result = client.get_user_request(bot_user=bot_user)

    return result.get('id', '')


def get_user_id_by_email(client: HTTPClient, email: str) -> str:
    """
    Gets a user ID from the email
    :param email: str: The email of the user
    :return: str: The id of the user
    """
    result = client.get_user_by_email_request(email)
    return result.get('id', '')


def get_user_id_by_username(client: HTTPClient, username: str) -> str:
    """
    Gets a user ID from the email
    :param email: str: The email of the user
    :return: str: The id of the user
    """
    result = client.get_user_by_username_request(username)
    return result.get('id', '')


def get_username_by_email(client: HTTPClient, email: str) -> str:
    """
    Gets a username from the email
    :param email: str: The email of the user
    :return: str: The username of the user
    """
    result = client.get_user_by_email_request(email)
    return result.get('username', '')


def get_username_by_id(client: HTTPClient, user_id: str) -> str:
    """
    Gets a username from the id
    :param email: str: The email of the user
    :return: str: The username of the user
    """
    result = client.get_user_request(user_id)
    return result.get('username', '')


def get_team_id_from_team_name(client: HTTPClient, team_name: str):
    """
    Gets a id from the team_name
    :param email: str: The email of the user
    :return: str: The username of the user
    """
    result = client.get_team_request(team_name)
    return result.get('id', '')


def fetch_context(force_refresh: bool = False) -> dict:
    """
    Fetches the integration instance context from the server if the CACHE_EXPIRY is smaller than the current epoch time
    In the event that the cache is not expired, we return a cached copy of the context which has been stored in memory.
    We can force the retrieval of the updated context by setting the force_refresh flag to True.
    :param force_refresh: bool: Indicates if the context should be refreshed regardless of the expiry time.
    :return: dict: Either a cached copy of the integration context, or the context itself.
    """
    global CACHED_INTEGRATION_CONTEXT, CACHE_EXPIRY
    now = int(datetime.now(timezone.utc).timestamp())
    if (now >= CACHE_EXPIRY) or force_refresh:
        demisto.debug(f'Cached context has expired or forced refresh. forced refresh value is {force_refresh}. '
                      'Fetching new context')
        CACHE_EXPIRY = next_expiry_time()
        CACHED_INTEGRATION_CONTEXT = get_integration_context()

    return CACHED_INTEGRATION_CONTEXT


def get_channel_id_from_context(channel_name: str = '', investigation_id=None):
    """
    Retrieves a MatterMost channel ID based on the provided criteria.

    :param channel_name: The name of the channel to get the ID for.
    :param investigation_id: The Demisto investigation ID to search for a mirrored channel.

    :return: The requested channel ID or None if not found.
    """
    if not channel_name and not investigation_id:
        return None
    integration_context = fetch_context()
    mirrors = json.loads(integration_context.get('mirrors', '[]'))

    # Filter mirrors based on the provided criteria.
    if investigation_id:
        mirrored_channel_filter = next((m for m in mirrors if m["investigation_id"] == investigation_id), None)
    else:
        mirrored_channel_filter = next((m for m in mirrors if m["channel_name"] == channel_name), None)
    if mirrored_channel_filter:
        return mirrored_channel_filter.get('channel_id')
    return None


def get_channel_id_to_send_notif(client: HTTPClient, to: list, channel_name: str | None, investigation_id: str) -> str:
    """
    Gets a channel ID for the correct channel to send the notification to
    :return: str: The channel id of the channel
    """
    channel_id = ''
    if to:
        # resolve users to list
        users = []
        for user in to:
            if re.match(emailRegex, user):
                uid = get_user_id_by_email(client, user)
            else:
                uid = get_user_id_by_username(client, user)
            users.append(uid)

        bot_id = get_user_id_from_token(client, bot_user=True)
        channel_object = client.create_direct_channel_request(users, bot_id)
        channel_id = channel_object.get('id', '')
        demisto.debug(f'MM: Created a new direct channel to: {users} with channel_id: {channel_id}')

    elif channel_name:  # if channel name provided and the channel was mirrored
        channel_id = get_channel_id_from_context(channel_name, investigation_id)

        if not channel_id:
            try:
                channel_details = client.get_channel_by_name_and_team_name_request(client.team_name, channel_name)
                channel_id = channel_details.get('id', '')
            except Exception as e:
                if channel_name == INCIDENT_NOTIFICATION_CHANNEL:
                    try:
                        demisto.debug(f'MM: Creating a {INCIDENT_NOTIFICATION_CHANNEL} channel to send notification to.')
                        params = {'team_id': get_team_id_from_team_name(client, client.team_name),
                                  'name': INCIDENT_NOTIFICATION_CHANNEL.lower(),
                                  'display_name': INCIDENT_NOTIFICATION_CHANNEL,
                                  'type': "O"}
                        channel_details = client.create_channel_request(params)
                        channel_id = channel_details.get('id', '')
                    except Exception as sec_e:
                        if 'Channel does not exist.' in str(sec_e):
                            hr = 'Could not create a new channel. An archived channel with the same name may exist' \
                                'in the provided team, choose a different name.'
                            raise DemistoException(hr)
                        else:
                            raise sec_e
                else:
                    raise DemistoException(
                        f"Did not find channel with name {channel_name}. Make sure it exists or choose a "
                        f"different one to send notifications to. Error: {e}")

    return channel_id


def save_entitlement(entitlement, message_id, reply, expiry, default_response, to_id):
    """
    Saves an entitlement

    Args:
        entitlement: The entitlement
        message_id: The message_id
        reply: The reply to send to the user.
        expiry: The question expiration date.
        default_response: The response to send if the question times out.
        to_id: the user id the message was sent to
    """
    integration_context = get_integration_context()
    messages = integration_context.get('messages', [])
    if messages:
        messages = json.loads(integration_context['messages'])
    messages.append({
        'root_id': message_id,
        'entitlement': entitlement,
        'reply': reply,
        'expiry': expiry,
        'sent': datetime.strftime(datetime.utcnow(), DATE_FORMAT),
        'default_response': default_response,
        'to_id': to_id
    })
    set_to_integration_context_with_retries({'messages': messages}, OBJECTS_TO_KEYS)


def extract_entitlement(entitlement: str) -> tuple[str, str, str]:
    """
    Extracts entitlement components from an entitlement string
    Args:
        entitlement: The entitlement itself

    Returns:
        Entitlement components
    """
    parts = entitlement.split('@')
    if len(parts) < 2:
        raise DemistoException("Entitlement cannot be parsed")
    guid = parts[0]
    id_and_task = parts[1].split('|')
    incident_id = id_and_task[0]
    task_id = ''

    if len(id_and_task) > 1:
        task_id = id_and_task[1]

    return guid, incident_id, task_id


def answer_question(text: str, message: dict, email: str = ''):
    """Answers a question from MattermostAskUser
    """
    global CLIENT
    entitlement = message.get('entitlement', '')
    root_id = message.get('root_id', '')
    guid, incident_id, task_id = extract_entitlement(entitlement)
    try:
        demisto.handleEntitlementForUser(incident_id, guid, email, text, task_id)
        process_entitlement_reply(text, root_id)
        demisto.debug(f"MM: Handled question for {incident_id=}, {task_id=} with {text=}")
    except Exception as e:
        demisto.error(f'Failed handling entitlement {entitlement}: {str(e)}')
    message['remove'] = True
    return incident_id


async def send_notification_async(client: HTTPClient, channel_id, message, root_id=''):
    client.send_notification_request(channel_id, message, root_id=root_id)


async def update_post_async(client: HTTPClient, message, root_id):
    client.update_post_request(message, root_id)


def process_entitlement_reply(  # pragma: no cover
    entitlement_reply: str,
    root_id: str = '',
    user_name: str | None = None,
    answer_text: str | None = None,
):
    """
    Triggered when an entitlement reply is found, this function will update the original message with the reply message.
    :param entitlement_reply: str: The text to update the asking question with.
    :param user_name: str: name of the user who answered the entitlement
    :param answer_text: str: The text attached to the button, used for string replacement.
    :return: None
    """
    global CLIENT
    if '{user}' in entitlement_reply:
        entitlement_reply = entitlement_reply.replace('{user}', str(user_name))
    if '{response}' in entitlement_reply and answer_text:
        entitlement_reply = entitlement_reply.replace('{response}', str(answer_text))
    demisto.debug(f'MM: process entitlement reply with {entitlement_reply} for {root_id}')
    CLIENT.update_post_request(entitlement_reply, root_id)


async def handle_text_received_from_mm(investigation_id: str, text: str, operator_email: str, operator_name: str):
    """
    Handles text received from MatterMost

    Args:
        investigation_id: The mirrored investigation ID
        text: The received text
        operator_email: The sender email
        operator_name: The sender name
    """
    if text:
        demisto.addEntry(id=investigation_id,
                         entry=text,
                         username=operator_name,
                         email=operator_email,
                         footer=MESSAGE_FOOTER
                         )


async def handle_posts(payload):
    """
    handle posts from the Mattermost that have been identified as possible mirrored messages
    If we find one, we will update the mirror object and send
    the message to the corresponding investigation's war room as an entry.
    :param payload: str: The request payload from mattermost
    :return: None
    """
    global CLIENT
    post = json.loads(payload.get("data", {}).get("post"))
    message = post.get('message', {})
    channel_id = post.get("channel_id")
    user_id = post.get('user_id')
    if not channel_id:
        return

    if is_bot_message(payload):
        demisto.debug("MM: Got a bot message. Will not mirror.")
        return

    # If a thread, we will check if it is a reply to a MattermostAsk task.
    if is_thread(post):
        demisto.debug(f"MM: Got a thread message. {payload=}")
        username = get_username_by_id(CLIENT, user_id)
        answer_text = post.get('message', '')
        root_id = post.get('root_id', '')
        entitlement_reply = await check_and_handle_entitlement(answer_text, root_id, username)
        demisto.debug(f"MM: Got {entitlement_reply=}")
        if entitlement_reply:
            process_entitlement_reply(entitlement_reply, root_id, username, answer_text)

        reset_listener_health()
        return

    # Check if the message is being sent directly to our bot.
    if is_dm(payload):
        demisto.debug(f"MM: Got a dm message. {payload=}")
        await handle_dm(user_id, message, channel_id, CLIENT)
        reset_listener_health()
        return

    integration_context = fetch_context()
    if not integration_context or 'mirrors' not in integration_context:
        return
    mirrors = json.loads(integration_context['mirrors'])
    mirror_filter = list(filter(lambda m: m['channel_id'] == channel_id, mirrors))

    if not mirror_filter:
        return
    for mirror in mirror_filter:
        if mirror['mirror_direction'] == 'FromDemisto' or mirror['mirror_type'] == 'none':
            return
        if not mirror['mirrored']:
            # In case the investigation is not mirrored yet
            mirror = mirrors.pop(mirrors.index(mirror))
            if mirror['mirror_direction'] and mirror['mirror_type']:
                investigation_id = mirror['investigation_id']
                mirror_type = mirror['mirror_type']
                auto_close = mirror['auto_close']
                direction = mirror['mirror_direction']
                demisto.mirrorInvestigation(investigation_id,
                                            f'{mirror_type}:{direction}', auto_close)
                mirror['mirrored'] = True
                mirrors.append(mirror)
                set_to_integration_context_with_retries({'mirrors': mirrors},
                                                        OBJECTS_TO_KEYS)

        user_details = CLIENT.get_user_request(user_id)
        operator_name = user_details.get('username', '')
        operator_email = user_details.get('email', '')
        investigation_id = mirror['investigation_id']
        await handle_text_received_from_mm(investigation_id, message, operator_email, operator_name)


async def handle_listen_error(error: str):
    """
    Logs an error and updates the module health accordingly.

    Args:
        error: The error string.
    """
    demisto.error(error)
    demisto.updateModuleHealth(error)


async def handle_dm(user_id: str, text: str, channel_id: str, client: HTTPClient):
    """
    Handles a direct message sent to the bot

    Args:
        user: The user who sent the message
        text: The message text
        client: The Slack client

    Returns:
        Text to return to the user
    """
    message: str = text.lower()
    user_details = client.get_user_request(user_id)
    user_name = user_details.get('username', '')
    user_email = user_details.get('email', '')
    if message.find('incident') != -1 and (message.find('create') != -1
                                           or message.find('open') != -1
                                           or message.find('new') != -1):

        demisto_user = demisto.findUser(email=user_email) if user_email else demisto.findUser(username=user_name)

        if not demisto_user and not ALLOW_INCIDENTS:
            data = 'You are not allowed to create incidents.'
        else:
            try:
                data = await translate_create(text, user_name, user_email, demisto_user)
            except Exception as e:
                data = f'Failed creating incidents: {str(e)}'
    else:
        try:
            data = demisto.directMessage(text, user_name, user_email, ALLOW_INCIDENTS)
        except Exception as e:
            data = str(e)

    if not data:
        data = 'Sorry, I could not perform the selected operation.'

    await send_notification_async(client, channel_id, data)


async def translate_create(message: str, user_name: str, user_email: str, demisto_user: dict) -> str:  # pragma: no cover
    """
    Processes an incident creation message
    Args:
        message: The creation message
        user_name: The name of the user in Slack
        user_email: The email of the user in Slack
        demisto_user: The demisto user associated with the request (if exists)

    Returns:
        Creation result
    """
    json_pattern = r'(?<=json=).*'
    name_pattern = r'(?<=name=).*'
    type_pattern = r'(?<=type=).*'
    message = message.replace("\n", '').replace('`', '')
    json_match = re.search(json_pattern, message)
    created_incident = None
    data = ''
    user_demisto_id = ''
    request_fields = {'ReporterEmail': user_email, 'Message': message}
    incidents = []
    if demisto_user:
        user_demisto_id = demisto_user.get('id', '')

    if json_match:
        if re.search(name_pattern, message) or re.search(type_pattern, message):
            data = 'No other properties other than json should be specified.'
        else:
            incidents_json = json_match.group()
            incidents = json.loads(incidents_json.replace('“', '"').replace('”', '"'))
            if not isinstance(incidents, list):
                incidents = [incidents]
            add_req_data_to_incidents(incidents, request_fields)
            created_incident = await create_incidents(incidents, user_name, user_email, user_demisto_id)

            if not created_incident:
                data = 'Failed creating incidents.'
    else:
        name_match = re.search(name_pattern, message)
        if not name_match:
            data = 'Please specify arguments in the following manner: name=<name> type=[type] or json=<json>.'
        else:
            incident_name = re.sub('type=.*', '', name_match.group()).strip()
            incident_type = ''

            type_match = re.search(type_pattern, message)
            if type_match:
                incident_type = re.sub('name=.*', '', type_match.group()).strip()

            incident = {'name': incident_name}

            incident_type = incident_type or INCIDENT_TYPE
            if incident_type:
                incident['type'] = incident_type
            incidents = add_req_data_to_incidents([incident], request_fields)
            created_incident = await create_incidents([incident], user_name, user_email, user_demisto_id)
            if not created_incident:
                data = 'Failed creating incidents.'

    if created_incident:
        demisto.debug(f'Created {len(incidents)} incidents')
        update_integration_context_samples(incidents)
        if isinstance(created_incident, list):
            created_incident = created_incident[0]
        server_links = demisto.demistoUrls()
        server_link = server_links.get('server')
        incident_name = created_incident['name']
        incident_id = created_incident['id']
        incident_url = get_war_room_url(f'{server_link}#/WarRoom/{incident_id}', incident_id)
        data = f'Successfully created incident {incident_name}.\n View it on: {incident_url}'

    return data


def add_req_data_to_incidents(incidents: list, request_fields: dict) -> list:  # pragma: no cover
    """
    Adds the request_fields as a rawJSON to every created incident for further information on the incident
    """
    for incident in incidents:
        incident['rawJSON'] = json.dumps(request_fields)
    return incidents


async def create_incidents(incidents: list, user_name: str, user_email: str, user_demisto_id: str = ''):
    """
    Creates incidents according to a provided JSON object
    Args:
        incidents: The incidents JSON
        user_name: The name of the user in MatterMost
        user_email: The email of the user in MattermOST
        user_demisto_id: The id of demisto user associated with the request (if exists)

    Returns:
        The creation result
    """

    for incident in incidents:
        # Add relevant labels to context
        labels = incident.get('labels', [])
        keys = [label.get('type') for label in labels]
        if 'Reporter' not in keys:
            labels.append({'type': 'Reporter', 'value': user_name})
        if 'ReporterEmail' not in keys:
            labels.append({'type': 'ReporterEmail', 'value': user_email})
        if 'Source' not in keys:
            labels.append({'type': 'Source', 'value': 'Slack'})
        incident['labels'] = labels

    data = demisto.createIncidents(incidents, userID=user_demisto_id) if user_demisto_id else demisto.createIncidents(
        incidents)

    return data


def update_integration_context_samples(incidents: list, max_samples: int = MAX_SAMPLES):  # pragma: no cover
    """
    Updates the integration context samples with the newly created incident.
    If the size of the samples has reached `MAX_SAMPLES`, will pop out the latest sample.
    Args:
        incidents (list): The list of the newly created incidents.
        max_samples (int): Max samples size.
    """
    ctx = get_integration_context()
    updated_samples_list: List[Dict] = incidents + ctx.get('samples', [])
    ctx['samples'] = updated_samples_list[:max_samples]
    set_integration_context(ctx)


def reset_listener_health():
    demisto.updateModuleHealth("MatterMost V2 - Event handled successfully.")
    demisto.info("MatterMost V2 - Event handled successfully.")


def find_mirror_by_investigation() -> dict:
    """
    Finds a mirrored channel by the mirrored investigation

    Returns:
        The mirror object
    """
    mirror: dict = {}
    investigation = demisto.investigation()
    if investigation:
        integration_context = get_integration_context()
        if integration_context.get('mirrors'):
            mirrors = json.loads(integration_context['mirrors'])
            investigation_filter = list(filter(lambda m: investigation.get('id') == m['investigation_id'],
                                               mirrors))
            if investigation_filter:
                mirror = investigation_filter[0]

    return mirror


''' COMMAND FUNCTIONS '''


def test_module(client: HTTPClient) -> str:  # pragma: no cover
    """Tests connectivity with the client.
    """
    try:
        client.get_user_request(user_id='me', bot_user=False)  # Validating the Personal Access Token
    except Exception as e:
        demisto.debug(str(e))
        if 'Invalid or expired session, please login again.' in str(e):
            raise DemistoException('Invalid or expired session. Make sure the Personal Access Token is configured properly.')
        else:
            raise e

    try:
        client.get_user_request(user_id='me', bot_user=True)  # Validating the Bot Access Token
    except Exception as e:
        demisto.debug(str(e))
        if 'Invalid or expired session, please login again.' in str(e):
            raise DemistoException('Invalid or expired session. Make sure the Bot Access Token is configured properly.')
        else:
            raise e

    try:
        if client.notification_channel and client.team_name:
            # Validating the default team and channel exists
            channel_details = client.get_channel_by_name_and_team_name_request(client.team_name, client.notification_channel)
            client.send_notification_request(channel_details.get('id', ''), 'Hi there! This is a test message from XSOAR.')

    except Exception as e:
        demisto.debug(str(e))
        if 'Unable to find the existing team' in str(e):
            raise DemistoException('Could not find the team, make sure it is valid and/or exists.')
        elif 'Channel does not exist' in str(e):
            raise DemistoException('Channel does not exist or archived, choose a different channel to send notifications to')
        else:
            raise e

    return 'ok'


def get_team_command(client: HTTPClient, args: dict[str, Any]) -> CommandResults:
    """ Gets a team """
    team_name = args.get('team_name', client.team_name)

    team_details = client.get_team_request(team_name)

    hr = tableToMarkdown('Team details:', team_details, headers=['name', 'display_name', 'type', 'id'])
    return CommandResults(
        outputs_prefix='Mattermost.Team',
        outputs_key_field='name',
        outputs=team_details,
        readable_output=hr,
    )


def list_channels_command(client: HTTPClient, args: dict[str, Any]) -> CommandResults:
    """ Lists channels """
    team_name = args.get('team', client.team_name)
    include_private_channels = argToBoolean(args.get('include_private_channels', False))
    page = arg_to_number(args.get('page', DEFAULT_PAGE_NUMBER))
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE))
    limit = args.get('limit', '')
    channel_details = []
    if limit:
        page = DEFAULT_PAGE_NUMBER
        page_size = limit

    team_details = client.get_team_request(team_name)

    params = {'page': page, 'per_page': page_size}
    channel_details = client.list_channel_request(team_details.get('id', ''), params)

    if include_private_channels:
        channel_details.extend(client.list_channel_request(team_details.get('id', ''), params, get_private=True))

    hr = tableToMarkdown('Channels:', channel_details, headers=['name', 'display_name', 'type', 'id'])
    return CommandResults(
        outputs_prefix='Mattermost.Channel',
        outputs_key_field='name',
        outputs=channel_details,
        readable_output=hr,
    )


def list_private_channels_for_user_command(client: HTTPClient, args: dict[str, Any]) -> CommandResults:
    """ Lists private channels for user """
    team_name = args.get('team_name', client.team_name)
    user_id = args.get('user_id', '')
    channels = []

    team_details = client.get_team_request(team_name)

    user_channels = client.list_channels_for_user_request(team_details.get('id', ''), user_id)

    params: dict[Any, Any] = {}
    channels = client.list_channel_request(team_details.get('id', ''), params, get_private=True)
    channels = [channel for channel in channels if channel['id'] in [c['channel_id'] for c in user_channels]]

    user_details = client.get_user_request(user_id)

    hr = tableToMarkdown(f'Channels for {user_details.get("username", user_id)}:',
                         channels, headers=['name', 'display_name', 'type', 'id'])
    return CommandResults(
        outputs_prefix='Mattermost.User',
        outputs_key_field='id',
        outputs={
            'id': user_id,
            'channels': channels
        },
        readable_output=hr,
    )


def create_channel_command(client: HTTPClient, args: dict[str, Any]) -> CommandResults:
    """ Creates a channel """
    team_name = args.get('team', client.team_name)
    channel_name = args.get('name', '')
    channel_display_name = args.get('display_name')
    channel_type = 'O' if args.get('type') == 'public' else 'P'
    purpose = args.get('purpose', '')
    header = args.get('header', '')

    team_details = client.get_team_request(team_name)

    params = {'team_id': team_details.get('id', ''),
              'name': channel_name,
              'display_name': channel_display_name,
              'type': channel_type,
              'purpose': purpose,
              'header': header}

    remove_nulls_from_dictionary(params)

    try:
        channel_details = client.create_channel_request(params)
        hr = f'The channel {channel_display_name} was created successfully, with channel ID: {channel_details.get("id")}'
    except Exception as e:
        if 'A channel with that name already exists' in str(e):
            try:
                channel_details = client.get_channel_by_name_and_team_name_request(team_name, channel_name)
                hr = f"Channel {channel_display_name} already exists."
            except Exception as sec_e:
                if 'Channel does not exist.' in str(sec_e):
                    hr = 'Could not create a new channel. An archived channel with the same name may exist' \
                        'in the provided team. Please choose a different name.'
                    raise DemistoException(hr)
                else:
                    raise sec_e
        else:
            raise e

    return CommandResults(
        outputs_prefix='Mattermost.Channel',
        outputs_key_field='id',
        outputs=channel_details,
        readable_output=hr
    )


def add_channel_member_command(client: HTTPClient, args: dict[str, Any]) -> CommandResults:
    """ Adds a channel member """
    team_name = args.get('team', client.team_name)
    channel_name = args.get('channel', '')
    user_id = args.get('user_id', '')

    channel_details = client.get_channel_by_name_and_team_name_request(team_name, channel_name)

    data = {'user_id': user_id}
    client.add_channel_member_request(channel_details.get('id', ''), data)

    user_details = client.get_user_request(user_id)

    hr = f'The member {user_details.get("username", user_id)} was added to the channel successfully, with channel ID: {channel_details.get("id")}'  # noqa: E501
    return CommandResults(
        readable_output=hr
    )


def remove_channel_member_command(client: HTTPClient, args: dict[str, Any]) -> CommandResults:
    """ Removes a channel member """
    team_name = args.get('team', client.team_name)
    channel_name = args.get('channel', '')
    user_id = args.get('user_id', '')

    channel_details = client.get_channel_by_name_and_team_name_request(team_name, channel_name)

    client.remove_channel_member_request(channel_details.get('id', ''), user_id)

    user_details = client.get_user_request(user_id)

    hr = f'The member {user_details.get("username", user_id)} was removed from the channel successfully.'
    return CommandResults(
        readable_output=hr
    )


def close_channel_command(client: HTTPClient, args: dict[str, Any]) -> CommandResults:
    """ Closes a channels """
    team_name = args.get('team_name', client.team_name)
    channel_name = args.get('channel', '')

    channel_details = {}
    channel_id = ''
    if channel_name:
        try:
            channel_details = client.get_channel_by_name_and_team_name_request(team_name, channel_name)
        except Exception as e:
            if 'Channel does not exist.' in str(e):
                hr = f'The channel {channel_name} was not found. It may have been already deleted, or not in the team provided.'
                return CommandResults(readable_output=hr)
            else:
                raise e

    try:
        client.close_channel_request(channel_details.get('id', '') or channel_id)
        hr = f'The channel {channel_name} was delete successfully.'
    except Exception as e:
        if 'Channel does not exist.' in str(e):
            hr = f'The channel {channel_name} was already deleted.'
        else:
            raise e

    mirror = find_mirror_by_investigation()
    integration_context = get_integration_context()
    if mirror:
        demisto.debug('MM: Found mirrored channel to close.')
        channel_id = mirror.get('channel_id', '')
        mirrors = json.loads(integration_context['mirrors'])
        # Check for mirrors on the archived channel
        channel_mirrors = list(filter(lambda m: channel_id == m['channel_id'], mirrors))
        for mirror in channel_mirrors:
            mirror['remove'] = True
            demisto.mirrorInvestigation(mirror['investigation_id'], f'none:{mirror["mirror_direction"]}',
                                        mirror['auto_close'])

        set_to_integration_context_with_retries({'mirrors': mirrors}, OBJECTS_TO_KEYS)

    return CommandResults(
        readable_output=hr
    )


def list_users_command(client: HTTPClient, args: dict[str, Any]) -> CommandResults:
    """ Lists users """
    team_name = args.get('team_name', '')
    channel_name = args.get('channel', '')
    page = arg_to_number(args.get('page', DEFAULT_PAGE_NUMBER))
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE))
    limit = arg_to_number(args.get('limit', ''))

    if limit:
        page = DEFAULT_PAGE_NUMBER
        page_size = limit

    team_id = ''
    if team_name:
        team_details = client.get_team_request(team_name)
        team_id = team_details.get('id', '')

    channel_id = ''
    if channel_name:
        if not team_name:
            raise DemistoException("Must provide a team name if a channel name was provided.")
        channel_details = client.get_channel_by_name_and_team_name_request(team_name, channel_name)
        channel_id = channel_details.get('id', '')
        team_id = ''  # The search in Mattermost is done with an OR operator

    params = {'page': page, 'per_page': page_size, 'in_team': team_id, 'in_channel': channel_id}
    remove_nulls_from_dictionary(params)

    users = client.list_users_request(params)

    hr = tableToMarkdown('Users:', users, headers=['username', 'email', 'role', 'id'])
    return CommandResults(
        outputs_prefix='Mattermost.User',
        outputs_key_field='id',
        outputs=users,
        readable_output=hr,
    )


def send_file_command(client: HTTPClient, args) -> CommandResults:
    """ Sends a file """
    channel_name = args.get('channel', '')
    team_name = args.get('team_name', client.team_name)
    message = args.get('message')
    entry_id = args.get('entry_id') or args.get('file')
    to = args.get('to', '')

    demisto.debug(f'{to=}, {channel_name=}')

    if (to and channel_name):
        raise DemistoException("Cannot use both to and channel_name arguments")

    if not to and not channel_name:
        raise DemistoException("You must provide an to or channel_name arguments")

    if to:
        # create a new direct channel and send the message there
        if re.match(emailRegex, to):
            to = get_user_id_by_email(client, to)
        else:
            to = get_user_id_by_username(client, to)

        bot_id = get_user_id_from_token(client, bot_user=True)
        channel_details = client.create_direct_channel_request(to, bot_id)
        demisto.debug(f'MM: Created a new direct channel to: {to} with channel_id: {channel_details.get("id")}')
    else:
        channel_details = client.get_channel_by_name_and_team_name_request(team_name, channel_name)

    file_info = demisto.getFilePath(entry_id)
    params = {'channel_id': channel_details.get('id'),
              'filename': file_info['name']}

    upload_response = client.send_file_request(file_info, params)
    demisto.debug('MM: Uploaded the file successfully to mattermost')

    data = {'channel_id': channel_details.get('id'),
            'message': message,
            'file_ids': [upload_response.get('file_infos', [])[0].get('id', '')]}   # always uploading a single file
    remove_nulls_from_dictionary(params)

    client.create_post_with_file_request(data)

    return CommandResults(
        readable_output=f'file {file_info["name"]} was successfully sent to channel {channel_name}'
    )


def mirror_investigation(client: HTTPClient, **args) -> CommandResults:
    """
    Updates the integration context with a new or existing mirror.
    """
    if not MIRRORING_ENABLED:
        raise DemistoException("Couldn't mirror investigation, Mirroring is disabled")
    if not LONG_RUNNING:
        raise DemistoException('Mirroring is enabled, however long running is disabled. For mirrors to work correctly,'
                               ' long running must be enabled.')
    client = client
    mirror_type = args.get('type', 'all')
    direction = args.get('direction', 'Both')
    channel_name = args.get('channel', '')
    team_name = args.get('team_name', client.team_name)
    mirror_to = args.get('mirrorTo', 'group')

    autoclose = argToBoolean(args.get('autoclose', True))
    send_first_message = False
    kick_admin = argToBoolean(args.get('kickAdmin', False))

    investigation = demisto.investigation()
    investigation_id = str(investigation.get('id'))
    if investigation.get('type') == PLAYGROUND_INVESTIGATION_TYPE:
        raise DemistoException('This action cannot be performed in the playground.')

    integration_context = get_integration_context()
    if not integration_context or not integration_context.get('mirrors', []):
        mirrors: list = []
        current_mirror = []
    else:
        mirrors = json.loads(integration_context['mirrors'])
        current_mirror = list(filter(lambda m: m['investigation_id'] == investigation_id, mirrors))

    demisto.debug(f'MM: {mirrors=}')
    demisto.debug(f'MM: {current_mirror=}')
    # get admin user id from token
    admin_user_id = get_user_id_from_token(client)

    channel_filter: list = []
    channel_id = ''
    if channel_name:
        # check if channel already exists
        channel_filter = list(filter(lambda m: m['channel_name'] == channel_name, mirrors))

    if not current_mirror:
        channel_name = channel_name or f'incident-{investigation_id}'
        if not channel_filter:
            channel_details: dict = {}
            try:
                channel_details = client.get_channel_by_name_and_team_name_request(team_name, channel_name)
                send_first_message = False
            except Exception as e:
                if '404' in str(e):
                    # create new channel
                    demisto.debug(f'MM: Creating a new channel for mirroring with name: {channel_name}')
                    channel_type = 'public' if mirror_to == 'channel' else 'private'
                    args = {'team_name': team_name, 'name': channel_name.lower(),
                            'display_name': channel_name, 'type': channel_type}
                    result = create_channel_command(client=client, args=args)
                    channel_details = result.outputs  # type: ignore
                    send_first_message = True
                else:
                    raise e

            channel_id = channel_details.get('id', '')
            channel_team_id = channel_details.get('team_id')
        else:
            mirrored_channel = channel_filter[0]
            channel_team_id = mirrored_channel['channel_team_id']
            channel_id = mirrored_channel['channel_id']
            channel_name = mirrored_channel['channel_name']

        mirror = {
            'channel_team_id': channel_team_id,
            'channel_id': channel_id,
            'channel_name': channel_name,
            'investigation_id': investigation.get('id'),
            'mirror_type': mirror_type,
            'mirror_direction': direction,
            'auto_close': bool(autoclose),
            'mirrored': True
        }
    else:
        mirror = mirrors.pop(mirrors.index(current_mirror[0]))
        channel_id = mirror['channel_id']
        if mirror_type:
            mirror['mirror_type'] = mirror_type
        if autoclose:
            mirror['auto_close'] = autoclose
        if direction:
            mirror['mirror_direction'] = direction
        if channel_name:
            # update channel name if needed
            demisto.debug(f'MM: Updating channel name to {channel_name}')
            params = {'name': channel_name, 'display_name': channel_name, 'id': channel_id}
            client.update_channel_request(channel_id=channel_id, params=params)
            mirror['channel_name'] = channel_name
        channel_name = mirror['channel_name']
        mirror['mirrored'] = True
    demisto.mirrorInvestigation(investigation_id, f'{mirror_type}:{direction}', autoclose)

    mirrors.append(mirror)
    set_to_integration_context_with_retries({'mirrors': mirrors}, OBJECTS_TO_KEYS)

    if send_first_message:
        server_links = demisto.demistoUrls()
        server_link = server_links.get('server')
        incident_url = get_war_room_url(f'{server_link}#/WarRoom/{investigation_id}', investigation_id)
        message_to_send = (f'This channel was created to mirror incident {investigation_id}.'
                           f' \n View it on: {incident_url}')

        client.send_notification_request(channel_id, message_to_send)
    if kick_admin:
        try:
            client.remove_channel_member_request(channel_id, admin_user_id)
        except Exception as e:
            demisto.debug(f'Could not kick admin from channel. Error: {e}')

    return CommandResults(
        readable_output=f'Investigation mirrored successfully with mirror type {mirror_type},\n channel name: {channel_name}'
    )


def send_notification(client: HTTPClient, **args):
    """
    Sends notification for a MatterMost channel
    """
    demisto.debug(f'MM: Sending notification with {args=}')
    to = argToList(args.get('to', ''))
    entry = args.get('entry')
    channel_name = args.get('channel', '')
    message_to_send = args.get("message", "")
    ignore_add_url = argToBoolean(args.get('ignoreAddURL', False))
    mattermost_ask = argToBoolean(args.get('mattermost_ask', False))
    entitlement = ''
    reply = ''
    expiry = ''
    default_response = ''

    if mattermost_ask:
        parsed_message = json.loads(args.get("message", ''))
        entitlement = parsed_message.get('entitlement', '')
        expiry = parsed_message.get('expiry', '')
        default_response = parsed_message.get('default_response', '')
        reply = parsed_message.get('reply', '')
        message_to_send = parsed_message.get('message', '')

    message_type = args.get('messageType', '')  # From server
    original_message = args.get('originalMessage', '')  # From server
    entry_object = args.get('entryObject')  # From server
    investigation_id = ''
    poll: dict = {}

    if (to and channel_name):
        raise DemistoException("Cannot use both to and channel_name arguments")

    channel_name = channel_name or client.notification_channel

    if entry_object:
        investigation_id = entry_object.get('investigationId')  # From server, available from demisto v6.1 and above

    if message_type and (message_type not in PERMITTED_NOTIFICATION_TYPES) and message_type != MIRROR_TYPE:
        demisto.debug(f'MM: Will not mirror the message type: {message_type}')
        return (f"Message type is not in permitted options. Received: {message_type}")

    if message_type and message_type == MIRROR_TYPE and original_message.find(MESSAGE_FOOTER) != -1:
        # return so there will not be a loop of messages
        return ("Message already mirrored")

    if channel_name == INCIDENT_NOTIFICATION_CHANNEL:
        if client.notification_channel:
            # change the notification channel to the one in the configuration
            channel_name = client.notification_channel
        else:
            demisto.debug('MM: No notification channel was configured, '
                          f'will send notification to {INCIDENT_NOTIFICATION_CHANNEL}')

    if not ignore_add_url:
        investigation = demisto.investigation()
        server_links = demisto.demistoUrls()
        if investigation:
            if investigation.get('type') != PLAYGROUND_INVESTIGATION_TYPE:
                link = server_links.get('warRoom')
                if link:
                    link = get_war_room_url(link)
                    if entry:
                        link += '/' + entry
                    message_to_send += f'\nView it on: {link}'
            else:
                link = server_links.get('server', '')
                if link:
                    message_to_send += f'\nView it on: {link}#/home'
    channel_id = get_channel_id_to_send_notif(client, to, channel_name, investigation_id)

    raw_data = client.send_notification_request(channel_id, message_to_send, props=poll)
    message_id = raw_data.get("id")
    demisto.debug(f'MM: Got replay from post: {raw_data}')
    if entitlement:
        demisto.debug(f'MM: Found entitlement, saving message to context: {entitlement}')
        save_entitlement(entitlement, message_id, reply, expiry, default_response, to if to else channel_id)
    return CommandResults(
        readable_output=f'Message sent to MatterMost successfully. Message ID is: {message_id}'
    )


def list_groups_command(client: HTTPClient, args: dict[str, Any]) -> CommandResults:
    """ Lists user groups """
    page = arg_to_number(args.get('page', DEFAULT_PAGE_NUMBER))
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE))
    limit = args.get('limit', '')
    q = args.get('group', '')
    group_details: list[Any] = []
    if limit:
        page = DEFAULT_PAGE_NUMBER
        page_size = limit

    params = {'page': page, 'per_page': page_size, 'q': q}
    group_details = client.list_groups_request(params)

    hr = tableToMarkdown('User groups:', group_details, headers=['name', 'display_name', 'description', 'id'])
    return CommandResults(
        outputs_prefix='Mattermost.Groups',
        outputs_key_field='name',
        outputs=group_details,
        readable_output=hr,
    )


def list_group_members_command(client: HTTPClient, args: dict[str, Any]) -> CommandResults:
    """ List the members of a user group """
    group_name = args.get('group', '')
    member_details = {}

    params = {'q': group_name}
    group_details = client.list_groups_request(params)

    if len(group_details) == 1:
        group_detail = group_details[0]
    elif len(group_details) == 0:
        raise DemistoException('No matching user group found')
    else:
        raise DemistoException('User group pattern is not unique:\n' + '\n'.join([x['name'] for x in group_details]))

    member_details = client.list_group_members_request(group_detail.get('id', ''))
    member_details['id'] = group_detail.get('id', '')
    member_details['name'] = group_detail.get('name', group_name)

    hr = tableToMarkdown('User group members:', member_details.get("members"), headers=['username', 'email', 'id'])
    return CommandResults(
        outputs_prefix='Mattermost.Groups',
        outputs_key_field='name',
        outputs=member_details,
        readable_output=hr,
    )


def add_group_member_command(client: HTTPClient, args: dict[str, Any]) -> CommandResults:
    """ Adds a member to a user group """
    group_name = args.get('group', '')
    user_ids = argToList(args.get('user_ids', ''))

    params = {'q': group_name}
    group_details = client.list_groups_request(params)

    if len(group_details) == 1:
        group_detail = group_details[0]
    elif len(group_details) == 0:
        raise DemistoException('No matching user group found')
    else:
        raise DemistoException('User group pattern is not unique:\n' + '\n'.join([x['name'] for x in group_details]))

    data = {'user_ids': user_ids}
    response = client.add_group_member_request(group_detail.get('id', ''), data)

    hr = []
    for user in user_ids:
        user_details = client.get_user_request(user)
        hr.append(f'The member {user_details.get("username", user)} was added to the user group successfully, with group ID: {group_detail.get("id")}')   # noqa: E501

    return CommandResults(
        readable_output="\n".join(hr),
        raw_response=response
    )


def remove_group_member_command(client: HTTPClient, args: dict[str, Any]) -> CommandResults:
    """ Removes a member form a user group """
    group_name = args.get('group', '')
    user_ids = argToList(args.get('user_ids', ''))

    params = {'q': group_name}
    group_details = client.list_groups_request(params)

    if len(group_details) == 1:
        group_detail = group_details[0]
    elif len(group_details) == 0:
        raise DemistoException('No matching user group found')
    else:
        raise DemistoException('User group pattern is not unique:\n' + '\n'.join([x['name'] for x in group_details]))

    data = {'user_ids': user_ids}
    response = client.remove_group_member_request(group_detail.get('id', ''), data)

    hr = []
    for user in user_ids:
        user_details = client.get_user_request(user)
        hr.append(f'The member {user_details.get("username", user)} was removed from the user group successfully, with group ID: {group_detail.get("id")}')   # noqa: E501

    return CommandResults(
        readable_output="\n".join(hr),
        raw_response=response
    )


def set_channel_role_command(client: HTTPClient, args: dict[str, Any]) -> CommandResults:
    """ Set channel role for a channel member """
    channel_id = args.get('channel_id', '')
    user_id = args.get('user_id', '')
    channel_role = "channel_user" + (" channel_admin" if args.get("role", "admin").lower() == "admin" else "")

    client.set_channel_role_request(channel_id, user_id, channel_role)

    user_details = client.get_user_request(user_id)
    hr = f'Set channel role for {user_details.get("username", user_id)} successfully to {"Admin" if args.get("role", "admin").lower() == "admin" else "Member"}.'   # noqa: E501

    return CommandResults(
        readable_output=hr
    )


''' MAIN FUNCTION '''


def handle_global_parameters(params: dict):  # pragma: no cover
    """Initializing the global parameters"""
    url = params.get('url', '')
    bot_access_token = params.get('bot_access_token', {}).get('password')
    personal_access_token = params.get('personal_access_token', {}).get('password')
    proxy = params.get('proxy', False)

    # Initializing global variables
    global SECRET_TOKEN, LONG_RUNNING, MIRRORING_ENABLED, CACHE_EXPIRY, CACHED_INTEGRATION_CONTEXT, DEMISTO_URL
    global BASE_URL, PROXY, SSL_CONTEXT, VERIFY_CERT, PROXIES, ALLOW_INCIDENTS, INCIDENT_TYPE, PROXY_URL
    global WEBSOCKET_URL, PORT, PERMITTED_NOTIFICATION_TYPES
    LONG_RUNNING = params.get('longRunning', False)
    MIRRORING_ENABLED = params.get('mirroring', False)
    SECRET_TOKEN = personal_access_token
    BASE_URL = url
    PROXY = proxy
    demisto_urls = demisto.demistoUrls()
    DEMISTO_URL = demisto_urls.get('server', '')
    PROXIES, _ = handle_proxy_for_long_running()
    PROXY_URL = PROXIES.get('http', '')  # aiohttp only supports http proxy
    ALLOW_INCIDENTS = params.get('allow_incidents', True)
    INCIDENT_TYPE = params.get('incidentType', 'Unclassified')
    default_permitted_notification_types = ['externalAskSubmit', 'externalFormSubmit']
    custom_permitted_notification_types = demisto.params().get('permitted_notifications', [])
    PERMITTED_NOTIFICATION_TYPES = default_permitted_notification_types + custom_permitted_notification_types
    VERIFY_CERT = not params.get('insecure', False)
    if not VERIFY_CERT:
        SSL_CONTEXT = ssl.create_default_context()
        SSL_CONTEXT.check_hostname = False
        SSL_CONTEXT.verify_mode = ssl.CERT_NONE
    else:
        # Use default SSL context
        SSL_CONTEXT = None

    if 'https://' in url:
        uri = url.replace("https://", "wss://", 1)
    else:
        uri = url.replace("http://", "ws://", 1)
    uri += '/api/v4/websocket'
    WEBSOCKET_URL = uri

    # Pull initial Cached context and set the Expiry
    CACHE_EXPIRY = next_expiry_time()
    CACHED_INTEGRATION_CONTEXT = get_integration_context()

    if MIRRORING_ENABLED and (not LONG_RUNNING or not bot_access_token):
        raise DemistoException("""Mirroring is enabled, however long running is disabled
or the necessary bot authentication parameters are missing.
For mirrors to work correctly, long running must be enabled and you must provide all
the mattermost-bot following parameters:
Bot Access Token""")


def main():  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    url = params.get('url', '')
    bot_access_token = params.get('bot_access_token', {}).get('password')
    personal_access_token = params.get('personal_access_token', {}).get('password')
    team_name = params.get('team_name', '')
    notification_channel = params.get('notification_channel')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    handle_global_parameters(params)

    command = demisto.command()
    try:
        global CLIENT

        headers = {'Authorization': f'Bearer {personal_access_token}'}
        client = HTTPClient(
            base_url=url,
            headers=headers,
            verify=verify_certificate,
            proxy=proxy,
            bot_access_token=bot_access_token,
            personal_access_token=personal_access_token,
            team_name=team_name,
            notification_channel=notification_channel,
        )
        CLIENT = client
        demisto.debug(f'Command being called is {command}')
        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'mirror-investigation':
            return_results(mirror_investigation(client, **args))
        elif command == 'mattermost-mirror-investigation':
            return_results(mirror_investigation(client, **args))
        elif command == 'send-notification':
            return_results(send_notification(client, **args))
        elif command == 'long-running-execution':
            run_long_running()
        elif command == 'mattermost-get-team':
            return_results(get_team_command(client, args))
        elif command == 'mattermost-list-channels':
            return_results(list_channels_command(client, args))
        elif command == 'mattermost-list-channels-for-user':
            return_results(list_private_channels_for_user_command(client, args))
        elif command == 'mattermost-create-channel':
            return_results(create_channel_command(client, args))
        elif command == 'mattermost-add-channel-member':
            return_results(add_channel_member_command(client, args))
        elif command == 'mattermost-remove-channel-member':
            return_results(remove_channel_member_command(client, args))
        elif command == 'mattermost-list-users':
            return_results(list_users_command(client, args))
        elif command == 'mattermost-close-channel':
            return_results(close_channel_command(client, args))
        elif command == 'close-channel':
            return_results(close_channel_command(client, args))
        elif command == 'mattermost-send-file':
            return_results(send_file_command(client, args))
        elif command == 'mattermost-list-usergroups':
            return_results(list_groups_command(client, args))
        elif command == 'mattermost-list-usergroup-members':
            return_results(list_group_members_command(client, args))
        elif command == 'mattermost-add-usergroup-member':
            return_results(add_group_member_command(client, args))
        elif command == 'mattermost-remove-usergroup-member':
            return_results(remove_group_member_command(client, args))
        elif command == 'mattermost-set-channel-role':
            return_results(set_channel_role_command(client, args))
        else:
            raise DemistoException('Unrecognized command: ' + demisto.command())

    except Exception as e:
        # For any other integration command exception, return an error
        return_error(f'Failed to execute {command} command. Error: {str(e)}.')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
