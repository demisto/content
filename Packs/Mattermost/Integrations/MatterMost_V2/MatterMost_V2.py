import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


from CommonServerUserPython import *  # noqa
import asyncio
import concurrent
import aiohttp
import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''
SYNC_CONTEXT = True
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
MAX_SAMPLES = 10
INCIDENT_TYPE: str
ALLOW_INCIDENTS: bool
MESSAGE_FOOTER = '\n**From MatterMost**'
MIRROR_TYPE = 'mirrorEntry'
OBJECTS_TO_KEYS = {
    'messages': 'entitlement',
}
DEFAULT_OPTIONS = {
        "timeout": 30,
        "request_timeout": None,
        "mfa_token": None,
        "auth": None,
        "keepalive": False,
        "keepalive_delay": 5,
        "websocket_kw_args": None,
        "debug": False,
        "http2": False,
    }
''' CLIENT CLASS '''


class WebSocketClient:
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
        self.last_msg = 0
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
                kw_args = {}
                if self.options["websocket_kw_args"]:
                    kw_args = self.options["websocket_kw_args"]
                async with aiohttp.ClientSession() as session:
                    async with session.ws_connect(
                        uri,
                        ssl=SSL_CONTEXT,
                        proxy=None,
                        **kw_args,
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
        This is a little complicated, but we only need to pong the websocket if
        we haven't recieved a message inside the timeout window.

        Since messages can be received, while we are waiting we need to check
        after sleep.
        """
        timeout = self.options["timeout"]
        while True:
            since_last_msg = time.time() - self.last_msg
            next_timeout = timeout - since_last_msg if since_last_msg <= timeout else timeout
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
        This is not needed when we just send the cookie we got on login
        when connecting to the websocket.
        """
        demisto.debug("MM: Authenticating websocket")
        json_data = json.dumps({"seq": 1, "action": "authentication_challenge", "data": {"token": self.token}})
        await websocket.send_str(json_data)
        while True:
            message = await websocket.receive_str()
            status = json.loads(message)
            demisto.debug(status)
            # We want to pass the events to the event_handler already
            # because the hello event could arrive before the authentication ok response
            await event_handler(self, message)
            if ("event" in status and status["event"] == "hello") and ("seq" in status and status["seq"] == 0):
                demisto.debug("MM: Websocket authentification OK")
                return True
            demisto.error("MM: Websocket authentification failed")

class Client(BaseClient):
    """Client class to interact with the MatterMost API
    """
    def __init__(
        self,
        base_url: str,
        headers: dict,
        personal_access_token: str,
        bot_access_token: str | None = None,
        team_name: str | None = None,
        notification_channel: str | None = None,
        verify=True,
        proxy=False,
    ):
        super().__init__(base_url, verify, proxy, headers=headers)
        self.bot_access_token = bot_access_token
        self.personal_access_token = personal_access_token
        self.team_name = team_name
        self.notification_channel = notification_channel
        self.ws_client = None

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

    def create_channel_request(self, params: dict) -> dict[str, str]:
        """Creates a channel"""
        response = self._http_request(method='POST', url_suffix='/api/v4/channels', json_data=params)

        return response

    def get_channel_by_name_and_team_name_request(self, team_name: str, channel_name: str) -> dict[str, Any]:
        """Gets a channel based on name and team name"""
        response = self._http_request(method='GET', url_suffix=f'/api/v4/teams/name/{team_name}/channels/name/{channel_name}')

        return response

    def add_channel_member_request(self, channel_id: str, data: dict) -> dict[str, str]:
        """Adds a channel member"""
        response = self._http_request(method='POST', url_suffix=f'/api/v4/channels/{channel_id}/members', json_data=data)

        return response

    def remove_channel_member_request(self, channel_id: str, user_id: dict) -> dict[str, str]:
        """Removes a channel member"""
        response = self._http_request(method='DELETE', url_suffix=f'/api/v4/channels/{channel_id}/members/{user_id}')

        return response

    def list_users_request(self, params: dict) -> list[dict[str, Any]]:
        """lists users"""
        response = self._http_request(method='GET', url_suffix='/api/v4/users', params=params)

        return response

    def close_channel_request(self, channel_id: str) -> list[dict[str, Any]]:
        """Cloeses a channel"""
        response = self._http_request(method='DELETE', url_suffix=f'/api/v4/channels/{channel_id}')

        return response

    def send_file_request(self, file_info: dict, params: dict) -> dict[str, str]:

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
        """Creates a post"""
        response = self._http_request(method='POST', url_suffix='/api/v4/posts', json_data=data)

        return response

    def update_channel_request(self, channel_id: str, params: dict) -> list[dict[str, Any]]:
        """Updates a channel"""
        response = self._http_request(method='PUT', url_suffix=f'/api/v4/channels/{channel_id}', json_data=params)

        return response
    
    def get_user_request(self, user_id: str = '', bot_user: bool = False):
        """Gets a user"""
        if not user_id:
            user_id = 'me'
        if bot_user:
            response = self._http_request(method='GET', url_suffix=f'/api/v4/users/{user_id}',
                                          headers={'authorization': f'Bearer {self.bot_access_token}'})
        else:
            response = self._http_request(method='GET', url_suffix=f'/api/v4/users/{user_id}')

        return response

    
    def send_notification_request(self, channel_id: str, message: str, file_ids: list[str] =[], root_id: str =''):
        "Sends a notification"
        data = {"channel_id": channel_id,
            "message": message,
            "root_id": root_id,
            "file_ids": file_ids,
        }
        remove_nulls_from_dictionary(data)
        response = self._http_request(method='POST', url_suffix='/api/v4/posts', json_data=data,
                                      headers={'authorization': f'Bearer {self.bot_access_token}'})

        return response
    
    def get_user_by_email_request(self, user_email: str):
        "Gets a user by email"
        response = self._http_request(method='GET', url_suffix=f'/api/v4/users/email/{user_email}')

        return response
    
    def get_user_by_username_request(self, username: str):
        "Gets a user by username"
        response = self._http_request(method='GET', url_suffix=f'/api/v4/users/username/{username}')

        return response
    
    def create_direct_channel_request(self, user_id: str, bot_id: str):
        "creates a direct channel"
        bot_id = get_user_id_from_token(self, bot_user=True)

        response = self._http_request(method='POST', url_suffix='/api/v4/channels/direct', data=[bot_id, user_id])

        return response

''' HELPER FUNCTIONS '''

def next_expiry_time() -> float:
    """
    Returns:
        A float representation of a new expiry time with an offset of 5 seconds
    """
    return (datetime.now(timezone.utc) + timedelta(seconds=5)).timestamp()


async def check_and_handle_entitlement(text: str, message_id: str, user_name: str) -> str:
    """
    Handles an entitlement message (a reply to a question)
    Args:
    Returns:
        If the message contains entitlement, return a reply.
    """
    integration_context = fetch_context(force_refresh=True)
    messages = integration_context.get('messages', [])
    reply = ''
    if not messages or not message_id:
        return reply
    messages = json.loads(messages)
    message_filter = list(filter(lambda q: q.get('message_id') == message_id, messages))
    if message_filter:
        message = message_filter[0]
        entitlement = message.get('entitlement')
        reply = message.get('reply', f'Thank you {user_name} for your response {text}.')
        guid, incident_id, task_id = extract_entitlement(entitlement)
        demisto.handleEntitlementForUser(incident_id, guid, user_name, text, task_id)
        message['remove'] = True
        set_to_integration_context_with_retries({'messages': messages}, OBJECTS_TO_KEYS, SYNC_CONTEXT)
    return reply


def run_long_running():
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

async def start_listening():
    """
    Starts a Slack SocketMode client and checks for mirrored incidents.
    """
    try:
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_in_executor(executor, long_running_loop)
        await mattermost_loop()
    except Exception as e:
        demisto.error(f"An error has occurred while gathering the loop tasks. {e}")


def long_running_loop():
    tts = 15 if MIRRORING_ENABLED else 60
    while True:
        error = ''
        try:
            # if MIRRORING_ENABLED:
            #     check_for_mirrors()
            # check_for_unanswered_questions()
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


async def listen(client: WebSocketClient, req):
    """
    This is the main listener which is attached to the open socket connection. When a SocketModeRequest has been received
    this flow will be triggered. The Payload can be of any type and this function will determine what type it is, then
    handle it accordingly. In the event that the request is nothing of interest to us, we will simply acknowledge the
    request, process the message and gracefully ignore it.
    :param client: SocketModeClient: This is the socket client which is created by the slack_loop function.
    :param req: SocketModeRequest: The request object which has been sent by Slack.
    :return: None
    """
    demisto.debug("Starting to process message")
    if req.retry_attempt:
        if req.retry_attempt > 0 and IGNORE_RETRIES:
            demisto.debug("Slack is resending the message. To prevent double posts, the retry is ignored.")
            return
        else:
            demisto.debug(f"Slack is resending the message. Ignore retries is - {IGNORE_RETRIES} and the "
                          f"retry attempt is - {req.retry_attempt}. Continuing to process the event.")
    data_type: str = req.type
    payload: dict = req.payload
    if data_type == 'error':
        error = payload.get('error', {})
        error_code = error.get('code')
        error_msg = error.get('msg')
        await handle_listen_error(
            f'Slack API has thrown an error. Code: {error_code}, Message: {error_msg}.')
        return
    try:
        data: dict = req.payload
        event: dict = data.get('event', {})
        text = event.get('text', '')
        user_id = data.get('user', {}).get('id', '')
        if not user_id:
            user_id = event.get('user', '')
        channel = event.get('channel', '')
        thread = event.get('thread_ts', None)
        message = data.get('message', {})
        action_text = ''
        message_ts = message.get('ts', '')
        actions = data.get('actions', [])
        state = data.get('state', {})
        response_url = data.get('response_url', '')
        quick_check_payload = json.dumps(data)

        # Check if the message is from a bot so we can quit processing
        if is_bot_message(data):
            return

        # Quick check for entitlement
        if re.search(ENTITLEMENT_REGEX, quick_check_payload):
            # At this point, we know there is an entitlement in the payload.
            # This is a check to determine if the event contains actions which are sent as part of a SlackAsk response.
            entitlement_reply = None
            user = await get_user_details(user_id=user_id)
            if len(actions) > 0:
                channel = data.get('channel', {}).get('id', '')
                entitlement_json = actions[0].get('value')
                entitlement_string = json.loads(entitlement_json)
                if entitlement_json is None:
                    return
                if actions[0].get('action_id') == 'xsoar-button-submit':
                    demisto.debug("Handling a SlackBlockBuilder response.")
                    if state:
                        state.update({"xsoar-button-submit": "Successful"})
                        action_text = json.dumps(state)
                else:
                    demisto.debug("Not handling a SlackBlockBuilder response.")
                    action_text = actions[0].get('text').get('text')
                _ = answer_question(action_text, entitlement_string,
                                    user.get('profile', {}).get('email'))  # type: ignore
                entitlement_reply = entitlement_string.get("reply", "Thank you for your reply.")
            if entitlement_reply:
                await process_entitlement_reply(entitlement_reply, user_id, action_text, response_url=response_url)
                reset_listener_health()
                return

        # If a thread_id is found in the payload, we will check if it is a reply to a SlackAsk task. Currently threads
        # are not mirrored
        if thread:
            user = await get_user_details(user_id=user_id)
            entitlement_reply = await check_and_handle_entitlement(text, user, thread)  # type: ignore
            if entitlement_reply:
                await process_entitlement_reply(entitlement_reply, user_id, action_text, channel=channel,
                                                message_ts=message_ts)
                reset_listener_health()
                return

    except Exception as e:
        await handle_listen_error(f'Error occurred while listening to Slack: {e}')


async def event_handler(client: WebSocketClient, req):
    demisto.debug(f"MM: Got events: {req} - with type {type(req)}")
    payload = json.loads(req)
    demisto.debug(f"MM: payload with type {type(payload)}")

    # if data_type == 'error':
    #     error = payload.get('error', {})
    #     error_code = error.get('code')
    #     error_msg = error.get('msg')
    #     await handle_listen_error(
    #         f'Slack API has thrown an error. Code: {error_code}, Message: {error_msg}.')
    #     return

        # Check if the message is from a bot so we can quit processing ASAP
    
    if payload.get('event') == 'hello' or payload.get('seq_reply') == 1:
        # we handle hello event afterwards
        return

    if payload.get('event') == 'posted':
        await handle_posts(payload)
        return
    
        # Check to see if the event is about a newly handled event.
    # elif payload.get('event') == 'channel_created' and MIRRORING_ENABLED:
    #     handle_newly_created_channel(payload)
    #     return

def is_bot_message(payload: dict) -> bool:
    """
    Determines if the message received was created by a bot or not.
    :param data: dict: The payload sent with the message
    :return: bool: True indicates the message was from a Bot, False indicates it was from an individual
    """
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
    Takes the channel ID and will see if the first letter of the ID is 'D'. If so, we know it's from a direct message.
    :param channel: str: The channel ID to check.
    :return: bool: Boolean indicating if the channel is a DM or not.
    """
    channel_type = payload.get('data', {}).get('channel_type')
    return channel_type == 'D'

def is_thread(post: dict):
    """
    Takes the channel ID and will see if the first letter of the ID is 'D'. If so, we know it's from a direct message.
    :param channel: str: The channel ID to check.
    :return: bool: Boolean indicating if the channel is a DM or not.
    """
    root_id = post.get('root_id', '')
    return root_id != ''

def handle_newly_created_channel(payload):
    creator = event.get('channel', {}).get('creator', '')
    channel_id = event.get('channel', {}).get('id', '')

    if creator == BOT_ID:
        if 'mirrors' in CACHED_INTEGRATION_CONTEXT:
            mirrors = json.loads(CACHED_INTEGRATION_CONTEXT['mirrors'])
            if len(mirrors) == 0:
                fetch_context(force_refresh=True)
                return
            mirror_filter = list(filter(lambda m: m['channel_id'] == channel_id, mirrors))
            if not mirror_filter:
                fetch_context(force_refresh=True)
                return
        else:
            fetch_context(force_refresh=True)
            return
    else:
        return

    
async def mattermost_loop():
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


def get_user_id_from_token(client, bot_user: bool = False):
    result = client.get_user_request(bot_user=bot_user)
    
    return result.get('id', '')

def get_user_id_by_email(client, email: str):
    result = client.get_user_by_email_request(email)
    return result.get('id')

def get_user_id_by_username(client, username: str):
    result = client.get_user_by_username_request(username)
    return result.get('id')

def get_username_by_email(client, email: str):
    result = client.get_user_by_email_request(email)
    return result.get('username')

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
        CACHED_INTEGRATION_CONTEXT = get_integration_context(SYNC_CONTEXT)

    return CACHED_INTEGRATION_CONTEXT

def get_channel_id_from_context(channel_name: str = '', investigation_id=None):
    """
    Retrieves a MatterMost channel ID based on the provided criteria.

    :param channel_name: The name of the channel to get the JID for.
    :param investigation_id: The Demisto investigation ID to search for a mirrored channel.

    :return: The requested channel JID or None if not found.
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

def get_channel_id_to_send_notif(client: Client, to: str, channel_name: str, investigation_id: str):
    
    channel_id = ''
    if to:
        # create a new channel and send the message there
        if re.match(emailRegex, to):
            to = get_user_id_by_email(client, to)
        else:
            to = get_user_id_by_username(client, to)

        bot_id = get_user_id_from_token(client, bot_user=True)
        channel_object = client.create_direct_channel_request(to, bot_id)
        channel_id = channel_object.get('id')

    elif channel_name:  # if channel name provided
        
        channel_id = get_channel_id_from_context(channel_name, investigation_id)
        if not channel_id:
            raise DemistoException(f"Did not find channel with name {channel_name}")

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
    integration_context = get_integration_context(SYNC_CONTEXT)
    messages = integration_context.get('messages', [])
    if messages:
        messages = json.loads(integration_context['messages'])
    messages.append({
        'message_id': message_id,
        'entitlement': entitlement,
        'reply': reply,
        'expiry': expiry,
        'sent': datetime.strftime(datetime.utcnow(), DATE_FORMAT),
        'default_response': default_response,
        'to_id': to_id
    })

    set_to_integration_context_with_retries({'messages': messages}, OBJECTS_TO_KEYS, SYNC_CONTEXT)

def extract_entitlement(entitlement: str) -> tuple[str, str, str]:
    """
    Extracts entitlement components from an entitlement string
    Args:
        entitlement: The entitlement itself
        text: The actual reply text

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

async def answer_question(text: str, question: dict, email: str = ''):
    entitlement = question.get('entitlement', '')
    to_id = question.get('to_id')
    guid, incident_id, task_id = extract_entitlement(entitlement)
    try:
        demisto.handleEntitlementForUser(incident_id, guid, email, text, task_id)
        bot_access_token = CLIENT.bot_access_token
        if bot_access_token:
            _ = await process_entitlement_reply(text, to_id)
    except Exception as e:
        demisto.error(f'Failed handling entitlement {entitlement}: {str(e)}')
    question['remove'] = True
    return incident_id

async def send_notification_async(client, channel_id, message, root_id=''):
    client.send_notification_request(channel_id, message, root_id=root_id)

async def process_entitlement_reply( #TODO
    entitlement_reply: str,
    to_id: str | None = None,
    user_name: str | None = None,
    action_text: str | None = None,
):
    """
    Triggered when an entitlement reply is found, this function will update the original message with the reply message.
    :param entitlement_reply: str: The text to update the asking question with.
    :param user_name: str: name of the user who answered the entitlement
    :param action_text: str: The text attached to the button, used for string replacement.
    :param accountId: str: Zoom account ID
    :return: None
    """
    if '{user}' in entitlement_reply:
        entitlement_reply = entitlement_reply.replace('{user}', str(user_name))
    if '{response}' in entitlement_reply and action_text:
        entitlement_reply = entitlement_reply.replace('{response}', str(action_text))

    content_json = {}
    await send_notification_async(CLIENT, channel_id, entitlement_reply, to_id)

async def handle_text_received_from_mm(investigation_id: str, text: str, operator_email: str, operator_name: str):
    """
    Handles text received from Zoom

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
    demisto.debug("MM: inside handle post")
    broadcast = payload.get("broadcast", {})
    demisto.debug("MM: 1")
    post = json.loads(payload.get("data", {}).get("post"))
    message = post.get('message', {})
    channel_id = post.get("channel_id")
    user_id = post.get('user_id')
    if not channel_id:
        return
    
    if is_bot_message(payload):
        demisto.debug("MM: Got a bot message. Will not mirror.")
        return

    # Check if the message is being sent directly to our bot.
    if is_dm(payload):
        await handle_dm(user_id, message, channel_id, CLIENT)  # type: ignore
        reset_listener_health()
        return

    # If a thread, we will check if it is a reply to a SlackAsk task.
    if is_thread(post):
        action_text = ''
        entitlement_reply = await check_and_handle_entitlement(text, user, thread)  # type: ignore
        if entitlement_reply:
            await process_entitlement_reply(entitlement_reply, user_id, action_text, channel=channel, message_ts=message_ts)
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
                                                        OBJECTS_TO_KEYS, SYNC_CONTEXT)
        
        user_details = CLIENT.get_user_request(user_id)
        operator_name = user_details.get('username')
        operator_email = user_details.get('email')
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


async def handle_dm(user_id: str, text: str, channel_id: str, client: Client):
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
    user_details = CLIENT.get_user_request(user_id)
    user_name = user_details.get('username')
    user_email = user_details.get('email')
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

async def translate_create(message: str, user_name: str, user_email: str, demisto_user: dict) -> str:
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
        data = f'Successfully created incident {incident_name}.\n View it on: {server_link}#/WarRoom/{incident_id}'

    return data


def add_req_data_to_incidents(incidents: list, request_fields: dict) -> list:
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
        user_name: The name of the user in Slack
        user_email: The email of the user in Slack
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


def update_integration_context_samples(incidents: list, max_samples: int = MAX_SAMPLES):
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
    demisto.updateModuleHealth("")
    demisto.info("MatterMost V2 - Event handled successfully.")
''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests connectivity with the client.
    Takes as an argument all client arguments to create a new client
    """
    if MIRRORING_ENABLED and (not LONG_RUNNING or not SECRET_TOKEN or not
                                client.bot_access_token):
        raise DemistoException("""Mirroring is enabled, however long running is disabled
or the necessary bot authentication parameters are missing.
For mirrors to work correctly, long running must be enabled and you must provide all
the MatterMost-bot following parameters:
Bot Access Token""")
    demisto.debug("Runnng test module")
    client.get_user_request(user_id='me', bot_user=False)
    client.get_user_request(user_id='me', bot_user=True)

    if client.notification_channel and client.team_name:
        channel_details = client.get_channel_by_name_and_team_name_request(client.team_name, client.notification_channel)
        client.send_notification_request(channel_details.get('id', ''), 'Hi there! This is a test message.')
    
    return 'ok'

def get_team_command(client: Client, args: dict[str, Any]) -> CommandResults:

    team_name = args.get('team_name', client.team_name)

    team_details = client.get_team_request(team_name)

    hr = tableToMarkdown('Team details:', team_details)
    return CommandResults(
        outputs_prefix='Mattermost.Team',
        outputs_key_field='name',
        outputs=team_details,
        readable_output=hr,
    )


def list_channels_command(client: Client, args: dict[str, Any]) -> CommandResults:

    team_name = args.get('team', client.team_name)
    include_private_channels = argToBoolean(args.get('include_private_channels', False))
    page = arg_to_number(args.get('page', DEFAULT_PAGE_NUMBER))
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE))
    limit = args.get('limit', '')
    
    if limit:
        page = DEFAULT_PAGE_NUMBER
        page_size = limit

    team_details = client.get_team_request(team_name)

    params = {'page': page, 'page_size': page_size}
    channel_details = client.list_channel_request(team_details.get('id', ''), params)

    if include_private_channels:
        channel_details += client.list_channel_request(team_details.get('id', ''), params, get_private=True)

    hr = tableToMarkdown('Channels:', channel_details)
    return CommandResults(
        outputs_prefix='Mattermost.Channel',
        outputs_key_field='name',
        outputs=channel_details,
        readable_output=hr,
    )


def create_channel_command(client: Client, args: dict[str, Any]) -> CommandResults:

    team_name = args.get('team', client.team_name)
    channel_name = args.get('name', '')
    channel_display_name = args.get('display_name')
    channel_type = 'O' if args.get('type') == 'Public' else 'P'
    purpose = args.get('purpose', '')
    header = args.get('header', '')

    team_details = client.get_team_request(team_name)

    params = {'team_id': team_details.get('id'),
              'name': channel_name,
              'display_name': channel_display_name,
              'type': channel_type,
              'purpose': purpose,
              'header': header}

    remove_nulls_from_dictionary(params)

    channel_details = client.create_channel_request(params)
    hr = f'The channel {channel_display_name} was created successfully, with channel ID: {channel_details.get("id")}'
    return CommandResults(
        outputs_prefix='Mattermost.Channel',
        outputs_key_field='id',
        outputs=channel_details,
        readable_output=hr
    )


def add_channel_member_command(client: Client, args: dict[str, Any]) -> CommandResults:

    team_name = args.get('team', client.team_name)
    channel_name = args.get('channel', '')
    user_id = args.get('user_id', '')

    channel_details = client.get_channel_by_name_and_team_name_request(team_name, channel_name)

    data = {'user_id': user_id}
    client.add_channel_member_request(channel_details.get('id', ''), data)

    hr = f'The member {user_id} was added to the channel successfully, with channel ID: {channel_details.get("id")}'
    return CommandResults(
        readable_output=hr
    )


def remove_channel_member_command(client: Client, args: dict[str, Any]) -> CommandResults:

    team_name = args.get('team_name', client.team_name)
    channel_name = args.get('channel', '')
    user_id = args.get('user_id', '')

    channel_details = client.get_channel_by_name_and_team_name_request(team_name, channel_name)

    client.remove_channel_member_request(channel_details.get('id', ''), user_id)

    hr = f'The member {user_id} was removed from the channel successfully.'
    return CommandResults(
        readable_output=hr
    )

def close_channel_command(client: Client, args: dict[str, Any]) -> CommandResults:
    team_name = args.get('team_name', client.team_name)
    channel_name = args.get('channel_name', '')

    channel_details = client.get_channel_by_name_and_team_name_request(team_name, channel_name)

    client.close_channel_request(channel_details.get('id', ''))

    hr = f'The channel {channel_name} was delete successfully.'
    return CommandResults(
        readable_output=hr
    )

def list_users_command(client: Client, args: dict[str, Any]) -> CommandResults:

    team_name = args.get('team_name', '')
    channel_name = args.get('channel_name', '')
    page = arg_to_number(args.get('page', DEFAULT_PAGE_NUMBER))
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE))
    limit = arg_to_number(args.get('limit'))

    if limit:
        page = DEFAULT_PAGE_NUMBER
        page_size = limit
    
    team_id = ''
    if team_name:
        team_details = client.get_team_request(team_name)
        team_id = team_details.get('id')

    channel_id = ''
    if channel_name:
        if not team_name:
            raise DemistoException("Must provide a team name if a channel name was provided.")
        channel_details = client.get_channel_by_name_and_team_name_request(team_name, channel_name)
        channel_id = channel_details.get('id')

    params = {'page': page, 'page_size': page_size, 'in_team': team_id, 'in_channel': channel_id}
    remove_nulls_from_dictionary(params)

    users = client.list_users_request(params)

    hr = tableToMarkdown('Users:', users)
    return CommandResults(
        outputs_prefix='Mattermost.User',
        outputs_key_field='id',
        outputs=users,
        readable_output=hr,
    )

def send_file_command(client: Client, args) -> CommandResults:

    channel_name = args.get('channel_name')
    team_name = args.get('team_name', client.team_name)
    message = args.get('message')
    entry_id = args.get('entry_id')

    channel_details = client.get_channel_by_name_and_team_name_request(team_name, channel_name)

    file_info = demisto.getFilePath(entry_id)
    params = {'channel_id': channel_details.get('id'),
              'filename': file_info['name']}

    upload_response = client.send_file_request(file_info, params)

    data = {'channel_id': channel_details.get('id'),
              'message': message,
              'file_ids': [upload_response.get('file_infos')[0].get('id')]}   # always uploading a single file
    remove_nulls_from_dictionary(params)

    client.create_post_with_file_request(data)

    return CommandResults(
        readable_output=f'file {file_info["name"]} was successfully sent to channel {channel_name}'
    )

def mirror_investigation(client: Client, **args) -> CommandResults:
    if not MIRRORING_ENABLED:
        demisto.error(" couldn't mirror investigation, Mirroring is disabled")
    if MIRRORING_ENABLED and not LONG_RUNNING:
        demisto.error('Mirroring is enabled, however long running is disabled. For mirrors to work correctly,'
                      ' long running must be enabled.')

    client = client
    mirror_type = args.get('type', 'all')
    direction = args.get('direction', 'Both')
    channel_name = args.get('channelName', client.notification_channel)
    team_name = args.get('team_name', client.team_name)

    autoclose = argToBoolean(args.get('autoclose', True))
    send_first_message = False
    kick_admin = argToBoolean(args.get('kickAdmin', False))

    investigation = demisto.investigation()
    investigation_id = str(investigation.get('id'))
    if investigation.get('type') == PLAYGROUND_INVESTIGATION_TYPE:
        return_error('Sorry, but this action cannot be performed in the playground.')

    integration_context = get_integration_context(SYNC_CONTEXT)
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
                    # create new public channel
                    demisto.debug('MM: Creating a new channel for mirroring')
                    args = {'team_name': team_name, 'name': channel_name.lower(), 'display_name': channel_name, 'type': 'Public'}
                    result = create_channel_command(client=client, args=args)
                    channel_details = result.outputs
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
        if channel_name and not channel_filter:
            # update channel name if needed
            params = {'name': channel_name, 'display_name': channel_name, 'id': channel_id}
            client.update_channel_request(channel_id=channel_id, params=params)
            mirror['channel_name'] = channel_name
        channel_name = mirror['channel_name']
        mirror['mirrored'] = True
    demisto.mirrorInvestigation(investigation_id, f'{mirror_type}:{direction}', autoclose)

    mirrors.append(mirror)
    set_to_integration_context_with_retries({'mirrors': mirrors}, OBJECTS_TO_KEYS, SYNC_CONTEXT)

    if send_first_message:
        server_links = demisto.demistoUrls()
        server_link = server_links.get('server')
        message_to_send = (f'This channel was created to mirror incident {investigation_id}.'
                   f' \n View it on: {server_link}#/WarRoom/{investigation_id}')

        client.send_notification_request(channel_id, message_to_send)
    if kick_admin:
        demisto.debug("kick-admin:")
        res = client.remove_channel_member_request(channel_id, admin_user_id)
        demisto.debug(f"res: {res}")
    return CommandResults(
        readable_output=f'Investigation mirrored successfully,\n channel name:{channel_name}'
    )

def send_notification(client, **args):

    client = client
    to = args.get('to', '')
    channel_name = args.get('channelName', '') or client.notification_channel
    mattermost_ask = argToBoolean(args.get('mattermost_ask', False))
    message_to_send = args.get("message", "")
    entitlement = None

    message_type = args.get('messageType', '')  # From server
    original_message = args.get('originalMessage', '')  # From server
    entry_object = args.get('entryObject')  # From server
    investigation_id = ''

    if (to and channel_name):
        raise DemistoException("Too many arguments")
    if not to and not channel_name:
        raise DemistoException("Missing arguments")

    if entry_object:
        investigation_id = entry_object.get('investigationId')  # From server, available from demisto v6.1 and above

    if message_type and message_type != MIRROR_TYPE:
        return (f"Message type is not in permitted options. Received: {message_type}")

    if message_type == MIRROR_TYPE and original_message.find(MESSAGE_FOOTER) != -1:
        # return so there will not be a loop of messages
        return ("Message already mirrored")

    channel_id = get_channel_id_to_send_notif(client, to, channel_name, investigation_id)

    if mattermost_ask:
        # script with a poll
        parsed_message = json.loads(message_to_send)
        entitlement = parsed_message.get('entitlement')
        message_to_send = parsed_message.get('blocks')
        reply = parsed_message.get('reply')
        expiry = parsed_message.get('expiry')
        default_response = parsed_message.get('default_response')
        
        # create the dict with the data for the poll
        
        # poll = create_poll()

    raw_data = client.send_notification_request(channel_id, message_to_send)
    if raw_data:
        message_id = raw_data.get("message_id")
        if entitlement:
            save_entitlement(entitlement, message_id, reply, expiry, default_response, to if to else channel_id)
    return CommandResults(
        readable_output=f'Message sent to MatterMost successfully. Message ID is: {raw_data.get("message_id")}'
    )

''' MAIN FUNCTION '''


def main():  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    url = params.get('url', '')

    bot_access_token = params.get('bot_access_token', {}).get('password')
    personal_access_token = params.get('personal_access_token', {}).get('password')
    team_name = params.get('team_name')
    notification_channel = params.get('notification_channel')

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    global SECRET_TOKEN, LONG_RUNNING, MIRRORING_ENABLED, CACHE_EXPIRY, CACHED_INTEGRATION_CONTEXT
    global BASE_URL, PROXY, SSL_CONTEXT, VERIFY_CERT, PROXIES, ALLOW_INCIDENTS, INCIDENT_TYPE
    LONG_RUNNING = params.get('longRunning', False)
    MIRRORING_ENABLED = params.get('mirroring', False)
    SECRET_TOKEN = personal_access_token
    BASE_URL = url
    PROXY = proxy
    ALLOW_INCIDENTS = params.get('allow_incidents', False)
    INCIDENT_TYPE = params.get('incidentType', '')
    VERIFY_CERT = not params.get('insecure', False)
    if not VERIFY_CERT:
        SSL_CONTEXT = ssl.create_default_context()
        SSL_CONTEXT.check_hostname = False
        SSL_CONTEXT.verify_mode = ssl.CERT_NONE
    else:
        # Use default SSL context
        SSL_CONTEXT = None
    
    PROXIES, _ = handle_proxy_for_long_running()
    # Pull initial Cached context and set the Expiry
    CACHE_EXPIRY = next_expiry_time()
    CACHED_INTEGRATION_CONTEXT = get_integration_context(SYNC_CONTEXT)

    if MIRRORING_ENABLED and (not LONG_RUNNING or not bot_access_token):
        raise DemistoException("""Mirroring is enabled, however long running is disabled
or the necessary bot authentication parameters are missing.
For mirrors to work correctly, long running must be enabled and you must provide all
the mattermost-bot following parameters:
Bot Access Token""")

    command = demisto.command()
    # this is to avoid BC. because some of the arguments given as <a-b>, i.e "user-list"
    args = {key.replace('-', '_'): val for key, val in args.items()}

    try:
        global CLIENT
        headers = {'Authorization': f'Bearer {personal_access_token}'}

        client = Client(
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
        elif command == 'send-notification':
            return_results(send_notification(client, **args))
        if command == 'long-running-execution':
            run_long_running()
        elif command == 'mattermost-get-team':
            return_results(get_team_command(CLIENT, args))
        elif command == 'mattermost-list-channels':
            return_results(list_channels_command(CLIENT, args))
        elif command == 'mattermost-create-channel':
            return_results(create_channel_command(CLIENT, args))
        elif command == 'mattermost-add-channel-member':
            return_results(add_channel_member_command(CLIENT, args))
        elif command == 'mattermost-remove-channel-member':
            return_results(remove_channel_member_command(CLIENT, args))
        elif command == 'mattermost-list-users':
            return_results(list_users_command(CLIENT, args))
        elif command == 'mattermost-close-channel':
            return_results(close_channel_command(CLIENT, args))
        elif command == 'mattermost-send-file':
            return_results(send_file_command(CLIENT, args))
        else:
            return_error('Unrecognized command: ' + demisto.command())

    except DemistoException as e:
        # For any other integration command exception, return an error
        return_error(f'Failed to execute {command} command. Error: {str(e)}.')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
