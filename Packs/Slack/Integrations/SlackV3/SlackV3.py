import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import asyncio
import concurrent
import logging.handlers
import ssl
import threading
from distutils.util import strtobool
import aiohttp
import slack_sdk
from urllib.parse import urlparse
from typing import TypedDict, Literal, get_args

from slack_sdk.errors import SlackApiError
from slack_sdk.socket_mode.aiohttp import SocketModeClient
from slack_sdk.socket_mode.request import SocketModeRequest
from slack_sdk.socket_mode.response import SocketModeResponse
from slack_sdk.web.async_client import AsyncWebClient
from slack_sdk.web.async_slack_response import AsyncSlackResponse
from slack_sdk.web.slack_response import SlackResponse

''' CONSTANTS '''

ALLOWED_HTTP_VERBS = Literal['POST', 'GET']
SEVERITY_DICT = {
    'Unknown': 0,
    'Low': 1,
    'Medium': 2,
    'High': 3,
    'Critical': 4
}

USER_TAG_EXPRESSION = '<@(.*?)>'
CHANNEL_TAG_EXPRESSION = '<#(.*?)>'
URL_EXPRESSION = r'<(https?://.+?)(?:\|.+)?>'
GUID_REGEX = r'(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}'
ENTITLEMENT_REGEX = fr'{GUID_REGEX}@(({GUID_REGEX})|(?:[\d_]+))_*(\|\S+)?\b'
COMMAND_REGEX = r"command.*?(?=;)"
MESSAGE_FOOTER = '\n**From Slack**'
MIRROR_TYPE = 'mirrorEntry'
INCIDENT_OPENED = 'incidentOpened'
INCIDENT_NOTIFICATION_CHANNEL = 'incidentNotificationChannel'
PLAYGROUND_INVESTIGATION_TYPE = 9
WARNING_ENTRY_TYPE = 11
POLL_INTERVAL_MINUTES: Dict[tuple, float] = {
    (0, 15): 1,
    (15, 60): 2,
    (60,): 5
}
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
OBJECTS_TO_KEYS = {
    'mirrors': 'investigation_id',
    'questions': 'entitlement',
    'users': 'id'
}
SYNC_CONTEXT = True
PROFILING_DUMP_ROWS_LIMIT = 20
MAX_SAMPLES = 10


class FileUploadParams(TypedDict):
    filename: str
    file: str                       # file path
    initial_comment: Optional[str]
    channel: str                    # channel ID
    thread_ts: Optional[str]        # thread ID


''' GLOBALS '''

USER_TOKEN: str
BOT_TOKEN: str
APP_TOKEN: str
PROXY_URL: Optional[str]
PROXIES: dict
DEDICATED_CHANNEL: str
ASYNC_CLIENT: slack_sdk.web.async_client.AsyncWebClient
CLIENT: slack_sdk.WebClient
USER_CLIENT: slack_sdk.WebClient
ALLOW_INCIDENTS: bool
INCIDENT_TYPE: str
SEVERITY_THRESHOLD: int
VERIFY_CERT: bool
SSL_CONTEXT: Optional[ssl.SSLContext]
QUESTION_LIFETIME: int
BOT_NAME: str
BOT_ICON_URL: str
MAX_LIMIT_TIME: int
PAGINATED_COUNT: int
ENABLE_DM: bool
DEFAULT_PERMITTED_NOTIFICATION_TYPES: List[str]
CUSTOM_PERMITTED_NOTIFICATION_TYPES: List[str]
PERMITTED_NOTIFICATION_TYPES: List[str]
COMMON_CHANNELS: dict
DISABLE_CACHING: bool
CHANNEL_NOT_FOUND_ERROR_MSG: str
BOT_ID: str
CACHED_INTEGRATION_CONTEXT: dict
CACHE_EXPIRY: float
MIRRORING_ENABLED: bool
FILE_MIRRORING_ENABLED: bool
LONG_RUNNING_ENABLED: bool
DEMISTO_API_KEY: str
DEMISTO_URL: str
IGNORE_RETRIES: bool
EXTENSIVE_LOGGING: bool

''' HELPER FUNCTIONS '''


def get_war_room_url(url: str) -> str:
    # a workaround until this bug is resolved: https://jira-dc.paloaltonetworks.com/browse/CRTX-107526
    if is_xsiam():
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


def get_bot_id() -> str:
    """
    Gets the app bot ID

    Returns:
        The app bot ID
    """
    response = CLIENT.auth_test()
    return response.get('user_id')  # type: ignore


def test_module():
    """
    Sends a test message to the dedicated slack channel.
    """
    if not DEDICATED_CHANNEL and len(CUSTOM_PERMITTED_NOTIFICATION_TYPES) > 0:
        return_error(
            "When 'Types of Notifications to Send' is populated, a dedicated channel is required.")
    if not BOT_TOKEN.startswith("xoxb"):
        return_error("Invalid Bot Token.")
    if not APP_TOKEN.startswith("xapp"):
        return_error("Invalid App Token.")
    if USER_TOKEN and not USER_TOKEN.startswith("xoxp"):
        return_error("Invalid User Token.")
    elif not DEDICATED_CHANNEL and len(CUSTOM_PERMITTED_NOTIFICATION_TYPES) == 0:
        CLIENT.auth_test()  # type: ignore
        if USER_TOKEN:
            USER_CLIENT.auth_test()
    else:
        channel = get_conversation_by_name(DEDICATED_CHANNEL)
        if not channel:
            return_error(CHANNEL_NOT_FOUND_ERROR_MSG)
        message = 'Hi there! This is a test message.'

        CLIENT.chat_postMessage(channel=channel.get('id'), text=message)  # type: ignore

    # Status of mirroring check
    if MIRRORING_ENABLED and not LONG_RUNNING_ENABLED:
        demisto.error('Mirroring is enabled, however long running is disabled. For mirrors to work correctly,'
                      ' long running must be enabled.')

    # validation for permitted_notifications since not all the options are supported by xsiam
    if is_xsiam():
        xsiam_permitted_notification_types = {"investigationClosed", "investigationDeleted", "incidentReminderSLA",
                                              "taskCompleted", "failedFetchIncidents", "mentionNew", "mentionOld"}

        if not_allowed := set(CUSTOM_PERMITTED_NOTIFICATION_TYPES).difference(xsiam_permitted_notification_types):
            demisto.error(f"The {','.join(sorted(not_allowed))} 'Types of Notifications to Send' are not supported in XSIAM.")

    demisto.results('ok')


def get_current_utc_time() -> datetime:
    """
    Returns:
        The current UTC time.
    """
    return datetime.utcnow()


def next_expiry_time() -> float:
    """
    Returns:
        A float representation of a new expiry time with an offset of 5 seconds
    """
    now = datetime.now(timezone.utc)
    unix_timestamp = now.timestamp()
    unix_timestamp_plus_5_seconds = unix_timestamp + 5
    return unix_timestamp_plus_5_seconds


def format_user_not_found_error(user: str) -> str:
    err_str = f'User {user} not found in Slack'
    if DISABLE_CACHING:
        err_str += ' and Disable Caching of Users and Channels is enabled. While caching is checked, it is advised to' \
                   ' perform actions using a users email. If this command worked previously for you, you may try' \
                   ' disabling the Disable Caching parameter from the instance configuration, however, this is not' \
                   ' recommended. Please refer to https://xsoar.pan.dev/docs/reference/integrations/slack-v3#caching' \
                   ' for more details.'
    return err_str


def return_user_filter(user_to_search: str, users_list):
    """
    Looks through the inputted list and if the user to search for exists, will return the user. Otherwise, it will
    return an empty dict

    Args:
        user_to_search: The user we are searching for
        users_list: A list of user dictionaries to search through

    Returns:
        The dict which matched the user to search for if one was found, else an empty dict.
    """
    users_filter = list(filter(lambda u: u.get('name', '').lower() == user_to_search
                                         or u.get('profile', {}).get('display_name', '').lower() == user_to_search
                                         or u.get('profile', {}).get('email', '').lower() == user_to_search
                                         or u.get('profile', {}).get('real_name', '').lower() == user_to_search,
                               users_list))
    if users_filter:
        return users_filter[0]
    else:
        return {}


def get_user_by_email(user_to_search: str) -> dict:
    """
    Searches for a user when given the user's email.

    Args:
        user_to_search: the user's email we are searching for.
    Returns:
        Formatted user results if a user is found.
    """
    if not re.match(emailRegex, user_to_search):
        raise ValueError('must provide user email')

    _body = {
        'email': user_to_search
    }
    response = send_slack_request_sync(CLIENT, 'users.lookupByEmail', http_verb='GET', body=_body)
    user = response.get('user', {})  # type: ignore

    if not user:
        err_str = format_user_not_found_error(user_to_search)
        demisto.results({
            'Type': WARNING_ENTRY_TYPE,
            'Contents': err_str,
            'ContentsFormat': formats['text']
        })
        return {}
    else:
        return format_user_results(user)


def add_user_to_context(user: dict, integration_context=None):
    """
    In some cases, we want to save user data to the integration context.

    Args:
        integration_context: The current context for the instance of the Slack which executed the command.
        user: The context safe version of a user's data to insert into the context.
    """
    if integration_context.get('users'):
        users = json.loads(integration_context['users'])
        users.append(user)
    else:
        users = [user]
    set_to_integration_context_with_retries({'users': users}, OBJECTS_TO_KEYS, SYNC_CONTEXT)


def paginated_search_for_user(user_to_search: str):
    """
    When a user cannot be found via the context or users.lookupByEmail, ONLY if DISABLE_CACHING is false, will we attempt
    to paginate through the Slack users.list results. Please note, for large workspaces, this action can exceed the
    timeout limit for the command which triggered it.

    Args:
        user_to_search: String representation of the user we are looking for. Can be user_name, display_name, real_name
    Returns:
        If a user is found, will return a context safe version of the user found. Else, will return an empty dict.
    """
    demisto.debug(f"Attempting to fetch data for {user_to_search} from Slack API.")
    body = {
        'limit': PAGINATED_COUNT
    }

    response = send_slack_request_sync(CLIENT, 'users.list', http_verb='GET', body=body)
    while True:
        workspace_users = response['members'] if response and response.get('members',
                                                                           []) else []
        cursor = response.get('response_metadata', {}).get('next_cursor')  # type: ignore[call-overload]
        user = return_user_filter(user_to_search.lower(), workspace_users)  # type: ignore[call-overload]
        if user:
            break
        if not cursor:
            break
        body = body.copy()  # strictly for unit testing purposes
        body.update({'cursor': cursor})
        response = send_slack_request_sync(CLIENT, 'users.list', http_verb='GET', body=body)

    if user:
        demisto.debug(f"User {user_to_search} was found.")
        return format_user_results(user)
    else:
        demisto.info(format_user_not_found_error(user=user_to_search))
        return {}


def format_user_results(user: dict):
    """
    Formats and truncates the user result from the Slack API

    Args:
        user: The user response retrieved from the Slack API
    Returns:
        Formatted and truncated version of the result which is context safe.
    """
    return {
        'name': user.get('name'),
        'id': user.get('id'),
        'profile': {
            'email': user.get('profile', {}).get('email', ''),
            'real_name': user.get('profile', {}).get('real_name', ''),
            'display_name': user.get('profile', {}).get('display_name', ''),
        }
    }


def get_user_by_name_without_caching(user_to_search: str) -> dict:
    """
    When Disable Caching is true, we look for the user by email only.

    Args:
        user_to_search: The user's email
    Returns:
        A slack user object
    """
    user = {}
    if re.match(emailRegex, user_to_search):
        demisto.debug(f"Checking via API for email of {user_to_search}")
        user = get_user_by_email(user_to_search)
    return user


def get_user_by_name_with_caching(user_to_search, add_to_context):
    """
    When Disable Caching is false, we look for the user first in the context. If the user is not found, then we proceed to
    search for the user by email, if that fails, then we will search for the user using a paginated call.

    Args:
        user_to_search: The user's email
    Returns:
        A slack user object
    """
    user = {}
    integration_context = get_integration_context(SYNC_CONTEXT)
    if integration_context.get('users'):
        demisto.debug(f"Checking in context for {user_to_search}")
        # Check if we already have the user to prevent call to users.lookupByEmail
        users = json.loads(integration_context['users'])
        user = return_user_filter(user_to_search.lower(), users)

    if not user and re.match(emailRegex, user_to_search):
        demisto.debug(f"Checking via API for email of {user_to_search}")
        user = get_user_by_email(user_to_search)
        if user and add_to_context:
            integration_context = get_integration_context(SYNC_CONTEXT)
            add_user_to_context(user=user, integration_context=integration_context)
    if not user:
        demisto.debug(f"Couldn't find {user_to_search} and caching is disabled. Checking API")
        user = paginated_search_for_user(user_to_search)
        demisto.debug(f"Found {user_to_search} - {user}")
        if user and add_to_context:
            integration_context = get_integration_context(SYNC_CONTEXT)
            add_user_to_context(user=user, integration_context=integration_context)
    return user


def get_user_by_name(user_to_search: str, add_to_context: bool = True) -> dict:
    """
    Gets a slack user by a user name

    Args:
        user_to_search: The user name or email
        add_to_context: Whether to update the integration context

    Returns:
        A slack user object
    """
    if DISABLE_CACHING:
        return get_user_by_name_without_caching(user_to_search=user_to_search)
    else:
        return get_user_by_name_with_caching(user_to_search=user_to_search, add_to_context=add_to_context)


def get_user_by_id(user_id: str) -> dict:
    """
    Retrieves a Slack user's details by user ID.

    Args:
        user_id: The user's unique ID in Slack.

    Returns:
        Formatted user results if a user is found.
    """
    if not user_id:
        raise ValueError('User ID must be provided')

    _body = {
        'user': user_id
    }
    response = send_slack_request_sync(CLIENT, 'users.info', http_verb='GET', body=_body)
    user = response.get('user', {})  # type: ignore

    if not user:
        err_str = format_user_not_found_error(user_id)
        demisto.results({
            'Type': WARNING_ENTRY_TYPE,
            'Contents': err_str,
            'ContentsFormat': formats['text']
        })
        return {}
    else:
        return format_user_results(user)


def search_slack_users(users: Union[list, str]) -> list:
    """
    Search given users in Slack

    Args:
        users: The users to find

    Returns:
        The slack users
    """
    slack_users = []

    if not isinstance(users, list):
        users = [users]

    # Filter NoneType elements from the user list
    users = list(filter(lambda x: x, users))

    for user in users:
        slack_user = get_user_by_name(user)
        if not slack_user:
            err_str = format_user_not_found_error(user=user)
            demisto.results({
                'Type': WARNING_ENTRY_TYPE,
                'Contents': err_str,
                'ContentsFormat': formats['text']
            })
        else:
            slack_users.append(slack_user)
    return slack_users


def find_mirror_by_investigation() -> dict:
    """
    Finds a mirrored channel by the mirrored investigation

    Returns:
        The mirror object
    """
    mirror: dict = {}
    investigation = demisto.investigation()
    if investigation:
        integration_context = get_integration_context(SYNC_CONTEXT)
        if integration_context.get('mirrors'):
            mirrors = json.loads(integration_context['mirrors'])
            investigation_filter = list(filter(lambda m: investigation.get('id') == m['investigation_id'],
                                               mirrors))
            if investigation_filter:
                mirror = investigation_filter[0]

    return mirror


def set_name_and_icon(body: dict, method: str):
    """
    If provided, sets a name and an icon for the bot if a message is sent.
    Args:
        body: The message body.
        method: The current API method.
    """
    if method == 'chat.postMessage':
        if BOT_NAME:
            body['username'] = BOT_NAME
        if BOT_ICON_URL:
            body['icon_url'] = BOT_ICON_URL


def validate_slack_request_args(
    http_verb: str,
    method: Optional[str],
    file_upload_params: Optional[FileUploadParams],
) -> None:
    """
    Performs basic pre-validation on the Slack request arguments

    Args:
        http_verb: The HTTP method to use.
        method: The Slack web API method to use (not relevant when file_upload_params are specified).
        file_upload_params: An instance of FileUploadParams (for uploading using the file-upload APIs).

    Raises:
        ValueError: If neither method nor file_upload_params are specified, or if an invalid http_verb is used.
    """
    if not method and not file_upload_params:
        # empty method is only allowed when uploading a file
        raise ValueError('Either a Slack web API method or file_upload_params need to specified')

    allowed_http_verb_values: tuple = get_args(ALLOWED_HTTP_VERBS)
    if http_verb not in allowed_http_verb_values:
        raise ValueError(f'Invalid http_verb: {http_verb}. Allowed values: {", ".join(allowed_http_verb_values)}.')


def send_slack_request_sync(
    client: slack_sdk.WebClient,
    method: str = '',  # irrelevant when file_upload_params are specified
    http_verb: ALLOWED_HTTP_VERBS = 'POST',
    body: Optional[dict] = None,
    file_upload_params: Optional[FileUploadParams] = None,
) -> SlackResponse:
    """
    Sends a request to slack API while handling rate limit errors.

    Args:
        client: The Synchronous Slack client.
        method: The Slack web API method to use (irrelevant when file_upload_params are specified).
        http_verb: The HTTP method to use.
        body: The request body.
        file_upload_params: An instance of FileUploadParams (for uploading using the file-upload APIs).

    Returns:
        The Slack API response.
    """
    validate_slack_request_args(http_verb=http_verb, method=method, file_upload_params=file_upload_params)

    if body is None:
        body = {}

    set_name_and_icon(body, method)
    total_try_time = 0
    while True:
        try:
            demisto.debug(f'Sending slack {method} (sync). Body is: {str(body)}')
            if file_upload_params:
                # When file_upload_params provided, use three-stage `file_upload_v2` wrapper method in Slack's SDK client
                # https://tools.slack.dev/python-slack-sdk/web/#uploading-files
                response = client.files_upload_v2(**file_upload_params)
            elif http_verb == 'POST':
                response = client.api_call(method, json=body)
            else:
                response = client.api_call(method, http_verb='GET', params=body)
        except SlackApiError as api_error:
            response = api_error.response
            headers = response.headers  # type: ignore
            if 'Retry-After' in headers:
                demisto.info(f'Got rate limit error (sync). Body is: {str(body)}\n{api_error}')
                retry_after = int(headers['Retry-After'])
                total_try_time += retry_after
                if total_try_time < MAX_LIMIT_TIME:
                    time.sleep(retry_after)
                    continue
            raise
        break

    return response  # type: ignore


async def send_slack_request_async(
    client: AsyncWebClient,
    method: str = '',    # irrelevant when file_upload_params are specified
    http_verb: ALLOWED_HTTP_VERBS = 'POST',
    body: Optional[dict] = None,
    file_upload_params: Optional[FileUploadParams] = None,
) -> SlackResponse:
    """
    Sends an async request to slack API while handling rate limit errors.

    Args:
        client: The Asynchronous Slack client.
        method: The Slack web API method to use (irrelevant when file_upload_params are specified).
        http_verb: The HTTP method to use.
        body: The request body.
        file_upload_params: An instance of FileUploadParams (for uploading using the file upload APIs).

    Returns:
        The Slack API response.
    """
    validate_slack_request_args(http_verb=http_verb, method=method, file_upload_params=file_upload_params)

    if body is None:
        body = {}

    set_name_and_icon(body, method)
    total_try_time = 0
    while True:
        try:
            demisto.debug(f'Sending slack {method} (async). Body is: {str(body)}')
            if file_upload_params:
                # When file_upload_params provided, use three-stage `file_upload_v2` wrapper method in Slack's SDK client
                # https://tools.slack.dev/python-slack-sdk/web/#uploading-files
                response = await client.files_upload_v2(**file_upload_params)
            elif http_verb == 'POST':
                response = await client.api_call(method, json=body)
            else:
                response = await client.api_call(method, http_verb='GET', params=body)
        except SlackApiError as api_error:
            demisto.debug(f'Got rate limit error (async). Body is: {str(body)}\n{api_error}')
            response = api_error.response
            headers = response.headers
            if 'Retry-After' in headers:
                retry_after = int(headers['Retry-After'])
                total_try_time += retry_after
                if total_try_time < MAX_LIMIT_TIME:
                    await asyncio.sleep(retry_after)
                    continue
            raise
        break

    return response  # type: ignore


''' MIRRORING '''


async def get_slack_name(slack_id: str, client: AsyncWebClient) -> str:
    """
    Get the slack name of a provided user or channel by its ID

    Args:
        client: The slack client
        slack_id: The slack user or channel ID

    Returns:
        The slack user or channel name
    """
    if not slack_id:
        return ''

    integration_context = get_integration_context(SYNC_CONTEXT)
    prefix = slack_id[0]
    slack_name = ''

    if prefix in ['C', 'D', 'G']:
        slack_id = slack_id.split('|')[0]
        conversation: dict = {}
        if integration_context.get('conversations'):
            conversations = list(filter(lambda c: c['id'] == slack_id,
                                        json.loads(integration_context['conversations'])))
            if conversations:
                conversation = conversations[0]
        if not conversation:
            conversation = await client.conversations_info(channel=slack_id)  # type: ignore
        slack_name = conversation.get('name', '')
    elif prefix == 'U':
        user: dict = {}
        if integration_context.get('users'):
            users = list(filter(lambda u: u['id'] == slack_id, json.loads(integration_context['users'])))
            if users:
                user = users[0]
        if not user:
            user = await client.users_info(user=slack_id)  # type: ignore

        slack_name = user.get('name', '')

    return slack_name


async def clean_message(message: str, client: AsyncWebClient) -> str:
    """
    Prettifies a slack message - replaces tags and URLs with clean expressions

    Args:
        message: The slack message
        client: The slack client

    Returns:
        The clean slack message
    """
    matches = re.findall(USER_TAG_EXPRESSION, message)
    matches += re.findall(CHANNEL_TAG_EXPRESSION, message)
    message = re.sub(USER_TAG_EXPRESSION, r'\1', message)
    message = re.sub(CHANNEL_TAG_EXPRESSION, r'\1', message)
    for match in matches:
        slack_name = await get_slack_name(match, client)
        message = message.replace(match, slack_name)

    resolved_message = re.sub(URL_EXPRESSION, r'\1', message)

    return resolved_message


def invite_users_to_conversation(conversation_id: str, users_to_invite: list):
    """
    Invites users to a provided conversation using a provided slack client with a channel token.

    Args:
        conversation_id: The slack conversation ID to invite the users to.
        users_to_invite: The user slack IDs to invite.
    """
    for user in users_to_invite:
        try:
            body = {
                'channel': conversation_id,
                'users': user
            }
            send_slack_request_sync(CLIENT, 'conversations.invite', body=body)

        except SlackApiError as e:
            message = str(e)
            if "already_in_channel" in message:
                continue
            elif message.find('cant_invite_self') == -1:
                raise


def kick_users_from_conversation(conversation_id: str, users_to_kick: list):
    """
    Kicks users from a provided conversation using a provided slack client with a channel token.

    Args:
        conversation_id: The slack conversation ID to kick the users from.
        users_to_kick: The user slack IDs to kick.
    """
    for user in users_to_kick:
        try:
            body = {
                'channel': conversation_id,
                'user': user
            }
            send_slack_request_sync(CLIENT, 'conversations.kick', body=body)
        except SlackApiError as e:
            message = str(e)
            if message.find('cant_invite_self') == -1:
                raise


def mirror_investigation():
    """
    Updates the integration context with a new or existing mirror.
    """
    if MIRRORING_ENABLED and not LONG_RUNNING_ENABLED:
        demisto.error('Mirroring is enabled, however long running is disabled. For mirrors to work correctly,'
                      ' long running must be enabled.')
    mirror_type = demisto.args().get('type', 'all')
    auto_close = demisto.args().get('autoclose', 'true')
    mirror_direction = demisto.args().get('direction', 'both')
    mirror_to = demisto.args().get('mirrorTo', 'group')
    channel_name = demisto.args().get('channelName', '')
    channel_topic = demisto.args().get('channelTopic', '')
    kick_admin = bool(strtobool(demisto.args().get('kickAdmin', 'false')))
    private = argToBoolean(demisto.args().get('private', 'false'))

    investigation = demisto.investigation()
    demisto.debug(f'SlackV3 integration: This is the investigation - {investigation}')

    if investigation.get('type') == PLAYGROUND_INVESTIGATION_TYPE:
        return_error('Can not perform this action in playground.')

    integration_context = get_integration_context(SYNC_CONTEXT)
    demisto.debug(f'SlackV3 integration: This is the integration context - {integration_context}')

    if not integration_context or not integration_context.get('mirrors', []):
        mirrors: list = []
    else:
        mirrors = json.loads(integration_context['mirrors'])

    investigation_id = investigation.get('id')
    send_first_message = False
    current_mirror = list(filter(lambda m: m['investigation_id'] == investigation_id, mirrors))
    channel_filter: list = []
    if channel_name:
        channel_filter = list(filter(lambda m: m['channel_name'] == channel_name, mirrors))
        demisto.debug(f'SlackV3 integration: This is the channel filter - {channel_filter}')

    if not current_mirror:
        channel_name = channel_name or f'incident-{investigation_id}'

        if not channel_filter:
            body = {
                'name': channel_name
            }

            if mirror_to != 'channel' or private:
                body['is_private'] = True

            conversation = send_slack_request_sync(CLIENT, 'conversations.create',  # type: ignore
                                                   body=body).get('channel', {})
            conversation_name = conversation.get('name')
            conversation_id = conversation.get('id')

            # Get the bot ID so we can invite him
            if integration_context.get('bot_id'):
                bot_id = integration_context['bot_id']
            else:
                bot_id = get_bot_id()
                set_to_integration_context_with_retries({'bot_id': bot_id}, OBJECTS_TO_KEYS, SYNC_CONTEXT)

            invite_users_to_conversation(conversation_id, [bot_id])  # type: ignore

            send_first_message = True
        else:
            mirrored_channel = channel_filter[0]
            conversation_id = mirrored_channel['channel_id']
            conversation_name = mirrored_channel['channel_name']

        mirror = {
            'channel_id': conversation_id,
            'channel_name': conversation_name,
            'investigation_id': investigation.get('id'),
            'mirror_type': mirror_type,
            'mirror_direction': mirror_direction,
            'mirror_to': mirror_to,
            'auto_close': bool(strtobool(auto_close)),
            'mirrored': False
        }

    else:
        mirror = mirrors.pop(mirrors.index(current_mirror[0]))
        conversation_id = mirror['channel_id']
        if mirror_type:
            mirror['mirror_type'] = mirror_type
        if auto_close:
            mirror['auto_close'] = bool(strtobool(auto_close))
        if mirror_direction:
            mirror['mirror_direction'] = mirror_direction
        if mirror_to and mirror['mirror_to'] != mirror_to:
            return_error('Cannot change the Slack channel type from XSOAR.')
        if channel_name:
            return_error('Cannot change the Slack channel name.')
        if channel_topic:
            return_error('Cannot change the Slack channel topic.')
        conversation_name = mirror['channel_name']
        mirror['mirrored'] = False

    set_topic = False
    if channel_topic:
        set_topic = True
    else:
        mirror_name = f'incident-{investigation_id}'
        channel_filter = list(filter(lambda m: m['channel_name'] == conversation_name, mirrors))
        if 'channel_topic' in mirror:
            channel_topic = mirror['channel_topic']
        elif channel_filter:
            channel_mirror = channel_filter[0]
            channel_topic = channel_mirror['channel_topic']
        else:
            channel_topic = ''
        mirrored_investigations_ids = [f'incident-{m["investigation_id"]}' for m in channel_filter]
        if not channel_topic or channel_topic.find('incident-') != -1:
            new_topic = ', '.join(mirrored_investigations_ids + [mirror_name])
            if channel_topic != new_topic:
                channel_topic = new_topic
                set_topic = True

    if set_topic:
        body = {
            'channel': conversation_id,
            'topic': channel_topic
        }
        send_slack_request_sync(CLIENT, 'conversations.setTopic', body=body)
    mirror['channel_topic'] = channel_topic

    mirrors.append(mirror)
    demisto.debug(f'SlackV3 integration: This is the mirrors list - {mirrors}')

    if DISABLE_CACHING:
        set_to_integration_context_with_retries({'mirrors': mirrors}, OBJECTS_TO_KEYS, SYNC_CONTEXT)
    else:
        if not integration_context or not integration_context.get('conversations', []):
            conversations: list = []
        else:
            conversations = json.loads(integration_context['conversations'])
        conversations.append({'name': conversation_name, 'id': conversation_id})
        set_to_integration_context_with_retries({'mirrors': mirrors, 'conversations': conversations}, OBJECTS_TO_KEYS,
                                                SYNC_CONTEXT)

    if send_first_message:
        server_links = demisto.demistoUrls()
        server_link = server_links.get('server')
        message = (f'This channel was created to mirror incident {investigation_id}.'
                   f' \n View it on: {server_link}#/WarRoom/{investigation_id}')
        body = {
            'text': message,
            'channel': conversation_id
        }

        send_slack_request_sync(CLIENT, 'chat.postMessage', body=body)

    if kick_admin:
        body = {
            'channel': conversation_id
        }
        send_slack_request_sync(CLIENT, 'conversations.leave', body=body)

    demisto.results(f'Investigation mirrored successfully, channel: {conversation_name}')


def long_running_loop():
    tts = 15 if MIRRORING_ENABLED else 60
    while True:
        error = ''
        try:
            if MIRRORING_ENABLED:
                check_for_mirrors()
            check_for_unanswered_questions()
            if EXTENSIVE_LOGGING:
                demisto.debug(f'Number of threads currently - {threading.active_count()}')
                stats, _ = slack_get_integration_context_statistics()
                demisto.debug(f'Integration Context Stats\n_____________\n{stats}')
            if SlackLog.messages:
                text = 'Full Integration Log:\n' + '\n'.join(SlackLog.messages)
                demisto.info(f"{text}")
                SlackLog.messages = []
            time.sleep(tts)
        except requests.exceptions.ConnectionError as e:
            error = f'Could not connect to the Slack endpoint: {str(e)}'
        except Exception as e:
            error = f'An error occurred: {e}'
        finally:
            demisto.updateModuleHealth('')
            if error:
                demisto.error(error)
                demisto.updateModuleHealth(error)


def get_poll_minutes(current_time: datetime, sent: Optional[str]) -> float:
    """
    Get the interval to wait before polling again in minutes.

    Args:
        current_time: The current time.
        sent: The time when the polling request was sent.

    Returns:
        Total minutes to wait before polling.
    """
    poll_time_minutes = 1.0
    if sent:
        sent_time = datetime.strptime(sent, DATE_FORMAT)
        total_delta = current_time - sent_time
        total_minutes = total_delta.total_seconds() / 60

        for minute_range, interval in POLL_INTERVAL_MINUTES.items():
            if len(minute_range) > 1 and total_minutes > minute_range[1]:
                continue
            poll_time_minutes = interval
            break

    return poll_time_minutes


def answer_question(text: str, question: dict, email: str = ''):
    entitlement = question.get('entitlement', '')
    content, guid, incident_id, task_id = extract_entitlement(entitlement, text)
    try:
        demisto.handleEntitlementForUser(incident_id, guid, email, content, task_id)
    except Exception as e:
        demisto.debug(f'Failed handling entitlement {entitlement}: {str(e)}')
    question['remove'] = True
    return incident_id


def check_for_unanswered_questions():
    integration_context = fetch_context()
    questions = integration_context.get('questions', None)
    if questions:
        questions = json.loads(questions)
        now = get_current_utc_time()
        now_string = datetime.strftime(now, DATE_FORMAT)
        updated_questions = []

        for question in questions:
            if question.get('expiry'):
                # Check if the question expired - if it did, answer it with the default response
                # and remove it
                expiry = datetime.strptime(question['expiry'], DATE_FORMAT)
                if expiry < now:
                    _ = answer_question(question.get('default_response'), question, email='')
                    updated_questions.append(question)
                    continue
            # Check if it has been enough time(determined by the POLL_INTERVAL_MINUTES parameter)
            # since the last polling time. if not, continue to the next question until it has.
            if question.get('last_poll_time'):
                last_poll_time = datetime.strptime(question['last_poll_time'], DATE_FORMAT)
                delta = now - last_poll_time
                minutes = delta.total_seconds() / 60
                sent = question.get('sent', None)
                poll_time_minutes = get_poll_minutes(now, sent)
                if minutes < poll_time_minutes:
                    continue
            question['last_poll_time'] = now_string
            updated_questions.append(question)
        if updated_questions:
            set_to_integration_context_with_retries({'questions': questions}, OBJECTS_TO_KEYS, SYNC_CONTEXT)


def check_for_mirrors():
    """
    Checks for newly created mirrors and handles the mirroring process
    """
    integration_context = fetch_context()
    if integration_context.get('mirrors'):
        mirrors = json.loads(integration_context['mirrors'])
        updated_mirrors = []
        updated_users = []
        for mirror in mirrors:
            if not mirror['mirrored']:
                investigation_id = mirror['investigation_id']
                mirror = mirrors.pop(mirrors.index(mirror))
                if mirror['mirror_to'] and mirror['mirror_direction'] and mirror['mirror_type']:
                    mirror_type = mirror['mirror_type']
                    auto_close = mirror['auto_close']
                    direction = mirror['mirror_direction']
                    channel_id = mirror['channel_id']
                    if isinstance(auto_close, str):
                        auto_close = bool(strtobool(auto_close))
                    users: List[Dict] = demisto.mirrorInvestigation(investigation_id,
                                                                    f'{mirror_type}:{direction}', auto_close)
                    if mirror_type != 'none':
                        try:
                            invited_users = invite_to_mirrored_channel(channel_id, users)
                            updated_users.extend(invited_users)
                        except Exception as error:
                            demisto.error(f"Could not invite investigation users to the mirrored channel: {error}")

                    mirror['mirrored'] = True
                    updated_mirrors.append(mirror)
                else:
                    demisto.info(f'Could not mirror {investigation_id}')

        if updated_mirrors:
            context = {'mirrors': updated_mirrors}
            if updated_users:
                context['users'] = updated_users

            set_to_integration_context_with_retries(context, OBJECTS_TO_KEYS, SYNC_CONTEXT)
        return


def invite_to_mirrored_channel(channel_id: str, users: List[Dict]) -> list:
    """
    Invite the relevant users to a mirrored channel
    Args:
        channel_id: The mirrored channel
        users: The users to invite, each a dict of username and email

    Returns:
        users: The slack users that were invited
    """
    slack_users = []
    for user in users:
        user_email = user.get('email', '')
        user_name = user.get('username', '')

        # Try to invite by XSOAR email, if not found then by XSOAR user name
        slack_user = get_user_by_name(user_email, False) if user_email else None
        if not slack_user and user_name:
            slack_user = get_user_by_name(user_name, False)
        if slack_user:
            slack_users.append(slack_user)
        else:
            err_str = format_user_not_found_error(user=user_name)
            demisto.results({
                'Type': WARNING_ENTRY_TYPE,
                'Contents': err_str,
                'ContentsFormat': formats['text']
            })

    users_to_invite = [user.get('id') for user in slack_users]
    invite_users_to_conversation(channel_id, users_to_invite)

    return slack_users


def extract_entitlement(entitlement: str, text: str) -> tuple[str, str, str, str]:
    """
    Extracts entitlement components from an entitlement string
    Args:
        entitlement: The entitlement itself
        text: The actual reply text

    Returns:
        Entitlement components
    """
    parts = entitlement.split('@')
    guid = parts[0]
    id_and_task = parts[1].split('|')
    incident_id = id_and_task[0]
    task_id = ''

    if len(id_and_task) > 1:
        task_id = id_and_task[1]
    content = text.replace(entitlement, '', 1)

    return content, guid, incident_id, task_id


class SlackLogger(IntegrationLogger):
    def __init__(self):
        super().__init__()
        self.level = logging.INFO

    def info(self, message):
        text = self.encode(message)
        self.messages.append(text)

    def debug(self, message):
        text = self.encode(message)
        self.messages.append(text)

    def error(self, message):
        text = self.encode(message)
        self.messages.append(text)

    def exception(self, message):
        text = self.encode(message)
        self.messages.append(text)

    def warning(self, message):
        text = self.encode(message)
        self.messages.append(text)

    def set_logging_level(self, debug: bool = True):
        if debug:
            self.level = logging.DEBUG
        else:
            self.level = logging.INFO


SlackLog = SlackLogger()


async def slack_loop():
    try:
        exception_await_seconds = 1
        while True:
            SlackLog.set_buffering(state=True)
            SlackLog.set_logging_level(debug=EXTENSIVE_LOGGING)
            client = SocketModeClient(
                app_token=APP_TOKEN,
                web_client=ASYNC_CLIENT,
                logger=SlackLog,  # type: ignore
                auto_reconnect_enabled=True,
                trace_enabled=EXTENSIVE_LOGGING,
            )
            if not VERIFY_CERT:
                # SocketModeClient does not respect environment variables for ssl verification.
                # Instead we use a custom session.
                session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(verify_ssl=VERIFY_CERT))
                client.aiohttp_client_session = session
            client.socket_mode_request_listeners.append(listen)  # type: ignore
            try:
                await client.connect()
                # After successful connection, we reset the backoff time.
                exception_await_seconds = 1
                await asyncio.sleep(float("inf"))
            except Exception as e:
                demisto.debug(f"Exception in long running loop, waiting {exception_await_seconds} - {e}")
                await asyncio.sleep(exception_await_seconds)
                exception_await_seconds *= 2
            finally:
                try:
                    await session.close()
                except Exception as e:
                    demisto.debug(f"Failed to close client. - {e}")
    except Exception as e:
        demisto.error(f"An error has occurred while trying to create the socket client. {e}")


async def handle_listen_error(error: str):
    """
    Logs an error and updates the module health accordingly.

    Args:
        error: The error string.
    """
    demisto.error(error)
    demisto.updateModuleHealth(error)


async def start_listening():
    """
    Starts a Slack SocketMode client and checks for mirrored incidents.
    """
    try:
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_in_executor(executor, long_running_loop)
        await slack_loop()
    except Exception as e:
        demisto.error(f"An error has occurred while gathering the loop tasks. {e}")


async def handle_dm(user: dict, text: str, client: AsyncWebClient):
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
    if message.find('incident') != -1 and (message.find('create') != -1
                                           or message.find('open') != -1
                                           or message.find('new') != -1):
        user_email = user.get('profile', {}).get('email', '')
        user_name = user.get('name', '')
        demisto_user = demisto.findUser(email=user_email) if user_email else demisto.findUser(username=user.get('name'))

        if not demisto_user and not ALLOW_INCIDENTS:
            data = 'You are not allowed to create incidents.'
        else:
            try:
                data = await translate_create(text, user_name, user_email, demisto_user)
            except Exception as e:
                data = f'Failed creating incidents: {str(e)}'
    else:
        try:
            data = demisto.directMessage(text, user.get('name'), user.get('profile', {}).get('email'), ALLOW_INCIDENTS)
        except Exception as e:
            data = str(e)

    if not data:
        data = 'Sorry, I could not perform the selected operation.'
    body = {
        'users': user.get('id')
    }
    im = await send_slack_request_async(client, 'conversations.open', body=body)
    channel = im.get('channel', {}).get('id')  # type: ignore
    body = {
        'text': data,
        'channel': channel
    }

    await send_slack_request_async(client, 'chat.postMessage', body=body)


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


def add_req_data_to_incidents(incidents: list, request_fields: dict) -> list:
    """
    Adds the request_fields as a rawJSON to every created incident for further information on the incident
    """
    for incident in incidents:
        incident['rawJSON'] = json.dumps(request_fields)
    return incidents


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


async def create_incidents(incidents: list, user_name: str, user_email: str, user_demisto_id: str = '') -> dict:
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


def is_bot_message(data: dict) -> bool:
    """
    Determines if the message received was created by a bot or not.
    :param data: dict: The payload sent with the message
    :return: bool: True indicates the message was from a Bot, False indicates it was from an individual
    """
    subtype = data.get('subtype', '')
    message_bot_id = data.get('bot_id', '')
    event: dict = data.get('event', {})
    if subtype == 'bot_message' or message_bot_id or event.get('bot_id', None):
        return True
    elif event.get('subtype') == 'bot_message':
        return True
    return bool(not (event.get('user') or data.get('user', {}).get('id') or data.get('envelope_id')))


async def get_user_details(user_id: str) -> AsyncSlackResponse:
    """
    Performs the retrieval of the User object from the UserID which is sent as part of the payload.
    :param user_id: str: The ID of the user to perform the lookup on.
    :return: AsyncSlackResponse: An AsyncSlackResponse object which is a dictionary of the user object.
    """
    user = await ASYNC_CLIENT.users_info(user=user_id)
    return user.get('user', {})  # type: ignore


def search_text_for_entitlement(text: str, user: AsyncSlackResponse) -> str:
    """
    In some cases, a user may send an entitlement string as part of the text, this function will search the text to see
    if an entitlement string exists, and if so, will handle the entitlement and return a default reply
    :param text: str: The text message found in the events payload
    :param user: AsyncSlackResponse: The user object returned from get_user_details
    :return: str: Returns a default response if an entitlement is found, otherwise an empty string.
    """
    entitlement_match = re.search(ENTITLEMENT_REGEX, text)
    if entitlement_match:
        content, guid, incident_id, task_id = extract_entitlement(entitlement_match.group(), text)
        demisto.handleEntitlementForUser(
            incident_id, guid, user.get('profile', {}).get('email'), content, task_id)  # type: ignore

        return 'Thank you for your response.'
    else:
        return ''


async def process_entitlement_reply(
        entitlement_reply: str,
        user_id: str,
        action_text: str,
        response_url: str | None = None,
        channel: str | None = None,
        message_ts: str | None = None
):
    """
    Triggered when an entitlement reply is found, this function will update the original message with the reply message.
    :param entitlement_reply: str: The text to update the asking question with.
    :param user_id: str: ID of the user who answered the entitlement
    :param action_text: str: The text attached to the button, used for string replacement.
    :param response_url: str: The response URL to use for the update.
    :param channel: str: The channel ID of where the question exists.
    :param message_ts: str: The timestamp of the message. Acts as a unique ID.
    :return: None
    """
    if '{user}' in entitlement_reply:
        entitlement_reply = entitlement_reply.replace('{user}', f'<@{user_id}>')
    if '{response}' in entitlement_reply and action_text:
        entitlement_reply = entitlement_reply.replace('{response}', str(action_text))
    if response_url:
        requests.post(response_url, json={'text': entitlement_reply, 'replace_original': True})
    else:
        await send_slack_request_async(client=ASYNC_CLIENT, method='chat.update',
                                       body={
                                           'channel': channel,
                                           'ts': message_ts,
                                           'text': entitlement_reply,
                                           'blocks': []
                                       })


def is_dm(channel: str) -> bool:
    """
    Takes the channel ID and will see if the first letter of the ID is 'D'. If so, we know it's from a direct message.
    :param channel: str: The channel ID to check.
    :return: bool: Boolean indicating if the channel is a DM or not.
    """
    return bool(channel and channel[0] == 'D' and ENABLE_DM)


async def process_mirror(channel_id: str, text: str, user: AsyncSlackResponse):
    """
    Process messages which have been identified as possible mirrored messages. If so, we grab the context (cached), and
    check for a match of the channel_id in the cached mirrors. If we find one, we will update the mirror object and send
    the message to the corresponding investigation's war room as an entry.
    :param channel_id: str: The ID of the channel for the message event we recieved.
    :param text: str: The text of the message event to be sent to a war room.
    :param user: AsyncSlackResponse: The user object for the user who sent the message.
    :return: None
    """
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
            if mirror['mirror_to'] and mirror['mirror_direction'] and mirror['mirror_type']:
                investigation_id = mirror['investigation_id']
                mirror_type = mirror['mirror_type']
                auto_close = mirror['auto_close']
                direction = mirror['mirror_direction']
                if isinstance(auto_close, str):
                    auto_close = bool(strtobool(auto_close))
                demisto.info(f'Mirroring: {investigation_id}')
                demisto.mirrorInvestigation(investigation_id,
                                            f'{mirror_type}:{direction}', auto_close)
                mirror['mirrored'] = True
                mirrors.append(mirror)
                set_to_integration_context_with_retries({'mirrors': mirrors},
                                                        OBJECTS_TO_KEYS, SYNC_CONTEXT)

        investigation_id = mirror['investigation_id']
        await handle_text(ASYNC_CLIENT, investigation_id, text, user)  # type: ignore


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
                      f'Fetching new context')
        CACHE_EXPIRY = next_expiry_time()
        CACHED_INTEGRATION_CONTEXT = get_integration_context(SYNC_CONTEXT)

    return CACHED_INTEGRATION_CONTEXT


def handle_newly_created_channel(creator, channel):
    """
    Only triggered on a created_channel event type, this function checks if the creator of the channel was the bot or
    user and if so, will check if the channel is in the cached context. If the channel is not in the context already
    we will refresh the context.
    :param channel: The Channel ID of the created channel.
    :param creator: User ID of the creator of the new channel.
    :return: None
    """
    if creator == BOT_ID:
        if 'mirrors' in CACHED_INTEGRATION_CONTEXT:
            mirrors = json.loads(CACHED_INTEGRATION_CONTEXT['mirrors'])
            if len(mirrors) == 0:
                fetch_context(force_refresh=True)
                return
            mirror_filter = list(filter(lambda m: m['channel_id'] == channel, mirrors))
            if not mirror_filter:
                fetch_context(force_refresh=True)
                return
        else:
            fetch_context(force_refresh=True)
            return
    else:
        return


def reset_listener_health():
    demisto.updateModuleHealth("")
    demisto.info("SlackV3 - Event handled successfully.")


async def listen(client: SocketModeClient, req: SocketModeRequest):
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
    if req.envelope_id:
        response = SocketModeResponse(envelope_id=req.envelope_id)
        await client.send_socket_mode_response(response)
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

        # Check if the message is from a bot so we can quit processing ASAP
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

        # Check if slash command received. If so, ignore for now.
        if data.get('command', None):
            return

        # Check to see if the event is about a newly handled event.
        elif event.get('type') == 'channel_created' and MIRRORING_ENABLED:
            creator = event.get('channel', {}).get('creator', '')
            channel_id = event.get('channel', {}).get('id', '')
            handle_newly_created_channel(creator=creator, channel=channel_id)
            return

        # Sometimes we can receive message_changed events, we currently do not support these.
        if event.get('subtype') == 'message_changed':
            return

        # Check if the message is being sent directly to our bot.
        if is_dm(channel):
            user = await get_user_details(user_id=user_id)
            await handle_dm(user, text, ASYNC_CLIENT)  # type: ignore
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

        # If a message has made it here, we need to check if the message is being mirrored. If not, we will ignore it.
        if MIRRORING_ENABLED:
            user = await get_user_details(user_id=user_id)
            await process_mirror(channel, text, user)
        reset_listener_health()
        return
    except Exception as e:
        await handle_listen_error(f'Error occurred while listening to Slack: {e}')


async def get_user_by_id_async(client: AsyncWebClient, user_id: str) -> dict:
    """
    Get the details of a slack user by id asynchronously.
    Args:
        client: The slack web client to use.
        user_id: The id of the user.

    Returns:
        The slack user.
    """
    body = {
        'user': user_id
    }
    return (await send_slack_request_async(client, 'users.info', http_verb='GET', body=body)).get('user', {})


async def handle_text(client: AsyncWebClient, investigation_id: str, text: str, user: dict):
    """
    Handles text received in the Slack workspace (not DM)

    Args:
        client: The Slack client
        investigation_id: The mirrored investigation ID
        text: The received text
        user: The sender
    """
    if text:
        demisto.addEntry(id=investigation_id,
                         entry=await clean_message(text, client),
                         username=user.get('name', ''),
                         email=user.get('profile', {}).get('email', ''),
                         footer=MESSAGE_FOOTER
                         )


async def check_and_handle_entitlement(text: str, user: dict, thread_id: str) -> str:
    """
    Handles an entitlement message (a reply to a question)
    Args:
        text: The message text
        user: The user who sent the reply
        thread_id: The thread ID

    Returns:
        If the message contains entitlement, return a reply.
    """
    integration_context = fetch_context()
    questions = integration_context.get('questions', [])
    if questions and thread_id:
        questions = json.loads(questions)
        question_filter = list(filter(lambda q: q.get('thread') == thread_id, questions))
        if question_filter:
            question = question_filter[0]
            entitlement = question.get('entitlement')
            reply = question.get('reply', 'Thank you for your response.')
            content, guid, incident_id, task_id = extract_entitlement(entitlement, text)
            demisto.handleEntitlementForUser(incident_id, guid, user.get('profile', {}).get('email'), content,
                                             task_id)
            question['remove'] = True
            set_to_integration_context_with_retries({'questions': questions}, OBJECTS_TO_KEYS, SYNC_CONTEXT)

            return reply

    return ''


''' SEND '''


def search_conversation_in_params(conversation_to_search):
    if conversation_to_search in COMMON_CHANNELS:
        return {'name': conversation_to_search, 'id': COMMON_CHANNELS[conversation_to_search]}
    return None


def search_conversation_in_context(conversation_to_search):
    """
    Some channels are stored in the context if they were created by the integration or they are mirrored channels. This
    will attempt to find the conversation in the context.

    Args:
        conversation_to_search: The conversation name we are searching for.

    Returns:
        if found, the conversation dictionary will be returned.
    """
    conversation: dict = {}
    integration_context = get_integration_context(SYNC_CONTEXT)
    conversations = integration_context.get('conversations')
    if conversations:
        conversations = json.loads(conversations)
        conversation_filter = list(
            filter(
                lambda c: conversation_to_search == c.get('name', '').lower(),
                conversations
            )
        )
        if conversation_filter:
            conversation = conversation_filter[0]
        else:
            demisto.debug(
                f'Could not find slack channel "{conversation_to_search}" in integration context, searching via API')
    else:
        demisto.debug(f"No conversations were found in the context while searching for {conversation_to_search}")
    return conversation


def get_conversation_from_api_paginated(conversation_to_search):
    """
    Searches the Slack API for the conversation. Used only when DISABLE_CACHING is false.

    Args:
        conversation_to_search: The conversation name that we are searching for.

    Returns:
        A conversation object containing only the conversation name and ID if found.
    """
    body = {
        'types': 'private_channel,public_channel',
        'exclude_archived': True,
        'limit': PAGINATED_COUNT
    }
    response = send_slack_request_sync(CLIENT, 'conversations.list', http_verb='GET', body=body)

    while True:
        conversations = response['channels'] if response and response.get('channels') else []
        cursor = response.get('response_metadata', {}).get('next_cursor')  # type: ignore
        conversation_filter = list(filter(lambda c: c.get('name').lower() == conversation_to_search, conversations))
        if conversation_filter:
            break
        if not cursor:
            demisto.info("Reached the end of looking for a channel")
            break

        body = body.copy()  # strictly for unit-test purposes (test_get_conversation_by_name_paging)
        body.update({'cursor': cursor})
        response = send_slack_request_sync(CLIENT, 'conversations.list', http_verb='GET', body=body)
    if conversation_filter:
        conversation = conversation_filter[0]
        return {
            'name': conversation.get('name'),
            'id': conversation.get('id')
        }
    else:
        return {}


def save_conversation_to_context(conversation):
    """
    Pulls the context and will insert the conversation. Used only when DISABLE_CACHING is false as it can cause the context
    to grow to unsustainable sizes.

    Args:
        conversation: The conversation to be inserted. Should contain ONLY the conversation name and ID
    """
    integration_context = get_integration_context(SYNC_CONTEXT)
    if conversation:
        conversations = integration_context.get('conversations')
        if conversations:
            conversations = json.loads(conversations)
            conversations.append(conversation)
        else:
            conversations = [conversation]
        set_to_integration_context_with_retries({'conversations': conversations}, OBJECTS_TO_KEYS, SYNC_CONTEXT)


def get_conversation_by_name(conversation_name: str) -> dict:
    """
    Get a slack conversation by its name. Order of operation is:
    1. Check the COMMON_CHANNEL parameter for the conversation
    2. Check the integration context for the conversation
    3. If DISABLE_CACHING is false, then we will paginate the api
    4. If DISABLE_CACHING is false, then we will save the results of the pagination to context

    Args:
        conversation_name: The conversation name

    Returns:
        The slack conversation
    """

    conversation_to_search = conversation_name.lower()
    conversation: dict = {}
    # Checks if the channel is defined in the integration params
    if len(COMMON_CHANNELS) > 0:
        conversation = search_conversation_in_params(conversation_to_search)

    if not DISABLE_CACHING:
        # Find conversation in the cache if DISABLE_CACHING is false.
        if not conversation:
            conversation = search_conversation_in_context(conversation_to_search)

        # Find conversation in the api if DISABLE_CACHING is false.
        if not conversation:
            conversation = get_conversation_from_api_paginated(conversation_to_search)
            # Save conversation to cache
            save_conversation_to_context(conversation)

    return conversation


def send_mirrored_file_to_slack(entry: str, message: str, original_channel: str, channel_id: str, comment: Optional[str] = None):
    """
    Sends a file from xsoar investigation to a mirrored slack channel

    Args:
        entry: the entry ID of the file
        message: the message from the war-room when uploading file
        original_channel: the channel name to upload the file
        channel_id: the channel ID to upload the file
        comment: a comment that was added when uploading the file
    """
    file_name = demisto.getFilePath(entry)["name"]
    if FILE_MIRRORING_ENABLED:
        demisto.debug(
            f'file {file_name} has been uploaded to a mirrored incident, '
            f'uploading the file to slack channel {original_channel}'
        )
        if comment:
            # if a comment was added when uploading the file, add it to the message
            message = f'{message}\nComment: {comment}'
        slack_send_file(original_channel, channel_id, entry, message)
    else:
        demisto.debug(f'file {file_name} will not be mirrored because file mirroring is not enabled')


def slack_send():
    """
    Sends a message to slack
    """

    args = demisto.args()
    message = args.get('message', '')
    to = args.get('to')
    original_channel = args.get('channel')
    channel_id = demisto.args().get('channel_id', '')
    group = args.get('group')
    message_type = args.get('messageType', '')  # From server
    original_message = args.get('originalMessage', '')  # From server
    entry = args.get('entry')
    ignore_add_url = args.get('ignoreAddURL', False) or args.get('IgnoreAddURL', False)
    thread_id = args.get('threadID', '')
    severity = args.get('severity')  # From server
    blocks = args.get('blocks')
    entry_object = args.get('entryObject')  # From server, available from demisto v6.1 and above
    entitlement = ''

    if message_type and (message_type not in PERMITTED_NOTIFICATION_TYPES) and message_type != MIRROR_TYPE:
        demisto.info(f"Message type is not in permitted options. Received: {message_type}")
        return

    if message_type == MIRROR_TYPE and original_message.find(MESSAGE_FOOTER) != -1:
        # return so there will not be a loop of messages
        return

    if message_type == MIRROR_TYPE:
        tags = argToList(demisto.params().get('filtered_tags', []))
        entry_tags = entry_object.get('tags', [])

        if tags and not entry_tags:
            return

        # return if the entry tags is not containing any of the filtered_tags
        if tags and not any(elem in entry_tags for elem in tags):
            return

        if entry:
            send_mirrored_file_to_slack(
                entry,
                message=message,
                original_channel=original_channel,
                channel_id=channel_id,
                comment=entry_object.get("contents")
            )
            return

    if (to and group) or (to and original_channel) or (to and original_channel and group):
        return_error('Only one destination can be provided.')

    if severity:
        try:
            severity = int(severity)
        except Exception:
            severity = None

    channel = original_channel
    if original_channel == INCIDENT_NOTIFICATION_CHANNEL or (not original_channel and message_type == INCIDENT_OPENED):
        original_channel = INCIDENT_NOTIFICATION_CHANNEL
        channel = DEDICATED_CHANNEL
        demisto.debug(f'trying to send message to channel {original_channel}, changing slack channel to {channel}')

    if (channel == DEDICATED_CHANNEL and original_channel == INCIDENT_NOTIFICATION_CHANNEL
            and ((severity is not None and severity < SEVERITY_THRESHOLD)
                 or not (len(CUSTOM_PERMITTED_NOTIFICATION_TYPES) > 0))):
        channel = None
        demisto.debug(
            f"Severity of the notification is - {severity} and the Severity threshold is {SEVERITY_THRESHOLD}")

    if not (to or group or channel or channel_id):
        return_error('Either a user, group, channel id, or channel must be provided.')

    reply = ''
    expiry = ''
    default_response = ''
    if blocks:
        entitlement_match = re.search(ENTITLEMENT_REGEX, blocks)
        if entitlement_match:
            try:
                parsed_message = json.loads(blocks)
                entitlement = parsed_message.get('entitlement')
                blocks = parsed_message.get('blocks')
                reply = parsed_message.get('reply')
                expiry = parsed_message.get('expiry')
                default_response = parsed_message.get('default_response')
            except Exception:
                demisto.info('Slack - could not parse JSON from entitlement blocks.')
    elif message:
        entitlement_match = re.search(ENTITLEMENT_REGEX, message)
        if entitlement_match:
            try:
                parsed_message = json.loads(message)
                entitlement = parsed_message.get('entitlement')
                message = parsed_message.get('message')
                reply = parsed_message.get('reply')
                expiry = parsed_message.get('expiry')
                default_response = parsed_message.get('default_response')
            except Exception:
                demisto.info('Slack - could not parse JSON from entitlement message.')

    response = slack_send_request(to, channel, group, entry, ignore_add_url, thread_id, message=message, blocks=blocks,
                                  channel_id=channel_id)

    if response:
        thread = response.get('ts')
        if entitlement:
            save_entitlement(entitlement, thread, reply, expiry, default_response)

        demisto.results({
            'Type': entryTypes['note'],
            'HumanReadable': f'Message sent to Slack successfully.\nThread ID is: {thread}',
            'Contents': response.data,
            'ContentsFormat': formats['json'],
            'EntryContext': {
                'Slack.Thread(val.ID===obj.ID)': {
                    'ID': thread
                },
            }
        })
    else:
        demisto.results('Could not send the message to Slack.')


def save_entitlement(entitlement, thread, reply, expiry, default_response):
    """
    Saves an entitlement with its thread

    Args:
        entitlement: The entitlement
        thread: The thread
        reply: The reply to send to the user.
        expiry: The question expiration date.
        default_response: The response to send if the question times out.
    """
    integration_context = get_integration_context(SYNC_CONTEXT)
    questions = integration_context.get('questions', [])
    if questions:
        questions = json.loads(integration_context['questions'])
    questions.append({
        'thread': thread,
        'entitlement': entitlement,
        'reply': reply,
        'expiry': expiry,
        'sent': datetime.strftime(get_current_utc_time(), DATE_FORMAT),
        'default_response': default_response
    })

    set_to_integration_context_with_retries({'questions': questions}, OBJECTS_TO_KEYS, SYNC_CONTEXT)


SEND_FILE_ERROR_EXPLANATIONS = {
    'access_denied': 'Access to a resource specified in the request is denied.',
    'channel_not_found': 'The value passed for channel_id was invalid.',
    'file_not_found': 'Could not find the file from the upload ticket.',
    'file_update_failed': 'Failure occurred when attempting to update the file.',
    'invalid_channel': 'The channel could not be found or the channel specified is invalid.',
    'posting_to_channel_denied': 'The user is not authorized to post to the target channel(s).',
    'account_inactive': 'The authentication token is for a deleted user or workspace when using a bot token.',
    'deprecated_endpoint': 'The endpoint has been deprecated.',
    'ekm_access_denied': 'Administrators have suspended the ability to post a message.',
    'enterprise_is_restricted': 'The method cannot be called from an Enterprise.',
    'invalid_auth': 'The provided token is invalid or the request originates from a disallowed IP address.',
    'method_deprecated': 'The method has been deprecated.',
    'missing_scope': 'The token used is not granted the specific scope permissions required to complete this request.',
    'not_allowed_token_type': 'The token type used in this request is not allowed.',
    'not_authed': 'No authentication token provided.',
    'not_in_channel': 'The user or bot used is not in the target channel(s). Ensure they are invited to the channel(s).',
    'no_permission': 'The workspace token used in this request does not have the permissions necessary to complete the request.',
    'org_login_required': 'The workspace is undergoing an enterprise migration and is temporarily unavailable.',
    'token_expired': 'The authentication token has expired.',
    'token_revoked': 'The authentication token is for a deleted user or workspace or the app has been removed.',
    'two_factor_setup_required': 'Two factor setup is required.',
    'team_access_not_granted': 'The token used is not granted the specific workspace access required to complete this request.',
    'accesslimited': 'Access to this method is limited on the current network.',
    'fatal_error': 'The Slack server could not complete this operation(s).',
    'internal_error': 'The Slack server could not complete this operation(s), likely due to a transient issue on our end.',
    'ratelimited': 'The request has been rate limited.',
    'request_timeout': 'Data was either missing or truncated for the POST request.',
    'service_unavailable': 'The Slack service is temporarily unavailable.',
    'team_added_to_org': 'The Slack workspace is currently undergoing migration to an Enterprise Organization.'
}


def slack_send_file(_channel: str | None = None, _channel_id: str = '', _entry_id: str | None = None, _comment: str = ""):
    """
    Sends a file to slack
    """
    to = demisto.args().get('to')
    channel = _channel or demisto.args().get('channel')
    channel_id = _channel_id or demisto.args().get('channel_id', '')
    group = demisto.args().get('group')
    entry_id = _entry_id or demisto.args().get('file')
    thread_id = demisto.args().get('threadID')
    comment = _comment or demisto.args().get('comment', '')

    if not (to or channel or group):
        mirror = find_mirror_by_investigation()
        if mirror:
            channel = mirror.get('channel_name')

    if not (to or channel or group or channel_id):
        return_error('Either a user, group, channel id or channel must be provided.')

    file_path = demisto.getFilePath(entry_id)

    file_dict = {
        'path': file_path['path'],
        'name': file_path['name'],
        'comment': comment
    }

    error_message = f'Failed to send file: {file_path["name"]} to Slack.'
    try:
        response = slack_send_request(to, channel, group, thread_id=thread_id, file_dict=file_dict, channel_id=channel_id)
        if response:
            return_results(CommandResults(readable_output='File sent to Slack successfully.'))
        else:
            raise DemistoException(message=error_message)
    except SlackApiError as e:
        demisto.debug(f'{error_message} {e}')
        if error_code := e.response.get('error'):
            error_explanation = SEND_FILE_ERROR_EXPLANATIONS.get(error_code, error_code.replace('_', ' ').capitalize())
            error_message += f' {error_explanation}'

        raise DemistoException(message=error_message)


def handle_tags_in_message_sync(message: str) -> str:
    """
    Handles user tags in a slack send message

    Args:
        message: The slack message

    Returns:
        The tagged slack message
    """
    matches = re.finditer(USER_TAG_EXPRESSION, message)
    for match in matches:
        slack_user = get_user_by_name(match.group(1))
        if slack_user:
            message = message.replace(match.group(0), f"<@{slack_user.get('id')}>")
        else:
            message = re.sub(USER_TAG_EXPRESSION, r'\1', message)
    return message


def send_message(destinations: list, entry: str, ignore_add_url: bool, integration_context: dict, message: str,
                 thread_id: str, blocks: str):
    """
    Sends a message to Slack.
    Args:
        destinations: The destinations to send to.
        entry: A WarRoom entry to send.
        ignore_add_url: Do not add a XSOAR URL to the message.
        integration_context: Current integration context.
        message: The message to send.
        thread_id: The Slack thread ID to send the message to.
        blocks: Message blocks to send

    Returns:
        The Slack send response.
    """
    if not message:
        if blocks:
            message = 'New message from SOC Bot'
            # This is shown in the notification bubble from Slack
        else:
            message = '\n'

    if message and not blocks:
        if ignore_add_url and isinstance(ignore_add_url, str):
            ignore_add_url = bool(strtobool(ignore_add_url))
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
                        message += f'\nView it on: {link}'
                else:
                    link = server_links.get('server', '')
                    if link:
                        message += f'\nView it on: {link}#/home'
    try:
        response = send_message_to_destinations(destinations, message, thread_id, blocks)
    except SlackApiError as e:
        if str(e).find('not_in_channel') == -1 and str(e).find('channel_not_found') == -1:
            raise
        bot_id = integration_context.get('bot_id')
        if not bot_id:
            bot_id = get_bot_id()
        for dest in destinations:
            invite_users_to_conversation(dest, [bot_id])
        response = send_message_to_destinations(destinations, message, thread_id, blocks)
    return response


def send_message_to_destinations(destinations: list, message: str, thread_id: str, blocks: str = '') \
        -> Optional[SlackResponse]:
    """
    Sends a message to provided destinations Slack.

    Args:
        destinations: Destinations to send to.
        message: The message to send.
        thread_id: Slack thread ID to send to.
        blocks: Message blocks to send

    Returns:
        The Slack send response.
    """
    response: Optional[SlackResponse] = None
    body: dict = {}

    if message:
        clean_message = handle_tags_in_message_sync(message)
        body['text'] = clean_message
    if blocks:
        block_list = json.loads(blocks, strict=False)
        body['blocks'] = block_list
    if thread_id:
        body['thread_ts'] = thread_id

    for destination in destinations:
        body['channel'] = destination
        response = send_slack_request_sync(CLIENT, 'chat.postMessage', body=body)

    return response


def send_file(destinations: list, file_dict: dict, integration_context: dict, thread_id: str) -> \
        Optional[SlackResponse]:
    """
    Sends a file to Slack.

    Args:
        destinations: Destinations to send the file to.
        file_dict: The file to send.
        integration_context: The current integration context.
        thread_id: A Slack thread to send to.

    Returns:
        The Slack send response.
    """
    try:
        response = send_file_to_destinations(destinations, file_dict, thread_id)
    except SlackApiError as e:
        if str(e).find('not_in_channel') == -1 and str(e).find('channel_not_found') == -1:
            raise
        bot_id = integration_context.get('bot_id')
        if not bot_id:
            bot_id = get_bot_id()
            integration_context['bot_id'] = bot_id
        for dest in destinations:
            invite_users_to_conversation(dest, [bot_id])
        response = send_file_to_destinations(destinations, file_dict, thread_id)

    return response


def send_file_to_destinations(destinations: list, file_dict: dict, thread_id: str) -> Optional[SlackResponse]:
    """
    Sends a file to provided destinations in Slack.

    Args:
        destinations: The destinations to send to.
        file_dict: The file to send.
        thread_id: A thread ID to send to.

    Returns:
        The Slack send response.
    """
    response: Optional[SlackResponse] = None

    for destination in destinations:
        file_upload_params = FileUploadParams(
            filename=file_dict['name'],
            file=file_dict['path'],
            initial_comment=file_dict.get('comment'),
            channel=destination,
            thread_ts=thread_id,
        )
        response = send_slack_request_sync(CLIENT, file_upload_params=file_upload_params)

    return response


def slack_send_request(to: str = None, channel: str = None, group: str = None, entry: str = '',
                       ignore_add_url: bool = False, thread_id: str = '', message: str = '',
                       blocks: str = '', file_dict: dict = None, channel_id: str = None) \
        -> Optional[SlackResponse]:
    """
    Requests to send a message or a file to Slack.

    Args:
        to: A Slack user to send to.
        channel: A Slack channel to send to.
        group: A Slack private channel to send to.
        entry: WarRoom entry to send.
        ignore_add_url: Do not add a Demisto URL to the message.
        thread_id: The Slack thread ID to send to.
        message: A message to send.
        blocks: Blocks to send with a slack message
        file_dict: A file to send.
        channel_id: ID of channel to send to.

    Returns:
        The Slack send response.
    """

    integration_context = get_integration_context(SYNC_CONTEXT)
    mirrors: list = []
    if integration_context and 'mirrors' in integration_context:
        mirrors = json.loads(integration_context['mirrors'])

    destinations = []

    if to:
        if isinstance(to, list):
            to = to[0]
        user = get_user_by_name(to)
        if not user:
            demisto.error(f'Could not find the Slack user {to}')
        else:
            body = {
                'users': user.get('id')
            }
            im = send_slack_request_sync(CLIENT, 'conversations.open', body=body)
            destinations.append(im.get('channel', {}).get('id'))  # type: ignore[call-overload]
    if channel or group or channel_id:
        if channel_id:
            destinations.append(channel_id)
        if not destinations:
            destination_name = channel or group
            mirrored_channel_filter = list(filter(lambda m: f'incident-{m["investigation_id"]}' == destination_name,
                                                  mirrors))
            if mirrored_channel_filter:
                channel_mirror = mirrored_channel_filter[0]
                conversation_id = channel_mirror['channel_id']
            else:
                conversation = get_conversation_by_name(destination_name)  # type: ignore
                if not conversation:
                    return_error(f'Could not find the Slack conversation {destination_name}. If caching is disabled,'
                                 f' try searching by channel_id')
                conversation_id = conversation.get('id')

            if conversation_id:
                destinations.append(conversation_id)

    if not destinations:
        return_error('Could not find any destination to send to.')

    if file_dict:
        response = send_file(destinations, file_dict, integration_context, thread_id)
        return response

    response = send_message(destinations, entry, ignore_add_url, integration_context, message,
                            thread_id, blocks)

    return response


def set_channel_topic():
    """
    Sets a topic for a slack channel
    """

    channel = demisto.args().get('channel')
    channel_id = demisto.args().get('channel_id', '')
    topic = demisto.args().get('topic')

    if not channel:
        mirror = find_mirror_by_investigation()
        if mirror:
            channel_id = mirror.get('channel_id', '')
            # We need to update the topic in the mirror
            integration_context = get_integration_context(SYNC_CONTEXT)
            mirrors = json.loads(integration_context['mirrors'])
            mirror = mirrors.pop(mirrors.index(mirror))
            mirror['channel_topic'] = topic
            mirrors.append(mirror)
            set_to_integration_context_with_retries({'mirrors': mirrors}, OBJECTS_TO_KEYS, SYNC_CONTEXT)
    if channel and not channel_id:
        channel = get_conversation_by_name(channel)
        channel_id = channel_id if channel_id else channel.get('id')

    if not channel_id:
        return_error(CHANNEL_NOT_FOUND_ERROR_MSG)

    body = {
        'channel': channel_id,
        'topic': topic
    }
    send_slack_request_sync(CLIENT, 'conversations.setTopic', body=body)

    demisto.results('Topic successfully set.')


def rename_channel():
    """
    Renames a slack channel
    """

    channel = demisto.args().get('channel')
    channel_id = demisto.args().get('channel_id', '')
    new_name = demisto.args().get('name')

    if not channel:
        mirror = find_mirror_by_investigation()
        if mirror:
            channel_id = mirror.get('channel_id', '')
            # We need to update the name in the mirror
            integration_context = get_integration_context(SYNC_CONTEXT)
            mirrors = json.loads(integration_context['mirrors'])
            mirror = mirrors.pop(mirrors.index(mirror))
            mirror['channel_name'] = new_name
            mirrors.append(mirror)
            set_to_integration_context_with_retries({'mirrors': mirrors}, OBJECTS_TO_KEYS, SYNC_CONTEXT)
    if channel and not channel_id:
        channel = get_conversation_by_name(channel)
        channel_id = channel_id if channel_id else channel.get('id')

    if not channel_id:
        return_error(CHANNEL_NOT_FOUND_ERROR_MSG)
    body = {
        'channel': channel_id,
        'name': new_name
    }
    send_slack_request_sync(CLIENT, 'conversations.rename', body=body)

    demisto.results('Channel renamed successfully.')


def close_channel():
    """
    Archives a slack channel by name or its incident ID if mirrored.
    """
    channel = demisto.args().get('channel')
    channel_id = demisto.args().get('channel_id', '')

    mirror = find_mirror_by_investigation()
    integration_context = get_integration_context(SYNC_CONTEXT)
    if mirror:
        channel_id = mirror.get('channel_id', '')
        # We need to update the topic in the mirror
        mirrors = json.loads(integration_context['mirrors'])
        channel_id = mirror['channel_id']
        # Check for mirrors on the archived channel
        channel_mirrors = list(filter(lambda m: channel_id == m['channel_id'], mirrors))
        for mirror in channel_mirrors:
            mirror['remove'] = True
            demisto.mirrorInvestigation(mirror['investigation_id'], f'none:{mirror["mirror_direction"]}',
                                        mirror['auto_close'])

        set_to_integration_context_with_retries({'mirrors': mirrors}, OBJECTS_TO_KEYS, SYNC_CONTEXT)
    if channel and not channel_id:
        channel = get_conversation_by_name(channel)
        channel_id = channel_id if channel_id else channel.get('id')

    if not channel_id:
        return_error(CHANNEL_NOT_FOUND_ERROR_MSG)
    body = {
        'channel': channel_id
    }
    send_slack_request_sync(CLIENT, 'conversations.archive', body=body)
    remove_channel_from_context(channel_id=channel_id, integration_context=integration_context)
    demisto.results('Channel successfully archived.')


def remove_channel_from_context(channel_id: str, integration_context: dict):
    """
    :param channel_id: The channel_id to remove.
    :param integration_context: The integration_context object.
    Removes a channel from the integration context
    """
    if 'conversations' in integration_context:
        conversations = json.loads(integration_context['conversations'])
        updated_conversations = [conversation for conversation in conversations if conversation.get('id') != channel_id]
        set_to_integration_context_with_retries({'conversations': updated_conversations}, OBJECTS_TO_KEYS, SYNC_CONTEXT)
        demisto.debug('Channel successfully removed from context.')
    demisto.debug('Channel was not stored in the context. No need to delete.')


def create_channel():
    """
    Creates a channel in Slack using the provided arguments.
    """
    channel_type = demisto.args().get('type', 'private')
    channel_name = demisto.args()['name']
    users = argToList(demisto.args().get('users', []))
    topic = demisto.args().get('topic')

    body = {
        'name': channel_name
    }

    if channel_type == 'private':
        body['is_private'] = True

    conversation = send_slack_request_sync(CLIENT, 'conversations.create', body=body).get(  # type: ignore
        'channel', {})

    if users:
        slack_users = search_slack_users(users)
        invite_users_to_conversation(conversation.get('id'),  # type: ignore
                                     [u.get('id') for u in slack_users])
    if topic:
        body = {
            'channel': conversation.get('id'),
            'topic': topic
        }
        send_slack_request_sync(CLIENT, 'conversations.setTopic', body=body)

    created_channel_name = conversation.get('name')
    created_channel_id = conversation.get('id')

    hr = f'Successfully created the channel {created_channel_name}'
    conversation_context = {
        'ID': created_channel_id,
        'Name': created_channel_name
    }

    if not DISABLE_CACHING:
        # Save it to integration context since we have it
        save_conversation_to_context({'name': created_channel_name, 'id': created_channel_id})

    context = {
        'Slack.Channel(val.ID === obj.ID)': conversation_context
    }
    return_results(CommandResults(
        readable_output=hr,
        outputs=context,
        raw_response=json.dumps(conversation)))


def invite_to_channel():
    channel = demisto.args().get('channel')
    channel_id = demisto.args().get('channel_id', '')
    users = argToList(demisto.args().get('users', '[]').rstrip(', '))

    if not users:
        # Not raising an error here to preserve BC
        demisto.results('Missing required argument - users')

    if not channel:
        mirror = find_mirror_by_investigation()
        if mirror:
            channel_id = mirror['channel_id']
    if channel and not channel_id:
        channel = get_conversation_by_name(channel)
        channel_id = channel.get('id')

    if not channel_id:
        return_error(CHANNEL_NOT_FOUND_ERROR_MSG)
    slack_users = search_slack_users(users)
    if slack_users:
        invite_users_to_conversation(channel_id, [u.get('id') for u in slack_users])
    else:
        return_error('No users found')

    demisto.results('Successfully invited users to the channel.')


def kick_from_channel():
    channel = demisto.args().get('channel')
    channel_id = demisto.args().get('channel_id', '')
    users = argToList(demisto.args().get('users', []))

    if not channel:
        mirror = find_mirror_by_investigation()
        if mirror:
            channel_id = mirror['channel_id']
    if channel and not channel_id:
        channel = get_conversation_by_name(channel)
        channel_id = channel.get('id')

    if not channel_id:
        return_error(CHANNEL_NOT_FOUND_ERROR_MSG)
    slack_users = search_slack_users(users)
    if slack_users:
        kick_users_from_conversation(channel_id, [u.get('id') for u in slack_users])
    else:
        return_error('No users were found')

    demisto.results('Successfully kicked users from the channel.')


def get_user():
    user_input = demisto.args()['user']

    # Check if the input might be an email or a user ID
    if re.match(emailRegex, user_input):
        slack_user = get_user_by_email(user_input)
    elif re.match("^[UW](?=.*\d)[A-Z0-9]{8}$", user_input):
        slack_user = get_user_by_id(user_input)
    else:
        slack_user = get_user_by_name(user_input)

    if not slack_user:
        err_str = format_user_not_found_error(user=user_input)
        demisto.results({
            'Type': WARNING_ENTRY_TYPE,
            'Contents': err_str,
            'ContentsFormat': formats['text']
        })

    profile = slack_user.get('profile', {})
    result_user = {
        'ID': slack_user.get('id'),
        'Username': slack_user.get('name'),
        'Name': profile.get('real_name_normalized') or profile.get('real_name'),
        'DisplayName': profile.get('display_name'),
        'Email': profile.get('email')
    }

    hr = tableToMarkdown('Details for Slack user: ' + user_input, result_user,
                         headers=['ID', 'Username', 'Name', 'DisplayName', 'Email'], headerTransform=pascalToSpace,
                         removeNull=True)
    context = {
        'Slack.User(val.ID === obj.ID)': createContext(result_user, removeNull=True)
    }

    return_outputs(hr, context, slack_user)


def slack_edit_message():
    args = demisto.args()
    channel = args.get('channel')
    channel_id = args.get('channel_id', '')
    thread_id = demisto.args().get('threadID')
    message = args.get('message')
    blocks = args.get('blocks')
    ignore_add_url = args.get('ignore_add_url')
    entry = args.get('entry')

    if not channel:
        mirror = find_mirror_by_investigation()
        channel_id = mirror['channel_id'] if mirror else channel_id if channel_id else channel.get('id')
    if channel and not channel_id:
        channel = get_conversation_by_name(channel)
        channel_id = channel.get('id')

    if not channel_id:
        return_error(CHANNEL_NOT_FOUND_ERROR_MSG)
    if not thread_id:
        return_error('The timestamp of the message to edit is required.')

    if message and not blocks:
        if ignore_add_url and isinstance(ignore_add_url, str):
            ignore_add_url = bool(strtobool(ignore_add_url))
        if not ignore_add_url:
            investigation = demisto.investigation()
            server_links = demisto.demistoUrls()
            if investigation:
                if investigation.get('type') != PLAYGROUND_INVESTIGATION_TYPE:
                    link = server_links.get('warRoom')
                    if link:
                        if entry:
                            link += '/' + entry
                        message += f'\nView it on: {link}'
                else:
                    link = server_links.get('server', '')
                    if link:
                        message += f'\nView it on: {link}#/home'

    body = {
        'channel': channel_id,
        'ts': thread_id
    }
    if message:
        clean_message = handle_tags_in_message_sync(message)
        body['text'] = clean_message
    if blocks:
        block_list = json.loads(blocks, strict=False)
        body['blocks'] = block_list
    try:
        response = send_slack_request_sync(CLIENT, 'chat.update', body=body)

        hr = "The message was successfully edited."
        result_edit = {
            'ID': response.get('ts', None),
            'Channel': response.get('channel', None),
            'Text': response.get('text', None)
        }
        context = {
            'Slack.Thread(val.ID === obj.ID)': result_edit
        }
        return_results(CommandResults(
            readable_output=hr,
            outputs=context,
            raw_response=json.dumps(response.data)))

    except SlackApiError as slack_error:
        return_error(f"{slack_error}")


def pin_message():
    channel = demisto.args().get('channel')
    thread_id = demisto.args().get('threadID')
    channel_id = demisto.args().get('channel_id')

    if not channel:
        mirror = find_mirror_by_investigation()
        channel_id = mirror['channel_id'] if mirror else channel_id if channel_id else channel.get('id')
    if channel and not channel_id:
        channel = get_conversation_by_name(channel)
        channel_id = channel.get('id')

    if not channel_id:
        return_error(CHANNEL_NOT_FOUND_ERROR_MSG)
    body = {
        'channel': channel_id,
        'timestamp': thread_id
    }
    try:
        send_slack_request_sync(CLIENT, 'pins.add', body=body)
        return_results('The message was successfully pinned.')

    except SlackApiError as slack_error:
        return_error(f"{slack_error}")


def list_channels():
    """
    List the conversations in the workspace
    """
    args = demisto.args()
    # Default for the SDK is public channels, but users can specify "public_channel", "private_channel", "mpim", and "im"
    # Multiple values can be passed for this argument as a comma separated list
    # By default archived channels are NOT included by the SDK. Explicitly set this if not set from the CLI or set to False
    body = {
        'types': args.get('channel_types'),
        'exclude_archived': argToBoolean(args.get('exclude_archived', 'true')),
        'limit': args.get('limit')
    }
    if args.get('cursor'):
        body['cursor'] = args.get('cursor')
    raw_response = send_slack_request_sync(CLIENT, 'conversations.list', http_verb="GET", body=body)
    # Provide an option to only select a channel by a name. Instead of returning a full list of results this allows granularity
    # Supports a single channel name
    if name_filter := args.get('name_filter'):
        for channel in raw_response['channels']:
            if channel['name'] == name_filter:
                channels = [channel]
                break
        else:
            raise DemistoException(f'No channel found with name: {name_filter}')
    else:
        channels = raw_response['channels']
    # Force list for consistent parsing
    if isinstance(channels, dict):
        channels = [channels]
    context = []  # type: List
    for channel in channels:
        entry = {
            'ID': channel.get('id'),
            'Name': channel.get('name'),
            'Created': channel.get('created'),
            'Purpose': channel.get('purpose', {}).get('value')
        }
        if channel.get('creator'):
            creator_details_response = send_slack_request_sync(CLIENT, 'users.info', http_verb="GET",
                                                               body={'user': channel.get('creator')})
            entry['Creator'] = creator_details_response['user']['name']
        context.append(entry)
    readable_output = tableToMarkdown(f'Channels list for {args.get("channel_types")} with filter {name_filter}',
                                      context)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': channels,
        'EntryContext': {'Slack.Channels': context},
        'ContentsFormat': formats['json'],
        'HumanReadable': readable_output,
        'ReadableContentsFormat': formats['markdown']
    })


def conversation_history():
    """
    Fetches a conversation's history of messages
    and events
    """
    args = demisto.args()
    channel_id = args.get('channel_id')
    limit = arg_to_number(args.get('limit'))
    conversation_id = args.get('conversation_id')
    body = {'channel': channel_id, 'limit': limit} if not conversation_id else {'channel': channel_id,
                                                                                'oldest': conversation_id,
                                                                                'inclusive': "true",
                                                                                'limit': 1}
    readable_output = ''
    raw_response = send_slack_request_sync(CLIENT, 'conversations.history', http_verb="GET", body=body)
    messages = raw_response.get('messages', '')
    if not raw_response.get('ok'):
        raise DemistoException(f'An error occurred while listing conversation history: {raw_response.get("error")}',
                               res=raw_response)
    if isinstance(messages, dict):
        messages = [messages]
    if not isinstance(messages, list):
        raise DemistoException(f'An error occurred while listing conversation history: {raw_response.get("error")}',
                               res=raw_response)
    context = []  # type: List
    for message in messages:
        thread_ts = 'N/A'
        has_replies = 'No'
        name = 'N/A'
        full_name = 'N/A'
        if 'subtype' not in message:
            user_id = message.get('user')
            user_details_response = send_slack_request_sync(CLIENT, 'users.info', http_verb="GET",
                                                            body={'user': user_id})
            user_details = user_details_response.get('user')
            full_name = user_details.get('real_name')
            name = user_details.get('name')
            if 'thread_ts' in message:
                thread_ts = message.get('thread_ts')
                has_replies = 'Yes'
        elif 'thread_ts' in message:
            thread_ts = message.get('thread_ts')
            has_replies = 'Yes'
            full_name = message.get('username')
            name = message.get('username')
            thread_ts = message.get('thread_ts')
            has_replies = 'Yes'
        entry = {
            'Type': message.get('type'),
            'Text': message.get('text'),
            'UserId': message.get('user'),
            'Name': name,
            'FullName': full_name,
            'TimeStamp': message.get('ts'),
            'HasReplies': has_replies,
            'ThreadTimeStamp': thread_ts
        }
        context.append(entry)
    readable_output = tableToMarkdown(f'Channel details from Channel ID - {channel_id}', context)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': messages,
        'EntryContext': {'Slack.Messages': context},
        'ContentsFormat': formats['json'],
        'HumanReadable': readable_output,
        'ReadableContentsFormat': formats['markdown']
    })


def conversation_replies():
    """
    Retrieves replies to specific messages, regardless of whether it's
    from a public or private channel, direct message, or otherwise.
    """
    args = demisto.args()
    channel_id = args.get('channel_id')
    context: list = []
    readable_output: str = ''
    body = {
        'channel': channel_id,
        'ts': args.get('thread_timestamp'),
        'limit': arg_to_number(args.get('limit'))
    }
    raw_response = send_slack_request_sync(CLIENT, 'conversations.replies', http_verb="GET", body=body)
    messages = raw_response.get('messages', '')
    if not raw_response.get('ok'):
        error = raw_response.get('error')
        return_error(f'An error occurred while listing conversation replies: {error}')
    if isinstance(messages, dict):
        messages = [messages]
    if not isinstance(messages, list):
        raise DemistoException(f'An error occurred while listing conversation replies: {raw_response.get("error")}')
    for message in messages:
        reply_count = 'No'
        name = 'N/A'
        full_name = 'N/A'
        if 'subtype' not in message:
            user_id = message.get('user')
            body = {
                'user': user_id
            }
            user_details_response = send_slack_request_sync(CLIENT, 'users.info', http_verb="GET", body=body)
            user_details = user_details_response.get('user')
            name = user_details.get('name')
            full_name = user_details.get('real_name')
        if 'reply_count' in message:
            reply_count = 'Yes'
        entry = {
            'Type': message.get('type'),
            'Text': message.get('text'),
            'UserId': message.get('user'),
            'Name': name,
            'FullName': full_name,
            'TimeStamp': message.get('ts'),
            'ThreadTimeStamp': message.get('thread_ts'),
            'IsParent': reply_count
        }
        context.append(entry)
    readable_output = tableToMarkdown(f'Channel details from Channel ID - {channel_id}', context)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': messages,
        'EntryContext': {'Slack.Threads': context},
        'ContentsFormat': formats['json'],
        'HumanReadable': readable_output,
        'ReadableContentsFormat': formats['markdown']
    })


def long_running_main():
    """
    Starts the long running thread.
    """
    try:
        asyncio.run(start_listening(), debug=EXTENSIVE_LOGGING)
    except Exception as e:
        demisto.error(f"The Loop has failed to run {str(e)}")
    finally:
        loop = asyncio.get_running_loop()
        try:
            loop.stop()
            loop.close()
        except Exception as e_:
            demisto.error(f'Failed to gracefully close the loop - {e_}')


def init_globals(command_name: str = ''):
    """
    Initializes global variables according to the integration parameters
    """

    global BOT_TOKEN, PROXY_URL, PROXIES, DEDICATED_CHANNEL, CLIENT, USER_CLIENT, \
        CACHED_INTEGRATION_CONTEXT, MIRRORING_ENABLED, FILE_MIRRORING_ENABLED, USER_TOKEN
    global SEVERITY_THRESHOLD, ALLOW_INCIDENTS, INCIDENT_TYPE, VERIFY_CERT, ENABLE_DM, BOT_ID, CACHE_EXPIRY
    global BOT_NAME, BOT_ICON_URL, MAX_LIMIT_TIME, PAGINATED_COUNT, SSL_CONTEXT, APP_TOKEN, ASYNC_CLIENT
    global DEFAULT_PERMITTED_NOTIFICATION_TYPES, CUSTOM_PERMITTED_NOTIFICATION_TYPES, PERMITTED_NOTIFICATION_TYPES
    global COMMON_CHANNELS, DISABLE_CACHING, CHANNEL_NOT_FOUND_ERROR_MSG, LONG_RUNNING_ENABLED, DEMISTO_API_KEY, DEMISTO_URL
    global IGNORE_RETRIES, EXTENSIVE_LOGGING

    VERIFY_CERT = not demisto.params().get('unsecure', False)
    if not VERIFY_CERT:
        SSL_CONTEXT = ssl.create_default_context()
        SSL_CONTEXT.check_hostname = False
        SSL_CONTEXT.verify_mode = ssl.CERT_NONE
    else:
        # Use default SSL context
        SSL_CONTEXT = None

    BOT_TOKEN = demisto.params().get('bot_token', {}).get('password', '')
    APP_TOKEN = demisto.params().get('app_token', {}).get('password', '')
    USER_TOKEN = demisto.params().get('user_token', {}).get('password', '')
    PROXIES = handle_proxy()
    PROXY_URL = PROXIES.get('http')  # aiohttp only supports http proxy
    DEDICATED_CHANNEL = demisto.params().get('incidentNotificationChannel', None)
    ASYNC_CLIENT = AsyncWebClient(token=BOT_TOKEN, ssl=SSL_CONTEXT, proxy=PROXY_URL)
    CLIENT = slack_sdk.WebClient(token=BOT_TOKEN, proxy=PROXY_URL, ssl=SSL_CONTEXT)
    USER_CLIENT = slack_sdk.WebClient(token=USER_TOKEN, proxy=PROXY_URL, ssl=SSL_CONTEXT)
    SEVERITY_THRESHOLD = SEVERITY_DICT.get(demisto.params().get('min_severity', 'Low'), 1)
    ALLOW_INCIDENTS = demisto.params().get('allow_incidents', False)
    INCIDENT_TYPE = demisto.params().get('incidentType')
    BOT_NAME = demisto.params().get('bot_name')  # Bot default name defined by the slack plugin (3-rd party)
    BOT_ICON_URL = demisto.params().get('bot_icon')  # Bot default icon url defined by the slack plugin (3-rd party)
    MAX_LIMIT_TIME = int(demisto.params().get('max_limit_time', '60'))
    PAGINATED_COUNT = int(demisto.params().get('paginated_count', '200'))
    ENABLE_DM = demisto.params().get('enable_dm', True)
    DEFAULT_PERMITTED_NOTIFICATION_TYPES = ['externalAskSubmit', 'externalFormSubmit']
    CUSTOM_PERMITTED_NOTIFICATION_TYPES = demisto.params().get('permitted_notifications', [])
    PERMITTED_NOTIFICATION_TYPES = DEFAULT_PERMITTED_NOTIFICATION_TYPES + CUSTOM_PERMITTED_NOTIFICATION_TYPES
    MIRRORING_ENABLED = demisto.params().get('mirroring', True)
    FILE_MIRRORING_ENABLED = demisto.params().get('enable_outbound_file_mirroring', False)
    LONG_RUNNING_ENABLED = demisto.params().get('longRunning', True)
    DEMISTO_API_KEY = demisto.params().get('demisto_api_key', {}).get('password', '')
    demisto_urls = demisto.demistoUrls()
    DEMISTO_URL = demisto_urls.get('server')
    IGNORE_RETRIES = demisto.params().get('ignore_event_retries', True)
    EXTENSIVE_LOGGING = demisto.params().get('extensive_logging', False)
    common_channels = demisto.params().get('common_channels', None)
    COMMON_CHANNELS = parse_common_channels(common_channels)
    DISABLE_CACHING = demisto.params().get('disable_caching', False)

    # Formats the error message for the 'Channel Not Found' errors
    error_str = 'The channel was not found'
    if DISABLE_CACHING:
        error_str += ' and Disable Caching of Users and Channels is checked. While caching is disabled, please use the' \
                     ' `channel_id` argument, or configure' \
                     ' the Common Channels parameter. If this command worked for you previously consider enabling ' \
                     'caching. However, note that it is recommended to Disable Caching. Please refer to ' \
                     'https://xsoar.pan.dev/docs/reference/integrations/slack-v3#caching for more details.'
    else:
        error_str += '. Either the Slack app is not a member of the channel, or the slack app does not have permission' \
                     ' to find the channel.'
    CHANNEL_NOT_FOUND_ERROR_MSG = error_str

    if command_name != 'long-running-execution':
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        if not loop._default_executor:  # type: ignore[attr-defined]
            demisto.info(f'setting _default_executor on loop: {loop} id: {id(loop)}')
            loop.set_default_executor(concurrent.futures.ThreadPoolExecutor(max_workers=4))

    # Handle Long-Running Specific Globals
    if command_name == 'long-running-execution':
        demisto.debug('in long running execution init globals')
        # Bot identification
        integration_context = get_integration_context(SYNC_CONTEXT)
        if integration_context.get('bot_user_id'):
            BOT_ID = integration_context['bot_user_id']
            if BOT_ID == 'null' or BOT_ID is None:
                # In some cases the bot_id can be stored as a string 'null', this handles this edge case.
                BOT_ID = get_bot_id()
                set_to_integration_context_with_retries({'bot_user_id': BOT_ID}, OBJECTS_TO_KEYS, SYNC_CONTEXT)
        else:
            BOT_ID = get_bot_id()
            set_to_integration_context_with_retries({'bot_user_id': BOT_ID}, OBJECTS_TO_KEYS, SYNC_CONTEXT)

        # Pull initial Cached context and set the Expiry
        CACHE_EXPIRY = next_expiry_time()
        CACHED_INTEGRATION_CONTEXT = get_integration_context(SYNC_CONTEXT)


def parse_common_channels(common_channels: str):
    common_channels = (common_channels or '').strip()
    if not common_channels:
        return {}
    try:
        stripped_channels = {}
        for pair in re.split(r',|\n', common_channels):
            stripped = pair.strip()
            if stripped:
                key, val = stripped.split(':')
                stripped_channels[key.strip()] = val.strip()
    except Exception as e:
        demisto.error(f'{common_channels=} error parsing common channels {str(e)}')
        raise ValueError('Invalid common_channels parameter value. common_channels must be in key:value,key2:value2 format') \
            from e
    return stripped_channels


def print_thread_dump():
    demisto.info(f'current thread: {threading.current_thread().name}')
    for threadId, stack in sys._current_frames().items():
        stack_str = '\n'.join(traceback.format_stack(stack))
        demisto.info(f'{threadId} stack: {stack_str}')


def loop_info():
    loop = asyncio.get_running_loop()
    info = f'loop: {loop}. id: {id(loop)}.'
    info += f'executor: {loop._default_executor} id: {id(loop._default_executor)}'  # type: ignore[attr-defined]
    if loop._default_executor:  # type: ignore[attr-defined]
        info += f' executor threads size: {len(loop._default_executor._threads)}'  # type: ignore[attr-defined]
        info += f' max: {loop._default_executor._max_workers} {loop._default_executor._threads}'  # type: ignore[attr-defined]
    return info


def slack_get_integration_context():
    context_statistics, integration_context = slack_get_integration_context_statistics()
    readable_stats = tableToMarkdown(name='Long Running Context Statistics', t=context_statistics)
    demisto.results({
        'Type': entryTypes['note'],
        'HumanReadable': readable_stats,
        'ContentsFormat': EntryFormat.MARKDOWN,
        'Contents': readable_stats,
    })
    return_results(
        fileResult('slack_integration_context.json', json.dumps(integration_context), EntryType.ENTRY_INFO_FILE))


def slack_get_integration_context_statistics():
    context_statistics = {}
    integration_context = get_integration_context()
    # Mirrors Data
    if integration_context.get('mirrors'):
        mirrors = json.loads(integration_context.get('mirrors'))
        context_statistics['Mirrors Count'] = len(mirrors)
        context_statistics['Mirror Size In Bytes'] = sys.getsizeof(integration_context.get('mirrors', []))
    # Conversations Data
    if integration_context.get('conversations'):
        conversations = json.loads(integration_context.get('conversations'))
        context_statistics['Conversations Count'] = len(conversations)
        context_statistics['Conversations Size In Bytes'] = sys.getsizeof(integration_context.get('conversations', []))
    # Users Data
    if integration_context.get('users'):
        users = json.loads(integration_context.get('users'))
        context_statistics['Users Count'] = len(users)
        context_statistics['Users Size In Bytes'] = sys.getsizeof(integration_context.get('users', []))
    # Questions Data
    if integration_context.get('questions'):
        questions = json.loads(integration_context.get('questions'))
        context_statistics['Questions Count'] = len(questions)
        context_statistics['Questions Size In Bytes'] = sys.getsizeof(integration_context.get('questions', []))
    return context_statistics, integration_context


def user_session_reset():
    user_id = demisto.args().get('user_id')
    body = {
        'user_id': user_id,
    }
    try:
        send_slack_request_sync(USER_CLIENT, 'admin.users.session.reset', body=body)
        return_results(CommandResults(readable_output=f"The session was reset successfully to the user {user_id}."))

    except SlackApiError as slack_error:
        return_error(f"{slack_error}")


def fetch_samples():
    """
    The integration fetches incidents in the long-running-execution command. Fetch incidents is called
    only when "Pull From Instance" is clicked in create new classifier section in Cortex XSOAR.
    The fetch incidents returns samples of incidents generated by the long-running-execution.
    """
    demisto.incidents(get_integration_context().get('samples'))


def main() -> None:
    """
    Main
    """
    global CLIENT, USER_CLIENT, EXTENSIVE_LOGGING

    commands = {
        'test-module': test_module,
        'fetch-incidents': fetch_samples,
        'long-running-execution': long_running_main,
        'mirror-investigation': mirror_investigation,
        'send-notification': slack_send,
        'slack-send-file': slack_send_file,
        'slack-set-channel-topic': set_channel_topic,
        'close-channel': close_channel,
        'slack-create-channel': create_channel,
        'slack-invite-to-channel': invite_to_channel,
        'slack-kick-from-channel': kick_from_channel,
        'slack-rename-channel': rename_channel,
        'slack-get-user-details': get_user,
        'slack-get-integration-context': slack_get_integration_context,
        'slack-edit-message': slack_edit_message,
        'slack-pin-message': pin_message,
        'slack-user-session-reset': user_session_reset,
        'slack-get-conversation-history': conversation_history,
        'slack-list-channels': list_channels,
        'slack-get-conversation-replies': conversation_replies,
    }

    command_name: str = demisto.command()

    try:
        demisto.info(f'{command_name} started.')
        command_func = commands[command_name]
        init_globals(command_name)
        demisto.info('after init globals')
        if EXTENSIVE_LOGGING:
            os.environ['PYTHONASYNCIODEBUG'] = "1"
        support_multithreading()
        command_func()  # type: ignore
    except Exception as e:
        demisto.error(f'Error occured error: {e}')
        demisto.error(traceback.format_exc())
        return_error(str(e))

    finally:
        demisto.info(f'{command_name} completed.')  # type: ignore
        if EXTENSIVE_LOGGING:
            print_thread_dump()


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    register_signal_handler_profiling_dump(profiling_dump_rows_limit=PROFILING_DUMP_ROWS_LIMIT)
    main()
