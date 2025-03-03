import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import shutil
from ZoomApiModule import *
from traceback import format_exc
from datetime import datetime
from fastapi import Depends, FastAPI, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.security.api_key import APIKey, APIKeyHeader
from secrets import compare_digest
from fastapi_utils.tasks import repeat_every
import uvicorn
from uvicorn.logging import AccessFormatter
from copy import copy
import hashlib
import hmac
from tempfile import NamedTemporaryFile


app = FastAPI()

basic_auth = HTTPBasic(auto_error=False)
token_auth = APIKeyHeader(auto_error=False, name='Authorization')

SYNC_CONTEXT = True
OBJECTS_TO_KEYS = {
    'messages': 'entitlement',
}
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
PLAYGROUND_INVESTIGATION_TYPE = 9

# Note#1: type "Pro" is the old version, and "Licensed" is the new one, and i want to support both.
# Note#2: type "Corporate" is officially not supported any more, but i did not remove it just in case it still works.
USER_TYPE_MAPPING = {
    "Basic": 1,
    "Pro": 2,
    "Licensed": 2,
    "Corporate": 3
}
MONTHLY_RECURRING_TYPE_MAPPING = {
    "Daily": 1,
    "Weekly": 2,
    "Monthly": 3
}
INSTANT = "Instant"
SCHEDULED = "Scheduled"
RECURRING_WITH_TIME = "Recurring meeting with fixed time"

MEETING_TYPE_NUM_MAPPING = {
    "Instant": 1,
    "Scheduled": 2,
    "Recurring meeting with fixed time": 8
}
FILE_TYPE_MAPPING = {
    'MP4': 'Video',
    'M4A': 'Audio'
}
POSTING_PERMISSIONS_MAPPING = {
    'All members can post': 1,
    'Only the owner and admins can post': 2,
    'Only the owner, admins and certain members can post': 3
}

MEMBER_PERMISSIONS_MAPPING = {
    'All channel members can add': 1,
    'Only channel owner and admins can add': 2
}

CHANNEL_TYPE_MAPPING = {
    'Private channel': 1,
    'Private channel with members that belong to one account': 2,
    'Public channel': 3,
    'New chat': 4
}
AT_TYPE = {
    'Mention a contact': 1,
    'Mention "all" to notify everyone in the channel.': 2

}

WRONG_TIME_FORMAT = "Wrong time format. Use this format: 'yyyy-MM-ddTHH:mm:ssZ' or 'yyyy-MM-ddTHH:mm:ss' "
LIMIT_AND_EXTRA_ARGUMENTS = """Too many arguments. If you choose a limit,
                                       don't enter a user_id or page_size or next_page_token or page_number."""
LIMIT_AND_EXTRA_ARGUMENTS_MEETING_LIST = """Too many arguments. If you choose a limit,
                                       don't enter a page_size or next_page_token or page_number."""
INSTANT_AND_TIME = "Too many arguments.Use start_time and timezone for scheduled meetings only."
JBH_TIME_AND_NO_JBH = """Collision arguments.
join_before_host_time argument can be used only if join_before_host is 'True'."""
WAITING_ROOM_AND_JBH = "Collision arguments. join_before_host argument can be used only if waiting_room is 'False'."
END_TIMES_AND_END_DATE_TIME = "Collision arguments. Choose only one of these two arguments, end_time or end_date_time."
NOT_RECURRING_WITH_RECURRING_ARGUMENTS = """One or more arguments that were filed
are used for a recurring meeting with a fixed time only."""
NOT_MONTHLY_AND_MONTHLY_ARGUMENTS = """One or more arguments that were
filed are for a recurring meeting with a fixed time and monthly recurrence_type only."""
MONTHLY_RECURRING_MISIING_ARGUMENTS = """Missing arguments. A recurring meeting with a fixed time and monthly recurrence_type
            must have the following arguments: monthly_week and monthly_week_day."""
NOT_WEEKLY_WITH_WEEKLY_ARGUMENTS = "Weekly_days is for weekly recurrence_type only."
EXTRA_PARAMS = """Too many fields were filled.
You should fill the Account ID, Client ID, and Client Secret fields (OAuth),
OR the API Key and API Secret fields (JWT - Deprecated)."""
RECURRING_MISSING_ARGUMENTS = """Missing arguments. A recurring meeting with a fixed
time is missing this argument: recurrence_type."""
MISSING_ARGUMENT = """Missing either a contact info or a channel id"""
USER_NOT_FOUND = """ This user email can't be found """
MARKDOWN_AND_EXTRA_ARGUMENTS = """Too many arguments. If you choose is_markdown,
                    don't provide one of the following arguments: start_position, end_position, format_type, at_type,
                    rt_start_position, rt_end_position or format_attr"""
MARKDOWN_EXTRA_FORMATS = """Too many style in text. you can provide only one style type"""
MARKDOWN_EXTRA_MENTIONS = """Too many mentions in text. you can provide only one mention in each message"""
WRONG_CHANNEL = """Couldn't find channel id base on provided channel_name. channel_name can use only for  mirrored channel.
Otherwise, please use the channel ID instead."""
MISSING_ARGUMENT_JID = """Missing argument: You must provide either a user ID or a channel ID.
If you're using a mirrored channel, you have the option to specify the channel name as well."""
TOO_MANY_JID = """Too many argument you must provide either a user JID or a channel id and not both """
BOT_PARAM_CHECK = """If you're using the Zoom chatbot, it's essential to provide all the necessary bot parameters,
including the botJID, bot_client_id, and bot_client_secret.
you can find these values in the Zoom Chatbot app configuration"""
OAUTH_PARAM_CHECK = """if you are using zoom APIs you must provide Oauth client_id and client_secret
you can find this values in the Zoom Oauth Server-To-Server app configuration"""
CLIENT: Zoom_Client
SECRET_TOKEN: str
MESSAGE_FOOTER = '\n**From Zoom**'
MIRRORING_ENABLED: bool = False
LONG_RUNNING: bool = False
MIRROR_TYPE = 'mirrorEntry'
CACHED_INTEGRATION_CONTEXT: dict
CACHE_EXPIRY: float


'''CLIENT CLASS'''


class UserAgentFormatter(AccessFormatter):
    """This formatter extracts and includes the 'User-Agent' header information
    in the log messages."""

    def get_user_agent(self, scope: Dict) -> str:
        headers = scope.get('headers', [])
        user_agent_header = list(filter(lambda header: header[0].decode().lower() == 'user-agent', headers))
        user_agent = ''
        if len(user_agent_header) == 1:
            user_agent = user_agent_header[0][1].decode()
        return user_agent

    def format_message(self, record):
        """Include the 'User-Agent' header information in the log message.
        Args:
            record: The log record to be formatted.
        Returns:
            str: The formatted log message."""
        record_copy = copy(record)
        scope = record_copy.__dict__['scope']
        user_agent = self.get_user_agent(scope)
        record_copy.__dict__.update({'user_agent': user_agent})
        return super().formatMessage(record_copy)


class Client(Zoom_Client):
    """ A client class that implements logic to authenticate with Zoom application. """

    def zoom_create_user(self, user_type_num: int, email: str, first_name: str, last_name: str):
        return self.error_handled_http_request(
            method='POST',
            url_suffix='users',
            headers={'authorization': f'Bearer {self.access_token}'},
            json_data={
                'action': 'create',
                'user_info': {
                    'email': email,
                    'type': user_type_num,
                    'first_name': first_name,
                    'last_name': last_name}},
        )

    def zoom_list_users(self, page_size: int, status: str = "active",
                        next_page_token: str = None,
                        role_id: str = None, url_suffix: str = None,
                        page_number: int = None):
        return self.error_handled_http_request(
            method='GET',
            url_suffix=url_suffix,
            headers={'authorization': f'Bearer {self.access_token}'},
            params={
                'status': status,
                'page_size': page_size,
                'page_number': page_number,
                'next_page_token': next_page_token,
                'role_id': role_id})

    def zoom_delete_user(self, user: str, action: str):
        return self.error_handled_http_request(
            method='DELETE',
            url_suffix='users/' + user,
            headers={'authorization': f'Bearer {self.access_token}'},
            json_data={'action': action},
            resp_type='response',
            return_empty_response=True
        )

    def zoom_create_meeting(self, url_suffix: str, json_data: dict):
        return self.error_handled_http_request(
            method='POST',
            url_suffix=url_suffix,
            headers={'authorization': f'Bearer {self.access_token}'},
            json_data=json_data)

    def zoom_meeting_get(self, meeting_id: str, occurrence_id: str | None = None,
                         show_previous_occurrences: bool | str = False):
        return self.error_handled_http_request(
            method='GET',
            url_suffix=f"/meetings/{meeting_id}",
            headers={'authorization': f'Bearer {self.access_token}'},
            params={
                "occurrence_id": occurrence_id,
                "show_previous_occurrences": show_previous_occurrences
            })

    def zoom_meeting_list(self, user_id: str, next_page_token: str | None = None, page_size: int | str = 30,
                          type: str | int | None = None, page_number: int = None):
        return self.error_handled_http_request(
            method='GET',
            url_suffix=f"users/{user_id}/meetings",
            headers={'authorization': f'Bearer {self.access_token}'},
            params={
                'type': type,
                'next_page_token': next_page_token,
                'page_size': page_size,
                'page_number': page_number
            })

    def zoom_fetch_recording(self, method: str, url_suffix: str = '', full_url: str = '',
                             stream: bool = False, resp_type: str = 'json'):
        return self.error_handled_http_request(
            method=method,
            full_url=full_url,
            url_suffix=url_suffix,
            resp_type=resp_type,
            stream=stream,
            headers={'authorization': f'Bearer {self.access_token}'},
        )

    def zoom_list_channels(self, page_size: int, next_page_token: str = None, url_suffix: str = '',
                           page_number: int = 1):
        return self.error_handled_http_request(
            method='GET',
            url_suffix=f"chat/{url_suffix}",
            headers={'authorization': f'Bearer {self.access_token}'},
            params={
                'page_size': page_size,
                'page_number': page_number,
                'next_page_token': next_page_token}
        )

    def zoom_create_channel(self, url_suffix: str, json_data: dict):
        return self.error_handled_http_request(
            method='POST',
            url_suffix=url_suffix,
            headers={'authorization': f'Bearer {self.access_token}'},
            json_data=json_data)

    def zoom_update_channel(self, url_suffix: str, json_data: dict):
        return self.error_handled_http_request(
            method='PATCH',
            url_suffix=url_suffix,
            headers={'authorization': f'Bearer {self.access_token}'},
            json_data=json_data,
            resp_type='response',
            return_empty_response=True
        )

    def zoom_list_user_channels(self, user_id: str, page_size: int, next_page_token: str = None, url_suffix: str = '',
                                page_number: int = None):
        return self.error_handled_http_request(
            method='GET',
            url_suffix=f"chat/{url_suffix}",
            headers={'authorization': f'Bearer {self.access_token}'},
            params={
                'user_id': user_id,
                'page_size': page_size,
                'page_number': page_number,
                'next_page_token': next_page_token}
        )

    def zoom_delete_channel(self, url_suffix: str):
        return self.error_handled_http_request(
            method='DELETE',
            url_suffix=url_suffix,
            headers={'authorization': f'Bearer {self.access_token}'},
            resp_type='response',
            return_empty_response=True
        )

    def zoom_invite_to_channel(self, members_json: str, url: str = None):
        return self.error_handled_http_request(
            method='POST',
            url_suffix=url,
            headers={'authorization': f'Bearer {self.access_token}'},
            json_data=members_json)

    def zoom_remove_from_channel(self, url_suffix: str = None):
        return self.error_handled_http_request(
            method='DELETE',
            url_suffix=url_suffix,
            headers={'authorization': f'Bearer {self.access_token}'},
            resp_type='response',
            return_empty_response=True)

    def zoom_send_file(self, url_suffix: str, file_info: dict, json_data: dict):

        files = {'file': (file_info['name'], open(file_info['path'], 'rb'))}

        response = self.error_handled_http_request(
            method='POST',
            full_url=url_suffix,
            headers={'Authorization': f'Bearer {self.access_token}'},
            files=files,
            data=json_data
        )
        return response

    def zoom_upload_file(self, url_suffix: str, file_info: dict):
        files = {'file': (file_info['name'], open(file_info['path'], 'rb'))}
        return self._http_request('POST',
                                  headers={'Authorization': f'Bearer {self.access_token}'},
                                  files=files,
                                  full_url=url_suffix)

    def zoom_send_message(self, url_suffix: str, json_data: dict):
        return self.error_handled_http_request(
            method='POST',
            url_suffix=url_suffix,
            json_data=json_data,
            headers={'authorization': f'Bearer {self.access_token}'}
        )

    def zoom_delete_message(self, url_suffix: str = None):
        return self.error_handled_http_request(
            method='DELETE',
            url_suffix=url_suffix,
            headers={'authorization': f'Bearer {self.access_token}'},
            resp_type='response',
            return_empty_response=True)

    def zoom_update_message(self, url_suffix: str, json_data: dict):
        return self.error_handled_http_request(
            method='PUT',
            url_suffix=url_suffix,
            json_data=json_data,
            headers={'authorization': f'Bearer {self.access_token}'},
            return_empty_response=True
        )

    def zoom_list_user_messages(self, user_id: str, date_arg: datetime, from_arg: datetime, to_arg: datetime, page_size: int,
                                next_page_token: str = None, url_suffix: str = None, page_number: int = None,
                                to_contact: str = None,
                                to_channel: str = None,
                                include_deleted_and_edited_message: bool = False,
                                search_type: str = None,
                                search_key: str = None,
                                exclude_child_message: bool = False):

        return self.error_handled_http_request(
            method='GET',
            url_suffix=f"chat/{url_suffix}",
            headers={'authorization': f'Bearer {self.access_token}'},
            params={
                'user_id': user_id,
                'page_size': page_size,
                'page_number': page_number,
                'next_page_token': next_page_token,
                'to_contact': to_contact,
                'to_channel': to_channel,
                'date': date_arg,
                'from': from_arg,
                'to': to_arg,
                'include_deleted_and_edited_message': include_deleted_and_edited_message,
                'search_key': search_key,
                'search_type': search_type,
                'exclude_child_message': exclude_child_message}
        )

    def zoom_send_notification(self, url_suffix: str, json_data: dict):
        return self.error_handled_http_request(
            method='POST',
            url_suffix=url_suffix,
            json_data=json_data,
            headers={'authorization': f'Bearer {self.bot_access_token}'}
        )

    def zoom_get_admin_user_id_from_token(self):
        return self.error_handled_http_request(
            method='get',
            url_suffix='users/me',
            headers={'authorization': f'Bearer {self.access_token}'}
        )

    def zoom_delete_user_token(self, url_suffix: str):
        return self.error_handled_http_request(
            method='DELETE',
            url_suffix=url_suffix,
            resp_type='response',
            headers={'authorization': f'Bearer {self.access_token}'}
        )


'''HELPER FUNCTIONS'''


def next_expiry_time() -> float:
    """
    Returns:
        A float representation of a new expiry time with an offset of 5 seconds
    """
    return (datetime.now(timezone.utc) + timedelta(seconds=5)).timestamp()


async def check_and_handle_entitlement(text: str, message_id: str, user_name: str, user_email: str) -> str:
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
        demisto.handleEntitlementForUser(incident_id, guid, user_email, text, task_id)
        message['remove'] = True
        set_to_integration_context_with_retries({'messages': messages}, OBJECTS_TO_KEYS, SYNC_CONTEXT)
    return reply


def save_entitlement(entitlement, message_id, reply, expiry, default_response, to_jid):
    """
    Saves an entitlement

    Args:
        entitlement: The entitlement
        message_id: The message_id
        reply: The reply to send to the user.
        expiry: The question expiration date.
        default_response: The response to send if the question times out.
        to_jid: the user jid the message was sent to
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
        'to_jid': to_jid
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


@app.on_event("startup")
@repeat_every(seconds=60, wait_first=True)
async def check_for_unanswered_messages():
    # demisto.debug('check for unanswered messages')
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
                    demisto.debug(f"message expired: {message}")
                    _ = await answer_question(message.get('default_response'), message, email='')
                    updated_messages.append(message)
                    continue
            updated_messages.append(message)
        if updated_messages:
            set_to_integration_context_with_retries({'messages': messages}, OBJECTS_TO_KEYS, SYNC_CONTEXT)


def run_long_running(port: int, is_test: bool = False):
    while True:
        certificate = demisto.params().get('certificate', '')
        private_key = demisto.params().get('key', '')

        certificate_path = ''
        private_key_path = ''
        try:
            ssl_args = {}

            if certificate and private_key:
                certificate_file = NamedTemporaryFile(delete=False)
                certificate_path = certificate_file.name
                certificate_file.write(bytes(certificate, 'utf-8'))
                certificate_file.close()
                ssl_args['ssl_certfile'] = certificate_path

                private_key_file = NamedTemporaryFile(delete=False)
                private_key_path = private_key_file.name
                private_key_file.write(bytes(private_key, 'utf-8'))
                private_key_file.close()
                ssl_args['ssl_keyfile'] = private_key_path

                demisto.debug('Starting HTTPS Server')
            else:
                demisto.debug('Starting HTTP Server')

            integration_logger = IntegrationLogger()
            integration_logger.buffering = False
            log_config = dict(uvicorn.config.LOGGING_CONFIG)
            log_config['handlers']['default']['stream'] = integration_logger
            log_config['handlers']['access']['stream'] = integration_logger
            log_config['formatters']['access'] = {
                '()': UserAgentFormatter,
                'fmt': '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s "%(user_agent)s"'
            }
            uvicorn.run(app, host='0.0.0.0', port=port, log_config=log_config, **ssl_args)  # type: ignore[arg-type]
        except Exception as e:
            demisto.error(f'An error occurred in the long running loop: {str(e)} - {format_exc()}')
            demisto.updateModuleHealth(f'An error occurred: {str(e)}')
        finally:
            if certificate_path:
                os.unlink(certificate_path)
            if private_key_path:
                os.unlink(private_key_path)
            time.sleep(5)


def run_log_running(port: int, is_test: bool = False):
    while True:
        try:
            demisto.debug('Starting Server')
            integration_logger = IntegrationLogger()
            integration_logger.buffering = False
            log_config = dict(uvicorn.config.LOGGING_CONFIG)
            log_config['handlers']['default']['stream'] = integration_logger
            log_config['handlers']['access']['stream'] = integration_logger
            log_config['formatters']['access'] = {
                '()': UserAgentFormatter,
                'fmt': '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s "%(user_agent)s"'
            }
            uvicorn.run(app, host='0.0.0.0', port=port, log_config=log_config)
            if is_test:
                time.sleep(5)
                return 'ok'
        except Exception as e:
            demisto.error(f'An error occurred in the long running loop: {str(e)} - {format_exc()}')
            demisto.updateModuleHealth(f'An error occurred: {str(e)}')
        finally:
            time.sleep(5)


async def zoom_send_notification_async(client, url_suffix, json_data_all):
    client.zoom_send_notification(url_suffix, json_data_all)


async def process_entitlement_reply(
    entitlement_reply: str,
    account_id: str,
    robot_jid: str,
    to_jid: str | None = None,
    user_name: str | None = None,
    action_text: str | None = None,
):
    """
    Triggered when an entitlement reply is found, this function will update the original message with the reply message.
    :param entitlement_reply: str: The text to update the asking question with.
    :param user_name: str: name of the user who answered the entitlement
    :param action_text: str: The text attached to the button, used for string replacement.
    :param toJid: str: The Jid of where the question exists.
    :param accountId: str: Zoom account ID
    :param robotJid: str: Zoom BOT JID
    :return: None
    """
    if '{user}' in entitlement_reply:
        entitlement_reply = entitlement_reply.replace('{user}', str(user_name))
    if '{response}' in entitlement_reply and action_text:
        entitlement_reply = entitlement_reply.replace('{response}', str(action_text))

    url_suffix = '/im/chat/messages'
    content_json = {
        "content": {
            "body": [
                {
                    "type": "message",
                    "text": entitlement_reply
                }
            ]
        },
        "to_jid": to_jid,
        "robot_jid": robot_jid,
        "account_id": account_id
    }
    await zoom_send_notification_async(CLIENT, url_suffix, content_json)


async def answer_question(text: str, question: dict, email: str = ''):
    entitlement = question.get('entitlement', '')
    to_jid = question.get('to_jid')
    guid, incident_id, task_id = extract_entitlement(entitlement)
    try:
        demisto.handleEntitlementForUser(incident_id, guid, email, text, task_id)
        account_id = CLIENT.account_id
        bot_jid = CLIENT.bot_jid
        if account_id and bot_jid:
            _ = await process_entitlement_reply(text, account_id, bot_jid, to_jid)
    except Exception as e:
        demisto.error(f'Failed handling entitlement {entitlement}: {str(e)}')
    question['remove'] = True
    return incident_id


async def handle_text_received_from_zoom(investigation_id: str, text: str, operator_email: str, operator_name: str):
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


async def handle_listen_error(error: str):
    """
    Logs an error and updates the module health accordingly.

    Args:
        error: The error string.
    """
    demisto.error(error)
    demisto.updateModuleHealth(error)


async def handle_mirroring(payload):
    """
    handle messages from the Zoom webhook that have been identified as possible mirrored messages
    If we find one, we will update the mirror object and send
    the message to the corresponding investigation's war room as an entry.
    :param payload: str: The request payload from zoom
    :return: None
    """
    channel_id = payload.get("object", {}).get("channel_id")
    if not channel_id:
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
        message = payload["object"]["message"]
        demisto.info(f"payload:{payload}")
        operator_email = payload["operator"]
        operator_name = zoom_get_user_name_by_email(CLIENT, operator_email)
        investigation_id = mirror['investigation_id']
        await handle_text_received_from_zoom(investigation_id, message, operator_email, operator_name)


async def event_url_validation(payload):
    """ Verify the authenticity of a token
    Args:
        payload : request from Zoom
    Returns:
        json_res: A dictionary containing the 'plainToken' and its corresponding 'encryptedToken' (HMAC-SHA256 signature).
    """
    plaintoken = payload.get('plainToken')
    hash_object = hmac.new(SECRET_TOKEN.encode('utf-8'), msg=plaintoken.encode('utf-8'), digestmod=hashlib.sha256)
    expected_signature = hash_object.hexdigest()
    json_res = {
        "plainToken": plaintoken,
        "encryptedToken": expected_signature
    }
    return json_res


@app.post('/')
async def handle_zoom_response(request: Request, credentials: HTTPBasicCredentials = Depends(basic_auth),
                               token: APIKey = Depends(token_auth)):
    """handle any response that came from Zoom app
    Args:
        request : zoom request
    Returns:
        JSONResponse:response to zoom
    """
    request = await request.json()
    demisto.debug(request)
    credentials_param = demisto.params().get('credentials')
    auth_failed = False
    v_token = demisto.params().get('verification_token', {}).get('password')
    if not str(token).startswith('Basic') and v_token:
        if token != v_token:
            auth_failed = True

    elif credentials and credentials_param and (username := credentials_param.get('identifier')):
        password = credentials_param.get('password', '')
        if not compare_digest(credentials.username, username) or not compare_digest(credentials.password, password):
            auth_failed = True
    if auth_failed:
        demisto.debug('Authorization failed')
        return Response(status_code=status.HTTP_401_UNAUTHORIZED, content='Authorization failed.')

    event_type = request['event']
    payload = request['payload']
    try:
        if event_type == 'endpoint.url_validation' and SECRET_TOKEN:
            res = await event_url_validation(payload)
            return JSONResponse(content=res)

        elif event_type == 'interactive_message_actions':
            if 'actionItem' in payload:
                action = payload['actionItem']['value']
            elif 'selectedItems' in payload:
                action = payload['selectedItems'][0]['value']
            else:
                return Response(status_code=status.HTTP_400_BAD_REQUEST)
            message_id = payload['messageId']
            account_id = payload['accountId']
            robot_jid = payload['robotJid']
            to_jid = payload['toJid']
            user_name = payload['userName']
            user_id = payload['userId']
            user_email = zoom_get_user_email_by_id(CLIENT, user_id)
            entitlement_reply = await check_and_handle_entitlement(action, message_id, user_name, user_email)
            if entitlement_reply:
                await process_entitlement_reply(entitlement_reply, account_id, robot_jid, to_jid, user_name, action)
                demisto.updateModuleHealth("")
            demisto.debug(f"Action {action} was clicked on message id {message_id}")
            return Response(status_code=status.HTTP_200_OK)
        elif event_type == "chat_message.sent" and MIRRORING_ENABLED:
            await handle_mirroring(payload)
            return Response(status_code=status.HTTP_200_OK)
        else:
            return Response(status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        await handle_listen_error(f'An error occurred while handling a response from Zoom: {e}')


def test_module(client: Client):
    """Tests connectivity with the client.
    Takes as an argument all client arguments to create a new client
    """
    try:
        if MIRRORING_ENABLED and (not LONG_RUNNING or not SECRET_TOKEN or not client.bot_client_id or not
                                  client.bot_client_secret or not client.bot_jid):
            raise DemistoException("""Mirroring is enabled, however long running is disabled
or the necessary bot authentication parameters are missing.
For mirrors to work correctly, long running must be enabled and you must provide all
the zoom-bot following parameters:
secret token,
Bot JID,
bot client id and secret id""")
        client.zoom_list_users(page_size=1, url_suffix="users")
        if client.bot_access_token:
            json_data = {
                "robot_jid": client.bot_jid,
                "to_jid": "foo@conference.xmpp.zoom.us",
                "account_id": client.account_id,
                "content": {
                    "head": {
                        "text": "hi"
                    }
                }
            }
            client.zoom_send_notification(url_suffix='/im/chat/messages', json_data=json_data)
    except DemistoException as e:
        error_message = e.message
        if 'Invalid access token' in error_message:
            error_message = INVALID_CREDENTIALS
        elif "The Token's Signature resulted invalid" in error_message:
            error_message = INVALID_API_SECRET
        elif 'Invalid client_id or client_secret' in error_message:
            error_message = INVALID_ID_OR_SECRET
        elif 'No channel or user can be found with the given to_jid.' in error_message:
            return 'ok'
        elif 'Invalid authorization token.' in error_message:
            error_message = INVALID_TOKEN
        elif 'No Chatbot can be found with the given robot_jid value.' in error_message:
            error_message = INVALID_BOT_ID
        elif 'Invalid robot_jid value specified in the Request Body.' in error_message:
            error_message = INVALID_BOT_ID
        else:
            error_message = f'Problem reaching Zoom API, check your credentials. Error message: {error_message}'
        return error_message
    return 'ok'


def remove_None_values_from_dict(dict_to_reduce: Dict[str, Any]):
    """
    Removes None values (but not False values) from a given dict and from the nested dicts in it.
    """
    reduced_dict = {}
    for key, value in dict_to_reduce.items():
        if value is not None:
            if isinstance(value, dict):
                reduced_nested_dict = remove_None_values_from_dict(value)
                if reduced_nested_dict:
                    reduced_dict[key] = reduced_nested_dict
            else:
                reduced_dict[key] = value

    return reduced_dict


def check_start_time_format(start_time):
    """checking if the time format is a full time format"""
    expected_format = "%Y-%m-%dT%H:%M:%S"
    if start_time.endswith("Z"):
        expected_format += "%z"
    try:
        datetime.strptime(start_time, expected_format)
    except ValueError as e:
        raise DemistoException(WRONG_TIME_FORMAT) from e


def manual_list_user_pagination(client: Client, next_page_token: str | None,
                                limit: int, status: str, role_id: str | None):
    res = []
    page_size = min(limit, MAX_RECORDS_PER_PAGE)
    while limit > 0 and next_page_token != '':
        response = client.zoom_list_users(page_size=page_size, status=status,
                                          next_page_token=next_page_token,
                                          role_id=role_id, url_suffix="users")
        next_page_token = response.get("next_page_token")

        res.append(response)
        limit -= MAX_RECORDS_PER_PAGE
    return res


def manual_list_channel_pagination(client: Client, next_page_token: str | None,
                                   limit: int, url_suffix: str):
    res = {}
    page_size = min(limit, MAX_RECORDS_PER_PAGE)
    while limit > 0:
        response = client.zoom_list_channels(page_size=page_size,
                                             next_page_token=next_page_token,
                                             url_suffix=url_suffix)
        next_page_token = response.get("next_page_token")

        res.update(response)
        limit -= MAX_RECORDS_PER_PAGE
    return res


def manual_list_user_channel_pagination(client: Client, user_id: str, next_page_token: str | None,
                                        limit: int, url_suffix: str):
    res = {}
    page_size = min(limit, MAX_RECORDS_PER_PAGE)
    while limit > 0:
        response = client.zoom_list_user_channels(user_id=user_id,
                                                  page_size=page_size,
                                                  next_page_token=next_page_token,
                                                  url_suffix=url_suffix)
        next_page_token = response.get("next_page_token")

        res.update(response)
        limit -= MAX_RECORDS_PER_PAGE
    return res


def manual_meeting_list_pagination(client: Client, user_id: str, next_page_token: str | None,
                                   limit: int, type: str | int | None):
    res = []
    page_size = min(limit, MAX_RECORDS_PER_PAGE)
    while limit > 0 and next_page_token != '':
        response = client.zoom_meeting_list(user_id=user_id,
                                            next_page_token=next_page_token,
                                            page_size=page_size,
                                            type=type)
        next_page_token = response.get("next_page_token")
        res.append(response)
        # subtract what i already got
        limit -= MAX_RECORDS_PER_PAGE
    return res


def remove_extra_info_list_users(limit, raw_data):
    """_summary_
    Due to the fact that page_size must be const,
    Extra information may be provided

    Args:
        limit (int): the number of records the user asked for
        raw_data (dict):the entire response from the pagination function
    """
    all_info = []
    for page in raw_data:
        users_info = page.get("users", [])
        for user in users_info:
            all_info.append(user)
            if len(all_info) >= limit:
                return all_info
    return all_info


def remove_extra_info_list(name, limit, raw_data):
    """_summary_
    Due to the fact that page_size must be const,
    Extra information may be provided
    Args:
        limit (int): the number of records the user asked for
        raw_data (dict):the entire response from the pagination function
    """
    all_info = []
    channel_info = raw_data.get(name, [raw_data])
    for channel in channel_info:
        all_info.append(channel)
        if len(all_info) >= limit:
            return all_info
    return all_info


def remove_extra_info_meeting_list(limit, raw_data):
    """
    Due to the fact that page_size must be const,
    Extra information may be provided to me, such as:
    In the case of limit = 301, manual_meeting_list_pagination will return 600 meetings (MAX_RECORDS * 2),
    The last 299 must be removed.

    Args:
        limit (int): the number of records the user asked for
        raw_data (dict):the entire response from the pagination function
    """
    all_info = []
    for page in raw_data:
        meetings = page.get("meetings")
        for meeting in meetings:
            all_info.append(meeting)
            if len(all_info) >= limit:
                return all_info
    return all_info


'''FORMATTING FUNCTIONS'''


def zoom_list_users_command(client, **args) -> CommandResults:

    # PREPROCESSING
    client = client
    page_size = arg_to_number(args.get('page_size', 30))
    user_id = args.get('user_id')
    status = args.get('status', "active")
    next_page_token = args.get('next_page_token')
    role_id = args.get('role_id')
    limit = arg_to_number(args.get('limit'))
    page_number = arg_to_number(args.get('page_number', 1))

    url_suffix = f'users/{user_id}' if user_id else 'users'

    if limit:
        if "page_size" in args or "page_number" in args or next_page_token or user_id:
            # arguments collision
            raise DemistoException(LIMIT_AND_EXTRA_ARGUMENTS)
        else:
            # multiple requests are needed
            raw_data = manual_list_user_pagination(client=client, next_page_token=next_page_token,
                                                   limit=limit, status=status, role_id=role_id)

            minimal_needed_info = remove_extra_info_list_users(limit, raw_data)

            md = tableToMarkdown('Users', minimal_needed_info, ['id', 'email',
                                                                'type', 'pmi', 'verified', 'created_at', 'status', 'role_id'])
            md += '\n' + tableToMarkdown('Metadata', [raw_data][0][0], ['total_records'])
            raw_data = raw_data[0]
    else:
        # only one request is needed
        raw_data = client.zoom_list_users(page_size=page_size, status=status,                      # type: ignore[arg-type]
                                          next_page_token=next_page_token,
                                          role_id=role_id, url_suffix=url_suffix, page_number=page_number)
        # parsing the data according to the different given arguments
        if user_id:
            md = tableToMarkdown('User', [raw_data], ['id', 'email',
                                                      'type', 'pmi', 'verified', 'created_at', 'status', 'role_id'])
        else:
            md = tableToMarkdown('Users', raw_data.get("users"), ['id', 'email',
                                                                  'type', 'pmi', 'verified', 'created_at', 'status', 'role_id'])
            md += '\n' + tableToMarkdown('Metadata', [raw_data], ['page_count', 'page_number',
                                                                  'page_size', 'total_records', 'next_page_token'])
    return CommandResults(
        outputs_prefix='Zoom',
        readable_output=md,
        outputs={
            'User': raw_data.get('users'),
            'Metadata': {'Count': raw_data.get('page_count'),
                         'Number': raw_data.get('page_number'),
                         'Size': raw_data.get('page_size'),
                         'Total': raw_data.get('total_records')}
        },
        raw_response=raw_data
    )


def zoom_create_user_command(client, **args) -> CommandResults:
    client = client
    user_type = args.get('user_type', "")
    email = args.get('email')
    first_name = args.get('first_name')
    last_name = args.get('last_name')
    user_type_num = USER_TYPE_MAPPING.get(user_type)
    raw_data = client.zoom_create_user(user_type_num, email, first_name, last_name)
    return CommandResults(
        outputs_prefix='Zoom.User',
        readable_output=f"User created successfully with ID: {raw_data.get('id')}",
        outputs=raw_data,
        raw_response=raw_data
    )


def zoom_delete_user_command(client, **args) -> CommandResults:
    client = client
    user = args.get('user')
    action = args.get("action")
    client.zoom_delete_user(user, action)
    return CommandResults(
        readable_output=f'User {user} was deleted successfully',
    )


def zoom_create_meeting_command(client, **args) -> CommandResults:
    client = client
    user_id = args.get('user')
    topic = args.get('topic', "")
    host_video = argToBoolean(args.get('host_video', True))
    join_before_host_time = args.get('join_before_host_time')
    start_time = args.get('start_time')
    timezone = args.get('timezone', "")
    type = args.get('type', "Instant")
    auto_record_meeting = args.get('auto_record_meeting')
    encryption_type = args.get('encryption_type')
    join_before_host = argToBoolean(args.get('join_before_host', False))
    meeting_authentication = argToBoolean(args.get('meeting_authentication', False))
    waiting_room = argToBoolean(args.get('waiting_room', False))
    end_date_time = args.get('end_date_time')
    end_times = arg_to_number(args.get('end_times', 1))
    monthly_day = arg_to_number(args.get('monthly_day', 1))
    monthly_week = arg_to_number(args.get('monthly_week'))
    monthly_week_day = arg_to_number(args.get('monthly_week_day'))
    repeat_interval = arg_to_number(args.get('repeat_interval'))
    recurrence_type = args.get('recurrence_type', "")
    weekly_days = arg_to_number(args.get('weekly_days', 1))

    num_type: int | None = MEETING_TYPE_NUM_MAPPING.get(type)

    # argument checking
    if type == INSTANT and (timezone or start_time):
        raise DemistoException(INSTANT_AND_TIME)

    if join_before_host_time and not join_before_host:
        raise DemistoException(JBH_TIME_AND_NO_JBH)

    if waiting_room and join_before_host:
        raise DemistoException(WAITING_ROOM_AND_JBH)

    if args.get("end_times") and end_date_time:
        raise DemistoException(END_TIMES_AND_END_DATE_TIME)

    if type != RECURRING_WITH_TIME and any((end_date_time, args.get("end_times"), args.get("monthly_day"),
                                            monthly_week, monthly_week_day, repeat_interval, args.get("weekly_days"))):
        raise DemistoException(NOT_RECURRING_WITH_RECURRING_ARGUMENTS)

    if type == RECURRING_WITH_TIME and recurrence_type != "Monthly" and any((args.get("monthly_day"),
                                                                             monthly_week, monthly_week_day)):
        raise DemistoException(NOT_MONTHLY_AND_MONTHLY_ARGUMENTS)

    if (type == RECURRING_WITH_TIME and recurrence_type == "Monthly"
            and not (monthly_week and monthly_week_day) and not args.get("monthly_day")):
        raise DemistoException(MONTHLY_RECURRING_MISIING_ARGUMENTS)

    if type == RECURRING_WITH_TIME and recurrence_type != "Weekly" and args.get("weekly_days"):
        raise DemistoException(NOT_WEEKLY_WITH_WEEKLY_ARGUMENTS)

    if type == RECURRING_WITH_TIME and not recurrence_type:
        raise DemistoException(RECURRING_MISSING_ARGUMENTS)

    # converting separately after the argument checking, because 0 as an int is equaled to false
    join_before_host_time = arg_to_number(join_before_host_time)

    if start_time:
        check_start_time_format(start_time)

    json_all_data: Dict[str, Union[Any, None, int]] = {}

    # special section for recurring meeting with fixed time
    if type == RECURRING_WITH_TIME:
        recurrence_type_num = MONTHLY_RECURRING_TYPE_MAPPING.get(recurrence_type)
        json_all_data.update({"recurrence": {
            "end_date_time": end_date_time,
            "end_times": end_times,
            "monthly_day": monthly_day,
            "monthly_week": monthly_week,
            "monthly_week_day": monthly_week_day,
            "repeat_interval": repeat_interval,
            "type": recurrence_type_num,
            "weekly_days": weekly_days
        }})
    json_all_data.update({
        "settings": {
            "auto_recording": auto_record_meeting,
            "encryption_type": encryption_type,
            "host_video": host_video,
            "jbh_time": join_before_host_time,
            "join_before_host": join_before_host,
            "meeting_authentication": meeting_authentication,
            "waiting_room": waiting_room
        },
        "start_time": start_time,
        "timezone": timezone,
        "type": num_type,
        "topic": topic,
    })
    # remove all keys with val of None
    json_data = remove_None_values_from_dict(json_all_data)
    url_suffix = f"users/{user_id}/meetings"
    # call the API
    raw_data = client.zoom_create_meeting(url_suffix=url_suffix, json_data=json_data)
    # parsing the response
    if type == "Recurring meeting with fixed time":
        raw_data.update({'start_time': raw_data.get("occurrences")[0].get('start_time')})
        raw_data.update({'duration': raw_data.get("occurrences")[0].get('duration')})

    md = tableToMarkdown('Meeting details', [raw_data], ['uuid', 'id', 'host_id', 'host_email', 'topic',
                                                         'type', 'status', 'start_time', 'duration',
                                                         'timezone', 'created_at', 'start_url', 'join_url'
                                                         ])

    # removing passwords from the response#
    safe_raw_data = raw_data
    for sensitive_info in ["password", "pstn_password", "encrypted_password", "h323_password"]:
        safe_raw_data.pop(sensitive_info, None)
    return CommandResults(
        outputs_prefix='Zoom.Meeting',
        readable_output=md,
        outputs=safe_raw_data,
        raw_response=raw_data
    )


def zoom_fetch_recording_command(client: Client, **args):
    # preprocessing
    results = []
    meeting_id = args.get('meeting_id')
    delete_after = argToBoolean(args.get('delete_after'))
    client = client

    data = client.zoom_fetch_recording(
        method='GET',
        url_suffix=f'meetings/{meeting_id}/recordings'
    )
    recording_files = data.get('recording_files')
    # Getting the audio and video files which are contained in every recording.
    for file in recording_files:
        download_url = file.get('download_url')
        try:
            # download the file
            demisto.debug(f"Trying to download the files of meeting {meeting_id}")
            record = client.zoom_fetch_recording(
                method='GET',
                full_url=download_url,
                resp_type='response',
                stream=True
            )
            file_type = file.get('file_type')
            file_type_as_literal = FILE_TYPE_MAPPING.get(file_type)
            # save the file
            filename = f'recording_{meeting_id}_{file.get("id")}.{file_type}'
            with open(filename, 'wb') as f:
                # Saving the content of the file locally.
                record.raw.decode_content = True
                shutil.copyfileobj(record.raw, f)

            results.append(file_result_existing_file(filename))
            results.append(CommandResults(
                readable_output=f"The {file_type_as_literal} file {filename} was downloaded successfully"))

            if delete_after:
                try:
                    # delete the file from the cloud
                    demisto.debug(f"Trying to delete the file {filename}")
                    client.zoom_fetch_recording(
                        method='DELETE',
                        url_suffix=f'meetings/{meeting_id}/recordings/{file["id"]}',
                        resp_type='response'
                    )
                    results.append(CommandResults(
                        readable_output=f"The {file_type_as_literal} file {filename} was successfully removed from the cloud."))
                except DemistoException as exp:
                    results.append(CommandResults(
                        readable_output=f"Failed to delete file {filename}. {exp}"))

        except DemistoException as exp:
            raise DemistoException(
                f'Unable to download recording for meeting {meeting_id}: {exp}')

    return results


def zoom_meeting_get_command(client, **args) -> CommandResults:
    client = client
    meeting_id = args.get('meeting_id')
    occurrence_id = args.get('occurrence_id')
    show_previous_occurrences = argToBoolean(args.get('show_previous_occurrences'))

    raw_data = client.zoom_meeting_get(meeting_id, occurrence_id, show_previous_occurrences)
    # parsing the response
    md = tableToMarkdown('Meeting details', raw_data, ['uuid', 'id', 'host_id', 'host_email', 'topic',
                                                       'type', 'status', 'start_time', 'duration',
                                                       'timezone', 'agenda', 'created_at', 'start_url', 'join_url',
                                                       ])
    # removing passwords from the response#
    safe_raw_data = raw_data
    for sensitive_info in ["password", "pstn_password", "encrypted_password", "h323_password"]:
        safe_raw_data.pop(sensitive_info, None)
    return CommandResults(
        outputs_prefix='Zoom.Meeting',
        readable_output=md,
        outputs_key_field="id",
        outputs=safe_raw_data,
        raw_response=raw_data
    )


def zoom_meeting_list_command(client, **args) -> CommandResults:
    client = client
    user_id = args.get('user_id', '')
    next_page_token = args.get('next_page_token')
    page_size = arg_to_number(args.get('page_size', 30))
    limit = arg_to_number(args.get('limit'))
    type = args.get('type')
    page_number = arg_to_number(args.get('page_number', 1))

    if limit:
        if "page_size" in args or next_page_token or 'page_number' in args:
            # arguments collision
            raise DemistoException(LIMIT_AND_EXTRA_ARGUMENTS_MEETING_LIST)
        else:
            # multiple request are needed
            raw_data = manual_meeting_list_pagination(client=client, user_id=user_id, next_page_token=next_page_token,
                                                      limit=limit, type=type)

            minimal_needed_info = remove_extra_info_meeting_list(limit=limit, raw_data=raw_data)

            md = tableToMarkdown("Meeting list", minimal_needed_info, ['uuid', 'id',
                                                                       'host_id', 'topic', 'type', 'start time', 'duration',
                                                                       'timezone', 'created_at', 'join_url'
                                                                       ])
            md += "\n" + tableToMarkdown('Metadata', [raw_data][0][0], ['total_records'])
            raw_data = raw_data[0]

    else:
        # one request in needed
        raw_data = client.zoom_meeting_list(user_id=user_id, next_page_token=next_page_token,
                                            page_size=page_size, type=type, page_number=page_number)
        # parsing the data
        md = tableToMarkdown("Meeting list", raw_data.get("meetings"), ['uuid', 'id',
                                                                        'host_id', 'topic', 'type', 'start_time', 'duration',
                                                                        'timezone', 'created_at', 'join_url'
                                                                        ])
        md += "\n" + tableToMarkdown('Metadata', [raw_data], ['next_page_token', 'page_size', 'page_number', 'total_records'])

    return CommandResults(
        outputs_prefix='Zoom',
        readable_output=md,
        # keeping the syntax of the output of the previous version
        outputs={
            'Meeting': raw_data,
            'Metadata': {'Size': raw_data.get('page_size'),
                         'Total': raw_data.get('total_records')}
        },
        raw_response=raw_data
    )


def check_authentication_type_parameters(api_key: str, api_secret: str,
                                         # checking if the user entered extra parameters
                                         # at the configuration level
                                         account_id: str, client_id: str, client_secret: str):
    if any((api_key, api_secret)) and any((account_id, client_id, client_secret)):
        raise DemistoException(EXTRA_PARAMS)


def check_authentication_bot_parameters(bot_Jid: str, client_id: str, client_secret: str):
    """check authentication parameters that both client_id, secret_id, bot_Jid are provided or none of them"""
    if (bot_Jid and client_id and client_secret) or (not bot_Jid and not client_id and not client_secret):
        return
    else:
        raise DemistoException(BOT_PARAM_CHECK)


def check_authentication_parameters(client_id: str, client_secret: str):
    """check authentication parameters that both client_id and secret are provided"""
    if (client_id and client_secret) or (not client_id and not client_secret):
        return
    else:
        raise DemistoException(OAUTH_PARAM_CHECK)


def zoom_list_account_public_channels_command(client, **args) -> CommandResults:
    """
    Lists public channels associated with a Zoom account.
    """
    # PREPROCESSING
    client = client
    page_size = arg_to_number(args.get('page_size', 50))
    channel_id = args.get('channel_id')
    next_page_token = args.get('next_page_token')
    limit = arg_to_number(args.get('limit'))
    page_number = arg_to_number(args.get('page_number', 1))

    url_suffix = f'channels/{channel_id}' if channel_id else 'channels'

    if limit:
        if "page_size" in args or "page_number" in args or next_page_token or channel_id:
            # arguments collision
            raise DemistoException(LIMIT_AND_EXTRA_ARGUMENTS)
        else:
            # multiple requests are needed
            raw_data = manual_list_channel_pagination(
                client=client, next_page_token=next_page_token, limit=limit, url_suffix=url_suffix)

            data = remove_extra_info_list('channels', limit, raw_data)
            token = raw_data.get('next_page_token', None)
    else:
        # only one request is needed
        raw_data = client.zoom_list_channels(page_size=page_size, next_page_token=next_page_token,
                                             url_suffix=url_suffix, page_number=page_number)
        # parsing the data according to the different given arguments
        data = [raw_data] if channel_id else raw_data.get("channels")
        token = raw_data.get('next_page_token', None)
    outputs = []
    for i in data:
        outputs.append({'Channel JID': i.get('jid'),
                        'Channel ID': i.get('id'),
                        'Channel name': i.get('name'),
                        'Channel type': i.get('type'),
                        'Channel url': i.get('channel_url')})

    md = tableToMarkdown('Channels', outputs, removeNull=True)
    md += '\n' + f'Channels Next Token: {token}'

    return CommandResults(
        outputs_prefix='Zoom.Channel',
        readable_output=md,
        outputs={**raw_data,
                 'ChannelsNextToken': token},
        raw_response=raw_data
    )


def zoom_list_user_channels_command(client, **args) -> CommandResults:
    """
    Lists channels associated with a specific Zoom user.
    """
    # PREPROCESSING
    client = client
    page_size = arg_to_number(args.get('page_size', 50))
    channel_id = args.get('channel_id')
    user_id = args.get('user_id', '')
    next_page_token = args.get('next_page_token')
    limit = arg_to_number(args.get('limit'))
    page_number = arg_to_number(args.get('page_number', 1))

    if user_id and re.match(emailRegex, user_id):
        user_id = zoom_get_user_id_by_email(client, user_id)

    data = []
    url_suffix = f'users/{user_id}/channels/{channel_id}' if channel_id else f'users/{user_id}/channels'
    if limit:
        if "page_size" in args or "page_number" in args or next_page_token:
            # arguments collision
            raise DemistoException(LIMIT_AND_EXTRA_ARGUMENTS)
        else:
            # multiple requests are needed
            raw_data = manual_list_user_channel_pagination(client=client, user_id=user_id,
                                                           next_page_token=next_page_token, limit=limit,
                                                           url_suffix=url_suffix)
            data = remove_extra_info_list('channels', limit, raw_data)
            token = raw_data.get('next_page_token', None)
    else:
        # only one request is needed
        raw_data = client.zoom_list_user_channels(user_id=user_id, page_size=page_size,
                                                  next_page_token=next_page_token, url_suffix=url_suffix,
                                                  page_number=page_number)
        # parsing the data according to the different given arguments
        data = [raw_data] if channel_id else raw_data.get("channels")
        token = raw_data.get('next_page_token', None)
    outputs = []
    for i in data:
        outputs.append({'User id': user_id,
                        'Channel ID': i.get('id'),
                        'channel JID': i.get('jid'),
                        'Channel name': i.get('name'),
                        'Channel type': i.get('type'),
                        'Channel url': i.get('channel_url')})
    md = tableToMarkdown('Channels', outputs)

    return CommandResults(
        outputs_prefix='Zoom.Channel',
        outputs_key_field='id',
        readable_output=md,
        outputs={**raw_data,
                 'UserChannelsNextToken': token},
        raw_response=raw_data
    )


def zoom_create_channel_command(client, **args) -> CommandResults:
    """
        Create a new zoom channel
    """
    client = client
    user_id = args.get('user_id')
    member_emails = argToList(args.get('member_emails'))
    add_member_permissions = args.get('add_member_permissions', None)
    add_member_permissions_num = MEMBER_PERMISSIONS_MAPPING.get(add_member_permissions)
    posting_permissions = args.get('posting_permissions', None)
    posting_permissions_num = POSTING_PERMISSIONS_MAPPING.get(posting_permissions)
    new_members_can_see_prev_msgs = args.get('new_members_can_see_prev_msgs', True)
    channel_name = args.get('channel_name')
    channel_type = args.get('channel_type', None)
    channel_type_num = CHANNEL_TYPE_MAPPING.get(channel_type)
    json_all_data = {}
    email_json = [{"email": email} for email in member_emails]

    if user_id and re.match(emailRegex, user_id):
        user_id = zoom_get_user_id_by_email(client, user_id)
    # special section for recurring meeting with fixed time
    json_all_data.update({
        "channel_settings": {
            "add_member_permissions": add_member_permissions_num,
            "new_members_can_see_previous_messages_files": new_members_can_see_prev_msgs,
            "posting_permissions": posting_permissions_num,
        },
        "name": channel_name,
        "type": channel_type_num,
        "members": email_json
    })

    json_data = remove_None_values_from_dict(json_all_data)
    url_suffix = f"/chat/users/{user_id}/channels"
    raw_data = client.zoom_create_channel(url_suffix, json_data)
    # md = tableToMarkdown('Channel details', [raw_data], ['id', 'name', 'type', 'channel_url'])

    outputs = []
    outputs.append({'User id': user_id,
                    'Channel ID': raw_data.get('id'),
                    'Channel name': raw_data.get('name'),
                    'Channel type': raw_data.get('type'),
                    'Channel url': raw_data.get('channel_url')})

    human_readable = tableToMarkdown('Channel details',
                                     outputs,
                                     removeNull=True)

    return CommandResults(
        outputs_prefix='Zoom.Channel',
        outputs_key_field='id',
        readable_output=human_readable,
        outputs=raw_data,
        raw_response=raw_data
    )


def zoom_delete_channel_command(client, **args) -> CommandResults:
    """
       Delete a Zoom channel
    """
    client = client
    channel_id = args.get('channel_id')
    user_id = args.get('user_id')
    url_suffix = f'/chat/users/{user_id}/channels/{channel_id}'

    if user_id and re.match(emailRegex, user_id):
        user_id = zoom_get_user_id_by_email(client, user_id)

    client.zoom_delete_channel(url_suffix)
    return CommandResults(
        readable_output=f'Channel {channel_id} was deleted successfully',
    )


def zoom_update_channel_command(client, **args) -> CommandResults:
    """
        Update a Zoom channel
    """
    client = client
    add_member_permissions = args.get('add_member_permissions', None)
    add_member_permissions_num = MEMBER_PERMISSIONS_MAPPING.get(add_member_permissions)
    posting_permissions = args.get('posting_permissions', None)
    posting_permissions_num = POSTING_PERMISSIONS_MAPPING.get(posting_permissions)
    new_members_can_see_prev_msgs = args.get('new_members_can_see_prev_msgs', True)
    channel_name = args.get('channel_name')
    channel_id = args.get('channel_id')
    user_id = args.get('user_id')
    json_all_data = {}

    if user_id and re.match(emailRegex, user_id):
        user_id = zoom_get_user_id_by_email(client, user_id)
    # special section for recurring meeting with fixed time
    json_all_data.update({
        "name": channel_name,
        "channel_settings": {
            "add_member_permissions": add_member_permissions_num,
            "new_members_can_see_previous_messages_files": new_members_can_see_prev_msgs,
            "posting_permissions": posting_permissions_num,
        }})

    json_data = remove_None_values_from_dict(json_all_data)
    url_suffix = f"/chat/users/{user_id}/channels/{channel_id}"
    client.zoom_update_channel(url_suffix, json_data)

    return CommandResults(
        readable_output=f"Channel {channel_id} was updated successfully",
    )


def zoom_invite_to_channel_command(client, **args) -> CommandResults:
    """
        invite users to Zoom channel
    """
    channel_id = args.get('channel_id')
    user_id = args.get('user_id')
    members = argToList(args.get('members'))
    url_suffix = f'/chat/users/{user_id}/channels/{channel_id}/members'
    json_members = [{"email": email} for email in members]

    if user_id and re.match(emailRegex, user_id):
        user_id = zoom_get_user_id_by_email(client, user_id)

    members_json = {'members': json_members}

    raw_data = client.zoom_invite_to_channel(members_json, url_suffix)

    outputs = [{
        'User id': raw_data.get('ids'),
        'Channel ID': channel_id,
        'Added at date and time': raw_data.get('added_at')
    }]

    human_readable = tableToMarkdown('Channel details', outputs, removeNull=True)

    return CommandResults(
        outputs_prefix='Zoom.Channel',
        outputs_key_field='id',
        readable_output=human_readable,
        outputs=raw_data,
        raw_response=raw_data
    )


def zoom_remove_from_channel_command(client, **args) -> CommandResults:
    """
        Remove a user from Zoom channel
    """
    client = client
    channel_id = args.get('channel_id')
    member_id = args.get('member_id')
    user_id = args.get('user_id')

    if user_id and re.match(emailRegex, user_id):
        user_id = zoom_get_user_id_by_email(client, user_id)

    url_suffix = f'/chat/users/{user_id}/channels/{channel_id}/members/{member_id}'
    client.zoom_remove_from_channel(url_suffix)
    return CommandResults(
        readable_output=f'Member {member_id} was successfully removed from channel {channel_id}',
    )


def zoom_send_file_command(client, **args) -> CommandResults:
    """
        Send file in Zoom
    """
    client = client
    user_id = args.get('user_id')
    to_channel = args.get('to_channel')
    to_contact = args.get('to_contact')
    entry_id = args.get('entry_id')

    if user_id and re.match(emailRegex, user_id):
        user_id = zoom_get_user_id_by_email(client, user_id)

    if "to_contact" not in args and "to_channel" not in args:
        raise DemistoException(MISSING_ARGUMENT)

    file_info = demisto.getFilePath(entry_id)
    upload_url = f'https://file.zoom.us/v2/chat/users/{user_id}/messages/files'
    json_data = remove_None_values_from_dict({
        'to_contact': to_contact,
        'to_channel': to_channel})
    upload_response = client.zoom_send_file(upload_url, file_info, json_data)

    message_id = upload_response.get('id')
    return CommandResults(
        readable_output=f'Message with id {message_id} was successfully sent'
    )


def process_links(formatted_message, formats):
    """
    Processes markdown links in the formatted message.
    for example- [my link](https://****.com)
    Args:
        formatted_message (str): The formatted message to process.

    Returns:
        str: The formatted message with links processed.
    """
    add_link_regex = r'\[([^[\]]*?)\]\((http[s]?://.*?)\)'
    matches = re.findall(add_link_regex, formatted_message)

    for match in matches:
        link_text, link_url = match
        add_link_range = {
            "text": link_text,
            "format_type": "AddLink",
            "format_attr": link_url
        }
        formats.append(add_link_range)
        # Replace Markdown syntax with plain text
        formatted_message = formatted_message.replace("[" + link_text + "](" + link_url + ")", link_text)

    return formatted_message, formats


def process_mentions(formatted_message, formats, at_contact=None):
    """
    Processes mentions in the markdown message you can provide just one mention on each message.
    for example-'@all'

    Args:
        formatted_message (str): The markdown message to process.
        at_contact (str): The contact to mention.

    Returns:
        str: The formatted message without the mention markdown.
    """
    mention_regex = r"(@\w+)"

    matches = re.findall(mention_regex, formatted_message)[:1]
    for match in matches:
        if match == '@all':
            mention_range = {
                'text': match,
                "at_type": 2,
                "at_contact": at_contact,
            }
            formats.append(mention_range)
        elif at_contact:
            mention_range = {
                'text': match,
                "at_contact": at_contact,
                "at_type": 1,
            }
            formats.append(mention_range)
    return formatted_message, formats


def process_background_colors(formatted_message, formats):
    """
    Processes background colors in the markdown message.
    for example- [#<rgb>bg](message that will be with background)

    Args:
        formatted_message (str): The markdown message to process.

    Returns:
        str: The formatted message without background color markdown.
    """
    bg_color_regex = r"\[#([A-Fa-f0-9]{6})bg\]\((.*?)\)"

    matches = re.findall(bg_color_regex, formatted_message)
    for match in matches:
        bg_color, text = match
        bg_color_range = {
            "text": text,
            "format_type": "BackgroundColor",
            "format_attr": bg_color,
        }
        formats.append(bg_color_range)

        # Replace Markdown syntax with plain text
        formatted_message = formatted_message.replace("[#" + bg_color + "bg](" + text + ")", text)
    return formatted_message, formats


def process_font_sizes(formatted_message, formats):
    """
    Processes font sizes in the markdown message.
    use s|m|l for text size
    for example- [s](message)

    Args:
        formatted_message (str): The markdown message to process.

    Returns:
        str: The formatted message without fontsize markdown.
    """
    font_size_regex = "\\[(s|m|l)\\]\\((.*?)\\)"
    matches = re.findall(font_size_regex, formatted_message)
    for match in matches:
        size, text = match
        font_size_range = {
            "text": text,
            "format_type": "FontSize",
            "format_attr": size
        }
        formats.append(font_size_range)

        # Replace Markdown syntax with plain text
        formatted_message = formatted_message.replace("[" + size + "](" + text + ")", text)
    return formatted_message, formats


def process_font_colors(formatted_message, formats):
    """
    Processes font colors in the formatted message.

    Args:
        formatted_message (str): The formatted message to process.

    Returns:
        str: The formatted message with font colors processed.
    """
    font_color_regex = "\\[#([A-Fa-f0-9]{6})\\]\\((.*?)\\)"
    matches = re.findall(font_color_regex, formatted_message)
    for match in matches:
        color, text = match
        font_color_range = {
            "text": text,
            "format_type": "FontColor",
            "format_attr": color,
        }
        formats.append(font_color_range)

        # Replace Markdown syntax with plain text
        formatted_message = formatted_message.replace("[#" + color + "](" + text + ")", text)
    return formatted_message, formats


def process_left_indent_and_paragraphs(formatted_message, formats):
    """
    Processes left indents and paragraphs in the markdown message.
    for left indents use >,>>,>>>
    for paragraph usr #,##,### (up to 3)
    this type of markdowns effect the whole line.

    Args:
        formatted_message (str): The formatted message to process.

    Returns:
        tuple: A tuple containing the formatted message, rich text formatting data, and @mention items.
    """

    left_indent_regex = r"(>{1,4})\s(.*?)$"
    paragraph_regex = r"(#{1,4})\s(.*?)$"
    lines = formatted_message.split("\n")
    for i, line in enumerate(lines):
        match = re.findall(left_indent_regex, line)
        for matches in match:
            indent_level, indent_text = matches
            left_indent_range = {
                "text": indent_text,
                "format_type": "LeftIndent",
                "format_attr": len(indent_level) * 20,
            }
            formats.append(left_indent_range)
            # Replace Markdown syntax with plain text
            lines[i] = indent_text

        pp_matches = re.findall(paragraph_regex, line)
        for p_matches in pp_matches:
            heading_level, heading_text = p_matches
            paragraph_range = {
                "text": heading_text,
                "format_type": "paragraph",
                "format_attr": f"h{len(heading_level)}",
            }
            formats.append(paragraph_range)
            lines[i] = heading_text
    formatted_message = "\n".join(lines)
    return formatted_message, formats


def parse_markdown_message(markdown_message: str, at_contact: str = None):
    """
    Parses a Markdown message and extracts formatting information.

    Args:
        markdown_message (str): The Markdown message to parse.
        at_contact (str, optional): The contact to mention. Defaults to None.

    Returns:
        tuple: A tuple containing the formatted message, rich text formatting data, and @mention items.
    """

    formats: List[dict] = []
    at_items = []
    rich_text = []
    formatted_message, formats = process_links(markdown_message, formats)
    formatted_message, formats = process_mentions(formatted_message, formats, at_contact)
    formatted_message, formats = process_background_colors(formatted_message, formats)
    formatted_message, formats = process_font_sizes(formatted_message, formats)
    formatted_message, formats = process_font_colors(formatted_message, formats)
    formatted_message, formats = process_left_indent_and_paragraphs(formatted_message, formats)

    # extract the start,end positions
    for i in range(len(formats)):
        t = formats[i]['text']
        start_position = formatted_message.find(t)
        end_position = start_position + len(t) - 1
        formats[i]["start_position"] = start_position
        formats[i]["end_position"] = end_position
        if formats[i].get('at_type'):
            at_items.append(formats[i])
        else:
            rich_text.append(formats[i])

    return formatted_message, {
        "message": formatted_message,
        "rich_text": rich_text,
        "at_items": at_items
    }


def zoom_send_message_command(client, **args) -> CommandResults:
    """
        Send  Zoom chat message
    """
    client = client
    at_contact = args.get('at_contact')
    user_id = args.get('user_id')
    message = args.get('message', '')
    entry_ids = argToList(args.get('entry_ids', []))
    reply_main_message_id = args.get('reply_main_message_id')
    to_channel = args.get('to_channel')
    to_contact = args.get('to_contact')
    is_markdown = args.get('is_markdown', False)

    if user_id and re.match(emailRegex, user_id):
        user_id = zoom_get_user_id_by_email(client, user_id)

    url_suffix = f'/chat/users/{user_id}/messages'
    upload_file_url = f'https://file.zoom.us/v2/chat/users/{user_id}/files'
    zoom_file_id: List = []
    for id in entry_ids:
        file_info = demisto.getFilePath(id)
        res = client.zoom_upload_file(upload_file_url, file_info)
        zoom_file_id.append(res.get('id'))

    # check if the text contain markdown to parse and also provide text style arguments
    if is_markdown:
        # check if text have more then 1 mention
        if message.count('@') > 1 and at_contact:
            raise DemistoException(MARKDOWN_EXTRA_MENTIONS)

        message, json_data_all = parse_markdown_message(message, at_contact)
        json_data_all.update({"file_ids": zoom_file_id, "reply_main_message_id": reply_main_message_id, "to_channel": to_channel,
                              "to_contact": to_contact})
    else:
        json_data_all = {
            "message": message,
            "file_ids": zoom_file_id,
            "reply_main_message_id": reply_main_message_id,
            "to_channel": to_channel,
            "to_contact": to_contact
        }
    json_data = remove_None_values_from_dict(json_data_all)

    raw_data = client.zoom_send_message(url_suffix, json_data)
    data = {
        'Mentioned user': at_contact,
        'Channel ID ': to_channel,
        'Message ID': raw_data.get('id'),
        'Contact': to_contact
    }

    md = tableToMarkdown('Message', data, removeNull=True)
    return CommandResults(
        outputs_prefix='Zoom.ChatMessage',
        readable_output=md,
        outputs_key_field='id',
        outputs=raw_data,
        raw_response=raw_data
    )


def zoom_delete_message_command(client, **args) -> CommandResults:
    """
        Delete Zoom chat message
    """
    client = client
    message_id = args.get('message_id')
    to_contact = args.get('to_contact',)
    user_id = args.get('user_id')
    to_channel = args.get('to_channel')

    if user_id and re.match(emailRegex, user_id):
        user_id = zoom_get_user_id_by_email(client, user_id)

    if to_channel:
        url_suffix = f'/chat/users/{user_id}/messages/{message_id}?to_channel={to_channel}'
    elif to_contact:
        url_suffix = f'/chat/users/{user_id}/messages/{message_id}?to_contact={to_contact}'
    else:
        raise DemistoException(MISSING_ARGUMENT)

    client.zoom_delete_message(url_suffix)
    return CommandResults(
        readable_output=f'Message {message_id} was deleted successfully',
    )


def zoom_update_message_command(client, **args) -> CommandResults:
    """
        Update Zoom chat message
    """
    client = client
    message_id = args.get('message_id')
    to_contact = args.get('to_contact')
    user_id = args.get('user_id')
    to_channel = args.get('to_channel')
    message = args.get('message')
    entry_ids = argToList(args.get('entry_ids', []))

    if user_id and re.match(emailRegex, user_id):
        user_id = zoom_get_user_id_by_email(client, user_id)

    upload_file_url = f'https://file.zoom.us/v2/chat/users/{user_id}/files'
    zoom_file_id: List = []
    demisto.debug(f'file id args {entry_ids}')
    for id in entry_ids:
        file_info = demisto.getFilePath(id)
        res = client.zoom_upload_file(upload_file_url, file_info)
        zoom_file_id.append(res.get('id'))
    demisto.debug('upload the file without error')

    url_suffix = f'/chat/users/{user_id}/messages/{message_id}'
    json_data = remove_None_values_from_dict(
        {
            "message": message,
            "file_ids": zoom_file_id,
            "to_channel": to_channel,
            "to_contact": to_contact})

    client.zoom_update_message(url_suffix, json_data)
    return CommandResults(
        readable_output=f'Message {message_id} was successfully updated',
    )


def zoom_delete_user_token_command(client, **args) -> CommandResults:
    """
        Revoke a user's Zoom SSO session
    """
    client = client
    user_id = args.get('user_id')
    url_suffix = f'/users/{user_id}/token'
    client.zoom_delete_user_token(url_suffix)
    return CommandResults(
        readable_output=f'User SSO token for user {user_id} is deleted',
    )


def zoom_get_user_id_by_email(client, email):
    """
    Retrieves the user ID associated with the given email address.

    :param client: The Zoom client object.,
    email: The email address of the user.

    :return: The user ID associated with the email address.
    :rtype: str
    """
    user_url_suffix = f'users/{email}'
    user_id = client.zoom_list_users(page_size=50, url_suffix=user_url_suffix).get('id')
    if not user_id:
        raise DemistoException(USER_NOT_FOUND)
    return user_id


def zoom_get_user_name_by_email(client, user_email):
    """
    Retrieves the user name associated with the given email address.

    :param client: The Zoom client object.
    user_email: The email address of the user.

    :return: The user name associated with the email address.
    :rtype: str
    """
    user_url_suffix = f'users/{user_email}'
    user_name = client.zoom_list_users(page_size=1, url_suffix=user_url_suffix)
    demisto.info(f"user_name: {user_name}")
    if not user_name:
        raise DemistoException(USER_NOT_FOUND)
    user_name = user_name.get('display_name')
    return user_name


def zoom_get_user_email_by_id(client, user_id):
    """
    Retrieves the user email address associated with the given user ID.

    :param client: The Zoom client object.
    user_id: The user ID of the user.

    :return: The email address associated with the user ID.
    :rtype: str
    """
    user_url_suffix = f'users/{user_id}'
    user_email = client.zoom_list_users(page_size=1, url_suffix=user_url_suffix).get('email')
    if not user_email:
        raise DemistoException(USER_NOT_FOUND)
    return user_email


def zoom_list_messages_command(client, **args) -> CommandResults:
    """
    Lists messages from Zoom chat.

    :raises DemistoException: If a required argument is missing.
    """

    client = client
    user_id = args.get('user_id')
    to_contact = args.get('to_contact')
    to_channel = args.get('to_channel')
    date_arg = arg_to_datetime(args.get('date'))
    from_arg = arg_to_datetime(args.get('from'))
    to_arg = arg_to_datetime(args.get('to'))
    date_arg = date_arg.strftime('%Y-%m-%dT%H:%M:%SZ') if date_arg else None
    from_arg = from_arg.strftime('%Y-%m-%dT%H:%M:%SZ') if from_arg else None
    to_arg = to_arg.strftime('%Y-%m-%dT%H:%M:%SZ') if to_arg else None
    include_deleted_and_edited_message = args.get('include_deleted_and_edited_message')
    search_type = args.get('search_type')
    search_key = args.get('search_key')
    exclude_child_message = args.get('exclude_child_message', False)
    limit = arg_to_number(args.get('limit', 50))
    page_size = arg_to_number(args.get('page_size'))

    if limit and page_size and limit != 50:
        raise DemistoException(LIMIT_AND_EXTRA_ARGUMENTS)
    else:
        limit = page_size if page_size else limit

    if not to_contact and not to_channel:
        raise DemistoException(MISSING_ARGUMENT)

    if user_id and re.match(emailRegex, user_id):
        user_id = zoom_get_user_id_by_email(client, user_id)
    json_data = {
        'user_id': user_id,
        'to_contact': to_contact,
        'to_channel': to_channel,
        'date': date_arg,
        'from': from_arg,
        'to': to_arg,
        'include_deleted_and_edited_message': include_deleted_and_edited_message,
        'search_type': search_type,
        'search_key': search_key,
        'exclude_child_message': exclude_child_message,
        'page_size': limit
    }
    # remove all keys with val of None
    request_data = remove_None_values_from_dict(json_data)
    url_suffix = f'users/{user_id}/messages'
    all_messages: List = []
    next_page_token = args.get('next_page_token', None)
    while True:
        try:
            raw_data = client.zoom_list_user_messages(url_suffix=url_suffix,
                                                      user_id=user_id,
                                                      to_contact=to_contact,
                                                      to_channel=to_channel,
                                                      date_arg=date_arg,
                                                      from_arg=from_arg,
                                                      to_arg=to_arg,
                                                      include_deleted_and_edited_message=include_deleted_and_edited_message,
                                                      search_type=search_type,
                                                      search_key=search_key,
                                                      exclude_child_message=exclude_child_message,
                                                      next_page_token=next_page_token,
                                                      page_size=limit)
            data = raw_data.get('messages', [])
            if limit and len(all_messages) + len(data) > limit:
                remaining_limit = limit - len(all_messages)
                data = data[:remaining_limit]

            all_messages.extend(data)

            if limit and len(all_messages) >= limit:
                all_messages = all_messages[:limit]
                break
            next_page_token = raw_data.get('next_page_token', None)
            if next_page_token and next_page_token != '':
                next_page_token = raw_data['next_page_token']
            else:
                break
        except DemistoException as e:
            error_message = e.message
            if 'The next page token is invalid or expired.' in error_message and next_page_token:
                raise DemistoException(f"Please ensure that the correct argument values are used when attempting to use \
the next_page_toke.\n Note that when using next_page_token it is mandatory to specify date time and not relative time.\n \
To find the appropriate values, refer to the ChatMessageNextToken located in the context. \n {error_message}")

    outputs = []
    for i in all_messages:
        outputs.append({
            'User id': user_id,
            'Message Id': i.get('id'),
            'Message text': i.get('message'),
            'Message sender': i.get('sender'),
            'Sender display name': i.get('sender_display_name'),
            'Date Time': i.get('date_time'),
            'From': str(from_arg),
            'To': str(to_arg)})

    md = tableToMarkdown('Messages', outputs)
    md += '\n' + 'Messages next token:' + raw_data.get('next_page_token', '')

    if raw_data.get('next_page_token'):
        request_data.update({'next_page_token': raw_data.get('next_page_token')})
    else:
        request_data = None

    return CommandResults(
        outputs_prefix='Zoom',
        readable_output=md,
        outputs={'ChatMessage': {'messages': all_messages},
                 'ChatMessageNextToken': request_data},
        raw_response=raw_data
    )


def get_channel_jid_from_context(channel_name: str = None, investigation_id=None):
    """
    Retrieves a Zoom channel JID based on the provided criteria.

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
        return mirrored_channel_filter.get('channel_jid')
    return None


def send_notification(client, **args):

    client = client
    bot_jid = client.bot_jid
    account_id = client.account_id
    to = args.get('to')
    channel_id = args.get('channel_id')
    visible_to_user = args.get('visible_to_user')
    zoom_ask = argToBoolean(args.get('zoom_ask', False))
    entitlement = None

    message_type = args.get('messageType', '')  # From server
    original_message = args.get('originalMessage', '')  # From server
    entry_object = args.get('entryObject')  # From server
    channel = args.get('channel')  # From server
    investigation_id = None
    if entry_object:
        investigation_id = entry_object.get('investigationId')  # From server, available from demisto v6.1 and above

    if message_type and message_type != MIRROR_TYPE:
        return (f"Message type is not in permitted options. Received: {message_type}")

    if message_type == MIRROR_TYPE and original_message.find(MESSAGE_FOOTER) != -1:
        # return so there will not be a loop of messages
        return ("Message already mirrored")

    if to and '@xmpp.zoom.us' not in to:

        if re.match(emailRegex, to):
            to = zoom_get_user_id_by_email(client, to).lower() + '@xmpp.zoom.us'
        else:
            to = to.lower() + '@xmpp.zoom.us'

    if channel_id and '@conference.xmpp.zoom.us' not in channel_id:
        channel_id = channel_id.lower() + '@conference.xmpp.zoom.us'

    if zoom_ask:
        parsed_message = json.loads(args.get("message", ''))
        entitlement = parsed_message.get('entitlement')
        message = parsed_message.get('blocks')
        reply = parsed_message.get('reply')
        expiry = parsed_message.get('expiry')
        default_response = parsed_message.get('default_response')
    else:
        message = {"head": {"type": "message", "text": args.get("message", "")}}
        reply = None
        expiry = None
        default_response = None
    if channel:  # if channel name provided
        channel_id = get_channel_jid_from_context(channel, investigation_id)
        if not channel_id:
            raise DemistoException(WRONG_CHANNEL)
    if (to and channel_id):
        raise DemistoException(TOO_MANY_JID)
    if not to and not channel_id:
        raise DemistoException(MISSING_ARGUMENT_JID)

    url_suffix = '/im/chat/messages'
    json_data_all = {
        "robot_jid": bot_jid,
        "to_jid": to if to else channel_id,
        "account_id": account_id,
        "visible_to_user": visible_to_user,
        "content":
            message
    }
    json_data = remove_None_values_from_dict(json_data_all)

    raw_data = client.zoom_send_notification(url_suffix, json_data)
    if raw_data:
        message_id = raw_data.get("message_id")
        if entitlement:
            save_entitlement(entitlement, message_id, reply, expiry, default_response, to if to else channel_id)
    return CommandResults(
        readable_output=f'Message sent to Zoom successfully. Message ID is: {raw_data.get("message_id")}'
    )


def get_admin_user_id_from_token(client):
    """ get the user admin id from the token"""
    admin_user_result = client.zoom_get_admin_user_id_from_token()
    return admin_user_result.get('id')


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


def mirror_investigation(client, **args) -> CommandResults:
    if not MIRRORING_ENABLED:
        demisto.error(" couldn't mirror investigation, Mirroring is disabled")
    if MIRRORING_ENABLED and not LONG_RUNNING:
        demisto.error('Mirroring is enabled, however long running is disabled. For mirrors to work correctly,'
                      ' long running must be enabled.')
    client = client
    type = args.get('type', 'all')
    direction = args.get('direction', 'Both')
    channel_name = args.get('channelName')
    autoclose = argToBoolean(args.get('autoclose', True))
    send_first_message = False
    # kick_admin = argToBoolean(args.get('kickAdmin', False))
    # members = argToList(args.get('members'))

    investigation = demisto.investigation()
    investigation_id = str(investigation.get('id'))
    if investigation.get('type') == PLAYGROUND_INVESTIGATION_TYPE:
        return_error('Sorry, but this action cannot be performed in the playground ')

    integration_context = get_integration_context(SYNC_CONTEXT)
    if not integration_context or not integration_context.get('mirrors', []):
        mirrors: list = []
        current_mirror = []
    else:
        mirrors = json.loads(integration_context['mirrors'])
        current_mirror = list(filter(lambda m: m['investigation_id'] == investigation_id, mirrors))

    # get admin user id from token
    admin_user_id = get_admin_user_id_from_token(client)

    channel_filter: list = []
    if channel_name:
        # check if channel already exists
        channel_filter = list(filter(lambda m: m['channel_name'] == channel_name, mirrors))

    if not current_mirror:
        channel_name = channel_name or f'incident-{investigation_id}'

        if not channel_filter:
            # create new channel
            result = zoom_create_channel_command(client=client, user_id=admin_user_id, channel_type='Public channel',
                                                 channel_name=channel_name, member_emails=admin_user_id)
            if result and isinstance(result.outputs, dict) and len(result.outputs) > 0:
                channel_jid = result.outputs.get('jid')
                channel_id = result.outputs.get('id')
            else:
                raise DemistoException("error in create new channel")
            send_first_message = True
        else:
            mirrored_channel = channel_filter[0]
            channel_jid = mirrored_channel['channel_jid']
            channel_id = mirrored_channel['channel_id']
            channel_name = mirrored_channel['channel_name']

        mirror = {
            'channel_jid': channel_jid,
            'channel_id': channel_id,
            'channel_name': channel_name,
            'investigation_id': investigation.get('id'),
            'mirror_type': type,
            'mirror_direction': direction,
            'auto_close': bool(autoclose),
            'mirrored': True
        }
    else:
        mirror = mirrors.pop(mirrors.index(current_mirror[0]))
        channel_jid = mirror['channel_jid']
        channel_id = mirror['channel_id']
        if type:
            mirror['mirror_type'] = type
        if autoclose:
            mirror['auto_close'] = autoclose
        if direction:
            mirror['mirror_direction'] = direction
        if channel_name and not channel_filter:
            # update channel name
            result = zoom_update_channel_command(client=client, user_id=admin_user_id,
                                                 channel_name=channel_name, channel_id=channel_id)
            mirror['channel_name'] = channel_name
        channel_name = mirror['channel_name']
        mirror['mirrored'] = True
    demisto.mirrorInvestigation(investigation_id, f'{type}:{direction}', autoclose)

    mirrors.append(mirror)
    set_to_integration_context_with_retries({'mirrors': mirrors}, OBJECTS_TO_KEYS, SYNC_CONTEXT)

    if send_first_message:
        server_links = demisto.demistoUrls()
        server_link = server_links.get('server')
        message = (f'This channel was created to mirror incident {investigation_id}.'
                   f' \n View it on: {server_link}#/WarRoom/{investigation_id}')
        url_suffix = '/im/chat/messages'
        json_data_all = {
            "content": {
                "body": [
                    {
                        "type": "message",
                        "text": message
                    }
                ]
            },
            "to_jid": channel_jid,
            "robot_jid": client.bot_jid,
            "account_id": client.account_id
        }
        client.zoom_send_notification(url_suffix, json_data_all)
    # if kick_admin:
    #     demisto.debug("kick-admin:")
    #     url_suffix = f'/chat/users/{admin_user_id}/channels/{channel_id}/members/{admin_user_id}'
    #     res = client.zoom_remove_from_channel(url_suffix)
    #     demisto.debug(f"res: {res}")
    return CommandResults(
        readable_output=f'Investigation mirrored successfully,\n channel name:{channel_name} \n channel JID: {channel_jid}'
    )


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
        if 'mirrors' in integration_context:
            mirrors = json.loads(integration_context['mirrors'])
            investigation_filter = list(filter(lambda m: investigation.get('id') == m['investigation_id'],
                                               mirrors))
            if investigation_filter:
                mirror = investigation_filter[0]

    return mirror


def close_channel(client, **args):
    """
        if AutoClose is true in mirroring
        delete the mirrored zoom channel from zoom and from the context
    """
    client = client
    admin_user_id = get_admin_user_id_from_token(client)
    mirror = find_mirror_by_investigation()
    channel_id = None
    integration_context = get_integration_context(SYNC_CONTEXT)
    if mirror:
        mirrors = json.loads(integration_context['mirrors'])
        channel_id = mirror.get('channel_id', '')
        channel_mirrors = list(filter(lambda m: channel_id == m['channel_id'], mirrors))
        for mirror in channel_mirrors:
            mirror['remove'] = True
            demisto.mirrorInvestigation(mirror['investigation_id'], f'none:{mirror["mirror_direction"]}',
                                        bool(mirror['auto_close']))
        set_to_integration_context_with_retries({'mirrors': mirrors}, OBJECTS_TO_KEYS, SYNC_CONTEXT)
    if channel_id:
        zoom_delete_channel_command(client=client, channel_id=channel_id, user_id=admin_user_id)
        return 'Channel successfully deleted.'
    return return_error('Channel {channel_id} not found')


def main():  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    base_url = params.get('url')
    account_id = params.get('account_id')
    client_id = params.get('credentials', {}).get('identifier')
    client_secret = params.get('credentials', {}).get('password')
    bot_client_id = params.get('bot_credentials', {}).get('identifier')
    bot_client_secret = params.get('bot_credentials', {}).get('password')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    bot_jid = params.get('botJID', None)
    secret_token = params.get('secret_token', {}).get('password')
    global SECRET_TOKEN, LONG_RUNNING, MIRRORING_ENABLED, CACHE_EXPIRY, CACHED_INTEGRATION_CONTEXT
    SECRET_TOKEN = secret_token
    LONG_RUNNING = params.get('longRunning', False)
    MIRRORING_ENABLED = params.get('mirroring', False)

    # Pull initial Cached context and set the Expiry
    CACHE_EXPIRY = next_expiry_time()
    CACHED_INTEGRATION_CONTEXT = get_integration_context(SYNC_CONTEXT)

    if MIRRORING_ENABLED and (not LONG_RUNNING or not SECRET_TOKEN or not bot_client_id or not bot_client_secret or not bot_jid):
        raise DemistoException("""Mirroring is enabled, however long running is disabled
or the necessary bot authentication parameters are missing.
For mirrors to work correctly, long running must be enabled and you must provide all
the zoom-bot following parameters:
secret token,
Bot JID,
bot client id and secret id""")
    if LONG_RUNNING:
        try:
            port = int(params.get('longRunningPort'))
        except ValueError as e:
            raise ValueError(f'Invalid listen port - {e}')
    else:
        port = 0
        demisto.debug(f"Not a longrunning, setting {port=}")

    command = demisto.command()
    # this is to avoid BC. because some of the arguments given as <a-b>, i.e "user-list"
    args = {key.replace('-', '_'): val for key, val in args.items()}

    try:
        check_authentication_bot_parameters(bot_jid, bot_client_id, bot_client_secret)
        check_authentication_parameters(client_id, client_secret)
        global CLIENT
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            bot_jid=bot_jid,
            account_id=account_id,
            client_id=client_id,
            client_secret=client_secret,
            bot_client_id=bot_client_id,
            bot_client_secret=bot_client_secret,
        )
        CLIENT = client
        results = CommandResults()

        if command == 'test-module':
            return_results(test_module(client=client))

        demisto.debug(f'Command being called is {command}')

        '''CRUD commands'''
        if command == 'long-running-execution':
            run_long_running(port)
        elif command == 'mirror-investigation':
            results = mirror_investigation(client, **args)
        elif command == 'close-channel':
            results = close_channel(client, **args)
        elif command == 'zoom-create-user':
            results = zoom_create_user_command(client, **args)
        elif command == 'zoom-create-meeting':
            results = zoom_create_meeting_command(client, **args)
        elif command == 'zoom-meeting-get':
            results = zoom_meeting_get_command(client, **args)
        elif command == 'zoom-meeting-list':
            results = zoom_meeting_list_command(client, **args)
        elif command == 'zoom-delete-user':
            results = zoom_delete_user_command(client, **args)
        elif command == 'zoom-fetch-recording':
            results = zoom_fetch_recording_command(client, **args)
        elif command == 'zoom-list-users':
            results = zoom_list_users_command(client, **args)
        elif command == 'zoom-list-account-public-channels':
            results = zoom_list_account_public_channels_command(client, **args)
        elif command == 'zoom-list-user-channels':
            results = zoom_list_user_channels_command(client, **args)
        elif command == 'zoom-create-channel':
            results = zoom_create_channel_command(client, **args)
        elif command == 'zoom-delete-channel':
            results = zoom_delete_channel_command(client, **args)
        elif command == 'zoom-update-channel':
            results = zoom_update_channel_command(client, **args)
        elif command == 'zoom-invite-to-channel':
            results = zoom_invite_to_channel_command(client, **args)
        elif command == 'zoom-remove-from-channel':
            results = zoom_remove_from_channel_command(client, **args)
        elif command == 'zoom-send-file':
            results = zoom_send_file_command(client, **args)
        elif command == 'zoom-list-messages':
            results = zoom_list_messages_command(client, **args)
        elif command == 'zoom-send-message':
            results = zoom_send_message_command(client, **args)
        elif command == 'zoom-delete-message':
            results = zoom_delete_message_command(client, **args)
        elif command == 'zoom-update-message':
            results = zoom_update_message_command(client, **args)
        elif command == 'zoom-delete-user-token':
            results = zoom_delete_user_token_command(client, **args)
        elif command == 'send-notification':
            results = send_notification(client, **args)

        else:
            return_error('Unrecognized command: ' + demisto.command())
        return_results(results)

    except DemistoException as e:
        # For any other integration command exception, return an error
        demisto.error(format_exc())
        return_error(f'Failed to execute {command} command. Error: {str(e)}.')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
