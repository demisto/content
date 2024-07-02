from traceback import format_exc
from secrets import compare_digest
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa
from typing import Any
import uvicorn
from fastapi import Depends, FastAPI, Request, Response, status
from fastapi_utils.tasks import repeat_every
from fastapi.security.api_key import APIKey, APIKeyHeader
from uvicorn.logging import AccessFormatter

''' CONSTANTS '''

app = FastAPI()
SCOPES = ['https://www.googleapis.com/auth/chat.bot']
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
OBJECTS_TO_KEYS = {
    'messages': 'entitlement',
}
OPTION_1 = ''
basic_auth = HTTPBasic(auto_error=False)
token_auth = APIKeyHeader(auto_error=False, name='Authorization')
CLIENT = None

''' CLIENT CLASS '''


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


class GoogleChatClient(BaseClient):
    def __init__(self, space_id, space_key, space_token):
        super().__init__(base_url='https://chat.googleapis.com/v1')
        self._space_id = space_id
        self._space_key = space_key
        self._space_token = space_token

    # def create_access_token(self):
    #     credentials = service_account.Credentials.from_service_account_file(
    #         self._space_token, scopes=SCOPES)
    #     # credentials.refresh(Request(scope=SCOPES))
    #     try:
    #         self._access_token = credentials.token
    #     except Exception as e:
    #         raise DemistoException(f"Could not generate an access token with error: {e}")

    def send_notification_request(self,
                                  message_body: str | None,
                                  message_to: str | None,
                                  space_id: str | None,
                                  thread_id: str | None,
                                  adaptive_card: dict[str, Any] | None):
        params = {"key": self._space_key}
        headers = {
            'Authorization': f'Bearer {self._space_token}',
            'Content-Type': 'application/json; charset=UTF-8'
        }
        body = {}
        body['text'] = message_body
        if message_to:
            body['privateMessageViewer'] = {'name': message_to}
        if thread_id:
            body['thread'] = {"threadKey": thread_id}
        if adaptive_card:
            body['cardsV2'] = adaptive_card
        try:
            response = self._http_request('POST', f'/spaces/{space_id or self._space_id}/messages',
                                          params=params,
                                          json_data=body,
                                          headers=headers,
                                          return_empty_response=True)
            return response
        except DemistoException as e:
            raise e


''' HELPER FUNCTIONS '''


def create_hr_response(response: dict[str, Any]):
    sender = response.get('sender', {})
    space = response.get('space', {})
    thread = response.get('thread', {})
    return {
        'Message name': response.get('name'),
        'Sender Name': sender.get('name'),
        'Sender display Name': sender.get('displayName'),
        'Sender Type': sender.get('type'),
        'Space Display Name': space.get('displayName'),
        'Space Name': space.get('name'),
        'Space Type': space.get('type'),
        'Thread Name': thread.get('name'),
        'Thread Key': thread.get('threadKey')
    }


''' COMMAND FUNCTIONS '''


def test_module(client: GoogleChatClient) -> str:
    message: str = ''
    try:
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def send_notification_command(client: GoogleChatClient, args: dict[str, Any]) -> CommandResults:

    message_body = args.get('message')
    message_to = args.get('to')
    space_id = args.get('space_id', client._space_id)
    thread_id = args.get('thread_id')
    adaptive_card = json.loads(args.get('adaptive_card')) if args.get('adaptive_card') else None  # type: ignore
    entitlement = args.get('entitlement')
    expiry = args.get('expiry')
    default_reply = args.get('default_reply')

    result = client.send_notification_request(message_body, message_to, space_id, thread_id, adaptive_card)
    message_id = result.get('name')
    if result.get('name') and entitlement and expiry and default_reply:
        save_entitlement(entitlement, message_id, space_id, expiry, message_to, thread_id, default_reply)
    headers = ['Message name', 'Sender Name', 'Sender display Name', 'Sender Type', 'Space Display Name', 'Space Name',
               'Space Type', 'Thread Name', 'Thread Key']
    adjusted_response = create_hr_response(result)
    command_results = CommandResults(
        outputs_prefix='GoogleChatWebhook.Message',
        outputs_key_field='Message name',
        outputs=result,
        raw_response=result,
        readable_output=tableToMarkdown('The Message that was sent:', adjusted_response, headers=headers,
                                        removeNull=True, headerTransform=string_to_table_header,
                                        )
    )
    return command_results


def save_entitlement(entitlement, message_id, space_id, expiry, message_to, thread_id, default_reply):
    """
    Saves an entitlement.

    Args:
        entitlement: The entitlement.
        message_id: The message_id
        space_id: The space_id.
        expiry: The survey expiration date.
        message_to: the user the message was sent to.
        thread_id: the thread id the message eas sent through.
    """
    integration_context = get_integration_context()
    messages = integration_context.get('messages', [])
    if messages:
        messages = json.loads(integration_context['messages'])
    messages.append({
        'message_id': message_id,
        'entitlement': entitlement,
        'space_id': space_id,
        'expiry': expiry,
        'sent_time': datetime.strftime(datetime.now(timezone.utc), DATE_FORMAT),
        'message_to': message_to,
        'thread_id': thread_id,
        'default_reply': default_reply
    })

    set_to_integration_context_with_retries({'messages': messages}, OBJECTS_TO_KEYS)


def run_long_running(port):
    while True:
        # certificate = demisto.params().get('certificate', '')
        # private_key = demisto.params().get('key', '')

        # certificate_path = ''
        # private_key_path = ''
        try:
            # ssl_args = {}

            # if certificate and private_key:
            #     certificate_file = NamedTemporaryFile(delete=False)
            #     certificate_path = certificate_file.name
            #     certificate_file.write(bytes(certificate, 'utf-8'))
            #     certificate_file.close()
            #     ssl_args['ssl_certfile'] = certificate_path

            #     private_key_file = NamedTemporaryFile(delete=False)
            #     private_key_path = private_key_file.name
            #     private_key_file.write(bytes(private_key, 'utf-8'))
            #     private_key_file.close()
            #     ssl_args['ssl_keyfile'] = private_key_path

            #     demisto.debug('Starting HTTPS Server')
            # else:
            #     demisto.debug('Starting HTTP Server')

            # integration_logger = IntegrationLogger()
            # integration_logger.buffering = False
            # log_config = dict(uvicorn.config.LOGGING_CONFIG)
            # log_config['handlers']['default']['stream'] = integration_logger
            # log_config['handlers']['access']['stream'] = integration_logger
            # log_config['formatters']['access'] = {
            #     '()': UserAgentFormatter,
            #     'fmt': '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s "%(user_agent)s"'
            # }
            # uvicorn.run(app, host='0.0.0.0', port=port, log_config=log_config, **ssl_args)
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
            uvicorn.run(app, host='0.0.0.0', port=port, log_config=log_config)
        except Exception as e:
            demisto.error(f'An error occurred in the long running loop: {str(e)} - {format_exc()}')
            demisto.updateModuleHealth(f'An error occurred: {str(e)}')
        finally:
            # if certificate_path:
            #     os.unlink(certificate_path)
            # if private_key_path:
            #     os.unlink(private_key_path)
            time.sleep(5)


def extract_entitlement(entitlement: str) -> tuple[str, str, str]:
    """
    Extracts entitlement components from an entitlement full string
    Args:
        entitlement: The full entitlement
        text: The actual reply text

    Returns:
        Entitlement components
    """
    parts = entitlement.split('@', 1)
    if len(parts) < 2:
        raise DemistoException("Entitlement cannot be parsed- entitlement not in format.")
    guid = parts[0]
    id_and_task = parts[1].split('|', 1)
    incident_id = id_and_task[0]
    task_id = ''

    if len(id_and_task) > 1:
        task_id = id_and_task[1]

    return guid, incident_id, task_id


async def answer_survey(message: dict):
    entitlement = message.get('entitlement', '')
    default_reply = message.get('default_reply')
    guid, incident_id, task_id = extract_entitlement(entitlement)
    try:
        demisto.handleEntitlementForUser(incident_id, guid, '', default_reply, task_id)
        # TODO
        # account_id = CLIENT.account_id
        # bot_jid = CLIENT.bot_jid
        # if account_id and bot_jid:
        #     _ = await process_entitlement_reply(text, account_id, bot_jid, to_jid)
    except Exception as e:
        demisto.error(f'Failed handling entitlement {entitlement}: {str(e)}')
    message['remove'] = True
    return incident_id


async def check_and_handle_entitlement(user_name, action_selected, message_id, space_id) -> str:
    """
    Handles an entitlement message (a reply to a question)
    Args:
    Returns:
        If the message contains entitlement, return a reply.
    """
    integration_context = get_integration_context()
    messages = integration_context.get('messages', [])
    reply = ''
    if not messages or not message_id:
        return reply
    messages = json.loads(messages)
    message_filter = list(filter(lambda q: q.get('message_id') == message_id, messages))
    if message_filter:
        message = message_filter[0]
        entitlement = message.get('entitlement')
        reply = message.get('reply', f'Thank you {user_name} for your response {action_selected}.')
        guid, incident_id, task_id = extract_entitlement(entitlement)
        demisto.handleEntitlementForUser(incident_id, guid, user_name, action_selected, task_id)
        message['remove'] = True
        set_to_integration_context_with_retries({'messages': messages}, OBJECTS_TO_KEYS)
    return reply


# async def googleChat_send_notification_async(client, url_suffix, json_data_all):
#     CLIENT.send_notification_request(url_suffix, json_data_all)


# async def process_entitlement_reply(
#     entitlement_reply: str,
#     account_id: str,
#     robot_jid: str,
#     to_jid: str | None = None,
#     user_name: str | None = None,
#     action_text: str | None = None,
# ):
#     """
#     Triggered when an entitlement reply is found, this function will update the original message with the reply message.
#     :param entitlement_reply: str: The text to update the asking question with.
#     :param user_name: str: name of the user who answered the entitlement
#     :param action_text: str: The text attached to the button, used for string replacement.
#     :param toJid: str: The Jid of where the question exists.
#     :param accountId: str: Zoom account ID
#     :param robotJid: str: Zoom BOT JID
#     :return: None
#     """
#     if '{user}' in entitlement_reply:
#         entitlement_reply = entitlement_reply.replace('{user}', str(user_name))
#     if '{response}' in entitlement_reply and action_text:
#         entitlement_reply = entitlement_reply.replace('{response}', str(action_text))

#     url_suffix = '/im/chat/messages'
#     content_json = {
#         "content": {
#             "body": [
#                 {
#                     "type": "message",
#                     "text": entitlement_reply
#                 }
#             ]
#         },
#         "to_jid": to_jid,
#         "robot_jid": robot_jid,
#         "account_id": account_id
#     }
#     await google_chat_send_notification_async(CLIENT, url_suffix, content_json)


@app.on_event("startup")
@repeat_every(seconds=60, wait_first=True)
async def check_for_expired_messages():
    """Send the default response if the message expiry time has expired.
    """
    integration_context = get_integration_context()
    messages = integration_context.get('messages')
    if messages:
        messages = json.loads(messages)
        now = datetime.now(timezone.utc)
        updated_messages = False
        for message in messages:
            if message.get('expiry'):
                expiry = datetime.strptime(message['expiry'], DATE_FORMAT)
                if expiry > now:
                    demisto.debug(f"message expired: {message}")
                    _ = await answer_survey(message)
                    updated_messages = True
        if updated_messages:
            set_to_integration_context_with_retries({'messages': messages}, OBJECTS_TO_KEYS)


@app.post('/')
async def handle_googleChat_response(request: Request, credentials: HTTPBasicCredentials = Depends(basic_auth),
                                     token: APIKey = Depends(token_auth)):
    # async def handle_googleChat_response(request: Request, credentials: HTTPBasicCredentials = Depends(basic_auth),
    #                             token: APIKey = Depends(token_auth)):
    """handle any response that came from Google Chat app.
    Args:
        request : Google Chat response to survey.
    Returns:
        JSONResponse: response from Google Chat survey
    """
    request = await request.json()
    demisto.debug(f"{request=}")
    credentials_param = demisto.params().get('credentials')
    # auth_failed = False
    # v_token = demisto.params().get('verification_token', {}).get('password')
    # if not str(token).startswith('Basic') and v_token:
    #     if token != v_token:
    #         auth_failed = True

    if credentials and credentials_param and (username := credentials_param.get('identifier')):
        password = credentials_param.get('password', '')
        if not compare_digest(credentials.username, username) or not compare_digest(credentials.password, password):
            auth_failed = True
    if auth_failed:
        demisto.debug('Authorization failed')
        return Response(status_code=status.HTTP_401_UNAUTHORIZED, content='Authorization failed.')
    event_type = request['type']
    try:
        if event_type == "CARD_CLICKED":
            message_id = request.get('message', {}).get('name').split('messages/', -1)[1]
            space_id = request.get('space', {}).get('name').split('spaces/')[1]
            action_selected = request.get('action', {}).get('actionMethodName')
            user_name = request.get('user', {}).get('displayName')
            demisto.debug(f'Got the a response with the following details {message_id=}, {space_id=}, {action_selected=}')
            entitlement_reply = await check_and_handle_entitlement(user_name, action_selected, message_id, space_id)
            if entitlement_reply:
                # await process_entitlement_reply(entitlement_reply, account_id, robot_jid, to_jid, user_name, action)
                demisto.updateModuleHealth("")
            demisto.debug(f"Action {action_selected} was clicked on message id {message_id}")
        else:
            return Response(status_code=status.HTTP_400_BAD_REQUEST)
        return Response(status_code=status.HTTP_200_OK)
    except Exception as e:
        demisto.error(f"Error: {e}")


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    LONG_RUNNING = params.get('longRunning', False)
    if LONG_RUNNING:
        try:
            port = arg_to_number(params.get('longRunningPort'))
        except ValueError as e:
            raise ValueError(f'Invalid listen port - {e}')
    try:
        client = GoogleChatClient(params.get('space_id'),
                                  params.get('space_key', {}).get('password'),
                                  params.get('space_token', {}).get('password'))
        global CLIENT
        CLIENT = client
        if command == 'long-running-execution':
            run_long_running(port)
        if command == 'test-module':
            result = test_module(client)
            return_results(result)
        elif command == 'send-notification':
            return_results(send_notification_command(client, demisto.args()))
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
