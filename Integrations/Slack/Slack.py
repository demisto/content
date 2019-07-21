import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from distutils.util import strtobool
import slack
from slack.errors import SlackApiError

import asyncio
import concurrent
import ssl


''' CONSTANTS '''


SEVERITY_DICT = {
    'Low': 1,
    'Medium': 2,
    'High': 3,
    'Critical': 4
}


USER_TAG_EXPRESSION = '<@(.*?)>'
CHANNEL_TAG_EXPRESSION = '<#(.*?)>'
URL_EXPRESSION = r'<(https?://.+?)(?:\|.+)?>'
GUID_REGEX = r'(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}'
ENTITLEMENT_REGEX = r'{}@(({})|\d+)(\|\S+)?\b'.format(GUID_REGEX, GUID_REGEX)
MESSAGE_FOOTER = '\n**From Slack**'
MIRROR_TYPE = 'mirrorEntry'
INCIDENT_OPENED = 'incidentOpened'
PLAYGROUND_INVESTIGATION_TYPE = 9
MAX_SEVERITY = 4


''' GLOBALS '''


TOKEN: str
CHANNEL_TOKEN: str
PROXY: str
DEDICATED_CHANNEL: str
LINK_FOOTER: str
GENERAL_FOOTER: str
CLIENT: slack.WebClient
CHANNEL_CLIENT: slack.WebClient
ALLOW_INCIDENTS: bool
NOTIFY_INCIDENTS: bool
INCIDENT_TYPE: str
SEVERITY_THRESHOLD: int


''' HELPER FUNCTIONS '''


def get_bot_id() -> str:
    """
    Gets the app bot ID
    :return: The app bot ID
    """
    response = CLIENT.auth_test()

    return response.get('user_id')


def test_module():
    """
    Sends a test message to the dedicated slack channel.
    """
    channel = get_conversation_by_name(DEDICATED_CHANNEL)
    if not channel:
        return_error('Dedicated channel not found')
    message = 'Hi there! This is a test message.'
    CLIENT.chat_postMessage(channel=channel.get('id'), text=message)

    demisto.results('ok')


def get_user_by_name(user_to_search: str, integration_context: dict) -> dict:
    """
    Gets a slack user by a user name
    :param user_to_search: The user name or email
    :param integration_context The integration context
    :return: A slack user object
    """

    user: dict = {}
    users: list = []
    if integration_context.get('users'):
        users = json.loads(integration_context['users'])
        users_filter = list(filter(lambda u: u.get('name') == user_to_search
                                             or u.get('profile', {}).get('email') == user_to_search, users))
        if users_filter:
            user = users_filter[0]
    if not user:
        workspace_users = []
        response = CLIENT.users_list()
        while True:
            workspace_users += response['members'] if response and response.get('members', []) else []
            cursor = response.get('response_metadata', {}).get('next_cursor')
            users_filter = list(filter(lambda u: u.get('name') == user_to_search
                                                 or u.get('profile', {}).get('email') == user_to_search,
                                       workspace_users))
            if users_filter:
                break
            if not cursor:
                break
            response = CLIENT.users_list(cursor=cursor)

        if users_filter:
            user = users_filter[0]
            users.append(user)
            integration_context['users'] = json.dumps(users)
            demisto.setIntegrationContext(integration_context)
        else:
            return {}

    return user


''' MIRRORING '''


async def get_slack_name(slack_id: str, client) -> str:
    """
    Get the slack name of a provided user or channel by its ID
    :param client: The slack client
    :param slack_id: The slack user or channel ID
    :return: The slack user or channel name
    """
    if not slack_id:
        return ''

    integration_context = demisto.getIntegrationContext()
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
            conversation = (await client.conversations_info(channel=slack_id)).get('channel', {})
        slack_name = conversation.get('name', '')
    elif prefix == 'U':
        user: dict = {}
        if integration_context.get('users'):
            users = list(filter(lambda u: u['id'] == slack_id, json.loads(integration_context['users'])))
            if users:
                user = users[0]
        if not user:
            user = (await client.users_info(user=slack_id)).get('user', {})

        slack_name = user.get('name', '')

    demisto.setIntegrationContext(integration_context)
    return slack_name


async def clean_message(message: str, client: slack.WebClient) -> str:
    """
    Prettifies a slack message - replaces tags and URLs with clean expressions
    :param message: The slack message
    :param client: The slack client
    :return: The clean slack message
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
    :param conversation_id: The slack conversation ID to invite the users to.
    :param users_to_invite: The user slack IDs to invite.
    """
    for user in users_to_invite:
        try:
            CHANNEL_CLIENT.conversations_invite(channel=conversation_id, users=user)
        except SlackApiError as e:
            message = str(e)
            if message.find('cant_invite_self') == -1:
                raise


def mirror_investigation():
    """
    Updates the integration context with a new or existing mirror.
    """
    mirror_type = demisto.args().get('type', 'all')
    auto_close = demisto.args().get('autoclose', 'true')
    mirror_direction = demisto.args().get('direction', 'both')
    mirror_to = demisto.args().get('mirrorTo', 'group')

    investigation = demisto.investigation()

    if investigation.get('type') == PLAYGROUND_INVESTIGATION_TYPE:
        return_error('Can not perform this action in playground.')

    integration_context = demisto.getIntegrationContext()

    if not integration_context or not integration_context.get('mirrors', []):
        mirrors: list = []
    else:
        mirrors = json.loads(integration_context['mirrors'])
    if not integration_context or not integration_context.get('conversations', []):
        conversations: list = []
    else:
        conversations = json.loads(integration_context['conversations'])

    investigation_id = investigation.get('id')
    slack_users = []
    for user in investigation.get('users'):
        slack_user = get_user_by_name(user, integration_context)
        if not slack_user:
            demisto.results({
                'Type': entryTypes['error'],
                'Contents': 'User {} not found in Slack'.format(user),
                'ContentsFormat': formats['text']
            })
        else:
            slack_users.append(slack_user)

    users_to_invite = list(map(lambda u: u.get('id'), slack_users))
    current_mirror = list(filter(lambda m: m['investigation_id'] == investigation_id, mirrors))
    if not current_mirror:
        if mirror_to == 'channel':
            conversation = CHANNEL_CLIENT.channels_create(name='incident-{}'
                                                          .format(investigation_id)).get('channel', {})
            conversation_id = conversation.get('id')
        else:
            conversation = CHANNEL_CLIENT.groups_create(name='incident-{}'
                                                        .format(investigation_id)).get('group', {})
            conversation_id = conversation.get('id')
        conversations.append(conversation)
        mirrors.append({
            'channel_id': conversation_id,
            'investigation_id': investigation.get('id'),
            'mirror_type': mirror_type,
            'mirror_direction': mirror_direction,
            'mirror_to': mirror_to,
            'auto_close': bool(strtobool(auto_close)),
            'mirrored': False
        })
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
            return_error('Cannot change the Slack channel type from Demisto.')
        mirror['mirrored'] = False
        mirrors.append(mirror)

    if integration_context.get('bot_id'):
        bot_id = integration_context['bot_id']
    else:
        bot_id = get_bot_id()
    users_to_invite += [bot_id]
    invite_users_to_conversation(conversation_id, users_to_invite)

    integration_context['bot_id'] = bot_id
    integration_context['mirrors'] = json.dumps(mirrors)
    integration_context['conversations'] = json.dumps(conversations)

    demisto.setIntegrationContext(integration_context)

    demisto.results('Investigation mirrored successfully')


def long_running_loop():
    """
    Runs in a long running container - checking for newly mirrored investigations.
    """
    while True:
        try:
            check_for_mirrors()
        except Exception as e:
            error = 'An error occurred: {}'.format(str(e))
            demisto.error(error)
            demisto.updateModuleHealth(error)
        finally:
            time.sleep(5)


def check_for_mirrors():
    """
    Checks for newly created mirrors and updates the server accordingly
    """
    integration_context = demisto.getIntegrationContext()
    if integration_context.get('mirrors'):
        mirrors = json.loads(integration_context['mirrors'])
        for mirror in mirrors:
            if not mirror['mirrored']:
                demisto.info('Mirroring: {}'.format(mirror['investigation_id']))
                mirror = mirrors.pop(mirrors.index(mirror))
                if mirror['mirror_to'] and mirror['mirror_direction'] and mirror['mirror_type']:
                    investigation_id = mirror['investigation_id']
                    mirror_type = mirror['mirror_type']
                    auto_close = mirror['auto_close']
                    direction = mirror['mirror_direction']
                    if isinstance(auto_close, str):
                        auto_close = bool(strtobool(auto_close))
                    demisto.mirrorInvestigation(investigation_id, '{}:{}'.format(mirror_type, direction), auto_close)
                    mirror['mirrored'] = True
                    mirrors.append(mirror)
                else:
                    demisto.info('Could not mirror {}'.format(mirror['investigation_id']))
                integration_context['mirrors'] = json.dumps(mirrors)
                demisto.setIntegrationContext(integration_context)


async def slack_loop():
    """
    Starts a Slack RTM client while checking the connection.
    """
    while True:
        loop = asyncio.get_running_loop()
        rtm_client = None
        try:
            rtm_client = slack.RTMClient(
                token=TOKEN,
                run_async=True,
                loop=loop,
                auto_reconnect=False
            )
            client_future = rtm_client.start()
            while True:
                await asyncio.sleep(10)
                if rtm_client._websocket is None or rtm_client._websocket.closed or client_future.done():
                    ex = client_future.exception()
                    if ex:
                        demisto.error('Slack client raised an exception: {}'.format(ex))
                    demisto.info('Slack - websocket is closed or done')
                    break
        except Exception as e:
            error = 'Slack client raised an exception: {}'.format(e)
            await handle_listen_error(error)
        finally:
            # If we got here, the websocket is closed or the client can't connect. Will try to connect every 5 seconds.
            if rtm_client and not rtm_client._stopped:
                rtm_client.stop()
            await asyncio.sleep(5)


async def handle_listen_error(error: str):
    """
    Logs an error and updates the module health accordingly.
    :param error: The error string.
    """
    demisto.error(error)
    demisto.updateModuleHealth(error)


async def start_listening():
    """
    Starts a Slack RTM client and checks for mirrored incidents.
    """
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    loop = asyncio.get_running_loop()
    loop.run_in_executor(executor, long_running_loop)
    await slack_loop()


async def handle_dm(user_id: str, text: str, client: slack.WebClient):
    """
    Handles a direct message sent to the bot
    :param user_id: The user who sent the message
    :param text: The message text
    :param client: The Slack client
    :return: Text to return to the user
    """
    integration_context = demisto.getIntegrationContext()

    user: dict = {}
    users: list = []
    if integration_context.get('users'):
        users = json.loads(integration_context['users'])
        user_filter = list(filter(lambda u: u['id'] == user_id, users))
        if user_filter:
            user = user_filter[0]
    if not user:
        user = (await client.users_info(user=user_id)).get('user', {})
        users.append(user)
        integration_context['users'] = json.dumps(users)
        demisto.setIntegrationContext(integration_context)

    message: str = text.lower()
    if message.find('incident') != -1 and (message.find('create') != -1
                                           or message.find('open') != -1
                                           or message.find('new') != -1):
        user_email = user.get('profile', {}).get('email')
        if user_email:
            demisto_user = demisto.findUser(email=user_email)
        else:
            demisto_user = demisto.findUser(username=user.get('name'))

        if not demisto_user and not ALLOW_INCIDENTS:
            data = 'You are not allowed to create incidents.'
        else:
            data = await translate_create(demisto_user, message)
    else:
        data = demisto.directMessage(message, user.get('name'), user.get('profile', {}).get('email'), ALLOW_INCIDENTS)

    im = await client.im_open(user=user.get('id'))
    channel = im.get('channel', {}).get('id')
    await client.chat_postMessage(channel=channel, text=data)


async def translate_create(demisto_user: dict, message: str) -> str:
    """
    Processes an incident creation message
    :param demisto_user: The Demisto user associated with the message (if exists)
    :param message: The creation message
    :return: Creation result
    """
    json_pattern = r'(?<=json=).*'
    name_pattern = r'(?<=name=).*'
    type_pattern = r'(?<=type=).*'
    json_match = re.search(json_pattern, message)
    created_incident = None
    data = ''
    if json_match:
        if re.search(name_pattern, message) or re.search(type_pattern, message):
            data = 'No other properties other than json should be specified.'
        else:
            incidents_json = json_match.group()
            incidents = json.loads(incidents_json.replace('“', '"').replace('”', '"'))
            if not isinstance(incidents, list):
                incidents = [incidents]
            created_incident = await create_incidents(demisto_user, incidents)

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

            created_incident = await create_incidents(demisto_user, [incident])
            if not created_incident:
                data = 'Failed creating incidents.'

    if created_incident:
        if isinstance(created_incident, list):
            created_incident = created_incident[0]
        server_links = demisto.demistoUrls()
        server_link = server_links.get('server')
        data = ('Successfully created incident {}.\n View it on: {}#/WarRoom/{}'
                .format(created_incident['name'], server_link, created_incident['id']))

    return data


async def create_incidents(demisto_user: dict, incidents: list) -> dict:
    """
    Creates incidents according to a provided JSON object
    :param demisto_user: The demisto user associated with the request (if exists)
    :param incidents: The incidents JSON
    :return: The creation result
    """
    if demisto_user:
        data = demisto.createIncidents(incidents, userID=demisto_user['id'])
    else:
        data = demisto.createIncidents(incidents)

    return data


@slack.RTMClient.run_on(event='message')
async def listen(**payload):
    """
    Listens to Slack RTM messages
    :param payload: The message payload
    """
    data: dict = payload.get('data', {})
    data_type: str = payload.get('type', '')
    client: slack.WebClient = payload.get('web_client')

    if data_type == 'error':
        error = payload.get('error', {})
        await handle_listen_error('Slack API has thrown an error. Code: {}, Message: {}.'
                                  .format(error.get('code'), error.get('msg')))
        return
    try:
        subtype = data.get('subtype', '')
        text = data.get('text', '')
        user_id = data.get('user', '')
        channel = data.get('channel', '')
        message_bot_id = data.get('bot_id', '')

        if subtype == 'bot_message' or message_bot_id:
            return

        if channel and channel[0] == 'D':
            # DM
            await handle_dm(user_id, text, client)
        else:
            integration_context = demisto.getIntegrationContext()
            if not integration_context or 'mirrors' not in integration_context:
                return

            channel_id = data.get('channel')
            mirrors = json.loads(integration_context['mirrors'])
            mirror_filter = list(filter(lambda m: m['channel_id'] == channel_id, mirrors))
            if not mirror_filter:
                return

            mirror: dict = mirrors.pop(mirrors.index(mirror_filter[0]))

            if mirror['mirror_direction'] == 'FromDemisto':
                return
            if mirror['mirror_type'] == 'none':
                return

            if not mirror['mirrored']:
                # In case the incident is not mirrored yet
                auto_close = mirror['auto_close']
                if isinstance(auto_close, str):
                    auto_close = bool(strtobool(auto_close))
                demisto.mirrorInvestigation(mirror['investigation_id'],
                                            '{}:{}'.format(mirror['mirror_type'], mirror['mirror_direction']),
                                            auto_close)
                mirror['mirrored'] = True

            mirrors.append(mirror)
            integration_context['mirrors'] = json.dumps(mirrors)

            await handle_text(client, integration_context, mirror['investigation_id'], text, user_id)

            demisto.setIntegrationContext(integration_context)
        # Reset module health
        demisto.updateModuleHealth("")
    except Exception as e:
        await handle_listen_error('Error occurred while listening to Slack: {}'.format(str(e)))


async def handle_text(client: slack.WebClient, integration_context: dict,
                      investigation_id: str, text: str, user_id: str):
    """
    Handles text received in the Slack workspace (not DM)
    :param client: The Slack client
    :param integration_context: The integration context
    :param investigation_id: The mirrored investigation ID
    :param text: The received text
    :param user_id: The ID of the sender
    """
    if text:
        user: dict = {}
        users: list = []
        if integration_context.get('users'):
            users = json.loads(integration_context['users'])
            user_filter = list(filter(lambda u: u['id'] == user_id, users))
            if user_filter:
                user = user_filter[0]
        if not user:
            user = (await client.users_info(user=user_id)).get('user', {})
            users.append(user)
            integration_context['users'] = json.dumps(users)

        is_entitlement = await check_entitlement(text, user)
        if not is_entitlement:
            demisto.addEntry(id=investigation_id,
                             entry=await clean_message(text, client),
                             username=user.get('name', ''),
                             email=user.get('profile', {}).get('email', ''),
                             footer=MESSAGE_FOOTER
                             )


async def check_entitlement(text: str, user: dict) -> bool:
    entitlement_match = re.search(ENTITLEMENT_REGEX, text)
    if entitlement_match:
        entitlement = entitlement_match.group()
        parts = entitlement.split('@')
        guid = parts[0]
        id_and_task = parts[1].split('|')
        incident_id = id_and_task[0]
        task_id = ''
        if len(id_and_task) > 1:
            task_id = id_and_task[1]
        content = text.replace(entitlement, '', 1)
        demisto.handleEntitlement(incident_id, guid, task_id, user.get('profile', {}).get('email'), content)
        return True

    return False


''' SEND '''


def get_conversation_by_name(conversation_name: str) -> dict:
    """
    Get a slack conversation by its name
    :param conversation_name: The conversation name
    :return: The slack conversation
    """
    response = CLIENT.conversations_list(types='private_channel,public_channel')

    conversations = response['channels'] if response and response.get('channels') else []

    if not conversations:
        return return_error('Could not retrieve conversations')

    conversation = list(filter(lambda c: c.get('name') == conversation_name, conversations))

    if not conversation:
        return {}

    return conversation[0]


def slack_send():
    """
    Sends a message to slack
    """
    message = demisto.args().get('message', '')
    to = demisto.args().get('to')
    channel = demisto.args().get('channel')
    group = demisto.args().get('group')
    message_type = demisto.args().get('messageType', '')
    entry = demisto.args().get('entry')
    ignore_add_url = demisto.args().get('IgnoreAddURL', False)
    thread_id = demisto.args().get('threadID', '')
    severity = demisto.args().get('severity')  # From server

    if message_type == MIRROR_TYPE and message.find(MESSAGE_FOOTER) != -1:
        # return so there will not be a loop of messages
        return

    if severity:
        try:
            severity = int(severity)
        except Exception:
            pass

    if not channel and message_type == INCIDENT_OPENED and severity > SEVERITY_THRESHOLD:
        channel = DEDICATED_CHANNEL

    response = slack_send_request(to, channel, group, entry, ignore_add_url, thread_id, message=message)

    if response:
        thread = response.get('ts')
        demisto.results({
            'Type': entryTypes['note'],
            'Contents': 'Message sent to Slack successfully.\nThread ID is: {}'.format(thread),
            'ContentsFormat': formats['text'],
            'EntryContext': {
                'Slack.Thread(val.ID===obj.ID)': {
                    'ID': thread
                },
            }
        })
    else:
        demisto.results('Could not send the message to Slack.')


def slack_send_file():
    """
    Sends a file to slack
    """
    to = demisto.args().get('to')
    channel = demisto.args().get('channel')
    group = demisto.args().get('group')
    entry_id = demisto.args().get('file')
    thread_id = demisto.args().get('threadID')
    comment = demisto.args().get('comment', '')

    file_path = demisto.getFilePath(entry_id)
    with open(file_path['path'], 'rb') as file:
        data = file.read()

    file = {
        'data': data,
        'name': file_path['name'],
        'comment': comment
    }

    response = slack_send_request(to, channel, group, thread_id=thread_id, file=file)
    if response:
        demisto.results('File sent to Slack successfully.')
    else:
        demisto.results('Could not send the file to Slack.')


def send_message(destinations: list, entry: str, ignore_add_url: bool, integration_context: dict, message: str,
                 thread_id: str):
    """
    Sends a message to Slack.
    :param destinations: The destinations to send to.
    :param entry: A WarRoom entry to send.
    :param ignore_add_url: Do not add a Demisto URL to the message.
    :param integration_context: Current integration context.
    :param message: The message to send.
    :param thread_id: The Slack thread ID to send the message to.
    :return: The Slack send response.
    """
    if not message:
        message = '\n'
    if ignore_add_url and isinstance(ignore_add_url, str):
        ignore_add_url = bool(strtobool(ignore_add_url))
    if not ignore_add_url and LINK_FOOTER:
        investigation = demisto.investigation()
        server_links = demisto.demistoUrls()
        if investigation:
            if investigation.get('type') != PLAYGROUND_INVESTIGATION_TYPE:
                link = server_links.get('warRoom')
                if link:
                    if entry:
                        link += '/' + entry
                    message += '\n{} {}'.format('View it on:', link)
            elif GENERAL_FOOTER:
                link = server_links.get('server', '')
                if link:
                    message += '\n{} {}'.format('View it on:', link + '#/home')
    try:
        response = send_message_to_destinations(destinations, message, thread_id)
    except SlackApiError as e:
        if str(e).find('not_in_channel') == -1:
            raise
        bot_id = integration_context.get('bot_id')
        if not bot_id:
            bot_id = get_bot_id()
        for dest in destinations:
            invite_users_to_conversation(dest, [bot_id])
        response = send_message_to_destinations(destinations, message, thread_id)
    return response


def send_message_to_destinations(destinations: list, message: str, thread_id: str) -> dict:
    """
    Sends a message to provided destinations Slack.
    :param destinations: Destinations to send to.
    :param message: The message to send.
    :param thread_id: Slack thread ID to send to.
    :return: The Slack send response.
    """
    response: dict = {}
    for destination in destinations:
        if thread_id:
            response = CLIENT.chat_postMessage(channel=destination, text=message, thread_ts=thread_id)
        else:
            response = CLIENT.chat_postMessage(channel=destination, text=message)
    return response


def send_file(destinations: list, file: dict, integration_context: dict, thread_id: str) -> dict:
    """
    Sends a file to Slack.
    :param destinations: Destinations to send the file to.
    :param file: The file to send.
    :param integration_context: The current integration context.
    :param thread_id: A Slack thread to send to.
    :return: The Slack send response.
    """
    try:
        response = send_file_to_destinations(destinations, file, thread_id)
    except SlackApiError as e:
        if str(e).find('not_in_channel') == -1:
            raise
        bot_id = integration_context.get('bot_id')
        if not bot_id:
            bot_id = get_bot_id()
            integration_context['bot_id'] = bot_id
        for dest in destinations:
            invite_users_to_conversation(dest, [bot_id])
        response = send_file_to_destinations(destinations, file, thread_id)
    return response


def send_file_to_destinations(destinations: list, file: dict, thread_id: str) -> dict:
    """
    Sends a file to provided destinations in Slack.
    :param destinations: The destinations to send to.
    :param file: The file to send.
    :param thread_id: A thread ID to send to.
    :return: The Slack send response.
    """
    response: dict = {}
    for destination in destinations:
        if thread_id:
            response = CLIENT.files_upload(channels=destination,
                                           file=file['data'], filename=file['name'],
                                           initial_comment=file['comment'], thread_ts=thread_id)
        else:
            response = CLIENT.files_upload(channels=destination,
                                           file=file['data'], filename=file['name'],
                                           initial_comment=file['comment'])
    return response


def slack_send_request(to: str, channel: str, group: str, entry: str = '', ignore_add_url: bool = False,
                       thread_id: str = '', message: str = '', file: dict = None) -> dict:
    """
    Requests to send a message or a file to Slack.
    :param to: A Slack user to send to.
    :param channel: A Slack channel to send to.
    :param group: A Slack private channel to send to.
    :param entry: WarRoom entry to send.
    :param severity: If it's a notification regrading an incident - it's the incident severity.
    :param ignore_add_url: Do not add a Demisto URL to the message.
    :param thread_id: The Slack thread ID to send to.
    :param message: A message to send.
    :param file: A file to send.
    :return: The Slack send response.
    """
    if not (to or group or channel):
        return_error('Either a user, group or channel must be provided.')

    integration_context = demisto.getIntegrationContext()
    conversations: list = []

    if integration_context:
        if 'conversations' in integration_context:
            conversations = json.loads(integration_context['conversations'])
    destinations = []

    if to:
        if isinstance(to, list):
            to = to[0]
        user = get_user_by_name(to, integration_context)
        if not user:
            demisto.error('Could not find the Slack user {}'.format(to))
        else:
            im = CLIENT.im_open(user=user.get('id'))
            destinations.append(im.get('channel', {}).get('id'))
    elif channel or group:
        destination_name = channel or group
        conversation_filter = list(filter(lambda c: c.get('name') == destination_name, conversations))
        if not conversation_filter:
            conversation = get_conversation_by_name(destination_name)
            if not conversation:
                return_error('Could not find the Slack conversation {}'.format(destination_name))
            conversations.append(conversation)
            integration_context['conversations'] = json.dumps(conversations)
        else:
            conversation = conversation_filter[0]
        destinations.append(conversation.get('id'))

    if not destinations:
        return_error('Could not find any destination to send to.')

    if file:
        response = send_file(destinations, file, integration_context, thread_id)
        return response

    response = send_message(destinations, entry, ignore_add_url, integration_context, message,
                            thread_id)

    demisto.setIntegrationContext(integration_context)
    return response


def close_channel():
    """
    Archives a mirrored slack channel by its incident ID.
    """
    demisto.info('Closing?')
    investigation = demisto.investigation()
    if investigation.get('type') == PLAYGROUND_INVESTIGATION_TYPE:
        return_error('Can not perform this action in playground.')

    integration_context = demisto.getIntegrationContext()
    if not integration_context or not integration_context.get('mirrors', []):
        return_error('No mirrors found for this incident.')

    mirrors = json.loads(integration_context['mirrors'])
    mirror = list(filter(lambda m: m['investigation_id'] == investigation.get('id'), mirrors))
    if not mirror:
        return_error('Could not find the mirrored Slack conversation.')

    mirror = mirrors.pop(mirrors.index(mirror[0]))
    conversation_id = mirror['channel_id']

    CHANNEL_CLIENT.conversations_archive(channel=conversation_id)

    integration_context['mirrors'] = json.dumps(mirrors)
    demisto.setIntegrationContext(integration_context)

    demisto.results('Channel successfully archived.')


def long_running_main():
    """
    Starts the long running thread.
    """
    asyncio.run(start_listening())


def init_globals():
    """
    Initializes global variables according to the integration parameters
    """
    global TOKEN, CHANNEL_TOKEN, PROXY, DEDICATED_CHANNEL, LINK_FOOTER, GENERAL_FOOTER, CLIENT, CHANNEL_CLIENT
    global SEVERITY_THRESHOLD, ALLOW_INCIDENTS, NOTIFY_INCIDENTS, INCIDENT_TYPE

    TOKEN = demisto.params().get('bot_token')
    CHANNEL_TOKEN = demisto.params().get('channel_token')
    PROXY = handle_proxy().get('https')
    DEDICATED_CHANNEL = demisto.params().get('incidentNotificationChannel')
    LINK_FOOTER = demisto.params().get('footer', True)
    GENERAL_FOOTER = demisto.params().get('general_footer', True)
    CLIENT = slack.WebClient(token=TOKEN, proxy=PROXY)
    CHANNEL_CLIENT = slack.WebClient(token=CHANNEL_TOKEN, proxy=PROXY)
    SEVERITY_THRESHOLD = SEVERITY_DICT.get(demisto.params().get('min_severity', 'Low'), 1)
    ALLOW_INCIDENTS = demisto.params().get('allow_incidents', False)
    NOTIFY_INCIDENTS = demisto.params().get('notify_incidents', True)
    INCIDENT_TYPE = demisto.params().get('incidentType')


def main():
    """
    Main
    """

    init_globals()

    commands = {
        'test-module': test_module,
        'long-running-execution': long_running_main,
        'slack-mirror-investigation': mirror_investigation,
        'mirror-investigation': mirror_investigation,
        'slack-send': slack_send,
        'send-notification': slack_send,
        'slack-send-file': slack_send_file,
        'close-channel': close_channel,
        'slack-close-channel': close_channel
    }

    try:
        command_func = commands[demisto.command()]
        command_func()
    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
