import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from distutils.util import strtobool
import slack
from slack.errors import SlackApiError
from timeit import default_timer as timer
import asyncio
import concurrent

TOKEN = demisto.params()['bot_token']
CHANNEL_TOKEN = demisto.params()['channel_token']

if not demisto.params().get('proxy', False):
    del os.environ['HTTPS_PROXY']
    del os.environ['https_proxy']
    PROXY = None
else:
    PROXY = os.environ['https_proxy'] or os.environ['HTTPS_PROXY']

USER_TAG_EXPRESSION = '<@(.*?)>'
CHANNEL_TAG_EXPRESSION = '<#(.*?)>'
URL_EXPRESSION = '<(https?://.+?)(?:\|.+)?>'
PLAYGROUND_INVESTIGATION_TYPE = 9
MAX_SEVERITY = 4
DEDICATED_CHANNEL = demisto.params()['incidentNotificationChannel']
LINK_FOOTER = demisto.params().get('footer')
GENERAL_FOOTER = demisto.params().get('general_footer')
CLIENT = slack.WebClient(token=TOKEN, proxy=PROXY)
CHANNEL_CLIENT = slack.WebClient(token=CHANNEL_TOKEN, proxy=PROXY)
SEVERITY_THRESHOLD = demisto.args().get('min_severity', 1)
# RTM_CLIENT = slack.RTMClient(token=TOKEN, run_async=False)


''' HELPER FUNCTIONS '''


def get_bot_id():
    """
    Gets the app bot ID
    :return: The app bot ID
    """
    response = CLIENT.auth_test()

    return response.get('user_id')


async def get_slack_name(slack_id: str) -> str:
    """
    Get the slack name of a provided object by its ID
    :param slack_id: The slack object ID
    :return: The slack object name
    """
    if not slack_id:
        return ''

    integration_context = demisto.getIntegrationContext()
    prefix = slack_id[0]
    slack_name = ''

    if prefix in ['C', 'D', 'G']:
        slack_id = slack_id.split('|')[0]
        conversation = ''
        if integration_context.get('conversations'):
            conversations = json.loads(integration_context['conversations'])
            conversation = list(filter(lambda c: c['id'] == slack_id, conversations))
            if conversation:
                conversation = conversation[0]
        if not conversation:
            loop = asyncio.get_event_loop()
            client = slack.WebClient(token=TOKEN, proxy=PROXY, loop=loop)
            conversation = (await client.conversations_info(channel=slack_id)).get('channel', {})
        slack_name = conversation.get('name', '')
    elif prefix == 'U':
        user = ''
        if integration_context.get('users'):
            users = json.loads(integration_context['users'])
            user = list(filter(lambda u: u['id'] == slack_id, users))
            if user:
                user = user[0]
        if not user:
            loop = asyncio.get_event_loop()
            client = slack.WebClient(token=TOKEN, proxy=PROXY, loop=loop)
            user = (await client.users_info(user=slack_id)).get('user', {})

        slack_name = user.get('name', '')

    demisto.setIntegrationContext(integration_context)
    return slack_name


async def clean_message(message: str):
    """
    Prettifies a slack message - replaces tags and URLs with clean expressions
    :param message: The slack message
    :return: The clean slack message
    """
    matches = re.findall(USER_TAG_EXPRESSION, message)
    matches += re.findall(CHANNEL_TAG_EXPRESSION, message)
    message = re.sub(USER_TAG_EXPRESSION, r'\1', message)
    message = re.sub(CHANNEL_TAG_EXPRESSION, r'\1', message)
    for match in matches:
        slack_name = await get_slack_name(match)
        message = message.replace(match, slack_name)

    resolved_message = re.sub(URL_EXPRESSION, r'\1', message)

    return resolved_message


def get_user(user):
    """
    Gets a slack user object by a user name
    :param user: The user name or email
    :return: A slack user object
    """
    response = CLIENT.users_list()

    users = response['members'] if response and response.get('members', []) else []
    if not users:
        return return_error('Could not retrieve users')

    user = list(filter(lambda u: u.get('name') == user or u.get('profile', {}).get('email') == user, users))

    if not user:
        return []

    return user[0]


def get_conversation(conversation_name):
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
        return []

    return conversation[0]


def invite_user_to_conversation(conversation_id, users_to_invite):
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


def test_module():
    """
    Sends a test message to the dedicated slack channel.
    """
    channel = get_conversation(DEDICATED_CHANNEL)
    if not channel:
        return_error('Dedicated channel not found')
    message = 'Hi there! This is a test message.'
    CLIENT.chat_postMessage(channel=channel.get('id'), text=message)

    demisto.results('ok')


''' MIRRORING '''


def clear_mirrors():
    demisto.setIntegrationContext({'mirrors': json.dumps([])})
    demisto.results('Successfully cleared mirrors.')


def mirror_investigation():
    """
    Updates the integration context with a new or existing mirror.
    """
    mirror_type = demisto.args().get('type')
    auto_close = demisto.args().get('autoclose')
    mirror_direction = demisto.args().get('direction')
    mirror_to = demisto.args().get('mirrorTo')

    investigation = demisto.investigation()

    if investigation.get('type') == PLAYGROUND_INVESTIGATION_TYPE:
        return_error('Can not perform this action in playground.')

    integration_context = demisto.getIntegrationContext()

    if not integration_context or not integration_context.get('mirrors', []):
        mirrors = []
    else:
        mirrors = json.loads(integration_context['mirrors'])
    if not integration_context or not integration_context.get('conversations', []):
        conversations = []
    else:
        conversations = json.loads(integration_context['conversations'])

    investigation_id = investigation.get('id')
    slack_users = []
    for user in investigation.get('users'):
        slack_user = get_user(user)
        if not slack_user:
            demisto.results({
                'Type': entryTypes['error'],
                'Contents': 'User {} not found in Slack'.format(user),
                'ContentsFormat': formats['text']
            })
        else:
            slack_users.append(slack_user)

    users_to_invite = list(map(lambda u: u.get('id'), slack_users))
    mirror = list(filter(lambda m: m['investigation_id'] == investigation_id, mirrors))
    if not mirror:
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
            'auto_close': auto_close,
            'mirrored': False
        })
    else:
        mirror = mirrors.pop(mirrors.index(mirror[0]))
        conversation_id = mirror['channel_id']
        if mirror_type:
            mirror['mirror_type'] = mirror_type
        if auto_close:
            mirror['auto_close'] = auto_close
        if mirror_direction:
            mirror['mirror_direction'] = mirror_direction
        if mirror_to:
            mirror['mirror_to'] = mirror_to
        mirrors.append(mirror)

    if integration_context.get('bot_id'):
        bot_id = integration_context['bot_id']
    else:
        bot_id = get_bot_id()
    users_to_invite += [bot_id]
    invite_user_to_conversation(conversation_id, users_to_invite)

    integration_context['bot_id'] = bot_id
    integration_context['mirrors'] = json.dumps(mirrors)
    integration_context['conversations'] = json.dumps(conversations)

    demisto.setIntegrationContext(integration_context)

    demisto.results('Investigation mirrored successfully')


def long_running_loop():
    while True:
        try:
            integration_context = demisto.getIntegrationContext()
            if integration_context.get('mirrors'):
                mirrors = json.loads(integration_context['mirrors'])
                for mirror in mirrors:
                    if not mirror['mirrored']:
                        demisto.info('Mirroring: {}'.format(mirror['investigation_id']))
                        mirror = mirrors.pop(mirrors.index(mirror))
                        demisto.mirrorInvestigation(mirror['investigation_id'], mirror['mirror_type'],
                                                    bool(strtobool(mirror['auto_close'])))
                        mirror['mirrored'] = True
                        mirrors.append(mirror)
                        integration_context['mirrors'] = json.dumps(mirrors)
                        demisto.setIntegrationContext(integration_context)
            #demisto.updateModuleHealth("")
            time.sleep(5)
        except Exception as e:
            demisto.updateModuleHealth('An error occurred: {}'.format(str(e)))


async def start_listening():
    """
    Starts a Slack RTM client and checks for mirrored incidents.
    """
    loop = asyncio.get_event_loop()
    rtm_client = slack.RTMClient(token=TOKEN, run_async=True, loop=loop)
    try:
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        await asyncio.gather(
            loop.run_in_executor(executor, long_running_loop),
            rtm_client.start()
        )
    finally:
        rtm_client.stop()


@slack.RTMClient.run_on(event='message')
async def listen(**payload):
    """
    Listens to Slack RTM messages
    :param payload: The message payload
    """
    start = timer()
    data = payload.get('data')
    data_type = payload.get('type')
    client = payload.get('web_client')

    if data_type == 'error':
        error = payload.get('error', {})
        demisto.updateModuleHealth('Slack API has thrown an error. Code: {}, Message: {}.'
                                   .format(error.get('code'), error.get('msg')))
        return
    try:
        subtype = data.get('subtype', '')
        text = data.get('text', '')
        user_id = data.get('user')

        if subtype == 'bot_message':
            return

        integration_context = demisto.getIntegrationContext()
        if not integration_context or 'mirrors' not in integration_context:
            return

        channel_id = data.get('channel')
        mirrors = json.loads(integration_context['mirrors'])
        mirror = list(filter(lambda m: m['channel_id'] == channel_id, mirrors))
        if not mirror:
            return

        mirror = mirrors.pop(mirrors.index(mirror[0]))

        if mirror['mirror_direction'] == 'FromDemisto':
            return

        if not mirror['mirrored']:
            demisto.mirrorInvestigation(mirror['investigation_id'], mirror['mirror_type'],
                                        bool(strtobool(mirror['auto_close'])))
            mirror['mirrored'] = True

        mirrors.append(mirror)

        if text:
            user = ''
            users = []
            if integration_context.get('users'):
                users = json.loads(integration_context['users'])
                user = list(filter(lambda u: u['id'] == user_id, users))
                if user:
                    user = user[0]
            if not user:
                user = (await client.users_info(user=user_id)).get('user', {})
                users.append(user)
            demisto.addEntry(id=mirror['investigation_id'],
                             entry=await clean_message(text), username=user.get('name', ''),
                             email=user.get('profile', {}).get('email', ''),
                             footer='\n**From Slack**' if text[0] != '!' else '')
            # TODO: do we want to set context if we don't have text?
            demisto.setIntegrationContext({'mirrors': json.dumps(mirrors), 'users': json.dumps(users)})
        # Reset module health
        demisto.updateModuleHealth("")
        end = timer()
        demisto.info('############# time: ' + str(end - start))
    except Exception as e:
        demisto.updateModuleHealth("Error occurred while listening to Slack: {}".format(str(e)))


''' SEND '''


def slack_send():
    """
    Sends a message to slack
    """
    message = demisto.args().get('message')
    to = demisto.args().get('to')
    channel = demisto.args().get('channel')
    group = demisto.args().get('group')
    entry = demisto.args().get('entry')
    ignore_add_url = demisto.args().get('IgnoreAddURL', 'false')
    thread_id = demisto.args().get('threadID')
    severity = demisto.args().get('severity')

    response = slack_send_request(to, channel, group, entry, severity, ignore_add_url, thread_id, message=message)

    if response:
        thread = response.get('ts')
        demisto.results('Message sent to Slack successfully.\nThread ID is: {}'.format(thread))
    else:
        demisto.results('Could not send the message to Slack.')


def slack_send_file():
    """
    Sends a file to slack
    :return:
    """
    to = demisto.args().get('to')
    channel = demisto.args().get('channel')
    group = demisto.args().get('group')
    entry_id = demisto.args().get('file')
    thread_id = demisto.args().get('threadID')
    comment = demisto.args().get('comment', '')

    file_path = demisto.getFilePath(entry_id)
    with open('5520@a2cb0993-027d-40ec-83c2-0c7b29541f2a', 'r') as file:
        data = file.read()

    file = {
        'data': data,
        'name': file_path['name'],
        'comment': comment
    }

    response = slack_send_request(to, channel, group, thread_id=thread_id, file=file)

    demisto.results('File sent to Slack successfully.')


def send_message(destinations, entry, ignore_add_url, integration_context, message,
                 thread_id):
    demisto.info('Sending message, to={}, msg={}'.format(str(destinations), message))
    if not message:
        message = '\n'
    if not bool(strtobool(ignore_add_url)) and LINK_FOOTER:
        investigation = demisto.investigation()
        server_links = demisto.demistoUrls()
        if investigation:
            if investigation.get('type') != PLAYGROUND_INVESTIGATION_TYPE:
                link = server_links.get('warRoom')
                if link:
                    if entry:
                        link += '/' + entry
                    message += '\n{} {}'.format(LINK_FOOTER, link)
            elif GENERAL_FOOTER:
                link = server_links.get('server', '')
                if link:
                    message += '\n{} {}'.format(GENERAL_FOOTER, link + '#/home')
    response = None

    try:
        for destination in destinations:
            if thread_id:
                response = CLIENT.chat_postMessage(channel=destination, text=message, thread_ts=thread_id)
            else:
                response = CLIENT.chat_postMessage(channel=destination, text=message)
    except SlackApiError as e:
        if str(e).find('not_in_channel') == -1:
            raise
        bot_id = integration_context.get('bot_id')
        if not bot_id:
            bot_id = get_bot_id()
        invite_user_to_conversation(destinations, bot_id)
        for destination in destinations:
            if thread_id:
                response = CLIENT.chat_postMessage(channel=destination, text=message, thread_ts=thread_id)
            else:
                response = CLIENT.chat_postMessage(channel=destination, text=message)
    return response


def send_file(destinations, file, integration_context, thread_id):
    response = None
    try:
        for destination in destinations:
            if thread_id:
                response = CLIENT.files_upload(channels=destination,
                                               content=file['data'], filename=file['name'],
                                               initial_comment=file['comment'], thread_ts=thread_id)
            else:
                response = CLIENT.files_upload(channels=destination,
                                               content=file['data'], filename=file['name'],
                                               initial_comment=file['comment'])
    except SlackApiError as e:
        if str(e).find('not_in_channel') == -1:
            raise
        bot_id = integration_context.get('bot_id')
        if not bot_id:
            bot_id = get_bot_id()
            integration_context['bot_id'] = bot_id
        invite_user_to_conversation(destinations, bot_id)
        for destination in destinations:
            if thread_id:
                response = CLIENT.files_upload(channels=destination,
                                               content=file['data'], filename=file['name'],
                                               initial_comment=file['comment'], thread_ts=thread_id)
            else:
                response = CLIENT.files_upload(channels=destination,
                                               content=file['data'], filename=file['name'],
                                               initial_comment=file['comment'])
    return response


def slack_send_request(to, channel, group, entry=None, severity=MAX_SEVERITY, ignore_add_url=None, thread_id=None,
                       message=None, file=None):
    if not (to or group or channel):
        return_error('Either a user, group or channel must be provided')

    integration_context = demisto.getIntegrationContext()
    conversations = []
    users = []

    if integration_context:
        if 'conversations' in integration_context:
            conversations = json.loads(integration_context['conversations'])
        if 'users' in integration_context:
            users = json.loads(integration_context['users'])
    destinations = []

    if channel == 'incidentNotificationChannel':
        if severity >= SEVERITY_THRESHOLD:
            channel = DEDICATED_CHANNEL
        else:
            channel = ''

    if to:
        if isinstance(to, list):
            to = to[0]
        user = list(filter(lambda u: u.get('name') == to or u.get('profile', {}).get('email') == to, users))
        if not user:
            user = get_user(to)
            if not user:
                demisto.error('Could not find the Slack user')
            else:
                users.append(user)
                integration_context['users'] = json.dumps(users)
        else:
            user = user[0]
        if user:
            im = CLIENT.im_open(user=user.get('id'))
            destinations.append(im.get('channel', {}).get('id'))
    if channel or group:
        destination_name = channel or group
        conversation = list(filter(lambda c: c.get('name') == destination_name, conversations))
        if not conversation:
            conversation = get_conversation(destination_name)
            if not conversation:
                return_error('Could not find the Slack conversation')
            conversations.append(conversation)
            integration_context['conversations'] = json.dumps(conversations)
        else:
            conversation = conversation[0]
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
    investigation = demisto.investigation()
    if investigation.get('type') == PLAYGROUND_INVESTIGATION_TYPE:
        return_error('Can not perform this action in playground.')

    integration_context = demisto.getIntegrationContext()
    if not integration_context or not integration_context.get('mirrors', []):
        return_error('No mirrors found.')

    mirrors = json.loads(integration_context['mirrors'])
    mirror = list(filter(lambda m: m['investigation_id'] == investigation.get('id'), mirrors))
    if not mirror:
        return_error('Could not find the mirrored Slack conversation.')

    mirror = mirror[0]
    conversation_id = mirror['channel_id']

    CHANNEL_CLIENT.conversations_archive(channel=conversation_id)

    demisto.results('Channel successfully archived')


def add_entry_test():
    data = {
        "type": "message",
        "channel": "GK911K64W",
        "user": "U2147483697",
        "text": "Hello world",
        "ts": "1355517523.000005"
    }
    text = data.get('text')

    integration_context = demisto.getIntegrationContext()

    if not integration_context or 'mirrors' not in integration_context:
        return
    mirrors = json.loads(integration_context['mirrors'])
    channel_name = CLIENT.conversations_info(channel=data.get('channel')).get('channel', {})
    investigation = mirrors.get(channel_name.get('name'), '')
    if not investigation:
        return

    if not investigation['mirrored']:
        demisto.mirrorInvestigation(investigation['investigation_id'], investigation['mirror_type'],
                                    investigation['auto_close'])
        investigation['mirrored'] = True
        mirrors[channel_name] = investigation
        demisto.setIntegrationContext({'mirrors': json.dumps(mirrors)})

    if text:
        demisto.addEntry(id=investigation['investigation_id'], entry=text)


def long_running_main():
    asyncio.run(start_listening())


def main():
    """
    Main
    """
    commands = {
        'test-module': test_module,
        'long-running-execution': long_running_main,
        'slack-mirror-investigation': mirror_investigation,
        'slack-clear-mirrors': clear_mirrors,
        'slack-send': slack_send,
        'slack-send-file': slack_send_file,
        'slack-close-channel': close_channel,
        'add_entry': add_entry_test
    }

    try:
        command_func = commands[demisto.command()]
        command_func()
    except Exception as e:
        raise
        LOG(str(e))
        LOG.print_log(False)
        return_error(str(e))


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
