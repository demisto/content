from slack.web.slack_response import SlackResponse

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from distutils.util import strtobool
import slack
from slack.errors import SlackApiError
from timeit import default_timer as timer

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
DEDICATED_CHANNEL = demisto.params()['channel']
LINK_FOOTER = demisto.params().get('footer')
GENERAL_FOOTER = demisto.params().get('general_footer')
CLIENT = slack.WebClient(token=TOKEN, proxy=PROXY)
SEVERITY_THRESHOLD = demisto.args().get('min_severity', 1)
RTM_CLIENT = slack.RTMClient(token=TOKEN)


''' HELPER FUNCTIONS '''


def get_bot_id():
    """
    Gets the app bot ID
    :return: The app bot ID
    """
    response = CLIENT.auth_test()

    return response.get('user_id')


def get_slack_name(slack_id: str) -> str:
    """
    Get the slack name of a provided object by its ID
    :param slack_id: The slack object ID
    :return: The slack object name
    """
    if not slack_id:
        return ''

    integration_context = demisto.getIntegrationContext()
    prefix = slack_id[0]

    if prefix in ['C', 'D', 'G']:
        slack_id = slack_id.split('|')[0]
        conversation = ''
        if integration_context.get('conversations'):
            conversations = json.loads(integration_context['conversations'])
            conversation = list(filter(lambda c: c['id'] == slack_id, conversations))
            if conversation:
                conversation = conversation[0]
        if not conversation:
            conversation = CLIENT.conversations_info(channel=slack_id).get('channel', {})
        return conversation.get('name', '')
    if prefix == 'U':
        user = ''
        if integration_context.get('users'):
            users = json.loads(integration_context['users'])
            user = list(filter(lambda u: u['id'] == slack_id, users))
            if user:
                user = user[0]
        if not user:
            user = CLIENT.users_info(user=slack_id).get('user', {})
        return user.get('name', '')

    return ''


def transform_expression(match):
    """
    Transforms a regex match for a slack ID to a slack name
    :param match:
    :return:
    """
    return get_slack_name(match.group(1))


def clean_message(message: str):
    """
    Prettifies a slack message - replaces tags and URLs with clean expressions
    :param message: The slack message
    :return: The clean slack message
    """
    resolved_message = re.sub(USER_TAG_EXPRESSION, transform_expression, message)
    resolved_message = re.sub(CHANNEL_TAG_EXPRESSION, transform_expression, resolved_message)
    resolved_message = re.sub(URL_EXPRESSION, r'\1', resolved_message)

    return resolved_message


def get_user(user_name):
    """
    Gets a slack user object by a user name
    :param user_name: The user name
    :return: A slack user object
    """
    response = CLIENT.users_list()

    users = response['members'] if response and response.get('members', []) else []
    if not users:
        return return_error('Could not retrieve users')

    user = list(filter(lambda u: u.get('name') == user_name, users))

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


def invite_user_to_conversation(channel_client, conversation_id, users_to_invite):
    """
    Invites users to a provided conversation using a provided slack client with a channel token.
    :param channel_client: Slack client with a channel token.
    :param conversation_id: The slack conversation ID to invite the users to.
    :param users_to_invite: The user slack IDs to invite.
    """
    for user in users_to_invite:
        try:
            channel_client.conversations_invite(channel=conversation_id, users=user)
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
    demisto.setIntegrationContext({'mirrors': {}})

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
    channel_client = slack.WebClient(token=CHANNEL_TOKEN, proxy=PROXY)
    if not mirror:
        if mirror_to == 'channel':
            conversation = channel_client.channels_create(name='incident-{}'
                                                          .format(investigation_id)).get('channel', {})
            conversation_id = conversation.get('id')
        else:
            conversation = channel_client.groups_create(name='incident-{}'
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
    invite_user_to_conversation(channel_client, conversation_id, users_to_invite)

    integration_context['bot_id'] = bot_id
    integration_context['mirrors'] = json.dumps(mirrors)
    integration_context['conversations'] = json.dumps(conversations)

    demisto.setIntegrationContext(integration_context)

    demisto.results('Investigation mirrored successfully')


def start_rtm():
    """
    Starts a Slack RTM client - runs in a long running container
    """
    RTM_CLIENT.start()


@slack.RTMClient.run_on(event='message')
def listen(**payload):
    """
    Listens to Slack RTM messages
    :param payload: The message payload
    """
    start = timer()
    data = payload.get('data')
    demisto.info(data.get('text'))
    data_type = payload.get('type')
    if data_type == 'error':
        error = payload.get('error', {})
        demisto.updateModuleHealth('Slack API has thrown an error. Code: {}, Message: {}. Trying to restart.'
                                   .format(error.get('code'), error.get('msg')))
        RTM_CLIENT.stop()
        RTM_CLIENT.start()
        return
    try:
        text = data.get('text', '')
        user_id = data.get('user')

        integration_context = demisto.getIntegrationContext()
        if not integration_context or 'mirrors' not in integration_context:
            return

        if integration_context.get('bot_id'):
            bot_id = integration_context['bot_id']
        else:
            bot_id = get_bot_id()
        if user_id == bot_id:
            return

        channel_id = data.get('channel')
        mirrors = json.loads(integration_context['mirrors'])
        investigation = list(filter(lambda m: m['channel_id'] == channel_id, mirrors))
        if not investigation:
            return
        else:
            investigation = investigation[0]

        if investigation['mirror_direction'] == 'FromDemisto':
            return

        if not investigation['mirrored']:
            demisto.mirrorInvestigation(investigation['investigation_id'], investigation['mirror_type'],
                                        bool(strtobool(investigation['auto_close'])))
            investigation['mirrored'] = True
        if text:
            user = ''
            if integration_context.get('users'):
                users = json.loads(integration_context['users'])
                user = list(filter(lambda u: u['id'] == user_id, users))
                if user:
                    user = user[0]
            else:
                users = []
            if not user:
                user = CLIENT.users_info(user=user_id).get('user', {})
                users.append(user)

            demisto.addEntry(id=investigation['investigation_id'],
                             entry=clean_message(text), username=user.get('name', ''),
                             email=user.get('profile', {}).get('email', ''), footer='\n**From Slack**')
            # TODO: do we want to set context if we don't have text?
            demisto.setIntegrationContext({'mirrors': json.dumps(mirrors),
                                           'bot_id': bot_id, 'users': json.dumps(users)})
        # Reset module health
        demisto.updateModuleHealth("")
        end = timer()
        demisto.info('############# time: ' + str(end - start))
    except Exception as e:
        demisto.info("Error occurred while listening to Slack: {}".format(str(e)))


''' SEND '''


def slack_send():
    message = demisto.args().get('message')
    to = demisto.args().get('to')
    channel = demisto.args().get('channel')
    group = demisto.args().get('group')
    entry = demisto.args().get('entry')
    ignore_add_url = demisto.args().get('ignoreAddURL', 'false')
    thread_id = demisto.args().get('threadID')

    destination = to or channel or group
    if not destination:
        return_error('Missing destination (channel, group or to) argument')
    if message:
        message += '\n'

    demisto.info('ignore: ' + str(ignore_add_url))
    if not bool(strtobool(ignore_add_url)) and LINK_FOOTER:
        investigation = demisto.investigation()
        links = demisto.demistoUrls()
        if investigation.get('type') != PLAYGROUND_INVESTIGATION_TYPE:
            link = links.get('warRoom')
            if link:
                if entry:
                    link += '/' + entry
                message += '\n{} {}'.format(LINK_FOOTER, link)
        elif GENERAL_FOOTER:
            link = links.get('server', '')
            if link:
                message += '\n{} {}'.format(GENERAL_FOOTER, link + '#/home')

    incidents = demisto.incidents()
    if incidents:
        incident = incidents[0]
        try:
            severity = int(incident.get('severity'), 4)
        except Exception:
            severity = 4
    else:
        severity = 4

    if severity > SEVERITY_THRESHOLD:
        if thread_id:
            response: SlackResponse = CLIENT.chat_postMessage(channel=destination, text=message, thread_ts=thread_id)
        else:
            response: SlackResponse = CLIENT.chat_postMessage(channel=destination, text=message)

        thread = response.get('ts')

        demisto.results('Message sent to Slack successfully.\nThread ID is: {}'.format(thread))


def close_channel():
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

    channel_client = slack.WebClient(token=CHANNEL_TOKEN)
    channel_client.conversations_archive(channel=conversation_id)

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


def main():
    """
    Main
    """
    commands = {
        'test-module': test_module,
        'long-running-execution': start_rtm,
        'slack-mirror-investigation': mirror_investigation,
        'slack-clear-mirrors': clear_mirrors,
        'slack-send': slack_send,
        'slack-close-channel': close_channel,
        'add_entry': add_entry_test
    }

    command_func = commands[demisto.command()]
    command_func()


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
