import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import slack


TOKEN = demisto.params()['bot_token']
CHANNEL_TOKEN = demisto.params()['channel_token']

if not demisto.params().get('proxy', False):
    del os.environ['HTTPS_PROXY']
    del os.environ['https_proxy']
    PROXY = None
else:
    PROXY = os.environ['https_proxy'] or os.environ['HTTPS_PROXY']

DEDICATED_CHANNEL = demisto.params()['channel']
CLIENT = slack.WebClient(token=TOKEN, proxy=PROXY)
RTM_CLIENT = slack.RTMClient(token=TOKEN)


def get_bot_id():
    response = CLIENT.auth_test()

    return response.get('user_id')


def get_conversation(conversation_name):
    response = CLIENT.conversations_list(types='private_channel,public_channel')

    conversations = response['channels'] if response and response.get('channels') else []

    if not conversations:
        return return_error('Could not retrieve conversations')
    else:
        conversation = list(filter(lambda c: c.get('name') == conversation_name, conversations))

        if not conversation:
            return []

        return conversation[0]


def send_message(message, destination, ignore_url, entry_id, thread_id):
    CLIENT.chat_postMessage(channel=destination, text=message)


def test_module():
    channel = get_conversation(DEDICATED_CHANNEL)
    if not channel:
        return_error('Dedicated channel not found')
    message = 'Hi there! This is a test message.'
    send_message(message, channel.get('id'))

    demisto.results('ok')


def clear_mirrors():
    demisto.setIntegrationContext({'mirrors': {}})

    demisto.results('Successfully cleared mirrors.')


def mirror_investigation():
    mirror_type = demisto.args().get('mirror_type', 'all')
    auto_close = demisto.args().get('auto_close', False)

    investigation = demisto.investigation()
    integration_context = demisto.getIntegrationContext()

    if not integration_context or not integration_context.get('mirrors', []):
        mirrors = []
    else:
        mirrors = json.loads(integration_context['mirrors'])

    investigation_id = investigation.get('id')
    investigation_group = list(filter(lambda m: m['investigation_id'] == investigation_id, mirrors))
    if not investigation_group or not investigation_group[0]:
        channel_client = slack.WebClient(token=CHANNEL_TOKEN, proxy=PROXY)
        investigation_group = channel_client.groups_create(name='investigation-{}'.format(investigation_id)).get('group', {})
        bot_id = get_bot_id()
        channel_client.conversations_invite(channel=investigation_group.get('id'), users=bot_id)
        mirrors.append({
            'channel_name': investigation_group.get('name'),
            'investigation_id': investigation.get('id'),
            'mirror_type': mirror_type,
            'auto_close': auto_close,
            'mirrored': False
        })

    demisto.setIntegrationContext({'mirrors': json.dumps(mirrors)})

    demisto.results('Investigation mirrored successfully')


def start_rtm():
    while True:
        RTM_CLIENT.start()


@slack.RTMClient.run_on(event='message')
def listen(**payload):
    data = payload.get('data')
    data_type = payload.get('type')
    if data_type == 'error':
        error = payload.get('error', {})
        demisto.updateModuleHealth('Slack API has thrown an error. Code: {}, Message: {}. Trying to restart.'
                                   .format(error.get('code'), error.get('msg')))
        RTM_CLIENT.stop()
        RTM_CLIENT.start()

    text = data.get('text', '')

    integration_context = demisto.getIntegrationContext()

    if not integration_context or 'mirrors' not in integration_context:
        return
    channel = CLIENT.conversations_info(channel=data.get('channel')).get('channel', {})
    if not channel:
        return

    channel_name = channel.get('name')
    mirrors = json.loads(integration_context['mirrors'])
    investigation = list(filter(lambda m: m['channel_name'] == channel_name, mirrors))
    if not investigation:
        return
    else:
        investigation = investigation[0]

    if not investigation['mirrored']:
        demisto.mirrorInvestigation(investigation['investigation_id'], investigation['mirror_type'], investigation['auto_close'])
        investigation['mirrored'] = True
        demisto.setIntegrationContext({'mirrors': json.dumps(mirrors)})

    if text:
        demisto.addEntry(id=investigation['investigation_id'], entry=text)


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
    commands = {
        'test-module': test_module,
        'long-running-execution': start_rtm,
        'slack-mirror-investigation': mirror_investigation,
        'slack-clear-mirrors': clear_mirrors,
        'add_entry': add_entry_test
    }

    command_func = commands[demisto.command()]
    command_func()


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()