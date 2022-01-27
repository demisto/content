import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import dateparser

STYLES_DICT = {
    'black': '',
    'green': 'primary',
    'red': 'danger'
}

DATE_FORMAT = '%Y-%m-%d %H:%M:%S'


def create_blocks(text: str, entitlement: str, options: list, reply: str) -> list:
    value = json.dumps({
        'entitlement': entitlement,
        'reply': reply
    })
    blocks: list = [{
        'type': 'section',
        'text': {
            'type': 'mrkdwn',
            'text': text
        }
    }]

    elements = []
    for option in options:
        element = {
            'type': 'button',
            'text': {
                'type': 'plain_text',
                'emoji': True,
                'text': option['text']
            },
            'value': value
        }
        if 'style' in option:
            element['style'] = option['style']
        elements.append(element)
    if elements:
        actions = {
            'type': 'actions',
            'elements': elements
        }
        blocks.append(actions)

    return blocks


def main():
    res = demisto.executeCommand('addEntitlement', {'persistent': demisto.get(demisto.args(), 'persistent'),
                                                    'replyEntriesTag': demisto.get(demisto.args(), 'replyEntriesTag')})
    if isError(res[0]):
        demisto.results(res)
        sys.exit(0)
    entitlement = demisto.get(res[0], 'Contents')
    option1 = demisto.get(demisto.args(), 'option1')
    option2 = demisto.get(demisto.args(), 'option2')
    extra_options = argToList(demisto.args().get('additionalOptions', ''))
    reply = demisto.get(demisto.args(), 'reply')
    response_type = demisto.get(demisto.args(), 'responseType')
    lifetime = demisto.get(demisto.args(), 'lifetime')
    slack_instance = demisto.get(demisto.args(), 'slackInstance')
    slack_version = demisto.args().get('slackVersion', 'SlackV3')
    try:
        expiry = datetime.strftime(dateparser.parse('in ' + lifetime, settings={'TIMEZONE': 'UTC'}),
                                   DATE_FORMAT)
    except Exception:
        expiry = datetime.strftime(dateparser.parse('in 1 day', settings={'TIMEZONE': 'UTC'}),
                                   DATE_FORMAT)
    default_response = demisto.get(demisto.args(), 'defaultResponse')

    entitlement_string = entitlement + '@' + demisto.investigation()['id']
    if demisto.get(demisto.args(), 'task'):
        entitlement_string += '|' + demisto.get(demisto.args(), 'task')

    args = {
        'ignoreAddURL': 'true',
        'using-brand': slack_version
    }
    if slack_instance:
        args.update({
            'using': slack_instance
        })
    user_options = [option1, option2]
    options = []
    if extra_options:
        user_options += extra_options
    if response_type == 'thread':
        for option in user_options:
            options.append(option.split('#')[0])
        string_options = ' or '.join(list(map(lambda o: '`{}`'.format(o), options)))
        message = '{} - Please reply to this thread with {}.'.format(demisto.args()['message'], string_options)
        args['message'] = json.dumps({
            'message': message,
            'entitlement': entitlement_string,
            'reply': reply,
            'expiry': expiry,
            'default_response': default_response
        })
    else:
        for option in user_options:
            option = option.split('#')
            button = {
                'text': option[0]
            }
            if len(option) > 1:
                style = STYLES_DICT.get(option[1])
                if style:
                    button['style'] = style
            options.append(button)
        blocks = json.dumps(create_blocks(demisto.args()['message'], entitlement_string, options, reply))
        args['blocks'] = json.dumps({
            'blocks': blocks,
            'entitlement': entitlement_string,
            'reply': reply,
            'expiry': expiry,
            'default_response': default_response
        })
        args['message'] = demisto.args()['message']

    to = demisto.get(demisto.args(), 'user')
    channel = demisto.get(demisto.args(), 'channel')
    channel_id = demisto.get(demisto.args(), 'channel_id')

    if to:
        args['to'] = to
    elif channel_id:
        args['channel_id'] = channel_id
    elif channel:
        args['channel'] = channel
    else:
        return_error('Either a user or a channel must be provided.')

    try:
        demisto.results(demisto.executeCommand('send-notification', args))
    except ValueError as e:
        if 'Unsupported Command' in str(e):
            return_error('The command is unsupported by this script. If you have SlackV2 enabled, '
                         'please use SlackAsk instead.')
        else:
            return_error('An error has occurred while executing the send-notification command',
                         error=e)


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
