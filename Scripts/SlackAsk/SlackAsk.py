import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

STYLES_DICT = {
    'black': '',
    'green': 'primary',
    'red': 'danger'
}


def create_blocks(text: str, entitlement: str, options: list) -> list:
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
            'value': entitlement
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
    entitlement_string = entitlement + '@' + demisto.investigation()['id']
    if demisto.get(demisto.args(), 'task'):
        entitlement_string += '|' + demisto.get(demisto.args(), 'task')
    response_type = demisto.args().get('responseType')

    args = {
        'ignoreAddURL': 'true'
    }
    user_options = [option1, option2]
    options = []
    if extra_options:
        user_options += extra_options
    if response_type == 'thread':
        for option in user_options:
            options.append(option.split(';')[0])
        string_options = ' or '.join(list(map(lambda o: '`{}`'.format(o), options)))
        message = '{} - Please reply to this thread with {}'.format(demisto.args()['message'], string_options)
        args['message'] = json.dumps({
            'message': message,
            'entitlement': entitlement_string
        })
    else:
        for option in user_options:
            option = option.split(';')
            button = {
                'text': option[0]
            }
            if len(option) > 1:
                style = STYLES_DICT.get(option[1])
                if style:
                    button['style'] = style
            options.append(button)
        blocks = json.dumps(create_blocks(demisto.args()['message'], entitlement_string, options))
        args['blocks'] = json.dumps({
            'blocks': blocks,
            'entitlement': entitlement_string
        })

    to = demisto.get(demisto.args(), 'user')
    channel = demisto.get(demisto.args(), 'channel')

    if to:
        args['to'] = to
    elif channel:
        args['channel'] = channel
    else:
        return_error('Either a user or a channel must be provided.')

    demisto.results(demisto.executeCommand('send-notification', args))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
