import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

STYLES_DICT = {
    'black': 'default',
    'green': 'primary',
    'red': 'danger'
}


def create_blocks(text, option1, option2, entitlement):
    return [{
        'type': 'section',
        'text': {
            'type': 'mrkdwn',
            'text': text
        }
    }, {
        'type': 'actions',
        'elements': [{
            'type': 'button',
            'text': {
                'type': 'plain_text',
                'emoji': True,
                'text': option1['text']
            },
            'style': option1['style'],
            'value': entitlement
        }, {
            'type': 'button',
            'text': {
                'type': 'plain_text',
                'emoji': True,
                'text': option2['text']
            },
            'style': option2['style'],
            'value': entitlement
        }]}]


def main():
    res = demisto.executeCommand('addEntitlement', {'persistent': demisto.get(demisto.args(), 'persistent'),
                                                    'replyEntriesTag': demisto.get(demisto.args(), 'replyEntriesTag')})
    if isError(res[0]):
        demisto.results(res)
        sys.exit(0)
    entitlement = demisto.get(res[0], 'Contents')
    option1 = demisto.get(demisto.args(), 'option1')
    if not option1:
        option1 = 'yes'
    option1_style = demisto.args().get('option1Style', 'black')
    option2 = demisto.get(demisto.args(), 'option2')
    if not option2:
        option2 = 'no'
    option2_style = demisto.args().get('option2Style', 'black')
    entitlement_string = entitlement + '@' + demisto.investigation()['id']
    if demisto.get(demisto.args(), 'task'):
        entitlement_string += '|' + demisto.get(demisto.args(), 'task')
    response_type = demisto.args().get('responseType')

    args = {
        'ignoreAddURL': 'true'
    }

    if response_type == 'thread':
        message = '%s - Please reply to this thread with `%s` or `%s`' % (demisto.args()['message'], option1, option2)
        args['message'] = json.dumps({
            'message': message,
            'entitlement': entitlement_string
        })
    else:
        option1 = {
            'text': option1,
            'style': STYLES_DICT.get(option1_style)
        }
        option2 = {
            'text': option2,
            'style': STYLES_DICT.get(option2_style)
        }
        blocks = json.dumps(create_blocks(demisto.args()['message'], option1, option2, entitlement_string))
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


if __name__ in ('__builtin__', '__main__'):
    main()
