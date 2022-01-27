import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from string import Template

import dateparser

DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

FILE_INFO = Template("Your upload *$file_name* was blocked due to company policy.")
POLICY_INFO = Template("Policy *$policy_name*")
OPTIONS = [
    {
        'text': 'A',
        'style': 'primary'
    },
    {
        'text': 'B',
        'style': 'primary'
    },
    {
        'text': 'C',
        'style': 'primary'
    }
]


def create_blocks(fileName: str, policyName: str, entitlement: str, options: list, reply: str) -> list:
    value = json.dumps({
        'entitlement': entitlement,
        'reply': reply
    })
    blocks: list = [{
        'type': 'section',
        'text': {
                'type': 'mrkdwn',
                'text': FILE_INFO.substitute(file_name=fileName)
        }
    }, {
        'type': 'section',
        'text': {
                'type': 'mrkdwn',
                'text': POLICY_INFO.substitute(policy_name=policyName)
        }
    }, {
        "type": "section",
        "text": {
                "type": "mrkdwn",
                "text": "*Provide justification for your action*"
        }
    }, {
        "type": "section",
        "text": {
                "type": "mrkdwn",
                "text": "*A.* This file does not contain sensitive information"
        }
    }, {
        "type": "section",
        "text": {
                "type": "mrkdwn",
                "text": "*B.* This file contains sensitive information, but I am authorized to send it for business purposes"
        }
    }, {
        "type": "section",
        "text": {
                "type": "mrkdwn",
                "text": "*C.* The file contains sensitive information and I am not authorized to send it"
        }
    }
    ]

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

    lifetime = '1 day'
    try:
        expiry = datetime.strftime(dateparser.parse('in ' + lifetime, settings={'TIMEZONE': 'UTC'}),
                                   DATE_FORMAT)
    except Exception:
        expiry = datetime.strftime(dateparser.parse('in 1 day', settings={'TIMEZONE': 'UTC'}),
                                   DATE_FORMAT)

    entitlement_string = entitlement + '@' + demisto.investigation()['id']
    if demisto.get(demisto.args(), 'task'):
        entitlement_string += '|' + demisto.get(demisto.args(), 'task')

    args = {
        'ignoreAddURL': 'true',
        'using-brand': 'SlackV2'
    }

    blocks = json.dumps(create_blocks('dummy_file.doc', 'dummy policy', entitlement_string, OPTIONS, None))
    args['blocks'] = json.dumps({
        'blocks': blocks,
        'entitlement': entitlement_string,
        'expiry': expiry,
        'default_response': 'NoResponse'
    })

    to = demisto.get(demisto.args(), 'user')

    if to:
        args['to'] = to
    else:
        return_error('A user must be provided.')

    try:
        demisto.results(demisto.executeCommand('send-notification', args))
    except ValueError as e:
        if 'Unsupported Command' in str(e):
            return_error(
                'The command is unsupported by any integration instance. If you have SlackV3 or above enabled, '
                'please use SlackAskV2 instead.')
        else:
            return_error('An error has occurred while executing the send-notification command',
                         error=e)


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
