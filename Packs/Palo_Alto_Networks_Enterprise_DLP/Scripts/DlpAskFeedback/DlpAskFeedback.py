import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import dateparser

DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

OPTIONS = [
    {
        'text': 'Yes',
        'style': 'primary'
    },
    {
        'text': 'No',
        'style': 'primary'
    }
]


def create_blocks(message: str, entitlement: str, reply: str) -> list:
    value = json.dumps({
        'entitlement': entitlement,
        'reply': reply
    })
    blocks: list = [{
        'type': 'section',
        'text': {
                'type': 'mrkdwn',
                'text': message
        }
    }
    ]

    elements = []
    for option in OPTIONS:
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

    actions = {
        'type': 'actions',
        'elements': elements
    }
    blocks.append(actions)

    return blocks


def main():
    args = demisto.args()
    res = demisto.executeCommand('addEntitlement', {'persistent': demisto.get(args, 'persistent'),
                                                    'replyEntriesTag': demisto.get(args, 'replyEntriesTag')})
    if isError(res[0]):
        demisto.results(res)
        sys.exit(0)
    entitlement = demisto.get(res[0], 'Contents')

    file_name = args.get('file_name')
    data_profile_name = args.get('data_profile_name')
    snippets = args.get('snippets', '')
    app_name = args.get('app_name', 'Unknown App')
    user_display_name = args.get('user_display_name')
    question_type = args.get('question_type')
    include_violation_detail = args.get('include_violation_detail')

    message = ''
    if include_violation_detail == 'True':
        res = demisto.executeCommand('pan-dlp-slack-message',
                                     {
                                         'user': user_display_name,
                                         'file_name': file_name,
                                         'data_profile_name': data_profile_name,
                                         'app_name': app_name,
                                         'snippets': snippets
                                     })
        if isError(res[0]):
            demisto.results(res)
            sys.exit(0)
        demisto.info(f'DLPAskFeedback - received slack message {json.dumps(res)}')
        message = demisto.get(res[0], 'Contents.message')
        message = message.encode('latin-1', 'backslashreplace').decode('unicode-escape')
        message += '\n\n'

    if question_type == 'ABOUT_EXEMPTION':
        message += f'Do you want to request a temporary exemption for {file_name}?'
    else:
        message += 'Please confirm if this file contains sensitive information:'

    lifetime = '1 day'
    expiry_date = dateparser.parse('in ' + lifetime, settings={'TIMEZONE': 'UTC'})
    if expiry_date:
        expiry = datetime.strftime(expiry_date, DATE_FORMAT)

    entitlement_string = f'{entitlement}@{demisto.investigation().get("id")}'
    if demisto.get(args, 'task'):
        entitlement_string += f'|{demisto.get(args, "task")}'

    send_notification_args = {
        'ignoreAddURL': 'true',
        'using-brand': 'SlackV3'
    }

    reply = "Thank you for your response."
    blocks = json.dumps(create_blocks(message, entitlement_string, reply))
    send_notification_args['blocks'] = json.dumps({
        'blocks': blocks,
        'entitlement': entitlement_string,
        'reply': reply,
        'expiry': expiry,
        'default_response': 'NoResponse'
    })

    to = demisto.get(args, 'user_id')

    if to:
        send_notification_args['to'] = to
    else:
        return_error('A user must be provided.')

    try:
        demisto.results(demisto.executeCommand('send-notification', send_notification_args))
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
