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


def send_slack_message(entitlement, task, user_id, message):
    lifetime = '1 day'
    expiry_date = dateparser.parse('in ' + lifetime, settings={'TIMEZONE': 'UTC'})
    expiry = datetime.strftime(expiry_date, DATE_FORMAT) if expiry_date else None

    entitlement_string = f'{entitlement}@{demisto.investigation().get("id")}'
    if task:
        entitlement_string += f'|{task}'

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

    if user_id:
        send_notification_args['to'] = user_id
        demisto.results(demisto.executeCommand('send-notification', send_notification_args))
    else:
        raise Exception('A user must be provided.')


def send_ms_teams_message(entitlement, task, user_id, message):
    investigation_id: str = demisto.investigation()['id']

    adaptive_card: dict = {
        'contentType': 'application/vnd.microsoft.card.adaptive',
        'content': {
            '$schema': 'http://adaptivecards.io/schemas/adaptive-card.json',
            'version': '1.0',
            'type': 'AdaptiveCard',
            'msteams': {
                'width': 'Full'
            },
            'body': [
                {
                    'type': 'TextBlock',
                    'text': message,
                    'wrap': True
                }
            ],
            'actions': [
                {
                    'type': 'Action.Submit',
                    'title': 'Yes',
                    'data': {
                        'response': 'Yes',
                        'entitlement': entitlement,
                        'investigation_id': investigation_id,
                        'task_id': task
                    }
                },
                {
                    'type': 'Action.Submit',
                    'title': 'No',
                    'data': {
                        'response': 'No',
                        'entitlement': entitlement,
                        'investigation_id': investigation_id,
                        'task_id': task
                    }
                }
            ]
        }
    }

    command_arguments: dict = {
        'adaptive_card': json.dumps(adaptive_card),
        'using-brand': 'Microsoft Teams'
    }

    if user_id:
        command_arguments['team_member'] = user_id
        demisto.results(demisto.executeCommand('send-notification', command_arguments))
    else:
        raise Exception('A user must be provided.')


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
    task = args.get('task')
    user_id = demisto.get(args, 'user_id')
    messenger = args.get('messenger')

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

    try:
        if messenger.upper() == 'SLACK':
            send_slack_message(entitlement, task, user_id, message)
        else:
            send_ms_teams_message(entitlement, task, user_id, message)
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
