import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import dateparser

DATE_FORMAT = '%Y-%m-%d %H:%M:%S'


def parse_option_text(option):
    parts = option.split("#", 1)
    if len(parts) == 2:
        text, color = parts
        if color not in ['red', 'green', 'blue']:
            raise DemistoException(f"The option: {option} has invalid color: {color}, the color options are red, green, blue.")
        style = color
    else:
        text = option
        style = None
    return text, style


def create_adaptive_card(message, user_options, response_type):
    select_buttons = []
    for _i, option in enumerate(user_options):
        option_text, option_style = parse_option_text(option)
        if response_type == 'button':
            select_button = {
                "text": option_text,
                "color": {
                    "red": "1" if option_style == "red" else "0",
                    "green": "1" if option_style == "green" else "0",
                    "blue": "1" if option_style == "blue" else "0",
                },
                "onClick": {
                    "action": {
                        "function": option_text}}
            }
        else:
            select_button = {
                "text": option_text,
                "value": option_text
            }
        select_buttons.append(select_button)
    card = {
        "cardId": "survey-card",
        "card": {
            "header": {
                "title": "Feedback request",
                "subtitle": message
            },
            "sections": [
                {
                    "header": "Choose one option:",
                    "collapsible": "false",
                    "uncollapsibleWidgetsCount": 1,
                    "widgets": [
                        {
                            "selectionInput": {
                                "name": "survey",
                                "label": "",
                                "type": 'RADIO_BUTTON' if response_type == 'button' else 'DROPDOWN'
                            }
                        }
                    ]
                }
            ]
        }
    }
    if response_type == 'button':
        card["card"]["sections"][0]["widgets"].append({"buttonList": {"buttons": select_buttons}})
    else:
        card["card"]["sections"][0]["widgets"][0]["selectionInput"]["items"] = select_buttons
        card["card"]["sections"][0]["widgets"].append({"buttonList": {"buttons": [
            {
                "text": "Submit",
                "onClick": {
                    "action": {
                        "function": "handleSurveyResponse",
                        "parameters": [
                            {
                                "key": "response",
                                "value": "${survey}"
                            }
                        ]
                    }
                }
            }
        ]}})
    return card


def main():
    demisto_args = demisto.args()
    res = demisto.executeCommand('addEntitlement', {'persistent': demisto_args.get('persistent')})
    if isError(res[0]):  # type: ignore
        return_results(res)
    entitlement = demisto.get(res[0], 'Contents')  # type: ignore
    option1 = demisto_args.get('option1')
    option2 = demisto_args.get('option2')
    message = demisto_args.get('message')
    default_reply = demisto_args.get('default_reply', parse_option_text(option1)[0])
    reply = demisto.args().get('reply')
    response_type = demisto_args.get('response_type', 'buttons')
    additional_options = argToList(demisto_args.get('additional_options', ''))
    lifetime = demisto_args.get('lifetime', '1 day')
    try:
        parsed_date = dateparser.parse('in ' + lifetime, settings={'TIMEZONE': 'UTC'})
        assert parsed_date is not None, (f'Could not parse in {lifetime}, please use the format: X day(s) or X month(s) or '
                                         'X hour(s) etc...')
        expiry = datetime.strftime(parsed_date,
                                   DATE_FORMAT)
    except Exception:
        parsed_date = dateparser.parse('in 1 day', settings={'TIMEZONE': 'UTC'})
        assert parsed_date is not None
        expiry = datetime.strftime(parsed_date,
                                   DATE_FORMAT)

    formatted_entitlement = entitlement + '@' + demisto.investigation()['id']  # type: ignore
    if demisto_args.get('task_id'):
        formatted_entitlement += '|' + demisto_args.get('task_id')  # type: ignore
    args = {}

    user_options = [option1, option2]
    if additional_options:
        user_options += additional_options
    adaptive_card = create_adaptive_card(message, user_options, response_type)
    args = {
        'entitlement': formatted_entitlement,
        'expiry': expiry,
        'adaptive_card': adaptive_card,
        'default_response': default_reply,
        'message': 'no_message',
        'reply': reply
    }
    user = demisto_args.get('user')
    space_id = demisto_args.get('space_id')

    if space_id:
        args['space_id'] = space_id
    else:
        return_error('A space_id must be specified')
    if user:
        args['to'] = user
    try:
        return_results(demisto.executeCommand('send-notification', args))
    except ValueError as e:
        if 'Unsupported Command' in str(e):
            return_error(f'The command is unsupported by this script. {e}')
        else:
            return_error('An error has occurred while executing the send-notification command',
                         error=e)  # type: ignore


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
