import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import dateparser

DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

def parse_option_text(option):
    parts = option.split("#", 1)
    if len(parts) == 2:
        text, color = parts
        #TODO
    else:
        text = option
        style = None
    return text, style

def create_adaptive_card(message, user_options, response_type):
    select_buttons = []
    for _i, option in enumerate(user_options):
        option_text, option_style = parse_option_text(option)
        select_button = {
            "text": option_text,
            "onClick": {
                "action":{
                    "function": option_text}}
        }
        select_buttons.append(select_button)
    return {
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
                            "name": "a",
                            "label": "a",
                            "type": 'RADIO_BUTTON' if response_type == 'button' else 'DROPDOWN'
                        }
                    },
                    {
                        "buttonList": {
                            "buttons": select_buttons
                        }
                    }
                ]
            }
        ]
    }
}


def main():
    demisto_args = demisto.args()
    res = demisto.executeCommand('addEntitlement', {'persistent': demisto_args.get('persistent')})
    if isError(res[0]): # type: ignore
        return_results(res)
    entitlement = demisto.get(res[0], 'Contents') # type: ignore
    option1 = demisto_args.get('option1')
    option2 = demisto_args.get('option2')
    message = demisto_args.get('message')
    default_reply = demisto_args.get('default_reply', option1)
    response_type = demisto_args.get('response_type', 'buttons')
    additional_options = argToList(demisto_args.get('additional_options', ''))
    lifetime = demisto_args.get('lifetime', '1 day')
    try:
        parsed_date = dateparser.parse('in ' + lifetime, settings={'TIMEZONE': 'UTC'})
        assert parsed_date is not None, f'Could not parse in {lifetime}, please use the format: X day(s) or X month(s) or X hour(s) etc...'
        expiry = datetime.strftime(parsed_date,
                                   DATE_FORMAT)
    except Exception:
        parsed_date = dateparser.parse('in 1 day', settings={'TIMEZONE': 'UTC'})
        assert parsed_date is not None
        expiry = datetime.strftime(parsed_date,
                                   DATE_FORMAT)

    formatted_entitlement = entitlement + '@' + demisto.investigation()['id'] # type: ignore
    if demisto_args.get('task'):
        formatted_entitlement += '|' + demisto_args.get('task') # type: ignore

    # args = {
    #     'ignoreAddURL': 'true',
    # }
    args = {}

    user_options = [option1, option2]
    if additional_options:
        user_options += additional_options
    adaptive_card = create_adaptive_card(message, user_options, response_type)
    args = {
        'entitlement': formatted_entitlement,
        'expiry': expiry,
        'adaptive_card': adaptive_card,
        'default_reply': default_reply,
        'message': 'no_message'
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
                         error=e) # type: ignore


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
