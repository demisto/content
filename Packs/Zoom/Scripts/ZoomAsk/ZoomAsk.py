import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import dateparser

STYLES_DICT = {
    'white': 'Default',
    'blue': 'Primary',
    'red': 'Danger',
    'gray': 'Disabled',
}

DATE_FORMAT = '%Y-%m-%d %H:%M:%S'


def parse_option_text(option_text):
    # Function to parse the option text with color information and extract the text and style
    # Format of the option text: "<text>#<color>"
    parts = option_text.split("#", 1)
    if len(parts) == 2:
        text, color = parts
        style = STYLES_DICT.get(color.lower(), 'Default')
    else:
        text = option_text
        style = 'Default'
    return text, style


def generate_json(text, options, response_type):
    if response_type == "button":
        # Generate JSON for button type response
        button_items = []
        for _i, option in enumerate(options):
            option_text, option_style = parse_option_text(option)
            button_item = {
                "value": option_text,
                "style": option_style,
                "text": option_text
            }
            button_items.append(button_item)

        json_data = {
            "head": {
                "type": "message",
                "text": text
            },
            "body": [
                {
                    "type": "actions",
                    "items": button_items
                }
            ]
        }

    elif response_type == "dropdown":
        # Generate JSON for dropdown type response
        select_items = []
        for _i, option in enumerate(options):
            option_text, _ = parse_option_text(option)
            select_item = {
                "value": option_text,
                "text": option_text
            }
            select_items.append(select_item)

        json_data = {
            "body": [
                {
                    "select_items": select_items,
                    "text": text,
                    "selected_item": {
                        "value": select_items[0].get('value')
                    },
                    "type": "select"
                }
            ]
        }

    else:
        raise ValueError("Invalid responseType. should be 'button' or 'dropdown'.")
    return json_data


def main():
    demisto_args = demisto.args()
    res = demisto.executeCommand('addEntitlement', {'persistent': demisto_args.get('persistent')})
    if isError(res[0]):
        return_results(res)
    entitlement = demisto.get(res[0], 'Contents')
    option1 = demisto_args.get('option1')
    option2 = demisto_args.get('option2')
    extra_options = argToList(demisto_args.get('additionalOptions', ''))
    reply = demisto_args.get('reply')
    response_type = demisto_args.get('responseType', 'buttons')
    lifetime = demisto_args.get('lifetime', '1 day')
    try:
        parsed_date = dateparser.parse('in ' + lifetime, settings={'TIMEZONE': 'UTC'})
        assert parsed_date is not None, f'Could not parse in {lifetime}'
        expiry = datetime.strftime(parsed_date,
                                   DATE_FORMAT)
    except Exception:
        parsed_date = dateparser.parse('in 1 day', settings={'TIMEZONE': 'UTC'})
        assert parsed_date is not None
        expiry = datetime.strftime(parsed_date,
                                   DATE_FORMAT)
    default_response = demisto_args.get('defaultResponse')

    entitlement_string = entitlement + '@' + demisto.investigation()['id']
    if demisto_args.get('task'):
        entitlement_string += '|' + demisto_args.get('task')

    args = {
        'ignoreAddURL': 'true',
        'using-brand': 'Zoom'
    }

    user_options = [option1, option2]
    if extra_options:
        user_options += extra_options
    blocks = json.dumps(generate_json(demisto.args()['message'], user_options, response_type))
    args['message'] = json.dumps({
        'blocks': blocks,
        'entitlement': entitlement_string,
        'reply': reply,
        'expiry': expiry,
        'default_response': default_response
    })
    to = demisto_args.get('user')
    channel_name = demisto_args.get('channel_name')
    channel = demisto_args.get('channel_id')

    if to:
        args['to'] = to
    elif channel:
        args['channel_id'] = channel
    elif channel_name:
        args['channel'] = channel_name
    else:
        return_error('Either a user or a channel_id or channel_name must be specified')

    args['zoom_ask'] = 'true'
    try:
        return_results(demisto.executeCommand('send-notification', args))
    except ValueError as e:
        if 'Unsupported Command' in str(e):
            return_error(f'The command is unsupported by this script. {e}')
        else:
            return_error('An error has occurred while executing the send-notification command',
                         error=e)


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
