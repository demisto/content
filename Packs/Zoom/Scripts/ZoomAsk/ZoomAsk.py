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


# def generate_message_json(text: str, options: list,):
#     # Create the JSON structure using Python dictionaries and lists
#     json_data = {
#         "head": {
#                 "type": "message",
#                 "text": text
#             },
#         "body": [
#                 {
#                     "type": "actions",
#                     "items": []
#                 }
#             ]
#     }
#     # Add the options to the "items" list in the JSON
#     for option_text in options:
#         item = {
#             "value": option_text.lower().replace(" ", "_"),  # Creating a simple value based on the text
#             "style": option_text['style'],  # Default style for all options (modify if needed)
#             "text": option_text['text']
#         }
#         json_data['content']['body'][0]['items'].append(item)

#     return json_data

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
        for i, option in enumerate(options):
            demisto.debug(f"option= {option}")
            option_text, option_style = parse_option_text(option)
            button_item = {
                "value": f"x0{i+1}",
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
        for i, option in enumerate(options):
            demisto.debug(f"option= {option}")
            option_text, _ = parse_option_text(option)
            select_item = {
                "value": f"v{i+1}",
                "text": option_text
            }
            select_items.append(select_item)

        json_data = {
            "body": [
                {
                    "select_items": select_items,
                    "text": text,
                    "selected_item": {
                        "value": "v1"
                    },
                    "type": "select"
                }
            ]
        }

    else:
        raise ValueError("Invalid responseType. It should be 'button' or 'dropdown'.")
    demisto.debug(json_data)
    return json_data


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
    slack_instance = demisto.get(demisto.args(), 'zoomInstance')
    try:
        parsed_date = dateparser.parse('in ' + lifetime, settings={'TIMEZONE': 'UTC'})
        assert parsed_date is not None, f'could not parse in {lifetime}'
        expiry = datetime.strftime(parsed_date,
                                   DATE_FORMAT)
    except Exception:
        parsed_date = dateparser.parse('in 1 day', settings={'TIMEZONE': 'UTC'})
        assert parsed_date is not None
        expiry = datetime.strftime(parsed_date,
                                   DATE_FORMAT)
    default_response = demisto.get(demisto.args(), 'defaultResponse')

    entitlement_string = entitlement + '@' + demisto.investigation()['id']
    if demisto.get(demisto.args(), 'task'):
        entitlement_string += '|' + demisto.get(demisto.args(), 'task')

    args = {
        'ignoreAddURL': 'true',
    }
    if slack_instance:
        args.update({
            'using': slack_instance
        })
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
    # args['message'] = blocks

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

    args['zoom_ask'] = 'true'
    demisto.debug(f"zoom ask: {args}")
    try:
        demisto.results(demisto.executeCommand('zoom-send-notification', args))
    except ValueError as e:
        if 'Unsupported Command' in str(e):
            return_error(f'The command is unsupported by this script. {e}')
        else:
            return_error('An error has occurred while executing the send-notification command',
                         error=e)


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
