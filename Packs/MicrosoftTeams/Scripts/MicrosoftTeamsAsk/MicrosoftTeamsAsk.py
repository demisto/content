from enum import Enum

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


class FormType(Enum):
    PREDEFINED_OPTIONS = 'predefined-options'
    OPEN_ANSWER = 'open-answer'


def main():
    script_arguments: dict = demisto.args()

    team_member: str = script_arguments.get('team_member', '')
    channel: str = script_arguments.get('channel', '')
    team: str = script_arguments.get('team', '')
    using_instance: str = script_arguments.get('using', '')

    if not (team_member or channel):
        raise ValueError('Either team member or channel must be provided.')

    if team_member and channel:
        raise ValueError('Either team member or channel should be provided, not both.')

    persistent: bool = script_arguments.get('persistent', '') == 'true'
    response: list = demisto.executeCommand('addEntitlement', {'persistent': persistent})
    if isError(response[0]):
        demisto.results(response)
        return

    entitlement: str = response[0]['Contents']
    investigation_id: str = demisto.investigation()['id']
    task_id: str = script_arguments.get('task_id', '')
    message_text: str = script_arguments.get('message', '')
    adaptive_card: str = script_arguments.get('adaptive_card', '')

    if message_text and adaptive_card:
        raise ValueError('Provide either message or adaptive card to send, not both.')

    form_type = FormType(script_arguments.get('form_type', FormType.PREDEFINED_OPTIONS.value))
    first_option: str = script_arguments.get('option1', '')
    second_option: str = script_arguments.get('option2', '')
    options: list = [first_option, second_option]
    command_arguments: dict = {}

    if adaptive_card:
        adaptive_card_object: dict = {
            "adaptive_card": json.loads(adaptive_card),
            "entitlement": entitlement,
            "investigation_id": investigation_id,
            "task_id": task_id
        }
        command_arguments["adaptive_card"] = adaptive_card_object
        command_arguments["using"] = using_instance
        command_arguments["using-brand"] = "Microsoft Teams"
    else:
        message: dict = {
            "message_text": message_text,
            "options": options,
            "entitlement": entitlement,
            "investigation_id": investigation_id,
            "task_id": task_id,
            "form_type": form_type.value
        }

        if form_type == FormType.PREDEFINED_OPTIONS:
            additional_options: list = argToList(script_arguments.get("additional_options"))
            options.extend(additional_options)
            message["options"] = options

        command_arguments["message"] = json.dumps(message)
        command_arguments["using"] = using_instance
        command_arguments["using-brand"] = "Microsoft Teams"

    if channel:
        command_arguments["channel"] = channel
        if team:
            command_arguments["team"] = team
    elif team_member:
        command_arguments["team_member"] = team_member

    demisto.debug(f"Calling command 'send-notification' with arguments:\n{command_arguments}")
    demisto.results(demisto.executeCommand('send-notification', command_arguments))


if __name__ == 'builtins':
    main()
