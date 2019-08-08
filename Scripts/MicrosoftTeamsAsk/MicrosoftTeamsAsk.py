import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def main():
    persistent: bool = True if demisto.args().get('persistent') == 'true' else False
    response: list = demisto.executeCommand('addEntitlement', {'persistent': persistent})
    if isError(response[0]):
        return_error(response)
        sys.exit(1)
    entitlement: str = response[0]['Contents']
    investigation_id: str = demisto.investigation()['id']
    task_id: str = demisto.args().get('task_id', '')
    message_text: str = demisto.args().get('message', '')
    first_option: str = demisto.args().get('option1', '')
    second_option: str = demisto.args().get('option2', '')
    options: list = [first_option, second_option]
    additional_options: str = argToList(demisto.args().get('additional_options', ''))
    options.extend(additional_options)
    message: dict = {
        'message_text': message_text,
        'options': options,
        'entitlement': entitlement,
        'investigation_id': investigation_id,
        'task_id': task_id
    }
    command_arguments: dict = {
        'team_member': demisto.args().get('team_member'),
        'message': json.dumps(message),
        'using-brand': 'Microsoft Teams'
    }
    demisto.results(demisto.executeCommand('send-notification', command_arguments))


if __name__ == 'builtins':
    main()
