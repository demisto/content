import demistomock as demisto
from CommonServerPython import entryTypes
import json
from SlackAsk import main


def execute_command(command, args):
    if command == 'addEntitlement':
        return [{
            'Type': entryTypes['note'],
            'Contents': '4404dae8-2d45-46bd-85fa-64779c12abe8'
        }]

    return []


def test_slack_ask_user(mocker):
    # Set
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'investigation', return_value={'id': '22'})
    mocker.patch.object(demisto, 'args', return_value={
        'user': 'alexios', 'message': 'wat up'
    })
    mocker.patch.object(demisto, 'results')

    # Arrange
    main()
    call_args = demisto.executeCommand.call_args[0]

    # Assert
    assert call_args[1] == {
        'message': json.dumps({
            'message': 'wat up - Please reply to this thread with `yes` or `no`',
            'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8@22'
        }),
        'ignoreAddURL': 'true',
        'to': 'alexios',
    }


def test_slack_ask_channel(mocker):
    # Set
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'investigation', return_value={'id': '22'})
    mocker.patch.object(demisto, 'args', return_value={
        'channel': 'general', 'message': 'wat up'
    })
    mocker.patch.object(demisto, 'results')

    # Arrange
    main()
    call_args = demisto.executeCommand.call_args[0]

    # Assert
    assert call_args[1] == {
        'message': json.dumps({
            'message': 'wat up - Please reply to this thread with `yes` or `no`',
            'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8@22'
        }),
        'ignoreAddURL': 'true',
        'channel': 'general',
    }
