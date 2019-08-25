from MicrosoftTeamsAsk import main
from CommonServerPython import entryTypes
import demistomock as demisto
import json


def execute_command(name, args=None):
    if name == 'addEntitlement':
        return [
            {
                'Type': entryTypes['note'],
                'Contents': '4404dae8-2d45-46bd-85fa-64779c12abe8'
            }
        ]
    elif name == 'send-notification':
        expected_message: str = json.dumps({
            'message_text': 'How are you today?',
            'options': ['Great', 'Wonderful', 'SSDD', 'Wooah'],
            'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8',
            'investigation_id': '32',
            'task_id': '44'
        })
        assert args == {
            'team_member': 'Shaq',
            'message': expected_message,
            'using-brand': 'Microsoft Teams'
        }
    else:
        raise ValueError('Unimplemented command called: {}'.format(name))


def test_microsoft_teams_ask(mocker):
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(
        demisto,
        'investigation',
        return_value={
            'id': '32'
        }
    )
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'message': 'How are you today?',
            'option1': 'Great',
            'option2': 'Wonderful',
            'additional_options': 'SSDD,Wooah',
            'team_member': 'Shaq',
            'task_id': '44'
        }
    )
    main()
    assert demisto.executeCommand.call_count == 2
