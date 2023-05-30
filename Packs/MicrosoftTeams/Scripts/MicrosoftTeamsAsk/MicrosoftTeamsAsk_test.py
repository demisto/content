from MicrosoftTeamsAsk import main
from CommonServerPython import entryTypes
import demistomock as demisto
import json
import pytest


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
        expected_script_arguments: dict = {
            'message': expected_message,
            'using-brand': 'Microsoft Teams'
        }
        if 'team_member' in args:
            expected_script_arguments['team_member'] = 'Shaq'
        elif 'channel' in args:
            expected_script_arguments['channel'] = 'WhatAchannel'
            if 'team' in args:
                expected_script_arguments['team'] = 'TestTeam'
        assert args == expected_script_arguments
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
    script_arguments: dict = {
        'message': 'How are you today?',
        'option1': 'Great',
        'option2': 'Wonderful',
        'additional_options': 'SSDD,Wooah',
        'task_id': '44'
    }
    mocker.patch.object(
        demisto,
        'args',
        return_value=script_arguments
    )
    with pytest.raises(ValueError) as e:
        main()
    assert str(e.value) == 'Either team member or channel must be provided.'

    script_arguments['team_member'] = 'Shaq'
    script_arguments['channel'] = 'WhatAchannel'
    script_arguments['team'] = 'TestTeam'
    mocker.patch.object(
        demisto,
        'args',
        return_value=script_arguments
    )
    with pytest.raises(ValueError) as e:
        main()
    assert str(e.value) == 'Either team member or channel should be provided, not both.'
    script_arguments.pop('team_member')
    mocker.patch.object(
        demisto,
        'args',
        return_value=script_arguments
    )
    main()
    assert demisto.executeCommand.call_count == 2
