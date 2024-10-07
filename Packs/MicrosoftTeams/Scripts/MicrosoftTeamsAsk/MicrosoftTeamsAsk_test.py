from MicrosoftTeamsAsk import main
from CommonServerPython import entryTypes
import demistomock as demisto
import json
import pytest

MS_TEAMS_ASK_MESSAGE_KEYS = {'message_text', 'options', 'entitlement', 'investigation_id',
                             'task_id', 'form_type'}

MS_TEAMS_ASK_AC_KEYS = {'adaptive_card', 'entitlement', 'investigation_id',
                        'task_id'}  # must be synced with ones in MicrosoftTeams.py


def execute_command(name, args=None):
    """
    if assert MS_TEAMS_ASK_MESSAGE_KEYS == json_message.keys() test fails, update the MS_TEAMS_ASK_MESSAGE_KEYS constant
     to have the same keys as the message keys in the MsTeamsAsk script and the test.
    """
    if name == 'addEntitlement':
        return [
            {
                'Type': entryTypes['note'],
                'Contents': '4404dae8-2d45-46bd-85fa-64779c12abe8'
            }
        ]
    elif name == 'send-notification':
        expected_script_arguments: dict = {}
        json_message = {
            'message_text': 'How are you today?',
            'options': ['Great', 'Wonderful', 'SSDD', 'Wooah'],
            'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8',
            'investigation_id': '32',
            'task_id': '44',
            'form_type': 'predefined-options'}

        if "message" in args:
            json_message['message_text'] = 'How are you today?'
            expected_message: str = json.dumps(json_message)
            assert json_message.keys() == MS_TEAMS_ASK_MESSAGE_KEYS
            expected_script_arguments["message"] = expected_message

        if "adaptive_card" in args:
            json_message['adaptive_card'] = {"contentType": "application/vnd.microsoft.card.adaptive",
                                             "content": {
                                                 "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                                                 "type": "AdaptiveCard",
                                                 "version": "1.0",
                                                 "body": [
                                                     {
                                                         "type": "Container",
                                                         "items": [{
                                                            "type": "TextBlock",
                                                            "text": "What a pretty adaptive card"
                                                         }]
                                                     }]
                                             }
                                             }
            json_message.pop("options")
            json_message.pop("message_text")
            json_message.pop("form_type")
            expected_message: str = json.dumps(json_message)
            assert json_message.keys() == MS_TEAMS_ASK_AC_KEYS
            expected_script_arguments["adaptive_card"] = expected_message

        expected_script_arguments['using-brand'] = 'Microsoft Teams'
        expected_script_arguments['using'] = ''

        if 'team_member' in args:
            expected_script_arguments['team_member'] = 'Shaq'
        elif 'channel' in args:
            expected_script_arguments['channel'] = 'WhatAchannel'
            if 'team' in args:
                expected_script_arguments['team'] = 'TestTeam'
        assert args == expected_script_arguments
        return None
    else:
        raise ValueError(f'Unimplemented command called: {name}')


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
        'task_id': '44',
        'form_type': 'predefined-options'
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
    script_arguments['adaptive_card'] = {"contentType": "application/vnd.microsoft.card.adaptive",
                                         "content": {
                                             "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                                             "type": "AdaptiveCard",
                                             "version": "1.0",
                                             "body": [
                                                 {
                                                     "type": "Container",
                                                     "items": [{
                                                        "type": "TextBlock",
                                                        "text": "What a pretty adaptive card"
                                                     }]
                                                 }]
                                         }
                                         }
    mocker.patch.object(
        demisto,
        'args',
        return_value=script_arguments
    )
    with pytest.raises(ValueError) as e:
        main()
    assert str(e.value) == 'Provide either message or adaptive card to send, not both.'


def test_microsoft_teams_ask_persistent(mocker):
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'investigation', return_value={'id': '32'})
    script_arguments = {
        'message': 'How are you today?',
        'option1': 'Great',
        'option2': 'Wonderful',
        'additional_options': 'SSDD,Wooah',
        'task_id': "44",
        'team_member': 'Shaq',
        'persistent': 'true'
    }
    mocker.patch.object(demisto, 'args', return_value=script_arguments)
    main()
    assert demisto.executeCommand.call_count == 2


def test_microsoft_teams_ask_error_response(mocker):
    def error_execute_command(name, args=None):
        if name == 'addEntitlement':
            return [{'Type': entryTypes['error'], 'Contents': 'Error adding entitlement'}]
        return None

    mocker.patch.object(demisto, 'executeCommand', side_effect=error_execute_command)
    mocker.patch.object(demisto, 'investigation', return_value={'id': '32'})
    script_arguments = {
        'message': 'Test message',
        'team_member': 'Charlie'
    }
    mocker.patch.object(demisto, 'args', return_value=script_arguments)
    mocker.patch.object(demisto, 'results')
    main()
    demisto.results.assert_called_once()
