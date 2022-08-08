import demistomock as demisto
from CommonServerPython import entryTypes
import dateparser
import datetime
import DlpAskFeedback

BLOCKS = [{
    "type": "section",
    "text": {
        "type": "mrkdwn",
        "text": "Are you sure"
    }
}, {
    "type": "actions",
    "elements": [{
        "type": "button",
        "text": {
            "type": "plain_text",
            "emoji": True,
            "text": "Yes"
        },
        "value": "{\"entitlement\": \"4404dae8-2d45-46bd-85fa-64779c12abe8@22\", \"reply\": \"Thank you for your response.\"}",
        "style": "primary"
    }, {
        "type": "button",
        "text": {
            "type": "plain_text",
            "emoji": True,
            "text": "No"
        },
        "value": "{\"entitlement\": \"4404dae8-2d45-46bd-85fa-64779c12abe8@22\", \"reply\": \"Thank you for your response.\"}",
        "style": "primary"
    }]
}]

BLOCKS_ADDITIONAL = [{
    'type': 'section',
    'text': {
        'type': 'mrkdwn',
        'text': 'wat up'
    }
}, {
    'type': 'actions',
    'elements': [{
        'type': 'button',
        'text': {
            'type': 'plain_text',
            'emoji': True,
            'text': 'yes'
        },
        'value': '{\"entitlement\": \"4404dae8-2d45-46bd-85fa-64779c12abe8@22\", \"reply\": \"Thank you brother.\"}',
        'style': 'danger'
    }, {
        'type': 'button',
        'text': {
            'type': 'plain_text',
            'emoji': True,
            'text': 'no'
        },
        'value': '{\"entitlement\": \"4404dae8-2d45-46bd-85fa-64779c12abe8@22\", \"reply\": \"Thank you brother.\"}',
        'style': 'danger'
    }, {
        'type': 'button',
        'text': {
            'type': 'plain_text',
            'emoji': True,
            'text': 'maybe'
        },
        'value': '{\"entitlement\": \"4404dae8-2d45-46bd-85fa-64779c12abe8@22\", \"reply\": \"Thank you brother.\"}',
    }]}]


def execute_command(command, args):
    if command == 'addEntitlement':
        return [{
            'Type': entryTypes['note'],
            'Contents': '4404dae8-2d45-46bd-85fa-64779c12abe8'
        }]
    elif command == 'pan-dlp-slack-message':
        return [{
            "Contents": {"message": "Are you sure"},
            "Type": 1
        }]

    return []


def test_slack_ask_user(mocker):
    # Set
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'investigation', return_value={'id': '22'})
    mocker.patch.object(demisto, 'args', return_value={
        'messenger': 'Slack', 'user_id': 'alexios', 'message': 'wat up', 'option1': 'yes#red', 'option2': 'no#red',
        'reply': 'Thank you brother.', 'lifetime': '24 hours', 'defaultResponse': 'NoResponse', 'using-brand': 'SlackV3'
    })
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(dateparser, 'parse', return_value=datetime.datetime(2019, 9, 26, 18, 38, 25))

    # Arrange
    DlpAskFeedback.main()
    call_args = demisto.executeCommand.call_args[0]

    # Assert
    assert call_args[1]['using-brand'] == 'SlackV3'
    assert call_args[1]['to'] == 'alexios'


def test_teams_ask_user(mocker):
    # Set
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'investigation', return_value={'id': '22'})
    mocker.patch.object(demisto, 'args', return_value={
        'messenger': 'Microsoft Teams', 'user_id': 'alexios', 'message': 'wat up', 'option1': 'yes#red', 'option2': 'no#red',
        'reply': 'Thank you brother.', 'lifetime': '24 hours', 'defaultResponse': 'NoResponse', 'using-brand': 'SlackV3'
    })
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(dateparser, 'parse', return_value=datetime.datetime(2019, 9, 26, 18, 38, 25))

    # Arrange
    DlpAskFeedback.main()
    call_args = demisto.executeCommand.call_args[0]

    # Assert
    assert call_args[1]['using-brand'] == 'Microsoft Teams'
    assert call_args[1]['team_member'] == 'alexios'
