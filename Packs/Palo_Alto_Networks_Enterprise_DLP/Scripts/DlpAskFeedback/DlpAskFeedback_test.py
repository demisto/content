import demistomock as demisto
from CommonServerPython import entryTypes
import json
import dateparser
import datetime
import DlpAskFeedback


BLOCKS = [{
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
    }]}]

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

    return []


def test_slack_ask_user(mocker):
    # Set
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'investigation', return_value={'id': '22'})
    mocker.patch.object(demisto, 'args', return_value={
        'user': 'alexios', 'message': 'wat up', 'option1': 'yes#red', 'option2': 'no#red',
        'reply': 'Thank you brother.', 'lifetime': '24 hours', 'defaultResponse': 'NoResponse', 'using-brand': 'SlackV2'
    })
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(dateparser, 'parse', return_value=datetime.datetime(2019, 9, 26, 18, 38, 25))

    # Arrange
    DlpAskFeedback.main()
    call_args = demisto.executeCommand.call_args[0]

    # Assert
    assert call_args[1] == {
        'ignoreAddURL': 'true',
        'using-brand': 'SlackV2',
        'blocks': json.dumps({
            'blocks': json.dumps(BLOCKS),
            'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8@22',
            'reply': 'Thank you brother.',
            'expiry': '2019-09-26 18:38:25',
            'default_response': 'NoResponse'
        }),
        'message': 'wat up',
        'to': 'alexios'
    }


def test_slack_ask_user_additional(mocker):
    # Set
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'investigation', return_value={'id': '22'})
    mocker.patch.object(demisto, 'args', return_value={
        'user': 'alexios', 'message': 'wat up', 'option1': 'yes#red', 'option2': 'no#red',
        'additionalOptions': 'maybe', 'reply': 'Thank you brother.', 'lifetime': '24 hours',
        'defaultResponse': 'NoResponse', 'using-brand': 'SlackV2'
    })
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(dateparser, 'parse', return_value=datetime.datetime(2019, 9, 26, 18, 38, 25))

    # Arrange
    DlpAskFeedback.main()
    call_args = demisto.executeCommand.call_args[0]

    # Assert
    assert call_args[1] == {
        'ignoreAddURL': 'true',
        'using-brand': 'SlackV2',
        'blocks': json.dumps({
            'blocks': json.dumps(BLOCKS_ADDITIONAL),
            'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8@22',
            'reply': 'Thank you brother.',
            'expiry': '2019-09-26 18:38:25',
            'default_response': 'NoResponse'
        }),
        'message': 'wat up',
        'to': 'alexios'
    }


def test_slack_ask_channel(mocker):
    # Set
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'investigation', return_value={'id': '22'})
    mocker.patch.object(demisto, 'args', return_value={
        'channel': 'general', 'message': 'wat up', 'option1': 'yes#red', 'option2': 'no#red',
        'reply': 'Thank you brother.', 'lifetime': '24 hours', 'defaultResponse': 'NoResponse', 'using-brand': 'SlackV2'
    })
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(dateparser, 'parse', return_value=datetime.datetime(2019, 9, 26, 18, 38, 25))

    # Arrange
    DlpAskFeedback.main()
    call_args = demisto.executeCommand.call_args[0]

    # Assert
    assert call_args[1] == {
        'ignoreAddURL': 'true',
        'using-brand': 'SlackV2',
        'blocks': json.dumps({
            'blocks': json.dumps(BLOCKS),
            'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8@22',
            'reply': 'Thank you brother.',
            'expiry': '2019-09-26 18:38:25',
            'default_response': 'NoResponse'
        }),
        'message': 'wat up',
        'channel': 'general'
    }


def test_slack_ask_user_threads(mocker):
    # Set
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'investigation', return_value={'id': '22'})
    mocker.patch.object(demisto, 'args', return_value={
        'user': 'alexios', 'message': 'wat up', 'responseType': 'thread', 'option1': 'yes#red', 'option2': 'no#red',
        'reply': 'Thank you brother.', 'lifetime': '24 hours', 'defaultResponse': 'NoResponse', 'using-brand': 'SlackV2'
    })
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(dateparser, 'parse', return_value=datetime.datetime(2019, 9, 26, 18, 38, 25))

    # Arrange
    DlpAskFeedback.main()
    call_args = demisto.executeCommand.call_args[0]

    # Assert
    assert call_args[1] == {
        'message': json.dumps({
            'message': 'wat up - Please reply to this thread with `yes` or `no`.',
            'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8@22',
            'reply': 'Thank you brother.',
            'expiry': '2019-09-26 18:38:25',
            'default_response': 'NoResponse'
        }),
        'ignoreAddURL': 'true',
        'using-brand': 'SlackV2',
        'to': 'alexios',
    }


def test_slack_ask_user_threads_additional(mocker):
    # Set
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'investigation', return_value={'id': '22'})
    mocker.patch.object(demisto, 'args', return_value={
        'user': 'alexios', 'message': 'wat up', 'option1': 'yes#red', 'option2': 'no#red',
        'additionalOptions': 'maybe', 'responseType': 'thread', 'reply': 'Thank you brother.',
        'lifetime': '24 hours', 'defaultResponse': 'NoResponse', 'using-brand': 'SlackV2'
    })
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(dateparser, 'parse', return_value=datetime.datetime(2019, 9, 26, 18, 38, 25))

    # Arrange
    DlpAskFeedback.main()
    call_args = demisto.executeCommand.call_args[0]

    # Assert
    assert call_args[1] == {
        'message': json.dumps({
            'message': 'wat up - Please reply to this thread with `yes` or `no` or `maybe`.',
            'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8@22',
            'reply': 'Thank you brother.',
            'expiry': '2019-09-26 18:38:25',
            'default_response': 'NoResponse'
        }),
        'ignoreAddURL': 'true',
        'using-brand': 'SlackV2',
        'to': 'alexios',
    }


def test_slack_ask_channel_threads(mocker):
    # Set
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'investigation', return_value={'id': '22'})
    mocker.patch.object(demisto, 'args', return_value={
        'channel': 'general', 'message': 'wat up', 'responseType': 'thread', 'option1': 'yes#red', 'option2': 'no#red',
        'reply': 'Thank you brother.', 'lifetime': '24 hours', 'defaultResponse': 'NoResponse', 'using-brand': 'SlackV2'
    })
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(dateparser, 'parse', return_value=datetime.datetime(2019, 9, 26, 18, 38, 25))

    # Arrange
    DlpAskFeedback.main()
    call_args = demisto.executeCommand.call_args[0]

    # Assert
    assert call_args[1] == {
        'message': json.dumps({
            'message': 'wat up - Please reply to this thread with `yes` or `no`.',
            'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8@22',
            'reply': 'Thank you brother.',
            'expiry': '2019-09-26 18:38:25',
            'default_response': 'NoResponse'
        }),
        'ignoreAddURL': 'true',
        'using-brand': 'SlackV2',
        'channel': 'general',
    }
