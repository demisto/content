import demistomock as demisto
from CommonServerPython import entryTypes
import json
import dateparser
import datetime
import SlackAskV2


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
        'reply': 'Thank you brother.', 'lifetime': '24 hours', 'defaultResponse': 'NoResponse', 'using-brand': 'SlackV3',
        'slackInstance': 'TestingInstance1'
    })
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(dateparser, 'parse', return_value=datetime.datetime(2019, 9, 26, 18, 38, 25))

    # Arrange
    SlackAskV2.main()
    call_args = demisto.executeCommand.call_args[0]

    # Assert
    assert call_args[1] == {
        'ignoreAddURL': 'true',
        'using-brand': 'SlackV3',
        'using': 'TestingInstance1',
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
        'defaultResponse': 'NoResponse', 'slackInstance': 'TestingInstance1',
        'slackVersion': 'SlackV3'
    })
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(dateparser, 'parse', return_value=datetime.datetime(2019, 9, 26, 18, 38, 25))

    # Arrange
    SlackAskV2.main()
    call_args = demisto.executeCommand.call_args[0]

    # Assert
    assert call_args[1] == {
        'ignoreAddURL': 'true',
        'using-brand': 'SlackV3',
        'using': 'TestingInstance1',
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
        'reply': 'Thank you brother.', 'lifetime': '24 hours', 'defaultResponse': 'NoResponse', 'using-brand': 'SlackV3'
    })
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(dateparser, 'parse', return_value=datetime.datetime(2019, 9, 26, 18, 38, 25))

    # Arrange
    SlackAskV2.main()
    call_args = demisto.executeCommand.call_args[0]

    # Assert
    assert call_args[1] == {
        'ignoreAddURL': 'true',
        'using-brand': 'SlackV3',
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
        'reply': 'Thank you brother.', 'lifetime': '24 hours', 'defaultResponse': 'NoResponse', 'using-brand': 'SlackV3'
    })
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(dateparser, 'parse', return_value=datetime.datetime(2019, 9, 26, 18, 38, 25))

    # Arrange
    SlackAskV2.main()
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
        'using-brand': 'SlackV3',
        'to': 'alexios',
    }


def test_slack_ask_user_threads_additional(mocker):
    # Set
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'investigation', return_value={'id': '22'})
    mocker.patch.object(demisto, 'args', return_value={
        'user': 'alexios', 'message': 'wat up', 'option1': 'yes#red', 'option2': 'no#red',
        'additionalOptions': 'maybe', 'responseType': 'thread', 'reply': 'Thank you brother.',
        'lifetime': '24 hours', 'defaultResponse': 'NoResponse', 'using-brand': 'SlackV3'
    })
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(dateparser, 'parse', return_value=datetime.datetime(2019, 9, 26, 18, 38, 25))

    # Arrange
    SlackAskV2.main()
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
        'using-brand': 'SlackV3',
        'to': 'alexios',
    }


def test_slack_ask_channel_threads(mocker):
    # Set
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'investigation', return_value={'id': '22'})
    mocker.patch.object(demisto, 'args', return_value={
        'channel': 'general', 'message': 'wat up', 'responseType': 'thread', 'option1': 'yes#red', 'option2': 'no#red',
        'reply': 'Thank you brother.', 'lifetime': '24 hours', 'defaultResponse': 'NoResponse', 'using-brand': 'SlackV3'
    })
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(dateparser, 'parse', return_value=datetime.datetime(2019, 9, 26, 18, 38, 25))

    # Arrange
    SlackAskV2.main()
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
        'using-brand': 'SlackV3',
        'channel': 'general',
    }
# import pytest
# from unittest.mock import patch, MagicMock
# from datetime import datetime
# import dateparser


# @pytest.fixture
# def demisto_mock():
#     with patch.dict('sys.modules', {'demistomock': MagicMock(), 'CommonServerPython': MagicMock(), 'CommonServerUserPython':
# MagicMock()}):
#         yield

# def test_parse_option_text():
#     assert script_name.parse_option_text("Hello#blue") == ("Hello", "Primary")
#     assert script_name.parse_option_text("Test#red") == ("Test", "Danger")
#     assert script_name.parse_option_text("Default Text") == ("Default Text", "Default")

# def test_generate_json_button():
#     options = ["Option1#blue", "Option2#red", "Option3#white"]
#     result = script_name.generate_json("Message Text", options, "button")
#     assert result["head"]["text"] == "Message Text"
#     assert len(result["body"][0]["items"]) == 3
#     assert result["body"][0]["items"][0]["value"] == "Option1"
#     assert result["body"][0]["items"][0]["style"] == "Primary"

# def test_generate_json_dropdown():
#     options = ["Choice1#blue", "Choice2#white", "Choice3#gray"]
#     result = script_name.generate_json("Dropdown Message", options, "dropdown")
#     assert result["body"][0]["text"] == "Dropdown Message"
#     assert len(result["body"][0]["select_items"]) == 3
#     assert result["body"][0]["select_items"][0]["value"] == "Choice1"

# def test_main(demisto_mock):
#     args = {
#         'message': 'Test Message',
#         'option1': 'Option 1',
#         'option2': 'Option 2',
#         'responseType': 'button',
#         'lifetime': '2 hours',
#         'user': 'test.user@example.com'
#         # Add other args as needed
#     }
#     with patch.object(dateparser, 'parse', return_value=datetime.utcnow()):
#         script_name.demisto.get.return_value = "Entitlement"
#         script_name.demisto.args.return_value = args
#         script_name.demisto.executeCommand.return_value = [{'Contents': 'Entitlement'}]
#         script_name.main()

# # Add more test cases as needed

# if __name__ == '__main__':
#     pytest.main(['-s', __file__])
