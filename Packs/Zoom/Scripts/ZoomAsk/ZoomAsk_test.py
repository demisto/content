import demistomock as demisto
from ZoomAsk import generate_json, main
import dateparser
from CommonServerPython import entryTypes
import datetime


def test_generate_json_button():
    text = "Test Text"
    options = ["Option1#blue", "Option2#red"]
    response_type = "button"
    result = generate_json(text, options, response_type)

    expected_result = {
        "head": {
            "type": "message",
            "text": text
        },
        "body": [
            {
                "type": "actions",
                "items": [
                    {
                        "value": "Option1",
                        "style": "Primary",
                        "text": "Option1"
                    },
                    {
                        "value": "Option2",
                        "style": "Danger",
                        "text": "Option2"
                    }
                ]
            }
        ]
    }

    assert result == expected_result


def test_generate_json_dropdown():
    text = "Test Text"
    options = ["Option1#blue", "Option2#red"]
    response_type = "dropdown"
    result = generate_json(text, options, response_type)

    expected_result = {
        "body": [
            {
                "select_items": [
                    {
                        "value": "Option1",
                        "text": "Option1"
                    },
                    {
                        "value": "Option2",
                        "text": "Option2"
                    }
                ],
                "text": text,
                "selected_item": {
                    "value": "Option1"
                },
                "type": "select"
            }
        ]
    }

    assert result == expected_result


def execute_command(command, args):
    if command == 'addEntitlement':
        return [{
            'Type': entryTypes['note'],
            'Contents': '4404dae8-2d45-46bd-85fa-64779c12abe8'
        }]

    return []


def test_main(mocker):

    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'investigation', return_value={'id': '22'})
    mocker.patch.object(demisto, 'args', return_value={
        'persistent': 'true',
        'option1': 'Option1',
        'option2': 'Option2',
        'additionalOptions': '',
        'reply': 'Test Reply',
        'responseType': 'button',
        'lifetime': '1 day',
        'defaultResponse': 'Default Response',
        'user': 'test@example.com',
        'message': 'Test Message',
        'channel_name': None,
        'channel_id': None,
        'task': None
    })
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(dateparser, 'parse', return_value=datetime.datetime(2019, 9, 26, 18, 38, 25))

    # Call the main function
    main()

    call_args = demisto.executeCommand.call_args[0]
    expected_args = {
        'ignoreAddURL': 'true',
        'message':
            '{"blocks": "{\\"head\\": {\\"type\\": \\"message\\", \\"text\\": \\"Test Message\\"}, \\"body\\": [{\\"type\\": \\"actions\\", \\"items\\": [{\\"value\\": \\"Option1\\", \\"style\\": \\"Default\\", \\"text\\": \\"Option1\\"}, {\\"value\\": \\"Option2\\", \\"style\\": \\"Default\\", \\"text\\": \\"Option2\\"}]}]}", "entitlement": "4404dae8-2d45-46bd-85fa-64779c12abe8@22", "reply": "Test Reply", "expiry": "2019-09-26 18:38:25", "default_response": "Default Response"}',  # noqa: E501
        'to': 'test@example.com',
        'zoom_ask': 'true',
        'using-brand': 'Zoom'
    }

    assert call_args[1] == expected_args
