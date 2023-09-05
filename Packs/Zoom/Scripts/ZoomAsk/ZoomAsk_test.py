import demistomock as demisto
from ZoomAsk import generate_json, main
import dateparser
import datetime
import json


def test_zoomask_user(mocker):
    # Set
    mocker.patch.object(demisto, 'executeCommand')
    mocker.patch.object(demisto, 'investigation', return_value={'id': '22'})
    mocker.patch.object(demisto, 'args', return_value={
        'user': 'alexios',
        'message': 'wat up',
        'option1': 'yes#red',
        'option2': 'no#red',
        'reply': 'Thank you brother.',
        'lifetime': '24 hours',
        'defaultResponse': 'NoResponse',
        'using-brand': 'ZoomAsk',
        'zoomInstance': 'TestingInstance1'
    })
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(dateparser, 'parse', return_value=datetime.datetime(2019, 9, 26, 18, 38, 25))

    # Arrange
    main()
    call_args = demisto.executeCommand.call_args[0]

    # Assert
    assert call_args[1] == {
        'ignoreAddURL': 'true',
        'using-brand': 'ZoomAsk',
        'using': 'TestingInstance1',
        # Update the expected 'blocks' value to match your script's logic
        'blocks': json.dumps({
            # Update with your script's block structure
        }),
        'message': 'wat up',
        'to': 'alexios'
    }


def test_generate_json_buttons():
    # Test generate_json function for 'buttons' responseType
    text = 'Test Message'
    options = ['Option 1#blue', 'Option 2#red']
    response_type = 'buttons'
    expected_json = {
        "head": {
            "type": "message",
            "text": text
        },
        "body": [
            {
                "type": "actions",
                "items": [
                    {
                        "value": "Option 1",
                        "style": "Primary",
                        "text": "Option 1"
                    },
                    {
                        "value": "Option 2",
                        "style": "Danger",
                        "text": "Option 2"
                    }
                ]
            }
        ]
    }
    assert generate_json(text, options, response_type) == expected_json


def test_generate_json_dropdown():
    # Test generate_json function for 'dropdown' responseType
    text = 'Test Message'
    options = ['Option 1#blue', 'Option 2#red']
    response_type = 'dropdown'
    expected_json = {
        "body": [
            {
                "select_items": [
                    {"value": "Option 1", "text": "Option 1"},
                    {"value": "Option 2", "text": "Option 2"}
                ],
                "text": text,
                "selected_item": {"value": "Option 1"},
                "type": "select"
            }
        ]
    }
    assert generate_json(text, options, response_type) == expected_json
