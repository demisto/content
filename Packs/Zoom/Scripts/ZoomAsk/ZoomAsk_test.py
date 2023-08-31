from CommonServerPython import entryTypes
import Zoom
import unittest
from unittest.mock import patch, MagicMock
from io import StringIO
import json
from datetime import datetime
from dateparser import parse as dateparser_parse
import demistomock as demisto

# Import the functions from the script you want to test
from ZoomAsk import parse_option_text, generate_json


class ZoomAsk_test(unittest.TestCase):
    
    @patch('demistomock.executeCommand')
    @patch('demistomock.get')
    def test_parse_option_text_with_color(self, mock_get, mock_executeCommand):
        # Test parsing an option text with color information
        option_text = 'Option1#blue'
        text, style = parse_option_text(option_text)
        
        # Verify parsing results
        self.assertEqual(text, 'Option1')
        self.assertEqual(style, 'Primary')

    @patch('demistomock.executeCommand')
    @patch('demistomock.get')
    def test_parse_option_text_without_color(self, mock_get, mock_executeCommand):
        # Test parsing an option text without color information
        option_text = 'Option2'
        text, style = parse_option_text(option_text)
        
        # Verify parsing results
        self.assertEqual(text, 'Option2')
        self.assertEqual(style, 'Default')
    
    @patch('demistomock.executeCommand')
    @patch('demistomock.get')
    def test_generate_json_button(self, mock_get, mock_executeCommand):
        # Mock inputs for generating JSON with button response type
        demisto.args.return_value = {
            'message': 'Test Message',
            'option1': 'Option1#blue',
            'option2': 'Option2#red',
            'responseType': 'button',
            # Other necessary inputs
        }
        
        # Mock executeCommand response
        mock_executeCommand.return_value = [{'Contents': 'Entitlement123'}]
        
        # Mock datetime
        datetime_mock = MagicMock()
        datetime_mock.strftime.return_value = '2023-08-29 12:00:00'
        with patch('your_script_file.datetime', datetime_mock):
            # Call the function to generate JSON
            json_data = generate_json(demisto.args()['message'], [demisto.args()['option1'], demisto.args()['option2']], demisto.args()['responseType'])
        
        # Verify the generated JSON
        expected_json = {
            "head": {
                "type": "message",
                "text": "Test Message"
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
        self.assertEqual(json_data, expected_json)

    @patch('demistomock.executeCommand')
    @patch('demistomock.get')
    def test_generate_json_dropdown(self, mock_get, mock_executeCommand):
        # Mock inputs for generating JSON with dropdown response type
        demisto.args.return_value = {
            'message': 'Test Message',
            'option1': 'Option1',
            'option2': 'Option2#red',
            'responseType': 'dropdown',
            # Other necessary inputs
        }
        
        # Mock executeCommand response
        mock_executeCommand.return_value = [{'Contents': 'Entitlement123'}]
        
        # Mock datetime
        datetime_mock = MagicMock()
        datetime_mock.strftime.return_value = '2023-08-29 12:00:00'
        with patch('your_script_file.datetime', datetime_mock):
            # Call the function to generate JSON
            json_data = generate_json(demisto.args()['message'], [demisto.args()['option1'], demisto.args()['option2']], demisto.args()['responseType'])
        
        # Verify the generated JSON
        expected_json = {
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
                    "text": "Test Message",
                    "selected_item": {
                        "value": "Option1"
                    },
                    "type": "select"
                }
            ]
        }
        self.assertEqual(json_data, expected_json)

        # Add assertions to check the expected behavior of the main function
        # For example, check if certain executeCommand calls were made, etc.

    # Add more test cases for other functions and scenarios

if __name__ == '__main__':
    unittest.main()
