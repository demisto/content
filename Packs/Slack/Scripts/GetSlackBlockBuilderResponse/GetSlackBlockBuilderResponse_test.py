import json
import unittest
from unittest.mock import patch, MagicMock
from typing import Any

import GetSlackBlockBuilderResponse


class TestGetSlackBlockBuilderResponseScript(unittest.TestCase):

    def test_get_slack_block_builder_entry_found(self):
        # Given: A list of entries where one contains the SlackBlockBuilder response
        entries: list[dict[str, Any]] = [
            {"Contents": "random content"},
            {"Contents": "xsoar-button-submit: some data"}
        ]

        # When: Searching for the SlackBlockBuilder entry
        result = GetSlackBlockBuilderResponse.get_slack_block_builder_entry(entries)

        # Then: The appropriate entry is found
        assert result is not None
        assert "xsoar-button-submit" in result["Contents"]

    def test_get_slack_block_builder_entry_not_found(self):
        # Given: A list of entries without the SlackBlockBuilder response
        entries: list[dict[str, Any]] = [{"Contents": "random content"}]

        # When: Searching for the SlackBlockBuilder entry
        result = GetSlackBlockBuilderResponse.get_slack_block_builder_entry(entries)

        # Then: No entry is found
        assert result is None

    @patch('GetSlackBlockBuilderResponse.return_results')
    def test_parse_entry_valid(self, mock_return_results: MagicMock):
        # Given: A valid entry with JSON contents
        entry: dict[str, Any] = {"Contents": json.dumps({"key": "value"})}

        # When: Parsing the entry
        GetSlackBlockBuilderResponse.parse_entry(entry)

        # Then: The return_results function is called once
        mock_return_results.assert_called_once()

    @patch('GetSlackBlockBuilderResponse.return_error')
    def test_parse_entry_invalid(self, mock_return_error: MagicMock):
        # Given: An entry with invalid JSON contents
        entry: dict[str, Any] = {"Contents": "not a valid json"}

        # When: Parsing the entry
        GetSlackBlockBuilderResponse.parse_entry(entry)

        # Then: The return_error function is called with a specific error message
        mock_return_error.assert_called_once_with("The response is not a valid JSON format. Received the following "
                                                  "response: not a valid json")

    @patch('GetSlackBlockBuilderResponse.demisto.executeCommand')
    @patch('GetSlackBlockBuilderResponse.return_error')
    def test_main_no_entries(self, mock_return_error, mock_execute_command):
        # Given: No entries are returned from executeCommand
        mock_execute_command.return_value = []

        # When: The main function is called
        GetSlackBlockBuilderResponse.main()

        # Then: return_error is called with a specific message
        mock_return_error.assert_called_once_with("No entries found.")

    @patch('GetSlackBlockBuilderResponse.demisto.executeCommand')
    @patch('GetSlackBlockBuilderResponse.get_slack_block_builder_entry')
    @patch('GetSlackBlockBuilderResponse.parse_entry')
    def test_main_valid_entry(self, mock_parse_entry, mock_get_entry, mock_execute_command):
        # Given: A valid entry is returned from get_slack_block_builder_entry
        mock_execute_command.return_value = [{"Contents": "some content"}]
        mock_get_entry.return_value = {"Contents": "xsoar-button-submit: valid json"}

        # When: The main function is called
        GetSlackBlockBuilderResponse.main()

        # Then: parse_entry is called with the valid entry
        mock_parse_entry.assert_called_once_with({"Contents": "xsoar-button-submit: valid json"})


if __name__ == '__main__':
    unittest.main()
