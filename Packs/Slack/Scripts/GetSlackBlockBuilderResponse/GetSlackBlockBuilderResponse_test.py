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
        mock_return_error.assert_called_once_with("The response is not a valid JSON format.")


if __name__ == '__main__':
    unittest.main()
