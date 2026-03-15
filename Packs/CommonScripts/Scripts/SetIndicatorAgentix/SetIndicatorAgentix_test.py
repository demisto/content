import pytest
from unittest.mock import patch
from SetIndicatorAgentix import set_indicator_if_exist


class TestSetIndicator:
    def test_no_arguments_provided(self):
        """Test that function returns error when no valid arguments are provided"""
        args = {"value": "1.1.1.1"}

        with pytest.raises(SystemExit):
            set_indicator_if_exist(args)

    def test_empty_arguments(self):
        """Test that function returns error when completely empty arguments"""
        args = {}

        with pytest.raises(SystemExit):
            set_indicator_if_exist(args)

    @patch("SetIndicatorAgentix.execute_command")
    def test_indicator_does_not_exist(self, mock_execute):
        """Test that function returns error when indicator does not exist"""
        args = {"value": "nonexistent.com", "type": "Domain"}
        mock_execute.return_value = None

        with pytest.raises(SystemExit):
            set_indicator_if_exist(args)

        mock_execute.assert_called_once_with("findIndicators", {"value": "nonexistent.com"})

    @patch("SetIndicatorAgentix.execute_command")
    def test_set_indicator_type_only(self, mock_execute):
        """Test setting indicator type only"""
        args = {"value": "1.1.1.1", "type": "IP"}
        mock_execute.side_effect = [
            {"data": [{"value": "1.1.1.1"}]},  # findIndicators response
            {},  # setIndicator response
        ]

        results = set_indicator_if_exist(args)

        assert len(results) == 1
        assert "Successfully set indicator properties" in results[0].readable_output
        assert results[0].outputs["Value"] == "1.1.1.1"

        # Verify calls
        assert mock_execute.call_count == 2
        mock_execute.assert_any_call("findIndicators", {"value": "1.1.1.1"})
        mock_execute.assert_any_call("setIndicator", args)

    @patch("SetIndicatorAgentix.execute_command")
    def test_set_indicator_verdict_only(self, mock_execute):
        """Test setting indicator verdict only"""
        args = {"value": "example.com", "verdict": "malicious"}
        mock_execute.side_effect = [
            {"data": [{"value": "example.com"}]},  # findIndicators response
            {},  # setIndicator response
        ]

        results = set_indicator_if_exist(args)

        assert len(results) == 1
        assert "Successfully set indicator properties" in results[0].readable_output
        assert results[0].outputs["Value"] == "example.com"

    @patch("SetIndicatorAgentix.execute_command")
    def test_set_indicator_tags_only(self, mock_execute):
        """Test setting indicator tags only"""
        args = {"value": "1.1.1.1", "tags": "malware,botnet"}
        mock_execute.side_effect = [
            {"data": [{"value": "1.1.1.1"}]},  # findIndicators response
            {},  # setIndicator response
        ]

        results = set_indicator_if_exist(args)

        assert len(results) == 1
        assert "Successfully set indicator properties" in results[0].readable_output
        assert results[0].outputs["Value"] == "1.1.1.1"

    @patch("SetIndicatorAgentix.execute_command")
    @patch("SetIndicatorAgentix.argToList")
    def test_associate_with_existing_issues(self, mock_arg_to_list, mock_execute):
        """Test associating indicator with existing issues"""
        args = {"value": "1.1.1.1", "related_issues": "123,456"}
        mock_arg_to_list.return_value = ["123", "456"]

        mock_execute.side_effect = [
            {"data": [{"value": "1.1.1.1"}]},  # findIndicators response
            {  # core-get-issues response
                "alerts": [{"alert_fields": {"internal_id": "123"}}, {"alert_fields": {"internal_id": "456"}}]
            },
            {},  # associateIndicatorsToAlert for issue 123
            {},  # associateIndicatorsToAlert for issue 456
        ]

        results = set_indicator_if_exist(args)

        assert len(results) == 1
        assert "Successfully associated indicator to the following issues ['123', '456']" in results[0].readable_output
        assert results[0].outputs["Value"] == "1.1.1.1"

        # Verify associateIndicatorsToAlert was called for each issue
        mock_execute.assert_any_call("associateIndicatorsToAlert", {"issueId": "123", "indicatorsValues": "1.1.1.1"})
        mock_execute.assert_any_call("associateIndicatorsToAlert", {"issueId": "456", "indicatorsValues": "1.1.1.1"})

    @patch("SetIndicatorAgentix.execute_command")
    @patch("SetIndicatorAgentix.argToList")
    def test_associate_with_nonexistent_issues(self, mock_arg_to_list, mock_execute):
        """Test associating indicator with issues that don't exist"""
        args = {"value": "1.1.1.1", "related_issues": "123,999"}
        mock_arg_to_list.return_value = ["123", "999"]

        mock_execute.side_effect = [
            {"data": [{"value": "1.1.1.1"}]},  # findIndicators response
            {  # core-get-issues response - only issue 123 exists
                "alerts": [{"alert_fields": {"internal_id": "123"}}]
            },
            {},  # associateIndicatorsToAlert for issue 123
        ]

        results = set_indicator_if_exist(args)

        assert len(results) == 2  # One success, one error
        assert any("Successfully associated indicator to the following issues ['123']" in r.readable_output for r in results)
        assert any(
            "The following issues were provided as related issues but don't exist: {'999'}" in r.readable_output for r in results
        )

        # Check that error result has entry_type 4
        error_result = next(r for r in results if "don't exist" in r.readable_output)
        assert error_result.entry_type == 4

    @patch("SetIndicatorAgentix.execute_command")
    @patch("SetIndicatorAgentix.argToList")
    def test_comprehensive_update(self, mock_arg_to_list, mock_execute):
        """Test updating all properties and associating with issues"""
        args = {
            "value": "example.com",
            "type": "Domain",
            "verdict": "suspicious",
            "tags": "phishing,malware",
            "related_issues": "123,456",
        }
        mock_arg_to_list.return_value = ["123", "456"]

        mock_execute.side_effect = [
            {"data": [{"value": "example.com"}]},  # findIndicators response
            {},  # setIndicator response
            {  # core-get-issues response
                "alerts": [{"alert_fields": {"internal_id": "123"}}, {"alert_fields": {"internal_id": "456"}}]
            },
            {},  # associateIndicatorsToAlert for issue 123
            {},  # associateIndicatorsToAlert for issue 456
        ]

        results = set_indicator_if_exist(args)

        assert len(results) == 1
        result_output = results[0].readable_output
        assert "Successfully set indicator properties" in result_output
        assert "Successfully associated indicator to the following issues ['123', '456']" in result_output
        assert results[0].outputs["Value"] == "example.com"

        # Verify setIndicator was called with all args
        mock_execute.assert_any_call("setIndicator", args)

    @patch("SetIndicatorAgentix.execute_command")
    @patch("SetIndicatorAgentix.argToList")
    def test_mixed_existing_and_nonexistent_issues(self, mock_arg_to_list, mock_execute):
        """Test associating with mix of existing and non-existing issues"""
        args = {"value": "example.com", "related_issues": "123,456,999"}
        mock_arg_to_list.return_value = ["123", "456", "999"]

        mock_execute.side_effect = [
            {"data": [{"value": "example.com"}]},  # findIndicators response
            {  # core-get-issues response - only 123 and 456 exist
                "alerts": [{"alert_fields": {"internal_id": "123"}}, {"alert_fields": {"internal_id": "456"}}]
            },
            {},  # associateIndicatorsToAlert for issue 123
            {},  # associateIndicatorsToAlert for issue 456
        ]

        results = set_indicator_if_exist(args)

        assert len(results) == 2  # One success, one error
        success_result = next(r for r in results if "Successfully associated" in r.readable_output)
        error_result = next(r for r in results if "don't exist" in r.readable_output)

        assert "Successfully associated indicator to the following issues ['123', '456']" in success_result.readable_output
        assert "The following issues were provided as related issues but don't exist: {'999'}" in error_result.readable_output
        assert error_result.entry_type == 4

    @patch("SetIndicatorAgentix.execute_command")
    @patch("SetIndicatorAgentix.argToList")
    def test_all_issues_nonexistent(self, mock_arg_to_list, mock_execute):
        """Test when all provided issues don't exist"""
        args = {"value": "1.1.1.1", "related_issues": "999,888"}
        mock_arg_to_list.return_value = ["999", "888"]

        mock_execute.side_effect = [
            {"data": [{"value": "1.1.1.1"}]},  # findIndicators response
            {"alerts": []},  # core-get-issues response - no issues found
        ]

        results = set_indicator_if_exist(args)

        assert len(results) == 1
        assert results[0].entry_type == 4
        assert "The following issues were provided as related issues but don't exist: " in results[0].readable_output
        assert "888" in results[0].readable_output
        assert "999" in results[0].readable_output

    @patch("SetIndicatorAgentix.execute_command")
    @patch("SetIndicatorAgentix.argToList")
    def test_empty_related_issues_list(self, mock_arg_to_list, mock_execute):
        """Test when related_issues argument is provided but empty"""
        args = {"value": "1.1.1.1", "type": "IP", "related_issues": ""}
        mock_arg_to_list.return_value = []

        mock_execute.side_effect = [
            {"data": [{"value": "1.1.1.1"}]},  # findIndicators response
            {},  # setIndicator response
        ]

        results = set_indicator_if_exist(args)

        assert len(results) == 1
        assert "Successfully set indicator properties" in results[0].readable_output
        assert "associated" not in results[0].readable_output

    @patch("SetIndicatorAgentix.execute_command")
    def test_only_related_issues_argument(self, mock_execute):
        """Test with only related_issues argument (no type, verdict, or tags)"""
        args = {"value": "example.com", "related_issues": "123"}

        with patch("SetIndicatorAgentix.argToList") as mock_arg_to_list:
            mock_arg_to_list.return_value = ["123"]

            mock_execute.side_effect = [
                {"data": [{"value": "example.com"}]},  # findIndicators response
                {  # core-get-issues response
                    "alerts": [{"alert_fields": {"internal_id": "123"}}]
                },
                {},  # associateIndicatorsToAlert response
            ]

            results = set_indicator_if_exist(args)

            assert len(results) == 1
            assert "Successfully associated indicator to the following issues ['123']" in results[0].readable_output
            assert "Successfully set indicator properties" not in results[0].readable_output

    @patch("SetIndicatorAgentix.execute_command")
    def test_multiple_properties_update(self, mock_execute):
        """Test updating multiple properties without related issues"""
        args = {"value": "1.1.1.1", "type": "IP", "verdict": "malicious", "tags": "botnet,malware"}

        mock_execute.side_effect = [
            {"data": [{"value": "1.1.1.1"}]},  # findIndicators response
            {},  # setIndicator response
        ]

        results = set_indicator_if_exist(args)

        assert len(results) == 1
        assert "Successfully set indicator properties" in results[0].readable_output
        assert results[0].outputs["Value"] == "1.1.1.1"

        # Verify setIndicator was called with all properties
        mock_execute.assert_any_call("setIndicator", args)

    @patch("SetIndicatorAgentix.execute_command")
    @patch("SetIndicatorAgentix.argToList")
    def test_core_get_issues_returns_none_alerts(self, mock_arg_to_list, mock_execute):
        """Test when core-get-issues returns structure without alerts key"""
        args = {"value": "1.1.1.1", "related_issues": "123"}
        mock_arg_to_list.return_value = ["123"]

        mock_execute.side_effect = [
            {"data": [{"value": "1.1.1.1"}]},  # findIndicators response
            {},  # core-get-issues response without alerts key
        ]

        results = set_indicator_if_exist(args)

        assert len(results) == 1
        assert results[0].entry_type == 4
        assert "The following issues were provided as related issues but don't exist: {'123'}" in results[0].readable_output

    @patch("SetIndicatorAgentix.execute_command")
    @patch("SetIndicatorAgentix.argToList")
    def test_issue_without_internal_id(self, mock_arg_to_list, mock_execute):
        """Test when issue response doesn't have internal_id field"""
        args = {"value": "example.com", "related_issues": "123"}
        mock_arg_to_list.return_value = ["123"]

        mock_execute.side_effect = [
            {"data": [{"value": "example.com"}]},  # findIndicators response
            {  # core-get-issues response with malformed alert
                "alerts": [
                    {"alert_fields": {}}  # Missing internal_id
                ]
            },
            None,
        ]

        results = set_indicator_if_exist(args)

        assert len(results) == 1
        assert results[0].entry_type == 4
