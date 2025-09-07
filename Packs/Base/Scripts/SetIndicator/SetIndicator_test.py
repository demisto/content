from SetIndicator import set_indicator_if_exist


class TestSetIndicatorIfExist:
    """Test cases for set_indicator_if_exist function"""

    def test_set_indicator_if_exist_success_with_all_fields(self, mocker):
        """
        Given:
        - Valid args with type, verdict, tags, and related_issues
        - Indicator exists in the system
        - All related issues exist
        When:
        - Executing set_indicator_if_exist function
        Then:
        - Should call findIndicators, setIndicator, core-get-issues, and associateIndicatorsToAlert
        - Should return success message
        """
        args = {
            "value": "test-indicator",
            "type": "IP",
            "verdict": "Malicious",
            "tags": ["tag1", "tag2"],
            "related_issues": ["issue1", "issue2"],
        }

        # Mock demisto functions
        mock_demisto = mocker.patch("SetIndicator.demisto")
        mock_demisto.executeCommand.return_value = [{"value": "test-indicator"}]  # Indicator exists

        # Mock execute_command calls
        mock_execute_command = mocker.patch("SetIndicator.execute_command")
        # mock_execute_command.return_value = {"result_count": 2}  # Simulating core-get-issues response
        mock_execute_command.side_effect = [
            None,  # setIndicator response
            {"result_count": 2},  # core-get-issues response
            None,  # associateIndicatorsToAlert response,
            None,  # associateIndicatorsToAlert response for the second issue
        ]

        # Mock argToList
        mock_arg_to_list = mocker.patch("SetIndicator.argToList")
        mock_arg_to_list.return_value = ["issue1", "issue2"]

        result = set_indicator_if_exist(args)

        # Verify all calls were made
        mock_demisto.executeCommand.assert_called_once_with("findIndicators", {"value": "test-indicator"})

        expected_execute_calls = [
            mocker.call("setIndicator", args),
            mocker.call("core-get-issues", {"issue_id": ["issue1", "issue2"]}),
            mocker.call("associateIndicatorsToAlert", {"issueId": "issue1", "indicatorsValues": "test-indicator"}),
            mocker.call("associateIndicatorsToAlert", {"issueId": "issue2", "indicatorsValues": "test-indicator"}),
        ]
        mock_execute_command.assert_has_calls(expected_execute_calls)

        assert result.readable_output == "Successfully set indicator."

    def test_set_indicator_if_exist_only_type_verdict_tags(self, mocker):
        """
        Given:
        - Args with only type, verdict, and tags (no related_issues)
        - Indicator exists in the system
        When:
        - Executing set_indicator_if_exist function
        Then:
        - Should call setIndicator but not issue-related commands
        - Should return success message
        """
        args = {"value": "test-indicator", "type": "IP", "verdict": "Malicious", "tags": ["tag1"]}

        mock_demisto = mocker.patch("SetIndicator.demisto")
        mock_demisto.executeCommand.return_value = [{"value": "test-indicator"}]

        mock_execute_command = mocker.patch("SetIndicator.execute_command")
        mocker.patch("SetIndicator.argToList", return_value=[])

        result = set_indicator_if_exist(args)

        mock_demisto.executeCommand.assert_called_once_with("findIndicators", {"value": "test-indicator"})
        mock_execute_command.assert_called_once_with("setIndicator", args)

        assert result.readable_output == "Successfully set indicator."

    def test_set_indicator_if_exist_only_related_issues(self, mocker):
        """
        Given:
        - Args with only related_issues (no type, verdict, or tags)
        - Indicator exists in the system
        - Related issues exist
        When:
        - Executing set_indicator_if_exist function
        Then:
        - Should not call setIndicator but should call issue-related commands
        - Should return success message
        """
        args = {"value": "test-indicator", "related_issues": ["issue1"]}

        mock_demisto = mocker.patch("SetIndicator.demisto")
        mock_demisto.executeCommand.return_value = [{"value": "test-indicator"}]

        mock_execute_command = mocker.patch("SetIndicator.execute_command")
        mock_execute_command.side_effect = [
            {"result_count": 1},  # core-get-issues response
            None,  # associateIndicatorsToAlert response
        ]

        mocker.patch("SetIndicator.argToList", return_value=["issue1"])

        result = set_indicator_if_exist(args)

        # Verify setIndicator was NOT called (no type, verdict, or tags)
        calls = [call for call in mock_execute_command.call_args_list if call[0][0] == "setIndicator"]
        assert len(calls) == 0

        # Verify issue-related calls were made
        mock_execute_command.assert_any_call("core-get-issues", {"issue_id": ["issue1"]})
        mock_execute_command.assert_any_call(
            "associateIndicatorsToAlert", {"issueId": "issue1", "indicatorsValues": "test-indicator"}
        )

        assert result.readable_output == "Successfully set indicator."

    def test_set_indicator_if_exist_no_valid_args(self, mocker):
        """
        Given:
        - Args without type, verdict, tags, or related_issues
        When:
        - Executing set_indicator_if_exist function
        Then:
        - Should call return_error with appropriate message
        """
        args = {"value": "test-indicator", "other_field": "some_value"}
        mock_demisto = mocker.patch("SetIndicator.demisto")
        mock_demisto.executeCommand.return_value = {"result_count": 1}
        mock_return_error = mocker.patch("SetIndicator.return_error")

        set_indicator_if_exist(args)

        mock_return_error.assert_called_once_with(
            "Please provide at lease one argument to update: type, verdict, tags, or related_issues."
        )

    def test_set_indicator_if_exist_indicator_not_exists(self, mocker):
        """
        Given:
        - Valid args but indicator does not exist
        When:
        - Executing set_indicator_if_exist function
        Then:
        - Should call return_error with indicator not exists message
        """
        args = {"value": "nonexistent-indicator", "type": "IP"}

        mock_demisto = mocker.patch("SetIndicator.demisto")
        mock_demisto.executeCommand.return_value = []  # No indicators found

        mock_return_error = mocker.patch("SetIndicator.return_error")

        set_indicator_if_exist(args)

        mock_demisto.executeCommand.assert_called_once_with("findIndicators", {"value": "nonexistent-indicator"})
        mock_return_error.assert_called_once_with("Indicator does not exist.")

    def test_set_indicator_if_exist_indicator_not_exists_none_response(self, mocker):
        """
        Given:
        - Valid args but findIndicators returns None
        When:
        - Executing set_indicator_if_exist function
        Then:
        - Should call return_error with indicator not exists message
        """
        args = {"value": "test-indicator", "type": "IP"}

        mock_demisto = mocker.patch("SetIndicator.demisto")
        mock_demisto.executeCommand.return_value = None

        mock_return_error = mocker.patch("SetIndicator.return_error")

        set_indicator_if_exist(args)

        mock_return_error.assert_called_once_with("Indicator does not exist.")

    def test_set_indicator_if_exist_related_issues_not_found(self, mocker):
        """
        Given:
        - Valid args with related_issues but some issues don't exist
        - Indicator exists in the system
        When:
        - Executing set_indicator_if_exist function
        Then:
        - Should call return_error about missing issues
        """
        args = {"value": "test-indicator", "type": "IP", "related_issues": ["issue1", "issue2", "issue3"]}

        mock_demisto = mocker.patch("SetIndicator.demisto")
        mock_demisto.executeCommand.return_value = [{"value": "test-indicator"}]

        mock_execute_command = mocker.patch("SetIndicator.execute_command")
        mock_execute_command.side_effect = [
            None,  # setIndicator response
            {"result_count": 2},  # core-get-issues response - only 2 out of 3 issues found
        ]

        mocker.patch("SetIndicator.argToList", return_value=["issue1", "issue2", "issue3"])
        mock_return_error = mocker.patch("SetIndicator.return_error")

        set_indicator_if_exist(args)

        mock_execute_command.assert_any_call("setIndicator", args)
        mock_execute_command.assert_any_call("core-get-issues", {"issue_id": ["issue1", "issue2", "issue3"]})
        mock_return_error.assert_called_once_with("One or more related issues do not exist.")

    def test_set_indicator_if_exist_empty_related_issues(self, mocker):
        """
        Given:
        - Args with related_issues that evaluates to empty list
        - Indicator exists in the system
        When:
        - Executing set_indicator_if_exist function
        Then:
        - Should not process related issues but still call setIndicator
        """
        args = {
            "value": "test-indicator",
            "type": "IP",
            "related_issues": "",  # Empty string
        }

        mock_demisto = mocker.patch("SetIndicator.demisto")
        mock_demisto.executeCommand.return_value = [{"value": "test-indicator"}]

        mock_execute_command = mocker.patch("SetIndicator.execute_command")
        mocker.patch("SetIndicator.argToList", return_value=[])  # Empty list

        result = set_indicator_if_exist(args)

        # Should only call setIndicator, not issue-related commands
        mock_execute_command.assert_called_once_with("setIndicator", args)

        assert result.readable_output == "Successfully set indicator."

    def test_set_indicator_if_exist_individual_field_combinations(self, mocker):
        """
        Given:
        - Different combinations of type, verdict, and tags
        When:
        - Executing set_indicator_if_exist function
        Then:
        - Should call setIndicator for any combination of these fields
        """
        mock_demisto = mocker.patch("SetIndicator.demisto")
        mock_demisto.executeCommand.return_value = [{"value": "test-indicator"}]

        mock_execute_command = mocker.patch("SetIndicator.execute_command")
        mocker.patch("SetIndicator.argToList", return_value=[])

        # Test with only type
        args = {"value": "test-indicator", "type": "IP"}
        result = set_indicator_if_exist(args)
        mock_execute_command.assert_called_with("setIndicator", args)
        assert result.readable_output == "Successfully set indicator."

        # Reset mock
        mock_execute_command.reset_mock()

        # Test with only verdict
        args = {"value": "test-indicator", "verdict": "Malicious"}
        result = set_indicator_if_exist(args)
        mock_execute_command.assert_called_with("setIndicator", args)
        assert result.readable_output == "Successfully set indicator."

        # Reset mock
        mock_execute_command.reset_mock()

        # Test with only tags
        args = {"value": "test-indicator", "tags": ["tag1"]}
        result = set_indicator_if_exist(args)
        mock_execute_command.assert_called_with("setIndicator", args)
        assert result.readable_output == "Successfully set indicator."

    def test_set_indicator_if_exist_debug_logging(self, mocker):
        """
        Given:
        - Valid args with related_issues
        - Indicator exists and issues exist
        When:
        - Executing set_indicator_if_exist function
        Then:
        - Should call demisto.debug with appropriate messages
        """
        args = {"value": "test-indicator", "type": "IP", "related_issues": ["issue1"]}

        mock_demisto = mocker.patch("SetIndicator.demisto")
        mock_demisto.executeCommand.return_value = [{"value": "test-indicator"}]

        mock_execute_command = mocker.patch("SetIndicator.execute_command")
        mock_execute_command.side_effect = [
            None,  # setIndicator
            {"result_count": 1},  # core-get-issues
            None,  # associateIndicatorsToAlert
        ]

        mocker.patch("SetIndicator.argToList", return_value=["issue1"])

        set_indicator_if_exist(args)

        # Verify debug calls were made
        debug_calls = mock_demisto.debug.call_args_list
        assert len(debug_calls) >= 3  # At least 3 debug calls should be made

        # Check specific debug messages
        debug_messages = [call[0][0] for call in debug_calls]
        assert any("Checking if test-indicator exists" in msg for msg in debug_messages)
        assert any("running setIndicator command" in msg for msg in debug_messages)
        assert any("Number issues found: 1" in msg for msg in debug_messages)
        assert any("running associateIndicatorsToAlert command with issue id issue1" in msg for msg in debug_messages)
