from unittest.mock import patch
from UpdateIssue import main


class TestUpdateIssueMain:
    @patch("UpdateIssue.demisto")
    @patch("UpdateIssue.execute_command")
    @patch("UpdateIssue.return_results")
    def test_main_with_set_issue_args_only(self, mock_return_results, mock_execute_command, mock_demisto):
        """Test main function when only setIssue arguments are provided"""
        # Arrange
        mock_demisto.args.return_value = {"id": "123", "systems": "test-system"}

        # Act
        main()

        # Assert
        mock_execute_command.assert_called_once_with("setIssue", {"id": "123", "systems": "test-system"})
        mock_return_results.assert_called_once_with("done")
        mock_demisto.debug.assert_called_once()

    @patch("UpdateIssue.demisto")
    @patch("UpdateIssue.execute_command")
    @patch("UpdateIssue.return_results")
    def test_main_with_update_issue_args_only(self, mock_return_results, mock_execute_command, mock_demisto):
        """Test main function when only core-update-issue arguments are provided"""
        # Arrange
        mock_demisto.args.return_value = {"id": "123", "name": "Updated Issue", "severity": "High"}

        # Act
        main()

        # Assert
        mock_execute_command.assert_called_once_with(
            "core-update-issue", {"id": "123", "name": "Updated Issue", "severity": "High"}
        )
        mock_return_results.assert_called_once_with("done")
        mock_demisto.debug.assert_called_once()

    @patch("UpdateIssue.demisto")
    @patch("UpdateIssue.execute_command")
    @patch("UpdateIssue.return_results")
    def test_main_with_both_command_args(self, mock_return_results, mock_execute_command, mock_demisto):
        """Test main function when both setIssue and core-update-issue arguments are provided"""
        # Arrange
        mock_demisto.args.return_value = {
            "id": "123",
            "systems": "test-system",
            "type": "incident",
            "name": "Updated Issue",
            "severity": "High",
        }

        # Act
        main()

        # Assert
        assert mock_execute_command.call_count == 2
        mock_execute_command.assert_any_call("setIssue", {"id": "123", "systems": "test-system"})
        mock_execute_command.assert_any_call(
            "core-update-issue", {"id": "123", "name": "Updated Issue", "severity": "High", "type": "incident"}
        )
        mock_return_results.assert_called_once_with("done")
        assert mock_demisto.debug.call_count == 2

    @patch("UpdateIssue.demisto")
    @patch("UpdateIssue.return_error")
    def test_main_with_no_update_args(self, mock_return_error, mock_demisto):
        """Test main function when only id is provided (no update arguments)"""
        # Arrange
        mock_demisto.args.return_value = {"id": "123"}

        # Act
        main()

        # Assert
        mock_return_error.assert_called_once_with("Please provide arguments to update the issue.")

    @patch("UpdateIssue.demisto")
    @patch("UpdateIssue.return_error")
    def test_main_with_empty_args(self, mock_return_error, mock_demisto):
        """Test main function when no arguments are provided"""
        # Arrange
        mock_demisto.args.return_value = {}

        # Act
        main()

        # Assert
        mock_return_error.assert_called_once_with("Please provide arguments to update the issue.")

    @patch("UpdateIssue.demisto")
    @patch("UpdateIssue.execute_command")
    @patch("UpdateIssue.return_error")
    def test_main_with_execute_command_exception(self, mock_return_error, mock_execute_command, mock_demisto):
        """Test main function when execute_command raises an exception"""
        # Arrange
        mock_demisto.args.return_value = {"id": "123", "systems": "test-system"}
        mock_execute_command.side_effect = Exception("Command execution failed")

        # Act
        main()

        # Assert
        mock_return_error.assert_called_once_with("Failed to execute script.\nError:\nCommand execution failed")

    @patch("UpdateIssue.demisto")
    @patch("UpdateIssue.execute_command")
    @patch("UpdateIssue.return_results")
    def test_main_without_id(self, mock_return_results, mock_execute_command, mock_demisto):
        """Test main function when no id is provided but other arguments are present"""
        # Arrange
        mock_demisto.args.return_value = {"systems": "test-system", "name": "New Issue"}

        # Act
        main()

        # Assert
        assert mock_execute_command.call_count == 2
        mock_execute_command.assert_any_call("setIssue", {"systems": "test-system", "id": None})
        mock_execute_command.assert_any_call("core-update-issue", {"name": "New Issue", "id": None})
        mock_return_results.assert_called_once_with("done")

    @patch("UpdateIssue.demisto")
    @patch("UpdateIssue.execute_command")
    @patch("UpdateIssue.return_results")
    def test_main_with_all_possible_args(self, mock_return_results, mock_execute_command, mock_demisto):
        """Test main function with all possible arguments"""
        # Arrange
        mock_demisto.args.return_value = {
            "id": "123",
            # setIssue args
            "systems": "test-system",
            # core-update-issue args
            "name": "Updated Issue",
            "assigned_user_mail": "user@example.com",
            "severity": "High",
            "occurred": "2023-01-01",
            "phase": "Investigation",
            "type": "incident",
            "description": "Test details",
        }

        # Act
        main()

        # Assert
        assert mock_execute_command.call_count == 2
        mock_execute_command.assert_any_call(
            "setIssue",
            {
                "id": "123",
                "systems": "test-system",
            },
        )
        mock_execute_command.assert_any_call(
            "core-update-issue",
            {
                "id": "123",
                "name": "Updated Issue",
                "assigned_user_mail": "user@example.com",
                "severity": "High",
                "occurred": "2023-01-01",
                "phase": "Investigation",
                "type": "incident",
                "description": "Test details",
            },
        )
        mock_return_results.assert_called_once_with("done")
