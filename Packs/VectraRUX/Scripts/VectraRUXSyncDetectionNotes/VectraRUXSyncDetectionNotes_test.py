from unittest.mock import patch
from VectraRUXSyncDetectionNotes import handle_error, main


class TestHandleError:
    """Test cases for handle_error function."""

    @patch("VectraRUXSyncDetectionNotes.isError")
    @patch("VectraRUXSyncDetectionNotes.return_error")
    def test_handle_error_with_error(self, mock_return_error, mock_is_error):
        """Test handle_error when command results contain an error."""
        mock_is_error.return_value = True
        command_results = [{"Contents": "Error message"}]

        handle_error(command_results)

        mock_is_error.assert_called_once_with(command_results)
        mock_return_error.assert_called_once_with("Error message")

    @patch("VectraRUXSyncDetectionNotes.isError")
    @patch("VectraRUXSyncDetectionNotes.return_error")
    def test_handle_error_without_error(self, mock_return_error, mock_is_error):
        """Test handle_error when command results do not contain an error."""
        mock_is_error.return_value = False
        command_results = [{"Contents": "Success"}]

        handle_error(command_results)

        mock_is_error.assert_called_once_with(command_results)
        mock_return_error.assert_not_called()


class TestMain:
    """Test cases for main function."""

    @patch("VectraRUXSyncDetectionNotes.demisto")
    @patch("VectraRUXSyncDetectionNotes.handle_error")
    @patch("VectraRUXSyncDetectionNotes.return_results")
    @patch("VectraRUXSyncDetectionNotes.EntryFormat")
    @patch("VectraRUXSyncDetectionNotes.EntryType")
    def test_main_success_with_single_note(
        self, mock_entry_type, mock_entry_format, mock_return_results, mock_handle_error, mock_demisto
    ):
        """Test main function with a single detection note."""
        detection_id = "456"
        notes_data = [{"created_by": "admin@example.com", "date_created": "2024-03-16T12:00:00", "note": "Single note content"}]

        mock_demisto.incident.return_value = {"CustomFields": {"vectraruxdetectionid": detection_id}}
        mock_demisto.executeCommand.return_value = [{"Contents": notes_data}]
        mock_handle_error.return_value = None
        mock_entry_format.MARKDOWN = "markdown"
        mock_entry_type.NOTE = 1

        main()

        mock_return_results.assert_called_once()
        call_args = mock_return_results.call_args[0][0]
        assert "admin@example.com" in call_args["Contents"]
        assert "Single note content" in call_args["Contents"]

    @patch("VectraRUXSyncDetectionNotes.demisto")
    @patch("VectraRUXSyncDetectionNotes.handle_error")
    @patch("VectraRUXSyncDetectionNotes.return_results")
    def test_main_success_with_empty_notes(self, mock_return_results, mock_handle_error, mock_demisto):
        """Test main function when no notes are returned."""
        detection_id = "789"

        mock_demisto.incident.return_value = {"CustomFields": {"vectraruxdetectionid": detection_id}}
        mock_demisto.executeCommand.return_value = [{"Contents": []}]
        mock_handle_error.return_value = None

        main()

        mock_demisto.executeCommand.assert_called_once_with("vectra-detection-note-list", {"detection_id": detection_id})
        mock_return_results.assert_called_once()
        call_args = mock_return_results.call_args[0][0]
        assert call_args == "Detection notes already synchronized."

    @patch("VectraRUXSyncDetectionNotes.demisto")
    @patch("VectraRUXSyncDetectionNotes.handle_error")
    @patch("VectraRUXSyncDetectionNotes.return_results")
    def test_main_handles_missing_detection_id(self, mock_return_results, mock_handle_error, mock_demisto):
        """Test main function handles missing detection ID in custom fields."""
        mock_demisto.incident.return_value = {"CustomFields": {}}
        mock_demisto.executeCommand.return_value = [{"Contents": []}]
        mock_handle_error.return_value = None

        main()

        mock_demisto.executeCommand.assert_called_once_with("vectra-detection-note-list", {"detection_id": ""})

    @patch("VectraRUXSyncDetectionNotes.demisto")
    @patch("VectraRUXSyncDetectionNotes.handle_error")
    @patch("VectraRUXSyncDetectionNotes.return_error")
    def test_main_handles_command_error(self, mock_return_error, mock_handle_error, mock_demisto):
        """Test main function handles errors from vectra-detection-note-list command."""
        detection_id = "999"

        mock_demisto.incident.return_value = {"CustomFields": {"vectraruxdetectionid": detection_id}}
        mock_demisto.executeCommand.return_value = [{"Type": 4, "Contents": "Command execution failed"}]
        mock_handle_error.side_effect = Exception("Command error")

        main()

        mock_return_error.assert_called_once()
        assert "Failed to execute VectraRUXSyncDetectionNotes" in str(mock_return_error.call_args)

    @patch("VectraRUXSyncDetectionNotes.demisto")
    @patch("VectraRUXSyncDetectionNotes.return_error")
    @patch("VectraRUXSyncDetectionNotes.traceback")
    def test_main_handles_exception(self, mock_traceback, mock_return_error, mock_demisto):
        """Test main function handles unexpected exceptions."""
        mock_demisto.incident.side_effect = Exception("Unexpected error")
        mock_traceback.format_exc.return_value = "Traceback details"

        main()

        mock_demisto.error.assert_called_once_with("Traceback details")
        mock_return_error.assert_called_once()
        assert "Failed to execute VectraRUXSyncDetectionNotes" in str(mock_return_error.call_args)

    @patch("VectraRUXSyncDetectionNotes.demisto")
    @patch("VectraRUXSyncDetectionNotes.handle_error")
    @patch("VectraRUXSyncDetectionNotes.return_results")
    @patch("VectraRUXSyncDetectionNotes.EntryFormat")
    @patch("VectraRUXSyncDetectionNotes.EntryType")
    def test_main_note_formatting(self, mock_entry_type, mock_entry_format, mock_return_results, mock_handle_error, mock_demisto):
        """Test that notes are formatted correctly with all required fields."""
        detection_id = "303"
        notes_data = [
            {
                "created_by": "test@vectra.ai",
                "date_created": "2024-03-16T08:00:00",
                "note": "Test note with special characters: @#$%",
            }
        ]

        mock_demisto.incident.return_value = {"CustomFields": {"vectraruxdetectionid": detection_id}}
        mock_demisto.executeCommand.return_value = [{"Contents": notes_data}]
        mock_handle_error.return_value = None
        mock_entry_format.MARKDOWN = "markdown"
        mock_entry_type.NOTE = 1

        main()

        mock_return_results.assert_called_once()
        call_args = mock_return_results.call_args[0][0]

        assert call_args["ContentsFormat"] == "markdown"
        assert call_args["Type"] == 1
        assert call_args["Note"] is True
        assert "[Fetched From Vectra]" in call_args["Contents"]
        assert "Added By: test@vectra.ai" in call_args["Contents"]
        assert "Added At: 2024-03-16T08:00:00 UTC" in call_args["Contents"]
        assert "Note: Test note with special characters: @#$%" in call_args["Contents"]
