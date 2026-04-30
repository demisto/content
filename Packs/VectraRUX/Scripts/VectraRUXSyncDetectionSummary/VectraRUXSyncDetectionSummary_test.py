from unittest.mock import patch
from VectraRUXSyncDetectionSummary import handle_error, main, MIRRORING_TAG


class TestHandleError:
    """Test cases for handle_error function."""

    @patch("VectraRUXSyncDetectionSummary.isError")
    @patch("VectraRUXSyncDetectionSummary.return_error")
    def test_handle_error_with_error(self, mock_return_error, mock_is_error):
        """Test handle_error when command results contain an error."""
        mock_is_error.return_value = True
        command_results = [{"Contents": "Error message"}]

        handle_error(command_results)

        mock_is_error.assert_called_once_with(command_results)
        mock_return_error.assert_called_once_with("Error message")

    @patch("VectraRUXSyncDetectionSummary.isError")
    @patch("VectraRUXSyncDetectionSummary.return_error")
    def test_handle_error_without_error(self, mock_return_error, mock_is_error):
        """Test handle_error when command results do not contain an error."""
        mock_is_error.return_value = False
        command_results = [{"Contents": "Success"}]

        handle_error(command_results)

        mock_is_error.assert_called_once_with(command_results)
        mock_return_error.assert_not_called()


class TestMain:
    """Test cases for main function."""

    @patch("VectraRUXSyncDetectionSummary.return_results")
    @patch("VectraRUXSyncDetectionSummary.demisto")
    @patch("VectraRUXSyncDetectionSummary.handle_error")
    @patch("VectraRUXSyncDetectionSummary.CommandResults")
    def test_main_tag_not_present_adds_tag(self, mock_command_results, mock_handle_error, mock_demisto, mock_return_results):
        """Test that tag is added (without remove) when Trigger_XSOAR_Mirroring is not present."""
        detection_id = "123"
        summary_data = {"description": "Test detection", "severity": "high"}

        mock_demisto.incident.return_value = {"CustomFields": {"vectraruxdetectionid": detection_id}}
        mock_demisto.mapObject.return_value = {}
        mock_demisto.executeCommand.side_effect = [
            [{"Contents": {"results": [{"summary": summary_data, "process_context_data": {}}]}}],  # vectra-detection-describe
            [{"Contents": {"tags": ["some_other_tag"]}}],  # vectra-detection-tag-list
            [{"Contents": "Tag added"}],  # vectra-detection-tag-add
            [{"Contents": "Success"}],  # setIncident
        ]
        mock_handle_error.return_value = None

        main()

        mock_demisto.executeCommand.assert_any_call(
            "vectra-detection-tag-add", {"detection_id": detection_id, "tags": MIRRORING_TAG}
        )
        remove_calls = [c for c in mock_demisto.executeCommand.call_args_list if c[0][0] == "vectra-detection-tag-remove"]
        assert len(remove_calls) == 0
        assert mock_demisto.executeCommand.call_count == 4

    @patch("VectraRUXSyncDetectionSummary.return_results")
    @patch("VectraRUXSyncDetectionSummary.demisto")
    @patch("VectraRUXSyncDetectionSummary.handle_error")
    @patch("VectraRUXSyncDetectionSummary.CommandResults")
    def test_main_tag_present_removes_and_readds_tag(
        self, mock_command_results, mock_handle_error, mock_demisto, mock_return_results
    ):
        """Test that tag is removed then re-added when Trigger_XSOAR_Mirroring is already present."""
        detection_id = "123"
        summary_data = {"description": "Test detection", "severity": "high"}

        mock_demisto.incident.return_value = {"CustomFields": {"vectraruxdetectionid": detection_id}}
        mock_demisto.mapObject.return_value = {}
        mock_demisto.executeCommand.side_effect = [
            [{"Contents": {"results": [{"summary": summary_data, "process_context_data": {}}]}}],  # vectra-detection-describe
            [{"Contents": {"tags": [MIRRORING_TAG, "other_tag"]}}],  # vectra-detection-tag-list
            [{"Contents": "Tag removed"}],  # vectra-detection-tag-remove
            [{"Contents": "Tag added"}],  # vectra-detection-tag-add
            [{"Contents": "Success"}],  # setIncident
        ]
        mock_handle_error.return_value = None

        main()

        mock_demisto.executeCommand.assert_any_call(
            "vectra-detection-tag-remove", {"detection_id": detection_id, "tags": MIRRORING_TAG}
        )
        mock_demisto.executeCommand.assert_any_call(
            "vectra-detection-tag-add", {"detection_id": detection_id, "tags": MIRRORING_TAG}
        )
        assert mock_demisto.executeCommand.call_count == 5

    @patch("VectraRUXSyncDetectionSummary.return_results")
    @patch("VectraRUXSyncDetectionSummary.demisto")
    @patch("VectraRUXSyncDetectionSummary.handle_error")
    @patch("VectraRUXSyncDetectionSummary.CommandResults")
    def test_main_tag_present_remove_called_before_add(
        self, mock_command_results, mock_handle_error, mock_demisto, mock_return_results
    ):
        """Test that remove is called before add when tag is already present."""
        detection_id = "123"

        mock_demisto.incident.return_value = {"CustomFields": {"vectraruxdetectionid": detection_id}}
        mock_demisto.mapObject.return_value = {}
        mock_demisto.executeCommand.side_effect = [
            [{"Contents": {"results": [{"summary": {}, "process_context_data": {}}]}}],
            [{"Contents": {"tags": [MIRRORING_TAG]}}],
            [{"Contents": "Tag removed"}],
            [{"Contents": "Tag added"}],
            [{"Contents": "Success"}],
        ]
        mock_handle_error.return_value = None

        main()

        command_names = [c[0][0] for c in mock_demisto.executeCommand.call_args_list]
        remove_idx = command_names.index("vectra-detection-tag-remove")
        add_idx = command_names.index("vectra-detection-tag-add")
        assert remove_idx < add_idx

    @patch("VectraRUXSyncDetectionSummary.return_results")
    @patch("VectraRUXSyncDetectionSummary.demisto")
    @patch("VectraRUXSyncDetectionSummary.handle_error")
    @patch("VectraRUXSyncDetectionSummary.CommandResults")
    def test_main_empty_tag_list_adds_tag(self, mock_command_results, mock_handle_error, mock_demisto, mock_return_results):
        """Test that tag is added when detection has no existing tags."""
        detection_id = "456"

        mock_demisto.incident.return_value = {"CustomFields": {"vectraruxdetectionid": detection_id}}
        mock_demisto.mapObject.return_value = {}
        mock_demisto.executeCommand.side_effect = [
            [{"Contents": {"results": []}}],
            [{"Contents": {"tags": []}}],
            [{"Contents": "Tag added"}],
            [{"Contents": "Success"}],
        ]
        mock_handle_error.return_value = None

        main()

        mock_demisto.executeCommand.assert_any_call(
            "vectra-detection-tag-add", {"detection_id": detection_id, "tags": MIRRORING_TAG}
        )
        remove_calls = [c for c in mock_demisto.executeCommand.call_args_list if c[0][0] == "vectra-detection-tag-remove"]
        assert len(remove_calls) == 0

    @patch("VectraRUXSyncDetectionSummary.return_results")
    @patch("VectraRUXSyncDetectionSummary.demisto")
    @patch("VectraRUXSyncDetectionSummary.handle_error")
    @patch("VectraRUXSyncDetectionSummary.CommandResults")
    def test_main_success_with_detection_summary(
        self, mock_command_results, mock_handle_error, mock_demisto, mock_return_results
    ):
        """Test main function successfully retrieves and sets detection summary."""
        detection_id = "123"
        summary_data = {"description": "Test detection", "severity": "high"}

        mock_demisto.incident.return_value = {"CustomFields": {"vectraruxdetectionid": detection_id}}
        mock_demisto.mapObject.return_value = {}
        mock_demisto.executeCommand.side_effect = [
            [{"Contents": {"results": [{"summary": summary_data, "process_context_data": {}}]}}],
            [{"Contents": {"tags": []}}],
            [{"Contents": "Tag added"}],
            [{"Contents": "Success"}],
        ]
        mock_handle_error.return_value = None

        main()

        mock_demisto.incident.assert_called_once()
        mock_demisto.executeCommand.assert_any_call("vectra-detection-describe", {"detection_ids": detection_id})
        mock_demisto.executeCommand.assert_any_call("vectra-detection-tag-list", {"detection_id": detection_id})
        mock_demisto.executeCommand.assert_any_call(
            "vectra-detection-tag-add", {"detection_id": detection_id, "tags": MIRRORING_TAG}
        )
        mock_demisto.executeCommand.assert_any_call("setIncident", {"details": summary_data})
        mock_command_results.assert_called_once_with(
            readable_output="Detection has been synchronized successfully with EDR process context and summary."
        )

    @patch("VectraRUXSyncDetectionSummary.return_results")
    @patch("VectraRUXSyncDetectionSummary.demisto")
    @patch("VectraRUXSyncDetectionSummary.handle_error")
    @patch("VectraRUXSyncDetectionSummary.CommandResults")
    def test_main_success_with_empty_result(self, mock_command_results, mock_handle_error, mock_demisto, mock_return_results):
        """Test main function when detection result is empty."""
        detection_id = "456"

        mock_demisto.incident.return_value = {"CustomFields": {"vectraruxdetectionid": detection_id}}
        mock_demisto.mapObject.return_value = {}
        mock_demisto.executeCommand.side_effect = [
            [{"Contents": {"results": []}}],
            [{"Contents": {"tags": []}}],
            [{"Contents": "Tag added"}],
            [{"Contents": "Success"}],
        ]
        mock_handle_error.return_value = None

        main()

        mock_demisto.executeCommand.assert_any_call("setIncident", {"details": {}})
        mock_command_results.assert_called_once_with(
            readable_output="Detection has been synchronized successfully with EDR process context and summary."
        )

    @patch("VectraRUXSyncDetectionSummary.return_results")
    @patch("VectraRUXSyncDetectionSummary.demisto")
    @patch("VectraRUXSyncDetectionSummary.handle_error")
    @patch("VectraRUXSyncDetectionSummary.CommandResults")
    def test_main_success_with_non_dict_contents(
        self, mock_command_results, mock_handle_error, mock_demisto, mock_return_results
    ):
        """Test main function when vectra-detection-describe returns non-dict contents."""
        detection_id = "789"

        mock_demisto.incident.return_value = {"CustomFields": {"vectraruxdetectionid": detection_id}}
        mock_demisto.mapObject.return_value = {}
        mock_demisto.executeCommand.side_effect = [
            [{"Contents": "error string"}],
            [{"Contents": {"tags": []}}],
            [{"Contents": "Tag added"}],
            [{"Contents": "Success"}],
        ]
        mock_handle_error.return_value = None

        main()

        mock_demisto.executeCommand.assert_any_call("setIncident", {"details": {}})
        mock_command_results.assert_called_once_with(
            readable_output="Detection has been synchronized successfully with EDR process context and summary."
        )

    @patch("VectraRUXSyncDetectionSummary.return_results")
    @patch("VectraRUXSyncDetectionSummary.demisto")
    @patch("VectraRUXSyncDetectionSummary.handle_error")
    @patch("VectraRUXSyncDetectionSummary.CommandResults")
    def test_main_success_with_detection_without_summary(
        self, mock_command_results, mock_handle_error, mock_demisto, mock_return_results
    ):
        """Test main function when detection does not have a summary field."""
        detection_id = "101"

        mock_demisto.incident.return_value = {"CustomFields": {"vectraruxdetectionid": detection_id}}
        mock_demisto.mapObject.return_value = {}
        mock_demisto.executeCommand.side_effect = [
            [{"Contents": {"results": [{"id": "101", "name": "Test Detection"}]}}],
            [{"Contents": {"tags": []}}],
            [{"Contents": "Tag added"}],
            [{"Contents": "Success"}],
        ]
        mock_handle_error.return_value = None

        main()

        mock_demisto.executeCommand.assert_any_call("setIncident", {"details": {}})
        mock_command_results.assert_called_once_with(
            readable_output="Detection has been synchronized successfully with EDR process context and summary."
        )

    @patch("VectraRUXSyncDetectionSummary.demisto")
    @patch("VectraRUXSyncDetectionSummary.handle_error")
    @patch("VectraRUXSyncDetectionSummary.return_error")
    def test_main_handles_command_error(self, mock_return_error, mock_handle_error, mock_demisto):
        """Test main function handles errors raised by handle_error during command execution."""
        detection_id = "999"

        mock_demisto.incident.return_value = {"CustomFields": {"vectraruxdetectionid": detection_id}}
        mock_demisto.executeCommand.return_value = [{"Type": 4, "Contents": "Command execution failed"}]
        mock_handle_error.side_effect = Exception("Command error")

        main()

        mock_return_error.assert_called_once()
        assert "Failed to execute VectraRUXSyncDetectionSummary" in str(mock_return_error.call_args)

    @patch("VectraRUXSyncDetectionSummary.demisto")
    @patch("VectraRUXSyncDetectionSummary.return_error")
    def test_main_handles_missing_detection_id(self, mock_return_error, mock_demisto):
        """Test main function handles missing detection ID in custom fields."""
        mock_demisto.incident.return_value = {"CustomFields": {}}
        mock_demisto.mapObject.return_value = {}
        mock_demisto.executeCommand.side_effect = [
            [{"Contents": {"results": []}}],
            [{"Contents": {"tags": []}}],
            [{"Contents": "Tag added"}],
            [{"Contents": "Success"}],
        ]

        main()

        assert mock_demisto.executeCommand.call_count >= 1

    @patch("VectraRUXSyncDetectionSummary.demisto")
    @patch("VectraRUXSyncDetectionSummary.return_error")
    @patch("VectraRUXSyncDetectionSummary.traceback")
    def test_main_handles_exception(self, mock_traceback, mock_return_error, mock_demisto):
        """Test main function handles unexpected exceptions."""
        mock_demisto.incident.side_effect = Exception("Unexpected error")
        mock_traceback.format_exc.return_value = "Traceback details"

        main()

        mock_demisto.error.assert_called_once_with("Traceback details")
        mock_return_error.assert_called_once()
        assert "Failed to execute VectraRUXSyncDetectionSummary" in str(mock_return_error.call_args)
