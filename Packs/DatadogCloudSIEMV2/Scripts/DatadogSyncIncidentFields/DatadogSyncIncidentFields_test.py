import demistomock as demisto
import pytest


@pytest.fixture
def mock_incident():
    """Fixture providing a mock incident with Datadog Security Signal ID."""
    return {
        "CustomFields": {"datadogcloudsiemv2securitysignalid": "test-signal-id-123"}
    }


@pytest.fixture
def mock_signal_data():
    """Fixture providing mock security signal data from Datadog."""
    return {
        "id": "test-signal-id-123",
        "attributes": {
            "message": "Test security signal",
            "severity": "high",
            "state": "open",
        },
        "triage": {"state": "open", "assignee": {"name": "john.doe@example.com"}},
    }


@pytest.fixture
def mock_archived_signal_data():
    """Fixture providing mock archived security signal data."""
    return {
        "id": "test-signal-id-123",
        "attributes": {
            "message": "Test security signal",
            "severity": "high",
            "state": "archived",
        },
        "triage": {
            "state": "archived",
            "archive_reason": "false_positive",
            "archive_comment": "This was a false positive detection",
            "assignee": {"name": "john.doe@example.com"},
        },
    }


class TestDatadogSyncIncidentFields:
    """Test class for DatadogSyncIncidentFields script."""

    def test_sync_incident_fields_success(
        self, mocker, mock_incident, mock_signal_data
    ):
        """Test successful synchronization of incident fields.

        Given: An incident with a valid Datadog Security Signal ID
        When: The script executes and successfully fetches signal data
        Then: Incident fields should be updated with the signal data
        """
        mocker.patch.object(demisto, "incident", return_value=mock_incident)
        mocker.patch.object(
            demisto,
            "executeCommand",
            side_effect=[
                [{"Type": 1, "Contents": mock_signal_data}],  # datadog-signal-get
                {},  # setIncident
                {},  # setOwner
            ],
        )
        mocker.patch.object(
            demisto,
            "mapObject",
            return_value={
                "datadogcloudsiemv2securitysignalid": "test-signal-id-123",
                "datadogcloudsiemv2securitysignalmessage": "Test security signal",
                "datadogcloudsiemv2securitysignalseverity": "high",
            },
        )
        mocker.patch("DatadogSyncIncidentFields.isError", return_value=False)
        mock_results = mocker.patch("DatadogSyncIncidentFields.return_results")

        from DatadogSyncIncidentFields import main

        main()

        mock_results.assert_called_once()
        result = mock_results.call_args[0][0]
        assert "Successfully synced incident fields" in result.readable_output

    def test_no_signal_id_in_incident(self, mocker):
        """Test error handling when incident has no signal ID.

        Given: An incident without a Datadog Security Signal ID
        When: The script executes
        Then: An error should be returned indicating no signal ID was found
        """
        incident_without_id = {"CustomFields": {}}
        mocker.patch.object(demisto, "incident", return_value=incident_without_id)
        mock_error = mocker.patch(
            "DatadogSyncIncidentFields.return_error", side_effect=SystemExit(0)
        )

        from DatadogSyncIncidentFields import main

        with pytest.raises(SystemExit):
            main()

        mock_error.assert_called_once()
        assert "No Datadog Security Signal ID found" in mock_error.call_args[0][0]

    def test_failed_to_fetch_signal(self, mocker, mock_incident):
        """Test error handling when fetching signal fails.

        Given: An incident with a valid signal ID
        When: The datadog-signal-get command fails
        Then: An error should be returned indicating fetch failure
        """
        mocker.patch.object(demisto, "incident", return_value=mock_incident)
        mocker.patch.object(
            demisto,
            "executeCommand",
            return_value=[{"Type": 4, "Contents": "API Error"}],
        )
        mocker.patch("DatadogSyncIncidentFields.isError", return_value=True)
        mocker.patch("DatadogSyncIncidentFields.get_error", return_value="API Error")
        mock_error = mocker.patch(
            "DatadogSyncIncidentFields.return_error", side_effect=SystemExit(0)
        )

        from DatadogSyncIncidentFields import main

        with pytest.raises(SystemExit):
            main()

        mock_error.assert_called_once()
        assert "Failed to fetch signal" in mock_error.call_args[0][0]

    def test_no_signal_data_returned(self, mocker, mock_incident):
        """Test error handling when no signal data is returned.

        Given: An incident with a valid signal ID
        When: The datadog-signal-get command returns empty data
        Then: An error should be returned indicating no signal data
        """
        mocker.patch.object(demisto, "incident", return_value=mock_incident)
        mocker.patch.object(
            demisto, "executeCommand", return_value=[{"Type": 1, "Contents": {}}]
        )
        mocker.patch("DatadogSyncIncidentFields.isError", return_value=False)
        mock_error = mocker.patch(
            "DatadogSyncIncidentFields.return_error", side_effect=SystemExit(0)
        )

        from DatadogSyncIncidentFields import main

        with pytest.raises(SystemExit):
            main()

        mock_error.assert_called_once()
        assert "No signal data returned" in mock_error.call_args[0][0]

    def test_archived_signal_closes_incident(
        self, mocker, mock_incident, mock_archived_signal_data
    ):
        """Test that archived signals trigger incident closure.

        Given: An incident with a signal ID and the signal is archived in Datadog
        When: The script executes and fetches the archived signal
        Then: The incident should be updated, owner set, and incident closed
        """
        mocker.patch.object(demisto, "incident", return_value=mock_incident)
        execute_command_mock = mocker.patch.object(
            demisto,
            "executeCommand",
            side_effect=[
                [
                    {"Type": 1, "Contents": mock_archived_signal_data}
                ],  # datadog-signal-get
                {},  # setIncident
                {},  # setOwner
                {},  # closeInvestigation
            ],
        )
        mocker.patch.object(
            demisto,
            "mapObject",
            return_value={
                "datadogcloudsiemv2securitysignalid": "test-signal-id-123",
                "datadogcloudsiemv2securitysignalmessage": "Test security signal",
                "datadogcloudsiemv2securitysignalseverity": "high",
            },
        )
        mocker.patch("DatadogSyncIncidentFields.isError", return_value=False)
        mock_results = mocker.patch("DatadogSyncIncidentFields.return_results")

        from DatadogSyncIncidentFields import main

        main()

        # Verify closeInvestigation was called with correct parameters
        close_investigation_call = None
        for call in execute_command_mock.call_args_list:
            if call[0][0] == "closeInvestigation":
                close_investigation_call = call
                break

        assert close_investigation_call is not None
        assert close_investigation_call[0][1]["closeReason"] == "false_positive"
        assert (
            close_investigation_call[0][1]["closeNotes"]
            == "This was a false positive detection"
        )
        mock_results.assert_called_once()

    def test_no_fields_to_update(self, mocker, mock_incident, mock_signal_data):
        """Test handling when mapping returns no fields to update.

        Given: An incident with a signal ID
        When: The mapper returns an empty result
        Then: A message indicating no fields to update should be returned
        """
        mocker.patch.object(demisto, "incident", return_value=mock_incident)
        mocker.patch.object(
            demisto,
            "executeCommand",
            return_value=[{"Type": 1, "Contents": mock_signal_data}],
        )
        mocker.patch.object(demisto, "mapObject", return_value={})
        mocker.patch("DatadogSyncIncidentFields.isError", return_value=False)
        mock_results = mocker.patch("DatadogSyncIncidentFields.return_results")

        from DatadogSyncIncidentFields import main

        main()

        mock_results.assert_called_once()
        result = mock_results.call_args[0][0]
        assert "No fields to update" in result.readable_output

    def test_exception_handling(self, mocker, mock_incident):
        """Test exception handling in the script.

        Given: An incident with a signal ID
        When: An unexpected exception occurs during execution
        Then: The error should be caught and returned appropriately
        """
        mocker.patch.object(demisto, "incident", return_value=mock_incident)
        mocker.patch.object(
            demisto, "executeCommand", side_effect=Exception("Unexpected error")
        )
        mocker.patch.object(demisto, "error")
        mock_error = mocker.patch(
            "DatadogSyncIncidentFields.return_error", side_effect=SystemExit(0)
        )

        from DatadogSyncIncidentFields import main

        with pytest.raises(SystemExit):
            main()

        mock_error.assert_called_once()
        assert (
            "Failed to execute DatadogSyncIncidentFields" in mock_error.call_args[0][0]
        )
        assert "Unexpected error" in mock_error.call_args[0][0]

    def test_signal_without_owner(self, mocker, mock_incident):
        """Test handling when signal has no assignee.

        Given: An incident with a signal ID
        When: The signal data has no assignee/owner
        Then: Incident fields should be updated but setOwner should not be called
        """
        signal_without_owner = {
            "id": "test-signal-id-123",
            "attributes": {"message": "Test security signal", "severity": "high"},
            "triage": {"state": "open"},
        }

        mocker.patch.object(demisto, "incident", return_value=mock_incident)
        execute_command_mock = mocker.patch.object(
            demisto,
            "executeCommand",
            side_effect=[
                [{"Type": 1, "Contents": signal_without_owner}],  # datadog-signal-get
                {},  # setIncident
            ],
        )
        mocker.patch.object(
            demisto,
            "mapObject",
            return_value={"datadogcloudsiemv2securitysignalid": "test-signal-id-123"},
        )
        mocker.patch("DatadogSyncIncidentFields.isError", return_value=False)
        mock_results = mocker.patch("DatadogSyncIncidentFields.return_results")

        from DatadogSyncIncidentFields import main

        main()

        # Verify setOwner was not called
        for call in execute_command_mock.call_args_list:
            assert call[0][0] != "setOwner"

        mock_results.assert_called_once()
