from unittest.mock import patch
from DSPMRerunIncidents import timeDifferenceInHours, reopenInvestigation, reopenIncident


def test_timeDifferenceInHours():
    given_timestamp = "2024-11-04 08:00:00.000000"
    rerun_time = 4
    result = timeDifferenceInHours(given_timestamp, rerun_time)
    assert result is True


@patch("DSPMRerunIncidents.demisto.executeCommand")
@patch("DSPMRerunIncidents.demisto.info")
def test_reopenInvestigation(mock_info, mock_execute_command):
    incident_id = "12345"
    mock_execute_command.side_effect = [
        [{"Contents": "Investigation reopened"}],
        [{"Contents": "done"}]
    ]
    result = reopenInvestigation(incident_id)

    assert result is True
    mock_execute_command.assert_any_call("reopenInvestigation", {"id": incident_id})
    mock_execute_command.assert_any_call("setPlaybook", {"incidentId": incident_id, "name": ""})
    mock_info.assert_any_call("Response from reopenInvestigation command:- [{'Contents': 'Investigation reopened'}]")
    mock_info.assert_any_call("Response from setPlaybook command:- [{'Contents': 'done'}]")


@patch("DSPMRerunIncidents.reopenInvestigation")
@patch("DSPMRerunIncidents.timeDifferenceInHours")
@patch("DSPMRerunIncidents.demisto.info")
def test_reopenIncident(mock_info, mock_time_diff, mock_reopen_investigation):
    args = {
        "rerun_time": 48,
        "incident_list": {"incident_id": "1", "incident_created": "2024-11-01 10:00:00.000000"}
    }

    # Mock responses
    mock_time_diff.return_value = True
    mock_reopen_investigation.return_value = True

    count, status = reopenIncident(args)

    # Assert
    assert count == 1
    assert status == "Successfully reopened 1 incidents."
    mock_info.assert_called_with("Successfully reopened 1 incidents.")
