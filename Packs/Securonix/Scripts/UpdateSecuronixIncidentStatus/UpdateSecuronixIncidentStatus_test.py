"""Unit test cases for UpdateSecuronixIncidentStatus script."""
from unittest.mock import patch
from UpdateSecuronixIncidentStatus import main

"""Constants"""

MOCK_ARGS = {
    "incident_id": "200",
    "active_state_status": "In Progress",
    "close_state_status": "closed",
    "active_state_action": "Start Investigation",
    "close_state_action": "Close Incident",
    "only_active": True
}
MOCK_INCIDENT = {
    "id": "100",
    "CustomFields": {
        "securonixincidentstatus": "new"
    }
}
MOCK_RESPONSE_PERFORM_ACTION = [{
    "Contents": "submitted",
    "ContentsFormat": "text",
    "EntryContext": None,
    "Type": 4
}]
MOCK_RESPONSE_ADD_COMMENT = [{
    "Contents": True,
    "ContentsFormat": "text",
    "EntryContext": None,
    "Type": 4
}]


@patch('UpdateSecuronixIncidentStatus.demisto.args')
@patch('UpdateSecuronixIncidentStatus.demisto.incident')
@patch('UpdateSecuronixIncidentStatus.demisto.executeCommand')
@patch('UpdateSecuronixIncidentStatus.return_results')
def test_update_securonix_incident_to_active_state(mock_return, mock_execute_command, mock_incident, mock_args):
    """Test case for successful execution of script to update incident in active state."""
    mock_args.return_value = MOCK_ARGS
    mock_incident.return_value = MOCK_INCIDENT
    mock_execute_command.side_effect = [MOCK_RESPONSE_PERFORM_ACTION, MOCK_RESPONSE_ADD_COMMENT]

    main()

    assert mock_return.call_args.args[0] == "Incident 200 has been moved to In Progress."


@patch('UpdateSecuronixIncidentStatus.demisto.args')
@patch('UpdateSecuronixIncidentStatus.demisto.incident')
@patch('UpdateSecuronixIncidentStatus.demisto.executeCommand')
@patch('UpdateSecuronixIncidentStatus.return_results')
def test_update_securonix_incident_to_close_state(mock_return, mock_execute_command, mock_incident, mock_args):
    """Test case for successful execution of script to update incident in close state."""
    MOCK_ARGS["only_active"] = False
    mock_args.return_value = MOCK_ARGS
    mock_incident.return_value = MOCK_INCIDENT
    mock_execute_command.side_effect = [MOCK_RESPONSE_PERFORM_ACTION, MOCK_RESPONSE_ADD_COMMENT,
                                        MOCK_RESPONSE_PERFORM_ACTION, MOCK_RESPONSE_ADD_COMMENT]
    main()

    assert mock_return.call_args.args[0] == "Successfully closed incident 200 on Securonix."


@patch('UpdateSecuronixIncidentStatus.demisto.args')
@patch('UpdateSecuronixIncidentStatus.demisto.incident')
@patch('UpdateSecuronixIncidentStatus.return_results')
def test_update_securonix_incident_when_incident_already_in_close_sate(mock_return, mock_incident, mock_args):
    """Test case for successful execution of script when incident is already in closed state."""
    MOCK_ARGS["only_active"] = False
    MOCK_INCIDENT["CustomFields"]["securonixincidentstatus"] = "closed"
    mock_args.return_value = MOCK_ARGS
    mock_incident.return_value = MOCK_INCIDENT

    main()

    assert mock_return.call_args.args[0] == "Incident 200 is already in closed state on Securonix."
