"""Unit test cases for SecuronixCloseHistoricalXSOARIncidents script."""

import json
from unittest.mock import patch

"""Constants"""

CLOSED_STATUS = ["closed", "completed"]
MOCK_EXECUTE_COMMAND_RESPONSE = [{
    "Contents": [],
    "ContentsFormat": "text",
    "EntryContext": None,
    "Type": 4
}]


def test_get_securonix_incident_id():
    """Test case scenario for successful execution of get_securonix_incident_id function."""
    from SecuronixCloseHistoricalXSOARIncidents import get_securonix_incident_id

    with open('test_data/mock_incident_contents.json', 'r') as f:
        mock_incident = json.load(f)

    assert get_securonix_incident_id(mock_incident) == 200


def test_is_securonix_incident_closed_when_incident_is_in_progress():
    """Test case scenario for execution of is_incident_closed_on_securonix function when incident is in progress."""
    from SecuronixCloseHistoricalXSOARIncidents import is_incident_closed_on_securonix

    with open('test_data/incident_activity_history_get_response.json', 'r') as f:
        mock_activity_history = json.load(f)[:2]

    assert is_incident_closed_on_securonix(mock_activity_history, CLOSED_STATUS) is False


def test_is_securonix_incident_closed_when_incident_is_closed():
    """Test case scenario for execution of is_incident_closed_on_securonix function when incident is closed."""
    from SecuronixCloseHistoricalXSOARIncidents import is_incident_closed_on_securonix

    with open('test_data/incident_activity_history_get_response.json', 'r') as f:
        mock_activity_history = json.load(f)

    assert is_incident_closed_on_securonix(mock_activity_history, CLOSED_STATUS) is True


def test_extract_closing_comments():
    """Test case scenario for successful execution of extract_closing_comments function."""
    from SecuronixCloseHistoricalXSOARIncidents import extract_closing_comments

    with open('test_data/incident_activity_history_get_response.json', 'r') as f:
        mock_activity_history = json.load(f)

    closing_comment = extract_closing_comments(mock_activity_history, CLOSED_STATUS)

    assert closing_comment == "Closing the XSOAR incident as Securonix incident is closed."


@patch('SecuronixCloseHistoricalXSOARIncidents.demisto.executeCommand')
def test_close_xsoar_incident_when_incident_in_progress(mock_execute_command):
    """Test case scenario for execution of close_xsoar_incident function when incident is in progress."""
    from SecuronixCloseHistoricalXSOARIncidents import close_xsoar_incident

    with open('test_data/incident_activity_history_get_response.json', 'r') as f:
        mock_activity_history = json.load(f)[:2]
    MOCK_EXECUTE_COMMAND_RESPONSE[0]["Contents"] = mock_activity_history

    mock_execute_command.side_effect = [MOCK_EXECUTE_COMMAND_RESPONSE]

    assert close_xsoar_incident('100', '200', CLOSED_STATUS) is False


@patch('SecuronixCloseHistoricalXSOARIncidents.demisto.executeCommand')
def test_close_xsoar_incident_when_incident_is_closed(mock_execute_command):
    """Test case scenario for execution of close_xsoar_incident function when incident is closed."""
    from SecuronixCloseHistoricalXSOARIncidents import close_xsoar_incident

    with open('test_data/incident_activity_history_get_response.json', 'r') as f:
        mock_activity_history = json.load(f)
    MOCK_EXECUTE_COMMAND_RESPONSE[0]["Contents"] = mock_activity_history

    mock_execute_command.side_effect = [MOCK_EXECUTE_COMMAND_RESPONSE, MOCK_EXECUTE_COMMAND_RESPONSE]

    assert close_xsoar_incident('100', '200', CLOSED_STATUS) is True


@patch('SecuronixCloseHistoricalXSOARIncidents.demisto.args')
@patch('SecuronixCloseHistoricalXSOARIncidents.demisto.executeCommand')
@patch('SecuronixCloseHistoricalXSOARIncidents.return_results')
def test_close_xsoar_incident_script_success(mock_return, mock_execute_command, mock_args):
    """Test case scenario for execution flow of script."""
    from SecuronixCloseHistoricalXSOARIncidents import main

    with open('test_data/mock_incidents.json', 'r') as f:
        mock_incidents_1 = json.load(f)
    with open('test_data/incident_activity_history_get_response.json', 'r') as f:
        mock_activity_history = json.load(f)
    MOCK_EXECUTE_COMMAND_RESPONSE[0]["Contents"] = mock_activity_history
    mock_args.return_value = {
        "from": "1 months",
        "to": "now",
        "close_states": "Closed, Completed"
    }
    mock_incidents_2 = [{"Contents": {"data": []}}]
    mock_execute_command.side_effect = [mock_incidents_1] + [MOCK_EXECUTE_COMMAND_RESPONSE] * 10 + [mock_incidents_2]

    main()

    assert mock_return.call_args.args[0].readable_output == "Successfully closed 5 XSOAR incidents!"
    assert mock_return.call_args.args[0].outputs_key_field == "IncidentIDs"
    assert mock_return.call_args.args[0].outputs_prefix == "Securonix.CloseHistoricalXSOARIncidents"
    assert mock_return.call_args.args[0].outputs == {"IncidentIDs": ["1", "2", "3", "4", "5"]}
