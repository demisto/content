import pytest
from pytest_mock import MockerFixture
import demistomock as demisto
from CommonServerPython import EntryType, DemistoException


def test_print_to_parent_incident(mocker: MockerFixture):
    """Tests print_to_parent_incident when the executeCommand command succeeds.

    Checks that the addEntries command is called with the right arguments.
    """
    from PrintToParentIncident import print_to_parent_incident

    execute_command_mocker = mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=[
            {
                "Type": EntryType.NOTE,
                "Contents": "done",
                "HumanReadable": None,
                "EntryContext": None,
            }
        ],
    )
    mocker.patch.object(demisto, "results")
    print_to_parent_incident(
        alert_id="4",
        value="Hello",
        parent_incident_id="INCIDENT-5",
    )
    # Right command is called
    assert execute_command_mocker.call_args[0][0] == "addEntries"
    # Right arguments are given
    assert execute_command_mocker.call_args[0][1] == {
        "entries": '[{"Type": 1, "ContentsFormat": "markdown", "Contents": "Entry from alert #4:\\nHello"}]',
        "id": "INCIDENT-5",
        "reputationCalcAsync": True,
    }
    assert demisto.results.call_args[0][0]["HumanReadable"] == "Successfully printed to parent incident INCIDENT-5."


def test_print_to_alert_error(mocker: MockerFixture):
    """Tests print_to_parent_incident when the executeCommand command fails.

    Checks that the system exists and an error message is returned.
    """
    from PrintToParentIncident import print_to_parent_incident

    error_message = "Something went wrong"
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=[
            {
                "Type": EntryType.ERROR,
                "Contents": error_message,
                "HumanReadable": None,
                "EntryContext": None,
            }
        ],
    )
    mocker.patch.object(demisto, "results")
    with pytest.raises(SystemExit):
        print_to_parent_incident(
            alert_id="4",
            value="Hello",
            parent_incident_id="INCIDENT-5",
        )
    assert demisto.results.call_args[0][0] == {
        "Type": EntryType.ERROR,
        "ContentsFormat": "text",
        "Contents": error_message,
        "EntryContext": None,
    }


def test_no_parent_incident_error():
    """Check that we return an error when no parent incident is found"""
    from PrintToParentIncident import validate_parent_incident_id

    with pytest.raises(DemistoException):
        validate_parent_incident_id(parent_incident_id="", alert_id=4)
