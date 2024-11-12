import pytest
from pytest_mock import MockerFixture
import demistomock as demisto
from CommonServerPython import EntryType


def test_print_to_incident(mocker: MockerFixture):
    """Tests print_to_incident_command when the executeCommand command succeeds.

    Checks that the addEntries command is called with the right arguments.
    """
    from PrintToIncident import print_to_incident_command

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
    print_to_incident_command(
        current_job_id="5",
        value="Hello",
        incident_id="INCIDENT-4",
    )
    # Right command is called
    assert execute_command_mocker.call_args[0][0] == "addEntries"
    # Right arguments are given
    assert execute_command_mocker.call_args[0][1] == {
        "entries": '[{"Type": 1, "ContentsFormat": "markdown", "Contents": "Entry from #5:\\nHello"}]',
        "id": "INCIDENT-4",
        "reputationCalcAsync": True,
    }
    assert demisto.results.call_args[0][0]["HumanReadable"] == "Successfully printed to incident INCIDENT-4."


def test_print_to_alert_error(mocker: MockerFixture):
    """Tests print_to_incident_command when the executeCommand command fails.

    Checks that the system exists and an error message is returned.
    """
    from PrintToIncident import print_to_incident_command

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
        print_to_incident_command(
            current_job_id="5",
            value="Hello",
            incident_id="INCIDENT-4",
        )
    assert demisto.results.call_args[0][0] == {
        "Type": EntryType.ERROR,
        "ContentsFormat": "text",
        "Contents": error_message,
        "EntryContext": None,
    }
