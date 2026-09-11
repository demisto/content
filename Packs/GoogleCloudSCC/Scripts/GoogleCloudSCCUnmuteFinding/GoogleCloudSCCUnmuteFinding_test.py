import json

import demistomock as demisto
import pytest
from CommonServerPython import DemistoException
from GoogleCloudSCCUnmuteFinding import (
    ERROR_MESSAGES,
    FINDING_NAME_INCIDENT_FIELD,
    MUTE_STATE_INCIDENT_FIELD,
    SET_INCIDENT_COMMAND,
    UNMUTE_COMMAND,
    get_finding_name,
    get_finding_name_from_incident,
    get_mute_state,
    unmute_finding,
)

FINDING_NAME = "organizations/123456789012/sources/1122334455667788990/locations/global/findings/bc5a86da657611ebb979005056a5924e"
INCIDENT_FINDING_NAME = (
    "organizations/123456789012/sources/1122334455667788990/locations/global/findings/aa5a86da657611ebb979005056a5924e"
)
SET_INCIDENT_SUCCESS_ENTRY = [{"Type": 1, "ContentsFormat": "text", "Contents": "Incident updated successfully."}]


def load_test_data(file_name: str):
    """Load a json file from the test_data directory."""
    with open(f"test_data/{file_name}") as file:
        return json.load(file)


def test_get_finding_name_from_incident(mocker):
    """
    Scenario: The finding name should be read from the "GoogleCloudSCC Finding Name" incident field.

    Given: An incident with the finding name field populated.
    When: get_finding_name_from_incident is called.
    Then: The finding name is returned.
    """
    mocker.patch.object(demisto, "incident", return_value={"CustomFields": {FINDING_NAME_INCIDENT_FIELD: FINDING_NAME}})

    assert get_finding_name_from_incident() == FINDING_NAME


@pytest.mark.parametrize(
    "incident", [{}, {"CustomFields": None}, {"CustomFields": {}}, {"CustomFields": {FINDING_NAME_INCIDENT_FIELD: "  "}}]
)
def test_get_finding_name_from_incident_when_field_is_empty(mocker, incident):
    """
    Scenario: An empty string should be returned when the incident field is not populated.

    Given: An incident without a usable finding name field.
    When: get_finding_name_from_incident is called.
    Then: An empty string is returned.
    """
    mocker.patch.object(demisto, "incident", return_value=incident)

    assert get_finding_name_from_incident() == ""


def test_get_finding_name_from_argument(mocker):
    """
    Scenario: The "finding_name" argument should take precedence over the incident field.

    Given: Script arguments containing the finding name and an incident with a different finding name.
    When: get_finding_name is called.
    Then: The finding name from the argument is returned and the incident is not used.
    """
    incident_mock = mocker.patch.object(
        demisto, "incident", return_value={"CustomFields": {FINDING_NAME_INCIDENT_FIELD: INCIDENT_FINDING_NAME}}
    )

    assert get_finding_name({"finding_name": f"  {FINDING_NAME}  "}) == FINDING_NAME
    assert incident_mock.call_count == 0


def test_get_finding_name_fallback_to_incident_field(mocker):
    """
    Scenario: The incident field should be used when the "finding_name" argument is not provided.

    Given: Empty script arguments and an incident with the finding name field populated.
    When: get_finding_name is called.
    Then: The finding name from the incident field is returned.
    """
    mocker.patch.object(demisto, "incident", return_value={"CustomFields": {FINDING_NAME_INCIDENT_FIELD: INCIDENT_FINDING_NAME}})

    assert get_finding_name({}) == INCIDENT_FINDING_NAME


def test_get_finding_name_when_name_is_not_available(mocker):
    """
    Scenario: An error should be raised when the finding name cannot be resolved.

    Given: Empty script arguments and an incident without the finding name field.
    When: get_finding_name is called.
    Then: A DemistoException is raised with the expected error message.
    """
    mocker.patch.object(demisto, "incident", return_value={"CustomFields": {}})

    with pytest.raises(DemistoException, match=ERROR_MESSAGES["MISSING_FINDING_NAME"]):
        get_finding_name({"finding_name": ""})


@pytest.mark.parametrize(
    "entries, expected_mute_state",
    [
        ([{"Type": 1, "Contents": {"mute": "UNMUTED"}}], "UNMUTED"),
        ([{"Type": 1, "Contents": "text entry"}, {"Type": 1, "Contents": {"mute": "UNDEFINED"}}], "UNDEFINED"),
        ([{"Type": 1, "Contents": {"name": FINDING_NAME}}], ""),
        ([], ""),
    ],
)
def test_get_mute_state(entries, expected_mute_state):
    """
    Scenario: The mute state should be taken from the unmute command response.

    Given: The entries returned by the unmute command.
    When: get_mute_state is called.
    Then: The mute state of the response is returned, or the default mute state when it is not present.
    """
    assert get_mute_state(entries) == expected_mute_state


def test_unmute_finding_success(mocker):
    """
    Scenario: The finding should be unmuted and the incident mute field should be updated.

    Given: Script arguments containing the finding name.
    When: unmute_finding is called.
    Then: The unmute command is executed with the finding name, the incident field is set with the mute state,
          and the command entries are returned.
    """
    entries = load_test_data("unmute_finding_entry.json")
    execute_command_mock = mocker.patch.object(demisto, "executeCommand", side_effect=[entries, SET_INCIDENT_SUCCESS_ENTRY])

    assert unmute_finding({"finding_name": FINDING_NAME}) == entries
    assert execute_command_mock.call_args_list == [
        mocker.call(UNMUTE_COMMAND, {"name": FINDING_NAME}),
        mocker.call(SET_INCIDENT_COMMAND, {"customFields": {MUTE_STATE_INCIDENT_FIELD: "UNMUTED"}}),
    ]


def test_unmute_finding_uses_finding_name_of_the_incident(mocker):
    """
    Scenario: The finding of the incident should be unmuted when the script is executed without arguments.

    Given: Empty script arguments and an incident with the finding name field populated.
    When: unmute_finding is called.
    Then: The unmute command is executed with the finding name of the incident.
    """
    mocker.patch.object(demisto, "incident", return_value={"CustomFields": {FINDING_NAME_INCIDENT_FIELD: INCIDENT_FINDING_NAME}})
    execute_command_mock = mocker.patch.object(
        demisto, "executeCommand", side_effect=[load_test_data("unmute_finding_entry.json"), SET_INCIDENT_SUCCESS_ENTRY]
    )

    unmute_finding({})

    assert execute_command_mock.call_args_list[0] == mocker.call(UNMUTE_COMMAND, {"name": INCIDENT_FINDING_NAME})


def test_unmute_finding_sets_default_mute_state_on_incident(mocker):
    """
    Scenario: The default mute state should be set on the incident when the response does not contain the mute state.

    Given: The unmute command returns an entry without the "mute" field.
    When: unmute_finding is called.
    Then: The incident field is set with the default mute state.
    """
    execute_command_mock = mocker.patch.object(
        demisto, "executeCommand", side_effect=[[{"Type": 1, "Contents": {"name": FINDING_NAME}}], SET_INCIDENT_SUCCESS_ENTRY]
    )

    unmute_finding({"finding_name": FINDING_NAME})

    assert execute_command_mock.call_args_list[1] == mocker.call(
        SET_INCIDENT_COMMAND, {"customFields": {MUTE_STATE_INCIDENT_FIELD: ""}}
    )


def test_unmute_finding_wraps_single_entry(mocker):
    """
    Scenario: A single entry response should be returned as a list.

    Given: The unmute command returns a single entry instead of a list of entries.
    When: unmute_finding is called.
    Then: The entry is returned wrapped in a list.
    """
    entry = load_test_data("unmute_finding_entry.json")[0]
    mocker.patch.object(demisto, "executeCommand", side_effect=[entry, SET_INCIDENT_SUCCESS_ENTRY])

    assert unmute_finding({"finding_name": FINDING_NAME}) == [entry]


def test_unmute_finding_when_set_incident_fails(mocker):
    """
    Scenario: An error should be raised when the incident mute field could not be updated.

    Given: The unmute command succeeds and the "setIncident" command returns an error entry.
    When: unmute_finding is called.
    Then: A DemistoException is raised with the finding name and the "setIncident" error.
    """
    error_message = "Item not found."
    mocker.patch.object(
        demisto,
        "executeCommand",
        side_effect=[
            load_test_data("unmute_finding_entry.json"),
            [{"Type": 4, "ContentsFormat": "text", "Contents": error_message}],
        ],
    )

    with pytest.raises(DemistoException) as exception_info:
        unmute_finding({"finding_name": FINDING_NAME})

    assert FINDING_NAME in str(exception_info.value)
    assert error_message in str(exception_info.value)
    assert "GoogleCloudSCC Finding Mute Status" in str(exception_info.value)


def test_unmute_finding_when_command_fails(mocker):
    """
    Scenario: An error should be raised when the unmute command fails.

    Given: The unmute command returns an error entry.
    When: unmute_finding is called.
    Then: A DemistoException is raised with the finding name and the command error.
    """
    error_message = "Finding not found."
    mocker.patch.object(
        demisto, "executeCommand", return_value=[{"Type": 4, "ContentsFormat": "text", "Contents": error_message}]
    )

    with pytest.raises(DemistoException) as exception_info:
        unmute_finding({"finding_name": FINDING_NAME})

    assert FINDING_NAME in str(exception_info.value)
    assert error_message in str(exception_info.value)


def test_unmute_finding_when_finding_name_is_missing(mocker):
    """
    Scenario: The unmute command should not be executed when the finding name is not available.

    Given: Empty script arguments and an incident without the finding name field.
    When: unmute_finding is called.
    Then: A DemistoException is raised and the unmute command is not executed.
    """
    mocker.patch.object(demisto, "incident", return_value={})
    execute_command_mock = mocker.patch.object(demisto, "executeCommand")

    with pytest.raises(DemistoException, match=ERROR_MESSAGES["MISSING_FINDING_NAME"]):
        unmute_finding({})

    assert execute_command_mock.call_count == 0
