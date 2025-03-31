import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from VectraXDRSyncEntityAssignment import main  # Import the main function from the script file
from VectraXDRSyncEntityAssignment import handle_error, map_and_update_entity_assignments


def test_handle_error_no_error():
    """
    Given:
    - Command results containing no errors.

    When:
    - Calling the 'handle_error' function with the provided command results.

    Then:
    - Assert that the function returns None, indicating no error.
    """
    # Test when no error in the command results
    command_results = [{"Type": 1, "Contents": "Success"}]
    assert handle_error(command_results) is None


def test_map_and_update_entity_assignments():
    """
    Given:
    - Test data containing various fields, including 'Vectra XDR Entity Assignment Details'.
    - A mapper and a mapper type.

    When:
    - Calling the 'map_and_update_entity_assignments' function with the provided data, mapper, and mapper type.

    Then:
    - Assert that the function returns a CommandResults object.
    - Assert that the readable output of the CommandResults indicates successful synchronization of assignments.
    """
    # Define your test data
    data = {"field1": "value1", "field2": "value2", "Assignment Details": "assignment_data"}
    mapper = "your_mapper"
    mapper_type = "incident_type"

    # Mock demisto.mapObject
    def mock_map_object(data, mapper, mapper_type):
        return data

    # Mock demisto.executeCommand
    def mock_execute_command(command, data):
        assert command == "setIncident"
        assert data == data

    # Replace the actual functions with the mock functions
    original_map_object = demisto.mapObject
    demisto.mapObject = mock_map_object

    original_execute_command = demisto.executeCommand
    demisto.executeCommand = mock_execute_command

    # Test the map_and_update_entity_assignments function
    result = map_and_update_entity_assignments(data, mapper, mapper_type)

    # Restore the original functions
    demisto.mapObject = original_map_object
    demisto.executeCommand = original_execute_command

    # Check if the result is a CommandResults object with the correct readable_output
    assert isinstance(result, CommandResults)
    assert result.readable_output == "Assignments have been synchronized successfully."


def test_main(mocker):
    """
    Given:
    - A mocked incident object.

    When:
    - Calling the 'main' function of the VectraXDRSyncEntityAssignment script.
    """
    mocker.patch.object(
        demisto, "incident", return_value={"CustomFields": {"vectraxdrentityid": "1", "vectraxdrentitytype": "host"}}
    )

    # Mock the demisto.executeCommand() function to return the command result.
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=[
            {
                "Type": "command",
                "Contents": [
                    {
                        "id": 212,
                        "assigned_by": {"id": 65, "username": "test.user4@mail.com"},
                        "date_assigned": "2023-08-18T06:29:56Z",
                        "events": [],
                        "account_id": 108,
                        "assigned_to": {"id": 60, "username": "test.user1@mail.com"},
                        "assignment_id": 212,
                    }
                ],
                "HumanReadable": "",
            }
        ],
    )

    # Call the main function
    main()
