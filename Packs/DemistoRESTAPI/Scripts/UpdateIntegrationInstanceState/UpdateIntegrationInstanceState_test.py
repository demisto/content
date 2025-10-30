import demistomock as demisto
from UpdateIntegrationInstanceState import update_integration_instance_state
from CommonServerPython import EntryType


def test_update_integration_instance_state(mocker):
    """
    Given:
        - An integration instance name 'TestIntegration' and an 'enable' state of True.

    When:
        - Calling `update_integration_instance_state`.

    Then:
        - Ensure `demisto.executeCommand` is called twice (once to search, once to update).
        - Ensure the function returns a `CommandResults` object with the expected success message.
    """
    instance_name = "TestIntegration"
    enable = True

    # Mock the response for the search call
    search_response = [
        {
            "Type": EntryType.NOTE,
            "Contents": {
                "response": {
                    "instances": [
                        {
                            "name": instance_name,
                            "id": "test_id",
                            "brand": "TestBrand",
                            "data": {},
                            "isIntegrationScript": True,
                            "version": -1,
                        }
                    ]
                }
            },
        }
    ]

    # Mock the response for the update call
    update_response = [{"Type": EntryType.NOTE, "Contents": "Success"}]

    # Set up the mock for demisto.executeCommand
    execute_command_mock = mocker.patch.object(
        demisto,
        "executeCommand",
        side_effect=[
            search_response,  # First call returns search results
            update_response,  # Second call returns update success
        ],
    )

    # Call the function
    command_results = update_integration_instance_state(instance_name, enable)

    # Assertions
    assert execute_command_mock.call_count == 2
    assert command_results.readable_output == f"Successfully enabling integration instance **{instance_name}**."
