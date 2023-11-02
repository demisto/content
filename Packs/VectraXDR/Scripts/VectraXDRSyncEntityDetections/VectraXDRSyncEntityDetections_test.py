import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from VectraXDRSyncEntityDetections import handle_error, map_and_update_entity_detections


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


def test_map_and_update_entity_detections():
    """
    Given:
    - Test data containing various fields, including 'Vectra XDR Entity Detection Details'.
    - A mapper and a mapper type.

    When:
    - Calling the 'map_and_update_entity_detections' function with the provided data, mapper, and mapper type.

    Then:
    - Assert that the function returns a CommandResults object.
    - Assert that the readable output of the CommandResults indicates successful synchronization of detections.
    """
    # Define your test data
    data = {
        "field1": "value1",
        "field2": "value2",
        "Vectra XDR Entity Detection Details": "detection_data"
    }
    mapper = "your_mapper"
    mapper_type = "incident_type"

    # Test the map_and_update_entity_detections function
    result = map_and_update_entity_detections(data, mapper, mapper_type)
    assert isinstance(result, CommandResults)
    assert result.readable_output == "Detections have been synchronized successfully."
