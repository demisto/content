import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any
import traceback


# HELPER FUNCTIONS

def handle_error(command_results: list[dict[str, Any]]) -> Union[None, str]:  # type: ignore
    """
    Handle errors in the command results after executing the commands.

    Args:
        command_results (List[Dict[str, Any]]): A list of command results, each represented as a dictionary.

    Returns:
        Union[None, str]: Returns a string if there is an error, otherwise None.
    """
    if isError(command_results):
        return return_error(command_results[0]["Contents"])


def map_and_update_entity_detections(data: dict[str, Any], mapper: str, mapper_type: str) -> CommandResults:
    """
    Convert a dictionary of data using pre-configured mappers and update the threat accordingly.

    Args:
        data (Dict[str, Any]): Data to map with the mapper.
        mapper (str): Mapper name to use for mapping data.
        mapper_type (str): Type of mapping to use in specified mapper (incident type).

    Returns:
        CommandResults: An object containing a human-readable message indicating successful synchronization.
    """
    # Map data to pre-configured mapper.
    mapped_data = demisto.mapObject(data, mapper, mapper_type)
    # Create a new dictionary to store the updated mapped data.
    updated_mapped_data = {}

    for key, value in mapped_data.items():
        if key == "Vectra XDR Entity Detection Details":
            # Remove whitespace and convert the key to lowercase to use as a dictionary key.
            new_key = "".join(key.lower().split())
            updated_mapped_data[new_key] = value
    # If there are fields to update, call the 'setIncident' command to update the incident with the latest data.
    demisto.executeCommand("setIncident", updated_mapped_data)
    return CommandResults(readable_output="Detections have been synchronized successfully.")


''' MAIN FUNCTION '''


def main():
    try:
        entity_id = demisto.incident().get('CustomFields', {}).get('vectraxdrentityid')
        entity_type = demisto.incident().get('CustomFields', {}).get('vectraxdrentitytype')
        command_args = {'entity_id': entity_id, 'entity_type': entity_type}
        command_result = demisto.executeCommand('vectra-entity-detection-list', command_args)
        # Handle command error if there is any
        handle_error(command_result)
        detections = command_result[0].get("Contents", {}).get('results', [])
        # Prepare entity json
        entity = {'detection_details': detections}
        result = map_and_update_entity_detections(entity, 'Vectra XDR - Incoming Mapper',
                                                  'Vectra XDR Entity')
        return_results(result)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute VectraXDRSyncEntityDetections. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
