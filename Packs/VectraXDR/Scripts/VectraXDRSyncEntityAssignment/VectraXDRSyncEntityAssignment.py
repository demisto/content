import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any
import traceback

ASSIGNMENT_LAYOUT_FIELDS = ['date_resolved', 'resolved_by', 'outcome']
EMPTY_ASSIGNMENT = [{"id": "", "date_assigned": "", "date_resolved": "", "assigned_to": {"username": ""},
                     "resolved_by": {"username": ""}, "assigned_by": {"username": ""}, "outcome": {"title": ""}}]


# HELPER FUNCTIONS

def handle_error(command_results: list[dict[str, Any]]) -> None:
    """
    Handle the error entries after executing the commands.

    Args:
        command_results (List[Dict[str, Any]]): Command results object.
    Returns:
        Union[None, str]: Returns a string if there is an error, otherwise None.
    """
    if isError(command_results):
        return return_error(command_results[0]["Contents"])


def map_and_update_entity_assignments(data: dict[str, Any], mapper: str, mapper_type: str) -> CommandResults:
    """
    Perform dictionary mapping using pre-configured mappers and update the entity assignments accordingly.

    Args:
        data: Data to map with the mapper.
        mapper: Mapper name to use for mapping data.
        mapper_type: Type of mapping to use in specified mapper(incident type).
    Returns:
        CommandResults: An object containing a human-readable message indicating successful synchronization.
    """
    # Map data to pre-configured mapper.
    mapped_data = demisto.mapObject(data, mapper, mapper_type)
    # Create a new dictionary to store the updated mapped data.
    updated_mapped_data = {}

    for key, value in mapped_data.items():
        if "Assignment" in key:
            # Remove whitespace and convert the key to lowercase to use as a dictionary key.
            new_key = "".join(key.lower().split())
            updated_mapped_data[new_key] = value
    # If there are fields to update, call the 'setIncident' command to update the incident with the latest data.
    demisto.executeCommand("setIncident", updated_mapped_data)
    return CommandResults(readable_output="Assignments have been synchronized successfully.")


''' MAIN FUNCTION '''


def main():
    try:
        entity_id = demisto.incident().get('CustomFields', {}).get('vectraxdrentityid')
        entity_type = demisto.incident().get('CustomFields', {}).get('vectraxdrentitytype')
        command_args = {'entity_ids': entity_id, 'entity_type': entity_type}
        command_result = demisto.executeCommand('vectra-assignment-list', command_args)
        # Handle command error if there is any
        handle_error(command_result)
        result = command_result[0].get("Contents", [])
        if isinstance(result, list):
            assignment = result[0] if len(result) > 0 else {}
            # Handling empty values which are removed from command output
            assignment_fields = assignment.keys()
            for field in ASSIGNMENT_LAYOUT_FIELDS:
                if field not in assignment_fields:
                    assignment[field] = ""
                    if field == "resolved_by":
                        assignment[field] = {"username": ""}
                    elif field == "outcome":
                        assignment[field] = {"title": ""}
        else:
            assignment = EMPTY_ASSIGNMENT
        # Prepare entity json
        entity = {'assignment_details': assignment}
        result = map_and_update_entity_assignments(entity, 'Vectra XDR - Incoming Mapper',
                                                   'Vectra XDR Entity')
        return_results(result)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute VectraXDRSyncEntityAssignment. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
