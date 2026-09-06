import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any
import traceback

MIRRORING_TAG = "Trigger-XSOAR-Mirroring"


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
    return None


def map_and_update_detection(data: dict[str, Any], mapper: str, mapper_type: str) -> CommandResults:
    """
    Perform dictionary mapping using pre-configured mappers and update the detection accordingly.

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
    updated_mapped_data = {"details": data.get("details")}

    for key, value in mapped_data.items():
        if "Process Context" in key:
            # Remove whitespace and convert the key to lowercase to use as a dictionary key.
            new_key = "".join(key.lower().split())
            updated_mapped_data[new_key] = value
    # If there are fields to update, call the 'setIncident' command to update the incident with the latest data.
    demisto.executeCommand("setIncident", updated_mapped_data)
    return CommandResults(readable_output="Detection has been synchronized successfully with EDR process context and summary.")


""" MAIN FUNCTION """


def main():
    try:
        detection_id = demisto.incident().get("CustomFields", {}).get("vectraruxdetectionid")
        command_args = {"detection_ids": detection_id}
        command_result = demisto.executeCommand("vectra-detection-describe", command_args)
        handle_error(command_result)

        tag_command_args = {"detection_id": detection_id}
        tag_list_command_result = demisto.executeCommand("vectra-detection-tag-list", tag_command_args)
        handle_error(tag_list_command_result)

        existing_tags = tag_list_command_result[0].get("Contents", {}).get("tags", [])
        if isinstance(existing_tags, list):
            existing_tags = [t.strip() for t in existing_tags if isinstance(t, str)]
        else:
            existing_tags = []

        if MIRRORING_TAG in existing_tags:
            tag_remove_result = demisto.executeCommand(
                "vectra-detection-tag-remove", {"detection_id": detection_id, "tags": MIRRORING_TAG}
            )
            handle_error(tag_remove_result)

        tag_add_result = demisto.executeCommand("vectra-detection-tag-add", {"detection_id": detection_id, "tags": MIRRORING_TAG})
        handle_error(tag_add_result)

        # Handle command error if there is any
        result = command_result[0].get("Contents", {})
        if isinstance(result, dict):
            detection = result.get("results", [])
            if detection:
                summary = detection[0].get("summary", {})
                process_context_data = detection[0].get("process_context_data", {})
            else:
                summary = {}
                process_context_data = {}
        else:
            summary = {}
            process_context_data = {}
        # Prepare entity json
        data = {"details": summary, "process_context_data": process_context_data}
        result = map_and_update_detection(data, "Vectra RUX - Incoming Mapper", "Vectra RUX Events Detection")
        return_results(result)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute VectraRUXSyncDetectionSummary. Error: {str(ex)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
