import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any
import traceback


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


def check_empty(x: Any) -> bool:
    """
    Check if input is empty (None, empty dict, empty list, or empty string).

    :param x: Input to check.
    :type x: Any
    :return: True if x is empty, False otherwise.
    :rtype: bool
    """
    return x is None or x == {} or x == [] or x == ""


def remove_empty_elements_for_fetch(d: Any) -> Any:
    """
    Recursively remove empty lists, empty dicts, or None elements from a dictionary or list.
    :param d: Input dictionary or list.
    :return: Dictionary or list with all empty lists, and empty dictionaries removed.
    """
    if not isinstance(d, dict | list):
        return d
    elif isinstance(d, list):
        return [v for v in (remove_empty_elements_for_fetch(v) for v in d) if not check_empty(v)]
    return {k: v for k, v in ((k, remove_empty_elements_for_fetch(v)) for k, v in d.items()) if not check_empty(v)}


def nullify_sentinels(d: Any) -> Any:
    """Recursively replace protobuf zero-value sentinel strings (ending with unspecified) with None."""
    if isinstance(d, str):
        return None if d.lower().endswith("unspecified") else d
    if isinstance(d, list):
        return [nullify_sentinels(v) for v in d]
    if isinstance(d, dict):
        return {k: nullify_sentinels(v) for k, v in d.items()}
    return d


def map_and_update_incident(data: dict[str, Any], mapper: str, mapper_type: str) -> CommandResults:
    """
    Perform dictionary mapping using pre-configured mappers and update the incident accordingly.

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
        new_key = "".join(key.lower().split())
        updated_mapped_data[new_key] = value
    # If there are fields to update, call the 'setIncident' command to update the incident with the latest data.

    demisto.executeCommand("setIncident", updated_mapped_data)
    return CommandResults(readable_output="Incident has been synchronized successfully.")


""" MAIN FUNCTION """


def main():
    try:
        args = demisto.args()
        incident_id = args.get("incident_id")

        if not incident_id:
            raise DemistoException("'incident_id' is required.")

        command_args = {"incident_ids": incident_id}
        command_result = demisto.executeCommand("cyberhaven-incident-list", command_args)

        if not command_result:
            return_error("No response received from cyberhaven-incident-list.")

        handle_error(command_result)

        # Handle command error if there is any
        result = command_result[0].get("Contents", [])

        resources = result.get("resources", []) if isinstance(result, dict) else []

        if not resources:
            return_error(f"Cyberhaven incident '{incident_id}' not found in Cyberhaven (it may have been deleted).")
            return

        response = nullify_sentinels(resources[0])
        incident_data = remove_empty_elements_for_fetch(response)

        result = map_and_update_incident(incident_data, "Cyberhaven - Incoming Mapper", "Cyberhaven Incident")
        return_results(result)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute CyberhavenIncidentRefresh. Error: {str(ex)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
