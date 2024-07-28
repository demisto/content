import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def print_to_incident_command(current_job_id: str, value: str, incident_id: str) -> None:
    """Prints a value to the specified incident ID.

    Args:
        current_job_id (str): The job ID running the script.
        value (str): The value to print.
        incident_id (str): The incident ID to print to.
    """
    entry_note = json.dumps(
        [{"Type": 1, "ContentsFormat": EntryFormat.MARKDOWN, "Contents": f"Entry from #{current_job_id}:\n{value}"}]
    )
    entry_tags_res: list[dict[str, Any]] = demisto.executeCommand(
        "addEntries", {"entries": entry_note, "id": incident_id, "reputationCalcAsync": True}
    )
    if isError(entry_tags_res[0]):
        return_error(get_error(entry_tags_res))
    else:
        return_results(CommandResults(readable_output=f"Successfully printed to incident {incident_id}."))


def main():  # pragma: no cover
    try:
        current_job: dict[str, Any] = demisto.incident()
        current_job_id: str = current_job["id"]
        args = demisto.args()
        value: str = args["value"]
        incident_id = args["incident_id"]
        print_to_incident_command(
            current_job_id=current_job_id,
            value=value,
            incident_id=incident_id,
        )
    except Exception as ex:
        return_error(f"Failed to execute PrintToIncident. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
