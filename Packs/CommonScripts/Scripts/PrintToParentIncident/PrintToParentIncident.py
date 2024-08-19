import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def print_to_parent_incident(alert_id: str, value: str, parent_incident_id: str) -> None:
    """Prints a value to the alert's parent incident.

    Args:
        alert_id (str): The alert ID running the script.
        value (str): The value to print.
        parent_incident_id (str): The parent incident's ID of the alert.
    """
    entry_note = json.dumps(
        [{"Type": 1, "ContentsFormat": EntryFormat.MARKDOWN, "Contents": f"Entry from alert #{alert_id}:\n{value}"}]
    )
    entry_tags_res: list[dict[str, Any]] = demisto.executeCommand(
        "addEntries", {"entries": entry_note, "id": parent_incident_id, "reputationCalcAsync": True}
    )
    if isError(entry_tags_res[0]):
        return_error(get_error(entry_tags_res))
    else:
        return_results(CommandResults(readable_output=f"Successfully printed to parent incident {parent_incident_id}."))


def validate_parent_incident_id(parent_incident_id: str, alert_id: str) -> str:
    """Validates if the parent incident ID of the alert is not empty, and return it.

    Args:
        parent_incident_id (str): The parent incident ID of the alert.
        alert_id (str): The alert ID running the script.

    Raises:
        DemistoException: If the parent incident ID is an empty string, meaning it couldn't be found.

    Returns:
        str: The parent incident ID if not empty.
    """
    if not parent_incident_id:
        raise DemistoException(f"No parent incident was found for {alert_id =}")
    return parent_incident_id


def main():  # pragma: no cover
    try:
        args = demisto.args()
        value: str = args["value"]
        current_alert: dict[str, Any] = demisto.incident()
        alert_id: str = current_alert["id"]
        parent_incident_id: str = validate_parent_incident_id(
            parent_incident_id=current_alert.get("parentXDRIncident", ""),
            alert_id=alert_id,
        )
        print_to_parent_incident(
            alert_id=alert_id,
            value=value,
            parent_incident_id=parent_incident_id,
        )
    except Exception as ex:
        return_error(f"Failed to execute PrintToParentIncident. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
