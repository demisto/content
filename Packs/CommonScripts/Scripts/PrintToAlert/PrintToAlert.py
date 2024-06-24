import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def print_to_alert_command(current_alert_id: str, value: str, alert_id: str) -> None:
    """Prints a value to the specified alert ID.

    Args:
        current_alert_id (str): The alert ID running the script.
        value (str): The value to print.
        alert_id (str): The alert ID to print to.
    """
    entry_note = json.dumps(
        [{"Type": 1, "ContentsFormat": EntryFormat.MARKDOWN, "Contents": f"Entry from alert #{current_alert_id}:\n{value}"}]
    )
    entry_tags_res: list[dict[str, Any]] = demisto.executeCommand(
        "addEntries", {"entries": entry_note, "id": alert_id, "reputationCalcAsync": True}
    )
    if isError(entry_tags_res[0]):
        return_error(get_error(entry_tags_res))
    else:
        return_results(CommandResults(readable_output=f"Successfully printed to alert {alert_id}."))


def main():  # pragma: no cover
    try:
        current_alert: dict[str, Any] = demisto.incident()
        current_alert_id: str = current_alert["id"]
        args = demisto.args()
        value: str = args["value"]
        alert_id = args["alert_id"]
        print_to_alert_command(
            current_alert_id=current_alert_id,
            value=value,
            alert_id=alert_id,
        )
    except Exception as ex:
        return_error(f"Failed to execute PrintToAlert. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
