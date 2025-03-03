import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_updated_alert(alert_id: str, earliest_time: str):
    readable_output = ""
    try:
        events = execute_command(
            "sekoia-xdr-search-events",
            {
                "earliest_time": earliest_time,
                "lastest_time": "now",
                "query": f"alert_short_ids:{alert_id}",
            },
        )
    except Exception as e:
        return_error(f"Failed to update alerts: {str(e)}")

    if events:
        demisto.executeCommand("setIncident", {"SekoiaXDRevents": events})
        readable_output = f"### Alert:\n ### Updated old events with new events in this alert with ID {alert_id}."
    else:
        readable_output = (
            f"### Alert:\n ### There is no events in this alert with ID {alert_id}."
        )

    return readable_output


def main():
    incident = demisto.incident()
    earliest_time = demisto.args()["earliest_time"]
    alert_short_id = incident.get("CustomFields", {}).get("alertid")

    try:
        readable_output = get_updated_alert(alert_short_id, earliest_time)
    except Exception as e:
        return_error(f"Failed to update alerts: {str(e)}")

    command_results = CommandResults(readable_output=readable_output)
    return_results(command_results)


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
