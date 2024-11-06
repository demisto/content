import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_status_name(alert_id: str):
    get_alert = execute_command("sekoia-xdr-get-alert", {"id": alert_id})
    return get_alert["status"]["name"]  # type: ignore


def close_alert(
    alert_id: str,
    reject: str,
    close_reason: Optional[str],
    close_notes: Optional[str],
    username: str,
):
    readable_output = ""
    alert_status = get_status_name(alert_id)
    if alert_status not in ["Closed", "Rejected"]:
        if reject == "false":
            execute_command("setIncident", {"sekoiaxdralertstatus": "Closed"})
            readable_output = f"**** The alert {alert_id} has been closed. ****"
        if reject == "true":
            execute_command("setIncident", {"sekoiaxdralertstatus": "Rejected"})
            readable_output = f"**** The alert {alert_id} has been rejected. ****"

    return_results(
        {
            "ContentsFormat": formats["markdown"],
            "Type": entryTypes["note"],
            "Contents": readable_output,
        }
    )


def main():
    incident = demisto.incidents()[0]  # type: ignore
    alert_short_id = incident.get("CustomFields", {}).get("alertid")
    reject = demisto.getArg("sekoiaxdralertreject")  # type: ignore
    close_reason = demisto.getArg("closeReason")
    close_notes = demisto.getArg("closeNotes")
    username = demisto.getArg("closingUserId")  # type: ignore

    close_alert(
        alert_short_id, reject, close_reason, close_notes, username  # type: ignore
    )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
