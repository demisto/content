import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401



def get_status_name(alert_id: str):
    get_alert = execute_command("sekoia-xdr-get-alert", {"id": alert_id})
    return get_alert["status"]["name"]  # type: ignore


def get_username(username: str):
    user = execute_command("getUserByUsername", {"username": username})
    return user["name"]  # type: ignore


def post_closure_comment(
    alert_id: str,
    close_reason: Optional[str],
    close_notes: Optional[str],
    username: Optional[str],
):
    try:
        execute_command(
            "sekoia-xdr-post-comment-alert",
            {
                "id": alert_id,
                "comment": (
                    f"{close_reason}-{close_notes}"
                    if close_reason and close_notes
                    else None
                ),
                "author": get_username(username),  # type: ignore
            },
        )
    except Exception as e:
        return_error(f"Failed to post comment: {str(e)}")


def alert_closure_status(mirror_status: str, alert_id: str, status: str):
    if mirror_status == "Both":
        execute_command("sekoia-xdr-update-status-alert", {"id": alert_id, "status": status})
    elif mirror_status == "Outgoing":
        execute_command("setIncident", {"sekoiaxdralertstatus": status})
        execute_command("sekoia-xdr-update-status-alert", {"id": alert_id, "status": status})
    else:
        execute_command("setIncident", {"sekoiaxdralertstatus": status})


def close_alert(
    alert_id: str,
    reject: str,
    close_reason: Optional[str],
    close_notes: Optional[str],
    username: str,
    mirror_status: str
):
    readable_output = ""
    alert_status = get_status_name(alert_id)
    if alert_status not in ["Closed", "Rejected"]:
        if reject == "false":
            alert_closure_status(mirror_status, alert_id, "Closed")
            readable_output = f"**** The alert {alert_id} with {mirror_status} mirror direction has been closed. ****"
        if reject == "true":
            alert_closure_status(mirror_status, alert_id, "Rejected")
            readable_output = f"**** The alert {alert_id} with {mirror_status} mirror direction has been rejected. ****"

        post_closure_comment(alert_id, close_reason, close_notes, username)

    else:
        execute_command("setIncident", {"sekoiaxdralertstatus": alert_status})
        readable_status = "closed" if alert_status.lower() == "closed" else "rejected"
        readable_output = f"**** The alert {alert_id} has been {readable_status}. ****"

    return_results(
        {
            "ContentsFormat": formats["markdown"],
            "Type": entryTypes["note"],
            "Contents": readable_output,
        }
    )


def main():
    incident = demisto.incidents()[0]  # type: ignore
    isMirrorEnable = incident.get("dbotMirrorDirection")
    alert_short_id = incident.get("CustomFields", {}).get("alertid")
    reject = demisto.getArg("sekoiaxdralertreject")  # type: ignore
    close_reason = demisto.getArg("closeReason")
    close_notes = demisto.getArg("closeNotes")
    username = demisto.getArg("closingUserId")  # type: ignore

    close_alert(
        alert_short_id, reject, close_reason, close_notes, username, isMirrorEnable   # type: ignore
    )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
