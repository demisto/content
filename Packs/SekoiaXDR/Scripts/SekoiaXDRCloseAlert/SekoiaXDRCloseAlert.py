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
    username: str,
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


def close_alert(
    alert_id: str,
    reject: str,
    isMirrorEnable: str,
    close_reason: Optional[str],
    close_notes: Optional[str],
    username: str,
):
    alert_status = get_status_name(alert_id)
    if alert_status not in ["Closed", "Rejected"]:
        if isMirrorEnable in ["Out", "Both"]:
            if reject == "false":
                execute_command("setIncident", {"sekoiaxdralertstatus": "Closed"})
                readable_output = f"**** The alert {alert_id} has been closed. ****"
            if reject == "true":
                execute_command("setIncident", {"sekoiaxdralertstatus": "Rejected"})
                readable_output = f"**** The alert {alert_id} has been rejected. ****"

        post_closure_comment(alert_id, close_reason, close_notes, username)

        return_results(
            {
                "ContentsFormat": formats["markdown"],
                "Type": entryTypes["note"],
                "Contents": readable_output,
            }
        )

    else:
        raise Exception("**** The alert is already closed or rejected. ****")


def main():
    incident = demisto.incidents()[0]  # type: ignore
    isMirrorEnable = incident.get("dbotMirrorDirection")
    alert_short_id = incident.get("CustomFields", {}).get("alertid")
    reject = demisto.getArg("sekoiaxdralertreject")  # type: ignore
    close_reason = demisto.getArg("closeReason")
    close_notes = demisto.getArg("closeNotes")
    owner = demisto.getArg("owner")
    username = demisto.getArg("closingUserId")  # type: ignore

    # Check if the owner is set when closing the incident otherwise raise an error.
    if not owner or owner == "Assign owner":
        raise Exception(
            "**** Please select a owner, the incident can't be closed without an owner. ****"
        )

    close_alert(
        alert_short_id, reject, isMirrorEnable, close_reason, close_notes, username
    )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
