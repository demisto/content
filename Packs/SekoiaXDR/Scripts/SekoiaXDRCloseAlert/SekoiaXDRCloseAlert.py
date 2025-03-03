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
):  # pragma: no cover
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
    close_reason: Optional[str],
    close_notes: Optional[str],
    username: str,
    mirror_status: str,
    is_mirror_out: bool,
):  # pragma: no cover
    readable_output = ""
    alert_status = get_status_name(alert_id)
    if alert_status not in ["Closed", "Rejected"]:
        if reject == "false":
            if mirror_status == "In" and is_mirror_out:
                execute_command(
                    "sekoia-xdr-update-status-alert",
                    {"id": alert_id, "status": "Closed"},
                )
            elif mirror_status is None and is_mirror_out:
                execute_command("setIncident", {"sekoiaxdralertstatus": "Closed"})
                execute_command(
                    "sekoia-xdr-update-status-alert",
                    {"id": alert_id, "status": "Closed"},
                )
            else:
                execute_command("setIncident", {"sekoiaxdralertstatus": "Closed"})
            readable_output = f"**** The alert {alert_id} has been closed. ****"
        if reject == "true":
            if mirror_status == "In" and is_mirror_out:
                execute_command(
                    "sekoia-xdr-update-status-alert",
                    {"id": alert_id, "status": "Rejected"},
                )
            elif mirror_status is None and is_mirror_out:
                execute_command("setIncident", {"sekoiaxdralertstatus": "Closed"})
                execute_command(
                    "sekoia-xdr-update-status-alert",
                    {"id": alert_id, "status": "Rejected"},
                )
            else:
                execute_command("setIncident", {"sekoiaxdralertstatus": "Rejected"})
            readable_output = f"**** The alert {alert_id} has been rejected. ****"

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


def main():  # pragma: no cover
    incident = demisto.incidents()[0]  # type: ignore
    mirror_direction = incident.get("dbotMirrorDirection")
    is_mirror_out = incident.get("CustomFields", {}).get("sekoiaxdrmirrorout")
    alert_short_id = incident.get("CustomFields", {}).get("alertid")
    reject = demisto.getArg("sekoiaxdralertreject")  # type: ignore
    close_reason = demisto.getArg("closeReason")
    close_notes = demisto.getArg("closeNotes")
    username = demisto.getArg("closingUserId")  # type: ignore
    close_alert(
        alert_short_id,
        reject,
        close_reason,
        close_notes,
        username,
        mirror_direction,
        is_mirror_out,  # type: ignore
    )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
