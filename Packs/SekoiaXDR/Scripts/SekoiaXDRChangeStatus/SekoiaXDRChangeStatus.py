import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_username():
    get_users = execute_command("getUsers", {"current": "true"})
    username = get_users[0]["name"]  # type: ignore
    return username


def post_comment(alert_short_id: str, comment: Optional[str], author: str):  # pragma: no cover
    try:
        execute_command(
            "sekoia-xdr-post-comment-alert",
            {"id": alert_short_id, "comment": comment, "author": author},
        )
    except Exception as e:
        return_error(
            f"Failed to post comment for alert with id {alert_short_id} : {str(e)}"
        )


def update_status(new_status: str, mirror_status: str, is_mirror_out: bool, short_id: str):
    if mirror_status == "In" and is_mirror_out:
        execute_command("sekoia-xdr-update-status-alert", {"id": short_id, "status": new_status})
    elif mirror_status is None and is_mirror_out:
        execute_command("setIncident", {"sekoiaxdralertstatus": new_status})
        execute_command("sekoia-xdr-update-status-alert", {"id": short_id, "status": new_status})
    else:
        execute_command("setIncident", {"sekoiaxdralertstatus": new_status})


def main():
    incident = demisto.incidents()[0]  # type: ignore
    mirror_direction = incident.get("dbotMirrorDirection")
    is_mirror_out = incident.get("CustomFields").get("sekoiaxdrmirrorout")
    alert_short_id = demisto.args()["short_id"]
    new_status = demisto.args()["status"]
    comment = demisto.args().get("comment")

    if new_status in ["Ongoing", "Acknowledged"]:
        update_status(new_status, mirror_direction, is_mirror_out, alert_short_id)
        if comment and is_mirror_out:
            post_comment(alert_short_id, comment, get_username())
        readable_output = f"### Status of the alert changed to:\n {new_status}"
        return_results(
            {
                "ContentsFormat": formats["markdown"],
                "Type": entryTypes["note"],
                "Contents": readable_output,
            }
        )
    else:
        raise Exception(
            f"Alert {alert_short_id} could not be changed to that status. \
                Please reject or close the Sekoia Alert by closing the XSOAR incident using the XSOAR close incident button."
        )


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
