import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    incident = demisto.incidents()[0]  # type: ignore
    isMirrorEnable = incident.get("dbotMirrorDirection")
    alert_short_id = demisto.args().get("short_id")
    new_status = demisto.args().get("status")
    comment = demisto.args().get("comment")

    if new_status in ["Ongoing", "Acknowledged"]:
        if comment:
            user = execute_command("getUsers", {"current": "true"})[0]["name"]  # type: ignore
            execute_command(
                "sekoia-xdr-post-comment-alert",
                {"id": alert_short_id, "comment": comment, "author": user},
            )
        if isMirrorEnable in ["Out", "Both"]:
            execute_command("setIncident", {"sekoiaalertstatus": new_status})
        elif isMirrorEnable == "In":
            execute_command(
                "sekoia-xdr-update-status-alert",
                {"id": alert_short_id, "status": new_status},
            )
        else:
            execute_command(
                "sekoia-xdr-update-status-alert",
                {"id": alert_short_id, "status": new_status},
            )
            execute_command("setIncident", {"sekoiaalertstatus": new_status})
        readable_output = f"### Status of the alert changed to:\n {new_status}"
        demisto.results(
            {
                "ContentsFormat": formats["markdown"],
                "Type": entryTypes["note"],
                "Contents": readable_output,
            }
        )
    else:
        raise Exception(
            "Sorry, the alert was not possible to be changed to that status.\n \
            If you want to reject or close the Sekoia Alert please do it \
            by closing the XSOAR incident with the XSOAR close incident button."
        )


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
