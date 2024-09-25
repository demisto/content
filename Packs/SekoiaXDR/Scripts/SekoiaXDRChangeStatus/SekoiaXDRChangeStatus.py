import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def update_status(new_status: str):
    execute_command("setIncident", {"sekoiaxdralertstatus": new_status})


def main():
    alert_short_id = demisto.args()["short_id"]
    new_status = demisto.args()["status"]

    if new_status in ["Ongoing", "Acknowledged"]:
        update_status(new_status)
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
