import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

incident = demisto.incidents()[0]  # type: ignore
isMirrorEnable = incident.get("dbotMirrorDirection")
alert_short_id = incident.get("CustomFields", {}).get("alertid")
reject = demisto.getArg("sekoiaalertreject")
close_reason = demisto.getArg("closeReason")
close_notes = demisto.getArg("closeNotes")
owner = demisto.getArg("owner")
username = demisto.getArg("closingUserId")

# Check if the owner is set when closing the incident otherwise raise an error.
if not owner or owner == "Assign owner" or not incident.get("owner"):
    raise Exception(
        "**** Please select a owner, the incident can't be closed without an owner. ****"
    )

# Check if the Sekoia Alert is closed and if not then make a comment and close it
get_alert = execute_command("sekoia-xdr-get-alert", {"id": alert_short_id})
alert_status = get_alert["status"]["name"]  # type: ignore
if alert_status not in ["Closed", "Rejected"]:
    # Check if the mirror Out or Both is enabled in which case the sekoiaalertstatus
    # field will be changed and in the period of 1 minute the mirror out will send the changes to Sekoia XDR.
    if isMirrorEnable in ["Out", "Both"]:
        # IF reject is False then close the sekoia alert and if reject is True then reject the sekoia alert.
        if reject == "false":
            execute_command("setIncident", {"sekoiaalertstatus": "Closed"})
        if reject == "true":
            execute_command("setIncident", {"sekoiaalertstatus": "Rejected"})

    # Send the close reason and notes as a comment to the Sekoia XDR alert using the name of the person who closed the incident.
    user = execute_command("getUserByUsername", {"username": username})
    comment = execute_command(
        "sekoia-xdr-post-comment-alert",
        {
            "id": alert_short_id,
            "comment": f"{close_reason}-{close_notes}",
            "author": user["name"],  # type: ignore
        },
    )
else:
    # If the alert is already closed or rejected then raise an error.
    raise Exception("**** The alert is already closed or rejected. ****")
