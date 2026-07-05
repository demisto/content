import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

try:
    incident = demisto.incident() or {}
    custom_fields = incident.get("CustomFields") or {}

    incident_type = incident.get("type")
    cypho_status = custom_fields.get("cyphostatus")
    incident_id = incident.get("id")
    owner = incident.get("owner")
    ticket_id = custom_fields.get("cyphoticketid")

    if not owner:
        raise DemistoException("Incident is not assigned. Please assign an owner before dismissing an issue.")

    if not ticket_id:
        raise DemistoException("Cypho ticket ID is missing from the incident.")

    if incident_type == "Cypho Under Review Issues" and cypho_status == "Candidate":
        users_response = demisto.executeCommand("getUsers", {})

        if is_error(users_response[0]):
            raise DemistoException("Failed to retrieve user list.")

        users = users_response[0].get("Contents", []) or []
        user_info = next((u for u in users if u.get("username") == owner), None)

        if not user_info or not user_info.get("email"):
            raise DemistoException(f"Could not find email for incident owner '{owner}'.")

        email = user_info.get("email")

        demisto.executeCommand(
            "cypho-approve-dismiss-issue",
            {
                "approve": "False",
                "ticket_id": ticket_id,
                "user_email": email,
            },
        )

        demisto.executeCommand(
            "setIncident",
            {"cyphostatus": "Dismiss"},
        )

        close_notes = (
            "The issue has been reviewed and determined to be non-critical. "
            "No further action is required at this time. "
            "Dismissing the alert for now, but will continue to monitor if it reoccurs."
        )

        demisto.executeCommand(
            "closeInvestigation",
            {
                "id": incident_id,
                "closeReason": "Other",
                "closeNotes": close_notes,
            },
        )

    else:
        raise DemistoException(
            "Either the incident type is not 'Cypho Under Review Issues' " "or the issue status is not set to 'Candidate'."
        )

except Exception as e:
    demisto.error(f"[CyphoDismissIssueButton] Error: {str(e)}")
    return_results(CommandResults(readable_output=f"Failed to dismiss Cypho ticket. Error: {str(e)}"))
