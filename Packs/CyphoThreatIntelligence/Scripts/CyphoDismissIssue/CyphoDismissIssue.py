import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

try:
    incident = demisto.incident()
    custom_fields = incident.get("CustomFields", {})
    args_update_incident = {"cyphostatus": "Dismiss"}
    Incident_Type, Cypho_Status, IncidentID, users_response, owner, ticket_id = incident.get("type"), custom_fields.get(
        "cyphostatus"), incident.get("id"), demisto.executeCommand("getUsers", {}), incident.get("owner"), custom_fields.get("cyphoticketid")

    if not owner:
        raise DemistoException("Incident is not assigned. Please assign an owner before dismiss a issue.")

    if Incident_Type == "Cypho Under Review Issues" and Cypho_Status == "Candidate":
        if is_error(users_response[0]):
            raise DemistoException("Failed to retrieve user list.")

        users = users_response[0].get("Contents", [])
        user_info = next((u for u in users if u.get("username") == owner), None)

        if not user_info or not user_info.get("email"):
            raise DemistoException(f"Could not find email for incident owner '{owner}'.")

        email = user_info.get("email")
        args_approve_issue = {"approve": "False", "ticket_id": ticket_id, "user_email": email}
        demisto.executeCommand("cypho-approve-dismiss-issue", args_approve_issue)
        demisto.executeCommand("setIncident", args_update_incident)
        demisto.executeCommand("closeInvestigation", {'id': IncidentID, 'closeReason': "Other",
                               'closeNotes': f"The issue has been reviewed and determined to be non-critical. No further action is required at this time. Dismissing the alert for now, but will continue to monitor if it reoccurs."})
    else:
        raise DemistoException(
            "Either the incident type is not 'Cypho Under Review Issues' or the issue status is not set to 'Candidate'.")

except Exception as e:
    demisto.error(f"[CyphoDismissIssueButton] Error: {str(e)}")
    return_results(CommandResults(readable_output=f"Failed to process approval for Cypho ticket. Error: {str(e)}"))
