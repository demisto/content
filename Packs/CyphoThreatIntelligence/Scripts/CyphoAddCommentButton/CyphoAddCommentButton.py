import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

try:
    incident = demisto.incident() or {}
    custom_fields = incident.get("CustomFields", {}) or {}

    comment = custom_fields.get("cyphocomments")
    ticket_id = custom_fields.get("cyphoticketid")
    owner = incident.get("owner")

    if not owner:
        raise DemistoException("Incident is not assigned. Please assign an owner before adding a comment.")

    if not ticket_id or not comment:
        raise DemistoException("Missing required fields: Cypho Ticket ID or Cypho Comment.")

    users_response = demisto.executeCommand("getUsers", {})
    if isError(users_response[0]):
        raise DemistoException("Failed to retrieve user list.")

    users = users_response[0].get("Contents", [])
    user_info = next((u for u in users if u.get("username") == owner), None)

    if not user_info or not user_info.get("email"):
        raise DemistoException(f"Could not find email for incident owner '{owner}'.")

    email = user_info.get("email")
    args = {"ticket_id": ticket_id, "user_email": email, "status_reason": comment}

    response = demisto.executeCommand("cypho-add-comment", args)
    if isError(response[0]):
        raise DemistoException(f"Failed to add comment: {response[0].get('Contents')}")

    return_results(CommandResults(readable_output=f"Comment successfully added to Cypho ticket {ticket_id} by {owner}."))

except Exception as e:
    demisto.error(f"[CyphoAddCommentButton] Error: {str(e)}")
    return_results(CommandResults(readable_output=f"Failed to add comment: {str(e)}"))
