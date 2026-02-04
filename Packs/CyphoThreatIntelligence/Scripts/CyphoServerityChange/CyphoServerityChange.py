import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

incident = demisto.incident() or {}
custom_fields = incident.get("CustomFields") or {}

cypho_severity = custom_fields.get("cyphorisklevel")
cypho_ticket_id = custom_fields.get("cyphoticketid")
owner = incident.get("owner")

if not cypho_ticket_id:
    raise DemistoException("Cypho ticket ID not found in incident fields.")

if not owner:
    raise DemistoException("Incident has no assigned owner.")

res = demisto.executeCommand("getUsers", {})
if isError(res[0]):
    raise DemistoException(f"Failed to retrieve users: {get_error(res)}")

all_users = res[0].get("Contents", [])
matched_user = next((u for u in all_users if u.get("username") == owner), None)

if not matched_user:
    raise DemistoException(f"Owner '{owner}' not found among XSOAR users.")

email = matched_user.get("email")
if not email:
    raise DemistoException(f"User '{owner}' has no email address configured.")

args = {"ticket_id": cypho_ticket_id, "user_email": email, "severity": cypho_severity}

demisto.executeCommand("cypho-update-severity", args)
demisto.results(f"Cypho ticket {cypho_ticket_id} severity updated to {cypho_severity} by {email}.")
