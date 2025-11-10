import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

try:
    current_user_resp = demisto.executeCommand("getUsers", {"current": True})
    current_user = current_user_resp[0].get("Contents", [{}])[0].get("username")

    if not current_user:
        raise ValueError("Could not determine the current user.")

    incident = demisto.incidents()[0]
    current_owner = incident.get("owner")

    if current_owner == current_user:
        demisto.results(f"Incident is already assigned to {current_user}. No changes made.")
    else:
        demisto.executeCommand("setOwner", {"owner": current_user})
        demisto.results(f"Incident ownership changed to {current_user}.")

except Exception as e:
    demisto.error(f"[CyphoAssignToMeButton] Error: {str(e)}")
    demisto.results("Failed to assign the incident to the current user.")
