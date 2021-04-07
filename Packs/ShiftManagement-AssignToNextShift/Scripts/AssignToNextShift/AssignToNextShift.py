import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# check if we have any users on call to assign to
users_on_call = demisto.executeCommand("getUsers", {"onCall": "true"})[0]['Contents']

# if we don't have on shift users, return error, else reassign the provided incident id's to the on-call analysts
if not users_on_call:
    return_error("No users on shift")
else:
    incident_id = demisto.args().get('incident_id')
    demisto.results(demisto.executeCommand("executeCommandAt", {
                    "command": "AssignAnalystToIncident", "arguments": {"onCall": "true"}, "incidents": incident_id}))
