import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# return the args and incident details to the war room, useful for seeing what you have available to you
# args can be called with demisto.args().get('argname')

# debugging
# demisto.results(demisto.args())
# demisto.results(demisto.incident())

# get the close notes & reason from the XSOAR Incident
close_reason = demisto.args().get('closeReason')
close_notes = demisto.args().get('closeNotes', 'No close notes provided')
servicenow_sysid = demisto.incident().get("dbotMirrorId", False)

# map XSOAR close reasons to Service Now close codes
close_code_map = {
    "False Positive": "Not Solved (Not Reproducible)",
    "Resolved": "Solved (Permanently)",
    "Other": "Solved (Work Around)",
    "Duplicate": "Solved (Work Around)"
}

close_code = close_code_map.get(close_reason, "Solved (Work Arounnd")

# handle if there is no service now sys_id, resolve and close snow ticket, make sure to set the servicenowstate to closed to avoid the sync reopening the ticket.
if servicenow_sysid:
    demisto.executeCommand("setIncident", {"servicenowstate": "7 - Closed"})
    demisto.results(demisto.executeCommand("servicenow-update-ticket",
                    {"id": servicenow_sysid, "close_code": close_code, "state": 6, "close_notes": close_notes}))
    demisto.results(demisto.executeCommand("servicenow-update-ticket", {"id": servicenow_sysid, "state": 7}))

else:
    demisto.results("No ServiceNow sys_id found, doing nothing...")
