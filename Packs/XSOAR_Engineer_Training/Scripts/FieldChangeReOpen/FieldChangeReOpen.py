import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# Field Change trigger script can take an "old" and "new" and then act accordingly.
# Can be used on fields like severity, or owner to do different actions such as escalation or notification.

# get the old and new values of the field
old = demisto.args().get("old").lower()
new = demisto.args().get("new").lower()

# get the incident ID, need to use investigationId in field change scripts
incident = demisto.incident().get('investigationId')

if old == "closed" and new != "closed":
    demisto.results(f"Incident {incident} status was changed from {old} to {new}")
    # could do something else like send a slack:
    # demisto.executeCommand("send-notification", {"message":"Incident {incident} reopened", "channel":"xsoar"})
