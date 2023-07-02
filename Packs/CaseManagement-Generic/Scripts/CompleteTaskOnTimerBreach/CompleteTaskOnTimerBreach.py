import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# get the incident id.
inc = demisto.incident().get('id')

# execute the taskComplete command on all tasks tagged with timerbreach.
demisto.executeCommand("taskComplete", {"id": "timerbreach", "incidentId": inc})
