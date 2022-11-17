import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

current_incident_id = demisto.incidents()[0]['id']
duplicate_id = demisto.args()['duplicateId']
res = demisto.executeCommand("linkIncidents", {"incidentId": duplicate_id,
                             "linkedIncidentIDs": current_incident_id, "action": "duplicate"})
demisto.results(res)
