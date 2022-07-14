import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
incident = demisto.args()

res = demisto.executeCommand("createNewIncident", incident)
if isError(res[0]):
    raise DemistoException(f"Could not create new incident: {res}")

created_incident = res[0]
id = created_incident.get("EntryContext", dict()).get("CreatedIncidentID")

res = demisto.executeCommand("linkIncidents", {"linkedIncidentIDs": id})
if isError(res[0]):
    raise DemistoException(f"Could not create link incidents: {res}")

return_results("Done!")
