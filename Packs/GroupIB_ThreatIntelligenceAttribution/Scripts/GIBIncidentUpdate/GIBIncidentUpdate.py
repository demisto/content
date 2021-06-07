import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
result = True
inc = demisto.incident()
custom_fields = inc.get("CustomFields", {})
del inc["CustomFields"]
del inc["labels"]
del inc["occurred"]
del inc["sla"]
inc.update(custom_fields)
demisto.error(custom_fields)
gibid = custom_fields.get('gibid')
demisto.error(gibid)
incid = demisto.executeCommand("getIncidents", {"query": "gibid: {0} and -status:Closed".format(gibid)})
total = int(incid[0]["Contents"]["total"])
if total > 0:
    result = False
    incident_id = incid[0]["Contents"]["data"][total - 1]["id"]
    demisto.error(incident_id)
    for key, value in inc.items():
        demisto.executeCommand('setIncident', {"id": incident_id, key: value})

return_results(result)
