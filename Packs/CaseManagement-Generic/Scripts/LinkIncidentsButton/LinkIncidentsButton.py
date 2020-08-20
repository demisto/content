import demistomock as demisto
from CommonServerPython import *

linkedIncidentIDs = demisto.args().get("linkedIncidentIDs")
action = demisto.args().get("action")
if action not in ["link", "unlink"]:
    action = "link"
counter = int(demisto.args().get("retryLimit"))
res = demisto.executeCommand("linkIncidents", {"linkedIncidentIDs": linkedIncidentIDs, "action": action})
while isError(res[0]) and counter > 0 and ("DB Version" in res[0]["Contents"]):
    time.sleep(2)
    demisto.error(f"{str(counter)} retry linkIncidents: {str(linkedIncidentIDs)}")
    res = demisto.executeCommand("linkIncidents", {"linkedIncidentIDs": linkedIncidentIDs, "action": action})
    counter = counter - 1
demisto.results(res)
