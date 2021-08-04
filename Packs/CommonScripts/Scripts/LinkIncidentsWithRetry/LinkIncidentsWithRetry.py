import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

linkedIncidentIDs = demisto.args()["linkedIncidentIDs"]
counter = int(demisto.args()["retryLimit"])
res = demisto.executeCommand("linkIncidents", {"linkedIncidentIDs": linkedIncidentIDs})
while isError(res[0]) and counter > 0 and ("DB Version" in res[0]["Contents"]):
    time.sleep(2)
    demisto.error(str(counter) + " retry linkIncidents:" + str(linkedIncidentIDs))
    res = demisto.executeCommand("linkIncidents", {"linkedIncidentIDs": linkedIncidentIDs})
    counter = counter - 1
demisto.results(res)
