import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

args = demisto.args()
linkedIncidentIDs = args.get("linkedIncidentIDs")

counter = int(args.get("retryLimit"))

res = demisto.executeCommand("linkIncidents", {"linkedIncidentIDs": linkedIncidentIDs})

while isError(res[0]) and counter > 0 and ("DB Version" in res[0].get("Contents")):
    time.sleep(2)
    demisto.error(f"{counter} retry linkIncidents:{linkedIncidentIDs}")
    res = demisto.executeCommand("linkIncidents", {"linkedIncidentIDs": linkedIncidentIDs})
    counter -= 1
return_results(res)
