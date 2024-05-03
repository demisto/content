import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

res = demisto.executeCommand("core-api-get", {"uri": "diagnostics/checks"})[0]["Contents"]["response"]
xVersion = demisto.executeCommand("DemistoVersion", {})[0]["Contents"]["DemistoVersion"]

wList = []
if "8." in xVersion['version']:
    wList.append({"Max Limit": "NA", "Current Count": "NA"})
else:
    wList.append({"Max Limit": res["checkRuns"]["diagnostic.docker.containers.count"]["result"]["metrics"]["issueLimit"],
                 "Current Count": res["checkRuns"]["diagnostic.docker.containers.count"]["result"]["metrics"]["currentCount"]})

demisto.results({"total": len(wList), "data": wList})
