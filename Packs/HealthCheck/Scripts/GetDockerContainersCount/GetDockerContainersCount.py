import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

res = demisto.executeCommand("core-api-get", {"uri": "diagnostics/checks"})[0]["Contents"]["response"]

wList = []
wList.append({"Max Limit": res["checkRuns"]["diagnostic.docker.containers.count"]["result"]["metrics"]["issueLimit"],
             "Current Count": res["checkRuns"]["diagnostic.docker.containers.count"]["result"]["metrics"]["currentCount"]})

return_results({"total": len(wList), "data": wList})
