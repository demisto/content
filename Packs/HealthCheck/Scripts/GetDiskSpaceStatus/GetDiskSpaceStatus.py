import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

res = demisto.executeCommand("core-api-get", {"uri": "diagnostics/checks"})[0]["Contents"]["response"]

wList = []
wList.append({"Total space (In GB)": round(res["checkRuns"]["diagnostic.disk.space"]["result"]["metrics"]["totalGb"], 2),
              "Used space (In GB)": round(res["checkRuns"]["diagnostic.disk.space"]["result"]["metrics"]["usedGb"], 2)})

return_results({"total": len(wList), "data": wList})
