import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

res = demisto.executeCommand("core-api-get", {"uri": "diagnostics/checks"})[0]["Contents"]["response"]
xVersion = demisto.executeCommand("DemistoVersion", {})[0]["Contents"]["DemistoVersion"]

wList = []
if "8." in xVersion['version']:
    wList.append({"Total space (In GB)": "NA", "Used space (In GB)": "NA"})
else:
    wList.append({"Total space (In GB)": round(res["checkRuns"]["diagnostic.disk.space"]["result"]["metrics"]["totalGb"], 2), "Used space (In GB)": round(
        res["checkRuns"]["diagnostic.disk.space"]["result"]["metrics"]["usedGb"], 2)})

demisto.results({"total": len(wList), "data": wList})
