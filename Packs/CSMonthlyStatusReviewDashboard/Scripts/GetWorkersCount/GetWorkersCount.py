import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

res = demisto.executeCommand("core-api-get", {"uri": "workers/status"})[0]["Contents"]["response"]

xVersion = demisto.executeCommand("DemistoVersion", {})[0]["Contents"]["DemistoVersion"]

wList = []
if "8." in xVersion['version']:
    wList.append({"Available": "NA", "Busy": "NA", "Total": "NA"})
else:
    wList.append({"Available": res['Available'], "Busy": res['Busy'], "Total": res['Total']})

return_results(tableToMarkdown("Workers Status", wList))
