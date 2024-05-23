import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

res = demisto.executeCommand("core-api-get", {"uri": "workers/status"})[0]["Contents"]["response"]

wList = []
wList.append({"Available": res['Available'], "Busy": res['Busy'], "Total": res['Total']})

return_results(tableToMarkdown("Workers status", wList))
