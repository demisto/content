import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

res = demisto.executeCommand("core-api-get", {"uri": "workers/status"})[0]["Contents"]["response"]

wList = []
wList.append({"Total": res['Total'], "Busy": res['Busy']})

return_results(tableToMarkdown("Workers status", wList))
