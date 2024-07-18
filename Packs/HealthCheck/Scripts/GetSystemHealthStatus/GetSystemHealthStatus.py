import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

res = demisto.executeCommand("core-api-get", {"uri": "diagnostics/checks"})[0]["Contents"]["response"]

wList = []
wList.append({"Web Socket Disconnects(last 12hrs)": res["checkRuns"]["diagnostic.websocket.disconnects"]["result"]
             ["metrics"]["totalDisconnects"], "Slow Searches": res["checkRuns"]["diagnostic.slow.searches"]["result"]["metrics"]})

return_results(tableToMarkdown("To get more context and guidance around the below table listings, \
    you can go to System Diagnostics page under the Settings and take actions accordingly", wList))
