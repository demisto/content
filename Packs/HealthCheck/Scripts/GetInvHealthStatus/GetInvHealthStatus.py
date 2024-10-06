import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

res = demisto.executeCommand("core-api-get", {"uri": "diagnostics/checks"})[0]["Contents"]["response"]

wList = []
wList.append(
    {"Big Incidents": res["checkRuns"]["diagnostic.incidents.IncidentSize"]["result"]["metrics"]["issuesCount"],
     "Incidents with Big Context": res["checkRuns"]["diagnostic.incidents.InvContextSize"]["result"]["metrics"]["issuesCount"],
     "Big Indicators": res["checkRuns"]["diagnostic.indicators.insightCache"]["result"]["metrics"]["issuesCount"]})

return_results(tableToMarkdown(
    "To get more context and guidance around the below table listings, you can go to System Diagnostics \
    page under the Settings and take actions accordingly", wList))
