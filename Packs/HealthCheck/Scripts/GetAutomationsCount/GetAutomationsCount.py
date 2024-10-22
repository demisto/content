import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

payload1 = {'query': 'system:T'}
res1 = demisto.executeCommand("core-api-post", {"uri": "automation/search",
                              "body": json.dumps(payload1)})[0]["Contents"]["response"]

if not res1['scripts']:
    res1['scripts'] = []


payload2 = {'query': 'system:F'}
res2 = demisto.executeCommand("core-api-post", {"uri": "automation/search",
                              "body": json.dumps(payload2)})[0]["Contents"]["response"]

if not res2['scripts']:
    res2['scripts'] = []


payload3 = {'query': 'deprecated:T'}
res3 = demisto.executeCommand("core-api-post", {"uri": "automation/search",
                              "body": json.dumps(payload3)})[0]["Contents"]["response"]

if not res3['scripts']:
    res3['scripts'] = []

wList = []
wList.append({"OOTB": len(res1["scripts"]), "Custom": len(res2["scripts"]), "Deprecated": len(res3["scripts"])})

return_results({"total": len(wList), "data": wList})
