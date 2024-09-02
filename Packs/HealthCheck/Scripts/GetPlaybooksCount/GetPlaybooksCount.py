import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

payload1 = {'query': 'system:T'}
res1 = demisto.executeCommand("core-api-post", {"uri": "playbook/search",
                              "body": json.dumps(payload1)})[0]["Contents"]["response"]

if not res1['playbooks']:
    res1['playbooks'] = []


payload2 = {'query': 'system:F'}
res2 = demisto.executeCommand("core-api-post", {"uri": "playbook/search",
                              "body": json.dumps(payload2)})[0]["Contents"]["response"]

if not res2['playbooks']:
    res2['playbooks'] = []

payload3 = {'query': 'deprecated:T'}
res3 = demisto.executeCommand("core-api-post", {"uri": "playbook/search",
                              "body": json.dumps(payload3)})[0]["Contents"]["response"]

if not res3['playbooks']:
    res3['playbooks'] = []


wList = []
wList.append({"OOTB": len(res1["playbooks"]), "Custom": len(res2["playbooks"]), "Deprecated": len(res3["playbooks"])})

return_results({"total": len(wList), "data": wList})
