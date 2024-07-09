import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

payload = {'query': 'system:T'}
res = demisto.executeCommand("core-api-post", {"uri": "playbook/search", "body": json.dumps(payload)})[0]["Contents"]["response"]

if not res['playbooks']:
    res['playbooks'] = []

playbooksList = []
for item in res["playbooks"]:
    playbook = {}
    if not (item.get('detached') is None):
        if item['detached'] is True:
            playbook['name'] = item['name']
            playbooksList.append(playbook)

return_results({"total": len(playbooksList), "data": playbooksList})
