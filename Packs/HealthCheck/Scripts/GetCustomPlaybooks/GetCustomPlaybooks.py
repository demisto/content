import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import dateutil.parser
import pytz


payload = {'query': 'system:F'}
res = demisto.executeCommand("core-api-post", {"uri": "playbook/search", "body": json.dumps(payload)})[0]["Contents"]["response"]

if not res['playbooks']:
    res['playbooks'] = []

playbooksList = []
for item in res["playbooks"]:
    playbook = {}
    if (item.get('system') is None):
        insertion_date = dateutil.parser.parse(item['modified'])
        diffretiation = pytz.utc.localize(datetime.utcnow()) - insertion_date
        if diffretiation.days < 30:
            playbook['name'] = item['name']
            playbooksList.append(playbook)

return_results({"total": len(playbooksList), "data": playbooksList})
