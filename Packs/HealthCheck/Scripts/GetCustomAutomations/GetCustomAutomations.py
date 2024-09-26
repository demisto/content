import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import dateutil.parser
import pytz


payload = {'query': 'system:F'}
res = demisto.executeCommand("core-api-post", {"uri": "automation/search",
                             "body": json.dumps(payload)})[0]["Contents"]["response"]

if not res['scripts']:
    res['scripts'] = []

scriptsList = []
for item in res["scripts"]:
    script = {}
    insertion_date = dateutil.parser.parse(item['modified'])
    diffretiation = pytz.utc.localize(datetime.utcnow()) - insertion_date
    if diffretiation.days < 30:
        script['name'] = item['name']
        scriptsList.append(script)

return_results({"total": len(scriptsList), "data": scriptsList})
