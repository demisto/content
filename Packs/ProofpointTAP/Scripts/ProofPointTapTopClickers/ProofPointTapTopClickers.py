import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

results = demisto.executeCommand('proofpoint-get-top-clickers', {'window': 90})[0]['Contents']['users']
users = []

for user in results:
    users.append({"name": user.get("identity").get("emails", [""])[0],
                  "data": [user.get("clickStatistics").get("clickCount")]})

return_results(json.dumps(users))
