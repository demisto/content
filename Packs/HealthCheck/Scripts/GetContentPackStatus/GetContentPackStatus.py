import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


res = demisto.executeCommand("core-api-get", {"uri": "contentpacks/installed-expired"})[0]["Contents"]["response"]

counter1 = 0
counter2 = 0
for item in res:
    if item['updateAvailable'] is True:
        counter1 += 1
    if item['deprecated'] is True:
        counter2 += 1

wList = []
wList.append({"Update Available packs": counter1, "Deprecated packs": counter2})

return_results({"total": len(wList), "data": wList})
