import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

listData = demisto.executeCommand("getList", {"listName": "XSOAR Health - Failed Unassigned Incident"})
listContent = list(listData[0].get('Contents').split(","))
entriesIDerrors_count = len(listContent)

if listContent == ['']:
    demisto.results(0)

else:
    demisto.results(entriesIDerrors_count)
