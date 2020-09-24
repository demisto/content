import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

list_data = demisto.executeCommand("getList", {"listName": "XSOAR Health - Failed Unassigned Incident"})
list_content = list_data[0].get('Contents').split(",")
entries_id_errors_count = len(list_content)

if list_content == ['']:
    demisto.results(0)

else:
    demisto.results(entries_id_errors_count)
