import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

list_data = demisto.executeCommand("getList", {"listName": "XSOAR Failed - Checked Integrations"})
list_content = list_data[0].get('Contents').split(",")
failing_incident_count = len(list_content)

if list_content == ['']:
    demisto.results(0)

else:
    demisto.results(list_content)
