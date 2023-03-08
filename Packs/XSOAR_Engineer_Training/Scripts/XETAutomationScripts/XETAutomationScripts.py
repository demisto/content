import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
list_name = "XETAutomationScripts"
markdown = demisto.executeCommand("getList", {"listName": list_name})[0]['Contents']
return_results(CommandResults(readable_output=markdown))
