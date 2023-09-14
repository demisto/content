import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# Call the 'deleteIndicators' command to delete expired indicators
res = demisto.executeCommand("deleteIndicators", {
    "query": "expirationStatus:expired",
    "doNotWhitelist": "true"
})

# Return the results of the 'deleteIndicators' command execution
return_results(res)
