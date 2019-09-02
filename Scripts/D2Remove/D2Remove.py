import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

result = demisto.executeCommand('d2_remove', demisto.args())

if isError(result[0]):
    demisto.results(result)
else:
    demisto.results('D2 agent removed successfully')
