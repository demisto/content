import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

resp = demisto.executeCommand("sandblast-download", demisto.args())
if resp and resp[0]['Contents']:
    demisto.results(resp)
else:
    demisto.results('No results.')
