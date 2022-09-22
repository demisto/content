import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

resp = demisto.executeCommand("imp-sf-set-endpoint-status", demisto.args())
demisto.results(resp)
