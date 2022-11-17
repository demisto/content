from time import strftime

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

field_name = demisto.args()['fieldName']

t = strftime("%a, %d %b %Y %H:%M:%S %Z")
res = demisto.executeCommand("setIncident", {field_name: t})
demisto.results(res)
