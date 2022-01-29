import datetime

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S+00:00')
fieldName = demisto.args()['fieldName']
# Example format: '2018-02-02T22:58:21+02:00'
demisto.log('[*] ' + fieldName + ' <- ' + now)
demisto.setContext(fieldName, now)
demisto.results(demisto.executeCommand("setIncident", {fieldName: now}))
