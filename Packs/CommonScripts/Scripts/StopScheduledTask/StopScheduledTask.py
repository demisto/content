import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

res = []

if demisto.args()['taskID']:
    res = demisto.executeCommand('scheduleEntry', {'id': demisto.args()['taskID'], 'cancel': 'cancel'})

demisto.results(res)
