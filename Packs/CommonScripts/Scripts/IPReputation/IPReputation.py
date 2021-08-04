import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

results = demisto.executeCommand('ip', {'ip': demisto.get(demisto.args(), 'ip')})

for item in results:
    if isError(item):
        item['Contents'] = item['Brand'] + ' returned an error.\n' + item['Contents']

demisto.results(results)
