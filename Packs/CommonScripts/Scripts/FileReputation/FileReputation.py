import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

results = demisto.executeCommand('file', {'file': demisto.get(demisto.args(), 'file')})

for item in results:
    if isError(item):
        item['Contents'] = item['Brand'] + ' returned an error.\n' + item['Contents']

demisto.results(results)
