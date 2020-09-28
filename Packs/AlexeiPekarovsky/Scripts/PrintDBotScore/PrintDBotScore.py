import demistomock as demisto
from CommonServerPython import *  # noqa: F401

fmt = demisto.get(demisto.args(), 'outputformat')
ctx = demisto.get(demisto.context(), 'DBotScore')
if ctx:
    md = "{ \"Reputation\":\n" + json.dumps(ctx, indent=4) + '\n}'
    demisto.results({'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': md})
    demisto.results(fileResult('reputation.json', md))
else:
    demisto.results('DBotScore Context empty.')
