import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

res = []
s2f = demisto.get(demisto.args(), 'systems2files')
if s2f:
    s2f = json.loads(s2f)
    if not isinstance(s2f, dict):
        demisto.results({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                         "Contents": "Wrong argument provided. Not a dict. Dump of args: " + json.dumps(demisto.args(), indent=4)})
    else:
        for k in s2f:
            res += demisto.executeCommand("copy-from", {'using': k, 'file': s2f[k]})
            demisto.log('Copying file ' + s2f[k] + ' from device ' + k)
demisto.results(res)
