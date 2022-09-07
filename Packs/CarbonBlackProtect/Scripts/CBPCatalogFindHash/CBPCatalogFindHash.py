import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

md5s = argToList(demisto.args()['md5'])
found = []
res = []
t = []
for md5 in md5s:
    resp = demisto.executeCommand('cbp-fileCatalog-search', {'query': 'md5:' + md5})
    if isError(resp[0]):
        demisto.results(resp)
    else:
        data = demisto.get(resp[0], 'Contents')
        if data:
            found.append(md5)
            t += data
appendContext('found_hashes', ','.join(found), dedup=True)
if t:
    res.append({"Type": entryTypes["note"], "ContentsFormat": formats["table"], "Contents": t})
else:
    res.append({"Type": entryTypes["note"], "ContentsFormat": formats["text"], "Contents": 'No results.'})
demisto.results(res)
