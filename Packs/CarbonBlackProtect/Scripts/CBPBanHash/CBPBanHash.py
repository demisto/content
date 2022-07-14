import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

CBP_HASH_BANNED = '3'
res = []
t = []
for h in argToList(demisto.args()['hash']):
    e = demisto.executeCommand("cbp-fileRule-createOrUpdate", {"fileState": CBP_HASH_BANNED, "hash": h})[0]
    if isError(e):
        res += [e]
    else:
        t.append(e['Contents'])

res.append({'ContentsFormat': formats['table'], 'Type': entryTypes['note'], 'Contents': t})
demisto.results(res)
