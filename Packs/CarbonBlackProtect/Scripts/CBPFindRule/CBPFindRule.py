import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

STATES = {1: "Unapproved", 2: "Approved", 3: "Banned"}
res = []
found = []
md = ''
t = []
limit = demisto.args()["limit"] if "limit" in demisto.args() else "10"
hashes = argToList(demisto.args()["hash"])
for h in hashes:
    resSearch = demisto.executeCommand("cbp-fileRule-search", {"query": "hash:" + h})
    for entry in resSearch:
        if isError(entry):
            res.append(entry)
        else:
            for rule in entry["Contents"]:
                t.append(rule)
                found.append(rule["hash"])
                md += "Hash " + rule["hash"] + " is in state **" + STATES[rule["fileState"]] + "**\n"
if found:
    appendContext('found_hashes', ','.join(found), dedup=True)
res.append({"Type": entryTypes["note"], "ContentsFormat": formats["markdown"], "Contents": md})
res.append({"Type": entryTypes["note"], "ContentsFormat": formats["table"], "Contents": t})
demisto.results(res)
