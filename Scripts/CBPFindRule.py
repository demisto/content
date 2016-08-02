STATES = { 1: "Unapproved", 2: "Approved", 3: "Banned" }
res = []
limit = demisto.args()["limit"] if "limit" in demisto.args() else "10"
resSearch = demisto.executeCommand("cbp-fileRule-search", { "query": "hash:" + demisto.args()["hash"] })
for entry in resSearch:
    if isError(entry):
        res.append(entry)
    else:
        for rule in entry["Contents"]:
            res.append(  { "Type" : entryTypes["note"], "ContentsFormat" : formats["markdown"], "Contents" : "Hash " + rule["hash"] + " is in state **" + STATES[rule["fileState"]] + "**" } )
demisto.results(res)
