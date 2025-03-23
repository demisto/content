import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def cbp_find_rule(args):
    STATES = {1: "Unapproved", 2: "Approved", 3: "Banned"}
    res = []
    found = []
    md = ""
    t = []
    hashes = argToList(args["hash"])
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
        appendContext("found_hashes", ",".join(found), dedup=True)
    res.append({"Type": entryTypes["note"], "ContentsFormat": formats["markdown"], "Contents": md})
    res.append({"Type": entryTypes["note"], "ContentsFormat": formats["table"], "Contents": t})
    demisto.results(res)


def main():  # pragma: no cover
    args = demisto.args()
    try:
        cbp_find_rule(args)
    except Exception as e:
        err_msg = f"Encountered an error while running the script: [{e}]"
        return_error(err_msg, error=e)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
