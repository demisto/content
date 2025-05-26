import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def cbp_catalog_find_hash(args):
    md5s = argToList(args.get("md5"))
    found = []
    res = []
    t = []
    for md5 in md5s:
        resp = demisto.executeCommand("cbp-fileCatalog-search", {"query": "md5:" + md5})
        if isError(resp[0]):
            demisto.results(resp)
        else:
            data = demisto.get(resp[0], "Contents")
            if data:
                found.append(md5)
                t += data
    appendContext("found_hashes", ",".join(found), dedup=True)
    if t:
        res.append({"Type": entryTypes["note"], "ContentsFormat": formats["table"], "Contents": t})
    else:
        res.append({"Type": entryTypes["note"], "ContentsFormat": formats["text"], "Contents": "No results."})
    demisto.results(res)


def main():  # pragma: no cover
    args = demisto.args()
    try:
        cbp_catalog_find_hash(args)
    except Exception as e:
        err_msg = f"Encountered an error while running the script: [{e}]"
        return_error(err_msg, error=e)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
