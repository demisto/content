import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def cbp_find_computer(args):
    # query syntax is according to Carbon Black Enterprise Protection query language documented in
    # https://developer.carbonblack.com/reference/enterprise-protection/7.2/rest-api/#query-condition - e.g. "name:*srv*"
    res = []
    if "limit" not in args:
        args["limit"] = "10"
    resCmd1 = demisto.executeCommand("cbp-computer-search", args)
    for entry in resCmd1:
        if isError(entry):
            res.append(entry)
        else:
            matches = entry.get("Contents")
            if matches:
                res.append({"Type": entryTypes["note"], "ContentsFormat": formats["table"], "Contents": matches})
            else:
                res.append({"Type": entryTypes["note"], "ContentsFormat": formats["text"], "Contents": "No matches."})
    demisto.results(res)


def main():  # pragma: no cover
    args = demisto.args()
    try:
        cbp_find_computer(args)
    except Exception as e:
        err_msg = f"Encountered an error while running the script: [{e}]"
        return_error(err_msg, error=e)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
