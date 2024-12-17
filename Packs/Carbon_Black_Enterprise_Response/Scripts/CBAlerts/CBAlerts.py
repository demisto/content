import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    # args: same as cb-alert
    res = []
    resCmd1 = demisto.executeCommand("cb-alert", demisto.args())
    for entry in resCmd1:
        if isError(entry):
            res.append(entry)
        else:
            matches = entry["Contents"]["results"]
            if matches:
                formattedMatches = [{k: json.dumps(m[k]) if type(m[k]) is dict else m[k] for k in m} for m in matches]
                res.append(
                    {"Type": entryTypes["note"], "ContentsFormat": formats["table"], "Contents": formattedMatches})
            else:
                res.append({"Type": entryTypes["note"], "ContentsFormat": formats["text"], "Contents": "No matches."})
    demisto.results(res)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
