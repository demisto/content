import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

resp = demisto.executeCommand("sandblast-query", demisto.args())

if isError(resp[0]):
    demisto.results(resp)
else:
    data = demisto.get(resp[0], "Contents.response")
    if data:
        data = data if isinstance(data, list) else [data]
        data = [{k: formatCell(row[k]) for k in row} for row in data]
        demisto.results({"ContentsFormat": formats["table"], "Type": entryTypes["note"], "Contents": data})
    else:
        demisto.results("No results.")
