import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

resp = demisto.executeCommand("netwitness-im-get-components", demisto.args())

if isError(resp[0]):
    demisto.results(resp)
else:
    data = demisto.get(resp[0], "Contents.components")
    if data:
        data = flattenTable(data)
        demisto.results({"ContentsFormat": formats["table"], "Type": entryTypes["note"], "Contents": data})
    else:
        demisto.results("No results.")
