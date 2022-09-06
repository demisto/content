import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

resp = demisto.executeCommand("algosec-get-ticket", demisto.args())

if isError(resp[0]):
    demisto.results(resp)
else:
    data = demisto.get(resp[0], "Contents.getTicketResponse")
    if data:
        raiseTable(data, 'ticket')
        for key in data:
            if isinstance(data[key], dict):
                if '-xmlns' in data[key]:
                    del data[key]['-xmlns']
                data[key] = zoomField(data[key], '#text')
        data = flattenRow(data)
        demisto.results({"ContentsFormat": formats["table"], "Type": entryTypes["note"], "Contents": data})
    else:
        demisto.results("No results.")
