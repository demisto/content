import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

resp = demisto.executeCommand("netwitness-im-get-events", demisto.args())

if isError(resp[0]):
    demisto.results(resp)
else:
    data = demisto.get(resp[0], "Contents.events")
    if data:
        data = data if isinstance(data, list) else [data]
        formatTimeColumns(data, ['time'])
        for row in data:
            newMeta = {}
            for var in row['meta']:
                newMeta['meta.' + var['name']] = var['value']
            row['meta'] = newMeta
            raiseTable(row, 'meta')
        data = [{k: formatCell(row[k]) for k in row} for row in data]
        demisto.results({"ContentsFormat": formats["table"], "Type": entryTypes["note"], "Contents": data})
    else:
        demisto.results("No results.")
