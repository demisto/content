import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

res = []
try:
    data = demisto.get(demisto.args(), 'data')
    if (isinstance(data, list) and data):
        res.append("yes")
    elif type(data) in [str, unicode] and data:
        if data[0] in ['[', '{']:
            data = data[1:]
        if data[-1] in [']', '}']:
            data = data[:-1]
        # If data resembles one of ",,," or "[,,]" or "[]" it is considered empty of results.
        res.append('yes' if data.replace(',', '') else 'no')
    else:
        res.append("no")
except Exception as ex:
    res.append({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                "Contents": "Error occurred while parsing data. Exception info:\n" + str(ex) + "\n\nInvalid data:\n" + str(data)})
demisto.results(res)
