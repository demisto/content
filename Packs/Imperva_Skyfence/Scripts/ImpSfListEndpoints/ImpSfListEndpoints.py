import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from datetime import date


def main():
    resp = demisto.executeCommand("imp-sf-list-endpoints", demisto.args())

    if isError(resp[0]):
        demisto.results(resp)
    else:
        data = demisto.get(resp[0], "Contents.result")
        if data:
            for i in range(len(data)):
                data[i]['last_updated_date'] = date.fromtimestamp(
                    float(data[i]['last_updated']) / 1000.0).strftime("%Y-%m-%d %H:%M:%S")

            data = data if isinstance(data, list) else [data]
            data = [{k: formatCell(row[k]) for k in row} for row in data]
            demisto.results({"ContentsFormat": formats["table"], "Type": entryTypes["note"], "Contents": data})
        else:
            demisto.results("No results.")


# python2 uses __builtin__ python3 uses builtins
if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
