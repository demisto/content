import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    res = demisto.executeCommand("cuckoo-view-task", {"id": demisto.args()["taskID"]})
    if isError(res[0]):
        demisto.results(res)
    else:
        data = demisto.get(res[0], 'Contents.task')
        if data:
            data = {k: formatCell(data[k]) for k in data}
            demisto.results({'ContentsFormat': formats['table'], 'Type': entryTypes['note'], 'Contents': data})
        else:
            demisto.results(res)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
