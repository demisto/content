import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    res = demisto.executeCommand("cuckoo-create-task-from-file", demisto.args())
    if isError(res[0]):
        demisto.results(res)
    else:
        taskid = demisto.get(res[0], 'Contents.task_id')
        if taskid:
            demisto.setContext('CuckooTaskID', str(taskid))
            demisto.results('Task #' + str(taskid) + " added.")
        else:
            demisto.results(res + [{"Type": entryTypes["error"],
                            "ContentsFormat": formats["text"], "Contents": 'No taskID returned.'}])


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
