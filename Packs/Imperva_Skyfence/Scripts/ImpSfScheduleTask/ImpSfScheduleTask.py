import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    res = []
    SCHEDULE_TASK_ID_LABAL = "ScheduleTaskID"

    dArgs = demisto.args()
    dArgs['command'] = '!ImpSfRevokeUnaccessedDevices'

    res = demisto.executeCommand('scheduleEntry', dArgs)
    if isError(res[0]):
        demisto.results(res)
    else:
        taskID = demisto.get(res[0], "Contents.id")
        demisto.setContext(SCHEDULE_TASK_ID_LABAL, taskID)
        demisto.results(res)


# python2 uses __builtin__ python3 uses builtins
if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
