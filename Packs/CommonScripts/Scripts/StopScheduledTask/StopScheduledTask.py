import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def stop_scheduled_task(args):
    return demisto.executeCommand('scheduleEntry', {'id': args['taskID'], 'cancel': 'cancel'})


def main():
    res = stop_scheduled_task(demisto.args())
    return_results(res)


if __name__ in ["__builtin__", "builtins"]:
    main()
