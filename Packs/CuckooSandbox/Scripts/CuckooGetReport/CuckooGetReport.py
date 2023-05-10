import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    demisto.results(demisto.executeCommand("cuckoo-get-task-report", {"id": demisto.args()["taskID"]}))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
