import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    demisto.results(demisto.executeCommand("cuckoo-task-screenshot", demisto.args()))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
