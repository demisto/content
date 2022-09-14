import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    return_results({
        'Type': EntryType.ERROR,
        'ContentsFormat': EntryFormat.TEXT,
        'Contents': demisto.getArg("message")
    })


if __name__ in ["__builtin__", "builtins"]:
    main()
