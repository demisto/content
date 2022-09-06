import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    return_error(demisto.getArg("message"))


if __name__ in ["__builtin__", "builtins"]:
    main()
