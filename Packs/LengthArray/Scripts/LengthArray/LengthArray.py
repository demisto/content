import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    value = demisto.args().get('value')

    if type(value) is list:
        result = len(value)
    elif value is None:
        result = None

    demisto.results(result)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
