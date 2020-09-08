import demistomock as demisto
from CommonServerPython import *  # noqa: F401


def main():
    value = demisto.args()['value']

    value = value[0]

    demisto.results(value)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
