import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    value = demisto.args()["value"]

    if isinstance(value, list):
        res = value
        res.reverse()
    else:
        res = value

    demisto.results(res)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
