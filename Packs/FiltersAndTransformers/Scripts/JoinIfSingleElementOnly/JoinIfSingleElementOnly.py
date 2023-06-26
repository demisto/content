import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def return_first_element_if_single(value):
    res = value
    if isinstance(value, list):
        if len(value) == 1:
            res = value[0]
    return res


def main():  # pragma: no cover
    value = demisto.args()["value"]
    res = return_first_element_if_single(value)
    demisto.results(res)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
