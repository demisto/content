import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

INVALID_ARG = "INVALID_ARG"


def to_float(s):
    try:
        return float(s)
    except Exception:
        return INVALID_ARG


# "1,8" => will return a tupple (1, 8)


def parse_range(rangeStr):
    splitted = rangeStr.split(",")
    if len(splitted) < 2:
        return INVALID_ARG, INVALID_ARG

    # parse
    return to_float(splitted[0]), to_float(splitted[1])


def main():
    leftArg = demisto.args()["left"]
    rightArg = demisto.args()["right"]

    left = to_float(leftArg)
    fromRange, toRange = parse_range(rightArg)

    if INVALID_ARG in [left, fromRange, toRange]:
        demisto.error(
            "InRange - invalid arguments. left shuld be a number, right should be from,to (e.g. '1,8'). "
            "got left - %s, right - %s" % (leftArg, rightArg))
        demisto.results(False)
    else:
        demisto.results(left >= fromRange and left <= toRange)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
