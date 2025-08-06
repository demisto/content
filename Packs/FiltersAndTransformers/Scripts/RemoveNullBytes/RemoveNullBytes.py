import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def removenullbytes(value):
    if isinstance(value, str):
        result = value.replace("\x00", "")
    else:
        return "error"
    return result


def main():
    value = demisto.args()["value"]
    result = removenullbytes(value)
    if result == "error":
        return_error("This transformer applies only to string")
    return_results(result)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
