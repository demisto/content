import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re


def iter_value(value: str, character: str, incr: bool) -> list:
    indexes = []
    for x in range(0, len(value)):
        if value[x] == character:
            if incr:
                indexes.append(x + 1)
            else:
                indexes.append(x)
    return indexes


def extract_inbetween(value: str, start: str, end: str) -> str:
    if isinstance(value, str):
        if start in value and end in value:
            start_indicies = []
            if len(start) == 1:
                start_indicies = iter_value(value, start, True)
            else:
                start_indicies = [(x.start() + len(start)) for x in re.finditer(start, value)]
            if len(end) == 1:
                end_indicies = iter_value(value, end, False)
            else:
                end_indicies = [x.start() for x in re.finditer(end, value)]
            start_index = start_indicies[0]
            end_index = end_indicies[-1]
            value = value[start_index:end_index]
    return value


def main():
    args = demisto.args()
    value = args.get('value')
    start = args.get('start')
    end = args.get('end')
    #try:
    return_results(extract_inbetween(value, start, end))
    #except Exception as err:
    #    return_error(f"An error occurred - {err}")


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
