import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re


def iter_value(value: str, character: str, incr: bool) -> list:
    """
    Iterate through characters in the 'value' string and match against the 'character'

    Args:
        value (str): The value to iterate through (each character)
        character (str): The character to match against

    Returns:
        list: A list of all the indexes in the 'value' string, where the 'character' matches
    """

    indexes = []
    for x in range(0, len(value)):
        if value[x] == character:
            if incr:
                indexes.append(x + 1)
            else:
                indexes.append(x)
    return indexes


def extract_inbetween(value: str, start: str, end: str) -> str:
    """
    Use regex to extract the value from 'value' using 'start' as
    the starting point and 'end' as the ending point. The 'start' will
    be used as a regex match and will match the FIRST instance. The 'end'
    will be used as a regex match and will match the LAST instance.

    Args:
        value (str): The string to search for regex matches in
        start (str): The regex to use for the starting match
        end (str): The regex to use for the ending match

    Returns:
        str: The extracted string from 'value'.
    """

    if isinstance(value, str):
        if start in value and end in value:
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
    else:
        raise DemistoException("ERROR: The input value must be a string")
    return value


def main():
    args = demisto.args()
    value = args.get('value')
    start = args.get('from')
    end = args.get('to')
    try:
        return_results(extract_inbetween(value, start, end))
    except Exception as err:
        return_error(f"An error occurred - {err}")


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
