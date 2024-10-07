import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def is_substring_in_list(single_str: str, str_list: list[str]) -> list:
    """
    This function checks if a string is in a list of strings, fully or partially, case insensitive.
    Args:
       single_str: A string to check if it exists in the list.
       str_list: A list of strings to check if the single_str is in it, fully or partially.
    Returns:
        True or False
    """
    return list(filter(lambda x: single_str in x.lower(), str_list))


def main():
    args = demisto.args()
    leftArg = args.get("left")
    rightArg = args.get("right")

    left_list = argToList(leftArg)
    right_list = argToList(rightArg)

    if not (leftArg and rightArg):
        return_results("")
    results = set()
    for left_val in left_list:
        results = results.union(list(filter(lambda right_val: left_val.lower() in right_val.lower(), right_list)))
    return return_results(str(list(results)))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
