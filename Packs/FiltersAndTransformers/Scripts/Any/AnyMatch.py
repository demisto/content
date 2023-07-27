import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def is_substring_in_list(single_str: str, str_list: list[str]) -> bool:
    """
    Checks if a string is in a list of strings, also as a substring. (case insensitive)
    Args:
       single_str: A string to check if it is in the list.
       str_list: A list of strings to check if the single_str is in it.
    Returns:
        True or False
    """
    lower_list = [x.lower() for x in str_list]
    return any(single_str.lower() in i for i in lower_list)


def main():
    leftArg = demisto.args()["left"]
    rightArg = demisto.args()["right"]

    left_list = argToList(str(leftArg))
    right_list = argToList(str(rightArg))

    for left_val in left_list:
        demisto.results(is_substring_in_list(left_val, right_list))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
