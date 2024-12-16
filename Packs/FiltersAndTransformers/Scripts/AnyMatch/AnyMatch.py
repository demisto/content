import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def is_substring_in_list(single_str: str, str_list: list[str]) -> bool:
    """
    This function checks if a string is in a list of strings, fully or partially, case insensitive.
    Args:
       single_str: A string to check if it exists in the list.
       str_list: A list of strings to check if the single_str is in it, fully or partially.
    Returns:
        True or False
    """
    lower_list = [x.lower() for x in str_list]
    return any(i in single_str.lower() for i in lower_list)


def main():
    args = demisto.args()
    leftArg = args.get("left")
    rightArg = args.get("right")

    left_list = argToList(str(leftArg)) if leftArg else []
    right_list = argToList(str(rightArg))
    if left_list:
        for left_val in left_list:
            return_results(is_substring_in_list(left_val, right_list))
    else:
        return_results(False)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
