import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def convert_all_inputs_to_list_of_strings(input) -> list[str]:
    """
    This function gets an input of all kinds and converts it to a list of strings.
    The input can be a string, a list of strings, a list of numbers, a dict, etc.

    Args:
        input: the input to convert to a list of strings.
    Returns:
        list of strings.
    """
    if isinstance(input, list):
        list_of_strings = []
        for item in input:
            if not isinstance(item, str):
                list_of_strings.append(str(item))
            else:
                list_of_strings.append(item)
        return list_of_strings
    elif isinstance(input, str):
        return [input]
    else:
        return [str(input)]


def common_elements(left_list: list[str], right_list: list[str]) -> list[str]:
    """
    This function gets two lists of strings and returns a list of all values from the right list that are equal or contain

    Args:
        left_list: list of strings to check if any of its items is in the right list.
        right_list: list of strings to check if any of its items is equal or contains any of the items from the left list.
    Returns:
        A list containing all values from the left that are equal or contain values from the left.
        Note: The comparing is not case sensitive.
        if no values are equal or contain values from the right, returns an empty list.
    """
    left_list = argToList(left_list)
    right_list = argToList(right_list)
    for l_item in left_list:
        for r_item in right_list:
            if l_item.lower() in r_item.lower():
                return True
    return False


def main():
    leftArg = demisto.args()["left"]
    rightArg = demisto.args()["right"]

    left_list = convert_all_inputs_to_list_of_strings(leftArg)
    right_list = convert_all_inputs_to_list_of_strings(rightArg)

    res = common_elements(leftArg, rightArg)

    for lval in left_list:

        in_range = any(lval.lower() in r.lower() for r in right_list)
        demisto.results(in_range)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
