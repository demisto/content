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


def all_from_left_that_exist_in_right(left_list: list[str], right_list: list[str]) -> list[str]:
    """
    This function checks if any of the items in the left list is in the right list.
    Args:
        left_list: the list to check if any of its items is in the right list.
        right_list: the list to check if any of the items in the left list is in it.
    Returns:
        A list containing all values from the left that are equal or contain values from the left.
        Note: The comparing is not case sensitive.
        if no values are equal or contain values from the right, returns an empty list.
    """
    all_results = []
    for l_item in left_list:
        for r_item in right_list:
            if l_item in r_item or l_item.lower() in r_item.lower():
                all_results.append(r_item)
    return all_results


def main():
    leftArg = demisto.args()["left"]
    rightArg = demisto.args()["right"]

    left_list = convert_all_inputs_to_list_of_strings(leftArg)
    right_list = convert_all_inputs_to_list_of_strings(rightArg)

    res = all_from_left_that_exist_in_right(left_list, right_list)

    demisto.results(res)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
