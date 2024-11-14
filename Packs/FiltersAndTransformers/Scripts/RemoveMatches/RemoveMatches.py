from CommonServerPython import *  # noqa: F401

import re


def filter_items(values: list, filter_list: list, ignore_case: bool, match_exact: bool):
    """Filter the values by the filter list.
    If an item matches an entry in the filter_list, than do not return it.

    Args:
        values (_type_): The value on which to apply the transformer
        filter_list (_type_): The list of pattern to filter from the values
        ignore_case (_type_): If True, ignore the case of the value
        match_exact (_type_): If True, only filter out values exactly matching the pattern

    Returns:
        _type_: The values not matching any of the patterns in the given list
    """
    filtered_items = []

    regex_ignore_case_flag = re.IGNORECASE if ignore_case else 0
    list_to_lowercase = [list_item.lower().strip() for list_item in filter_list]
    for value in values:
        if match_exact:
            if ignore_case:
                if value.lower() in list_to_lowercase:
                    continue
            else:
                if value in filter_list:
                    continue
        else:
            filtered = False
            for filter_string in filter_list:
                filter_string = filter_string.strip()  # remove trailing/leading whitespace
                if filter_string and re.search(filter_string, value, regex_ignore_case_flag):
                    filtered = True
                    break
            if filtered:
                continue
        filtered_items.append(value)

    return filtered_items


''' MAIN FUNCTION '''


def main():  # pragma: no cover
    try:
        args = demisto.args()
        ignore_case = argToBoolean(args.get('ignore_case', 'True'))
        match_exact = argToBoolean(args.get('match_exact', 'False'))
        values = argToList(args.get('value'))
        delimiter = args.get('delimiter', '\n')
        list: str = args.get('filters', '')
        if not list:
            filtered_items = values
        else:
            filters = re.split(delimiter, list)
            filtered_items = filter_items(values=values,
                                          filter_list=filters,
                                          ignore_case=ignore_case,
                                          match_exact=match_exact)
        return_results(filtered_items)
    except Exception as ex:
        return_error(f'Failed to execute FilterByListTransformer. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
